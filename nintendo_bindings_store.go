package main

// Store side of the console identity bindings (see nintendo_bindings.go for why
// they exist).
//
// # Why a sidecar file instead of a field on Account
//
// Bindings live in their OWN JSON file rather than inside accounts.json, and the
// index lives here rather than inside jsonStore. That is deliberate: this fork
// then touches upstream's data model not at all, so it rebases cleanly onto
// nextendo-account whenever upstream moves, and an operator can inspect, back up
// or delete the binding table without going near the account file.
//
// Resolution is O(1) through two reverse indexes. The old bs:did lookup walked
// every account on every console request, which was both slow and a small
// denial-of-service surface on a path a console hits constantly.

import (
	"encoding/json"
	"errors"
	"log"
	"os"
	"sync"
	"time"
)

// errBindingTaken means the console identity already belongs to another account.
var errBindingTaken = errors.New("binding already belongs to another account")

// bindingTable is the persisted binding store.
type bindingTable struct {
	path string

	mu sync.RWMutex
	// Accounts maps an account PID to the console identities bound to it. A
	// player may have several (one per console or per profile).
	Accounts map[uint64][]NintendoBinding `json:"accounts"`

	// Reverse indexes, derived from Accounts and rebuilt on load and on write.
	byBaas  map[string]uint64
	byBsDid map[string]uint64

	dirty bool
}

var (
	bindingsOnce  sync.Once
	bindingsTable *bindingTable
)

// bindingsFile is where the table is stored. Next to accounts.json by default.
func bindingsFile() string {
	if v := os.Getenv("NEXTENDO_BINDINGS_FILE"); v != "" {
		return v
	}
	return "nintendo_bindings.json"
}

// openBindings loads the table once.
func openBindings() *bindingTable {
	bindingsOnce.Do(func() {
		t := &bindingTable{
			path:     bindingsFile(),
			Accounts: map[uint64][]NintendoBinding{},
			byBaas:   map[string]uint64{},
			byBsDid:  map[string]uint64{},
		}
		if b, err := os.ReadFile(t.path); err == nil && len(b) > 0 {
			if err := json.Unmarshal(b, t); err != nil {
				// A corrupt table must not take the server down and must not be
				// silently overwritten: move it aside so it can be inspected.
				backup := t.path + ".corrupt." + time.Now().UTC().Format("20060102T150405")
				_ = os.Rename(t.path, backup)
				log.Printf("[bind] %s illisible (%v) ; déplacé vers %s, on repart à vide", t.path, err, backup)
				t.Accounts = map[uint64][]NintendoBinding{}
			}
		}
		if t.Accounts == nil {
			t.Accounts = map[uint64][]NintendoBinding{}
		}
		t.reindex()
		log.Printf("[bind] table des liaisons console : %d compte(s) depuis %s", len(t.Accounts), t.path)
		bindingsTable = t
	})
	return bindingsTable
}

// reindex rebuilds the reverse indexes. Caller holds the write lock (or is the
// loader, before the table is shared).
func (t *bindingTable) reindex() {
	t.byBaas = map[string]uint64{}
	t.byBsDid = map[string]uint64{}
	for pid, list := range t.Accounts {
		for _, b := range list {
			if b.BaasID != "" {
				t.byBaas[b.BaasID] = pid
			}
			if b.BsDid != "" {
				t.byBsDid[b.BsDid] = pid
			}
		}
	}
}

// persist writes the table. Atomic rename, so a crash mid-write cannot truncate it.
func (t *bindingTable) persist() error {
	b, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return err
	}
	tmp := t.path + ".tmp"
	// 0600: this table maps consoles to players.
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, t.path); err != nil {
		return err
	}
	t.dirty = false
	return nil
}

// Bind records a console identity for an account.
//
// Returns whether the binding is new. errBindingTaken when another account owns
// one of the ids: refusing is the point — a console silently changing owner would
// be the original bug in a new shape.
func (t *bindingTable) Bind(pid uint64, b NintendoBinding) (bool, error) {
	b.BaasID, b.BsDid, b.NaID = normalizeHexID(b.BaasID), normalizeHexID(b.BsDid), normalizeHexID(b.NaID)
	if pid == 0 || (b.BaasID == "" && b.BsDid == "") {
		return false, errors.New("bind: pid and at least one id are required")
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	if b.BaasID != "" {
		if other, taken := t.byBaas[b.BaasID]; taken && other != pid {
			return false, errBindingTaken
		}
	}
	if b.BsDid != "" {
		if other, taken := t.byBsDid[b.BsDid]; taken && other != pid {
			return false, errBindingTaken
		}
	}

	now := time.Now().UTC()
	if b.BoundAt.IsZero() {
		b.BoundAt = now
	}
	b.LastSeen = now

	// Merge into an existing entry for the same console, so a re-link does not
	// accumulate duplicates.
	list := t.Accounts[pid]
	for i := range list {
		cur := &list[i]
		if (b.BaasID != "" && cur.BaasID == b.BaasID) || (b.BsDid != "" && cur.BsDid == b.BsDid) {
			if b.BaasID != "" {
				cur.BaasID = b.BaasID
			}
			if b.BsDid != "" {
				cur.BsDid = b.BsDid
			}
			if b.NaID != "" {
				cur.NaID = b.NaID
			}
			if b.Label != "" {
				cur.Label = b.Label
			}
			cur.LastSeen = now
			t.Accounts[pid] = list
			t.reindex()
			return false, t.persist()
		}
	}
	t.Accounts[pid] = append(list, b)
	t.reindex()
	return true, t.persist()
}

// Unbind removes the binding matching either id from an account.
func (t *bindingTable) Unbind(pid uint64, baasID, bsDid string) error {
	baasID, bsDid = normalizeHexID(baasID), normalizeHexID(bsDid)
	t.mu.Lock()
	defer t.mu.Unlock()

	list, ok := t.Accounts[pid]
	if !ok {
		return ErrNotFound
	}
	kept := make([]NintendoBinding, 0, len(list))
	removed := false
	for _, b := range list {
		if (baasID != "" && b.BaasID == baasID) || (bsDid != "" && b.BsDid == bsDid) {
			removed = true
			continue
		}
		kept = append(kept, b)
	}
	if !removed {
		return ErrNotFound
	}
	if len(kept) == 0 {
		delete(t.Accounts, pid)
	} else {
		t.Accounts[pid] = kept
	}
	t.reindex()
	return t.persist()
}

// Resolve looks a console identity up in the binding table.
//
// via is "binding:baas" or "binding:bsdid"; ok is false when nothing matches, and
// the caller then tries the derived ids (see server.resolveConsole).
func (t *bindingTable) Resolve(baasID, bsDid string) (pid uint64, via string, ok bool) {
	baasID, bsDid = normalizeHexID(baasID), normalizeHexID(bsDid)
	t.mu.RLock()
	defer t.mu.RUnlock()
	if baasID != "" {
		if pid, found := t.byBaas[baasID]; found {
			return pid, "binding:baas", true
		}
	}
	if bsDid != "" {
		if pid, found := t.byBsDid[bsDid]; found {
			return pid, "binding:bsdid", true
		}
	}
	return 0, "", false
}

// Touch refreshes the LastSeen of a binding, so an operator can tell a live
// console from an old one. Best-effort: it does not persist on its own (the next
// real write does), because a console request must never wait on disk.
func (t *bindingTable) Touch(pid uint64, baasID, bsDid string) {
	baasID, bsDid = normalizeHexID(baasID), normalizeHexID(bsDid)
	t.mu.Lock()
	defer t.mu.Unlock()
	list := t.Accounts[pid]
	now := time.Now().UTC()
	for i := range list {
		b := &list[i]
		if (baasID != "" && b.BaasID == baasID) || (bsDid != "" && b.BsDid == bsDid) {
			b.LastSeen = now
			t.dirty = true
			return
		}
	}
}

// resetBindingsForTest drops the loaded table so a test can point the store at a
// fresh file. Only ever called from tests; a running server loads the table once.
func resetBindingsForTest() {
	bindingsOnce = sync.Once{}
	bindingsTable = nil
}

// List returns the bindings of an account (for the admin space / support).
func (t *bindingTable) List(pid uint64) []NintendoBinding {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]NintendoBinding, len(t.Accounts[pid]))
	copy(out, t.Accounts[pid])
	return out
}

// Count returns how many consoles are bound, for the start-up log.
func (t *bindingTable) Count() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	n := 0
	for _, list := range t.Accounts {
		n += len(list)
	}
	return n
}
