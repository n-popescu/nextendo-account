package main

// Ban system — un ban Discord (relayé par le bot de vérif via /api/admin/ban) supprime le
// compte Nextendo ET pose une "pierre tombale" (tombstone) qui persiste APRÈS la suppression :
// l'e-mail et l'IP ne peuvent plus se réinscrire, le friend code n'est jamais réattribué, le
// PID reste marqué banni, et le site peut afficher l'utilisateur comme "Banni" à ses anciens
// amis. Le cloud (saves) et l'historique de jeu sont effacés : plus aucune trace exploitable.

import (
	"crypto/subtle"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type banRecord struct {
	PID         uint64    `json:"pid"`
	Email       string    `json:"email,omitempty"`
	FriendCode  string    `json:"friend_code,omitempty"`
	Username    string    `json:"username,omitempty"`
	RegIPs      []string  `json:"reg_ips,omitempty"`
	DiscordID   string    `json:"discord_id,omitempty"`   // réservé aussi : ce Discord ne peut plus relier de compte
	DiscordName string    `json:"discord_name,omitempty"` // pseudo Discord (affichage admin)
	BannedAt    time.Time `json:"banned_at"`
	Reason      string    `json:"reason,omitempty"`
}

type banStore struct {
	mu      sync.RWMutex
	path    string
	list    []banRecord
	email   map[string]bool
	ip      map[string]bool
	pid     map[uint64]int
	code    map[string]bool
	discord map[string]bool
}

var bans = newBanStore()

func banFilePath() string {
	if v := os.Getenv("NEXTENDO_BANS"); v != "" {
		return v
	}
	if d := os.Getenv("NEXTENDO_DATA"); d != "" {
		return filepath.Join(filepath.Dir(d), "bans.json")
	}
	return "bans.json"
}

func newBanStore() *banStore {
	b := &banStore{path: banFilePath()}
	if raw, err := os.ReadFile(b.path); err == nil {
		var f struct {
			Bans []banRecord `json:"bans"`
		}
		if json.Unmarshal(raw, &f) == nil {
			b.list = f.Bans
		}
	}
	b.reindex()
	log.Printf("[ban] %d tombstone(s) chargé(s) (%s)", len(b.list), b.path)
	return b
}

// reindex rebuilds the lookup maps. Caller holds the write lock (or it's init-time).
func (b *banStore) reindex() {
	b.email = map[string]bool{}
	b.ip = map[string]bool{}
	b.pid = map[uint64]int{}
	b.code = map[string]bool{}
	b.discord = map[string]bool{}
	for i, r := range b.list {
		if r.Email != "" {
			b.email[strings.ToLower(r.Email)] = true
		}
		if r.FriendCode != "" {
			b.code[strings.ToUpper(r.FriendCode)] = true
		}
		if r.DiscordID != "" {
			b.discord[r.DiscordID] = true
		}
		b.pid[r.PID] = i
		for _, ip := range r.RegIPs {
			if ip != "" {
				b.ip[ip] = true
			}
		}
	}
}

func (b *banStore) persist() {
	raw, _ := json.MarshalIndent(map[string]any{"bans": b.list}, "", "  ")
	tmp := b.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		log.Printf("[ban] persist: %v", err)
		return
	}
	_ = os.Rename(tmp, b.path)
}

func (b *banStore) add(r banRecord) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if r.BannedAt.IsZero() {
		r.BannedAt = time.Now().UTC()
	}
	if i, ok := b.pid[r.PID]; ok {
		b.list[i] = r
	} else {
		b.list = append(b.list, r)
	}
	b.reindex()
	b.persist()
	log.Printf("[ban] tombstone pid=%d email=%s code=%s ips=%v", r.PID, r.Email, r.FriendCode, r.RegIPs)
}

func banIsEmailBanned(email string) bool {
	e := strings.ToLower(strings.TrimSpace(email))
	bans.mu.RLock()
	defer bans.mu.RUnlock()
	return bans.email[e]
}

func banIsIPBanned(ip string) bool {
	if ip == "" {
		return false
	}
	bans.mu.RLock()
	defer bans.mu.RUnlock()
	return bans.ip[ip]
}

func banIsPIDBanned(pid uint64) bool {
	bans.mu.RLock()
	defer bans.mu.RUnlock()
	_, ok := bans.pid[pid]
	return ok
}

func banIsCodeBanned(code string) bool {
	bans.mu.RLock()
	defer bans.mu.RUnlock()
	return bans.code[strings.ToUpper(code)]
}

// banIsDiscordBanned : ce compte Discord a-t-il déjà été banni ? (empêche de relier un
// nouveau compte Nextendo au Discord d'un banni)
func banIsDiscordBanned(discordID string) bool {
	if discordID == "" {
		return false
	}
	bans.mu.RLock()
	defer bans.mu.RUnlock()
	return bans.discord[discordID]
}

// banAll : tous les tombstones. L'espace admin les affiche pour qu'un banni RESTE visible dans
// la liste (sinon il disparaît, le ban ayant supprimé le compte) et puisse être débanni.
func banAll() []banRecord {
	bans.mu.RLock()
	defer bans.mu.RUnlock()
	out := make([]banRecord, len(bans.list))
	copy(out, bans.list)
	return out
}

// banRemove lève un ban : le tombstone saute, donc l'e-mail / l'IP / le code ami / le Discord
// redeviennent libres. Renvoie l'enregistrement levé (on y lit le Discord à débannir).
func banRemove(pid uint64) (banRecord, bool) {
	bans.mu.Lock()
	defer bans.mu.Unlock()
	i, ok := bans.pid[pid]
	if !ok {
		return banRecord{}, false
	}
	rec := bans.list[i]
	bans.list = append(bans.list[:i], bans.list[i+1:]...)
	bans.reindex()
	bans.persist()
	log.Printf("[ban] levé pid=%d email=%s ips=%v discord=%s", rec.PID, rec.Email, rec.RegIPs, rec.DiscordID)
	return rec, true
}

// banRecordForPID returns the tombstone for a PID (used to render "Banni" in friend lists).
func banRecordForPID(pid uint64) (banRecord, bool) {
	bans.mu.RLock()
	defer bans.mu.RUnlock()
	if i, ok := bans.pid[pid]; ok {
		return bans.list[i], true
	}
	return banRecord{}, false
}

// SetRegIP records the account's registration IP (reserved if it gets banned later).
func (s *jsonStore) SetRegIP(id int64, ip string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.Accts[id]
	if !ok {
		return ErrNotFound
	}
	if a.RegIP == ip {
		return nil
	}
	a.RegIP = ip
	return s.persist()
}

// banAccount hard-deletes the account for pid, writes a ban tombstone (e-mail / IP / friend
// code / PID reserved), wipes its cloud saves + play history, and cuts its sessions.
func (s *server) banAccount(pid uint64, reason string) {
	if acct, err := s.store.ByPID(pid); err == nil {
		rec := banRecord{
			PID:         acct.PID,
			Email:       strings.ToLower(acct.Email),
			FriendCode:  acct.FriendCode,
			Username:    acct.Username,
			DiscordID:   acct.DiscordID,
			DiscordName: acct.DiscordUsername,
			Reason:      reason,
		}
		if acct.RegIP != "" {
			rec.RegIPs = []string{acct.RegIP}
		}
		bans.add(rec)
		os.RemoveAll(filepath.Join(saveDir, strconv.FormatUint(pid, 10)))         // cloud saves
		os.Remove(filepath.Join(historyDir, strconv.FormatUint(pid, 10)+".json")) // play history
		revokeAllForPID(pid, "banned")
		_ = s.store.DeleteByPID(pid)
		// Miroir du ban Discord -> Nextendo : un ban prononcé ICI (site/admin) bannit aussi sur
		// le Discord. Best-effort et asynchrone : si le bot est down, le ban reste effectif.
		relayDiscordBan(rec.DiscordID, reason)
		log.Printf("[ban] pid=%d (%s) banni + supprimé, raison=%q", pid, rec.Email, reason)
		return
	}
	if !banIsPIDBanned(pid) {
		bans.add(banRecord{PID: pid, Reason: reason})
	}
}

// adminBan bans an account by PID. POST /api/admin/ban {pid, reason?}
// Auth: X-Admin-Key service header (Discord bot) OR an admin bearer session.
func (s *server) adminBan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST attendu")
		return
	}
	if !s.adminOrServiceKey(w, r) {
		return
	}
	var in struct {
		PID    uint64 `json:"pid"`
		Reason string `json:"reason"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.PID == 0 {
		writeErr(w, http.StatusBadRequest, "pid requis")
		return
	}
	s.banAccount(in.PID, in.Reason)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "pid": in.PID})
}

// adminUnban lève un ban. POST /api/admin/unban {pid}
// Le tombstone saute : l'e-mail, l'IP d'inscription, le code ami et le Discord redeviennent
// libres, et le Discord est débanni du serveur. À noter : le compte lui-même reste supprimé
// (le ban l'avait effacé) — la personne peut de nouveau s'inscrire, ce que le ban empêchait.
// Auth : X-Admin-Key OU session admin.
func (s *server) adminUnban(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST attendu")
		return
	}
	if !s.adminOrServiceKey(w, r) {
		return
	}
	var in struct {
		PID uint64 `json:"pid"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.PID == 0 {
		writeErr(w, http.StatusBadRequest, "pid requis")
		return
	}
	rec, ok := banRemove(in.PID)
	if !ok {
		writeErr(w, http.StatusNotFound, "aucun ban pour ce PID")
		return
	}
	relayDiscordUnban(rec.DiscordID, "Débanni sur Nextendo")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "pid": in.PID})
}

// adminServiceKey returns the shared service key used by the Discord bot to call the ban
// endpoint. Read from NEXTENDO_ADMIN_KEY, else from <datadir>/admin_key.txt (so it can be
// deployed as a file without recreating the container).
func adminServiceKey() string {
	if v := strings.TrimSpace(os.Getenv("NEXTENDO_ADMIN_KEY")); v != "" {
		return v
	}
	if d := os.Getenv("NEXTENDO_DATA"); d != "" {
		if b, err := os.ReadFile(filepath.Join(filepath.Dir(d), "admin_key.txt")); err == nil {
			return strings.TrimSpace(string(b))
		}
	}
	return ""
}

// adminOrServiceKey allows either the X-Admin-Key service key (Discord bot) or an admin
// bearer session. Writes the HTTP error itself when neither passes.
func (s *server) adminOrServiceKey(w http.ResponseWriter, r *http.Request) bool {
	if key := adminServiceKey(); key != "" {
		if got := r.Header.Get("X-Admin-Key"); got != "" && subtle.ConstantTimeCompare([]byte(got), []byte(key)) == 1 {
			return true
		}
	}
	_, ok := s.requireAdmin(w, r)
	return ok
}
