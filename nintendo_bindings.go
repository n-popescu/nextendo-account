package main

// Console identity bindings — the fix for "every Switch adds friends as the same
// person".
//
// # The bug this exists for
//
// A Switch authenticates with a BAAS *device account* and presents an id_token on
// every request:
//
//	sub      the BAAS/NSA user id   (per console user)
//	bs:did   the device account id  (per console)
//
// nx-account (the Switch-facing server) has to turn those into a Nextendo account
// on EVERY request. Until now the only way to do that was to compare them against
// ids DERIVED from the account PID:
//
//	BaasID = HMAC(secret, "baas:"  + pid)[:8]
//	BsDid  = HMAC(secret, "bsdid:" + pid)[:8]
//
// That only works if the console adopts the id *we* minted. A console caches its
// device account in system save 8000000000000010 and presents its own id forever —
// so a console provisioned before the account existed, or provisioned while
// somebody else's account was linked, matches nothing. The lookup 404s, and
// nx-account then falls back to a process-wide "last authenticated account"
// variable (the comment on internalPIDByBsDid says so explicitly). Every console
// therefore converges onto ONE identity: whoever set the server up. Their friend
// code is shown to everybody, and friend requests are sent as them. Reissuing a
// friend code changes the code, not the binding, which is exactly what was
// observed.
//
// # What this file adds
//
//   - a real binding table: the ids a console ACTUALLY presents, stored per
//     account, several per account (one per console/profile);
//   - GET  /internal/whoami — the single resolution entry point, which answers
//     404 and NOTHING ELSE when it cannot resolve. There is no default identity;
//   - POST /internal/bind — records a binding (called by the console link flow);
//   - POST /internal/unbind — removes one.
//
// A binding belongs to exactly one account: binding an id that is already bound
// elsewhere is refused with 409 rather than silently moved, so two consoles can
// never resolve to the same account by accident.
//
// nx-account is not part of this repository. The change it needs is small and is
// specified in the fork's README section and in the splatoon-3 repository's
// docs/FRIENDS.md: resolve with /internal/whoami using the ids from the
// id_token of the request being served, and DELETE the global fallback.

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// NintendoBinding is one console/profile identity bound to an account.
type NintendoBinding struct {
	// BaasID is the BAAS/NSA user id the console presents in the id_token "sub".
	// Per console USER, which is what makes this the right key: two profiles on
	// one console are two players.
	BaasID string `json:"baas_id,omitempty"`
	// BsDid is the device account id ("bs:did"). Per console.
	BsDid string `json:"bs_did,omitempty"`
	// NaID is the Nintendo-Account-shaped id, when the console presents one.
	NaID string `json:"na_id,omitempty"`
	// Label is free text for the operator ("switch-lite", "oled"), never used
	// for resolution.
	Label   string    `json:"label,omitempty"`
	BoundAt time.Time `json:"bound_at"`
	// LastSeen is refreshed on every successful resolution, so an operator can
	// tell a live console from an old one.
	LastSeen time.Time `json:"last_seen,omitempty"`
}

// resolveConsole is the ONE resolution function: it turns the console identity a
// request carries into the Nextendo account that owns it.
//
// Order, most specific first:
//
//  1. an explicit binding on the BAAS/NSA id — per console USER, so it tells two
//     profiles on one console apart;
//  2. an explicit binding on the device id;
//  3. the DERIVED BaasID (a console that adopted the id we minted);
//  4. the DERIVED BsDid.
//
// Anything else returns ErrNotFound. There is deliberately no fifth step: the
// missing fifth step IS the fix. A caller that gets an error must refuse the
// console's request, never fall back to a default, "first" or "last seen" account.
//
// A successful DERIVED match is promoted into the binding table, so the next
// lookup for that console is O(1) and the table self-heals into a complete
// picture of who plays on what.
func (s *server) resolveConsole(baasID, bsDid string) (*Account, string, error) {
	baasID, bsDid = normalizeHexID(baasID), normalizeHexID(bsDid)
	if baasID == "" && bsDid == "" {
		return nil, "", ErrNotFound
	}
	table := openBindings()

	if pid, via, ok := table.Resolve(baasID, bsDid); ok {
		acct, err := s.store.ByPID(pid)
		if err != nil {
			// A binding whose account is gone (deleted account): drop it rather
			// than keep resolving to nothing.
			_ = table.Unbind(pid, baasID, bsDid)
			return nil, "", ErrNotFound
		}
		table.Touch(pid, baasID, bsDid)
		return acct, via, nil
	}

	// Derived ids: the console adopted what we minted. O(accounts), but only on
	// the first request of such a console — it is promoted to a binding below.
	for _, a := range s.store.AllAccounts() {
		a.ensureNintendoIDs()
		switch {
		case baasID != "" && normalizeHexID(a.BaasID) == baasID:
			s.promoteBinding(a.PID, baasID, bsDid, a.NaID)
			return a, "derived:baas", nil
		case bsDid != "" && normalizeHexID(a.BsDid) == bsDid:
			s.promoteBinding(a.PID, baasID, bsDid, a.NaID)
			return a, "derived:bsdid", nil
		}
	}
	return nil, "", ErrNotFound
}

// promoteBinding records a console identity discovered through the derived ids.
// Failure is logged and ignored: it is an optimisation, not a requirement.
func (s *server) promoteBinding(pid uint64, baasID, bsDid, naID string) {
	if _, err := openBindings().Bind(pid, NintendoBinding{
		BaasID: baasID, BsDid: bsDid, NaID: naID, Label: "auto (id dérivé)",
	}); err != nil && err != errBindingTaken {
		log.Printf("[bind] promotion automatique pid=%d échouée : %v", pid, err)
	}
}

// internalWhoami (INTERNAL) resolves the console identity carried by a request
// into the Nextendo account that owns it.
//
//	GET /internal/whoami?baas=<sub>&bsdid=<bs:did>
//	200 {"pid":1800000042,"via":"binding:baas","username":"…","friendCode":"SW-…"}
//	404 {"found":false}
//
// FAIL-CLOSED, and that is the whole point of this endpoint: an unresolvable
// console gets 404 and the caller must refuse the request. It must never be
// turned into a default, a "last seen" or a "first" account — that is the bug
// this file exists to kill.
func (s *server) internalWhoami(w http.ResponseWriter, r *http.Request) {
	if !internalKeyOK(r) {
		writeErr(w, http.StatusUnauthorized, "interne")
		return
	}
	q := r.URL.Query()
	baasID := normalizeHexID(q.Get("baas"))
	bsDid := normalizeHexID(q.Get("bsdid"))
	if baasID == "" && bsDid == "" {
		writeErr(w, http.StatusBadRequest, "baas et/ou bsdid requis")
		return
	}

	acct, via, err := s.resolveConsole(baasID, bsDid)
	if err != nil || acct == nil {
		// The single most important log line of this feature: it says a console
		// reached the server with an identity nobody owns — precisely the case
		// where the old code silently served somebody else's account.
		log.Printf("[whoami] baas=%q bsdid=%q -> AUCUN COMPTE (le client doit être refusé, jamais rattaché à un compte par défaut)", baasID, bsDid)
		writeJSON(w, http.StatusNotFound, map[string]any{"found": false})
		return
	}
	// A console that resolves is a console that is on and online: this is the
	// cheapest, most reliable presence signal we have (see console_presence.go).
	noteConsoleOnline(acct.PID)
	log.Printf("[whoami] baas=%q bsdid=%q -> pid=%d (%s) via %s", baasID, bsDid, acct.PID, acct.Username, via)
	writeJSON(w, http.StatusOK, map[string]any{
		"found":      true,
		"pid":        acct.PID,
		"via":        via,
		"username":   acct.Username,
		"nickname":   displayName(acct),
		"friendCode": acct.FriendCode,
		"baasUserID": acct.BaasID,
		"bsDid":      acct.BsDid,
	})
}

// internalBind (INTERNAL) records the console identity of an account.
//
//	POST /internal/bind
//	{"pid":1800000042,"baas_id":"8ca8d7842f865b2f","bs_did":"581ea786a91f1689","label":"switch-1"}
//
// Called by the console account-link flow with the ids from the token the console
// ACTUALLY presented. That is what makes a console with a pre-existing device
// account work without a factory reset: instead of expecting it to adopt our
// derived id, we learn its own.
//
// 409 when another account already owns one of the ids. Silently moving a
// binding would recreate the bug in a new shape (a console quietly changing
// owner), so it is refused and the operator has to unbind it first.
func (s *server) internalBind(w http.ResponseWriter, r *http.Request) {
	if !internalKeyOK(r) {
		writeErr(w, http.StatusUnauthorized, "interne")
		return
	}
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST attendu")
		return
	}
	var in struct {
		PID    uint64 `json:"pid"`
		BaasID string `json:"baas_id"`
		BsDid  string `json:"bs_did"`
		NaID   string `json:"na_id"`
		Label  string `json:"label"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "json invalide")
		return
	}
	in.BaasID, in.BsDid, in.NaID = normalizeHexID(in.BaasID), normalizeHexID(in.BsDid), normalizeHexID(in.NaID)
	if in.PID == 0 || (in.BaasID == "" && in.BsDid == "") {
		writeErr(w, http.StatusBadRequest, "pid et (baas_id ou bs_did) requis")
		return
	}
	// The account must exist: binding a console to a PID nobody owns would create
	// an identity that resolves to nothing.
	acct, err := s.store.ByPID(in.PID)
	if err != nil {
		writeErr(w, http.StatusNotFound, "compte introuvable")
		return
	}
	created, err := openBindings().Bind(in.PID, NintendoBinding{
		BaasID:  in.BaasID,
		BsDid:   in.BsDid,
		NaID:    in.NaID,
		Label:   clampLabel(in.Label),
		BoundAt: time.Now().UTC(),
	})
	switch {
	case err == errBindingTaken:
		log.Printf("[bind] pid=%d baas=%q bsdid=%q REFUSÉ : déjà lié à un autre compte", in.PID, in.BaasID, in.BsDid)
		writeErr(w, http.StatusConflict, "cette console est déjà liée à un autre compte")
		return
	case err != nil:
		writeErr(w, http.StatusInternalServerError, "erreur")
		return
	}
	log.Printf("[bind] pid=%d (%s) baas=%q bsdid=%q label=%q nouveau=%v", acct.PID, acct.Username, in.BaasID, in.BsDid, in.Label, created)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "created": created, "pid": acct.PID})
}

// internalUnbind (INTERNAL) removes a console binding from an account.
//
//	POST /internal/unbind  {"pid":…, "baas_id":"…", "bs_did":"…"}
//
// Needed to move a console from one account to another (the recovery path for a
// console that was poisoned by the old fallback behaviour).
func (s *server) internalUnbind(w http.ResponseWriter, r *http.Request) {
	if !internalKeyOK(r) {
		writeErr(w, http.StatusUnauthorized, "interne")
		return
	}
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST attendu")
		return
	}
	var in struct {
		PID    uint64 `json:"pid"`
		BaasID string `json:"baas_id"`
		BsDid  string `json:"bs_did"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.PID == 0 {
		writeErr(w, http.StatusBadRequest, "pid requis")
		return
	}
	if err := openBindings().Unbind(in.PID, in.BaasID, in.BsDid); err != nil {
		writeErr(w, http.StatusNotFound, "liaison introuvable")
		return
	}
	log.Printf("[bind] pid=%d liaison retirée (baas=%q bsdid=%q)", in.PID, in.BaasID, in.BsDid)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// internalKeyOK checks the shared internal key the other /internal/* routes use.
// Same rule as the existing handlers: when the key is unset (a co-located
// single-host deployment) the application-layer check is skipped and
// internal_guard.go's source-address check is the only gate.
func internalKeyOK(r *http.Request) bool {
	k := os.Getenv("NEXTENDO_INTERNAL_KEY")
	return k == "" || r.Header.Get("X-Internal-Key") == k
}

// normalizeHexID puts a console id into ONE canonical form, so the same identity
// always maps to the same binding however it was spelled.
//
// This is fiddlier than it looks. A console id is a 64-bit number that appears as
// 16 hex characters in an id_token ("581ea786a91f1689") but in DECIMAL on other
// paths (the console stores it as a u64, and the NEX auth's /api/nsa is called
// with the decimal form). Worse, a short string like "1000" is valid hex AND valid
// decimal. The rule that resolves the ambiguity:
//
//	exactly 16 hex characters  -> hex   (the id_token form is always 16 wide)
//	otherwise parses as decimal -> decimal
//	otherwise parses as hex      -> hex
//	otherwise                    -> kept verbatim (not a number at all)
//
// and the result is always printed as %016x, so "1000", "0x3e8"-style hex and
// "00000000000003e8" all land on the same key.
func normalizeHexID(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return ""
	}
	if len(s) == 16 && isHexID(s) {
		if v, err := strconv.ParseUint(s, 16, 64); err == nil {
			return fmt.Sprintf("%016x", v)
		}
	}
	if v, err := strconv.ParseUint(s, 10, 64); err == nil {
		return fmt.Sprintf("%016x", v)
	}
	if v, err := strconv.ParseUint(s, 16, 64); err == nil {
		return fmt.Sprintf("%016x", v)
	}
	return s
}

// isHexID reports whether s is made of hex digits only.
func isHexID(s string) bool {
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return len(s) > 0
}

// clampLabel bounds the operator label. It comes from a caller and is displayed,
// so it is bounded here rather than trusted.
func clampLabel(s string) string {
	s = strings.TrimSpace(s)
	const max = 48
	if len(s) > max {
		return s[:max]
	}
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			continue
		}
		out = append(out, r)
	}
	return string(out)
}
