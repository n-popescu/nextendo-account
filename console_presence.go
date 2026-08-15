package main

// Console presence — the other half of the fix for "friends are never online".
//
// # The bug this exists for
//
// presence.go holds an in-memory presence table with a 90-second TTL, and it had
// exactly two writers:
//
//	POST /api/presence          the emulator fork, around private-battle hosting
//	POST /internal/presence-batch  a NEX game server, for players INSIDE that game
//
// Nothing reported a console that is simply on and online: sitting in the Home
// Menu, in a game with no Nextendo server, or in a menu before matchmaking. The
// Home Menu friend list is exactly where players look at each other's status, so
// the normal state of a Switch friend was "offline" — the reported symptom.
//
// nx-account (the Switch-facing server) DOES see that presence, but this server
// gave it no way to write it: /api/presence needs a user bearer token, which a
// server-to-server component does not have, and presence-batch is shaped for
// "these PIDs are in this game".
//
// # What this file adds
//
//	POST /internal/presence   a single-account presence write for an internal caller
//	noteConsoleOnline(pid)     called on every successful console identity
//	                           resolution, because a console that polls its friend
//	                           list is online by definition
//
// The console presence uses a LONGER TTL than a game presence: a console polls
// less often than a game reports, and 90 seconds would make friends flicker.
// A stronger, fresher presence (status 2 = playing) is never downgraded by it.

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
)

// Presence status values, as nn::friends and the NPLN bridge use them.
const (
	presenceStatusOffline = 0
	presenceStatusOnline  = 1
	presenceStatusPlaying = 2
)

// consolePresenceTTL is how long a console counts as online after we last heard
// from it. Configurable because it trades responsiveness (a friend going offline)
// against flicker (a console that polls slowly), and the right value depends on
// how chatty the deployment's consoles are.
func consolePresenceTTL() time.Duration {
	if v := os.Getenv("NEXTENDO_CONSOLE_PRESENCE_TTL"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return time.Duration(n) * time.Second
		}
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return 5 * time.Minute
}

// consoleOnline remembers the last time a console was heard from, per account.
// Kept beside the main presence table (rather than inside it) so it can have its
// own TTL and can never overwrite a richer game presence.
var consoleOnline = struct {
	mu   sync.Mutex
	seen map[uint64]time.Time
}{seen: map[uint64]time.Time{}}

// noteConsoleOnline records that we just served an authenticated request for this
// account's console.
//
// Called from the identity endpoints (/internal/identity, /internal/pid-by-bsdid,
// /internal/whoami, /internal/login). Those are called by nx-account on the
// console's behalf, so reaching them IS proof the console is on and connected —
// the cheapest reliable presence signal available, and it needs no change on the
// nx-account side at all.
func noteConsoleOnline(pid uint64) {
	if pid == 0 {
		return
	}
	consoleOnline.mu.Lock()
	consoleOnline.seen[pid] = time.Now()
	// Bounded: a flood of unknown PIDs must not grow this table without end.
	if len(consoleOnline.seen) > 20000 {
		cutoff := time.Now().Add(-consolePresenceTTL())
		for k, t := range consoleOnline.seen {
			if t.Before(cutoff) {
				delete(consoleOnline.seen, k)
			}
		}
	}
	consoleOnline.mu.Unlock()

	// Publish it as a real presence so every existing consumer — the Switch
	// friend list, the website, the NPLN bridge — sees it, but never downgrade a
	// fresher "playing" presence to a plain "online".
	if p, ok := getPresence(pid); ok && p.Status > presenceStatusOnline {
		return
	}
	setPresence(pid, presenceStatusOnline, "", "", "")
}

// consoleIsOnline reports whether the account's console was heard from within the
// console TTL. Used by the presence view so a console that stopped polling is
// dropped even if the main presence table has not expired yet.
func consoleIsOnline(pid uint64) bool {
	consoleOnline.mu.Lock()
	t, ok := consoleOnline.seen[pid]
	consoleOnline.mu.Unlock()
	return ok && time.Since(t) < consolePresenceTTL()
}

// clearPresence removes a presence immediately instead of waiting for the TTL.
//
// Lives here rather than in presence.go so this fork does not touch that file:
// same package, so it reaches the table directly. Used when a console reports
// that it went offline — a friend list that takes 90 seconds to notice somebody
// left looks broken.
func clearPresence(pid uint64) {
	presenceMu.Lock()
	delete(presenceByPID, pid)
	presenceMu.Unlock()
}

// internalPresence (INTERNAL) writes ONE account's presence.
//
//	POST /internal/presence
//	{"pid":1800000042,"status":1,"app_id":"0100c2500fc20000","app_field":"<base64>","app_detail":""}
//
// This is what nx-account calls when the console reports its presence
// (nn::friends UpdateUserPresence). It is the server-to-server counterpart of
// /api/presence, which needs a user token nx-account does not have.
//
// status 0 clears the presence immediately, so "went offline" is instant rather
// than a TTL expiry — a friend list that takes 90 seconds to notice somebody left
// looks broken.
func (s *server) internalPresence(w http.ResponseWriter, r *http.Request) {
	if !internalKeyOK(r) {
		writeErr(w, http.StatusUnauthorized, "interne")
		return
	}
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST attendu")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var in struct {
		PID       uint64 `json:"pid"`
		Status    int    `json:"status"`
		AppID     string `json:"app_id"`
		AppField  string `json:"app_field"`
		AppDetail string `json:"app_detail"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.PID == 0 {
		writeErr(w, http.StatusBadRequest, "pid requis")
		return
	}
	// The PID must be a real account: an unchecked write would let an internal
	// caller fill the presence table with anything.
	if _, err := s.store.ByPID(in.PID); err != nil {
		writeErr(w, http.StatusNotFound, "compte introuvable")
		return
	}
	if in.Status == presenceStatusOffline {
		clearPresence(in.PID)
		consoleOnline.mu.Lock()
		delete(consoleOnline.seen, in.PID)
		consoleOnline.mu.Unlock()
		log.Printf("[presence] pid=%d hors ligne (poussé par la console)", in.PID)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}
	setPresence(in.PID, in.Status, in.AppField, in.AppID, clampDetail(in.AppDetail))
	noteConsoleOnline(in.PID)
	log.Printf("[presence] pid=%d status=%d app=%q (poussé par la console)", in.PID, in.Status, in.AppID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
