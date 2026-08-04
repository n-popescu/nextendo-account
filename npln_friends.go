package main

// NPLN friend bridge — exposes a Nextendo account's friend graph to the npln-s3
// server (Splatoon 3 / NPLN) in the identity shape NPLN uses, so S3 shows the SAME
// unified Nextendo friends as the NEX games (S2/MK8).
//
// A Nextendo account (its NEX PID) maps deterministically to an NPLN identity:
//   - the account-id hex (16 hex chars, e.g. "ef43faf025ebc94e") = its BAAS/NSA id
//   - the NPLN user id "u-<base32>"     (e.g. "u-qoahvkaf4bclq6uqu6in")
// Both derive from the PID (like the na/baas ids), so every NPLN service — auth,
// friends, presence, cloud-save — agrees on the same identity without shared state.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"net/http"
	"os"
	"strconv"
	"strings"
)

// npln user ids are lowercase base32 (Crockford-ish alphabet the console uses).
var nplnUserB32 = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// nplnAccountHex is the account's NPLN/BAAS account id — reuses the same derivation
// as the BAAS id (16 hex chars).
func nplnAccountHex(pid uint64) string { return deriveID(sessionSecret, "baas", pid) }

// nplnUserID is the account's stable NPLN user id "u-<base32>".
func nplnUserID(pid uint64) string {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], pid)
	h := hmac.New(sha256.New, sessionSecret)
	h.Write([]byte("npln-user:"))
	h.Write(b[:])
	return "u-" + nplnUserB32.EncodeToString(h.Sum(nil)[:12])
}

type nplnFriendEntry struct {
	PID        uint64         `json:"pid"`
	UserID     string         `json:"user_id"`
	AccountHex string         `json:"account_hex"`
	Name       string         `json:"name"`
	Presence   map[string]any `json:"presence"`
}

func nplnPresence(pid uint64) map[string]any {
	if p, ok := getPresence(pid); ok {
		return map[string]any{"status": p.Status, "app_field": p.AppField, "app_id": p.AppID, "app_detail": p.AppDetail}
	}
	return map[string]any{"status": 0, "app_field": "", "app_id": "", "app_detail": ""}
}

// internalNplnFriends: GET /internal/npln-friends?pid=<accountPID> -> the account's
// NPLN identity, a verified-account gate signal, and its friends (each with their NPLN
// identity + real-time presence). Consumed by npln-s3's Friends/Presence services to
// build SubscribeFriendUsersResponse. Server-to-server (no session token).
func (s *server) internalNplnFriends(w http.ResponseWriter, r *http.Request) {
	// Cet endpoint n'avait AUCUNE garde, contrairement à ses voisins. Il expose le graphe
	// d'amis ET le account_hex (l'identifiant NSA), qui sert de credential d'identité aux
	// serveurs de jeu : le divulguer permettait de jouer en ligne à la place du compte.
	if k := os.Getenv("NEXTENDO_INTERNAL_KEY"); k != "" && r.Header.Get("X-Internal-Key") != k {
		http.Error(w, "interne", http.StatusUnauthorized)
		return
	}
	pid, err := strconv.ParseUint(strings.TrimSpace(r.URL.Query().Get("pid")), 10, 64)
	if err != nil || pid == 0 {
		http.Error(w, "bad pid", http.StatusBadRequest)
		return
	}
	acct, err := s.store.ByPID(pid)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	friends := make([]nplnFriendEntry, 0, len(acct.Friends))
	for _, fpid := range acct.Friends {
		f, err := s.store.ByPID(fpid)
		if err != nil {
			continue
		}
		friends = append(friends, nplnFriendEntry{
			PID:        fpid,
			UserID:     nplnUserID(fpid),
			AccountHex: nplnAccountHex(fpid),
			Name:       displayName(f),
			Presence:   nplnPresence(fpid),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"pid":         pid,
		"user_id":     nplnUserID(pid),
		"account_hex": nplnAccountHex(pid),
		// The online account gate: online is allowed only for a verified, non-frozen
		// Nextendo account (fail-closed identity — same rule as the NEX games).
		"verified": acct.EmailVerified && !acct.Disabled,
		"friends":  friends,
	})
}
