package main

// Token revocation, loaded from configuration instead of copy-pasted per repository.
//
// # The problem this fixes
//
// A "nx2." login token is an HMAC over "pid.username.expiry" with a 30-day life. When one
// leaks there is no way to invalidate it short of rotating the shared secret — which would
// log out every player and change every account's derived BAAS/NA ids — so each server
// carries a denylist of leaked payloads, checked even when the signature is valid.
//
// That denylist was a map literal duplicated in nine components (the account server and
// every game server), with a comment asking future maintainers to keep them in sync. They
// did not stay in sync: the payload leaked by the 1.6.5 Windows release was revoked in
// three of them, and the other six still accepted it. A leaked credential that works on
// most of the fleet is not revoked in any meaningful sense — and via the
// "one place at a time" gate, whoever holds it can also keep the real owner offline.
//
// # The fix
//
// Keep the built-in entries (so this repository alone is still correct), and ALSO load
// entries from configuration:
//
//	NEXTENDO_REVOKED_TOKENS       payloads separated by commas, semicolons or newlines
//	NEXTENDO_REVOKED_TOKENS_FILE  a file with one payload per line ("#" starts a comment)
//
// Revoking the next leak is then a config change deployed to every server, not nine source
// edits that can drift again. Both sources are merged at start-up, before the listener
// accepts anything, so the login path still reads a map nobody writes to afterwards.
//
// A payload is the DECODED middle segment of the token: "1800000006.Kazuu.1787343209".

import (
	"fmt"
	"os"
	"strings"
)

func init() { loadRevokedPayloads() }

// loadRevokedPayloads merges the configured denylist into revokedNexPayloads.
func loadRevokedPayloads() {
	added := 0
	for _, p := range parseRevokedList(os.Getenv("NEXTENDO_REVOKED_TOKENS")) {
		if !revokedNexPayloads[p] {
			revokedNexPayloads[p] = true
			added++
		}
	}
	if path := os.Getenv("NEXTENDO_REVOKED_TOKENS_FILE"); path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			// Loud, because a denylist that silently failed to load is worse than no
			// denylist: the operator believes a leaked token is dead when it is not.
			fmt.Printf("[Auth] ATTENTION : liste de révocation %s illisible (%v) — les jetons qu'elle contient restent ACCEPTÉS\n", path, err)
		} else {
			for _, p := range parseRevokedList(string(b)) {
				if !revokedNexPayloads[p] {
					revokedNexPayloads[p] = true
					added++
				}
			}
		}
	}
	if total := len(revokedNexPayloads); total > 0 {
		fmt.Printf("[Auth] %d jeton(s) nx2 révoqué(s) (%d depuis la configuration)\n", total, added)
	}
}

// parseRevokedList splits a denylist on newlines, commas and semicolons, dropping blanks
// and "#" comments so a file can document why each entry is there.
func parseRevokedList(raw string) []string {
	var out []string
	for _, line := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ',' || r == ';'
	}) {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		out = append(out, line)
	}
	return out
}
