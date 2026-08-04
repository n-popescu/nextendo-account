package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

// signNexPayload mints an nx2 token for an ARBITRARY payload string. signNexToken always sets
// expiry = now+30d, so it can't reproduce the exact leaked payload — this helper can.
func signNexPayload(payload string) string {
	mac := hmac.New(sha256.New, sessionSecret)
	mac.Write([]byte("nex:" + payload))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return "nx2." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + sig
}

// TestVerifyNexToken_RevokedPayloadRejected locks in the 2026-07-22 fix: the nex_token leaked by
// the 1.6.5-win release (its portable/nextendo_account.txt shipped a live session) must be refused
// even though its HMAC is valid, while a fresh token for the SAME account keeps working (i.e. the
// revocation is surgical, not a whole-account block).
func TestVerifyNexToken_RevokedPayloadRejected(t *testing.T) {
	if len(sessionSecret) == 0 {
		sessionSecret = []byte("test-session-secret-not-for-prod!")
	}

	const leaked = "1800000006.Kazuu.1787343209" // exact payload from the leaked token
	if _, ok := verifyNexToken(signNexPayload(leaked)); ok {
		t.Fatalf("le token fuité %q DOIT être rejeté par la révocation (signature pourtant valide)", leaked)
	}

	// A fresh token for the same account (far-future expiry, NOT in the denylist) stays valid,
	// proving Kazuu can simply re-login and the account isn't globally locked out.
	const fresh = "1800000006.Kazuu.4102444800" // year 2100
	pid, ok := verifyNexToken(signNexPayload(fresh))
	if !ok || pid != 1800000006 {
		t.Fatalf("un nouveau token pour le même compte doit rester valide (ok=%v pid=%d)", ok, pid)
	}
}
