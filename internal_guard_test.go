package main

import (
	"net"
	"net/http"
	"testing"
)

// La garde /internal est le seul rempart une fois le port publié rouvert au homebrew. Ce test fige son
// contrat : un conteneur du réseau interne passe SANS clé, la passerelle (= Internet via le port
// publié) est refusée sauf clé, et X-Forwarded-For ne peut RIEN contourner.
func TestInternalGuard(t *testing.T) {
	_, internalNet, _ := net.ParseCIDR("10.0.0.0/24")
	rules := []internalNetRule{{net: internalNet, gateway: net.ParseIP("10.0.0.1")}}
	const key = "s3cr3t-interne"

	req := func(remote, xff, hdrKey string) *http.Request {
		r := &http.Request{RemoteAddr: remote, Header: http.Header{}}
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		if hdrKey != "" {
			r.Header.Set("X-Internal-Key", hdrKey)
		}
		return r
	}

	cases := []struct {
		name  string
		r     *http.Request
		allow bool
	}{
		{"conteneur interne (10.0.0.26) sans clé -> OK", req("10.0.0.26:5000", "", ""), true},
		{"passerelle (Internet via le port publié) sans clé -> REFUS", req("10.0.0.1:5000", "", ""), false},
		{"passerelle AVEC la bonne clé (external caller) -> OK", req("10.0.0.1:5000", "", key), true},
		{"IP publique quelconque sans clé -> REFUS", req("203.0.113.9:443", "", ""), false},
		{"IP publique AVEC clé -> OK", req("203.0.113.9:443", "", key), true},
		{"clé ERRONÉE -> REFUS", req("203.0.113.9:443", "", "mauvaise"), false},
		{"loopback -> OK", req("127.0.0.1:5000", "", ""), true},
		// L'ATTAQUE : source réelle = passerelle (Internet), mais X-Forwarded-For prétend être un
		// conteneur interne. Doit rester REFUSÉ (on ignore X-Forwarded-For).
		{"spoof X-Forwarded-For depuis la passerelle -> REFUS", req("10.0.0.1:5000", "10.0.0.26", ""), false},
	}

	for _, c := range cases {
		if got := internalAllowedWith(c.r, key, rules); got != c.allow {
			t.Errorf("%s : got allow=%v, want %v", c.name, got, c.allow)
		}
	}
}
