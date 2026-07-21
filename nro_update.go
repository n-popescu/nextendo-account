package main

// Auto-mise a jour du homebrew Nextendo (.nro).
//   GET /api/nro/latest   -> {"version":N,"size":M,"notes":"..."}
//   GET /api/nro/download -> le binaire nextendo.nro
// Le .nro et sa version sont dans nroDir (nro/version.txt, nro/notes.txt, nro/nextendo.nro).

import (
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

var nroDir = getenvNro("NEXTENDO_NRO_DIR", "nro")

func getenvNro(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func (s *server) nro(w http.ResponseWriter, r *http.Request) {
	switch {
	case strings.HasSuffix(r.URL.Path, "/latest"):
		version := 0
		if b, err := os.ReadFile(filepath.Join(nroDir, "version.txt")); err == nil {
			if n, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil {
				version = n
			}
		}
		notes := ""
		if b, err := os.ReadFile(filepath.Join(nroDir, "notes.txt")); err == nil {
			notes = strings.TrimSpace(string(b))
		}
		// [Audit #1] On accompagne la version d'une empreinte + signature : un client qui les
		// vérifie ne peut plus se faire refiler un binaire substitué de même taille en HTTP clair.
		// Champs additifs — les clients actuels (qui ne lisent que version/size) les ignorent.
		out := map[string]any{"version": version, "notes": notes}
		if b, err := os.ReadFile(filepath.Join(nroDir, "nextendo.nro")); err == nil {
			out["size"] = int64(len(b))
			out["sha256"] = sha256Hex(b)
			if sig := signBlob(b); sig != "" {
				out["sig"] = sig
				out["sig_alg"] = "ed25519"
				out["pubkey"] = signingPubKeyB64()
			}
		}
		writeJSON(w, http.StatusOK, out)

	case strings.HasSuffix(r.URL.Path, "/download"):
		// Lu en mémoire (le .nro fait quelques Mo) pour pouvoir signer les octets EXACTS servis
		// et exposer l'empreinte/signature en en-têtes, sans divergence possible avec /latest.
		b, err := os.ReadFile(filepath.Join(nroDir, "nextendo.nro"))
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(len(b)))
		w.Header().Set("X-Nextendo-SHA256", sha256Hex(b))
		if sig := signBlob(b); sig != "" {
			w.Header().Set("X-Nextendo-Signature", sig)
			w.Header().Set("X-Nextendo-Signature-Alg", "ed25519")
		}
		w.Header().Set("Connection", "close")
		_, _ = w.Write(b)

	case strings.HasSuffix(r.URL.Path, "/pubkey"):
		// La clé publique à épingler côté client (le jour où un client vérifie la signature).
		writeJSON(w, http.StatusOK, map[string]any{"alg": "ed25519", "pubkey": signingPubKeyB64()})

	default:
		w.WriteHeader(http.StatusNotFound)
	}
}
