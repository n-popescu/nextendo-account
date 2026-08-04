package main

// [Audit Prelude #1/#2/#6] Intégrité VÉRIFIABLE des artefacts servis au homebrew.
//
// Le canal de MAJ ne validait que la TAILLE de ce qu'il téléchargeait. Sur du HTTP en clair,
// un homme du milieu substitue n'importe quel binaire de même taille sans être détecté — c'est
// la faille critique #1 (et #6 pour le second canal BCAT). Le serveur fournit désormais, pour
// chaque artefact :
//   - un SHA-256    : détecte la corruption et une substitution triviale ;
//   - une signature Ed25519 : détecte l'ALTÉRATION même par un MITM actif, à condition que le
//     client ÉPINGLE la clé publique.
//
// Honnêteté sur la portée : la clé vit sur le serveur. Elle défait un MITM réseau (le cas de
// l'audit sur le HTTP clair), mais PAS une compromission du serveur lui-même (audit #7) — ça,
// seule une clé épinglée hors-ligne dans le client le règle, et le client ne nous appartient
// plus. Côté serveur, produire la preuve est le maximum possible ; la vérifier revient au client.

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var (
	signOnce sync.Once
	signKey  ed25519.PrivateKey
)

// signKeyPath : NEXTENDO_SIGN_KEY si posé, sinon <nroDir>/sign_ed25519.key.
func signKeyPath() string {
	if p := os.Getenv("NEXTENDO_SIGN_KEY"); p != "" {
		return p
	}
	return filepath.Join(nroDir, "sign_ed25519.key")
}

// signingKey charge la clé Ed25519 privée (64 octets bruts ou 32 de seed, en base64 ou hex).
// Absente -> on en GÉNÈRE une et on la persiste (perms 0600) pour que la signature marche
// d'emblée : contre un MITM réseau, une clé auto-générée côté serveur suffit ; l'épinglage
// hors-ligne (contre la compromission serveur) est un choix produit distinct.
func signingKey() ed25519.PrivateKey {
	signOnce.Do(func() {
		path := signKeyPath()
		if b, err := os.ReadFile(path); err == nil {
			switch raw := decodeKeyBytes(strings.TrimSpace(string(b))); len(raw) {
			case ed25519.PrivateKeySize:
				signKey = ed25519.PrivateKey(raw)
			case ed25519.SeedSize:
				signKey = ed25519.NewKeyFromSeed(raw)
			default:
				log.Printf("[sign] clé %s invalide (%d octets) : signature désactivée, SHA-256 seul", path, len(raw))
				return
			}
			log.Printf("[sign] signature Ed25519 active (clé publique %s)",
				base64.StdEncoding.EncodeToString(signKey.Public().(ed25519.PublicKey)))
			return
		}
		// Pas de clé : en générer une et la poser à côté.
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			log.Printf("[sign] génération de clé impossible : %v (SHA-256 seul)", err)
			return
		}
		enc := base64.StdEncoding.EncodeToString(priv)
		if err := os.WriteFile(path, []byte(enc+"\n"), 0o600); err != nil {
			log.Printf("[sign] clé générée mais non persistée (%v) : elle changera au prochain boot", err)
		}
		signKey = priv
		log.Printf("[sign] clé Ed25519 GÉNÉRÉE et posée dans %s (clé publique %s)",
			path, base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)))
	})
	return signKey
}

func decodeKeyBytes(s string) []byte {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && (len(b) == ed25519.SeedSize || len(b) == ed25519.PrivateKeySize) {
		return b
	}
	if b, err := hex.DecodeString(s); err == nil {
		return b
	}
	return nil
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// signBlob : signature base64 de b, ou "" si aucune clé.
func signBlob(b []byte) string {
	if k := signingKey(); k != nil {
		return base64.StdEncoding.EncodeToString(ed25519.Sign(k, b))
	}
	return ""
}

// signingPubKeyB64 : clé publique base64, ou "" si aucune clé (à épingler côté client).
func signingPubKeyB64() string {
	if k := signingKey(); k != nil {
		return base64.StdEncoding.EncodeToString(k.Public().(ed25519.PublicKey))
	}
	return ""
}
