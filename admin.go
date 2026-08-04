package main

// Gel de relance ("launch freeze"). Pendant la finalisation de la nouvelle version de
// Nextendo, l'opérateur peut :
//   - FERMER les inscriptions (register + guest) sans redéploiement, via
//     NEXTENDO_REGISTRATION=closed dans nextendo.env ;
//   - FERMER 100 % des comptes SAUF un (le sien), via NEXTENDO_LOCKDOWN_KEEP_PID=<pid> —
//     appliqué AU DÉMARRAGE, dans le process (aucune surface réseau). Les autres comptes
//     ne peuvent plus se connecter au site NI jouer en ligne (online-check).
// Tout est RÉVERSIBLE : enlever la variable d'env rouvre ; NEXTENDO_ENABLE_ALL=1 réactive
// tous les comptes au prochain démarrage.
//
// On N'EXPOSE PAS d'endpoint HTTP d'admin : le port du conteneur est publié en 0.0.0.0 et
// docker-proxy masque l'IP source, donc un garde « loopback only » serait contournable.
// Le gel passe donc uniquement par la config (env), lue au boot.

import (
	"log"
	"net/http"
	"os"
	"strconv"
)

// registrationOpen reports whether NEW account creation (register + guest) is allowed.
// Default OPEN (rétro-compatible) ; le gel la ferme via NEXTENDO_REGISTRATION=closed.
func registrationOpen() bool {
	return os.Getenv("NEXTENDO_REGISTRATION") != "closed"
}

// ---------------------------------------------------------------------------
// Store: opérations de gel (implémentées sur jsonStore)
// ---------------------------------------------------------------------------

// SetDisabled ferme/rouvre UN compte.
func (s *jsonStore) SetDisabled(id int64, disabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.Accts[id]
	if !ok {
		return ErrNotFound
	}
	a.Disabled = disabled
	return s.persist()
}

// LockdownExcept ferme TOUS les comptes sauf keepPID. Le compte conservé est aussi
// force-vérifié + réactivé (sinon le gate e-mail #6 verrouillerait l'opérateur, car son
// adresse @nextendo.net ne peut pas recevoir le mail de vérification). Idempotent.
// Retourne le nombre de comptes nouvellement désactivés.
func (s *jsonStore) LockdownExcept(keepPID uint64) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, a := range s.Accts {
		if a.PID == keepPID {
			a.Disabled = false
			a.EmailVerified = true // l'opérateur garde l'accès en ligne (son e-mail ne peut être vérifié par lien)
			// Tous les AUTRES comptes sont fermés : sa liste d'amis (des comptes beta) est vidée
			// pour repartir sur une base propre. Idempotent.
			a.Friends = nil
			a.FriendRequests = nil
			a.Blocked = nil
			continue
		}
		if !a.Disabled {
			a.Disabled = true
			n++
		}
	}
	return n, s.persist()
}

// EnableAll annule le gel : rouvre tous les comptes. Retourne le nombre réactivé.
func (s *jsonStore) EnableAll() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, a := range s.Accts {
		if a.Disabled {
			a.Disabled = false
			n++
		}
	}
	return n, s.persist()
}

// applyLaunchFreeze applies the env-driven freeze at startup (in-process, no HTTP).
// NEXTENDO_LOCKDOWN_KEEP_PID=<pid>  → ferme tout sauf ce PID (et le vérifie/réactive).
// NEXTENDO_ENABLE_ALL=1             → réactive tous les comptes (annule le gel).
func applyLaunchFreeze(store Store) {
	if v := os.Getenv("NEXTENDO_LOCKDOWN_KEEP_PID"); v != "" {
		if pid, err := strconv.ParseUint(v, 10, 64); err == nil && pid != 0 {
			if n, err := store.LockdownExcept(pid); err != nil {
				log.Printf("[freeze] LockdownExcept(%d) a échoué : %v", pid, err)
			} else {
				log.Printf("[freeze] démarrage : %d comptes fermés, PID %d conservé (vérifié+actif)", n, pid)
			}
		} else {
			log.Printf("[freeze] NEXTENDO_LOCKDOWN_KEEP_PID=%q invalide — ignoré", v)
		}
	}
	if os.Getenv("NEXTENDO_ENABLE_ALL") == "1" {
		if n, err := store.EnableAll(); err != nil {
			log.Printf("[freeze] EnableAll a échoué : %v", err)
		} else {
			log.Printf("[freeze] ENABLE_ALL : %d comptes réactivés", n)
		}
	}
}

// siteConfig est l'état PUBLIC du site : le front l'appelle pour afficher/masquer le
// formulaire d'inscription pendant le gel. GET /api/site-config
func (s *server) siteConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"registration_open": registrationOpen()})
}
