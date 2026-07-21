package main

// Protection des routes /internal/* (plan de contrôle : identity, login, resolve, presence…).
//
// Le service expose des routes publiques (/api/*) et des routes de contrôle (/internal/*) sur le
// même port. Les routes /internal/* valident des identifiants et lisent des comptes : elles ne
// doivent JAMAIS être joignables depuis Internet. Plutôt qu'un pare-feu réseau, on applique une
// garde APPLICATIVE.
//
// Deux voies d'autorisation pour /internal/* :
//   1. Source = un conteneur du réseau interne de confiance, mais PAS la passerelle du réseau
//      (un appel arrivant par le port publié apparaît comme la passerelle → considéré Internet).
//   2. Clé interne partagée (X-Internal-Key), pour les appelants légitimes hors réseau. La clé
//      est lue de l'environnement ou d'un fichier, configurable sans recréer le conteneur.
//
// ⚠ On lit RemoteAddr (la vraie source TCP, non falsifiable), JAMAIS X-Forwarded-For (fourni
// par le client, donc spoofable — s'en servir ici serait un contournement trivial).

import (
	"crypto/subtle"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// internalNetRule : un sous-réseau interne de confiance et sa passerelle (= chemin Internet).
type internalNetRule struct {
	net     *net.IPNet
	gateway net.IP
}

var (
	internalGuardOnce sync.Once
	internalKeyCached string
	internalNetRules  []internalNetRule
)

// loadInternalGuard initialise (une fois) la clé et les sous-réseaux de confiance.
//
// Le sous-réseau de confiance par défaut est un EXEMPLE ; configurez le vôtre via
// internal_net.conf (une règle « CIDR GATEWAY » par ligne) et la clé via NEXTENDO_INTERNAL_KEY
// ou internal_key.txt. Sans configuration, seule la voie « clé interne » autorise /internal/*.
func loadInternalGuard() {
	internalGuardOnce.Do(func() {
		// Clé : env si posé (souplesse), sinon fichier /data/internal_key.txt.
		internalKeyCached = strings.TrimSpace(os.Getenv("NEXTENDO_INTERNAL_KEY"))
		if internalKeyCached == "" {
			if b, err := os.ReadFile(internalDataPath("internal_key.txt")); err == nil {
				internalKeyCached = strings.TrimSpace(string(b))
			}
		}

		rules := "10.0.0.0/24 10.0.0.1"
		if b, err := os.ReadFile(internalDataPath("internal_net.conf")); err == nil && len(strings.TrimSpace(string(b))) > 0 {
			rules = string(b)
		}
		for _, line := range strings.Split(rules, "\n") {
			f := strings.Fields(line)
			if len(f) < 1 {
				continue
			}
			_, n, err := net.ParseCIDR(f[0])
			if err != nil {
				continue
			}
			r := internalNetRule{net: n}
			if len(f) >= 2 {
				r.gateway = net.ParseIP(f[1])
			}
			internalNetRules = append(internalNetRules, r)
		}
	})
}

// internalDataPath renvoie <dataDir>/name. dataDir = le CWD (/data dans le conteneur), là où
// vivent déjà accounts.json etc.
func internalDataPath(name string) string {
	if d := os.Getenv("NEXTENDO_DATA_DIR"); d != "" {
		return filepath.Join(d, name)
	}
	return name
}

// remoteIP renvoie l'IP source TCP RÉELLE de la requête (jamais X-Forwarded-For).
func remoteIP(r *http.Request) net.IP {
	host := r.RemoteAddr
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return net.ParseIP(host)
}

// internalAllowed : la requête peut-elle atteindre une route /internal/* ?
func internalAllowed(r *http.Request) bool {
	loadInternalGuard()
	return internalAllowedWith(r, internalKeyCached, internalNetRules)
}

// internalAllowedWith porte la logique pure (clé + règles explicites), pour être testable sans
// dépendre du chargement global.
func internalAllowedWith(r *http.Request, key string, rules []internalNetRule) bool {
	// Voie 2 : clé interne partagée (appelants légitimes hors du réseau interne).
	if key != "" && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Internal-Key")), []byte(key)) == 1 {
		return true
	}

	// Voie 1 : source = un conteneur du réseau interne, mais pas la passerelle (= pas Internet).
	// On lit RemoteAddr (source TCP réelle), jamais X-Forwarded-For.
	ip := remoteIP(r)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return true // process local (diagnostic depuis le conteneur lui-même)
	}
	for _, rule := range rules {
		if rule.net != nil && rule.net.Contains(ip) {
			if rule.gateway != nil && ip.Equal(rule.gateway) {
				return false // vient du port publié -> Internet -> refusé (sauf clé)
			}
			return true
		}
	}
	return false
}

// internalOnly enveloppe un handler /internal/* de la garde. Réponse 403 muette sinon (on ne
// révèle pas l'existence de la route), avec une trace serveur pour repérer un blocage à tort.
func internalOnly(name string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !internalAllowed(r) {
			log.Printf("[internal-guard] REFUSÉ %s depuis %s (source non interne, clé absente/incorrecte)", name, r.RemoteAddr)
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		h(w, r)
	}
}
