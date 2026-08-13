package main

// Table pays -> nx-account, pour le drapeau affiché en jeu.
//
// LA CHAÎNE COMPLÈTE, telle qu'elle existe déjà côté console :
//   1. le joueur choisit son pays sur le site        (country.go, ce serveur)
//   2. nx-account le met dans l'objet utilisateur BAAS, champ "country"
//   3. Mario Kart le lit au démarrage, le range dans sa fiche joueur, et
//      l'ENVOIE aux autres joueurs, qui affichent le drapeau
//
// nx-account ne peut pas lire nos comptes : il vit dans un autre conteneur et
// ne voit pas accounts.json. Il relit donc une simple table JSON, décrite dans
// son country_store.go, indexée par baasUserID. Ce fichier la produit.
//
// Pourquoi baasUserID et pas le PID : c'est l'identifiant présent dans TOUS les
// handlers BAAS de nx-account, celui qu'il a sous la main au moment de bâtir
// l'objet utilisateur. Le PID n'y est pas toujours.
//
// Écriture au démarrage puis à chaque changement de pays. Pas de minuterie :
// un compte qui ne change pas de pays n'a aucune raison de réécrire un fichier.

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

var countryMapMu sync.Mutex

// countryMapPath : à côté de accounts.json, donc dans le répertoire que
// nx-account monte sur /data. Surchargeable pour les tests.
func countryMapPath() string {
	if v := strings.TrimSpace(os.Getenv("NEXTENDO_COUNTRY_MAP_OUT")); v != "" {
		return v
	}
	data := strings.TrimSpace(os.Getenv("NEXTENDO_DATA"))
	if data == "" {
		data = "accounts.json"
	}
	return filepath.Join(filepath.Dir(data), "country_map.json")
}

// writeCountryMap régénère la table depuis les comptes. Silencieux en cas
// d'échec d'écriture : un drapeau manquant ne doit pas faire tomber le serveur.
func writeCountryMap(store Store) {
	countryMapMu.Lock()
	defer countryMapMu.Unlock()

	out := map[string]string{}
	for _, a := range store.AllAccounts() {
		if a == nil || a.Country == "" || a.PID == 0 {
			continue
		}
		// INDEXE PAR PID, pas par baasUserID : nx-account fabrique un identifiant
		// BAAS *par appareil* a l inscription, celui stocke dans le compte n est
		// donc PAS celui qu il manipule a l execution (verifie dans ses journaux :
		// le BaasID du compte n y apparait jamais). Le PID, lui, est connu des
		// deux cotes.
		out[strconv.FormatUint(a.PID, 10)] = a.Country
	}

	b, err := json.Marshal(out)
	if err != nil {
		return
	}
	p := countryMapPath()
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0644); err != nil { // lisible par nx-account
		log.Printf("[country] écriture de %s : %v", tmp, err)
		return
	}
	if err := os.Rename(tmp, p); err != nil { // remplacement atomique
		log.Printf("[country] remplacement de %s : %v", p, err)
		return
	}
	log.Printf("[country] table écrite : %d compte(s) avec un pays -> %s", len(out), p)
}
