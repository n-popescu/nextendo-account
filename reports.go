package main

// Rapports de bug envoyés depuis l'émulateur.
//
// Pourquoi ça existe : jusqu'ici un bug arrivait sous forme de capture d'écran sur Discord
// ("j'ai eu 2618-0006"), et il fallait ensuite corréler à la main les logs de trois serveurs
// pour retrouver la session concernée. Le joueur, lui, a le code d'erreur ET le log sous les
// yeux au moment où ça casse. Ce chemin les récupère au moment exact, avec de quoi retrouver
// la session côté serveur (PID + horodatage).
//
// Rétention volontairement bornée : c'est une boîte de réception de diagnostic, pas un
// stockage. Les rapports vieux ou en trop sont jetés — un rapport d'il y a une semaine ne
// correspond plus à aucun log serveur de toute façon.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

type bugReport struct {
	ID       string `json:"id"`
	PID      uint64 `json:"pid"`
	Nickname string `json:"nickname"`

	// Le pseudo Discord, figé au moment du signalement : c'est par là qu'on répond au
	// joueur, et le chercher plus tard échouerait s'il a délié son compte entre-temps.
	// L'id est gardé aussi — deux personnes peuvent porter le même pseudo Discord.
	Discord   string `json:"discord,omitempty"`
	DiscordID string `json:"discord_id,omitempty"`

	ErrorCode string    `json:"error_code"` // "2618-0006" — vide si envoyé depuis le menu
	Game      string    `json:"game"`       // title id du jeu courant
	Version   string    `json:"version"`    // version de l'émulateur
	Comment   string    `json:"comment"`    // ce que le joueur faisait, dans ses mots
	Log       string    `json:"log"`        // fin du log de l'émulateur
	CreatedAt time.Time `json:"created_at"`
	Handled   bool      `json:"handled"`
}

const (
	// Assez pour la fin d'une session (les ~200 dernières lignes), pas assez pour qu'un
	// client puisse nous envoyer un fichier.
	maxReportLog = 128 * 1024
	maxComment   = 500

	// Bornes de la boîte de réception.
	maxReports    = 200
	reportMaxAge  = 7 * 24 * time.Hour
	reportPerHour = 5 // par compte : un bug qui boucle ne doit pas noyer les autres
)

var (
	reportsMu sync.Mutex
	reports   []bugReport
	reportSeq uint64
)

// POST /api/report {error_code, game, version, comment, log}
// Auth : le jeton du joueur (même que /api/friends). Le PID vient du compte, jamais du corps
// de la requête — sinon n'importe qui pourrait signaler au nom d'un autre.
func (s *server) report(w http.ResponseWriter, r *http.Request) {
	acct, ok := s.accountFromBearer(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "Session invalide ou expirée.")
		return
	}
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST attendu")
		return
	}

	// Le quota AVANT de lire quoi que ce soit. Un signalement pèse jusqu'à 192 Ko à lire et
	// à parser : refuser après le décodage laisserait un client en boucle nous faire allouer
	// et parser tout ça à chaque fois, quota ou pas. Le refus doit coûter moins cher que
	// l'acceptation, sinon la limite protège la boîte de réception mais pas le serveur.
	if !reportQuotaAvailable(acct.PID) {
		// Refus explicite plutôt que silencieux : le joueur doit savoir que son envoi n'est
		// pas parti, sinon il croit avoir signalé.
		writeErr(w, http.StatusTooManyRequests, "Trop de signalements récents. Réessaie dans une heure.")
		return
	}

	var in struct {
		ErrorCode string `json:"error_code"`
		Game      string `json:"game"`
		Version   string `json:"version"`
		Comment   string `json:"comment"`
		Log       string `json:"log"`
	}
	// Le corps est borné AVANT le décodage : le log peut légitimement faire 128 Ko, mais
	// rien n'oblige un client à s'en tenir là.
	r.Body = http.MaxBytesReader(w, r.Body, maxReportLog+64*1024)
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "JSON invalide")
		return
	}

	// Découpé hors verrou : clampLog copie jusqu'à 128 Ko, et le faire sous le mutex ferait
	// se sérialiser les signalements sur des copies de blocs — en bloquant au passage la
	// page admin, qui prend le même verrou.
	rep := bugReport{
		PID:       acct.PID,
		Nickname:  displayName(acct),
		Discord:   acct.DiscordUsername,
		DiscordID: acct.DiscordID,
		ErrorCode: clampReportField(in.ErrorCode, 32),
		Game:      clampReportField(in.Game, 32),
		Version:   clampReportField(in.Version, 32),
		Comment:   clampReportField(in.Comment, maxComment),
		Log:       clampLog(in.Log),
		CreatedAt: time.Now(),
	}

	reportsMu.Lock()

	// Re-vérifié sous verrou : le quota au-dessus est une garde bon marché, mais deux envois
	// simultanés peuvent tous deux la passer. Ici c'est la vraie décision.
	if reportsFromLastHour(acct.PID) >= reportPerHour {
		reportsMu.Unlock()
		writeErr(w, http.StatusTooManyRequests, "Trop de signalements récents. Réessaie dans une heure.")

		return
	}

	pruneReports()

	reportSeq++
	rep.ID = fmt.Sprintf("r%d", reportSeq)
	reports = append(reports, rep)

	if len(reports) > maxReports {
		// Les plus anciens partent. Le tableau garde la capacité du plus grand qu'il a eu,
		// mais les entrées coupées doivent être libérables : sans re-slice dans un tableau
		// neuf, on garderait des logs de 128 Ko référencés par la partie inutilisée.
		reports = append([]bugReport(nil), reports[len(reports)-maxReports:]...)
	}

	reportsMu.Unlock()

	fmt.Printf("[report] pid=%d (%s / discord=%s) code=%q game=%s : %q (log %d o)\n",
		acct.PID, displayName(acct), acct.DiscordUsername, in.ErrorCode, in.Game,
		clampReportField(in.Comment, 60), len(in.Log))

	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// GET /api/admin/reports — la boîte de réception.
// POST /api/admin/reports?id=rN&handled=true — marquer traité.
// Auth : session admin OU X-Admin-Key (comme les autres routes de service, pour que le bot
// Discord / l'outillage ops puisse tirer les signalements sans compte admin interactif).
func (s *server) adminReports(w http.ResponseWriter, r *http.Request) {
	if !s.adminOrServiceKey(w, r) {
		return
	}

	reportsMu.Lock()
	defer reportsMu.Unlock()

	pruneReports()

	if r.Method == http.MethodPost {
		id := r.URL.Query().Get("id")
		for i := range reports {
			if reports[i].ID == id {
				reports[i].Handled = r.URL.Query().Get("handled") != "false"
				writeJSON(w, http.StatusOK, map[string]any{"ok": true})
				return
			}
		}
		writeErr(w, http.StatusNotFound, "Signalement introuvable")
		return
	}

	// Plus récent d'abord : c'est ce qu'on veut voir en ouvrant la page.
	out := append([]bugReport(nil), reports...)
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })

	writeJSON(w, http.StatusOK, map[string]any{"reports": out, "count": len(out)})
}

// reportQuotaAvailable dit, sans lire le corps de la requête, s'il reste du quota à ce
// compte. Prend le verrou lui-même et le rend tout de suite : c'est une garde d'entrée, pas
// la décision finale (voir le re-test sous verrou dans report).
func reportQuotaAvailable(pid uint64) bool {
	reportsMu.Lock()
	defer reportsMu.Unlock()

	return reportsFromLastHour(pid) < reportPerHour
}

// L'appelant tient reportsMu.
func reportsFromLastHour(pid uint64) int {
	cutoff := time.Now().Add(-time.Hour)
	n := 0
	for _, rep := range reports {
		if rep.PID == pid && rep.CreatedAt.After(cutoff) {
			n++
		}
	}
	return n
}

// L'appelant tient reportsMu.
func pruneReports() {
	cutoff := time.Now().Add(-reportMaxAge)
	kept := reports[:0]
	for _, rep := range reports {
		if rep.CreatedAt.After(cutoff) {
			kept = append(kept, rep)
		}
	}
	reports = kept
}

// clampReportField borne un champ court et retire les caractères de contrôle : ce texte
// vient d'un client et s'affiche dans la page admin.
func clampReportField(s string, max int) string {
	out := make([]rune, 0, max)
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			continue
		}
		if len(out) >= max {
			break
		}
		out = append(out, r)
	}
	return strings.TrimSpace(string(out))
}

// clampLog garde la FIN du log : c'est là qu'est l'erreur. Couper le début perd le contexte
// de démarrage, couper la fin perdrait le crash lui-même.
func clampLog(s string) string {
	if len(s) <= maxReportLog {
		return s
	}
	return "[…début tronqué…]\n" + s[len(s)-maxReportLog:]
}
