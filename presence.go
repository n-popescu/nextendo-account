package main

// Real-time friend PRESENCE relay for S2 (and any NEX game) 2-player private-battle
// join. Splatoon 2 encodes its joinable-room state into the nn::friends presence
// "AppKeyValueStorage" (a 0xC0-byte key-value blob: SessionId, Mode, Attr, Full,
// InGame, Tag, Password, ...). For a friend to be JOINABLE, the joiner's S2 must see
// the HOST's real presence (status + that blob). The Ryujinx fork:
//   - HOST: on nn::friends UpdateUserPresence, POSTs {status, app_field(base64 0xC0)} here.
//   - JOINER: GET /api/friends now returns each friend's presence, which the fork puts
//     back into friend.Presence so S2 sees the host as in a joinable private battle.
// Presence is ephemeral (in-memory, TTL'd) — never persisted to accounts.json.

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type presenceEntry struct {
	Status    int    // nn::friends PresenceStatus (0=Offline, 1=Online, 2=OnlinePlay)
	AppField  string // base64 of the 0xC0 nn::friends AppKeyValueStorage blob
	AppID     string // title id of the game currently played (e.g. 0100f8f0000a2000 = S2) — GÉNÉRIQUE
	AppDetail string // mode lu dans le PLAY REPORT du jeu (« Single Player »…), TEXTE LIBRE du jeu.
	// Vide pour la plupart des titres : n'existe que pour les ~13 jeux ayant une
	// spec PlayReports côté émulateur. Ne jamais l'inventer côté serveur.
	Updated time.Time
}

var (
	presenceMu    sync.RWMutex
	presenceByPID = map[uint64]presenceEntry{}
)

// A friend whose presence hasn't refreshed within this window is treated as offline.
const presenceTTL = 90 * time.Second

func setPresence(pid uint64, status int, appField, appID, appDetail string) {
	presenceMu.Lock()
	presenceByPID[pid] = presenceEntry{Status: status, AppField: appField, AppID: appID, AppDetail: appDetail, Updated: time.Now()}
	presenceMu.Unlock()
	// garde la session de jeu "fraîche" tant que le jeu remonte de la présence (pour la
	// règle "un seul endroit à la fois" — quand le jeu s'arrête, l'autre endroit se libère).
	if status > 0 {
		refreshPlayByPID(pid)
	}
}

// Taille max du détail de présence, côté serveur. Le client borne déjà à 64, mais ce texte
// arrive d'un CLIENT (donc modifiable) et repart vers TOUS les amis : un client trafiqué
// pourrait sinon pousser un pavé dans la liste d'amis de chacun. Le client n'est pas une
// frontière de confiance ; cette borne, si.
const maxPresenceDetail = 64

// clampDetail borne le détail et retire les caractères de contrôle. Le contenu reste du texte
// libre venant du jeu : il est affiché comme du TEXTE par le client, jamais interprété.
func clampDetail(s string) string {
	out := make([]rune, 0, maxPresenceDetail)
	for _, r := range s {
		// Coupe les retours ligne/contrôles : une présence tient sur une ligne, et ça évite
		// qu'un client trafiqué n'injecte de la mise en forme dans l'UI d'un ami.
		if r < 0x20 || r == 0x7f {
			continue
		}
		if len(out) >= maxPresenceDetail {
			break
		}
		out = append(out, r)
	}
	return strings.TrimSpace(string(out))
}

// getPresence returns the fresh presence for a PID, or (zero,false) if absent/stale.
func getPresence(pid uint64) (presenceEntry, bool) {
	presenceMu.RLock()
	e, ok := presenceByPID[pid]
	presenceMu.RUnlock()
	if !ok || time.Since(e.Updated) > presenceTTL {
		return presenceEntry{}, false
	}
	return e, true
}

// POST /api/presence  {"status":int,"app_field":"<base64 0xC0 blob>"}
// Auth: web session token OR nex token (same as /api/friends).
func (s *server) presence(w http.ResponseWriter, r *http.Request) {
	acct, ok := s.accountFromBearer(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "Session invalide ou expirée.")
		return
	}
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST attendu")
		return
	}
	var in struct {
		Status    int    `json:"status"`
		AppField  string `json:"app_field"`
		AppId     string `json:"app_id"`     // titre du jeu courant (générique) — le fork le remonte
		AppDetail string `json:"app_detail"` // mode issu du play report du jeu (« Single Player »…), souvent vide
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "JSON invalide")
		return
	}
	setPresence(acct.PID, in.Status, in.AppField, in.AppId, clampDetail(in.AppDetail))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// POST /internal/presence-batch  {"status":int,"appId":"…","pids":[…]}
// INTERNAL (co-located, no auth): the GAME SERVERS report which PIDs are
// online NOW so friends see them ONLINE in the Switch friend list. Refreshed periodically;
// a PID not re-reported within presenceTTL (90s) falls back to offline. This is the missing
// presence SOURCE — the Ryujinx fork only posts presence for a private-battle HOST.
func (s *server) presenceBatch(w http.ResponseWriter, r *http.Request) {
	// Sans garde ni borne, n'importe qui pouvait marquer n'importe quel compte « en ligne
	// / en jeu » dans les listes d'amis et le tableau de bord, et surtout faire enfler la
	// table de présence indéfiniment (une requête avec des millions de PID = mémoire
	// épuisée). On exige donc la clé interne et on borne l'entrée.
	if k := os.Getenv("NEXTENDO_INTERNAL_KEY"); k != "" && r.Header.Get("X-Internal-Key") != k {
		writeErr(w, http.StatusUnauthorized, "interne")
		return
	}
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST attendu")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var in struct {
		Status int      `json:"status"`
		AppId  string   `json:"appId"`
		Pids   []uint64 `json:"pids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "JSON invalide")
		return
	}
	if in.Status == 0 {
		in.Status = 2 // par défaut : en jeu (OnlinePlay)
	}
	// Cap : au-delà, la requête est tronquée plutôt que d'accepter une liste arbitraire.
	const maxPresenceBatch = 5000
	if len(in.Pids) > maxPresenceBatch {
		log.Printf("[presence-batch] liste tronquée : %d PID reçus, cap à %d", len(in.Pids), maxPresenceBatch)
		in.Pids = in.Pids[:maxPresenceBatch]
	}
	for _, pid := range in.Pids {
		setPresence(pid, in.Status, "", in.AppId, "") // AppId = LE jeu ; les serveurs de jeu n'ont pas de play report
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "n": len(in.Pids)})
}
