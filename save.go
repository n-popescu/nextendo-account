package main

import (
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// saveMu serializes cloud-save writes PER ACCOUNT so the quota check (reading the current total) and
// the write are atomic. Without it, N concurrent uploads for DIFFERENT titles each read the total
// BEFORE the others have written, each sees room under the limit, and collectively they blow past
// it. Keyed by PID → different accounts still write fully concurrently.
var saveMu sync.Map // uint64 -> *sync.Mutex

// lockSavePID locks the per-account save mutex and returns its unlock func.
func lockSavePID(pid uint64) func() {
	m, _ := saveMu.LoadOrStore(pid, &sync.Mutex{})
	mu := m.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

// [Nextendo] Cloud-save read/list/delete helpers + the eligibility set. The write/GET/HEAD path
// lives in the save() handler in main.go; these are the pieces it dispatches to (/info, DELETE)
// plus the /api/saves listing used by the site's personal space.
//
// This file was reconstructed from the deployed binary's behaviour + the references in main.go
// (the original source was built in a throwaway workspace and lost). Storage layout is the one
// main.go uses: saveDir/<pid>/<titleId>.bin.

// cloudSaveTitles is the set of title IDs eligible for cloud saves for EVERY account: the games the
// emulator actually syncs (ApplicationData.NextendoCompatibleVersion). Non-boosters are limited to
// EXACTLY these; boosters may additionally push any other title. Keys are lower-case (title ids are
// matched lower-cased). Mirrors the client switch so server and emulator agree.
var cloudSaveTitles = map[string]bool{
	"0100152000022000": true, // Mario Kart 8 Deluxe
	"01006a800016e000": true, // Super Smash Bros. Ultimate
	"0100f8f0000a2000": true, // Splatoon 2 (EU)
	"01003bc0000a0000": true, // Splatoon 2 (US)
	"01003c700009c800": true, // Splatoon 2 (JP)
	"01006f8002326000": true, // Animal Crossing: New Horizons
}

// cloudSaveLimit is the per-account quota (5 MiB). Discord boosters get cloudSaveLimitBooster.
const cloudSaveLimit = 5 * 1024 * 1024
const cloudSaveLimitBooster = 10 * 1024 * 1024 // 10 MiB pour les boosters Discord

// cloudSaveLimitFor returns the storage quota for an account (boosters get 10 MiB instead of 5).
func cloudSaveLimitFor(a *Account) int64 {
	if a.IsBooster {
		return cloudSaveLimitBooster
	}
	return cloudSaveLimit
}

// cloudSaveGate reports whether an account may use cloud saves (upload AND download), and if not,
// a user-facing reason. Cloud saves are reserved for full accounts that have a VERIFIED e-mail
// AND a linked Discord account — guests qualify for neither. Enforced on every save operation so
// both the push (émulateur, à la fermeture) and the pull (au lancement) are gated identically.
func cloudSaveGate(a *Account) (string, bool) {
	if a.IsGuest() {
		return "Les sauvegardes dans le cloud ne sont pas disponibles pour les profils invités.", false
	}
	if !a.EmailVerified {
		return "Vérifie ton adresse e-mail pour activer les sauvegardes dans le cloud.", false
	}
	if a.DiscordID == "" && a.DiscordUsername == "" {
		return "Lie ton compte à Discord pour activer les sauvegardes dans le cloud.", false
	}
	return "", true
}

type saveEntry struct {
	TitleID   string `json:"titleId"`
	Name      string `json:"name,omitempty"`
	Icon      string `json:"icon,omitempty"` // base64 game icon, reused from the account's play history
	Size      int64  `json:"size"`
	UpdatedAt string `json:"updatedAt,omitempty"`
}

// saveIcons builds a canonical-titleID -> base64 icon map from the account's own play history
// (the emulator uploads each game's icon there). Lets the site show real game icons next to
// each cloud save without any extra artwork store.
func saveIcons(pid uint64) map[string]string {
	m := map[string]string{}
	for _, h := range loadHistory(filepath.Join(historyDir, strconv.FormatUint(pid, 10)+".json")) {
		if h.Icon != "" {
			m[canonTitleID(h.TitleID)] = h.Icon
		}
	}
	return m
}

func gameName(titleID string) string {
	if g, ok := gamesDB[titleID]; ok {
		return g.Name
	}
	if canon, ok := gameAliases[titleID]; ok {
		if g, ok := gamesDB[canon]; ok {
			return g.Name
		}
	}
	return ""
}

// saveList: GET /api/saves — every cloud save for the account, with the quota usage so the site
// can show "X / 5 Mo" and the per-game breakdown.
func (s *server) saveList(w http.ResponseWriter, r *http.Request) {
	acct, ok := s.accountFromBearer(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "Session invalide ou expirée.")
		return
	}
	if acct.IsGuest() {
		writeErr(w, http.StatusForbidden, "Les sauvegardes cloud ne sont pas disponibles pour les profils invités.")
		return
	}

	dir := filepath.Join(saveDir, strconv.FormatUint(acct.PID, 10))
	entries := []saveEntry{}
	icons := saveIcons(acct.PID)
	var total int64
	if items, err := os.ReadDir(dir); err == nil {
		for _, it := range items {
			if it.IsDir() || !strings.HasSuffix(it.Name(), ".bin") {
				continue
			}
			info, ierr := it.Info()
			if ierr != nil {
				continue
			}
			id := strings.TrimSuffix(it.Name(), ".bin")
			total += info.Size()
			entries = append(entries, saveEntry{
				TitleID:   id,
				Name:      gameName(id),
				Icon:      icons[canonTitleID(id)],
				Size:      info.Size(),
				UpdatedAt: info.ModTime().UTC().Format(time.RFC3339),
			})
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Size > entries[j].Size })

	// Éligibilité cloud-save (Discord lié + e-mail vérifié) : renvoyée pour que l'espace perso
	// affiche le bon message d'activation plutôt qu'une liste vide sans explication. reasonCode est
	// une clé machine ("guest"/"email"/"discord") pour que le site localise le message lui-même.
	reason, eligible := cloudSaveGate(acct)
	reasonCode := ""
	if !eligible {
		switch {
		case acct.IsGuest():
			reasonCode = "guest"
		case !acct.EmailVerified:
			reasonCode = "email"
		default:
			reasonCode = "discord"
		}
	}

	// Échéance de grâce (downgrade booster en dépassement) : le site affiche un compte à rebours.
	graceUntil := ""
	if !acct.CloudGraceUntil.IsZero() {
		graceUntil = acct.CloudGraceUntil.UTC().Format(time.RFC3339)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"saves":      entries,
		"totalSize":  total,
		"limit":      cloudSaveLimitFor(acct),
		"isBooster":  acct.IsBooster,
		"eligible":   eligible,
		"reason":     reason,
		"reasonCode": reasonCode,
		"graceUntil": graceUntil,
	})
}

// saveInfo: GET /api/save/<titleId>/info — one save's metadata (dispatched from save()).
func (s *server) saveInfo(w http.ResponseWriter, r *http.Request) {
	acct, ok := s.accountFromBearer(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "Session invalide ou expirée.")
		return
	}

	titleID := strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/save/"), "/info"))
	if !reTitleID.MatchString(titleID) {
		writeErr(w, http.StatusBadRequest, "titleId invalide")
		return
	}

	p := filepath.Join(saveDir, strconv.FormatUint(acct.PID, 10), titleID+".bin")
	info, err := os.Stat(p)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"titleId": titleID, "exists": false, "size": 0})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"titleId":   titleID,
		"exists":    true,
		"size":      info.Size(),
		"name":      gameName(titleID),
		"updatedAt": info.ModTime().UTC().Format(time.RFC3339),
	})
}

// saveDelete: DELETE /api/save/<titleId> — remove one cloud save (dispatched from save()).
func (s *server) saveDelete(w http.ResponseWriter, r *http.Request) {
	acct, ok := s.accountFromBearer(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "Session invalide ou expirée.")
		return
	}
	if acct.IsGuest() {
		writeErr(w, http.StatusForbidden, "Indisponible pour les profils invités.")
		return
	}

	titleID := strings.ToLower(strings.TrimPrefix(r.URL.Path, "/api/save/"))
	if !reTitleID.MatchString(titleID) {
		writeErr(w, http.StatusBadRequest, "titleId invalide")
		return
	}

	p := filepath.Join(saveDir, strconv.FormatUint(acct.PID, 10), titleID+".bin")
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		writeErr(w, http.StatusInternalServerError, "échec suppression")
		return
	}
	_ = os.Remove(p + ".bak")
	// Si une échéance de grâce était posée (downgrade booster) et que l'utilisateur vient de
	// repasser sous 5 Mo, on la lève immédiatement (retour propre, sans attendre le balayage).
	if !acct.CloudGraceUntil.IsZero() {
		dir := filepath.Join(saveDir, strconv.FormatUint(acct.PID, 10))
		if cloudUsage(dir) <= cloudSaveLimit {
			_ = s.store.SetCloudGrace(acct.ID, time.Time{})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "deleted": titleID})
}

// cloudGracePeriod : délai laissé à un compte qui perd le statut booster en dépassement pour
// redescendre sous 5 Mo lui-même, avant nettoyage automatique.
const cloudGracePeriod = 72 * time.Hour

// SetCloudGrace pose (ou efface si until est zéro) l'échéance de grâce cloud d'un compte.
func (s *jsonStore) SetCloudGrace(id int64, until time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.Accts[id]
	if !ok {
		return ErrNotFound
	}
	if a.CloudGraceUntil.Equal(until) {
		return nil // inchangé : pas de réécriture disque
	}
	a.CloudGraceUntil = until
	return s.persist()
}

// AllWithCloudGrace renvoie les comptes ayant une échéance de grâce cloud en attente (balayage).
func (s *jsonStore) AllWithCloudGrace() []*Account {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*Account
	for _, a := range s.Accts {
		if !a.CloudGraceUntil.IsZero() {
			out = append(out, a)
		}
	}
	return out
}

// cloudUsage somme la taille des .bin d'un dossier de sauvegardes (par PID).
func cloudUsage(dir string) int64 {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	var total int64
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".bin") {
			continue
		}
		if info, ierr := e.Info(); ierr == nil {
			total += info.Size()
		}
	}
	return total
}

// deleteBoosterOnlySaves supprime les sauvegardes des jeux hors des 4 jeux autorisés aux
// non-boosters (cloudSaveTitles) — c.-à-d. les jeux qu'un booster seul pouvait pousser. Utilisé
// au downgrade booster→non-booster. Renvoie le nombre d'octets libérés.
func deleteBoosterOnlySaves(dir string) int64 {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	var freed int64
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".bin") {
			continue
		}
		title := strings.ToLower(strings.TrimSuffix(e.Name(), ".bin"))
		if cloudSaveTitles[title] {
			continue // jeu autorisé aux non-boosters → conservé
		}
		if info, ierr := e.Info(); ierr == nil {
			freed += info.Size()
		}
		_ = os.Remove(filepath.Join(dir, e.Name()))
		_ = os.Remove(filepath.Join(dir, e.Name()+".bak"))
	}
	return freed
}

// deleteHeaviestSave supprime la plus grosse sauvegarde du dossier ; renvoie son titleID (ou "").
func deleteHeaviestSave(dir string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	var name string
	var max int64 = -1
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".bin") {
			continue
		}
		if info, ierr := e.Info(); ierr == nil && info.Size() > max {
			max = info.Size()
			name = e.Name()
		}
	}
	if name == "" {
		return ""
	}
	_ = os.Remove(filepath.Join(dir, name))
	_ = os.Remove(filepath.Join(dir, name+".bak"))
	return strings.TrimSuffix(name, ".bin")
}

// applyBoosterDowngrade est appelé quand un compte perd le statut booster : la limite retombe de
// 10 à 5 Mo. On tente de le remettre dans les clous sans détruire de sauvegarde Nextendo :
//  1. suppression des jeux NON-Nextendo (perk réservé aux boosters) ;
//  2. si toujours au-dessus de 5 Mo → échéance de 3 j (affichée dans l'espace perso) pour que
//     l'utilisateur supprime lui-même une sauvegarde. Passé le délai, cloudGraceSweep fait le
//     ménage (save la plus lourde). Idempotent.
func (s *server) applyBoosterDowngrade(a *Account) {
	dir := filepath.Join(saveDir, strconv.FormatUint(a.PID, 10))
	if cloudUsage(dir) <= cloudSaveLimit {
		_ = s.store.SetCloudGrace(a.ID, time.Time{})
		return
	}
	if freed := deleteBoosterOnlySaves(dir); freed > 0 {
		log.Printf("[cloud] pid=%d downgrade booster : %d o de jeux réservés booster supprimés", a.PID, freed)
	}
	if cloudUsage(dir) <= cloudSaveLimit {
		_ = s.store.SetCloudGrace(a.ID, time.Time{})
		return
	}
	_ = s.store.SetCloudGrace(a.ID, time.Now().Add(cloudGracePeriod))
	log.Printf("[cloud] pid=%d downgrade booster : encore au-dessus de 5 Mo → compte à rebours 3 j", a.PID)
}

// cloudGraceSweep : passé l'échéance de grâce, si le compte dépasse toujours 5 Mo, on supprime les
// sauvegardes les plus lourdes jusqu'à repasser sous la limite. Lancé périodiquement.
func (s *server) cloudGraceSweep() {
	now := time.Now()
	for _, a := range s.store.AllWithCloudGrace() {
		if a.CloudGraceUntil.IsZero() || now.Before(a.CloudGraceUntil) {
			continue // échéance non atteinte
		}
		dir := filepath.Join(saveDir, strconv.FormatUint(a.PID, 10))
		// Redevenu booster, ou déjà repassé sous la limite → on lève simplement la contrainte.
		if a.IsBooster || cloudUsage(dir) <= cloudSaveLimit {
			_ = s.store.SetCloudGrace(a.ID, time.Time{})
			continue
		}
		deleteBoosterOnlySaves(dir) // filet : au cas où il resterait des jeux réservés booster
		for cloudUsage(dir) > cloudSaveLimit {
			title := deleteHeaviestSave(dir)
			if title == "" {
				break
			}
			log.Printf("[cloud] pid=%d échéance dépassée : suppression auto de la save la plus lourde (%s)", a.PID, title)
		}
		_ = s.store.SetCloudGrace(a.ID, time.Time{})
	}
}

// cloudGraceLoop lance le balayage au démarrage puis toutes les 30 min.
func (s *server) cloudGraceLoop() {
	s.cloudGraceSweep()
	t := time.NewTicker(30 * time.Minute)
	defer t.Stop()
	for range t.C {
		s.cloudGraceSweep()
	}
}
