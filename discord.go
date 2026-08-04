package main

// Lien Discord — le bot de vérif POUSSE ici le lien Discord↔Nextendo (POST /api/admin/discord-link)
// pour que le COMPTE devienne la source de vérité. Deux choses en découlent, impossibles tant que le
// lien ne vivait que dans le store du bot :
//   1. le gate online peut exiger un compte lié au Discord (NEXTENDO_REQUIRE_DISCORD=1) ;
//   2. un ban prononcé depuis le site connaît enfin le Discord ID -> on le relaie au bot, qui bannit
//      sur le serveur Discord (le miroir du ban Discord -> Nextendo qui existait déjà).

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// SetDiscordLink enregistre (ou efface si discordID == "") le lien Discord d'un compte.
func (s *jsonStore) SetDiscordLink(id int64, discordID, username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.Accts[id]
	if !ok {
		return ErrNotFound
	}
	if a.DiscordID == discordID && a.DiscordUsername == username {
		return nil // déjà à jour : pas de réécriture disque
	}
	a.DiscordID = discordID
	a.DiscordUsername = username
	switch {
	case discordID == "":
		a.DiscordLinkedAt = time.Time{}
	case a.DiscordLinkedAt.IsZero():
		a.DiscordLinkedAt = time.Now().UTC()
	}
	return s.persist()
}

// SetBooster met à jour le statut « booster du serveur Discord » d'un compte. Poussé par le bot
// (qui voit le premium_since / le rôle booster du membre) en même temps que le lien. Un booster a
// droit au cloud-save pour TOUS les jeux (voir le handler save), pas seulement les jeux Nextendo.
func (s *jsonStore) SetBooster(id int64, isBooster bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.Accts[id]
	if !ok {
		return ErrNotFound
	}
	if a.IsBooster == isBooster {
		return nil // pas de changement : pas de réécriture disque
	}
	a.IsBooster = isBooster
	return s.persist()
}

// adminDiscordLink : le bot de vérif pousse le lien après une vérification réussie, et rejoue tous
// ses liens existants au démarrage (backfill). POST /api/admin/discord-link
// {pid, discord_id, discord_username, is_booster} — discord_id vide = délier.
// Auth : X-Admin-Key (bot) OU session admin.
func (s *server) adminDiscordLink(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST attendu")
		return
	}
	if !s.adminOrServiceKey(w, r) {
		return
	}
	var in struct {
		PID             uint64 `json:"pid"`
		DiscordID       string `json:"discord_id"`
		DiscordUsername string `json:"discord_username"`
		IsBooster       bool   `json:"is_booster"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.PID == 0 {
		writeErr(w, http.StatusBadRequest, "pid requis")
		return
	}
	in.DiscordID = strings.TrimSpace(in.DiscordID)
	// Un Discord banni ne peut pas se relier à un nouveau compte.
	if in.DiscordID != "" && banIsDiscordBanned(in.DiscordID) {
		writeErr(w, http.StatusForbidden, "Ce compte Discord est banni.")
		return
	}
	acct, err := s.store.ByPID(in.PID)
	if err != nil {
		writeErr(w, http.StatusNotFound, "compte inconnu")
		return
	}
	if err := s.store.SetDiscordLink(acct.ID, in.DiscordID, strings.TrimSpace(in.DiscordUsername)); err != nil {
		writeErr(w, http.StatusInternalServerError, "échec enregistrement")
		return
	}
	// Statut booster : seulement s'il reste lié (un délié n'est plus booster chez nous).
	wasBooster := acct.IsBooster
	booster := in.IsBooster && in.DiscordID != ""
	if serr := s.store.SetBooster(acct.ID, booster); serr != nil {
		log.Printf("[discord] pid=%d échec set booster: %v", in.PID, serr)
	}
	// Perte du statut booster → la limite retombe à 5 Mo : on nettoie l'excédent (jeux non-Nextendo
	// puis, à défaut, compte à rebours de 3 j avant nettoyage auto). Hors du chemin critique.
	// À l'inverse, (re)devenir booster lève immédiatement toute échéance de grâce en cours.
	if wasBooster && !booster {
		go s.applyBoosterDowngrade(acct)
	} else if booster {
		_ = s.store.SetCloudGrace(acct.ID, time.Time{})
	}
	if in.DiscordID == "" {
		log.Printf("[discord] pid=%d délié", in.PID)
	} else {
		log.Printf("[discord] pid=%d lié à %s (%s) booster=%v", in.PID, in.DiscordID, in.DiscordUsername, booster)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "pid": in.PID, "linked": in.DiscordID != ""})
}

// discordLinkRequired : le gate online exige-t-il un compte lié à Discord ?
// Piloté par NEXTENDO_REQUIRE_DISCORD=1 — on le laisse OFF tant que le backfill des liens
// existants n'est pas confirmé, sinon on verrouillerait dehors tous les comptes déjà liés
// (leur lien ne vit encore que dans le store du bot).
func discordLinkRequired() bool {
	return os.Getenv("NEXTENDO_REQUIRE_DISCORD") == "1"
}

// botServiceURL / botServiceKey : comment joindre le bot de vérif pour lui relayer un ban.
// Le bot tourne sur le même réseau docker (coolify) que nous.
func botServiceURL() string {
	if v := strings.TrimSpace(os.Getenv("NEXTENDO_BOT_URL")); v != "" {
		return strings.TrimRight(v, "/")
	}
	return "http://nextendo-verify:8080"
}

func botServiceKey() string {
	// Le bot accepte la même clé de service que celle qu'il nous présente : un seul secret partagé.
	return adminServiceKey()
}

var botHTTP = &http.Client{Timeout: 5 * time.Second}

// relayDiscordBan / relayDiscordUnban préviennent le bot qu'il doit bannir / débannir ce Discord.
func relayDiscordBan(discordID, reason string)   { relayDiscord("ban", discordID, reason) }
func relayDiscordUnban(discordID, reason string) { relayDiscord("unban", discordID, reason) }

// relayDiscord appelle le bot sur /internal/discord-<action>. Best-effort et NON bloquant : si le
// bot est down, l'action Nextendo (ban ou sa levée) reste effective — on ne veut jamais qu'un bot
// injoignable empêche de modérer.
func relayDiscord(action, discordID, reason string) {
	if discordID == "" {
		return
	}
	key := botServiceKey()
	if key == "" {
		log.Printf("[discord] %s non relayé (pas de clé de service) discord=%s", action, discordID)
		return
	}
	go func() {
		body, _ := json.Marshal(map[string]string{"discord_id": discordID, "reason": reason})
		req, err := http.NewRequest(http.MethodPost, botServiceURL()+"/internal/discord-"+action, bytes.NewReader(body))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Admin-Key", key)
		resp, err := botHTTP.Do(req)
		if err != nil {
			log.Printf("[discord] relais %s -> bot ÉCHEC discord=%s: %v", action, discordID, err)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			log.Printf("[discord] relais %s -> bot statut %s discord=%s", action, resp.Status, discordID)
			return
		}
		log.Printf("[discord] %s relayé au bot discord=%s", action, discordID)
	}()
}
