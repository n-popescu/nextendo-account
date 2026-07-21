package main

// Espace ADMIN — réservé au(x) compte(s) dont l'e-mail est dans NEXTENDO_ADMIN_EMAILS
// (aucun par défaut ; à configurer). Donne à l'opérateur la vue complète : liste des utilisateurs
// (pseudo, e-mail, code ami, vérifié, en ligne, sessions, activité), stats globales, et la
// suppression d'un compte. Toutes les routes vérifient l'admin via le bearer (token web ou nex).

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

// adminEmailSet is the set of e-mails allowed into the admin space.
func adminEmailSet() map[string]bool {
	// Aucun admin par défaut : renseignez NEXTENDO_ADMIN_EMAILS (liste séparée par des virgules).
	v := os.Getenv("NEXTENDO_ADMIN_EMAILS")
	m := map[string]bool{}
	for _, e := range strings.Split(v, ",") {
		if e = strings.TrimSpace(strings.ToLower(e)); e != "" {
			m[e] = true
		}
	}
	return m
}

func isAdminAccount(a *Account) bool {
	return a != nil && adminEmailSet()[strings.ToLower(a.Email)]
}

func (s *server) requireAdmin(w http.ResponseWriter, r *http.Request) (*Account, bool) {
	acct, ok := s.accountFromBearer(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "Session invalide ou expirée.")
		return nil, false
	}
	if !isAdminAccount(acct) {
		writeErr(w, http.StatusForbidden, "Accès réservé à l'administrateur.")
		return nil, false
	}
	return acct, true
}

// isOnline : présence fraîche (jeu) OU une session (navigateur/émulateur/switch) vue < 5 min.
func isOnline(pid uint64) bool {
	if e, ok := getPresence(pid); ok && e.Status > 0 {
		return true
	}
	for _, se := range sessionsForPID(pid) {
		if !se.Revoked && time.Since(se.LastSeen) < 5*time.Minute {
			return true
		}
	}
	return false
}

// adminCheck lets the front know whether the current session is admin (to show the /admin link).
// GET /api/admin/check
func (s *server) adminCheck(w http.ResponseWriter, r *http.Request) {
	acct, ok := s.accountFromBearer(r)
	writeJSON(w, http.StatusOK, map[string]any{"admin": ok && isAdminAccount(acct)})
}

type adminUserRow struct {
	PID           uint64 `json:"pid"`
	Username      string `json:"username"`
	Email         string `json:"email"`
	FriendCode    string `json:"friend_code"`
	CreatedAt     string `json:"created_at"`
	EmailVerified bool   `json:"email_verified"`
	Disabled      bool   `json:"disabled"`
	Online        bool   `json:"online"`
	Playing       string `json:"playing"` // titleId du jeu en cours, "" sinon
	Sessions      int    `json:"sessions"`
	LastSeen      string `json:"last_seen"`
	Friends       int    `json:"friends"`
	IsAdmin       bool   `json:"is_admin"`
	// Lien Discord poussé par le bot (voir discord.go). On affiche le PSEUDO, pas l'id numérique.
	Discord   string `json:"discord,omitempty"`
	DiscordID string `json:"discord_id,omitempty"`
	// Banni : la ligne vient d'un tombstone — le compte lui-même a été supprimé par le ban, mais
	// on le garde visible dans la liste pour pouvoir le débannir.
	Banned    bool   `json:"banned,omitempty"`
	BanReason string `json:"ban_reason,omitempty"`
	BannedAt  string `json:"banned_at,omitempty"`
	BanIPs    string `json:"ban_ips,omitempty"`
}

// adminUsers lists every account with its activity. GET /api/admin/users
func (s *server) adminUsers(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	all := s.store.AllAccounts()
	rows := make([]adminUserRow, 0, len(all))
	for _, a := range all {
		playing := ""
		if e, ok := getPresence(a.PID); ok && e.Status > 0 {
			playing = e.AppID
		}
		sess := sessionsForPID(a.PID)
		lastSeen := ""
		for _, se := range sess {
			if ls := se.LastSeen.UTC().Format(time.RFC3339); ls > lastSeen {
				lastSeen = ls
			}
		}
		rows = append(rows, adminUserRow{
			PID: a.PID, Username: a.Username, Email: a.Email, FriendCode: a.FriendCode,
			CreatedAt: a.CreatedAt.UTC().Format(time.RFC3339), EmailVerified: a.EmailVerified || a.IsGuest(),
			Disabled: a.Disabled, Online: isOnline(a.PID), Playing: playing, Sessions: len(sess),
			LastSeen: lastSeen, Friends: len(a.Friends), IsAdmin: isAdminAccount(a),
			Discord: a.DiscordUsername, DiscordID: a.DiscordID,
		})
	}
	// Les bannis : le ban a supprimé leur compte, mais on rejoue les tombstones pour qu'ils
	// RESTENT visibles dans la liste (et débannissables). CreatedAt = date du ban : la ligne se
	// classe naturellement, et l'UI l'affiche comme "banni le …".
	for _, b := range banAll() {
		rows = append(rows, adminUserRow{
			PID: b.PID, Username: b.Username, Email: b.Email, FriendCode: b.FriendCode,
			CreatedAt: b.BannedAt.UTC().Format(time.RFC3339),
			Banned:    true, BanReason: b.Reason, BannedAt: b.BannedAt.UTC().Format(time.RFC3339),
			BanIPs:  strings.Join(b.RegIPs, ", "),
			Discord: b.DiscordName, DiscordID: b.DiscordID,
		})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].CreatedAt > rows[j].CreatedAt })
	writeJSON(w, http.StatusOK, map[string]any{"users": rows, "total": len(rows)})
}

// adminStats returns aggregate counters. GET /api/admin/stats
func (s *server) adminStats(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	all := s.store.AllAccounts()
	total, verified, online, disabled := len(all), 0, 0, 0
	today := time.Now().UTC().Format("2006-01-02")
	newToday := 0
	for _, a := range all {
		if a.EmailVerified || a.IsGuest() {
			verified++
		}
		if a.Disabled {
			disabled++
		}
		if isOnline(a.PID) {
			online++
		}
		if strings.HasPrefix(a.CreatedAt.UTC().Format(time.RFC3339), today) {
			newToday++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"total": total, "verified": verified, "unverified": total - verified,
		"disabled": disabled, "online": online, "new_today": newToday,
	})
}

// adminDeleteUser hard-deletes an account by PID (not the admin's own). POST /api/admin/delete-user {pid}
func (s *server) adminDeleteUser(w http.ResponseWriter, r *http.Request) {
	acct, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	var in struct {
		PID uint64 `json:"pid"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.PID == 0 {
		writeErr(w, http.StatusBadRequest, "pid requis")
		return
	}
	if in.PID == acct.PID {
		writeErr(w, http.StatusBadRequest, "Tu ne peux pas supprimer ton propre compte admin.")
		return
	}
	if err := s.store.DeleteByPID(in.PID); err != nil {
		writeErr(w, http.StatusNotFound, "Compte introuvable.")
		return
	}
	revokeAllForPID(in.PID, "") // coupe ses sessions
	log.Printf("[admin] compte pid=%d supprimé par %s", in.PID, acct.Email)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ---------------------------------------------------------------------------
// Store: opérations admin (implémentées sur jsonStore)
// ---------------------------------------------------------------------------

// AllAccounts returns a snapshot slice of every account.
func (s *jsonStore) AllAccounts() []*Account {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Account, 0, len(s.Accts))
	for _, a := range s.Accts {
		out = append(out, a)
	}
	return out
}

// DeleteByPID hard-deletes the account with this PID (and its index entries).
func (s *jsonStore) DeleteByPID(pid uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, a := range s.Accts {
		if a.PID == pid {
			delete(s.Accts, id)
			// byUser n'est PAS unique (pseudos partagés) : ne retire que s'il pointe sur CE compte.
			if s.byUser[strings.ToLower(a.Username)] == id {
				delete(s.byUser, strings.ToLower(a.Username))
			}
			delete(s.byMail, strings.ToLower(a.Email))
			delete(s.byPID, a.PID)
			delete(s.byCode, a.FriendCode)
			return s.persist()
		}
	}
	return ErrNotFound
}
