package main

// [Nextendo] Self-service account deletion. A member can delete their own Nextendo account from
// their personal space. Deleting:
//   - frees the identifiers (PID, e-mail, friend code, username) so they can be reused/re-registered;
//   - unlinks Discord (account side here; the verify bot is told best-effort, see relayDiscordUnlink);
//   - removes the person from EVERYONE's friends / requests / favorites / blocked lists;
//   - keeps a small TRACE record so the account still shows in the admin space as "deleted".
// Irreversible for the user; the trace is for moderation ("au cas où").

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// DeletedRecord is the trace kept after an account is deleted — enough to identify who it was,
// without the account staying active anywhere.
type DeletedRecord struct {
	PID             uint64    `json:"pid"`
	Username        string    `json:"username"`
	FriendCode      string    `json:"friend_code"`
	Email           string    `json:"email,omitempty"`
	DiscordUsername string    `json:"discord_username,omitempty"`
	DeletedAt       time.Time `json:"deleted_at"`
	Reason          string    `json:"reason,omitempty"` // "self" = the user did it
}

// removeUint64 filters pid out of a PID slice, in place.
func removeUint64(s []uint64, pid uint64) []uint64 {
	if len(s) == 0 {
		return s
	}
	out := s[:0]
	for _, x := range s {
		if x != pid {
			out = append(out, x)
		}
	}
	return out
}

// SoftDeleteByPID removes the account with this PID everywhere (freeing its identifiers and pulling
// it out of every other account's social lists) and keeps a DeletedRecord trace. Returns the trace
// and the account's Discord id (so the caller can relay a best-effort unlink to the verify bot).
func (s *jsonStore) SoftDeleteByPID(pid uint64, reason string) (*DeletedRecord, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var target *Account
	var targetID int64
	for id, a := range s.Accts {
		if a.PID == pid {
			target, targetID = a, id
			break
		}
	}
	if target == nil {
		return nil, "", ErrNotFound
	}

	discordID := target.DiscordID
	rec := &DeletedRecord{
		PID:             target.PID,
		Username:        target.Username,
		FriendCode:      target.FriendCode,
		Email:           target.Email,
		DiscordUsername: target.DiscordUsername,
		DeletedAt:       time.Now().UTC(),
		Reason:          reason,
	}

	// Pull the PID out of everyone else's social lists so nobody keeps a dangling friend.
	for _, a := range s.Accts {
		if a.PID == pid {
			continue
		}
		a.Friends = removeUint64(a.Friends, pid)
		a.FriendRequests = removeUint64(a.FriendRequests, pid)
		a.Favorites = removeUint64(a.Favorites, pid)
		a.Blocked = removeUint64(a.Blocked, pid)
	}

	// Hard-remove the account + its index entries (frees e-mail, PID, friend code, username).
	delete(s.Accts, targetID)
	if s.byUser[strings.ToLower(target.Username)] == targetID {
		delete(s.byUser, strings.ToLower(target.Username))
	}
	delete(s.byMail, strings.ToLower(target.Email))
	delete(s.byPID, target.PID)
	delete(s.byCode, target.FriendCode)

	s.Deleted = append(s.Deleted, rec)

	if err := s.persist(); err != nil {
		return nil, "", err
	}
	return rec, discordID, nil
}

// AllDeleted returns a snapshot of the deletion trace for the admin space.
func (s *jsonStore) AllDeleted() []*DeletedRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*DeletedRecord, len(s.Deleted))
	copy(out, s.Deleted)
	return out
}

// relayDiscordUnlink tells the verify bot to forget this Discord's link (best-effort, like the
// ban relay). If the bot has no /internal/discord-unlink endpoint yet it just logs a non-200.
func relayDiscordUnlink(discordID string) { relayDiscord("unlink", discordID, "account deleted") }

// deleteAccount: the logged-in member deletes their own account. Requires the account password as
// a confirmation, so a stray click / stolen session cannot wipe the account silently.
// POST /api/delete-account {password}
func (s *server) deleteAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST attendu")
		return
	}
	acct, ok := s.accountFromBearer(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "Session invalide ou expirée.")
		return
	}
	if acct.IsGuest() {
		writeErr(w, http.StatusBadRequest, "Un compte invité ne peut pas être supprimé ici.")
		return
	}
	var in struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "JSON invalide")
		return
	}
	// Destructif + reconfirmation par mot de passe (bcrypt) : on borne le brute-force via une
	// session volée.
	if !rateGuard(w, r, rlDelete, "suppression compte") {
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(acct.PasswordHash), []byte(in.Password)) != nil {
		writeErr(w, http.StatusUnauthorized, "Mot de passe incorrect.")
		return
	}

	pid := acct.PID
	rec, discordID, err := s.store.SoftDeleteByPID(pid, "self")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "Échec de la suppression.")
		return
	}
	if discordID != "" {
		relayDiscordUnlink(discordID)
	}
	revokeAllForPID(pid, "") // coupe toutes ses sessions

	log.Printf("[delete] compte pid=%d (%s) supprimé par l'utilisateur", rec.PID, rec.Username)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// adminDeleted lists the deletion trace. GET /api/admin/deleted
func (s *server) adminDeleted(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": s.store.AllDeleted()})
}
