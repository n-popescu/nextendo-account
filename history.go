package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// historyDir holds per-account game-history blobs at historyDir/<pid>.json.
// The emulator pushes the local play history (all games) and pulls the merged
// result, so the "Historique de jeu" follows the account and never disappears.
var historyDir = "history"

type historyEntry struct {
	TitleID    string `json:"title_id"`
	Name       string `json:"name"`
	Icon       string `json:"icon,omitempty"` // base64 PNG/JPEG of the game icon
	Seconds    int64  `json:"seconds"`        // total play time
	LastPlayed string `json:"last_played"`    // RFC3339 UTC; "" if unknown
}

// pidFromBearer resolves the account PID from a web session token OR a persisted
// nx2 NEX token (the emulator only keeps the latter).
func (s *server) pidFromBearer(r *http.Request) (uint64, bool) {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if id, ok := verifyToken(tok); ok {
		if acct, err := s.store.ByID(id); err == nil {
			return acct.PID, true
		}
		return 0, false
	}
	if p, ok := verifyNexToken(tok); ok {
		return p, true
	}
	return 0, false
}

func (s *server) history(w http.ResponseWriter, r *http.Request) {
	pid, ok := s.pidFromBearer(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "Session invalide ou expirée.")
		return
	}
	path := filepath.Join(historyDir, strconv.FormatUint(pid, 10)+".json")

	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"history": loadHistory(path)})
	case http.MethodPut, http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, 32<<20) // 32 MiB cap (icons included)
		var in struct {
			History []historyEntry `json:"history"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeErr(w, http.StatusBadRequest, "JSON invalide")
			return
		}
		merged := mergeHistory(loadHistory(path), in.History)
		if err := saveHistory(path, merged); err != nil {
			writeErr(w, http.StatusInternalServerError, "erreur interne")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"history": merged})
	default:
		writeErr(w, http.StatusMethodNotAllowed, "GET ou PUT attendu")
	}
}

// friendHistory: GET ?pid=X returns friend X's game history — only if X is one of
// the caller's accepted friends (privacy). Read-only; no push.
func (s *server) friendHistory(w http.ResponseWriter, r *http.Request) {
	acct, ok := s.accountFromBearer(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "Session invalide ou expirée.")
		return
	}
	pid, err := strconv.ParseUint(strings.TrimSpace(r.URL.Query().Get("pid")), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "pid invalide")
		return
	}
	if !hasFriendPID(acct, pid) {
		writeErr(w, http.StatusForbidden, "Ce joueur n'est pas dans tes amis.")
		return
	}
	path := filepath.Join(historyDir, strconv.FormatUint(pid, 10)+".json")
	writeJSON(w, http.StatusOK, map[string]any{"history": loadHistory(path)})
}

// historyToPlayLog convertit l'historique stocké (title_id/seconds/last_played) vers le format
// playLog du menu HOME (appInfo:appId/totalPlayTime en minutes/lastPlayedAt unix), pour réinjecter
// TON vrai historique dans ton propre objet user BAAS servi à la console.
func historyToPlayLog(pid uint64) string {
	entries := loadHistory(filepath.Join(historyDir, strconv.FormatUint(pid, 10)+".json"))
	if len(entries) == 0 {
		return ""
	}
	type plEntry struct {
		AppID          string `json:"appInfo:appId"`
		GroupID        string `json:"appInfo:presenceGroupId"`
		TotalPlayCount int    `json:"totalPlayCount"`
		TotalPlayTime  int64  `json:"totalPlayTime"`
		FirstPlayedAt  int64  `json:"firstPlayedAt"`
		LastPlayedAt   int64  `json:"lastPlayedAt"`
	}
	out := make([]plEntry, 0, len(entries))
	for _, e := range entries {
		var lp int64
		if e.LastPlayed != "" {
			if t, err := time.Parse(time.RFC3339, e.LastPlayed); err == nil {
				lp = t.Unix()
			}
		}
		out = append(out, plEntry{AppID: e.TitleID, GroupID: e.TitleID, TotalPlayCount: 1, TotalPlayTime: e.Seconds / 60, FirstPlayedAt: lp, LastPlayedAt: lp})
	}
	b, _ := json.Marshal(out)
	return string(b)
}

func loadHistory(path string) []historyEntry {
	entries := []historyEntry{}
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &entries)
	}
	return entries
}

func saveHistory(path string, entries []historyEntry) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// mergeHistory keeps, per title, the higher play time + most recent last-played
// (and the latest non-empty name/icon), so the account's history never regresses
// or disappears — even across reinstalls or a different machine.
func mergeHistory(existing, incoming []historyEntry) []historyEntry {
	byID := map[string]historyEntry{}
	for _, e := range existing {
		byID[strings.ToLower(e.TitleID)] = e
	}
	for _, in := range incoming {
		key := strings.ToLower(in.TitleID)
		if key == "" {
			continue
		}
		cur, ok := byID[key]
		if !ok {
			byID[key] = in
			continue
		}
		if in.Seconds > cur.Seconds {
			cur.Seconds = in.Seconds
		}
		if in.LastPlayed > cur.LastPlayed { // RFC3339 UTC sorts lexicographically
			cur.LastPlayed = in.LastPlayed
		}
		if in.Name != "" {
			cur.Name = in.Name
		}
		if in.Icon != "" {
			cur.Icon = in.Icon
		}
		byID[key] = cur
	}
	out := make([]historyEntry, 0, len(byID))
	for _, e := range byID {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].LastPlayed > out[j].LastPlayed
	})
	return out
}
