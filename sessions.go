// Nextendo Network — session registry.
//
// The web/session token used to be STATELESS (base64(id.expiry).hmac), so a token
// could never be listed or revoked. This adds a server-side session store so the
// account page can show every active session (browser / Ryujinx emulator / real
// Switch) with its IP + geo, revoke any one, or "close everything" — and so a
// revoked browser token stops working immediately.
//
// The web token now carries a session id: base64(accountID.sessionID.expiry).hmac.
// verifyToken checks that session is still valid (present + not revoked). Legacy
// 2-field tokens stay valid (no session tracking) so existing logins don't break.
//
// GAME sessions (Ryujinx / Switch) are registered by the NEX login path (auth
// server → /internal/session or the emulator's /api/nex-token call) so they appear
// in the same list and drive the single-location + reconnect logic.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Session is one active login for an account.
type Session struct {
	ID       string    `json:"id"`    // random, embedded in the token / referenced by clients
	PID      uint64    `json:"pid"`   // owning account PID
	Kind     string    `json:"kind"`  // "browser" | "ryujinx" | "switch"
	IP       string    `json:"ip"`    // client IP at creation
	Geo      string    `json:"geo"`   // "Ville, Pays" (resolved async; "" until then)
	Agent    string    `json:"agent"` // user-agent / device label
	Created  time.Time `json:"created"`
	LastSeen time.Time `json:"last_seen"`
	Revoked  bool      `json:"revoked"` // set by a revoke; the token/clients then fail
	Playing  bool      `json:"playing"` // ryujinx/switch: currently in an online game (single-location)
}

var (
	sessMu    sync.Mutex
	sessByID  = map[string]*Session{}
	sessPath  = "sessions.json"
	sessDirty bool
)

// A session not seen within this window is considered dead (auto-pruned + treated offline).
const sessionTTL = 45 * 24 * time.Hour // matches the token 30-day expiry with margin

func loadSessions(path string) {
	sessPath = path
	if b, err := os.ReadFile(path); err == nil {
		var list []*Session
		if json.Unmarshal(b, &list) == nil {
			for _, s := range list {
				sessByID[s.ID] = s
			}
		}
	}
	// background flusher for last_seen touches (persist at most every 15s when dirty)
	go func() {
		for range time.Tick(15 * time.Second) {
			sessMu.Lock()
			if sessDirty {
				persistSessionsLocked()
			}
			sessMu.Unlock()
		}
	}()
}

// persistSessionsLocked writes the store; caller holds sessMu.
func persistSessionsLocked() {
	list := make([]*Session, 0, len(sessByID))
	for _, s := range sessByID {
		list = append(list, s)
	}
	if b, err := json.MarshalIndent(list, "", " "); err == nil {
		tmp := sessPath + ".tmp"
		if os.WriteFile(tmp, b, 0o600) == nil {
			_ = os.Rename(tmp, sessPath)
		}
	}
	sessDirty = false
}

func randID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// newSession creates + persists a session and kicks off async geo resolution.
func newSession(pid uint64, kind, ip, agent string) *Session {
	s := &Session{ID: randID(), PID: pid, Kind: kind, IP: ip, Agent: agent,
		Created: time.Now().UTC(), LastSeen: time.Now().UTC()}
	sessMu.Lock()
	sessByID[s.ID] = s
	persistSessionsLocked()
	sessMu.Unlock()
	go resolveGeo(s.ID, ip)
	return s
}

// sessionValid reports whether a session id is present + not revoked, and refreshes
// its last_seen. Empty id (legacy token) is treated as valid (no tracking).
func sessionValid(id string) bool {
	if id == "" {
		return true
	}
	sessMu.Lock()
	defer sessMu.Unlock()
	s, ok := sessByID[id]
	if !ok || s.Revoked {
		return false
	}
	s.LastSeen = time.Now().UTC()
	sessDirty = true
	return true
}

// sessionsForPID lists an account's non-revoked, non-stale sessions (newest first-ish).
func sessionsForPID(pid uint64) []*Session {
	sessMu.Lock()
	defer sessMu.Unlock()
	out := []*Session{}
	for _, s := range sessByID {
		if s.PID == pid && !s.Revoked && time.Since(s.LastSeen) < sessionTTL {
			out = append(out, s)
		}
	}
	return out
}

// revokeSession marks one session revoked (idempotent). Returns the revoked session.
func revokeSession(id string) *Session {
	sessMu.Lock()
	defer sessMu.Unlock()
	s, ok := sessByID[id]
	if !ok {
		return nil
	}
	s.Revoked = true
	persistSessionsLocked()
	return s
}

// revokeAllForPID revokes every session of an account (optionally keeping exceptID).
// Returns how many were revoked (excluding the kept one).
func revokeAllForPID(pid uint64, exceptID string) int {
	sessMu.Lock()
	defer sessMu.Unlock()
	n := 0
	for id, s := range sessByID {
		if s.PID == pid && !s.Revoked && id != exceptID {
			s.Revoked = true
			n++
		}
	}
	if n > 0 {
		persistSessionsLocked()
	}
	return n
}

// setPlaying flags/unflags a game session as actively in an online game (single-location).
func setPlaying(id string, playing bool) {
	sessMu.Lock()
	if s, ok := sessByID[id]; ok {
		s.Playing = playing
		s.LastSeen = time.Now().UTC()
		sessDirty = true
	}
	sessMu.Unlock()
}

// activePlaySession returns the id of a NON-revoked game session currently playing for
// this PID, other than exceptID — used to BLOCK a second concurrent place (single-location).
func activePlaySession(pid uint64, exceptID string) *Session {
	sessMu.Lock()
	defer sessMu.Unlock()
	for id, s := range sessByID {
		if s.PID == pid && s.Playing && !s.Revoked && id != exceptID && time.Since(s.LastSeen) < 5*time.Minute {
			return s
		}
	}
	return nil
}

// sessionByID returns a copy-safe pointer (read) for status checks.
func sessionByID(id string) (*Session, bool) {
	sessMu.Lock()
	defer sessMu.Unlock()
	s, ok := sessByID[id]
	return s, ok
}

// upsertPlaySession finds the play-session for this exact device (pid+kind+ip) and
// refreshes it (playing), or creates one. Called by the NEX auth on online login so the
// device shows in the account's sessions and drives single-location + reconnect.
func upsertPlaySession(pid uint64, kind, ip string) *Session {
	sessMu.Lock()
	for _, s := range sessByID {
		if s.PID == pid && s.Kind == kind && s.IP == ip && !s.Revoked {
			s.Playing = true
			s.LastSeen = time.Now().UTC()
			sessDirty = true
			sessMu.Unlock()
			return s
		}
	}
	sessMu.Unlock()
	agent := map[string]string{"ryujinx": "Émulateur Ryujinx", "switch": "Nintendo Switch"}[kind]
	s := newSession(pid, kind, ip, agent)
	setPlaying(s.ID, true)
	return s
}

// upsertDeviceSession is like upsertPlaySession but for a device that is CONNECTED (a Nextendo
// account is linked) without necessarily being IN a game: it refreshes the existing device
// session — or creates one — WITHOUT forcing Playing=true. The Ryujinx fork heartbeats here so
// the emulator shows in the account's sessions as soon as it's open with a linked account, and
// only flips to "in a game" when it actually plays online (upsertPlaySession).
func upsertDeviceSession(pid uint64, kind, ip string) *Session {
	sessMu.Lock()
	for _, s := range sessByID {
		if s.PID == pid && s.Kind == kind && s.IP == ip && !s.Revoked {
			s.LastSeen = time.Now().UTC()
			sessDirty = true
			sessMu.Unlock()
			return s
		}
	}
	sessMu.Unlock()
	agent := map[string]string{"ryujinx": "Émulateur Ryujinx", "switch": "Nintendo Switch"}[kind]
	return newSession(pid, kind, ip, agent)
}

// activePlayElsewhere returns an active (playing, fresh, non-revoked) play-session for this
// PID that is a DIFFERENT device (a different kind, e.g. Switch vs Ryujinx) — used to BLOCK
// a second place. Same kind = same device reconnecting (allowed). A device is "playing" only
// while its game keeps reporting presence; ~5 min after it stops, the other place is freed.
func activePlayElsewhere(pid uint64, kind, ip string) *Session {
	sessMu.Lock()
	defer sessMu.Unlock()
	for _, s := range sessByID {
		if s.PID == pid && s.Playing && !s.Revoked && time.Since(s.LastSeen) < 5*time.Minute && s.Kind != kind {
			return s
		}
	}
	return nil
}

// refreshPlayByPID keeps a PID's play-session(s) fresh from a presence report (so
// "playing" stays true while the game is online).
func refreshPlayByPID(pid uint64) {
	sessMu.Lock()
	for _, s := range sessByID {
		if s.PID == pid && s.Playing && !s.Revoked {
			s.LastSeen = time.Now().UTC()
			sessDirty = true
		}
	}
	sessMu.Unlock()
}

// playSessionForDevice returns a PID's play-session for a given IP (revoked or not) — the
// client polls session-status by its own IP to learn if it was disconnected from the site.
func playSessionForDevice(pid uint64, ip string) (*Session, bool) {
	sessMu.Lock()
	defer sessMu.Unlock()
	for _, s := range sessByID {
		if s.PID == pid && s.IP == ip && s.Playing {
			return s, true
		}
	}
	return nil, false
}

// ---- geo resolution (ip-api.com, free, http-only, 45 req/min) ----

var (
	geoMu    sync.Mutex
	geoCache = map[string]string{}
)

func resolveGeo(sessID, ip string) {
	geo := geoForIP(ip)
	if geo == "" {
		return
	}
	sessMu.Lock()
	if s, ok := sessByID[sessID]; ok {
		s.Geo = geo
		persistSessionsLocked()
	}
	sessMu.Unlock()
}

func geoForIP(ip string) string {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return ""
	}
	if p := net.ParseIP(ip); p != nil && (p.IsLoopback() || p.IsPrivate()) {
		return "Réseau local"
	}
	geoMu.Lock()
	if v, ok := geoCache[ip]; ok {
		geoMu.Unlock()
		return v
	}
	geoMu.Unlock()
	cl := &http.Client{Timeout: 3 * time.Second}
	resp, err := cl.Get("http://ip-api.com/json/" + ip + "?fields=status,country,city")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<12))
	var g struct{ Status, Country, City string }
	if json.Unmarshal(body, &g) != nil || g.Status != "success" {
		return ""
	}
	loc := g.Country
	if g.City != "" {
		loc = g.City + ", " + g.Country
	}
	if loc == "" {
		return ""
	}
	geoMu.Lock()
	geoCache[ip] = loc
	geoMu.Unlock()
	return loc
}

// sessionPublic is the safe view returned to the account page.
func sessionPublic(s *Session, currentID string) map[string]any {
	label := map[string]string{"browser": "Navigateur", "ryujinx": "Ryujinx (émulateur)", "switch": "Nintendo Switch"}[s.Kind]
	if label == "" {
		label = s.Kind
	}
	return map[string]any{
		"id":         s.ID,
		"kind":       s.Kind,
		"kind_label": label,
		"ip":         s.IP,
		"geo":        s.Geo,
		"agent":      s.Agent,
		"playing":    s.Playing,
		"created":    s.Created.Format(time.RFC3339),
		"last_seen":  s.LastSeen.Format(time.RFC3339),
		"current":    s.ID == currentID,
	}
}
