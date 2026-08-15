package main

// Tests for the console identity bindings and the console presence — the two
// halves of the Switch friends fix. Both encode rules that are easy to break by
// accident and expensive to debug in production, which is exactly what happened
// before: a resolution that quietly fell back to one account, and a presence
// nobody wrote.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newTestServer builds a server with a temporary JSON store and two accounts.
func newTestServer(t *testing.T) (*server, *Account, *Account) {
	t.Helper()
	if len(sessionSecret) == 0 {
		sessionSecret = []byte("test-secret-for-bindings")
	}
	// The binding table is a sidecar file loaded once per process; point it at a
	// fresh temp file and reset the loader so each test starts clean.
	dir := t.TempDir()
	t.Setenv("NEXTENDO_BINDINGS_FILE", filepath.Join(dir, "nintendo_bindings.json"))
	resetBindingsForTest()
	store, err := newJSONStore(filepath.Join(dir, "accounts.json"))
	if err != nil {
		t.Fatal(err)
	}
	a, err := store.Create("alice", "alice@example.test", "x")
	if err != nil {
		t.Fatal(err)
	}
	b, err := store.Create("bob", "bob@example.test", "x")
	if err != nil {
		t.Fatal(err)
	}
	a.ensureNintendoIDs()
	b.ensureNintendoIDs()
	return &server{store: store}, a, b
}

// call runs an internal endpoint and returns the recorder.
func call(t *testing.T, h http.HandlerFunc, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, target, nil)
	} else {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
	}
	w := httptest.NewRecorder()
	h(w, r)
	return w
}

// decode reads a JSON body.
func decode(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("body is not JSON (%d): %s", w.Code, w.Body.String())
	}
	return out
}

// TestWhoamiResolvesAnExplicitBinding is the core of the fix: a console that
// presents ITS OWN ids (not ones derived from a PID) resolves to the account it
// was bound to.
func TestWhoamiResolvesAnExplicitBinding(t *testing.T) {
	s, alice, _ := newTestServer(t)

	// A console that already had a device account: its ids match nothing derived.
	const consoleBaas = "8ca8d7842f865b2f"
	const consoleDid = "581ea786a91f1689"

	body := `{"pid":` + pidStr(alice.PID) + `,"baas_id":"` + consoleBaas + `","bs_did":"` + consoleDid + `","label":"switch-1"}`
	if w := call(t, s.internalBind, http.MethodPost, "/internal/bind", body); w.Code != http.StatusOK {
		t.Fatalf("bind returned %d: %s", w.Code, w.Body.String())
	}

	w := call(t, s.internalWhoami, http.MethodGet, "/internal/whoami?baas="+consoleBaas+"&bsdid="+consoleDid, "")
	if w.Code != http.StatusOK {
		t.Fatalf("whoami returned %d: %s", w.Code, w.Body.String())
	}
	got := decode(t, w)
	if pid := uint64(got["pid"].(float64)); pid != alice.PID {
		t.Errorf("pid = %d, want alice (%d)", pid, alice.PID)
	}
	if via, _ := got["via"].(string); via != "binding:baas" {
		t.Errorf("via = %q, want binding:baas", via)
	}
}

// TestWhoamiFailsClosed is the rule that was missing. An unknown console must get
// 404 — never the first account, never the last one to authenticate.
func TestWhoamiFailsClosed(t *testing.T) {
	s, _, _ := newTestServer(t)
	w := call(t, s.internalWhoami, http.MethodGet, "/internal/whoami?baas=deadbeefdeadbeef&bsdid=0123456789abcdef", "")
	if w.Code != http.StatusNotFound {
		t.Fatalf("whoami returned %d for an unknown console, want 404 (body: %s)", w.Code, w.Body.String())
	}
	got := decode(t, w)
	if found, _ := got["found"].(bool); found {
		t.Error("whoami claimed to have found an account")
	}
	if _, hasPID := got["pid"]; hasPID {
		t.Error("whoami returned a pid for an unknown console — this is the bug it exists to prevent")
	}
}

// TestWhoamiResolvesDerivedIDs keeps the old behaviour working: a console that DID
// adopt the ids we minted still resolves, without any binding.
func TestWhoamiResolvesDerivedIDs(t *testing.T) {
	s, alice, _ := newTestServer(t)
	w := call(t, s.internalWhoami, http.MethodGet, "/internal/whoami?baas="+alice.BaasID, "")
	if w.Code != http.StatusOK {
		t.Fatalf("whoami returned %d for a derived id: %s", w.Code, w.Body.String())
	}
	got := decode(t, w)
	if pid := uint64(got["pid"].(float64)); pid != alice.PID {
		t.Errorf("pid = %d, want %d", pid, alice.PID)
	}
	if via, _ := got["via"].(string); via != "derived:baas" {
		t.Errorf("via = %q, want derived:baas", via)
	}
}

// TestBindingIsExclusive: binding a console that already belongs to somebody else
// must be REFUSED, not silently moved. A console quietly changing owner is the
// original bug in a new shape.
func TestBindingIsExclusive(t *testing.T) {
	s, alice, bob := newTestServer(t)
	const consoleBaas = "1111111111111111"

	if w := call(t, s.internalBind, http.MethodPost, "/internal/bind",
		`{"pid":`+pidStr(alice.PID)+`,"baas_id":"`+consoleBaas+`"}`); w.Code != http.StatusOK {
		t.Fatalf("first bind returned %d", w.Code)
	}
	w := call(t, s.internalBind, http.MethodPost, "/internal/bind",
		`{"pid":`+pidStr(bob.PID)+`,"baas_id":"`+consoleBaas+`"}`)
	if w.Code != http.StatusConflict {
		t.Fatalf("second bind returned %d, want 409 Conflict", w.Code)
	}

	// Alice must still own it.
	got := decode(t, call(t, s.internalWhoami, http.MethodGet, "/internal/whoami?baas="+consoleBaas, ""))
	if pid := uint64(got["pid"].(float64)); pid != alice.PID {
		t.Errorf("the console moved to pid=%d", pid)
	}
}

// TestUnbindThenRebind is the documented recovery path for a console that was
// poisoned by the old fallback: unbind it from the wrong account, bind it to the
// right one.
func TestUnbindThenRebind(t *testing.T) {
	s, alice, bob := newTestServer(t)
	const consoleBaas = "2222222222222222"

	call(t, s.internalBind, http.MethodPost, "/internal/bind", `{"pid":`+pidStr(alice.PID)+`,"baas_id":"`+consoleBaas+`"}`)
	if w := call(t, s.internalUnbind, http.MethodPost, "/internal/unbind",
		`{"pid":`+pidStr(alice.PID)+`,"baas_id":"`+consoleBaas+`"}`); w.Code != http.StatusOK {
		t.Fatalf("unbind returned %d: %s", w.Code, w.Body.String())
	}
	if w := call(t, s.internalBind, http.MethodPost, "/internal/bind",
		`{"pid":`+pidStr(bob.PID)+`,"baas_id":"`+consoleBaas+`"}`); w.Code != http.StatusOK {
		t.Fatalf("rebind returned %d: %s", w.Code, w.Body.String())
	}
	got := decode(t, call(t, s.internalWhoami, http.MethodGet, "/internal/whoami?baas="+consoleBaas, ""))
	if pid := uint64(got["pid"].(float64)); pid != bob.PID {
		t.Errorf("pid = %d, want bob (%d)", pid, bob.PID)
	}
}

// TestBindingAcceptsDecimalIDs: a console presents these ids as 64-bit numbers on
// some paths (the NEX auth's /api/nsa does), so both spellings must resolve to the
// same binding.
func TestBindingAcceptsDecimalIDs(t *testing.T) {
	s, alice, _ := newTestServer(t)
	const hexID = "00000000000003e8" // 1000
	call(t, s.internalBind, http.MethodPost, "/internal/bind", `{"pid":`+pidStr(alice.PID)+`,"baas_id":"`+hexID+`"}`)

	// Same id in decimal.
	w := call(t, s.internalWhoami, http.MethodGet, "/internal/whoami?baas=1000", "")
	if w.Code != http.StatusOK {
		t.Fatalf("whoami with a decimal id returned %d", w.Code)
	}
}

// TestTwoProfilesOnTwoConsoles: two accounts, two consoles, no crosstalk. This is
// the end state the fix is for — previously both resolved to one account.
func TestTwoProfilesOnTwoConsoles(t *testing.T) {
	s, alice, bob := newTestServer(t)
	call(t, s.internalBind, http.MethodPost, "/internal/bind", `{"pid":`+pidStr(alice.PID)+`,"baas_id":"aaaa000000000001","bs_did":"aaaa000000000002"}`)
	call(t, s.internalBind, http.MethodPost, "/internal/bind", `{"pid":`+pidStr(bob.PID)+`,"baas_id":"bbbb000000000001","bs_did":"bbbb000000000002"}`)

	first := decode(t, call(t, s.internalWhoami, http.MethodGet, "/internal/whoami?baas=aaaa000000000001&bsdid=aaaa000000000002", ""))
	second := decode(t, call(t, s.internalWhoami, http.MethodGet, "/internal/whoami?baas=bbbb000000000001&bsdid=bbbb000000000002", ""))
	if uint64(first["pid"].(float64)) != alice.PID || uint64(second["pid"].(float64)) != bob.PID {
		t.Fatalf("consoles resolved to %v and %v; want %d and %d", first["pid"], second["pid"], alice.PID, bob.PID)
	}
	if first["friendCode"] == second["friendCode"] {
		t.Error("both consoles were served the same friend code — the reported bug")
	}
}

// TestConsolePresenceMakesAFriendOnline: resolving a console's identity is proof
// the console is online, and must publish presence. Without this nothing reports a
// console that is not inside a NEX game, which is why friends looked offline.
func TestConsolePresenceMakesAFriendOnline(t *testing.T) {
	s, alice, _ := newTestServer(t)
	clearPresence(alice.PID)

	call(t, s.internalWhoami, http.MethodGet, "/internal/whoami?baas="+alice.BaasID, "")

	p, ok := getPresence(alice.PID)
	if !ok {
		t.Fatal("no presence was published for a console that just resolved its identity")
	}
	if p.Status != presenceStatusOnline {
		t.Errorf("status = %d, want %d (online)", p.Status, presenceStatusOnline)
	}
	if !consoleIsOnline(alice.PID) {
		t.Error("consoleIsOnline is false right after a resolution")
	}
}

// TestConsolePresenceDoesNotDowngradePlaying: a player IN a game must not be
// demoted to plain "online" by a console poll.
func TestConsolePresenceDoesNotDowngradePlaying(t *testing.T) {
	s, alice, _ := newTestServer(t)
	setPresence(alice.PID, presenceStatusPlaying, "", "0100c2500fc20000", "")

	call(t, s.internalWhoami, http.MethodGet, "/internal/whoami?baas="+alice.BaasID, "")

	p, _ := getPresence(alice.PID)
	if p.Status != presenceStatusPlaying {
		t.Errorf("status = %d, want %d (playing) — a console poll downgraded a game presence", p.Status, presenceStatusPlaying)
	}
	if p.AppID != "0100c2500fc20000" {
		t.Errorf("app id = %q, want the game's", p.AppID)
	}
}

// TestInternalPresenceWrite covers the endpoint nx-account calls when the console
// reports its presence, including the immediate offline.
func TestInternalPresenceWrite(t *testing.T) {
	s, alice, _ := newTestServer(t)

	body := `{"pid":` + pidStr(alice.PID) + `,"status":2,"app_id":"0100c2500fc20000","app_field":"YmxvYg=="}`
	if w := call(t, s.internalPresence, http.MethodPost, "/internal/presence", body); w.Code != http.StatusOK {
		t.Fatalf("presence write returned %d: %s", w.Code, w.Body.String())
	}
	p, ok := getPresence(alice.PID)
	if !ok || p.Status != presenceStatusPlaying || p.AppField != "YmxvYg==" {
		t.Fatalf("presence = %+v, ok=%v", p, ok)
	}

	// status 0 clears it at once, instead of waiting out the TTL.
	if w := call(t, s.internalPresence, http.MethodPost, "/internal/presence",
		`{"pid":`+pidStr(alice.PID)+`,"status":0}`); w.Code != http.StatusOK {
		t.Fatalf("offline write returned %d", w.Code)
	}
	if _, ok := getPresence(alice.PID); ok {
		t.Error("presence survived an explicit offline report")
	}
	if consoleIsOnline(alice.PID) {
		t.Error("consoleIsOnline is still true after an explicit offline report")
	}
}

// TestInternalPresenceRejectsUnknownAccount: an unchecked write would let an
// internal caller fill the presence table with anything.
func TestInternalPresenceRejectsUnknownAccount(t *testing.T) {
	s, _, _ := newTestServer(t)
	if w := call(t, s.internalPresence, http.MethodPost, "/internal/presence", `{"pid":1234567890,"status":1}`); w.Code != http.StatusNotFound {
		t.Fatalf("returned %d for an unknown account, want 404", w.Code)
	}
}

// TestNplnFriendsPublishesFavoritesAndBlocks: Splatoon 3 reads both, and an empty
// block list lets the game match a player with somebody they blocked.
func TestNplnFriendsPublishesFavoritesAndBlocks(t *testing.T) {
	s, alice, bob := newTestServer(t)
	store := s.store.(*jsonStore)

	if _, _, err := store.SendFriendRequest(alice.ID, bob.PID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AcceptFriendRequest(bob.ID, alice.PID); err != nil {
		t.Fatal(err)
	}
	if err := store.SetFavorite(alice.ID, bob.PID, true); err != nil {
		t.Fatal(err)
	}

	// A third account to block.
	carol, err := store.Create("carol", "carol@example.test", "x")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.BlockUser(alice.ID, carol.PID); err != nil {
		t.Fatal(err)
	}

	w := call(t, s.internalNplnFriends, http.MethodGet, "/internal/npln-friends?pid="+pidStr(alice.PID), "")
	if w.Code != http.StatusOK {
		t.Fatalf("npln-friends returned %d: %s", w.Code, w.Body.String())
	}
	var out struct {
		UserID  string `json:"user_id"`
		Friends []struct {
			PID      uint64 `json:"pid"`
			UserID   string `json:"user_id"`
			Favorite bool   `json:"favorite"`
		} `json:"friends"`
		Blocked []struct {
			PID uint64 `json:"pid"`
		} `json:"blocked"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.UserID == "" || !strings.HasPrefix(out.UserID, "u-") {
		t.Errorf("user_id = %q, want a u- id", out.UserID)
	}
	if len(out.Friends) != 1 || out.Friends[0].PID != bob.PID {
		t.Fatalf("friends = %+v, want just bob", out.Friends)
	}
	if !out.Friends[0].Favorite {
		t.Error("the favorite flag was not published; Splatoon 3 would show the friend unstarred")
	}
	if out.Friends[0].UserID == "" {
		t.Error("the friend has no NPLN user id; the game cannot match it")
	}
	if len(out.Blocked) != 1 || out.Blocked[0].PID != carol.PID {
		t.Errorf("blocked = %+v, want carol", out.Blocked)
	}
}

// TestConsolePresenceTTLIsConfigurable guards the knob that trades friend-offline
// responsiveness against flicker.
func TestConsolePresenceTTLIsConfigurable(t *testing.T) {
	t.Setenv("NEXTENDO_CONSOLE_PRESENCE_TTL", "42")
	if got := consolePresenceTTL(); got != 42*time.Second {
		t.Errorf("ttl = %s, want 42s", got)
	}
	t.Setenv("NEXTENDO_CONSOLE_PRESENCE_TTL", "2m")
	if got := consolePresenceTTL(); got != 2*time.Minute {
		t.Errorf("ttl = %s, want 2m", got)
	}
}

// itoa keeps the JSON literals above readable.
func pidStr(v uint64) string {
	if v == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}
