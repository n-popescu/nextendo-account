package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func testEnsureSecret() {
	if len(sessionSecret) == 0 {
		sessionSecret = []byte("test-session-secret-not-for-prod!")
	}
}

func TestOAuthAccessTokenRoundtrip(t *testing.T) {
	testEnsureSecret()
	tok := signOAuthToken(1800000042, "nxc_test", []string{"identity"}, time.Hour)
	c, ok := verifyOAuthToken(tok)
	if !ok || c.PID != 1800000042 || c.CID != "nxc_test" {
		t.Fatalf("roundtrip: ok=%v claims=%+v", ok, c)
	}
	if _, ok := verifyOAuthToken(tok + "x"); ok {
		t.Fatal("token altéré accepté")
	}
	if _, ok := verifyOAuthToken(signOAuthToken(1, "c", []string{"identity"}, -time.Minute)); ok {
		t.Fatal("token expiré accepté")
	}
}

func TestOAuthCodeExchange(t *testing.T) {
	testEnsureSecret()
	store, err := newJSONStore(filepath.Join(t.TempDir(), "accounts.json"))
	if err != nil {
		t.Fatal(err)
	}
	acct, err := store.Create("tester", "t@example.com", "x")
	if err != nil {
		t.Fatal(err)
	}
	srv := &server{store: store}

	secret := "topsecret"
	hash, _ := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	oauthReg.mu.Lock()
	oauthReg.m["nxc_x"] = &oauthClient{
		ID: "nxc_x", SecretHash: string(hash), Name: "TestApp",
		RedirectURIs: []string{"https://app.example.com/cb"}, Scopes: []string{"identity", "friends"},
	}
	oauthReg.mu.Unlock()

	verifier := "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	seedCode := func() string {
		return newAuthCode(authCodeData{
			clientID: "nxc_x", pid: acct.PID, scopes: []string{"identity"},
			redirectURI: "https://app.example.com/cb", challenge: challenge,
			expiry: time.Now().Add(time.Minute),
		})
	}
	post := func(f url.Values) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/api/oauth/token", strings.NewReader(f.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		srv.oauthToken(w, r)
		return w
	}
	base := func(code string) url.Values {
		return url.Values{
			"grant_type": {"authorization_code"}, "code": {code}, "client_id": {"nxc_x"},
			"client_secret": {secret}, "redirect_uri": {"https://app.example.com/cb"},
			"code_verifier": {verifier},
		}
	}

	// 1) échange nominal → access token
	code := seedCode()
	w := post(base(code))
	if w.Code != 200 {
		t.Fatalf("token: %d %s", w.Code, w.Body.String())
	}
	var tr struct {
		AccessToken string `json:"access_token"`
		Scope       string `json:"scope"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &tr)
	claims, ok := verifyOAuthToken(tr.AccessToken)
	if !ok || claims.PID != acct.PID {
		t.Fatalf("access token invalide: %s", w.Body.String())
	}

	// 2) usage unique : rejouer le même code échoue
	if w2 := post(base(code)); w2.Code == 200 {
		t.Fatal("code rejoué accepté (doit être usage unique)")
	}

	// 3) userinfo scopé → identité
	ur := httptest.NewRequest("GET", "/api/oauth/userinfo", nil)
	ur.Header.Set("Authorization", "Bearer "+tr.AccessToken)
	uw := httptest.NewRecorder()
	srv.oauthUserinfo(uw, ur)
	if uw.Code != 200 || !strings.Contains(uw.Body.String(), "tester") {
		t.Fatalf("userinfo: %d %s", uw.Code, uw.Body.String())
	}

	// 4) mauvais client_secret → refus
	bad := base(seedCode())
	bad.Set("client_secret", "wrong")
	if wb := post(bad); wb.Code == 200 {
		t.Fatal("client_secret erroné accepté")
	}

	// 5) mauvais PKCE verifier → refus
	badpk := base(seedCode())
	badpk.Set("code_verifier", "not-the-verifier")
	if wp := post(badpk); wp.Code == 200 {
		t.Fatal("PKCE verifier erroné accepté")
	}
}
