package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"html"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// OAuth « Sign in with Nextendo » — flow Authorization Code (+ PKCE).
//
// C'est le chemin PROPRE pour qu'un site tiers laisse ses visiteurs accéder à
// leur compte Nextendo SANS jamais voir leur mot de passe : le tiers redirige le
// navigateur vers /api/oauth/authorize (servi ICI, sur l'origine nextendo.network),
// l'utilisateur s'authentifie et consent SUR NOTRE DOMAINE, puis revient chez le
// tiers avec un `code` à usage unique, que le serveur du tiers échange (serveur-à-
// serveur) contre un access token scopé. Le mot de passe ne quitte jamais notre
// origine → aucun relais possible.
//
// Endpoints (tous sous /api/* → déjà routés vers ce serveur, zéro conf nginx) :
//   GET  /api/oauth/authorize        page de consentement + (POST) émission du code
//   POST /api/oauth/token            échange code → access token
//   GET  /api/oauth/userinfo         données scopées (Bearer access token)
//   POST /api/oauth/register-client  (admin) enregistre une application tierce

// ---------------------------------------------------------------------------
// Scopes (n'exposer QUE ce qu'on remplit réellement).

var oauthScopes = map[string]string{
	"identity": "ton identité Nextendo (pseudo, PID, code ami)",
	"friends":  "ta liste d'amis Nextendo",
}

func parseScopes(s string) []string {
	fields := strings.FieldsFunc(s, func(r rune) bool { return r == ' ' || r == ',' || r == '+' })
	seen := map[string]bool{}
	var out []string
	for _, x := range fields {
		if x != "" && !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

// scopesAllowed : chaque scope demandé doit être connu ET autorisé pour le client.
func scopesAllowed(req, allowed []string) bool {
	ok := map[string]bool{}
	for _, s := range allowed {
		ok[s] = true
	}
	for _, s := range req {
		if oauthScopes[s] == "" || !ok[s] {
			return false
		}
	}
	return true
}

func oauthContains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Utilitaires crypto.

func oauthRandToken(nbytes int) string {
	b := make([]byte, nbytes)
	if _, err := rand.Read(b); err != nil {
		return "" // extrêmement improbable ; les appelants traitent "" comme une erreur
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func oauthDataDir() string {
	if d := os.Getenv("NEXTENDO_DATA"); d != "" {
		// NEXTENDO_DATA peut pointer directement le fichier accounts.json ; dans ce
		// cas on veut son dossier (ex. /data/accounts.json → /data).
		if strings.HasSuffix(strings.ToLower(d), ".json") {
			return filepath.Dir(d)
		}
		return d
	}
	return "."
}

// ---------------------------------------------------------------------------
// Registre des clients (applications tierces). Admin-issued, persisté en JSON.

type oauthClient struct {
	ID           string    `json:"client_id"`
	SecretHash   string    `json:"secret_hash"` // bcrypt du client_secret ; le secret en clair n'est JAMAIS stocké
	Name         string    `json:"name"`
	RedirectURIs []string  `json:"redirect_uris"`
	Scopes       []string  `json:"scopes"`
	CreatedAt    time.Time `json:"created_at"`
}

var oauthReg = struct {
	mu sync.Mutex
	m  map[string]*oauthClient
}{m: map[string]*oauthClient{}}

func oauthClientsPath() string { return filepath.Join(oauthDataDir(), "oauth_clients.json") }

func init() { loadOAuthClients() }

func loadOAuthClients() {
	b, err := os.ReadFile(oauthClientsPath())
	if err != nil {
		return
	}
	var list []*oauthClient
	if json.Unmarshal(b, &list) != nil {
		return
	}
	oauthReg.mu.Lock()
	defer oauthReg.mu.Unlock()
	for _, c := range list {
		oauthReg.m[c.ID] = c
	}
}

func saveOAuthClientsLocked() {
	list := make([]*oauthClient, 0, len(oauthReg.m))
	for _, c := range oauthReg.m {
		list = append(list, c)
	}
	b, _ := json.MarshalIndent(list, "", "  ")
	if err := os.WriteFile(oauthClientsPath(), b, 0o600); err != nil {
		log.Printf("[oauth] écriture clients: %v", err)
	}
}

// emulatorClientID : client OAuth first-party de l'émulateur officiel. Client PUBLIC
// (pas de secret → PKCE + redirect loopback obligatoires, RFC 8252 pour app native).
const emulatorClientID = "nextendo-emulator"

func getOAuthClient(id string) (*oauthClient, bool) {
	if id == emulatorClientID {
		// Built-in : jamais dans le fichier de clients. SecretHash vide = client public ;
		// le redirect loopback est validé à part (isLoopbackRedirect).
		return &oauthClient{ID: emulatorClientID, Name: "Émulateur Nextendo", Scopes: []string{"identity", "friends"}}, true
	}
	oauthReg.mu.Lock()
	defer oauthReg.mu.Unlock()
	c, ok := oauthReg.m[id]
	return c, ok
}

// isLoopbackRedirect : redirect_uri loopback (RFC 8252) — http://127.0.0.1:<port> ou
// http://localhost:<port>. Le port est dynamique (l'app native écoute sur un port libre),
// donc pas de match exact possible : on exige loopback + http.
func isLoopbackRedirect(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" {
		return false
	}
	h := u.Hostname()
	return h == "127.0.0.1" || h == "localhost" || h == "::1"
}

// ---------------------------------------------------------------------------
// Codes d'autorisation : usage unique, TTL court, en mémoire.

type authCodeData struct {
	clientID    string
	pid         uint64
	scopes      []string
	redirectURI string
	challenge   string // PKCE S256 (vide = pas de PKCE)
	expiry      time.Time
}

var authCodes = struct {
	mu sync.Mutex
	m  map[string]authCodeData
}{m: map[string]authCodeData{}}

func newAuthCode(d authCodeData) string {
	code := oauthRandToken(32)
	if code == "" {
		return ""
	}
	authCodes.mu.Lock()
	authCodes.m[code] = d
	now := time.Now()
	for k, v := range authCodes.m { // nettoyage opportuniste
		if now.After(v.expiry) {
			delete(authCodes.m, k)
		}
	}
	authCodes.mu.Unlock()
	return code
}

func consumeAuthCode(code string) (authCodeData, bool) {
	authCodes.mu.Lock()
	defer authCodes.mu.Unlock()
	d, ok := authCodes.m[code]
	if !ok {
		return authCodeData{}, false
	}
	delete(authCodes.m, code) // usage unique
	if time.Now().After(d.expiry) {
		return authCodeData{}, false
	}
	return d, true
}

// ---------------------------------------------------------------------------
// Access token : signé (HMAC), payload lisible pour appliquer les scopes.

type oauthClaims struct {
	PID   uint64   `json:"pid"`
	CID   string   `json:"cid"`
	Scope []string `json:"scp"`
	Exp   int64    `json:"exp"`
}

func signOAuthToken(pid uint64, cid string, scopes []string, ttl time.Duration) string {
	c := oauthClaims{PID: pid, CID: cid, Scope: scopes, Exp: time.Now().Add(ttl).Unix()}
	b, _ := json.Marshal(c)
	p := base64.RawURLEncoding.EncodeToString(b)
	mac := hmac.New(sha256.New, sessionSecret)
	mac.Write([]byte("oauth-access:" + p))
	return p + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func verifyOAuthToken(tok string) (*oauthClaims, bool) {
	parts := strings.SplitN(tok, ".", 2)
	if len(parts) != 2 {
		return nil, false
	}
	mac := hmac.New(sha256.New, sessionSecret)
	mac.Write([]byte("oauth-access:" + parts[0]))
	want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(want), []byte(parts[1])) {
		return nil, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, false
	}
	var c oauthClaims
	if json.Unmarshal(raw, &c) != nil {
		return nil, false
	}
	if time.Now().Unix() > c.Exp {
		return nil, false
	}
	return &c, true
}

// ---------------------------------------------------------------------------
// GET/POST /api/oauth/authorize

func (s *server) oauthAuthorize(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.oauthAuthorizePage(w, r)
	case http.MethodPost:
		s.oauthAuthorizeApprove(w, r)
	default:
		writeErr(w, http.StatusMethodNotAllowed, "GET ou POST attendu")
	}
}

// validateAuthorizeReq contrôle les paramètres communs à GET (affichage) et POST
// (émission). Renvoie (client, scopes, redirectURI, messageErreur).
func validateAuthorizeReq(q url.Values) (*oauthClient, []string, string, string) {
	client, ok := getOAuthClient(q.Get("client_id"))
	if !ok {
		return nil, nil, "", "Application inconnue (client_id invalide)."
	}
	redirectURI := q.Get("redirect_uri")
	if client.ID == emulatorClientID {
		if !isLoopbackRedirect(redirectURI) {
			return nil, nil, "", "redirect_uri doit être loopback (127.0.0.1) pour l'émulateur."
		}
	} else if !oauthContains(client.RedirectURIs, redirectURI) {
		return nil, nil, "", "redirect_uri non autorisée pour cette application."
	}
	if q.Get("response_type") != "code" {
		return nil, nil, "", `response_type doit être "code".`
	}
	scopes := parseScopes(q.Get("scope"))
	if len(scopes) == 0 {
		scopes = []string{"identity"}
	}
	if !scopesAllowed(scopes, client.Scopes) {
		return nil, nil, "", "Scope demandé non autorisé pour cette application."
	}
	return client, scopes, redirectURI, ""
}

func (s *server) oauthAuthorizePage(w http.ResponseWriter, r *http.Request) {
	client, scopes, _, errMsg := validateAuthorizeReq(r.URL.Query())
	if errMsg != "" {
		oauthErrorPage(w, errMsg)
		return
	}
	oauthConsentPage(w, client, scopes)
}

func (s *server) oauthAuthorizeApprove(w http.ResponseWriter, r *http.Request) {
	acct, ok := s.accountFromBearer(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "Connecte-toi d'abord sur nextendo.network.")
		return
	}
	q := r.URL.Query()
	client, scopes, redirectURI, errMsg := validateAuthorizeReq(q)
	if errMsg != "" {
		writeErr(w, http.StatusBadRequest, errMsg)
		return
	}
	code := newAuthCode(authCodeData{
		clientID:    client.ID,
		pid:         acct.PID,
		scopes:      scopes,
		redirectURI: redirectURI,
		challenge:   q.Get("code_challenge"),
		expiry:      time.Now().Add(60 * time.Second),
	})
	if code == "" {
		writeErr(w, http.StatusInternalServerError, "erreur interne")
		return
	}
	u, err := url.Parse(redirectURI)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "redirect_uri invalide")
		return
	}
	qq := u.Query()
	qq.Set("code", code)
	if st := q.Get("state"); st != "" {
		qq.Set("state", st)
	}
	u.RawQuery = qq.Encode()
	log.Printf("[oauth] code émis client=%s pid=%d scopes=%v", client.ID, acct.PID, scopes)
	writeJSON(w, http.StatusOK, map[string]any{"redirect": u.String()})
}

// ---------------------------------------------------------------------------
// POST /api/oauth/token  (serveur-à-serveur)

func oauthTokenErr(w http.ResponseWriter, code string) {
	writeJSON(w, http.StatusBadRequest, map[string]any{"error": code})
}

func (s *server) oauthToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST attendu")
		return
	}
	_ = r.ParseForm()
	if r.PostFormValue("grant_type") != "authorization_code" {
		oauthTokenErr(w, "unsupported_grant_type")
		return
	}
	clientID := r.PostFormValue("client_id")
	client, ok := getOAuthClient(clientID)
	if !ok {
		oauthTokenErr(w, "invalid_client")
		return
	}
	isPublic := client.SecretHash == "" // client public (émulateur) : pas de secret, PKCE obligatoire
	if !isPublic {
		if bcrypt.CompareHashAndPassword([]byte(client.SecretHash), []byte(r.PostFormValue("client_secret"))) != nil {
			oauthTokenErr(w, "invalid_client")
			return
		}
	}
	d, ok := consumeAuthCode(r.PostFormValue("code"))
	if !ok {
		oauthTokenErr(w, "invalid_grant")
		return
	}
	if d.clientID != clientID || d.redirectURI != r.PostFormValue("redirect_uri") {
		oauthTokenErr(w, "invalid_grant")
		return
	}
	if isPublic && d.challenge == "" { // PKCE obligatoire pour un client public
		oauthTokenErr(w, "invalid_grant")
		return
	}
	if d.challenge != "" { // PKCE : sha256(verifier) doit matcher le challenge
		sum := sha256.Sum256([]byte(r.PostFormValue("code_verifier")))
		if base64.RawURLEncoding.EncodeToString(sum[:]) != d.challenge {
			oauthTokenErr(w, "invalid_grant")
			return
		}
	}
	// Client first-party émulateur : on renvoie les identifiants online (nex_token), comme
	// /api/login, pour que l'émulateur se connecte SANS avoir jamais vu le mot de passe.
	if clientID == emulatorClientID {
		acct, err := s.store.ByPID(d.pid)
		if err != nil {
			oauthTokenErr(w, "invalid_grant")
			return
		}
		log.Printf("[oauth] émulateur connecté pid=%d (%s)", acct.PID, acct.Username)
		writeJSON(w, http.StatusOK, map[string]any{
			"token_type": "Bearer",
			"nex_token":  signNexToken(acct.PID, acct.Username),
			"account":    acct.Public(),
		})
		return
	}
	tok := signOAuthToken(d.pid, clientID, d.scopes, time.Hour)
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": tok,
		"token_type":   "Bearer",
		"expires_in":   3600,
		"scope":        strings.Join(d.scopes, " "),
	})
}

// ---------------------------------------------------------------------------
// GET /api/oauth/userinfo  (Bearer access token)

func (s *server) oauthUserinfo(w http.ResponseWriter, r *http.Request) {
	claims, ok := verifyOAuthToken(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if !ok {
		writeErr(w, http.StatusUnauthorized, "access token invalide ou expiré")
		return
	}
	acct, err := s.store.ByPID(claims.PID)
	if err != nil {
		writeErr(w, http.StatusNotFound, "compte introuvable")
		return
	}
	scp := map[string]bool{}
	for _, name := range claims.Scope {
		scp[name] = true
	}
	out := map[string]any{"scope": strings.Join(claims.Scope, " ")}
	if scp["identity"] {
		out["pid"] = acct.PID
		out["username"] = acct.Username
		out["friend_code"] = acct.FriendCode
		if acct.Profile != nil && acct.Profile.Name != "" {
			out["display_name"] = acct.Profile.Name
		}
	}
	if scp["friends"] {
		friends := make([]map[string]any, 0, len(acct.Friends))
		for _, fpid := range acct.Friends {
			if f, e := s.store.ByPID(fpid); e == nil {
				friends = append(friends, map[string]any{"pid": f.PID, "username": f.Username, "friend_code": f.FriendCode})
			} else {
				friends = append(friends, map[string]any{"pid": fpid})
			}
		}
		out["friends"] = friends
	}
	writeJSON(w, http.StatusOK, out)
}

// ---------------------------------------------------------------------------
// POST /api/oauth/register-client  (admin) — émet un nouveau client tiers.

func (s *server) oauthRegisterClient(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST attendu")
		return
	}
	acct, ok := s.accountFromBearer(r)
	if !ok || !isAdminAccount(acct) {
		writeErr(w, http.StatusForbidden, "admin requis")
		return
	}
	var in struct {
		Name         string   `json:"name"`
		RedirectURIs []string `json:"redirect_uris"`
		Scopes       []string `json:"scopes"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil {
		writeErr(w, http.StatusBadRequest, "JSON invalide")
		return
	}
	if strings.TrimSpace(in.Name) == "" || len(in.RedirectURIs) == 0 {
		writeErr(w, http.StatusBadRequest, "name et redirect_uris requis")
		return
	}
	for _, u := range in.RedirectURIs {
		pu, err := url.Parse(u)
		if err != nil || pu.Scheme != "https" || pu.Host == "" {
			writeErr(w, http.StatusBadRequest, "chaque redirect_uri doit être une URL https absolue")
			return
		}
	}
	scopes := in.Scopes
	if len(scopes) == 0 {
		scopes = []string{"identity"}
	}
	for _, name := range scopes {
		if oauthScopes[name] == "" {
			writeErr(w, http.StatusBadRequest, "scope inconnu : "+name)
			return
		}
	}
	clientID := "nxc_" + oauthRandToken(9)
	secret := oauthRandToken(24)
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "erreur interne")
		return
	}
	oauthReg.mu.Lock()
	oauthReg.m[clientID] = &oauthClient{
		ID: clientID, SecretHash: string(hash), Name: strings.TrimSpace(in.Name),
		RedirectURIs: in.RedirectURIs, Scopes: scopes, CreatedAt: time.Now(),
	}
	saveOAuthClientsLocked()
	oauthReg.mu.Unlock()
	log.Printf("[oauth] client enregistré: %s (%q) par %s", clientID, in.Name, acct.Username)
	writeJSON(w, http.StatusCreated, map[string]any{
		"client_id":     clientID,
		"client_secret": secret,
		"scopes":        scopes,
		"note":          "Note le client_secret MAINTENANT — il ne sera plus jamais affiché.",
	})
}

// ---------------------------------------------------------------------------
// Pages HTML (servies sur l'origine nextendo.network).

func oauthErrorPage(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)
	page := strings.ReplaceAll(oauthErrorHTML, "__MSG__", html.EscapeString(msg))
	_, _ = w.Write([]byte(page))
}

func oauthConsentPage(w http.ResponseWriter, client *oauthClient, scopes []string) {
	// Injecté en JSON : le JS de la page (i18n client) construit le texte + traduit
	// les scopes par clé, dans la langue du navigateur (comme le site).
	clientJSON, _ := json.Marshal(client.Name)
	scopesJSON, _ := json.Marshal(scopes)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	page := oauthConsentHTML
	page = strings.ReplaceAll(page, "__CLIENT__", string(clientJSON))
	page = strings.ReplaceAll(page, "__SCOPES__", string(scopesJSON))
	page = strings.ReplaceAll(page, "__SITEKEY__", html.EscapeString(turnstileSitekey()))
	_, _ = w.Write([]byte(page))
}

const oauthErrorHTML = `<!doctype html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Nextendo — erreur</title>
<style>body{font-family:system-ui,sans-serif;background:#0f1115;color:#e7e9ee;display:grid;place-items:center;min-height:100vh;margin:0}
.card{max-width:420px;padding:28px;background:#171a21;border:1px solid #262b36;border-radius:14px}
h1{font-size:18px;margin:0 0 10px}p{color:#aab1c0;line-height:1.5}a{color:#8ab4ff}</style></head>
<body><div class="card"><h1>Requête OAuth invalide</h1><p>__MSG__</p>
<p><a href="/">Retour à Nextendo</a></p></div></body></html>`

const oauthConsentHTML = `<!doctype html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Se connecter avec Nextendo</title>
<style>
:root{color-scheme:dark}
*{box-sizing:border-box}
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:radial-gradient(1200px 600px at 20% -10%,#12233a 0%,#0b0d12 55%);color:#e7e9ee;display:grid;place-items:center;min-height:100vh;margin:0}
.card{max-width:410px;width:calc(100% - 32px);padding:30px;background:#12151c;border:1px solid #232833;border-radius:18px;box-shadow:0 24px 70px rgba(0,0,0,.45)}
.brand{display:flex;align-items:center;gap:10px;margin-bottom:22px;font-weight:700;font-size:15px}
.brand .logo{width:28px;height:28px;border-radius:8px;background:linear-gradient(135deg,#3b82f6,#22d3ee);display:grid;place-items:center;color:#fff;font-size:16px}
h1{font-size:20px;margin:0 0 6px;line-height:1.3}.sub{color:#9aa3b2;margin:0 0 18px;line-height:1.5;font-size:14px}
label{display:block;font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:#7b8394;margin:14px 0 6px}
input{width:100%;padding:12px 14px;background:#0b0d12;border:1px solid #2a303c;border-radius:10px;color:#e7e9ee;font-size:15px}
input:focus{outline:none;border-color:#3b82f6}
.btn{width:100%;padding:13px;border:0;border-radius:11px;font-size:15px;font-weight:600;cursor:pointer;margin-top:10px}
.btn--p{background:#3b82f6;color:#fff}.btn--g{background:#1b2029;color:#cfd4de}
.btn:disabled{opacity:.6;cursor:default}
.who{display:flex;align-items:center;gap:13px;margin:0 0 18px;padding:13px;background:#0b0d12;border:1px solid #232833;border-radius:13px}
.who img,.who .ph{width:46px;height:46px;border-radius:50%;object-fit:cover;background:#232833;flex:0 0 auto}
.who b{display:block;font-size:15px}.who span{color:#7b8394;font-size:12px}
ul{margin:6px 0 20px;padding-left:20px}li{color:#cfd4de;margin:7px 0}
.row{display:flex;gap:10px}.err{color:#ff8a8a;margin-top:10px;font-size:13px;min-height:1em}
small{color:#6b7280;display:block;margin-top:18px;line-height:1.45;font-size:12px}
.hidden{display:none}.ts{margin:14px 0 2px}
</style></head>
<body><div class="card">
<div class="brand"><span class="logo">▲</span>Nextendo Network</div>

<div id="loginStep" class="hidden">
  <h1 id="loginTitle"></h1>
  <p class="sub" id="loginSub"></p>
  <label id="lblEmail"></label><input id="email" type="email" autocomplete="email" placeholder="you@example.com">
  <label id="lblPassword"></label><input id="password" type="password" autocomplete="current-password" placeholder="••••••••">
  <div id="ts" class="ts"></div>
  <button class="btn btn--p" id="signIn"></button>
  <button class="btn btn--g" id="createAcc"></button>
  <p class="err" id="loginErr"></p>
</div>

<div id="consentStep" class="hidden">
  <h1 id="consentTitle"></h1>
  <div class="who" id="who"><div class="ph"></div><div><b id="whoName">…</b><span id="whoCode"></span></div></div>
  <p class="sub" id="consentSub"></p>
  <ul id="scopes"></ul>
  <div class="row"><button class="btn btn--g" id="deny"></button><button class="btn btn--p" id="approve"></button></div>
  <button class="btn btn--g" id="switchAcc" style="margin-top:6px;font-size:13px;background:none;color:#7b8394"></button>
  <p class="err" id="consentErr"></p>
</div>

<small id="footer"></small>
</div>
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js?onload=nxTsOnload" async defer></script>
<script>
(function(){
  var q = new URLSearchParams(location.search);
  var SITEKEY = "__SITEKEY__";
  var CLIENT = __CLIENT__;
  var SCOPES = __SCOPES__;
  function $(id){ return document.getElementById(id); }

  var I18N = {
    loginTitle:{en:"Sign in to authorize",es:"Inicia sesión para autorizar",fr:"Connexion pour autoriser",pt:"Entre para autorizar",de:"Anmelden zum Autorisieren",it:"Accedi per autorizzare",ru:"Войдите для авторизации",zh:"登录以授权",ja:"承認のためにサインイン",ar:"سجّل الدخول للتفويض"},
    loginSub:{en:"{c} wants to connect to your Nextendo account. Sign in below to authorize it.",es:"{c} quiere conectarse a tu cuenta Nextendo. Inicia sesión abajo para autorizarlo.",fr:"{c} veut se connecter à ton compte Nextendo. Connecte-toi ci-dessous pour l'autoriser.",pt:"{c} quer ligar-se à tua conta Nextendo. Entra abaixo para autorizar.",de:"{c} möchte sich mit deinem Nextendo-Konto verbinden. Melde dich unten an, um es zu autorisieren.",it:"{c} vuole connettersi al tuo account Nextendo. Accedi qui sotto per autorizzarlo.",ru:"{c} хочет подключиться к вашему аккаунту Nextendo. Войдите ниже, чтобы разрешить.",zh:"{c} 想要连接到你的 Nextendo 账户。请在下方登录以授权。",ja:"{c} があなたの Nextendo アカウントへの接続を求めています。下でサインインして承認してください。",ar:"يريد {c} الاتصال بحساب Nextendo الخاص بك. سجّل الدخول أدناه للسماح بذلك."},
    lblEmail:{en:"E-mail",es:"Correo",fr:"E-mail",pt:"E-mail",de:"E-Mail",it:"E-mail",ru:"Эл. почта",zh:"电子邮件",ja:"メール",ar:"البريد الإلكتروني"},
    lblPassword:{en:"Password",es:"Contraseña",fr:"Mot de passe",pt:"Palavra-passe",de:"Passwort",it:"Password",ru:"Пароль",zh:"密码",ja:"パスワード",ar:"كلمة المرور"},
    signIn:{en:"Sign in with Nextendo",es:"Iniciar sesión con Nextendo",fr:"Se connecter avec Nextendo",pt:"Entrar com Nextendo",de:"Mit Nextendo anmelden",it:"Accedi con Nextendo",ru:"Войти через Nextendo",zh:"使用 Nextendo 登录",ja:"Nextendo でサインイン",ar:"تسجيل الدخول عبر Nextendo"},
    createAcc:{en:"No account yet? Create one",es:"¿Sin cuenta? Crea una",fr:"Pas encore de compte ? En créer un",pt:"Sem conta? Cria uma",de:"Noch kein Konto? Erstelle eins",it:"Non hai un account? Creane uno",ru:"Нет аккаунта? Создайте",zh:"还没有账户？创建一个",ja:"アカウントがない？作成する",ar:"ليس لديك حساب؟ أنشئ واحدًا"},
    consentTitle:{en:"{c} wants to sign you in",es:"{c} quiere iniciar tu sesión",fr:"{c} veut se connecter",pt:"{c} quer iniciar a tua sessão",de:"{c} möchte dich anmelden",it:"{c} vuole farti accedere",ru:"{c} хочет выполнить вход",zh:"{c} 想要为你登录",ja:"{c} がサインインしようとしています",ar:"يريد {c} تسجيل دخولك"},
    consentSub:{en:"This application is requesting access to:",es:"Esta aplicación solicita acceso a:",fr:"Cette application demande l'accès à :",pt:"Esta aplicação pede acesso a:",de:"Diese Anwendung fordert Zugriff auf:",it:"Questa applicazione richiede l'accesso a:",ru:"Это приложение запрашивает доступ к:",zh:"此应用请求访问：",ja:"このアプリは次へのアクセスを求めています：",ar:"يطلب هذا التطبيق الوصول إلى:"},
    scope_identity:{en:"your Nextendo identity (nickname, PID, friend code)",es:"tu identidad Nextendo (apodo, PID, código de amigo)",fr:"ton identité Nextendo (pseudo, PID, code ami)",pt:"a tua identidade Nextendo (nome, PID, código de amigo)",de:"deine Nextendo-Identität (Name, PID, Freundescode)",it:"la tua identità Nextendo (nome, PID, codice amico)",ru:"вашей личности Nextendo (никнейм, PID, код друга)",zh:"你的 Nextendo 身份（昵称、PID、好友码）",ja:"あなたの Nextendo アイデンティティ（ニックネーム、PID、フレンドコード）",ar:"هويتك في Nextendo (الاسم، PID، رمز الصديق)"},
    scope_friends:{en:"your Nextendo friends list",es:"tu lista de amigos Nextendo",fr:"ta liste d'amis Nextendo",pt:"a tua lista de amigos Nextendo",de:"deine Nextendo-Freundesliste",it:"la tua lista amici Nextendo",ru:"вашего списка друзей Nextendo",zh:"你的 Nextendo 好友列表",ja:"あなたの Nextendo フレンドリスト",ar:"قائمة أصدقائك في Nextendo"},
    deny:{en:"Deny",es:"Rechazar",fr:"Refuser",pt:"Recusar",de:"Ablehnen",it:"Rifiuta",ru:"Отклонить",zh:"拒绝",ja:"拒否",ar:"رفض"},
    approve:{en:"Authorize",es:"Autorizar",fr:"Autoriser",pt:"Autorizar",de:"Autorisieren",it:"Autorizza",ru:"Разрешить",zh:"授权",ja:"承認",ar:"تفويض"},
    switchAcc:{en:"Not you? Switch account",es:"¿No eres tú? Cambiar de cuenta",fr:"Ce n'est pas vous ? Changer de compte",pt:"Não és tu? Trocar de conta",de:"Nicht du? Konto wechseln",it:"Non sei tu? Cambia account",ru:"Это не вы? Сменить аккаунт",zh:"不是你？切换账户",ja:"あなたではない？アカウントを切り替える",ar:"لست أنت؟ تبديل الحساب"},
    footer:{en:"You're on nextendo.network. Your password stays here — the application never sees it.",es:"Estás en nextendo.network. Tu contraseña se queda aquí: la aplicación nunca la ve.",fr:"Tu es sur nextendo.network. Ton mot de passe reste ici — l'application ne le voit jamais.",pt:"Estás em nextendo.network. A tua palavra-passe fica aqui — a aplicação nunca a vê.",de:"Du bist auf nextendo.network. Dein Passwort bleibt hier — die Anwendung sieht es nie.",it:"Sei su nextendo.network. La tua password resta qui — l'applicazione non la vede mai.",ru:"Вы на nextendo.network. Ваш пароль остаётся здесь — приложение его не видит.",zh:"你在 nextendo.network 上。你的密码留在这里——应用永远看不到它。",ja:"あなたは nextendo.network にいます。パスワードはここに残り、アプリが見ることはありません。",ar:"أنت على nextendo.network. كلمة مرورك تبقى هنا — لا يراها التطبيق أبدًا."},
    errFields:{en:"Enter your e-mail and password.",es:"Introduce tu correo y contraseña.",fr:"Renseigne ton e-mail et ton mot de passe.",pt:"Introduz o teu e-mail e palavra-passe.",de:"Gib deine E-Mail und dein Passwort ein.",it:"Inserisci e-mail e password.",ru:"Введите эл. почту и пароль.",zh:"请输入你的电子邮件和密码。",ja:"メールとパスワードを入力してください。",ar:"أدخل بريدك الإلكتروني وكلمة المرور."},
    errCreds:{en:"Incorrect credentials.",es:"Credenciales incorrectas.",fr:"Identifiants incorrects.",pt:"Credenciais incorretas.",de:"Falsche Anmeldedaten.",it:"Credenziali errate.",ru:"Неверные данные.",zh:"凭据不正确。",ja:"認証情報が正しくありません。",ar:"بيانات الاعتماد غير صحيحة."},
    errGeneric:{en:"Error.",es:"Error.",fr:"Erreur.",pt:"Erro.",de:"Fehler.",it:"Errore.",ru:"Ошибка.",zh:"错误。",ja:"エラー。",ar:"خطأ."},
    errNetwork:{en:"Network error.",es:"Error de red.",fr:"Erreur réseau.",pt:"Erro de rede.",de:"Netzwerkfehler.",it:"Errore di rete.",ru:"Ошибка сети.",zh:"网络错误。",ja:"ネットワークエラー。",ar:"خطأ في الشبكة."}
  };
  var SUPPORTED = {en:1,es:1,fr:1,pt:1,de:1,it:1,ru:1,zh:1,ja:1,ar:1};
  function detectLang(){
    var s = localStorage.getItem('nx_lang'); if(s && SUPPORTED[s]) return s;
    var navs = (navigator.languages && navigator.languages.length) ? navigator.languages : [navigator.language||''];
    for(var i=0;i<navs.length;i++){ var two=String(navs[i]).slice(0,2).toLowerCase(); if(SUPPORTED[two]) return two; }
    return 'en';
  }
  var LANG = detectLang();
  function t(k){ var e=I18N[k]; return (e && (e[LANG]||e.en)) || ''; }
  if(LANG==='ar'){ document.documentElement.dir='rtl'; }

  // Texte statique
  $('loginTitle').textContent=t('loginTitle');
  $('loginSub').innerHTML = t('loginSub').replace('{c}','<b>'+String(CLIENT).replace(/[<>&]/g,'')+'</b>');
  $('lblEmail').textContent=t('lblEmail'); $('lblPassword').textContent=t('lblPassword');
  $('signIn').textContent=t('signIn'); $('createAcc').textContent=t('createAcc');
  $('consentTitle').textContent=t('consentTitle').replace('{c}',CLIENT);
  $('consentSub').textContent=t('consentSub');
  $('deny').textContent=t('deny'); $('approve').textContent=t('approve');
  $('switchAcc').textContent=t('switchAcc'); $('footer').textContent=t('footer');
  var ul=$('scopes'); (SCOPES||[]).forEach(function(sc){ var li=document.createElement('li'); li.textContent=t('scope_'+sc)||sc; ul.appendChild(li); });

  function show(step){ $('loginStep').classList.toggle('hidden', step!=='login'); $('consentStep').classList.toggle('hidden', step!=='consent'); }
  window.nxTsOnload = function(){ if(SITEKEY && window.turnstile){ turnstile.render('#ts', {sitekey:SITEKEY, theme:'dark'}); } };

  function denyRedirect(){
    var u = q.get('redirect_uri'); if(!u){ location.href='/'; return; }
    location.href = u + (u.indexOf('?')>=0?'&':'?') + 'error=access_denied' + (q.get('state')?('&state='+encodeURIComponent(q.get('state'))):'');
  }

  function loadConsent(token){
    fetch('/api/me',{headers:{Authorization:'Bearer '+token}}).then(function(r){return r.ok?r.json():null;}).then(function(me){
      var a = me && me.account; if(!a){ show('login'); return; }
      $('whoName').textContent = a.username || ('PID '+a.pid);
      $('whoCode').textContent = a.friend_code || '';
      show('consent');
    }).catch(function(){ show('login'); });
    fetch('/api/profile',{headers:{Authorization:'Bearer '+token}}).then(function(r){return r.ok?r.json():null;}).then(function(p){
      var img = p && p.profile && p.profile.image;
      if(img){ var e=document.createElement('img'); e.src='data:image/jpeg;base64,'+img; e.alt=''; var w=$('who'); w.replaceChild(e, w.firstElementChild); }
    }).catch(function(){});
  }

  $('deny').onclick = denyRedirect;
  $('switchAcc').onclick = function(){ localStorage.removeItem('nx_token'); $('email').value=''; $('password').value=''; show('login'); if(window.turnstile){ turnstile.reset(); } };
  $('approve').onclick = function(){
    var token = localStorage.getItem('nx_token')||''; this.disabled=true; $('consentErr').textContent='';
    fetch(location.href,{method:'POST',headers:{Authorization:'Bearer '+token}}).then(function(r){return r.json().then(function(j){return{ok:r.ok,j:j};});}).then(function(res){
      if(res.ok && res.j.redirect){ location.href = res.j.redirect; }
      else { $('consentErr').textContent = (res.j && res.j.error) || t('errGeneric'); $('approve').disabled=false; }
    }).catch(function(){ $('consentErr').textContent=t('errNetwork'); $('approve').disabled=false; });
  };

  $('signIn').onclick = function(){
    var email=$('email').value.trim(), pw=$('password').value; $('loginErr').textContent='';
    if(!email || !pw){ $('loginErr').textContent=t('errFields'); return; }
    this.disabled=true;
    var headers={'Content-Type':'application/json'};
    if(SITEKEY && window.turnstile){ var tk=turnstile.getResponse(); if(tk){ headers['Cf-Turnstile-Response']=tk; } }
    fetch('/api/login',{method:'POST',headers:headers,body:JSON.stringify({login:email,password:pw})}).then(function(r){return r.json().then(function(j){return{ok:r.ok,j:j};});}).then(function(res){
      if(res.ok && res.j.token){ localStorage.setItem('nx_token', res.j.token); loadConsent(res.j.token); }
      else { $('loginErr').textContent = (res.j && res.j.error) || t('errCreds'); $('signIn').disabled=false; if(window.turnstile){ turnstile.reset(); } }
    }).catch(function(){ $('loginErr').textContent=t('errNetwork'); $('signIn').disabled=false; });
  };
  $('createAcc').onclick = function(){ window.open('/register','_blank'); };

  var token = localStorage.getItem('nx_token')||'';
  if(token){ loadConsent(token); } else { show('login'); }
})();
</script></body></html>`
