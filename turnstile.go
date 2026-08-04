package main

import (
	"crypto/subtle"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Turnstile (Cloudflare) — verrou anti-relais.
//
// Problème : n'importe qui peut copier nos pages login/inscription (open source)
// et relayer les identifiants vers notre API via son propre proxy serveur (le cas
// themyndgame.com). Aucun contrôle d'en-tête (Origin/Referer/CORS) ne l'arrête,
// car un proxy serveur forge tous les en-têtes.
//
// La parade : un challenge Turnstile lié À NOTRE DOMAINE. Cloudflare renvoie le
// `hostname` sur lequel le widget a tourné ; on le vérifie ICI. Un formulaire servi
// depuis un autre domaine (même avec notre sitekey) produit un token dont le
// hostname ne matche pas → refusé. Le proxy ne peut PAS obtenir un token valide
// pour nextendo.network depuis son domaine.
//
// Fail-open de configuration : si NEXTENDO_TURNSTILE_SECRET est vide, la vérif est
// DÉSACTIVÉE (ne casse ni le dev ni la prod tant que la clé n'est pas posée). Le
// verrou s'active dès que le secret est défini ET que les pages envoient le token.
var turnstileHTTP = &http.Client{Timeout: 5 * time.Second}

// turnstileSecret : secret Cloudflare, lu depuis l'env OU (fallback) un fichier
// `turnstile_secret.key` dans le dossier de données. Le fallback fichier évite de
// devoir recréer le conteneur juste pour poser une variable d'env.
func turnstileSecret() string {
	if v := os.Getenv("NEXTENDO_TURNSTILE_SECRET"); v != "" {
		return v
	}
	b, _ := os.ReadFile(oauthDataDir() + "/turnstile_secret.key")
	return strings.TrimSpace(string(b))
}

// turnstileEnabled : la vérif n'est active que si un secret est configuré.
func turnstileEnabled() bool { return turnstileSecret() != "" }

// turnstileSitekey : sitekey Turnstile (PUBLIQUE) pour les widgets rendus par le serveur
// (page de consentement OAuth). Env NEXTENDO_TURNSTILE_SITEKEY, sinon fichier
// `turnstile_sitekey.txt` dans le dossier de données. Vide = pas de widget.
func turnstileSitekey() string {
	if v := os.Getenv("NEXTENDO_TURNSTILE_SITEKEY"); v != "" {
		return v
	}
	b, _ := os.ReadFile(oauthDataDir() + "/turnstile_sitekey.txt")
	return strings.TrimSpace(string(b))
}

// turnstileAllowedHosts : hostnames acceptés pour le token.
// Défaut = nextendo.network (+ www) ; surchargeable via NEXTENDO_TURNSTILE_HOSTNAMES
// (liste séparée par des virgules).
func turnstileAllowedHosts() []string {
	if v := os.Getenv("NEXTENDO_TURNSTILE_HOSTNAMES"); v != "" {
		var out []string
		for _, h := range strings.Split(v, ",") {
			if h = strings.TrimSpace(strings.ToLower(h)); h != "" {
				out = append(out, h)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	return []string{"nextendo.network", "www.nextendo.network"}
}

type turnstileResp struct {
	Success    bool     `json:"success"`
	Hostname   string   `json:"hostname"`
	ErrorCodes []string `json:"error-codes"`
}

// verifyTurnstile appelle siteverify et exige success + hostname autorisé.
// Renvoie (ok, raison). ok=false ⇒ challenge refusé (identifiants NON traités).
func verifyTurnstile(token, remoteIP string) (ok bool, reason string) {
	secret := turnstileSecret()
	if secret == "" {
		return true, "disabled" // non configuré → fail-open
	}
	if strings.TrimSpace(token) == "" {
		// Fail-open sur token ABSENT : le widget Turnstile ne s'est pas chargé chez
		// l'utilisateur (bloqueur de pub, extension vie privée, DNS FAI, ou script CF
		// `api.js` — chargé async/defer — pas encore résolu au moment du clic). Bloquer
		// ici (403) verrouillait des utilisateurs LÉGITIMES hors de leur compte : ils
		// lisaient « Échec de la vérification » comme « mon mot de passe ne marche pas »
		// (519 refus missing-token observés, dont de vraies IP).
		//
		// L'anti-relais NE repose PAS sur la présence d'un token quelconque, mais sur son
		// HOSTNAME : un relais qui sert notre formulaire depuis son domaine produit un
		// token à hostname étranger → refusé plus bas. Un relais qui n'envoie AUCUN token
		// n'a de toute façon rien gagné, et le vrai rempart identité reste le flow OAuth
		// « Se connecter avec Nextendo ». On préfère donc laisser passer que verrouiller.
		return true, "missing-token-allowed"
	}
	form := url.Values{"secret": {secret}, "response": {token}}
	if remoteIP != "" {
		form.Set("remoteip", remoteIP)
	}
	resp, err := turnstileHTTP.PostForm("https://challenges.cloudflare.com/turnstile/v0/siteverify", form)
	if err != nil {
		// Cloudflare injoignable = souci d'infra CHEZ NOUS, pas un levier pour
		// l'attaquant (ses tokens sont soit absents soit hostname-étranger, donc
		// bloqués par les branches ci-dessus). On préfère ne pas mettre tout le
		// login légitime à terre pour une panne CF passagère.
		log.Printf("[turnstile] siteverify injoignable: %v (login laissé passer)", err)
		return true, "verify-unreachable"
	}
	defer resp.Body.Close()
	var tr turnstileResp
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		log.Printf("[turnstile] réponse siteverify illisible: %v (login laissé passer)", err)
		return true, "verify-bad-response"
	}
	if !tr.Success {
		// Token présent mais rejeté par Cloudflare (le plus souvent `timeout-or-duplicate`
		// : token périmé — page ouverte >5 min — ou double-submit). Ce n'est PAS un signal
		// de relais : un relais obtient un token VALIDE mais à hostname étranger, traité
		// plus bas. Bloquer ici (403) relockerait des utilisateurs légitimes sur un token
		// stale. On laisse passer (le rempart anti-relais reste le hostname + OAuth ;
		// le brute-force reste borné par le rate-limiter).
		log.Printf("[turnstile] token rejeté (%s) depuis %s — laissé passer (pas un relais)", strings.Join(tr.ErrorCodes, ","), remoteIP)
		return true, "failed-allowed"
	}
	host := strings.ToLower(strings.TrimSpace(tr.Hostname))
	for _, h := range turnstileAllowedHosts() {
		if host == h {
			return true, "ok"
		}
	}
	// success mais hostname inconnu = formulaire relayé depuis un autre domaine.
	// C'est LE seul cas qu'on bloque en dur : un token valide obtenu sur un domaine
	// étranger = relais (cas themyndgame). Impossible à forger pour notre sitekey.
	log.Printf("[turnstile] REFUS relais : token valide mais hostname=%q non autorisé (source %s)", host, remoteIP)
	return false, "foreign-hostname:" + host
}

// turnstileGuard : à appeler en tête de login/register. Écrit l'erreur et renvoie
// false si le challenge échoue. No-op si le verrou n'est pas configuré.
func turnstileGuard(w http.ResponseWriter, r *http.Request) bool {
	if !turnstileEnabled() {
		return true
	}
	// Exemption des appels de SERVICE de confiance (ex : le bot de vérif Discord `nextendo-verify`,
	// qui valide déjà SON PROPRE captcha Turnstile puis appelle /api/login pour vérifier les
	// identifiants). Ce n'est PAS un navigateur : lui imposer un token Turnstile le bloquerait
	// (« missing-token ») et casserait la vérif Discord pour tout le monde. Un service légitime
	// présente la clé de service partagée (même secret que /api/admin/*). Comparaison constante-
	// temps. Un relais externe (themyndgame) n'a PAS cette clé → il reste soumis à Turnstile.
	if key := adminServiceKey(); key != "" {
		if got := r.Header.Get("X-Admin-Key"); got != "" && subtle.ConstantTimeCompare([]byte(got), []byte(key)) == 1 {
			return true
		}
	}
	ok, reason := verifyTurnstile(r.Header.Get("Cf-Turnstile-Response"), clientIP(r))
	if !ok {
		log.Printf("[turnstile] blocage (%s) depuis %s", reason, clientIP(r))
		writeErr(w, http.StatusForbidden, "Échec de la vérification. Connecte-toi directement sur https://nextendo.network — un autre site ne peut pas te connecter à ton compte Nextendo.")
		return false
	}
	return true
}
