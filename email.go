// Nextendo Network — transactional e-mail (verification + password reset).
//
// Provider-agnostic: any SMTP relay works (Brevo, Gmail, Mailgun, SES, your own
// Postfix…) via env config. If SMTP is NOT configured, the action LINK is logged
// instead of sent (dev mode) so the whole flow works locally without credentials
// and the operator can copy the link out of the logs.
//
// Env:
//
//	NEXTENDO_SMTP_HOST   e.g. smtp-relay.brevo.com   (empty => dev/log mode)
//	NEXTENDO_SMTP_PORT   587 (STARTTLS, default) or 465 (implicit TLS)
//	NEXTENDO_SMTP_USER   SMTP login
//	NEXTENDO_SMTP_PASS   SMTP password / API key
//	NEXTENDO_SMTP_FROM   From header, e.g. "Nextendo Network <no-reply@nextendo.network>"
//	NEXTENDO_BASE_URL    public origin for links (default https://nextendo.network)
package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"os"
	"strconv"
	"strings"
	"time"
)

// errNoSMTP is returned by sendMail when no relay is configured (dev/log mode).
var errNoSMTP = errors.New("smtp not configured")

// baseURL is the public site origin used to build e-mailed links.
func baseURL() string {
	if v := strings.TrimRight(os.Getenv("NEXTENDO_BASE_URL"), "/"); v != "" {
		return v
	}
	return "https://nextendo.network"
}

type smtpConfig struct{ host, port, user, pass, from string }

func loadSMTP() (smtpConfig, bool) {
	c := smtpConfig{
		host: strings.TrimSpace(os.Getenv("NEXTENDO_SMTP_HOST")),
		port: strings.TrimSpace(os.Getenv("NEXTENDO_SMTP_PORT")),
		user: os.Getenv("NEXTENDO_SMTP_USER"),
		pass: os.Getenv("NEXTENDO_SMTP_PASS"),
		from: strings.TrimSpace(os.Getenv("NEXTENDO_SMTP_FROM")),
	}
	if c.port == "" {
		c.port = "587"
	}
	if c.from == "" {
		c.from = "Nextendo Network <no-reply@nextendo.network>"
	}
	// host suffices: a no-auth LOCAL relay (the host's Postfix, trusting the
	// container subnet via mynetworks) needs neither user nor pass.
	ok := c.host != ""
	return c, ok
}

// emailAddr extracts the bare address from a "Name <addr>" header value.
func emailAddr(from string) string {
	if i := strings.LastIndexByte(from, '<'); i >= 0 {
		if j := strings.IndexByte(from[i:], '>'); j >= 0 {
			return from[i+1 : i+j]
		}
	}
	return strings.TrimSpace(from)
}

// sendMail delivers an HTML e-mail. Returns errNoSMTP (so the caller can log the
// link) when no relay is configured, or a real error if a configured send fails.
func sendMail(to, subject, htmlBody string) error {
	c, ok := loadSMTP()
	if !ok {
		return errNoSMTP
	}
	msg := buildMIME(c.from, to, subject, htmlBody)
	// No-auth path = LOCAL relay (host Postfix on the trusted Docker network):
	// plaintext, no STARTTLS, no AUTH — OpenDKIM on the relay signs the message.
	if c.user == "" || c.pass == "" {
		return sendPlainRelay(c, to, msg)
	}
	// Authenticated relay (e.g. Brevo SMTP): implicit TLS on 465, else STARTTLS+AUTH.
	if c.port == "465" {
		return sendImplicitTLS(c, to, msg)
	}
	auth := smtp.PlainAuth("", c.user, c.pass, c.host)
	return smtp.SendMail(c.host+":"+c.port, auth, emailAddr(c.from), []string{to}, []byte(msg))
}

// sendPlainRelay hands the message to a no-auth SMTP relay — the VPS host's Postfix,
// reachable on the Docker bridge gateway (mynetworks trusts the container subnet).
// Plaintext, no STARTTLS, no AUTH; deliverability (DKIM signing, queuing, MX
// delivery) is Postfix + OpenDKIM's job.
func sendPlainRelay(c smtpConfig, to, msg string) error {
	cl, err := smtp.Dial(net.JoinHostPort(c.host, c.port))
	if err != nil {
		return err
	}
	defer cl.Close()
	if err := cl.Mail(emailAddr(c.from)); err != nil {
		return err
	}
	if err := cl.Rcpt(to); err != nil {
		return err
	}
	w, err := cl.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write([]byte(msg)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return cl.Quit()
}

// sendImplicitTLS handles port 465 (TLS from the first byte), which smtp.SendMail
// does not support (it expects plaintext-then-STARTTLS).
func sendImplicitTLS(c smtpConfig, to string, msg string) error {
	conn, err := tls.Dial("tcp", net.JoinHostPort(c.host, c.port), &tls.Config{ServerName: c.host})
	if err != nil {
		return err
	}
	cl, err := smtp.NewClient(conn, c.host)
	if err != nil {
		return err
	}
	defer cl.Close()
	if err := cl.Auth(smtp.PlainAuth("", c.user, c.pass, c.host)); err != nil {
		return err
	}
	if err := cl.Mail(emailAddr(c.from)); err != nil {
		return err
	}
	if err := cl.Rcpt(to); err != nil {
		return err
	}
	wc, err := cl.Data()
	if err != nil {
		return err
	}
	if _, err := wc.Write([]byte(msg)); err != nil {
		return err
	}
	if err := wc.Close(); err != nil {
		return err
	}
	return cl.Quit()
}

// fromDomain returns the domain of the From address (for Message-ID / Reply-To alignment).
func fromDomain(from string) string {
	a := emailAddr(from)
	if i := strings.LastIndexByte(a, '@'); i >= 0 {
		return a[i+1:]
	}
	return "nextendo.network"
}

// randToken returns n random bytes hex-encoded (Message-ID + tracking ids).
func randToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// buildMIME assembles the HTML e-mail with the deliverability headers that keep the
// self-hosted Postfix+OpenDKIM path out of spam: a domain-aligned Message-ID (so it
// matches the DKIM d=), an explicit Date, a real Reply-To, and List-Unsubscribe.
// encodeAddressHeader renders a From/To value with its display name RFC-2047-encoded when it
// contains non-ASCII, so the header stays pure ASCII (RFC 5322) — required for strict MTAs like
// Proton that don't offer SMTPUTF8.
func encodeAddressHeader(v string) string {
	if a, err := mail.ParseAddress(v); err == nil {
		return (&mail.Address{Name: a.Name, Address: a.Address}).String()
	}
	return v
}

func buildMIME(from, to, subject, htmlBody string) string {
	domain := fromDomain(from)
	replyTo := os.Getenv("NEXTENDO_SMTP_REPLYTO")
	if replyTo == "" {
		replyTo = "support@" + domain
	}
	var b strings.Builder
	b.WriteString("From: " + encodeAddressHeader(from) + "\r\n")
	b.WriteString("To: " + to + "\r\n")
	// Subject encodé en RFC 2047 (=?utf-8?…?=) : les accents ne restent PAS en UTF-8 brut dans
	// l'en-tête → Postfix n'exige plus SMTPUTF8, donc Proton & co (qui ne l'offrent pas) acceptent.
	b.WriteString("Subject: " + mime.QEncoding.Encode("utf-8", subject) + "\r\n")
	b.WriteString("Date: " + time.Now().UTC().Format(time.RFC1123Z) + "\r\n")
	b.WriteString("Message-ID: <" + randToken(16) + "@" + domain + ">\r\n")
	b.WriteString("Reply-To: " + replyTo + "\r\n")
	b.WriteString("List-Unsubscribe: <mailto:unsubscribe@" + domain + "?subject=unsubscribe>\r\n")
	b.WriteString("X-Entity-Ref-ID: " + randToken(12) + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
	b.WriteString("\r\n")
	b.WriteString(htmlBody)
	return b.String()
}

// mailTemplate wraps content in the branded Nextendo e-mail shell (dark, orange
// accent, one big CTA button). Inline styles only — e-mail clients ignore <style>.
func mailTemplate(heading, intro, ctaText, ctaURL, footnote string) string {
	return `<!DOCTYPE html><html><body style="margin:0;padding:0;background:#0b0d12;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#0b0d12;padding:32px 0;">
<tr><td align="center">
<table width="480" cellpadding="0" cellspacing="0" style="max-width:480px;width:100%;background:#12151d;border:1px solid #242a37;border-radius:16px;overflow:hidden;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;">
<tr><td style="padding:28px 32px 0;">
<span style="display:inline-block;font-weight:700;font-size:15px;color:#fff;letter-spacing:.2px;">
<span style="color:#ff6a3d;">◆</span> Nextendo <span style="color:#6b7488;font-weight:500;">// network</span></span>
</td></tr>
<tr><td style="padding:20px 32px 0;">
<h1 style="margin:0 0 10px;font-size:22px;line-height:1.25;color:#fff;font-weight:700;">` + heading + `</h1>
<p style="margin:0;font-size:15px;line-height:1.6;color:#aeb6c6;">` + intro + `</p>
</td></tr>
<tr><td style="padding:24px 32px 8px;">
<a href="` + ctaURL + `" style="display:inline-block;background:#ff6a3d;color:#1a0c06;text-decoration:none;font-weight:700;font-size:15px;padding:13px 26px;border-radius:10px;">` + ctaText + `</a>
</td></tr>
<tr><td style="padding:8px 32px 28px;">
<p style="margin:0 0 6px;font-size:12px;line-height:1.6;color:#6b7488;">Ou copie ce lien dans ton navigateur :</p>
<p style="margin:0;font-size:12px;line-height:1.5;word-break:break-all;"><a href="` + ctaURL + `" style="color:#ff8a63;">` + ctaURL + `</a></p>
</td></tr>
<tr><td style="padding:0 32px 28px;border-top:1px solid #242a37;">
<p style="margin:16px 0 0;font-size:12px;line-height:1.6;color:#6b7488;">` + footnote + `</p>
</td></tr>
</table>
</td></tr>
</table>
</body></html>`
}

// ---------------------------------------------------------------------------
// Stateless signed action tokens (no DB storage). Format: base64url(payload).sig
// payload = "purpose.accountID.expiryUnix". The HMAC also binds an `extra` string:
//   - reset  : the account's current password hash  => token dies once used (the
//              hash changes on reset, so a replayed reset link no longer verifies).
//   - verify : the account's e-mail => a link is invalidated if the e-mail changes.
// ---------------------------------------------------------------------------

func signActionToken(purpose string, accountID int64, extra string, ttl time.Duration) string {
	payload := fmt.Sprintf("%s.%d.%d", purpose, accountID, time.Now().Add(ttl).Unix())
	mac := hmac.New(sha256.New, sessionSecret)
	mac.Write([]byte(purpose + ":" + payload + ":" + extra))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + sig
}

// peekActionTokenID extracts the account id from a token WITHOUT verifying it, so
// the caller can load the account to obtain the `extra` binding (password hash /
// e-mail) needed to actually verify. Never trust the id until verifyActionToken.
func peekActionTokenID(purpose, tok string) (int64, bool) {
	parts := strings.SplitN(tok, ".", 2)
	if len(parts) != 2 {
		return 0, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return 0, false
	}
	fields := strings.SplitN(string(raw), ".", 3)
	if len(fields) != 3 || fields[0] != purpose {
		return 0, false
	}
	id, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return 0, false
	}
	return id, true
}

func verifyActionToken(purpose, tok, extra string) (int64, bool) {
	parts := strings.SplitN(tok, ".", 2)
	if len(parts) != 2 {
		return 0, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return 0, false
	}
	mac := hmac.New(sha256.New, sessionSecret)
	mac.Write([]byte(purpose + ":" + string(raw) + ":" + extra))
	want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(want), []byte(parts[1])) {
		return 0, false
	}
	fields := strings.SplitN(string(raw), ".", 3) // purpose.id.expiry
	if len(fields) != 3 || fields[0] != purpose {
		return 0, false
	}
	id, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return 0, false
	}
	exp, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return 0, false
	}
	return id, true
}

// sendVerificationEmail e-mails (or, in dev mode, logs) an address-verification link.
func sendVerificationEmail(acct *Account) {
	tok := signActionToken("verify", acct.ID, strings.ToLower(acct.Email), 7*24*time.Hour)
	link := baseURL() + "/verify?token=" + tok
	html := mailTemplate(
		"Confirme ton adresse e-mail",
		"Bienvenue sur Nextendo Network, "+htmlEscape(acct.Username)+" ! Confirme ton adresse pour sécuriser ton compte et pouvoir récupérer ton mot de passe si besoin.",
		"Vérifier mon e-mail", link,
		"Tu n'as pas créé de compte Nextendo ? Ignore cet e-mail.")
	if err := sendMail(acct.Email, "Confirme ton adresse e-mail — Nextendo Network", html); err != nil {
		if errors.Is(err, errNoSMTP) {
			log.Printf("[email:DEV] verify link for %s (%s): %s", acct.Username, acct.Email, link)
		} else {
			log.Printf("[email] verify send to %s FAILED: %v (link: %s)", acct.Email, err, link)
		}
	} else {
		log.Printf("[email] verify sent to %s", acct.Email)
	}
}

// sendResetEmail e-mails (or logs) a password-reset link (1h TTL, single-use).
func sendResetEmail(acct *Account) {
	tok := signActionToken("reset", acct.ID, acct.PasswordHash, time.Hour)
	link := baseURL() + "/reset?token=" + tok
	html := mailTemplate(
		"Réinitialise ton mot de passe",
		"Une réinitialisation du mot de passe a été demandée pour ton compte "+htmlEscape(acct.Username)+". Ce lien expire dans 1 heure.",
		"Choisir un nouveau mot de passe", link,
		"Tu n'es pas à l'origine de cette demande ? Ignore cet e-mail, ton mot de passe reste inchangé.")
	if err := sendMail(acct.Email, "Réinitialisation du mot de passe — Nextendo Network", html); err != nil {
		if errors.Is(err, errNoSMTP) {
			log.Printf("[email:DEV] reset link for %s (%s): %s", acct.Username, acct.Email, link)
		} else {
			log.Printf("[email] reset send to %s FAILED: %v (link: %s)", acct.Email, err, link)
		}
	} else {
		log.Printf("[email] reset sent to %s", acct.Email)
	}
}

// htmlEscape neutralises the few characters that matter inside our e-mail HTML text nodes.
func htmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")
	return r.Replace(s)
}
