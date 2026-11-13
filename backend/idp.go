package main

import (
	"crypto/pbkdf2"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
)

// Built-in OpenID Connect provider ("Assafwah IdP").
//
// A real authorization-code + PKCE provider: discovery, JWKS, /authorize,
// /token, /userinfo. The hosted sign-in page is a route in the React app; it
// talks to /idp/api/* to verify the password, evaluate Conditional Access,
// run MFA (TOTP) and enrolment, then redirects back to the client with a code.
// Every attempt lands in the sign-in log that feeds identity threat detection.

type IdPUser struct {
	Username     string   `json:"username"`
	IdentityID   string   `json:"identityId,omitempty"`
	Name         string   `json:"name"`
	Email        string   `json:"email"`
	Groups       []string `json:"groups"`
	PasswordHash string   `json:"passwordHash"`
	TOTPSecret   string   `json:"totpSecret,omitempty"`
	MFAEnrolled  bool     `json:"mfaEnrolled"`
	MFAMethod    string   `json:"mfaMethod,omitempty"` // totp | (push, fido2 simulated in logs)
	Disabled     bool     `json:"disabled"`
	BreakGlass   bool     `json:"breakGlass,omitempty"`
	LastSignIn   string   `json:"lastSignIn,omitempty"`
}

// DemoPassword is printed on the hosted sign-in page. Every demo user shares it.
const DemoPassword = "test123"

func hashPassword(pw, salt string) string {
	k, _ := pbkdf2.Key(sha256.New, pw, []byte(salt), 120000, 32)
	return "pbkdf2-sha256$120000$" + salt + "$" + hex.EncodeToString(k)
}

func checkPassword(stored, pw string) bool {
	p := strings.Split(stored, "$")
	if len(p) != 4 {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(hashPassword(pw, p[2])), []byte(stored)) == 1
}

// demoSecret makes TOTP secrets deterministic so the in-app virtual
// authenticator works after a reset. Real deployments use newTOTPSecret().
func demoSecret(username string) string {
	sum := sha1.Sum([]byte("iam-projects-demo:" + username))
	return b32.EncodeToString(sum[:])
}

func (s *State) idpUser(username string) *IdPUser {
	for i := range s.IdPUsers {
		if strings.EqualFold(s.IdPUsers[i].Username, username) {
			return &s.IdPUsers[i]
		}
	}
	return nil
}

// ---------- locations used for simulated sign-in context ----------

type Location struct {
	Key         string  `json:"key"`
	City        string  `json:"city"`
	Country     string  `json:"country"`
	CountryName string  `json:"countryName"`
	IP          string  `json:"ip"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	Anonymizer  bool    `json:"anonymizer"`
}

// IPs are from the RFC 5737 documentation ranges, so no real address appears in the demo.
var Locations = []Location{
	{"nashville", "Nashville", "US", "United States", "198.51.100.18", 36.16, -86.78, false},
	{"clarksville", "Clarksville", "US", "United States", "198.51.100.201", 36.53, -87.36, false},
	{"chicago", "Chicago", "US", "United States", "198.51.100.40", 41.88, -87.63, false},
	{"london", "London", "GB", "United Kingdom", "203.0.113.142", 51.51, -0.13, false},
	{"amsterdam", "Amsterdam", "NL", "Netherlands", "203.0.113.12", 52.37, 4.90, false},
	{"lagos", "Lagos", "NG", "Nigeria", "192.0.2.77", 6.52, 3.38, false},
	{"frankfurt-tor", "Frankfurt (Tor exit)", "DE", "Germany", "192.0.2.47", 50.11, 8.68, true},
	{"moscow", "Moscow", "RU", "Russia", "192.0.2.9", 55.75, 37.62, false},
}

func locByKey(k string) Location {
	for _, l := range Locations {
		if l.Key == k {
			return l
		}
	}
	return Locations[0]
}

func locByIP(ip string) *Location {
	for i := range Locations {
		if Locations[i].IP == ip {
			return &Locations[i]
		}
	}
	return nil
}

// ---------- clients registered with the built-in IdP ----------

type oidcClient struct {
	ID, Name, Secret string
	RedirectPaths    []string // relative to the issuer's host
	RedirectURIs     []string // absolute
}

var idpClientSecret = func() string {
	if v := os.Getenv("IDP_CLIENT_SECRET"); v != "" {
		return v
	}
	return randToken(32)
}()

func idpClients() []oidcClient {
	return []oidcClient{{ID: "iam-projects", Name: "IAM Projects console", Secret: idpClientSecret, RedirectPaths: []string{"/auth/callback"}}}
}

func idpClient(id string) *oidcClient {
	for _, c := range idpClients() {
		if c.ID == id {
			return &c
		}
	}
	return nil
}

func (c *oidcClient) allowsRedirect(r *http.Request, uri string) bool {
	if slices.Contains(c.RedirectURIs, uri) {
		return true
	}
	u, err := url.Parse(uri)
	if err != nil {
		return false
	}
	return u.Host == r.Host && slices.Contains(c.RedirectPaths, u.Path)
}

// ---------- in-flight authorization transactions and codes ----------

type authTxn struct {
	ID, ClientID, RedirectURI, State, Nonce, Challenge, Scope, Issuer string
	Username                                                          string
	Ctx                                                               signInCtx
	PasswordOK, MFADone                                               bool
	Policies                                                          []string
	Expires                                                           time.Time
	PendingSecret                                                     string
}

type authCode struct {
	Code, ClientID, RedirectURI, Challenge, Nonce, Scope, Issuer, Username string
	AMR                                                                    []string
	AuthTime                                                               int64
	Expires                                                                time.Time
}

var idpMem = struct {
	sync.Mutex
	txns  map[string]*authTxn
	codes map[string]*authCode
}{txns: map[string]*authTxn{}, codes: map[string]*authCode{}}

var idpKey *signingKey

func issuerFor(r *http.Request) string {
	if v := os.Getenv("PUBLIC_URL"); v != "" {
		return strings.TrimRight(v, "/") + "/idp"
	}
	return baseURL(r) + "/idp"
}

func registerIdP(mux *http.ServeMux) {
	mux.HandleFunc("GET /idp/.well-known/openid-configuration", idpDiscovery)
	mux.HandleFunc("GET /idp/jwks", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"keys": []any{idpKey.jwk()}})
	})
	mux.HandleFunc("GET /idp/authorize", idpAuthorize)
	mux.HandleFunc("POST /idp/token", idpToken)
	mux.HandleFunc("GET /idp/userinfo", idpUserinfo)
	mux.HandleFunc("GET /idp/api/txn/{id}", idpTxnInfo)
	mux.HandleFunc("POST /idp/api/txn/{id}/password", idpPassword)
	mux.HandleFunc("POST /idp/api/txn/{id}/mfa", idpMFA)
	mux.HandleFunc("POST /idp/api/txn/{id}/enroll", idpEnroll)
	mux.HandleFunc("GET /api/idp/users", getIdPUsers)
	mux.HandleFunc("POST /api/idp/users/{username}/reset-mfa", postResetMFA)
	mux.HandleFunc("POST /api/idp/users/{username}/disable", postToggleUser(true))
	mux.HandleFunc("POST /api/idp/users/{username}/enable", postToggleUser(false))
}

func idpDiscovery(w http.ResponseWriter, r *http.Request) {
	iss := issuerFor(r)
	writeJSON(w, 200, map[string]any{
		"issuer": iss, "authorization_endpoint": iss + "/authorize", "token_endpoint": iss + "/token",
		"userinfo_endpoint": iss + "/userinfo", "jwks_uri": iss + "/jwks",
		"response_types_supported": []string{"code"}, "grant_types_supported": []string{"authorization_code"},
		"subject_types_supported": []string{"public"}, "id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email", "groups"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"code_challenge_methods_supported":      []string{"S256"},
		"claims_supported":                      []string{"sub", "name", "email", "preferred_username", "groups", "amr", "acr", "auth_time", "nonce"},
	})
}

// idpAuthorize validates the request and hands the browser to the hosted sign-in page.
func idpAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	c := idpClient(q.Get("client_id"))
	if c == nil {
		fail(w, 400, "unknown client_id")
		return
	}
	redirect := q.Get("redirect_uri")
	if !c.allowsRedirect(r, redirect) {
		fail(w, 400, "redirect_uri is not registered for this client")
		return
	}
	back := func(errCode, desc string) {
		u, _ := url.Parse(redirect)
		v := u.Query()
		v.Set("error", errCode)
		v.Set("error_description", desc)
		v.Set("state", q.Get("state"))
		u.RawQuery = v.Encode()
		http.Redirect(w, r, u.String(), http.StatusFound)
	}
	if q.Get("response_type") != "code" {
		back("unsupported_response_type", "only the authorization code flow is supported")
		return
	}
	if !slices.Contains(strings.Fields(q.Get("scope")), "openid") {
		back("invalid_scope", "scope must include openid")
		return
	}
	if q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
		back("invalid_request", "PKCE with S256 is required")
		return
	}
	t := &authTxn{ID: randToken(16), ClientID: c.ID, RedirectURI: redirect, State: q.Get("state"), Nonce: q.Get("nonce"),
		Challenge: q.Get("code_challenge"), Scope: q.Get("scope"), Issuer: issuerFor(r), Expires: nowT().Add(10 * time.Minute)}
	idpMem.Lock()
	for k, v := range idpMem.txns {
		if nowT().After(v.Expires) {
			delete(idpMem.txns, k)
		}
	}
	idpMem.txns[t.ID] = t
	idpMem.Unlock()
	http.Redirect(w, r, "/#signin?txn="+t.ID, http.StatusFound)
}

func getTxn(w http.ResponseWriter, r *http.Request) *authTxn {
	idpMem.Lock()
	defer idpMem.Unlock()
	t := idpMem.txns[r.PathValue("id")]
	if t == nil || nowT().After(t.Expires) {
		fail(w, 404, "sign-in session expired; start again from the application")
		return nil
	}
	return t
}

func idpTxnInfo(w http.ResponseWriter, r *http.Request) {
	t := getTxn(w, r)
	if t == nil {
		return
	}
	c := idpClient(t.ClientID)
	store.View(func(s *State) {
		users := []map[string]any{}
		for _, u := range s.IdPUsers {
			users = append(users, map[string]any{"username": u.Username, "name": u.Name, "groups": u.Groups, "mfaEnrolled": u.MFAEnrolled, "breakGlass": u.BreakGlass})
		}
		writeJSON(w, 200, map[string]any{"client": c.Name, "clientId": c.ID, "scope": t.Scope, "redirectUri": t.RedirectURI,
			"demoPassword": DemoPassword, "users": users, "locations": Locations})
	})
}

type pwIn struct {
	Username, Password, Location, Device, Client string
}

// idpPassword: first factor, lockout, then Conditional Access decides what happens next.
func idpPassword(w http.ResponseWriter, r *http.Request) {
	t := getTxn(w, r)
	if t == nil {
		return
	}
	var in pwIn
	if err := decode(r, &in); err != nil || strings.TrimSpace(in.Username) == "" {
		fail(w, 400, "username and password are required")
		return
	}
	loc := locByKey(in.Location)
	ctx := signInCtx{Username: strings.ToLower(strings.TrimSpace(in.Username)), App: t.ClientID, Location: loc,
		Device: orDefault(in.Device, "managed"), Client: orDefault(in.Client, "browser")}
	var resp map[string]any
	var code int
	_ = store.Update(func(s *State) error {
		u := s.idpUser(ctx.Username)
		if until := s.lockedUntil(ctx.Username); !until.IsZero() {
			s.recordSignIn(ctx, "locked", "Account locked after repeated failures (smart lockout)", "none", nil, "live")
			code, resp = 423, map[string]any{"error": "Account temporarily locked after too many failed attempts. Try again after " + until.Format("15:04 UTC") + "."}
			return nil
		}
		if u == nil || !checkPassword(u.PasswordHash, in.Password) {
			s.recordSignIn(ctx, "failure", "Invalid username or password", "none", nil, "live")
			code, resp = 401, map[string]any{"error": "Invalid username or password."}
			return nil
		}
		if u.Disabled {
			s.recordSignIn(ctx, "failure", "Account disabled", "none", nil, "live")
			code, resp = 403, map[string]any{"error": "This account is disabled."}
			return nil
		}
		ctx.Groups = u.Groups
		ctx.BreakGlass = u.BreakGlass
		ctx.Risk = s.signInRisk(ctx)
		ev := s.evaluateCA(ctx)
		t.Username, t.Ctx, t.PasswordOK, t.Policies = u.Username, ctx, true, ev.Applied
		switch {
		case ev.Decision == "block":
			s.recordSignIn(ctx, "blocked", "Blocked by Conditional Access: "+strings.Join(ev.BlockedBy, ", "), "none", ev.Applied, "live")
			code, resp = 403, map[string]any{"error": "Access blocked by Conditional Access.", "evaluation": ev}
		case ev.Decision == "mfa" && !u.MFAEnrolled:
			t.PendingSecret = newTOTPSecret()
			code, resp = 200, map[string]any{"next": "enroll", "evaluation": ev, "secret": t.PendingSecret,
				"otpauth": fmt.Sprintf("otpauth://totp/Assafwah%%20IdP:%s?secret=%s&issuer=Assafwah%%20IdP&algorithm=SHA1&digits=6&period=30", url.PathEscape(u.Username), t.PendingSecret)}
		case ev.Decision == "mfa":
			code, resp = 200, map[string]any{"next": "mfa", "evaluation": ev}
		default:
			s.recordSignIn(ctx, "success", "", "none", ev.Applied, "live")
			u.LastSignIn = now()
			code, resp = 200, map[string]any{"next": "done", "evaluation": ev, "redirect": issueCode(t, []string{"pwd"})}
		}
		return nil
	})
	writeJSON(w, code, resp)
}

func idpMFA(w http.ResponseWriter, r *http.Request) {
	t := getTxn(w, r)
	if t == nil {
		return
	}
	if !t.PasswordOK {
		fail(w, 400, "password step not completed")
		return
	}
	var in struct{ Code string }
	_ = decode(r, &in)
	var resp map[string]any
	code := 200
	_ = store.Update(func(s *State) error {
		u := s.idpUser(t.Username)
		if u == nil || !u.MFAEnrolled || !verifyTOTP(u.TOTPSecret, in.Code) {
			s.recordSignIn(t.Ctx, "mfa-denied", "Invalid or expired one-time code", "totp", t.Policies, "live")
			code, resp = 401, map[string]any{"error": "That code is not valid. Codes change every 30 seconds."}
			return nil
		}
		s.recordSignIn(t.Ctx, "success", "", "totp", t.Policies, "live")
		u.LastSignIn = now()
		resp = map[string]any{"next": "done", "redirect": issueCode(t, []string{"pwd", "otp", "mfa"})}
		return nil
	})
	writeJSON(w, code, resp)
}

// idpEnroll registers a TOTP authenticator during sign-in (MFA registration campaign).
func idpEnroll(w http.ResponseWriter, r *http.Request) {
	t := getTxn(w, r)
	if t == nil {
		return
	}
	var in struct{ Code string }
	_ = decode(r, &in)
	if !t.PasswordOK || t.PendingSecret == "" {
		fail(w, 400, "no enrolment in progress")
		return
	}
	if !verifyTOTP(t.PendingSecret, in.Code) {
		fail(w, 401, "That code doesn't match. Check the time on your phone and try the next code.")
		return
	}
	var redirect string
	_ = store.Update(func(s *State) error {
		u := s.idpUser(t.Username)
		u.TOTPSecret, u.MFAEnrolled, u.MFAMethod, u.LastSignIn = t.PendingSecret, true, "totp", now()
		s.audit(u.Username, "mfa.registered", u.Username, "Registered a TOTP authenticator app during sign-in")
		s.recordSignIn(t.Ctx, "success", "MFA registered", "totp", t.Policies, "live")
		redirect = issueCode(t, []string{"pwd", "otp", "mfa"})
		return nil
	})
	writeJSON(w, 200, map[string]any{"next": "done", "redirect": redirect})
}

func issueCode(t *authTxn, amr []string) string {
	c := &authCode{Code: randToken(24), ClientID: t.ClientID, RedirectURI: t.RedirectURI, Challenge: t.Challenge, Nonce: t.Nonce,
		Scope: t.Scope, Issuer: t.Issuer, Username: t.Username, AMR: amr, AuthTime: nowT().Unix(), Expires: nowT().Add(60 * time.Second)}
	idpMem.Lock()
	idpMem.codes[c.Code] = c
	delete(idpMem.txns, t.ID)
	idpMem.Unlock()
	u, _ := url.Parse(t.RedirectURI)
	v := u.Query()
	v.Set("code", c.Code)
	v.Set("state", t.State)
	u.RawQuery = v.Encode()
	return u.String()
}

// ---------- token endpoint ----------

type tokenSet struct {
	IDToken     string `json:"id_token"`
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
}

type oauthErr struct{ Code, Desc string }

func (e oauthErr) Error() string { return e.Code + ": " + e.Desc }

// exchangeCode is the token endpoint's logic, shared with the in-process relying party.
func exchangeCode(form url.Values, basicUser, basicPass string) (*tokenSet, error) {
	clientID, secret := basicUser, basicPass
	if clientID == "" {
		clientID, secret = form.Get("client_id"), form.Get("client_secret")
	}
	c := idpClient(clientID)
	if c == nil || subtle.ConstantTimeCompare([]byte(c.Secret), []byte(secret)) != 1 {
		return nil, oauthErr{"invalid_client", "client authentication failed"}
	}
	if form.Get("grant_type") != "authorization_code" {
		return nil, oauthErr{"unsupported_grant_type", "only authorization_code is supported"}
	}
	idpMem.Lock()
	ac := idpMem.codes[form.Get("code")]
	delete(idpMem.codes, form.Get("code")) // single use
	idpMem.Unlock()
	switch {
	case ac == nil || nowT().After(ac.Expires):
		return nil, oauthErr{"invalid_grant", "code is invalid, expired or already used"}
	case ac.ClientID != c.ID || ac.RedirectURI != form.Get("redirect_uri"):
		return nil, oauthErr{"invalid_grant", "code was issued to a different client or redirect_uri"}
	case pkceChallenge(form.Get("code_verifier")) != ac.Challenge:
		return nil, oauthErr{"invalid_grant", "PKCE verification failed"}
	}
	var u IdPUser
	store.View(func(s *State) {
		if p := s.idpUser(ac.Username); p != nil {
			u = *p
		}
	})
	iat := nowT().Unix()
	acr := "1"
	if slices.Contains(ac.AMR, "mfa") {
		acr = "2"
	}
	idt, err := idpKey.sign(map[string]any{
		"iss": ac.Issuer, "sub": u.Username, "aud": c.ID, "iat": iat, "exp": iat + 3600, "auth_time": ac.AuthTime,
		"nonce": ac.Nonce, "name": u.Name, "email": u.Email, "preferred_username": u.Username, "groups": u.Groups,
		"amr": ac.AMR, "acr": acr, "sid": randToken(8),
	})
	if err != nil {
		return nil, err
	}
	at, _ := idpKey.sign(map[string]any{
		"iss": ac.Issuer, "sub": u.Username, "aud": "iam-projects-api", "iat": iat, "exp": iat + 900, "scope": ac.Scope,
		"client_id": c.ID, "groups": u.Groups, "jti": randToken(12),
	})
	return &tokenSet{IDToken: idt, AccessToken: at, TokenType: "Bearer", ExpiresIn: 900, Scope: ac.Scope}, nil
}

func idpToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid_request"})
		return
	}
	user, pass, _ := r.BasicAuth()
	ts, err := exchangeCode(r.PostForm, user, pass)
	w.Header().Set("Cache-Control", "no-store")
	if err != nil {
		if oe, ok := err.(oauthErr); ok {
			code := 400
			if oe.Code == "invalid_client" {
				code = 401
			}
			writeJSON(w, code, map[string]string{"error": oe.Code, "error_description": oe.Desc})
			return
		}
		fail(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, ts)
}

func idpUserinfo(w http.ResponseWriter, r *http.Request) {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	claims, err := verifyJWT(tok, jwks{Keys: []struct{ Kty, Kid, N, E, Alg string }{jwkStruct(idpKey)}}, issuerFor(r), "iam-projects-api")
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		fail(w, 401, err.Error())
		return
	}
	store.View(func(s *State) {
		u := s.idpUser(fmt.Sprint(claims["sub"]))
		if u == nil {
			fail(w, 404, "user not found")
			return
		}
		writeJSON(w, 200, map[string]any{"sub": u.Username, "name": u.Name, "email": u.Email, "preferred_username": u.Username, "groups": u.Groups})
	})
}

func jwkStruct(k *signingKey) struct{ Kty, Kid, N, E, Alg string } {
	j := k.jwk()
	return struct{ Kty, Kid, N, E, Alg string }{"RSA", k.kid, j["n"].(string), j["e"].(string), "RS256"}
}

// ---------- directory admin ----------

func getIdPUsers(w http.ResponseWriter, r *http.Request) {
	store.View(func(s *State) {
		out := []map[string]any{}
		for _, u := range s.IdPUsers {
			row := map[string]any{"username": u.Username, "name": u.Name, "email": u.Email, "groups": u.Groups, "identityId": u.IdentityID,
				"mfaEnrolled": u.MFAEnrolled, "mfaMethod": u.MFAMethod, "disabled": u.Disabled, "breakGlass": u.BreakGlass, "lastSignIn": u.LastSignIn}
			// Demo only: secrets are exposed so the in-app virtual authenticator can show codes.
			if u.MFAEnrolled {
				row["demoTotpSecret"] = u.TOTPSecret
			}
			if l := s.lockedUntil(u.Username); !l.IsZero() {
				row["lockedUntil"] = fmtT(l)
			}
			out = append(out, row)
		}
		writeJSON(w, 200, map[string]any{"users": out, "demoPassword": DemoPassword})
	})
}

func postResetMFA(w http.ResponseWriter, r *http.Request) {
	err := store.Update(func(s *State) error {
		u := s.idpUser(r.PathValue("username"))
		if u == nil {
			return httpErr{404, "user not found"}
		}
		u.MFAEnrolled, u.TOTPSecret, u.MFAMethod = false, "", ""
		s.audit(actor(r), "mfa.reset", u.Username, "MFA methods cleared; user must re-register at next sign-in")
		return nil
	})
	if err != nil {
		respondErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]string{"status": "reset"})
}

func postToggleUser(disable bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := store.Update(func(s *State) error {
			u := s.idpUser(r.PathValue("username"))
			if u == nil {
				return httpErr{404, "user not found"}
			}
			u.Disabled = disable
			act := "idp.user.enabled"
			if disable {
				act = "idp.user.disabled"
				revokeSessions(u.Username)
			}
			s.audit(actor(r), act, u.Username, "Sign-in "+map[bool]string{true: "blocked", false: "allowed"}[disable])
			return nil
		})
		if err != nil {
			respondErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]bool{"disabled": disable})
	}
}

func orDefault(v, d string) string {
	if strings.TrimSpace(v) == "" {
		return d
	}
	return v
}
