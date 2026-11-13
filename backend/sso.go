package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// The console as an OpenID Connect relying party. It signs people in through
// either the built-in IdP or an external Keycloak realm (OIDC_ISSUER), using the
// authorization code flow with PKCE, state and nonce, then verifies the ID token
// signature against the provider's JWKS before creating a session. Signed-in
// users become the actor on every audit entry.

type session struct {
	SID      string   `json:"sid"`
	Username string   `json:"u"`
	Name     string   `json:"n"`
	Email    string   `json:"e"`
	Groups   []string `json:"g"`
	AMR      []string `json:"amr"`
	IdP      string   `json:"idp"`
	Iat      int64    `json:"iat"`
	Exp      int64    `json:"exp"`
}

type loginState struct {
	State, Nonce, Verifier, IdP, Redirect string
	Exp                                   int64
}

// revocations: sessions issued before this time for a user are rejected.
var revoked = struct {
	sync.Mutex
	before map[string]int64
}{before: map[string]int64{}}

func revokeSessions(username string) {
	revoked.Lock()
	revoked.before[strings.ToLower(username)] = nowT().Unix()
	revoked.Unlock()
}

// token sets kept in memory per session for the token inspector.
var tokenStore = struct {
	sync.Mutex
	m map[string]map[string]any
}{m: map[string]map[string]any{}}

func currentSession(r *http.Request) *session {
	c, err := r.Cookie("iam_session")
	if err != nil {
		return nil
	}
	var s session
	if !openCookie(c.Value, &s) || s.Exp < nowT().Unix() {
		return nil
	}
	revoked.Lock()
	b := revoked.before[strings.ToLower(s.Username)]
	revoked.Unlock()
	if b != 0 && s.Iat <= b {
		return nil
	}
	return &s
}

// ---------- providers ----------

type provider struct {
	ID, Name                  string
	Issuer, ClientID, Secret  string
	External                  bool
	authEndpoint, tokenEP     string
	jwksURI, userinfoEndpoint string
}

var kc = struct {
	sync.Mutex
	disc    *provider
	fetched time.Time
	keys    jwks
}{}

func keycloakConfigured() bool {
	return os.Getenv("OIDC_ISSUER") != "" && os.Getenv("OIDC_CLIENT_ID") != ""
}

func getJSON(u string, v any) error {
	c := http.Client{Timeout: 8 * time.Second}
	res, err := c.Get(u)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return fmt.Errorf("%s returned %d", u, res.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(v)
}

// keycloak returns the external provider, discovering endpoints and keys (cached 10 min).
func keycloak() (*provider, jwks, error) {
	kc.Lock()
	defer kc.Unlock()
	if kc.disc != nil && time.Since(kc.fetched) < 10*time.Minute {
		return kc.disc, kc.keys, nil
	}
	iss := strings.TrimRight(os.Getenv("OIDC_ISSUER"), "/")
	var d struct {
		Issuer, AuthorizationEndpoint, TokenEndpoint, JwksURI, UserinfoEndpoint string
	}
	var raw map[string]any
	if err := getJSON(iss+"/.well-known/openid-configuration", &raw); err != nil {
		return nil, jwks{}, err
	}
	d.Issuer, _ = raw["issuer"].(string)
	d.AuthorizationEndpoint, _ = raw["authorization_endpoint"].(string)
	d.TokenEndpoint, _ = raw["token_endpoint"].(string)
	d.JwksURI, _ = raw["jwks_uri"].(string)
	d.UserinfoEndpoint, _ = raw["userinfo_endpoint"].(string)
	var keys jwks
	if err := getJSON(d.JwksURI, &keys); err != nil {
		return nil, jwks{}, err
	}
	kc.disc = &provider{ID: "keycloak", Name: "Keycloak", Issuer: d.Issuer, ClientID: os.Getenv("OIDC_CLIENT_ID"), Secret: os.Getenv("OIDC_CLIENT_SECRET"),
		External: true, authEndpoint: d.AuthorizationEndpoint, tokenEP: d.TokenEndpoint, jwksURI: d.JwksURI, userinfoEndpoint: d.UserinfoEndpoint}
	kc.keys, kc.fetched = keys, time.Now()
	return kc.disc, keys, nil
}

func builtin(r *http.Request) *provider {
	iss := issuerFor(r)
	return &provider{ID: "builtin", Name: "Assafwah IdP (built-in)", Issuer: iss, ClientID: "iam-projects", Secret: idpClientSecret, authEndpoint: iss + "/authorize"}
}

func redirectURI(r *http.Request) string {
	if v := os.Getenv("PUBLIC_URL"); v != "" {
		return strings.TrimRight(v, "/") + "/auth/callback"
	}
	return baseURL(r) + "/auth/callback"
}

// ---------- handlers ----------

func registerSSO(mux *http.ServeMux) {
	mux.HandleFunc("GET /auth/login", ssoLogin)
	mux.HandleFunc("GET /auth/callback", ssoCallback)
	mux.HandleFunc("POST /auth/logout", ssoLogout)
	mux.HandleFunc("GET /api/me", getMe)
}

func secureCookie(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func ssoLogin(w http.ResponseWriter, r *http.Request) {
	var p *provider
	if r.URL.Query().Get("idp") == "keycloak" {
		if !keycloakConfigured() {
			fail(w, 400, "Keycloak is not configured on this deployment (set OIDC_ISSUER, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET)")
			return
		}
		kp, _, err := keycloak()
		if err != nil {
			fail(w, 502, "Keycloak discovery failed: "+err.Error())
			return
		}
		p = kp
	} else {
		p = builtin(r)
	}
	ls := loginState{State: randToken(16), Nonce: randToken(16), Verifier: randToken(32), IdP: p.ID, Redirect: "/#sso", Exp: nowT().Add(10 * time.Minute).Unix()}
	http.SetCookie(w, &http.Cookie{Name: "iam_login", Value: sealCookie(ls), Path: "/auth", HttpOnly: true, Secure: secureCookie(r), SameSite: http.SameSiteLaxMode, MaxAge: 600})
	q := url.Values{
		"response_type": {"code"}, "client_id": {p.ClientID}, "redirect_uri": {redirectURI(r)},
		"scope": {"openid profile email"}, "state": {ls.State}, "nonce": {ls.Nonce},
		"code_challenge": {pkceChallenge(ls.Verifier)}, "code_challenge_method": {"S256"},
	}
	if r.URL.Query().Get("prompt") != "" {
		q.Set("prompt", r.URL.Query().Get("prompt"))
	}
	http.Redirect(w, r, p.authEndpoint+"?"+q.Encode(), http.StatusFound)
}

func ssoCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	back := func(msg string) { http.Redirect(w, r, "/#login?error="+url.QueryEscape(msg), http.StatusFound) }
	if e := q.Get("error"); e != "" {
		back(e + ": " + q.Get("error_description"))
		return
	}
	c, err := r.Cookie("iam_login")
	var ls loginState
	if err != nil || !openCookie(c.Value, &ls) || ls.Exp < nowT().Unix() {
		back("login state missing or expired; start again")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "iam_login", Value: "", Path: "/auth", MaxAge: -1})
	if q.Get("state") != ls.State {
		back("state mismatch (possible CSRF); sign-in rejected")
		return
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {q.Get("code")}, "redirect_uri": {redirectURI(r)}, "code_verifier": {ls.Verifier}}

	var ts *tokenSet
	var claims map[string]any
	var p *provider
	if ls.IdP == "keycloak" {
		kp, keys, err := keycloak()
		if err != nil {
			back(err.Error())
			return
		}
		p = kp
		ts, err = oidcTokenRequest(kp, form)
		if err != nil {
			back(err.Error())
			return
		}
		claims, err = verifyJWT(ts.IDToken, keys, kp.Issuer, kp.ClientID)
		if err != nil {
			back("ID token rejected: " + err.Error())
			return
		}
	} else {
		p = builtin(r)
		ts, err = exchangeCode(form, p.ClientID, p.Secret)
		if err != nil {
			back(err.Error())
			return
		}
		claims, err = verifyJWT(ts.IDToken, jwks{Keys: []struct{ Kty, Kid, N, E, Alg string }{jwkStruct(idpKey)}}, p.Issuer, p.ClientID)
		if err != nil {
			back("ID token rejected: " + err.Error())
			return
		}
	}
	if claims["nonce"] != ls.Nonce {
		back("nonce mismatch (possible token replay); sign-in rejected")
		return
	}
	str := func(k string) string { v, _ := claims[k].(string); return v }
	list := func(v any) []string {
		out := []string{}
		if xs, ok := v.([]any); ok {
			for _, x := range xs {
				out = append(out, strings.TrimPrefix(fmt.Sprint(x), "/"))
			}
		}
		return out
	}
	groups := list(claims["groups"])
	if ra, ok := claims["realm_access"].(map[string]any); ok { // Keycloak realm roles
		groups = append(groups, list(ra["roles"])...)
	}
	amr := list(claims["amr"])
	if len(amr) == 0 && str("acr") != "" {
		amr = []string{"acr:" + str("acr")}
	}
	sess := session{SID: randToken(12), Username: firstNonEmpty(str("preferred_username"), str("sub")), Name: str("name"), Email: str("email"),
		Groups: groups, AMR: amr, IdP: p.ID, Iat: nowT().Unix(), Exp: nowT().Add(8 * time.Hour).Unix()}
	http.SetCookie(w, &http.Cookie{Name: "iam_session", Value: sealCookie(sess), Path: "/", HttpOnly: true, Secure: secureCookie(r), SameSite: http.SameSiteLaxMode, MaxAge: 8 * 3600})

	idH, idC, _ := decodeJWT(ts.IDToken)
	atH, atC, _ := decodeJWT(ts.AccessToken) // Keycloak access tokens are JWTs too; opaque tokens just won't decode
	tokenStore.Lock()
	tokenStore.m[sess.SID] = map[string]any{"provider": p.Name, "issuer": p.Issuer, "idToken": map[string]any{"raw": ts.IDToken, "header": idH, "claims": idC},
		"accessToken": map[string]any{"raw": ts.AccessToken, "header": atH, "claims": atC}, "scope": ts.Scope, "expiresIn": ts.ExpiresIn, "verified": true, "storedAt": nowT().Unix()}
	tokenStore.Unlock()
	_ = store.Update(func(s *State) error {
		s.audit(sess.Username, "sso.login", sess.Username, fmt.Sprintf("Signed in via %s (amr: %s)", p.Name, strings.Join(amr, ",")))
		return nil
	})
	http.Redirect(w, r, ls.Redirect, http.StatusFound)
}

func oidcTokenRequest(p *provider, form url.Values) (*tokenSet, error) {
	req, _ := http.NewRequest("POST", p.tokenEP, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(p.ClientID), url.QueryEscape(p.Secret))
	res, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	var ts tokenSet
	var e struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	b, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode != 200 {
		_ = json.Unmarshal(b, &e)
		return nil, errors.New("token endpoint: " + e.Error + " " + e.ErrorDescription)
	}
	if err := json.Unmarshal(b, &ts); err != nil {
		return nil, err
	}
	return &ts, nil
}

func ssoLogout(w http.ResponseWriter, r *http.Request) {
	if s := currentSession(r); s != nil {
		tokenStore.Lock()
		delete(tokenStore.m, s.SID)
		tokenStore.Unlock()
		_ = store.Update(func(st *State) error { st.audit(s.Username, "sso.logout", s.Username, "Signed out"); return nil })
	}
	http.SetCookie(w, &http.Cookie{Name: "iam_session", Value: "", Path: "/", MaxAge: -1})
	writeJSON(w, 200, map[string]string{"status": "signed out"})
}

func getMe(w http.ResponseWriter, r *http.Request) {
	providers := []map[string]any{
		{"id": "builtin", "name": "Assafwah IdP (built-in)", "configured": true, "issuer": issuerFor(r)},
		{"id": "keycloak", "name": "Keycloak", "configured": keycloakConfigured(), "issuer": os.Getenv("OIDC_ISSUER")},
	}
	s := currentSession(r)
	if s == nil {
		writeJSON(w, 200, map[string]any{"authenticated": false, "providers": providers})
		return
	}
	tokenStore.Lock()
	tk := tokenStore.m[s.SID]
	tokenStore.Unlock()
	var prof *Profile
	store.View(func(st *State) {
		if p := st.profile(s.Username); p != nil {
			c := *p
			prof = &c
		}
	})
	writeJSON(w, 200, map[string]any{"authenticated": true, "user": s, "tokens": tk, "providers": providers, "profile": prof})
}
