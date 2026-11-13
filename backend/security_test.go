package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// raw performs a request and returns the recorder, so tests can follow redirects and cookies.
func (c *client) raw(method, target, body string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for _, ck := range cookies {
		req.AddCookie(ck)
	}
	rec := httptest.NewRecorder()
	c.mux.ServeHTTP(rec, req)
	return rec
}

func cookie(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == name {
			return ck
		}
	}
	return nil
}

// signIn runs the full authorization-code + PKCE flow through the real router.
func signIn(t *testing.T, c *client, username, location string) (*http.Cookie, map[string]any) {
	t.Helper()
	login := c.raw("GET", "/auth/login", "")
	if login.Code != 302 {
		t.Fatalf("login: %d", login.Code)
	}
	lc := cookie(login, "iam_login")
	authz := c.raw("GET", login.Header().Get("Location"), "")
	loc := authz.Header().Get("Location")
	if authz.Code != 302 || !strings.HasPrefix(loc, "/#signin?txn=") {
		t.Fatalf("authorize: %d %s %s", authz.Code, loc, authz.Body.String())
	}
	txn := strings.TrimPrefix(loc, "/#signin?txn=")
	code, out := c.do("POST", "/idp/api/txn/"+txn+"/password", map[string]string{"username": username, "password": DemoPassword, "location": location})
	if code != 200 {
		return nil, out
	}
	if out["next"] == "mfa" {
		var u IdPUser
		store.View(func(s *State) { u = *s.idpUser(username) })
		code, out = c.do("POST", "/idp/api/txn/"+txn+"/mfa", map[string]string{"code": totpAt(u.TOTPSecret, time.Now())})
		if code != 200 {
			t.Fatalf("mfa: %d %v", code, out)
		}
	}
	if out["next"] != "done" {
		t.Fatalf("expected done, got %v", out)
	}
	cb, _ := url.Parse(out["redirect"].(string))
	rec := c.raw("GET", cb.RequestURI(), "", lc)
	if rec.Code != 302 || rec.Header().Get("Location") != "/#sso" {
		t.Fatalf("callback: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	return cookie(rec, "iam_session"), out
}

func TestOIDCFlowWithMFAAndActor(t *testing.T) {
	c := newClient(t)
	sc, _ := signIn(t, c, "yusuf.ali", "nashville")
	if sc == nil {
		t.Fatal("no session cookie")
	}
	rec := c.raw("GET", "/api/me", "", sc)
	if !strings.Contains(rec.Body.String(), `"authenticated":true`) || !strings.Contains(rec.Body.String(), `"otp"`) {
		t.Fatalf("me: %s", rec.Body.String())
	}
	// audit actor comes from the session, not X-Actor
	c.raw("POST", "/api/requests", `{"identityId":"ID-1","entitlementId":"sf-user","justification":"test"}`, sc)
	store.View(func(s *State) {
		if s.Audit[0].Actor != "yusuf.ali" {
			t.Errorf("actor = %s", s.Audit[0].Actor)
		}
	})
	// revoked sessions stop working
	revokeSessions("yusuf.ali")
	time.Sleep(1100 * time.Millisecond)
	if rec := c.raw("GET", "/api/me", "", sc); !strings.Contains(rec.Body.String(), `"authenticated":false`) {
		t.Error("session should be revoked")
	}
}

func TestTokenEndpointRejectsBadPKCEAndReuse(t *testing.T) {
	newClient(t)
	verifier := randToken(32)
	ac := &authCode{Code: "c1", ClientID: "iam-projects", RedirectURI: "http://x/auth/callback", Challenge: pkceChallenge(verifier), Issuer: "http://x/idp", Username: "omar.farouk", Expires: time.Now().Add(time.Minute)}
	idpMem.codes["c1"] = ac
	form := url.Values{"grant_type": {"authorization_code"}, "code": {"c1"}, "redirect_uri": {"http://x/auth/callback"}, "code_verifier": {"wrong"}}
	if _, err := exchangeCode(form, "iam-projects", idpClientSecret); err == nil || !strings.Contains(err.Error(), "PKCE") {
		t.Fatalf("expected PKCE failure, got %v", err)
	}
	idpMem.codes["c1"] = ac
	form.Set("code_verifier", verifier)
	ts, err := exchangeCode(form, "iam-projects", idpClientSecret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyJWT(ts.IDToken, jwks{Keys: []struct{ Kty, Kid, N, E, Alg string }{jwkStruct(idpKey)}}, "http://x/idp", "iam-projects"); err != nil {
		t.Fatalf("id token should verify: %v", err)
	}
	if _, err := exchangeCode(form, "iam-projects", idpClientSecret); err == nil {
		t.Fatal("code must be single use")
	}
	if _, err := exchangeCode(form, "iam-projects", "bad-secret"); err == nil {
		t.Fatal("bad client secret must fail")
	}
}

func TestLockoutAndConditionalAccess(t *testing.T) {
	c := newClient(t)
	start := func() string {
		authz := c.raw("GET", "/idp/authorize?client_id=iam-projects&redirect_uri=http://example.com/auth/callback&response_type=code&scope=openid&code_challenge=abc&code_challenge_method=S256&state=s", "")
		return strings.TrimPrefix(authz.Header().Get("Location"), "/#signin?txn=")
	}
	for i := 0; i < 5; i++ {
		c.do("POST", "/idp/api/txn/"+start()+"/password", map[string]string{"username": "omar.farouk", "password": "nope"})
	}
	if code, _ := c.do("POST", "/idp/api/txn/"+start()+"/password", map[string]string{"username": "omar.farouk", "password": DemoPassword}); code != 423 {
		t.Fatalf("expected lockout 423, got %d", code)
	}
	// sanctioned country is blocked by CA004
	code, out := c.do("POST", "/idp/api/txn/"+start()+"/password", map[string]string{"username": "priya.raman", "password": DemoPassword, "location": "moscow"})
	if code != 403 || !strings.Contains(toJSON(out), "CA004") {
		t.Fatalf("expected CA004 block, got %d %v", code, out)
	}
	// legacy auth: allowed until CA003 is turned on
	_, ev := c.do("POST", "/api/ca/whatif", map[string]string{"username": "priya.raman", "client": "legacy-imap"})
	if ev["decision"] == "block" {
		t.Fatal("CA003 is off on seed")
	}
	c.do("PUT", "/api/ca/policies/CA003", map[string]string{"state": "on"})
	_, ev = c.do("POST", "/api/ca/whatif", map[string]string{"username": "priya.raman", "client": "legacy-imap"})
	if ev["decision"] != "block" {
		t.Fatalf("legacy should now be blocked: %v", ev)
	}
	if !checkMap()["C16"].Pass {
		t.Error("C16 should pass once legacy auth is blocked")
	}
	// unenrolled user must register MFA when MFA is required
	code, out = c.do("POST", "/idp/api/txn/"+start()+"/password", map[string]string{"username": "sofia.alvarez", "password": DemoPassword, "device": "unmanaged"})
	if code != 200 || out["next"] != "enroll" {
		t.Fatalf("expected enrolment, got %d %v", code, out)
	}
}

func TestDetectionsAndTriage(t *testing.T) {
	newClient(t)
	var alerts []Alert
	store.View(func(s *State) { alerts = s.detect() })
	rules := map[string]Alert{}
	for _, a := range alerts {
		rules[a.Rule] = a
	}
	for _, r := range []string{"D1", "D2", "D3", "D4", "D5", "D6"} {
		if _, ok := rules[r]; !ok {
			t.Errorf("seeded attack %s not detected", r)
		}
	}
	if rules["D4"].Severity != "critical" {
		t.Errorf("MFA fatigue followed by approval should be critical, got %s", rules["D4"].Severity)
	}
	c := &client{t, routes(t.TempDir())}
	code, _ := c.do("POST", "/api/monitoring/alerts/"+url.PathEscape(rules["D1"].ID), map[string]any{"status": "closed-true-positive", "notes": "Tor spray, no successes", "actions": []string{"block-ip"}})
	if code != 200 {
		t.Fatalf("triage: %d", code)
	}
	_, ev := c.do("POST", "/api/ca/whatif", map[string]string{"username": "omar.farouk", "location": "frankfurt-tor"})
	if ev["decision"] != "block" {
		t.Fatalf("blocked IP should be denied by CA006: %v", ev)
	}
}

func TestVaultCheckoutRequiresAccessAndMFA(t *testing.T) {
	c := newClient(t)
	var vid, secret string
	store.View(func(s *State) { vid, secret = s.Vault[1].ID, s.idpUser("yusuf.ali").TOTPSecret })
	code, _ := c.do("POST", "/api/vault/"+vid+"/checkout", map[string]string{"identityId": "ID-7", "reason": "fix catalog", "code": totpAt(secret, time.Now())})
	if code != 403 {
		t.Fatalf("checkout without active access should be 403, got %d", code)
	}
	c.do("POST", "/api/pam/elevate", map[string]any{"identityId": "ID-7", "entitlementId": "sn-admin", "justification": "fix", "ticket": "CHG0012345", "minutes": 30})
	if code, _ := c.do("POST", "/api/vault/"+vid+"/checkout", map[string]string{"identityId": "ID-7", "reason": "fix", "code": "000000"}); code != 401 {
		t.Fatalf("bad MFA should be 401, got %d", code)
	}
	code, out := c.do("POST", "/api/vault/"+vid+"/checkout", map[string]string{"identityId": "ID-7", "reason": "fix", "code": totpAt(secret, time.Now())})
	if code != 200 || len(out["password"].(string)) != 24 {
		t.Fatalf("checkout: %d %v", code, out)
	}
	var v0 int
	store.View(func(s *State) { v0 = s.Vault[1].Version })
	c.do("POST", "/api/vault/"+vid+"/checkin", nil)
	store.View(func(s *State) {
		if s.Vault[1].Version != v0+1 || s.Vault[1].CheckedOutBy != "" {
			t.Error("check-in must rotate the password")
		}
		if pw, _ := unseal(s.Vault[1].Ciphertext); pw == out["password"] {
			t.Error("password should change after check-in")
		}
	})
}

func TestCloudPolicySimulator(t *testing.T) {
	c := newClient(t)
	sim := func(p, a, r string, ctx map[string]any) string {
		_, out := c.do("POST", "/api/cloud/simulate", map[string]any{"principal": p, "action": a, "resource": r, "context": ctx})
		return out["decision"].(string)
	}
	us := map[string]any{"region": "us-east-1", "mfa": true, "sourceIp": "198.51.100.18"}
	cases := []struct{ p, a, r, want string }{
		{"user/omar.farouk", "lambda:UpdateFunctionCode", "arn:aws:lambda:us-east-1:111122223333:function:dev-api", "allowed"},
		{"user/omar.farouk", "lambda:UpdateFunctionCode", "arn:aws:lambda:us-east-1:111122223333:function:prod-api", "implicit-deny"},
		{"user/omar.farouk", "s3:GetObject", "arn:aws:s3:::acme-prod-claims/2026/x.csv", "explicit-deny"},
		{"role/DataAnalyst", "s3:GetObject", "arn:aws:s3:::acme-rcm-extracts/claims/q3.csv", "allowed"},
		{"user/svc-legacy-deploy", "iam:CreateUser", "*", "allowed"},
	}
	for _, k := range cases {
		if got := sim(k.p, k.a, k.r, us); got != k.want {
			t.Errorf("%s %s %s = %s, want %s", k.p, k.a, k.r, got, k.want)
		}
	}
	if got := sim("role/DataAnalyst", "s3:GetObject", "arn:aws:s3:::acme-rcm-extracts/claims/q3.csv", map[string]any{"sourceIp": "8.8.8.8"}); got != "implicit-deny" {
		t.Errorf("off-network read should be denied, got %s", got)
	}
	if got := sim("user/omar.farouk", "lambda:UpdateFunctionCode", "arn:aws:lambda:us-east-1:111122223333:function:dev-api", map[string]any{"region": "eu-west-1"}); got != "implicit-deny" {
		t.Errorf("wrong region should be denied, got %s", got)
	}
	// boundary: attach a broad EC2 policy to omar; boundary must still stop it
	store.Update(func(s *State) error {
		s.CloudPolicies = append(s.CloudPolicies, CloudPolicy{ID: "pol-ec2", Name: "EC2Full", Document: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:*","Resource":"*"}]}`, AttachedTo: []string{"user/omar.farouk"}})
		return nil
	})
	if got := sim("user/omar.farouk", "ec2:TerminateInstances", "*", us); got != "boundary-deny" {
		t.Errorf("boundary should cap EC2, got %s", got)
	}
	if checkMap()["C18"].Pass {
		t.Fatal("C18 fails on seed")
	}
	c.do("PUT", "/api/cloud/policies/pol-legacy", map[string]string{"document": `{"Version":"2012-10-17","Statement":[{"Sid":"Deploy","Effect":"Allow","Action":["s3:PutObject"],"Resource":"arn:aws:s3:::acme-deploy/*"}]}`})
	if !checkMap()["C18"].Pass {
		t.Error("C18 should pass after scoping the legacy policy")
	}
}

func TestHRFeedPlanAndApply(t *testing.T) {
	c := newClient(t)
	rec := c.raw("GET", "/api/automation/hr-feed/sample", "")
	feed := rec.Body.String()
	_, out := c.do("POST", "/api/automation/hr-feed", map[string]any{"csv": feed})
	got := map[string]int{}
	for _, a := range out["plan"].([]any) {
		got[a.(map[string]any)["action"].(string)]++
	}
	if got["joiner"] != 1 || got["mover"] != 1 || got["leaver"] != 1 || got["update"] != 1 || got["skip"] != 1 {
		t.Fatalf("unexpected plan: %v", got)
	}
	c.do("POST", "/api/automation/hr-feed", map[string]any{"csv": feed, "apply": true})
	store.View(func(s *State) {
		if s.identity("ID-5").Status != "terminated" || s.identity("ID-2").RoleID != "r-eng" {
			t.Error("leaver / mover not applied")
		}
	})
	if m := checkMap(); !m["C1"].Pass || !m["C2"].Pass {
		t.Errorf("lifecycle controls should still pass: %v %v", m["C1"].Findings, m["C2"].Findings)
	}
}

func toJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestAccessCheck(t *testing.T) {
	c := newClient(t)
	_, out := c.do("GET", "/api/access-check?identityId=ID-3&entitlementId=erp-ap", nil)
	if out["allowed"] != true || out["via"] != "role" {
		t.Fatalf("Priya should hold AP via role: %v", out)
	}
	_, out = c.do("GET", "/api/access-check?identityId=ID-3&entitlementId=erp-approve", nil)
	if out["allowed"] != false || !strings.Contains(toJSON(out), "sod-2") {
		t.Fatalf("Priya approving payments should be denied and flag sod-2: %v", out)
	}
	_, out = c.do("GET", "/api/access-check?identityId=ID-7&entitlementId=sn-admin", nil)
	if out["allowed"] != false || !strings.Contains(toJSON(out), "eligible") {
		t.Fatalf("Yusuf should be JIT-eligible, not standing: %v", out)
	}
}

func TestDemoPasswordSync(t *testing.T) {
	newClient(t)
	_ = store.Update(func(s *State) error {
		s.IdPUsers[0].PasswordHash = hashPassword("old-password", "salt-x")
		if !syncDemoPasswords(s) || !checkPassword(s.IdPUsers[0].PasswordHash, DemoPassword) {
			t.Fatal("demo password should be re-synced")
		}
		if syncDemoPasswords(s) {
			t.Fatal("second sync should be a no-op")
		}
		return nil
	})
}

func TestProfileSelfService(t *testing.T) {
	c := newClient(t)
	if rec := c.raw("GET", "/api/profile", ""); rec.Code != 401 {
		t.Fatalf("profile needs a session, got %d", rec.Code)
	}
	sc, _ := signIn(t, c, "yusuf.ali", "nashville")
	rec := c.raw("PUT", "/api/profile", `{"displayName":"Yusuf A.","title":"IAM Engineer","bio":"hi","website":"https://example.com","prefs":{"landing":"lab","reduceMotion":true}}`, sc)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"landing":"lab"`) {
		t.Fatalf("update: %d %s", rec.Code, rec.Body.String())
	}
	if rec := c.raw("PUT", "/api/profile", `{"avatar":"data:text/html;base64,PHNjcmlwdD4="}`, sc); rec.Code != 400 {
		t.Fatalf("non-image avatar must be rejected, got %d", rec.Code)
	}
	if rec := c.raw("PUT", "/api/profile", `{"website":"javascript:alert(1)"}`, sc); rec.Code != 400 {
		t.Fatalf("non-https website must be rejected, got %d", rec.Code)
	}
	rec = c.raw("GET", "/api/profile", "", sc)
	if !strings.Contains(rec.Body.String(), `"access"`) || !strings.Contains(rec.Body.String(), "ServiceNow") {
		t.Fatalf("profile should list the user's access: %s", rec.Body.String()[:200])
	}
	if !strings.Contains(c.raw("GET", "/api/me", "", sc).Body.String(), "Yusuf A.") {
		t.Fatal("/api/me should carry the profile")
	}
	c.raw("POST", "/api/profile/signout-everywhere", "", sc)
	time.Sleep(1100 * time.Millisecond)
	if rec := c.raw("GET", "/api/profile", "", sc); rec.Code != 401 {
		t.Fatalf("sign out everywhere should kill the session, got %d", rec.Code)
	}
}
