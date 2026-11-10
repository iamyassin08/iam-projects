package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Tests drive the real router (routes) so auth, path patterns and JSON shapes
// are exercised exactly as a client or IdP would hit them.

type client struct {
	t   *testing.T
	mux *http.ServeMux
}

func newClient(t *testing.T) *client {
	t.Helper()
	clock = time.Now
	var err error
	store, err = OpenStore(filepath.Join(t.TempDir(), "iam.json"))
	if err != nil {
		t.Fatal(err)
	}
	return &client{t, routes(t.TempDir())}
}

func (c *client) do(method, path string, body any, hdr ...string) (int, map[string]any) {
	c.t.Helper()
	var rdr *bytes.Reader
	if s, ok := body.(string); ok {
		rdr = bytes.NewReader([]byte(s))
	} else {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rdr)
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	rec := httptest.NewRecorder()
	c.mux.ServeHTTP(rec, req)
	out := map[string]any{}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func checkMap() map[string]CheckResult {
	m := map[string]CheckResult{}
	store.View(func(s *State) {
		for _, c := range runChecks(s) {
			m[c.ID] = c
		}
	})
	return m
}

func TestSeedFindings(t *testing.T) {
	newClient(t)
	m := checkMap()
	if len(m) != 14 {
		t.Fatalf("expected 14 controls, got %d", len(m))
	}
	for _, id := range []string{"C6", "C7", "C9", "C10", "C11", "C12"} {
		if m[id].Pass {
			t.Errorf("%s should start as a seeded finding", id)
		}
	}
	for _, id := range []string{"C1", "C2", "C3", "C4", "C5", "C8", "C13", "C14"} {
		if !m[id].Pass {
			t.Errorf("%s should pass on seed: %v", id, m[id].Findings)
		}
	}
	for id, c := range m {
		if len(c.Frameworks) == 0 {
			t.Errorf("%s has no framework mapping", id)
		}
	}
}

func TestCertificationRevokeAndAutoRevoke(t *testing.T) {
	c := newClient(t)
	code, camp := c.do("POST", "/api/certifications", map[string]any{"name": "SOX ERP", "scope": "system", "systemId": "erp", "dueDays": 7, "autoRevoke": true})
	if code != 201 {
		t.Fatalf("launch: %d %v", code, camp)
	}
	cid := camp["id"].(string)
	var items []CertItem
	store.View(func(s *State) {
		for _, it := range s.CertItems {
			if it.CampaignID == cid {
				items = append(items, it)
			}
		}
	})
	if len(items) != 2 { // Priya erp-ap, Grace erp-approve
		t.Fatalf("expected 2 ERP items, got %d", len(items))
	}
	var priya, grace CertItem
	for _, it := range items {
		if it.IdentityID == "ID-3" {
			priya = it
		} else {
			grace = it
		}
	}
	if code, _ := c.do("POST", "/api/certifications/"+cid+"/items/"+priya.ID, map[string]string{"decision": "revoke"}); code != 400 {
		t.Fatalf("revoke without comment should be refused, got %d", code)
	}
	if code, out := c.do("POST", "/api/certifications/"+cid+"/items/"+priya.ID, map[string]string{"decision": "revoke", "comment": "Moved to AR"}); code != 200 {
		t.Fatalf("revoke: %d %v", code, out)
	}
	store.View(func(s *State) {
		if s.hasGrant("ID-3", "erp-ap") {
			t.Fatal("revoked birthright still granted")
		}
		if !s.excluded("ID-3", "erp-ap") {
			t.Fatal("revoked birthright should be excluded from role re-sync")
		}
	})
	if !checkMap()["C2"].Pass {
		t.Fatal("C2 should honour certification exclusions")
	}
	// Close: Grace's undecided item is revoked on non-response.
	if code, _ := c.do("POST", "/api/certifications/"+cid+"/close", nil); code != 200 {
		t.Fatal("close failed")
	}
	store.View(func(s *State) {
		if s.hasGrant(grace.IdentityID, grace.EntitlementID) {
			t.Fatal("auto-revoke on close did not remove the undecided grant")
		}
	})
	// Overdue detection
	clock = func() time.Time { return time.Now().AddDate(0, 0, 30) }
	defer func() { clock = time.Now }()
	if checkMap()["C13"].Pass {
		t.Fatal("the seeded Q4 campaign should be overdue 30 days from now")
	}
}

func TestJITElevationExpires(t *testing.T) {
	c := newClient(t)
	req := map[string]any{"identityId": "ID-7", "entitlementId": "sn-admin", "minutes": 30, "justification": "Patch MID server", "ticket": "chg0099123"}
	if code, out := c.do("POST", "/api/pam/elevate", map[string]any{"identityId": "ID-2", "entitlementId": "sn-admin", "minutes": 30, "justification": "x", "ticket": "CHG0001234"}); code != 403 {
		t.Fatalf("ineligible user should get 403, got %d %v", code, out)
	}
	if code, _ := c.do("POST", "/api/pam/elevate", map[string]any{"identityId": "ID-7", "entitlementId": "sn-admin", "minutes": 30, "justification": "x", "ticket": "none"}); code != 400 {
		t.Fatal("missing ticket should be refused")
	}
	if code, _ := c.do("POST", "/api/pam/elevate", map[string]any{"identityId": "ID-7", "entitlementId": "sn-admin", "minutes": 500, "justification": "x", "ticket": "CHG0001234"}); code != 400 {
		t.Fatal("duration above eligibility max should be refused")
	}
	code, ses := c.do("POST", "/api/pam/elevate", req)
	if code != 201 {
		t.Fatalf("elevate: %d %v", code, ses)
	}
	store.View(func(s *State) {
		g := s.findGrant("ID-7", "sn-admin")
		if g == nil || g.Source != "jit" || g.ExpiresAt == "" {
			t.Fatalf("expected a jit grant with expiry, got %+v", g)
		}
	})
	clock = func() time.Time { return time.Now().Add(31 * time.Minute) }
	defer func() { clock = time.Now }()
	if checkMap()["C8"].Pass {
		t.Fatal("C8 should fail while an expired grant is still present")
	}
	store.Update(func(s *State) error { s.sweepExpired(); return nil })
	store.View(func(s *State) {
		if s.hasGrant("ID-7", "sn-admin") {
			t.Fatal("sweeper did not remove expired grant")
		}
		if s.session(ses["id"].(string)).Status != "expired" {
			t.Fatal("session not marked expired")
		}
	})
	if !checkMap()["C8"].Pass {
		t.Fatal("C8 should pass after the sweep")
	}
}

func TestBreakGlassAndSoD(t *testing.T) {
	c := newClient(t)
	// Omar holds aws-dev (birthright); JIT aws-admin would break sod-3 even though he is eligible.
	if code, out := c.do("POST", "/api/pam/elevate", map[string]any{"identityId": "ID-1", "entitlementId": "aws-admin", "minutes": 30, "justification": "x", "ticket": "CHG0001234"}); code != 409 || !strings.Contains(out["error"].(string), "sod-3") {
		t.Fatalf("expected SoD refusal, got %d %v", code, out)
	}
	if code, _ := c.do("POST", "/api/pam/elevate", map[string]any{"identityId": "ID-5", "entitlementId": "sn-admin", "minutes": 90, "justification": "outage", "breakGlass": true}); code != 400 {
		t.Fatal("break-glass over 60 minutes should be refused")
	}
	code, ses := c.do("POST", "/api/pam/elevate", map[string]any{"identityId": "ID-5", "entitlementId": "sn-admin", "minutes": 15, "justification": "outage", "breakGlass": true})
	if code != 201 {
		t.Fatalf("break-glass: %d %v", code, ses)
	}
	c.do("POST", "/api/pam/sessions/"+ses["id"].(string)+"/revoke", nil)
	for _, p := range []string{"PIM-", ses["id"].(string)} {
		_ = p
	}
	// Review every outstanding break-glass session, then C9 passes.
	var ids []string
	store.View(func(s *State) {
		for _, p := range s.PAMSessions {
			if p.BreakGlass {
				ids = append(ids, p.ID)
			}
		}
	})
	for _, id := range ids {
		if code, out := c.do("POST", "/api/pam/sessions/"+id+"/review", map[string]string{"notes": "Verified against incident"}); code != 200 {
			t.Fatalf("review %s: %d %v", id, code, out)
		}
	}
	if !checkMap()["C9"].Pass {
		t.Fatal("C9 should pass after reviews")
	}
}

func TestSCIMProvisioning(t *testing.T) {
	c := newClient(t)
	if code, _ := c.do("GET", "/scim/v2/Users", nil); code != 401 {
		t.Fatalf("expected 401 without token, got %d", code)
	}
	code, tok := c.do("POST", "/api/scim/tokens", map[string]string{"name": "Okta test"})
	if code != 201 {
		t.Fatalf("token: %d", code)
	}
	auth := []string{"Authorization", "Bearer " + tok["token"].(string), "Content-Type", "application/scim+json"}
	store.View(func(s *State) {
		raw, _ := json.Marshal(s.SCIMTokens)
		if strings.Contains(string(raw), tok["token"].(string)) {
			t.Fatal("plaintext token must never be persisted")
		}
	})

	// Create (joiner) with a group → birthright access
	user := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"nadia.k@demo.local","externalId":"WD-777",
	  "name":{"givenName":"Nadia","familyName":"Karim"},"title":"AP Specialist","active":true,"groups":[{"value":"r-ap"}],
	  "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"department":"Finance","manager":{"displayName":"Grace Kim"}}}`
	code, u := c.do("POST", "/scim/v2/Users", user, auth...)
	if code != 201 {
		t.Fatalf("create: %d %v", code, u)
	}
	uid := u["id"].(string)
	if code, _ := c.do("POST", "/scim/v2/Users", user, auth...); code != 409 {
		t.Fatal("duplicate userName should be 409 uniqueness")
	}
	store.View(func(s *State) {
		if !s.hasGrant(uid, "erp-ap") {
			t.Fatal("SCIM joiner did not get birthright access")
		}
	})

	// Filter
	code, list := c.do("GET", `/scim/v2/Users?filter=userName%20eq%20%22nadia.k@demo.local%22`, nil, auth...)
	if code != 200 || list["totalResults"].(float64) != 1 {
		t.Fatalf("filter: %d %v", code, list)
	}
	if code, _ := c.do("GET", `/scim/v2/Users?filter=userName%20eq%20%22x%22%20or%20title%20pr`, nil, auth...); code != 400 {
		t.Fatal("unsupported filter should be invalidFilter 400")
	}

	// Group membership change = mover
	code, g := c.do("PATCH", "/scim/v2/Groups/r-sales", `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"add","path":"members","value":[{"value":"`+uid+`"}]}]}`, auth...)
	if code != 200 {
		t.Fatalf("group patch: %d %v", code, g)
	}
	store.View(func(s *State) {
		if s.hasGrant(uid, "erp-ap") || !s.hasGrant(uid, "sf-user") {
			t.Fatal("group add should behave like a mover")
		}
	})

	// Entra-style deactivate: capitalised op, string boolean → leaver
	code, _ = c.do("PATCH", "/scim/v2/Users/"+uid, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"Replace","path":"active","value":"False"}]}`, auth...)
	if code != 200 {
		t.Fatalf("deactivate: %d", code)
	}
	store.View(func(s *State) {
		if s.identity(uid).Status != "terminated" || len(s.grantsFor(uid)) != 0 {
			t.Fatal("SCIM deactivate should terminate and revoke all")
		}
	})
	if !checkMap()["C1"].Pass {
		t.Fatal("C1 must pass after a SCIM leaver")
	}
	// Reactivate = rehire
	c.do("PATCH", "/scim/v2/Users/"+uid, `{"Operations":[{"op":"replace","value":{"active":true}}]}`, auth...)
	store.View(func(s *State) {
		if s.identity(uid).Status != "active" || !s.hasGrant(uid, "sf-user") {
			t.Fatal("SCIM reactivate should rehire with birthright")
		}
	})
	// Revoked token stops working
	c.do("DELETE", "/api/scim/tokens/"+tok["id"].(string), nil)
	if code, _ := c.do("GET", "/scim/v2/Users", nil, auth...); code != 401 {
		t.Fatal("revoked token should be rejected")
	}
}

func TestReconciliationAndManualLeaver(t *testing.T) {
	c := newClient(t)
	code, rec := c.do("GET", "/api/reconciliation", nil)
	if code != 200 {
		t.Fatal(code)
	}
	counts := rec["counts"].(map[string]any)
	if counts["rogue"].(float64) != 2 || counts["orphan"].(float64) != 1 || counts["unowned-service"].(float64) != 1 {
		t.Fatalf("unexpected seed counts %v", counts)
	}
	var mlee, dbrooks, svc, ortega string
	store.View(func(s *State) {
		for _, a := range s.TargetAccounts {
			switch a.AccountName {
			case "mlee.clinical":
				mlee = a.ID
			case "dbrooks-sales":
				dbrooks = a.ID
			case "svc-legacy-deploy":
				svc = a.ID
			case "j.ortega":
				ortega = a.ID
			}
		}
	})
	if code, out := c.do("POST", "/api/reconciliation/accounts/"+mlee, map[string]string{"action": "adopt", "reason": "x"}); code != 409 {
		t.Fatalf("adopting an SoD-breaking rogue account must be refused, got %d %v", code, out)
	}
	c.do("POST", "/api/reconciliation/accounts/"+mlee, map[string]string{"action": "disable", "reason": "Breaks sod-4"})
	c.do("POST", "/api/reconciliation/accounts/"+dbrooks, map[string]string{"action": "disable", "reason": "Not approved"})
	c.do("POST", "/api/reconciliation/accounts/"+ortega, map[string]string{"action": "disable", "reason": "Not in HR"})
	if code, _ := c.do("POST", "/api/reconciliation/accounts/"+svc, map[string]string{"action": "assign-owner", "reason": "CI owner"}); code != 400 {
		t.Fatal("assign-owner without an owner should be refused")
	}
	c.do("POST", "/api/reconciliation/accounts/"+svc, map[string]string{"action": "assign-owner", "owner": "Omar Farouk", "reason": "Owns CI"})
	m := checkMap()
	if !m["C10"].Pass || !m["C11"].Pass {
		t.Fatalf("C10/C11 should pass after remediation: %v %v", m["C10"].Findings, m["C11"].Findings)
	}

	// Terminating someone with Epic (manual) access leaves an orphan behind.
	c.do("POST", "/api/jml/leaver", map[string]string{"identityId": "ID-5"})
	if checkMap()["C10"].Pass {
		t.Fatal("a leaver from a manual system should create an orphan account")
	}
}

func TestRiskScoring(t *testing.T) {
	c := newClient(t)
	_, out := c.do("GET", "/api/risk", nil)
	rows := out["identities"].([]any)
	top := rows[0].(map[string]any)
	if top["score"].(float64) < 50 {
		t.Fatalf("expected a high-risk identity at the top, got %v", top)
	}
	byName := map[string]float64{}
	for _, r := range rows {
		m := r.(map[string]any)
		byName[m["name"].(string)] = m["score"].(float64)
	}
	if byName["Priya Raman"] >= byName["Sofia Alvarez"] {
		t.Fatal("dormant standing Domain Admin should score above a plain AP clerk")
	}
	// Dormant revoke drops the score.
	before := byName["Sofia Alvarez"]
	c.do("POST", "/api/grants/revoke", map[string]string{"identityId": "ID-6", "entitlementId": "ad-admins", "reason": "Unused 210 days; use JIT"})
	_, out = c.do("GET", "/api/risk", nil)
	for _, r := range out["identities"].([]any) {
		m := r.(map[string]any)
		if m["name"] == "Sofia Alvarez" && m["score"].(float64) >= before {
			t.Fatal("revoking dormant admin should lower risk")
		}
	}
	if !checkMap()["C12"].Pass {
		t.Fatal("C12 should pass once the dormant admin grant is removed")
	}
}
