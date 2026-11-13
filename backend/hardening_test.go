package main

import (
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"
)

func TestSecurityHeadersAndRateLimit(t *testing.T) {
	c := newClient(t)
	h := secure(rateLimit(c.mux))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/health", nil))
	for _, k := range []string{"Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy"} {
		if rec.Header().Get(k) == "" {
			t.Errorf("missing %s", k)
		}
	}
	authLimit = newLimiter(30, 3)
	codes := []int{}
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "/auth/login", nil)
		req.Header.Set("CF-Connecting-IP", "198.51.100.9")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		codes = append(codes, rec.Code)
	}
	if codes[0] != http.StatusFound || codes[4] != http.StatusTooManyRequests {
		t.Fatalf("expected redirects then 429, got %v", codes)
	}
	// another address is unaffected
	req := httptest.NewRequest("GET", "/auth/login", nil)
	req.Header.Set("CF-Connecting-IP", "198.51.100.10")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("other IP should pass, got %d", rec.Code)
	}
}

func TestTenantCapacity(t *testing.T) {
	newClient(t)
	_ = store.Update(func(s *State) error {
		for len(s.Identities) < maxIdentities {
			s.Identities = append(s.Identities, Identity{ID: s.nextID("ID"), Status: "active"})
		}
		return nil
	})
	c := &client{t, routes(t.TempDir())}
	if code, _ := c.do("POST", "/api/jml/joiner", map[string]string{"name": "X", "roleId": "r-eng"}); code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 when tenant is full, got %d", code)
	}
}

func TestEmbeddedSignInStart(t *testing.T) {
	srv := httptest.NewServer(newClient(t).mux)
	defer srv.Close()
	jar, _ := cookiejar.New(nil)
	req, _ := http.NewRequest("GET", srv.URL+"/auth/login?login_hint=yusuf.ali&return=login", nil)
	req.Header.Set("Accept", "application/json")
	res, err := (&http.Client{Jar: jar}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var out struct{ Txn, LoginHint string }
	json.NewDecoder(res.Body).Decode(&out)
	res.Body.Close()
	if res.StatusCode != 200 || out.Txn == "" || out.LoginHint != "yusuf.ali" {
		t.Fatalf("want txn JSON, got %d %+v", res.StatusCode, out)
	}
}
