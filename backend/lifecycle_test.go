package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

// End-to-end lab: hire → request with SoD conflict → move → terminate,
// asserting the controls after each step. Run with: go test ./...

func call(t *testing.T, h http.HandlerFunc, method, path string, body any, pattern string) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(method, path, bytes.NewReader(b))
	mux := http.NewServeMux()
	mux.HandleFunc(pattern, h)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func checksPass(t *testing.T, ids ...string) {
	t.Helper()
	store.View(func(s *State) {
		res := map[string]CheckResult{}
		for _, c := range runChecks(s) {
			res[c.ID] = c
		}
		for _, id := range ids {
			if !res[id].Pass {
				t.Fatalf("control %s failed: %v", id, res[id].Findings)
			}
		}
	})
}

func TestLifecycle(t *testing.T) {
	var err error
	store, err = OpenStore(filepath.Join(t.TempDir(), "iam.json"))
	if err != nil {
		t.Fatal(err)
	}

	// Joiner
	rec := call(t, postJoiner, "POST", "/api/jml/joiner", map[string]string{"name": "Lab User", "roleId": "r-ap"}, "POST /api/jml/joiner")
	if rec.Code != 201 {
		t.Fatalf("joiner: %d %s", rec.Code, rec.Body)
	}
	var id Identity
	json.Unmarshal(rec.Body.Bytes(), &id)
	checksPass(t, "C1", "C2", "C3", "C4")

	// Request that conflicts with AP Clerk (sod-1)
	rec = call(t, postRequest, "POST", "/api/requests", map[string]string{"identityId": id.ID, "entitlementId": "erp-vendor", "justification": "lab"}, "POST /api/requests")
	var q AccessRequest
	json.Unmarshal(rec.Body.Bytes(), &q)
	if q.SoDConflict == "" {
		t.Fatal("expected SoD conflict to be flagged")
	}
	if rec = call(t, decideRequest("approved"), "POST", "/api/requests/"+q.ID+"/approve", map[string]string{}, "POST /api/requests/{id}/approve"); rec.Code != 400 {
		t.Fatalf("approval without reason should be refused, got %d", rec.Code)
	}
	call(t, decideRequest("approved"), "POST", "/api/requests/"+q.ID+"/approve", map[string]string{"reason": "CFO accepted for 30 days"}, "POST /api/requests/{id}/approve")
	checksPass(t, "C3", "C4")

	// Mover: request-based access outside the new role must go
	call(t, postMover, "POST", "/api/jml/mover", map[string]string{"identityId": id.ID, "newRoleId": "r-eng"}, "POST /api/jml/mover")
	store.View(func(s *State) {
		if s.hasGrant(id.ID, "erp-vendor") || s.hasGrant(id.ID, "erp-ap") {
			t.Fatal("mover kept finance access")
		}
	})
	checksPass(t, "C2", "C4")

	// Leaver
	call(t, postLeaver, "POST", "/api/jml/leaver", map[string]string{"identityId": id.ID}, "POST /api/jml/leaver")
	checksPass(t, "C1")
}
