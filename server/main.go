package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

var store *Store

func main() {
	dbPath := env("DATA_PATH", "./data/iam.json")
	staticDir := env("STATIC_DIR", "../web/dist")
	port := env("PORT", "8080")

	var err error
	loadVaultKey(dbPath)
	if idpKey, err = loadOrCreateKey(filepath.Join(filepath.Dir(dbPath), "idp-signing.pem")); err != nil {
		log.Fatalf("idp key: %v", err)
	}
	store, err = OpenStore(dbPath)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}

	mux := routes(staticDir)
	go expirySweeper(15 * time.Second)
	go housekeeping()

	log.Printf("IAM Projects listening on :%s (data=%s)", port, dbPath)
	log.Fatal(newServer(port, secure(rateLimit(logReq(mux)))).ListenAndServe())
}

// routes wires every endpoint; tests use it to drive the real router.
func routes(staticDir string) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]string{"status": "ok"}) })
	mux.HandleFunc("GET /api/summary", getSummary)
	mux.HandleFunc("GET /api/catalog", getCatalog)
	mux.HandleFunc("GET /api/identities", getIdentities)
	mux.HandleFunc("GET /api/identities/{id}/access", getIdentityAccess)
	mux.HandleFunc("GET /api/access-check", getAccessCheck)
	mux.HandleFunc("GET /api/jml/events", getJMLEvents)
	mux.HandleFunc("POST /api/jml/joiner", postJoiner)
	mux.HandleFunc("POST /api/jml/mover", postMover)
	mux.HandleFunc("POST /api/jml/leaver", postLeaver)
	mux.HandleFunc("GET /api/requests", getRequests)
	mux.HandleFunc("POST /api/requests", postRequest)
	mux.HandleFunc("POST /api/requests/{id}/approve", decideRequest("approved"))
	mux.HandleFunc("POST /api/requests/{id}/deny", decideRequest("denied"))
	mux.HandleFunc("PUT /api/roles/{id}/entitlements", putRoleEntitlement)
	mux.HandleFunc("GET /api/systems", getSystems)
	mux.HandleFunc("GET /api/audit", getAudit)
	mux.HandleFunc("POST /api/reset", postReset)
	mux.HandleFunc("GET /api/lab/checks", getChecks)
	mux.HandleFunc("POST /api/grants/revoke", postRevokeGrant)

	// Access certifications (user access reviews)
	mux.HandleFunc("GET /api/certifications", getCampaigns)
	mux.HandleFunc("POST /api/certifications", postCampaign)
	mux.HandleFunc("GET /api/certifications/{id}", getCampaign)
	mux.HandleFunc("POST /api/certifications/{id}/items/{itemId}", postCertDecision)
	mux.HandleFunc("POST /api/certifications/{id}/close", postCloseCampaign)

	// Just-in-time privileged access
	mux.HandleFunc("GET /api/pam", getPAM)
	mux.HandleFunc("POST /api/pam/elevate", postElevate)
	mux.HandleFunc("POST /api/pam/sessions/{id}/revoke", postEndSession)
	mux.HandleFunc("POST /api/pam/sessions/{id}/review", postReviewSession)
	mux.HandleFunc("POST /api/pam/eligibility", postEligibility)
	mux.HandleFunc("DELETE /api/pam/eligibility", deleteEligibility)

	// Risk & reconciliation
	mux.HandleFunc("GET /api/risk", getRisk)
	mux.HandleFunc("GET /api/reconciliation", getReconciliation)
	mux.HandleFunc("POST /api/reconciliation/accounts/{id}", postAccountAction)

	// SCIM 2.0 (RFC 7643 / 7644) for inbound provisioning from an IdP
	mux.HandleFunc("GET /api/scim/tokens", getTokens)
	mux.HandleFunc("POST /api/scim/tokens", postToken)
	mux.HandleFunc("DELETE /api/scim/tokens/{id}", deleteToken)
	registerSCIM(mux)

	// Identity security: OIDC provider + relying party, MFA, Conditional Access,
	// sign-in monitoring, credential vault, cloud IAM, HR-feed automation
	registerIdP(mux)
	registerSSO(mux)
	registerCA(mux)
	registerMonitoring(mux)
	registerVault(mux)
	registerCloud(mux)
	registerFeed(mux)

	mux.Handle("/", spa(staticDir))
	return mux
}

// ---------- plumbing ----------

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func decode(r *http.Request, v any) error {
	return json.NewDecoder(http.MaxBytesReader(nil, r.Body, 64<<10)).Decode(v)
}

func actor(r *http.Request) string {
	if s := currentSession(r); s != nil {
		return s.Username
	}
	if a := strings.TrimSpace(r.Header.Get("X-Actor")); a != "" {
		return a
	}
	return "iam.admin"
}

type httpErr struct {
	code int
	msg  string
}

func (e httpErr) Error() string { return e.msg }

func respondErr(w http.ResponseWriter, err error) {
	var he httpErr
	if errors.As(err, &he) {
		fail(w, he.code, he.msg)
		return
	}
	fail(w, 500, err.Error())
}

func logReq(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			log.Printf("%s %s", r.Method, r.URL.Path)
		}
		h.ServeHTTP(w, r)
	})
}

// spa serves the built React app and falls back to index.html.
func spa(dir string) http.Handler {
	fs := http.FileServer(http.Dir(dir))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := filepath.Join(dir, filepath.Clean(r.URL.Path))
		if st, err := os.Stat(p); err != nil || st.IsDir() {
			http.ServeFile(w, r, filepath.Join(dir, "index.html"))
			return
		}
		fs.ServeHTTP(w, r)
	})
}

// ---------- read endpoints ----------

func getSummary(w http.ResponseWriter, r *http.Request) {
	store.View(func(s *State) {
		active, pending, privileged, jit, reviews := 0, 0, 0, 0, 0
		for _, i := range s.Identities {
			if i.Status == "active" {
				active++
			}
		}
		for _, q := range s.Requests {
			if q.Status == "pending" {
				pending++
			}
		}
		for _, g := range s.Grants {
			if e := s.entitlement(g.EntitlementID); e != nil && e.Privileged {
				privileged++
			}
		}
		for _, p := range s.PAMSessions {
			if p.Status == "active" {
				jit++
			}
		}
		for _, c := range s.CertItems {
			if c.Decision == "pending" {
				if camp := s.campaign(c.CampaignID); camp != nil && camp.Status == "active" {
					reviews++
				}
			}
		}
		failing := 0
		for _, c := range runChecks(s) {
			if !c.Pass {
				failing++
			}
		}
		high := 0
		for _, rk := range riskScores(s) {
			if rk.Score >= 50 {
				high++
			}
		}
		writeJSON(w, 200, map[string]int{
			"activeIdentities": active, "pendingRequests": pending, "roles": len(s.Roles),
			"systems": len(s.Systems), "grants": len(s.Grants), "privilegedGrants": privileged,
			"activeJIT": jit, "pendingReviews": reviews, "failingControls": failing, "highRisk": high,
		})
	})
}

func getCatalog(w http.ResponseWriter, r *http.Request) {
	store.View(func(s *State) {
		writeJSON(w, 200, map[string]any{
			"roles": s.Roles, "systems": s.Systems, "entitlements": s.Entitlements, "sodRules": s.SoDRules,
		})
	})
}

func getIdentities(w http.ResponseWriter, r *http.Request) {
	store.View(func(s *State) {
		type row struct {
			Identity
			GrantCount int `json:"grantCount"`
		}
		out := []row{}
		for _, i := range s.Identities {
			out = append(out, row{i, len(s.grantsFor(i.ID))})
		}
		writeJSON(w, 200, out)
	})
}

func getIdentityAccess(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	store.View(func(s *State) {
		if s.identity(id) == nil {
			fail(w, 404, "identity not found")
			return
		}
		writeJSON(w, 200, s.grantsFor(id))
	})
}

func getJMLEvents(w http.ResponseWriter, r *http.Request) {
	store.View(func(s *State) {
		ev := append([]JMLEvent{}, s.JMLEvents...)
		sort.SliceStable(ev, func(a, b int) bool { return ev[a].At > ev[b].At })
		writeJSON(w, 200, ev)
	})
}

func getRequests(w http.ResponseWriter, r *http.Request) {
	store.View(func(s *State) {
		rq := append([]AccessRequest{}, s.Requests...)
		sort.SliceStable(rq, func(a, b int) bool { return rq[a].RequestedAt > rq[b].RequestedAt })
		writeJSON(w, 200, rq)
	})
}

func getSystems(w http.ResponseWriter, r *http.Request) {
	store.View(func(s *State) {
		type row struct {
			System
			Users        int `json:"users"`
			Entitlements int `json:"entitlements"`
			Privileged   int `json:"privilegedGrants"`
		}
		out := []row{}
		for _, sys := range s.Systems {
			users := map[string]bool{}
			ents, priv := 0, 0
			for _, e := range s.Entitlements {
				if e.SystemID != sys.ID {
					continue
				}
				ents++
				for _, g := range s.Grants {
					if g.EntitlementID == e.ID {
						users[g.IdentityID] = true
						if e.Privileged {
							priv++
						}
					}
				}
			}
			if sys.ID == "workday" || sys.ID == "entra" { // every active identity is sourced / federated
				for _, i := range s.Identities {
					if i.Status == "active" {
						users[i.ID] = true
					}
				}
			}
			out = append(out, row{sys, len(users), ents, priv})
		}
		writeJSON(w, 200, out)
	})
}

func getAudit(w http.ResponseWriter, r *http.Request) {
	store.View(func(s *State) {
		n := len(s.Audit)
		if n > 200 {
			n = 200
		}
		writeJSON(w, 200, s.Audit[:n])
	})
}

func postReset(w http.ResponseWriter, r *http.Request) {
	if err := store.Reset(); err != nil {
		respondErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]string{"status": "reset"})
}

// ---------- JML ----------

type joinerReq struct {
	Name, Email, Department, Title, Manager, RoleID, StartDate string
}

func postJoiner(w http.ResponseWriter, r *http.Request) {
	var in joinerReq
	if err := decode(r, &in); err != nil {
		fail(w, 400, "invalid JSON")
		return
	}
	if strings.TrimSpace(in.Name) == "" || in.RoleID == "" {
		fail(w, 400, "name and roleId are required")
		return
	}
	var out Identity
	err := store.Update(func(s *State) error {
		id, err := s.createIdentity(actor(r), newIdentity{in.Name, in.Email, in.Department, in.Title, in.Manager, in.RoleID, in.StartDate, ""})
		if err != nil {
			return err
		}
		out = *id
		return nil
	})
	if err != nil {
		respondErr(w, err)
		return
	}
	writeJSON(w, 201, out)
}

type moverReq struct {
	IdentityID, NewRoleID, NewDepartment, NewTitle string
}

func postMover(w http.ResponseWriter, r *http.Request) {
	var in moverReq
	if err := decode(r, &in); err != nil {
		fail(w, 400, "invalid JSON")
		return
	}
	if in.NewRoleID == "" {
		fail(w, 400, "newRoleId is required")
		return
	}
	var ev JMLEvent
	err := store.Update(func(s *State) (err error) {
		ev, err = s.moveIdentity(actor(r), in.IdentityID, in.NewRoleID, in.NewTitle, in.NewDepartment)
		return err
	})
	if err != nil {
		respondErr(w, err)
		return
	}
	writeJSON(w, 200, ev)
}

type leaverReq struct {
	IdentityID, EndDate string
}

func postLeaver(w http.ResponseWriter, r *http.Request) {
	var in leaverReq
	if err := decode(r, &in); err != nil {
		fail(w, 400, "invalid JSON")
		return
	}
	var ev JMLEvent
	err := store.Update(func(s *State) (err error) {
		ev, err = s.terminateIdentity(actor(r), in.IdentityID, in.EndDate)
		return err
	})
	if err != nil {
		respondErr(w, err)
		return
	}
	writeJSON(w, 200, ev)
}

// postRevokeGrant removes one grant outright (remediation of dormant or excess access).
func postRevokeGrant(w http.ResponseWriter, r *http.Request) {
	var in struct{ IdentityID, EntitlementID, Reason string }
	if err := decode(r, &in); err != nil || strings.TrimSpace(in.Reason) == "" {
		fail(w, 400, "identityId, entitlementId and a reason are required")
		return
	}
	err := store.Update(func(s *State) error {
		g := s.findGrant(in.IdentityID, in.EntitlementID)
		if g == nil {
			return httpErr{404, "grant not found"}
		}
		src := g.Source
		s.revoke(in.IdentityID, in.EntitlementID, "")
		if src == "role" {
			s.Exclusions = append(s.Exclusions, Exclusion{in.IdentityID, in.EntitlementID, "", in.Reason, now()})
		}
		s.audit(actor(r), "grant.revoked", in.IdentityID, fmt.Sprintf("%s revoked (%s): %s", in.EntitlementID, src, in.Reason))
		return nil
	})
	if err != nil {
		respondErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]string{"status": "revoked"})
}

// ---------- Access requests ----------

type newRequest struct {
	IdentityID, EntitlementID, Justification string
}

func postRequest(w http.ResponseWriter, r *http.Request) {
	var in newRequest
	if err := decode(r, &in); err != nil {
		fail(w, 400, "invalid JSON")
		return
	}
	if strings.TrimSpace(in.Justification) == "" {
		fail(w, 400, "a business justification is required")
		return
	}
	var out AccessRequest
	err := store.Update(func(s *State) error {
		id := s.identity(in.IdentityID)
		if id == nil || id.Status != "active" {
			return httpErr{404, "active identity not found"}
		}
		ent := s.entitlement(in.EntitlementID)
		if ent == nil {
			return httpErr{400, "unknown entitlement"}
		}
		if s.hasGrant(id.ID, ent.ID) {
			return httpErr{409, id.Name + " already has " + ent.Name}
		}
		for _, q := range s.Requests {
			if q.IdentityID == id.ID && q.EntitlementID == ent.ID && q.Status == "pending" {
				return httpErr{409, "a pending request already exists"}
			}
		}
		conflict := ""
		if rule := s.sodConflict(id.ID, ent.ID); rule != nil {
			conflict = rule.ID + ": " + rule.Description
		}
		if err := s.atCapacity("request"); err != nil {
			return err
		}
		out = AccessRequest{s.nextID("REQ"), id.ID, ent.ID, in.Justification, "pending", conflict, now(), "", "", ""}
		s.Requests = append(s.Requests, out)
		detail := fmt.Sprintf("%s requested %s", id.Name, ent.Name)
		if conflict != "" {
			detail += " (SoD conflict flagged)"
		}
		s.audit(actor(r), "request.created", out.ID, detail)
		return nil
	})
	if err != nil {
		respondErr(w, err)
		return
	}
	writeJSON(w, 201, out)
}

func decideRequest(decision string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in struct{ Reason string }
		_ = decode(r, &in)
		reqID := r.PathValue("id")
		var out AccessRequest
		err := store.Update(func(s *State) error {
			var q *AccessRequest
			for i := range s.Requests {
				if s.Requests[i].ID == reqID {
					q = &s.Requests[i]
				}
			}
			if q == nil {
				return httpErr{404, "request not found"}
			}
			if q.Status != "pending" {
				return httpErr{409, "request already " + q.Status}
			}
			if decision == "approved" && q.SoDConflict != "" && strings.TrimSpace(in.Reason) == "" {
				return httpErr{400, "SoD conflict: approving requires a documented risk-acceptance reason"}
			}
			q.Status, q.DecidedBy, q.DecidedAt, q.Reason = decision, actor(r), now(), in.Reason
			if decision == "approved" {
				s.grant(q.IdentityID, q.EntitlementID, "request")
			}
			s.audit(actor(r), "request."+decision, q.ID, fmt.Sprintf("%s for %s %s", q.EntitlementID, q.IdentityID, in.Reason))
			out = *q
			return nil
		})
		if err != nil {
			respondErr(w, err)
			return
		}
		writeJSON(w, 200, out)
	}
}

// ---------- Role matrix ----------

func putRoleEntitlement(w http.ResponseWriter, r *http.Request) {
	var in struct {
		EntitlementID string `json:"entitlementId"`
		Granted       bool   `json:"granted"`
	}
	if err := decode(r, &in); err != nil {
		fail(w, 400, "invalid JSON")
		return
	}
	roleID := r.PathValue("id")
	var role Role
	affected := 0
	err := store.Update(func(s *State) error {
		ro := s.role(roleID)
		if ro == nil {
			return httpErr{404, "role not found"}
		}
		ent := s.entitlement(in.EntitlementID)
		if ent == nil {
			return httpErr{400, "unknown entitlement"}
		}
		has := false
		for i, e := range ro.Entitlements {
			if e == ent.ID {
				has = true
				if !in.Granted {
					ro.Entitlements = append(ro.Entitlements[:i], ro.Entitlements[i+1:]...)
				}
				break
			}
		}
		if in.Granted && !has {
			// Block role designs that would bake an SoD conflict into the role itself.
			for _, rule := range s.SoDRules {
				for _, e := range ro.Entitlements {
					if (rule.A == ent.ID && rule.B == e) || (rule.B == ent.ID && rule.A == e) {
						return httpErr{409, "blocked by " + rule.ID + ": " + rule.Description}
					}
				}
			}
			ro.Entitlements = append(ro.Entitlements, ent.ID)
		}
		// Re-sync everyone in the role (role-based grants only).
		for _, id := range s.Identities {
			if id.RoleID != ro.ID || id.Status != "active" {
				continue
			}
			if in.Granted && s.grant(id.ID, ent.ID, "role") {
				affected++
			}
			if !in.Granted && s.revoke(id.ID, ent.ID, "role") {
				affected++
			}
		}
		verb := "removed from"
		if in.Granted {
			verb = "added to"
		}
		s.audit(actor(r), "role.updated", ro.ID, fmt.Sprintf("%s %s %s; %d identities re-synced", ent.Name, verb, ro.Name, affected))
		role = *ro
		return nil
	})
	if err != nil {
		respondErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"role": role, "affected": affected})
}
