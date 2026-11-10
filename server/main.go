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
)

var store *Store

func main() {
	dbPath := env("DATA_PATH", "./data/iam.json")
	staticDir := env("STATIC_DIR", "../web/dist")
	port := env("PORT", "8080")

	var err error
	store, err = OpenStore(dbPath)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]string{"status": "ok"}) })
	mux.HandleFunc("GET /api/summary", getSummary)
	mux.HandleFunc("GET /api/catalog", getCatalog)
	mux.HandleFunc("GET /api/identities", getIdentities)
	mux.HandleFunc("GET /api/identities/{id}/access", getIdentityAccess)
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
	mux.Handle("/", spa(staticDir))

	log.Printf("IAM Projects listening on :%s (data=%s)", port, dbPath)
	log.Fatal(http.ListenAndServe(":"+port, logReq(mux)))
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
	return json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20)).Decode(v)
}

func actor(r *http.Request) string {
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
		active, pending, privileged := 0, 0, 0
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
		writeJSON(w, 200, map[string]int{
			"activeIdentities": active, "pendingRequests": pending, "roles": len(s.Roles),
			"systems": len(s.Systems), "grants": len(s.Grants), "privilegedGrants": privileged,
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
		role := s.role(in.RoleID)
		if role == nil {
			return httpErr{400, "unknown role"}
		}
		email := in.Email
		if email == "" {
			email = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(in.Name), " ", ".")) + "@demo.local"
		}
		for _, i := range s.Identities {
			if strings.EqualFold(i.Email, email) && i.Status == "active" {
				return httpErr{409, "an active identity already uses " + email}
			}
		}
		dept := in.Department
		if dept == "" {
			dept = role.Department
		}
		start := in.StartDate
		if start == "" {
			start = now()[:10]
		}
		out = Identity{s.nextID("ID"), in.Name, email, dept, in.Title, in.Manager, role.ID, "active", start, ""}
		s.Identities = append(s.Identities, out)
		granted := []string{}
		for _, e := range role.Entitlements {
			if s.grant(out.ID, e, "role") {
				granted = append(granted, e)
			}
		}
		s.JMLEvents = append(s.JMLEvents, JMLEvent{s.nextID("JML"), "joiner", out.ID,
			fmt.Sprintf("%s joined %s as %s", out.Name, dept, role.Name), granted, []string{}, now()})
		s.audit(actor(r), "jml.joiner", out.ID, fmt.Sprintf("Created %s, role %s, granted %d birthright entitlements", out.Name, role.Name, len(granted)))
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
	var ev JMLEvent
	err := store.Update(func(s *State) error {
		id := s.identity(in.IdentityID)
		if id == nil || id.Status != "active" {
			return httpErr{404, "active identity not found"}
		}
		newRole := s.role(in.NewRoleID)
		if newRole == nil {
			return httpErr{400, "unknown role"}
		}
		if newRole.ID == id.RoleID {
			return httpErr{400, "identity already has that role"}
		}
		oldRole := s.role(id.RoleID)
		keep := map[string]bool{}
		for _, e := range newRole.Entitlements {
			keep[e] = true
		}
		revoked, granted := []string{}, []string{}
		if oldRole != nil {
			for _, e := range oldRole.Entitlements {
				if !keep[e] && s.revoke(id.ID, e, "role") {
					revoked = append(revoked, e)
				}
			}
		}
		// Request-based access is also re-certified on a move: anything outside the new role is removed.
		for _, g := range s.grantsFor(id.ID) {
			if g.Source == "request" && !keep[g.EntitlementID] && s.revoke(id.ID, g.EntitlementID, "request") {
				revoked = append(revoked, g.EntitlementID)
			}
		}
		for _, e := range newRole.Entitlements {
			if s.grant(id.ID, e, "role") {
				granted = append(granted, e)
			}
		}
		oldName := "none"
		if oldRole != nil {
			oldName = oldRole.Name
		}
		id.RoleID = newRole.ID
		if in.NewDepartment != "" {
			id.Department = in.NewDepartment
		} else {
			id.Department = newRole.Department
		}
		if in.NewTitle != "" {
			id.Title = in.NewTitle
		}
		ev = JMLEvent{s.nextID("JML"), "mover", id.ID, fmt.Sprintf("%s moved from %s to %s", id.Name, oldName, newRole.Name), granted, revoked, now()}
		s.JMLEvents = append(s.JMLEvents, ev)
		s.audit(actor(r), "jml.mover", id.ID, fmt.Sprintf("%s → %s: +%d / -%d entitlements", oldName, newRole.Name, len(granted), len(revoked)))
		return nil
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
	err := store.Update(func(s *State) error {
		id := s.identity(in.IdentityID)
		if id == nil || id.Status != "active" {
			return httpErr{404, "active identity not found"}
		}
		revoked := []string{}
		for _, g := range s.grantsFor(id.ID) {
			s.revoke(id.ID, g.EntitlementID, "")
			revoked = append(revoked, g.EntitlementID)
		}
		// Cancel any open requests for the leaver.
		for i := range s.Requests {
			if s.Requests[i].IdentityID == id.ID && s.Requests[i].Status == "pending" {
				s.Requests[i].Status, s.Requests[i].DecidedBy, s.Requests[i].DecidedAt, s.Requests[i].Reason = "denied", "system", now(), "Auto-cancelled: identity terminated"
			}
		}
		id.Status = "terminated"
		id.EndDate = in.EndDate
		if id.EndDate == "" {
			id.EndDate = now()[:10]
		}
		ev = JMLEvent{s.nextID("JML"), "leaver", id.ID, fmt.Sprintf("%s left; account disabled and all access revoked", id.Name), []string{}, revoked, now()}
		s.JMLEvents = append(s.JMLEvents, ev)
		s.audit(actor(r), "jml.leaver", id.ID, fmt.Sprintf("Disabled %s, revoked %d entitlements", id.Name, len(revoked)))
		return nil
	})
	if err != nil {
		respondErr(w, err)
		return
	}
	writeJSON(w, 200, ev)
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
