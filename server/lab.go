package main

import (
	"fmt"
	"net/http"
)

// Control checks are read-only assertions over the current state — the
// "Test" step of the lab framework. Each one is a real IAM control an
// auditor would ask about. Run them after every JML / request / role change.

type CheckResult struct {
	ID       string   `json:"id"`
	Control  string   `json:"control"`
	Why      string   `json:"why"`
	Module   string   `json:"module"`
	Pass     bool     `json:"pass"`
	Findings []string `json:"findings"`
}

func runChecks(s *State) []CheckResult {
	name := func(id string) string {
		if i := s.identity(id); i != nil {
			return i.Name
		}
		return id
	}
	ent := func(id string) string {
		if e := s.entitlement(id); e != nil {
			return e.Name
		}
		return id
	}
	out := []CheckResult{}
	add := func(id, module, control, why string, findings []string) {
		if findings == nil {
			findings = []string{}
		}
		out = append(out, CheckResult{id, control, why, module, len(findings) == 0, findings})
	}

	// C1 Leavers hold no access
	var f []string
	for _, i := range s.Identities {
		if i.Status != "active" {
			if n := len(s.grantsFor(i.ID)); n > 0 {
				f = append(f, fmt.Sprintf("%s is terminated but still holds %d entitlements", i.Name, n))
			}
		}
	}
	add("C1", "jml", "Terminated identities hold zero access", "Orphaned accounts are the #1 audit finding after terminations.", f)

	// C2 Role grants match the role exactly (no access creep from old roles)
	f = nil
	for _, i := range s.Identities {
		if i.Status != "active" {
			continue
		}
		r := s.role(i.RoleID)
		want := map[string]bool{}
		if r != nil {
			for _, e := range r.Entitlements {
				want[e] = true
				if !s.hasGrant(i.ID, e) {
					f = append(f, fmt.Sprintf("%s is missing birthright %s", i.Name, ent(e)))
				}
			}
		}
		for _, g := range s.grantsFor(i.ID) {
			if g.Source == "role" && !want[g.EntitlementID] {
				f = append(f, fmt.Sprintf("%s keeps %s from a previous role (access creep)", i.Name, ent(g.EntitlementID)))
			}
		}
	}
	add("C2", "jml", "Role-based access matches the current role", "Movers must lose old access and gain new access in the same event.", f)

	// C3 Every request-based grant traces to an approved request
	f = nil
	for _, g := range s.Grants {
		if g.Source != "request" {
			continue
		}
		ok := false
		for _, q := range s.Requests {
			if q.IdentityID == g.IdentityID && q.EntitlementID == g.EntitlementID && q.Status == "approved" {
				ok = true
			}
		}
		if !ok {
			f = append(f, fmt.Sprintf("%s holds %s with no approved request", name(g.IdentityID), ent(g.EntitlementID)))
		}
	}
	add("C3", "requests", "Every extra grant has an approved request", "Auditors sample grants and ask: who approved this, and why?", f)

	// C4 SoD conflicts only exist with a documented exception
	f = nil
	for _, i := range s.Identities {
		for _, r := range s.SoDRules {
			if s.hasGrant(i.ID, r.A) && s.hasGrant(i.ID, r.B) {
				documented := false
				for _, q := range s.Requests {
					if q.IdentityID == i.ID && q.Status == "approved" && q.SoDConflict != "" && q.Reason != "" && (q.EntitlementID == r.A || q.EntitlementID == r.B) {
						documented = true
					}
				}
				if !documented {
					f = append(f, fmt.Sprintf("%s violates %s (%s + %s) with no risk acceptance", i.Name, r.ID, ent(r.A), ent(r.B)))
				}
			}
		}
	}
	add("C4", "requests", "SoD conflicts have a documented risk acceptance", "Toxic combinations are allowed only as a recorded, owned exception.", f)

	// C5 No role contains both sides of an SoD rule
	f = nil
	for _, ro := range s.Roles {
		has := map[string]bool{}
		for _, e := range ro.Entitlements {
			has[e] = true
		}
		for _, r := range s.SoDRules {
			if has[r.A] && has[r.B] {
				f = append(f, fmt.Sprintf("Role %s contains %s", ro.Name, r.ID))
			}
		}
	}
	add("C5", "roles", "No role bakes in an SoD conflict", "If the role is toxic, every member is a finding.", f)

	// C6 Privileged access is never birthright
	f = nil
	for _, ro := range s.Roles {
		for _, e := range ro.Entitlements {
			if x := s.entitlement(e); x != nil && x.Privileged {
				f = append(f, fmt.Sprintf("Role %s grants privileged %s to everyone in it", ro.Name, x.Name))
			}
		}
	}
	add("C6", "roles", "Privileged access is requested, not birthright", "Least privilege: admin rights need a person, a reason and an expiry.", f)

	// C7 Every system has an owner and a provisioning method
	f = nil
	for _, sy := range s.Systems {
		if sy.Owner == "" {
			f = append(f, sy.Name+" has no owner")
		}
		if sy.Provisioning == "Manual" {
			f = append(f, sy.Name+" is provisioned manually — leavers depend on a ticket being worked")
		}
	}
	add("C7", "systems", "Every system is owned and automatically provisioned", "Manual apps are where deprovisioning gets missed.", f)

	return out
}

func getChecks(w http.ResponseWriter, r *http.Request) {
	store.View(func(s *State) { writeJSON(w, 200, runChecks(s)) })
}
