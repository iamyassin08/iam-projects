package main

import (
	"fmt"
	"net/http"
)

// Access check answers the RBAC edge-case question auditors and analysts ask:
// "can this person use this entitlement right now, and through what path?"
// It explains every route to access (role, approved request, live JIT) and
// what would happen if they asked for it (eligibility, SoD, pending request).

type accessCheck struct {
	Allowed  bool     `json:"allowed"`
	Via      string   `json:"via"` // role | request | jit | none
	Reasons  []string `json:"reasons"`
	NextStep string   `json:"nextStep"`
}

func (s *State) checkAccess(identityID, entID string) (accessCheck, error) {
	id, e := s.identity(identityID), s.entitlement(entID)
	if id == nil || e == nil {
		return accessCheck{}, httpErr{404, "identity or entitlement not found"}
	}
	out := accessCheck{Via: "none", Reasons: []string{}}
	add := func(f string, a ...any) { out.Reasons = append(out.Reasons, fmt.Sprintf(f, a...)) }
	ro := s.role(id.RoleID)
	if id.Status != "active" {
		add("✗ %s is terminated: leavers hold no access", id.Name)
		out.NextStep = "No access. A rehire goes through Joiner · Mover · Leaver."
		return out, nil
	}
	if g := s.findGrant(id.ID, e.ID); g != nil {
		out.Allowed, out.Via = true, g.Source
		switch g.Source {
		case "role":
			add("✓ birthright: the %s role includes %s", ro.Name, e.Name)
		case "request":
			add("✓ approved access request outside the role")
		case "jit":
			add("✓ live just-in-time elevation until %s", g.ExpiresAt)
		}
		if e.Privileged && g.Source != "jit" {
			add("⚠ privileged access held standing, not just-in-time (C6 / C12 territory)")
		}
		out.NextStep = "Access exists. Recertify it in the next access review."
		return out, nil
	}
	add("✗ the %s role does not include %s", roleName(ro), e.Name)
	if s.excluded(id.ID, e.ID) {
		add("✗ revoked in an access review; role re-sync will not restore it")
	}
	for _, q := range s.Requests {
		if q.IdentityID == id.ID && q.EntitlementID == e.ID && q.Status == "pending" {
			add("… a request (%s) is waiting for approval", q.ID)
		}
	}
	if el := s.eligible(id.ID, e.ID); el != nil {
		add("… eligible for just-in-time activation, up to %d minutes", el.MaxMinutes)
		out.NextStep = "Activate it on Just-in-time access with a change ticket."
	} else {
		out.NextStep = "Raise an access request with a business justification."
	}
	if r := s.sodConflict(id.ID, e.ID); r != nil {
		add("⚠ granting it would break %s: %s", r.ID, r.Description)
		out.NextStep += " Approval would need a documented risk acceptance."
	}
	return out, nil
}

func roleName(r *Role) string {
	if r == nil {
		return "(none)"
	}
	return r.Name
}

func getAccessCheck(w http.ResponseWriter, r *http.Request) {
	store.View(func(s *State) {
		res, err := s.checkAccess(r.URL.Query().Get("identityId"), r.URL.Query().Get("entitlementId"))
		if err != nil {
			respondErr(w, err)
			return
		}
		writeJSON(w, 200, res)
	})
}
