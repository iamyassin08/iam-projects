package main

import (
	"fmt"
	"strings"
)

// Lifecycle operations shared by the JML UI endpoints and the SCIM API, so an
// upstream IdP pushing a change gets exactly the same controls as an analyst.

type newIdentity struct {
	Name, Email, Department, Title, Manager, RoleID, StartDate, ExternalID string
}

func (s *State) createIdentity(actor string, in newIdentity) (*Identity, error) {
	if strings.TrimSpace(in.Name) == "" {
		return nil, httpErr{400, "name is required"}
	}
	var role *Role
	if in.RoleID != "" {
		if role = s.role(in.RoleID); role == nil {
			return nil, httpErr{400, "unknown role"}
		}
	}
	email := strings.TrimSpace(in.Email)
	if email == "" {
		email = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(in.Name), " ", ".")) + "@demo.local"
	}
	for _, i := range s.Identities {
		if strings.EqualFold(i.Email, email) && i.Status == "active" {
			return nil, httpErr{409, "an active identity already uses " + email}
		}
	}
	dept := in.Department
	if dept == "" && role != nil {
		dept = role.Department
	}
	start := in.StartDate
	if start == "" {
		start = now()[:10]
	}
	id := Identity{
		ID: s.nextID("ID"), ExternalID: in.ExternalID, Name: in.Name, Email: email, Department: dept,
		Title: in.Title, Manager: in.Manager, RoleID: in.RoleID, Status: "active", StartDate: start,
		Created: now(), Updated: now(),
	}
	s.Identities = append(s.Identities, id)
	granted := []string{}
	roleName := "no role"
	if role != nil {
		roleName = role.Name
		for _, e := range role.Entitlements {
			if s.grant(id.ID, e, "role") {
				granted = append(granted, e)
			}
		}
	}
	s.JMLEvents = append(s.JMLEvents, JMLEvent{s.nextID("JML"), "joiner", id.ID,
		fmt.Sprintf("%s joined %s as %s%s", id.Name, orDash(dept), roleName, via(actor)), granted, []string{}, now()})
	s.audit(actor, "jml.joiner", id.ID, fmt.Sprintf("Created %s, role %s, granted %d birthright entitlements", id.Name, roleName, len(granted)))
	return s.identity(id.ID), nil
}

// moveIdentity swaps role. newRoleID may be "" (SCIM group removal): all role access is removed.
func (s *State) moveIdentity(actor, identityID, newRoleID, newTitle, newDept string) (JMLEvent, error) {
	id := s.identity(identityID)
	if id == nil || id.Status != "active" {
		return JMLEvent{}, httpErr{404, "active identity not found"}
	}
	var newRole *Role
	if newRoleID != "" {
		if newRole = s.role(newRoleID); newRole == nil {
			return JMLEvent{}, httpErr{400, "unknown role"}
		}
	}
	if newRoleID == id.RoleID {
		return JMLEvent{}, httpErr{400, "identity already has that role"}
	}
	oldRole := s.role(id.RoleID)
	s.clearExclusions(id.ID) // a new job means a fresh birthright baseline
	keep := map[string]bool{}
	if newRole != nil {
		for _, e := range newRole.Entitlements {
			keep[e] = true
		}
	}
	revoked, granted := []string{}, []string{}
	if oldRole != nil {
		for _, e := range oldRole.Entitlements {
			if !keep[e] && s.revoke(id.ID, e, "role") {
				revoked = append(revoked, e)
			}
		}
	}
	// Request-based access is re-certified on a move: anything outside the new role is removed.
	for _, g := range s.grantsFor(id.ID) {
		if g.Source == "request" && !keep[g.EntitlementID] && s.revoke(id.ID, g.EntitlementID, "request") {
			revoked = append(revoked, g.EntitlementID)
		}
	}
	if newRole != nil {
		for _, e := range newRole.Entitlements {
			if s.grant(id.ID, e, "role") {
				granted = append(granted, e)
			}
		}
	}
	oldName, newName := "no role", "no role"
	if oldRole != nil {
		oldName = oldRole.Name
	}
	if newRole != nil {
		newName = newRole.Name
	}
	id.RoleID = newRoleID
	switch {
	case newDept != "":
		id.Department = newDept
	case newRole != nil:
		id.Department = newRole.Department
	}
	if newTitle != "" {
		id.Title = newTitle
	}
	id.Updated = now()
	ev := JMLEvent{s.nextID("JML"), "mover", id.ID, fmt.Sprintf("%s moved from %s to %s%s", id.Name, oldName, newName, via(actor)), granted, revoked, now()}
	s.JMLEvents = append(s.JMLEvents, ev)
	s.audit(actor, "jml.mover", id.ID, fmt.Sprintf("%s → %s: +%d / -%d entitlements", oldName, newName, len(granted), len(revoked)))
	return ev, nil
}

func (s *State) terminateIdentity(actor, identityID, endDate string) (JMLEvent, error) {
	id := s.identity(identityID)
	if id == nil || id.Status != "active" {
		return JMLEvent{}, httpErr{404, "active identity not found"}
	}
	revoked := []string{}
	manual := map[string]bool{}
	for _, g := range s.grantsFor(id.ID) {
		s.revoke(id.ID, g.EntitlementID, "")
		revoked = append(revoked, g.EntitlementID)
		if e := s.entitlement(g.EntitlementID); e != nil {
			if sys := s.system(e.SystemID); sys != nil && sys.Provisioning == "Manual" {
				manual[sys.ID] = true
			}
		}
	}
	// End any live JIT elevation.
	for i := range s.PAMSessions {
		if p := &s.PAMSessions[i]; p.IdentityID == id.ID && p.Status == "active" {
			p.Status, p.EndedAt, p.EndedBy = "revoked", now(), "leaver"
		}
	}
	// Cancel any open requests for the leaver.
	for i := range s.Requests {
		if s.Requests[i].IdentityID == id.ID && s.Requests[i].Status == "pending" {
			s.Requests[i].Status, s.Requests[i].DecidedBy, s.Requests[i].DecidedAt, s.Requests[i].Reason = "denied", "system", now(), "Auto-cancelled: identity terminated"
		}
	}
	// Connected systems are deprovisioned automatically. Manual systems are not:
	// the account stays enabled in the target until someone works the ticket.
	for i := range s.TargetAccounts {
		if a := &s.TargetAccounts[i]; a.IdentityID == id.ID && a.Status == "enabled" {
			if sys := s.system(a.SystemID); sys == nil || sys.Provisioning != "Manual" {
				a.Status = "disabled"
			}
		}
	}
	for sysID := range manual {
		sys := s.system(sysID)
		s.TargetAccounts = append(s.TargetAccounts, TargetAccount{
			ID: s.nextID("ACC"), SystemID: sysID, AccountName: strings.Split(id.Email, "@")[0], Type: "user",
			IdentityID: id.ID, Status: "enabled", LastLogin: daysAgo(1),
			Note: "Manual system: deprovisioning ticket opened for " + sys.Owner + ", not yet worked",
		})
	}
	id.Status = "terminated"
	id.Updated = now()
	// The IdP account is disabled in the same event and live sessions are killed.
	for i := range s.IdPUsers {
		if u := &s.IdPUsers[i]; u.IdentityID == id.ID && !u.Disabled {
			u.Disabled = true
			revokeSessions(u.Username)
			s.audit(actor, "idp.user.disabled", u.Username, "Leaver: sign-in blocked and sessions revoked"+via(actor))
		}
	}
	id.EndDate = endDate
	if id.EndDate == "" {
		id.EndDate = now()[:10]
	}
	id.Updated = now()
	ev := JMLEvent{s.nextID("JML"), "leaver", id.ID, fmt.Sprintf("%s left; account disabled and all access revoked%s", id.Name, via(actor)), []string{}, revoked, now()}
	s.JMLEvents = append(s.JMLEvents, ev)
	s.audit(actor, "jml.leaver", id.ID, fmt.Sprintf("Disabled %s, revoked %d entitlements", id.Name, len(revoked)))
	return ev, nil
}

// rehire reactivates a terminated identity (SCIM active=true) with fresh birthright access.
func (s *State) rehireIdentity(actor, identityID string) (JMLEvent, error) {
	id := s.identity(identityID)
	if id == nil {
		return JMLEvent{}, httpErr{404, "identity not found"}
	}
	if id.Status == "active" {
		return JMLEvent{}, nil
	}
	id.Status, id.EndDate, id.StartDate, id.Updated = "active", "", now()[:10], now()
	s.clearExclusions(id.ID)
	granted := []string{}
	if r := s.role(id.RoleID); r != nil {
		for _, e := range r.Entitlements {
			if s.grant(id.ID, e, "role") {
				granted = append(granted, e)
			}
		}
	}
	ev := JMLEvent{s.nextID("JML"), "rehire", id.ID, fmt.Sprintf("%s re-hired; birthright access restored%s", id.Name, via(actor)), granted, []string{}, now()}
	s.JMLEvents = append(s.JMLEvents, ev)
	s.audit(actor, "jml.rehire", id.ID, fmt.Sprintf("Re-activated %s with %d birthright entitlements", id.Name, len(granted)))
	return ev, nil
}

func via(actor string) string {
	if strings.HasPrefix(actor, "scim:") {
		return " (via SCIM)"
	}
	return ""
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}
