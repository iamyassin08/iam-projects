package main

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
)

// Control checks are read-only assertions over the current state — the
// "Test" step of the lab framework. Each one is a real IAM control an
// auditor would ask about. Run them after every JML / request / role change.

type CheckResult struct {
	ID         string   `json:"id"`
	Control    string   `json:"control"`
	Why        string   `json:"why"`
	Module     string   `json:"module"`
	Frameworks []string `json:"frameworks"` // NIST SP 800-53 r5, SOX ITGC, HIPAA Security Rule
	Pass       bool     `json:"pass"`
	Findings   []string `json:"findings"`
}

// Framework references per control. These are the citations an auditor would
// map the control to; see docs/CONTROLS.md for the reasoning.
var frameworks = map[string][]string{
	"C1":  {"NIST AC-2(3)", "SOX ITGC: access removal", "HIPAA 164.308(a)(3)(ii)(C)"},
	"C2":  {"NIST AC-2", "NIST AC-6", "SOX ITGC: access modification"},
	"C3":  {"NIST AC-2(1)", "SOX ITGC: access provisioning approval"},
	"C4":  {"NIST AC-5", "SOX ITGC: segregation of duties"},
	"C5":  {"NIST AC-5", "NIST AC-6"},
	"C6":  {"NIST AC-6(5)", "NIST AC-6(1)", "CIS 5.4"},
	"C7":  {"NIST CM-8", "NIST AC-2(1)"},
	"C8":  {"NIST AC-2(2)", "NIST AC-6(5)"},
	"C9":  {"NIST AC-2(4)", "NIST AU-6", "HIPAA 164.312(a)(2)(ii)"},
	"C10": {"NIST AC-2(3)", "NIST IA-4", "SOX ITGC: access removal"},
	"C11": {"NIST AC-2", "NIST AC-6", "SOX ITGC: unauthorized access"},
	"C12": {"NIST AC-2(3)", "NIST AC-6(7)"},
	"C13": {"NIST AC-2(j)", "SOX ITGC: user access review", "HIPAA 164.308(a)(4)(ii)(C)"},
	"C14": {"NIST IA-5(1)", "NIST SC-12"},
	"C15": {"NIST IA-2(1)", "NIST IA-2(2)", "HIPAA 164.312(d)", "CIS 6.3", "CIS 6.5"},
	"C16": {"NIST IA-2", "NIST AC-17", "CIS 4.8"},
	"C17": {"NIST IA-5(1)", "NIST AC-2(4)", "CIS 5.2", "SOX ITGC: privileged access"},
	"C18": {"NIST AC-6", "NIST AC-6(10)", "CIS 6.8"},
	"C19": {"NIST AC-6(5)", "NIST IA-2(1)", "CIS 6.5"},
	"C20": {"NIST IR-4", "NIST SI-4", "NIST AU-6", "HIPAA 164.308(a)(6)(ii)"},
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
		out = append(out, CheckResult{id, control, why, module, frameworks[id], len(findings) == 0, findings})
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
				if !s.hasGrant(i.ID, e) && !s.excluded(i.ID, e) {
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

	// C8 Expired JIT elevations are actually removed
	f = nil
	for _, g := range s.Grants {
		if g.Source == "jit" && g.ExpiresAt != "" && !nowT().Before(parseT(g.ExpiresAt)) {
			f = append(f, fmt.Sprintf("%s still holds %s after its JIT window ended", name(g.IdentityID), ent(g.EntitlementID)))
		}
	}
	add("C8", "pam", "Expired JIT elevations are removed", "Time-boxed access only works if the clock is enforced.", f)

	// C9 Break-glass use is reviewed
	f = nil
	for _, p := range s.PAMSessions {
		if p.BreakGlass && p.ReviewedBy == "" && p.Status != "active" {
			f = append(f, fmt.Sprintf("%s: %s used break-glass %s with no post-use review", p.ID, name(p.IdentityID), ent(p.EntitlementID)))
		}
	}
	add("C9", "pam", "Every break-glass session is reviewed", "Emergency access bypasses approval, so it must be reviewed after the fact.", f)

	// C10 No orphaned or unowned accounts in target systems
	f = nil
	for _, a := range s.TargetAccounts {
		if c := s.classify(a); c.Finding == "orphan" || c.Finding == "unowned-service" {
			f = append(f, fmt.Sprintf("%s / %s: %s", sysName(s, a.SystemID), a.AccountName, c.Detail))
		}
	}
	add("C10", "risk", "No orphaned or ownerless accounts in target systems", "Reconciliation finds what deprovisioning missed.", f)

	// C11 No rogue access created outside IAM
	f = nil
	for _, a := range s.TargetAccounts {
		if c := s.classify(a); c.Finding == "rogue" {
			f = append(f, fmt.Sprintf("%s / %s: %s", sysName(s, a.SystemID), a.AccountName, c.Detail))
		}
	}
	add("C11", "risk", "No access granted directly in apps, outside IAM", "If IAM did not grant it, nobody approved it.", f)

	// C12 Privileged access is used
	f = nil
	for _, d := range s.dormant() {
		if d.Privileged {
			f = append(f, fmt.Sprintf("%s has not used %s in %d days", name(d.IdentityID), ent(d.EntitlementID), d.DaysUnused))
		}
	}
	add("C12", "risk", fmt.Sprintf("Standing privileged access is used within %d days", DormantDays), "Unused admin rights are pure risk: remove them or move them to JIT.", f)

	// C13 Certification campaigns finish on time
	f = nil
	for _, c := range s.Campaigns {
		if st := s.stats(c); st.Overdue {
			f = append(f, fmt.Sprintf("%s is overdue with %d of %d items undecided", c.Name, st.Total-st.Decided, st.Total))
		}
	}
	add("C13", "certifications", "Access reviews are completed by their due date", "An overdue review is a missed control for the whole quarter.", f)

	// C14 SCIM credentials are rotated
	f = nil
	for _, t := range s.SCIMTokens {
		if !t.Revoked && nowT().Sub(parseT(t.CreatedAt)).Hours() > 90*24 {
			f = append(f, fmt.Sprintf("Token %s (%s…) is older than 90 days", t.Name, t.Prefix))
		}
	}
	add("C14", "scim", "Provisioning tokens are rotated within 90 days", "A long-lived bearer token is a standing credential to create and delete users.", f)

	// C15 MFA is enforced for every user (not just admins, not report-only)
	f = nil
	enforced := false
	for _, p := range s.CAPolicies {
		if p.State == "on" && p.Grant == "mfa" && inAny(p.IncludeGroups, []string{"all-staff"}) && len(p.RiskLevels) == 0 && len(p.Devices) == 0 && len(p.Countries) == 0 && len(p.NotCountries) == 0 {
			enforced = true
		}
		if p.State == "report-only" && p.Grant == "mfa" {
			f = append(f, p.ID+" "+p.Name+" is in report-only: it logs but does not enforce")
		}
	}
	if !enforced && len(f) == 0 {
		f = append(f, "No enabled Conditional Access policy requires MFA for all users")
	}
	if enforced {
		f = nil
	}
	for _, u := range s.IdPUsers {
		if !u.MFAEnrolled && !u.Disabled {
			f = append(f, u.Name+" has no MFA method registered")
		}
	}
	add("C15", "mfa", "MFA is enforced and registered for every user", "Passwords alone are phished and sprayed daily; MFA blocks over 99% of those attacks.", f)

	// C16 Legacy authentication is blocked
	f = nil
	blocked := false
	for _, p := range s.CAPolicies {
		if p.State == "on" && p.Grant == "block" && slices.Contains(p.ClientApps, "legacy") {
			blocked = true
		}
	}
	if !blocked {
		f = append(f, "No enabled policy blocks legacy authentication (IMAP/POP/basic SMTP bypass MFA)")
	}
	add("C16", "mfa", "Legacy authentication protocols are blocked", "Basic auth can't do MFA, so attackers use it to skip your MFA policy.", f)

	// C17 Vaulted privileged credentials are rotated on schedule
	f = nil
	for _, v := range s.Vault {
		if age := int(nowT().Sub(parseT(v.RotatedAt)).Hours() / 24); age > v.RotationDays {
			f = append(f, fmt.Sprintf("%s last rotated %d days ago (policy: %d)", v.Name, age, v.RotationDays))
		}
	}
	add("C17", "vault", "Vaulted admin passwords are rotated on schedule and after use", "A shared admin password that never changes is a standing backdoor.", f)

	// C18 No cloud policy grants full admin to a principal
	f = nil
	for _, p := range s.CloudPolicies {
		for _, x := range lintPolicy(p) {
			if x.Severity == "critical" && len(p.AttachedTo) > 0 {
				f = append(f, fmt.Sprintf("%s (attached to %s): %s", p.Name, strings.Join(p.AttachedTo, ", "), x.Detail))
			}
		}
	}
	add("C18", "cloud", "No cloud identity has Action:* on Resource:*", "Least privilege in the cloud: wildcard admin turns one leaked key into a full breach.", f)

	// C19 Sensitive cloud permissions need MFA or just-in-time activation
	f = nil
	for _, p := range s.CloudPolicies {
		for _, x := range lintPolicy(p) {
			if x.Rule == "sensitive-no-mfa" || x.Rule == "passrole-star" {
				f = append(f, fmt.Sprintf("%s / %s: %s", p.Name, x.Sid, x.Detail))
			}
		}
	}
	for _, x := range s.azureFindings() {
		if x["severity"] == "high" {
			f = append(f, "Azure: "+x["detail"])
		}
	}
	add("C19", "cloud", "Sensitive cloud permissions require MFA or PIM", "Standing cloud admin with no step-up is the shortest path from phished user to tenant owner.", f)

	// C20 Identity threat alerts are triaged
	f = nil
	for _, a := range s.detect() {
		if (a.Severity == "high" || a.Severity == "critical") && a.Status == "open" {
			f = append(f, fmt.Sprintf("%s alert %q (%s) is untriaged", a.Severity, a.Title, firstNonEmpty(a.User, a.IP)))
		}
	}
	add("C20", "monitoring", "High-severity identity alerts are triaged", "Detection without response is just logging.", f)

	return out
}

func getChecks(w http.ResponseWriter, r *http.Request) {
	store.View(func(s *State) { writeJSON(w, 200, runChecks(s)) })
}
