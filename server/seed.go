package main

// Seed returns a realistic demo tenant: one HR source, one IdP, a directory,
// and SaaS/cloud apps, with RBAC roles, SoD rules, JIT eligibility, review
// history and some target-system drift. All names are fictional demo data;
// product names only label the type of system being simulated.
//
// The tenant ships with deliberate audit findings (C6, C7, C9, C10, C11, C12)
// so the lab has something real to remediate.
func Seed() *State {
	s := &State{Seq: 100}

	s.Systems = []System{
		{"workday", "Workday (HRIS)", "hris", "n/a", "Source", "HR Operations", "high"},
		{"entra", "Microsoft Entra ID", "idp", "OIDC / SAML", "Source", "IAM Team", "high"},
		{"ad", "Active Directory", "directory", "LDAP / Kerberos", "API", "IAM Team", "high"},
		{"m365", "Microsoft 365", "app", "SAML", "SCIM", "IT Ops", "medium"},
		{"servicenow", "ServiceNow", "app", "SAML", "SCIM", "IT Service Mgmt", "medium"},
		{"salesforce", "Salesforce", "app", "SAML", "SCIM", "Sales Ops", "medium"},
		{"github", "GitHub Enterprise", "app", "SAML", "SCIM", "Engineering", "high"},
		{"aws", "AWS IAM Identity Center", "cloud", "SAML", "SCIM", "Cloud Platform", "high"},
		{"erp", "NetSuite ERP", "app", "SAML", "API", "Finance", "high"},
		{"ehr", "Epic EHR", "app", "LDAP", "Manual", "Revenue Cycle", "high"},
	}

	s.Entitlements = []Entitlement{
		{"m365-e3", "m365", "M365 E3 license", false},
		{"ad-users", "ad", "Domain Users", false},
		{"ad-admins", "ad", "Domain Admins", true},
		{"sn-requester", "servicenow", "Requester", false},
		{"sn-itil", "servicenow", "ITIL Agent", false},
		{"sn-admin", "servicenow", "Platform Admin", true},
		{"sf-user", "salesforce", "Sales User", false},
		{"sf-admin", "salesforce", "System Administrator", true},
		{"gh-member", "github", "Org Member", false},
		{"gh-owner", "github", "Org Owner", true},
		{"aws-readonly", "aws", "ReadOnlyAccess", false},
		{"aws-dev", "aws", "Developer (non-prod)", false},
		{"aws-admin", "aws", "AdministratorAccess (prod)", true},
		{"erp-ap", "erp", "AP Clerk — enter invoices", false},
		{"erp-vendor", "erp", "Vendor Master — create vendors", false},
		{"erp-approve", "erp", "Payment Approver", true},
		{"ehr-billing", "ehr", "Billing & Claims", false},
		{"ehr-clinical", "ehr", "Clinical Chart Access", true},
	}

	s.Roles = []Role{
		{"r-eng", "Software Engineer", "Engineering", "Builds and ships product code", []string{"m365-e3", "ad-users", "sn-requester", "gh-member", "aws-dev"}},
		{"r-sales", "Account Executive", "Sales", "Owns customer pipeline", []string{"m365-e3", "ad-users", "sn-requester", "sf-user"}},
		{"r-ap", "AP Specialist", "Finance", "Enters and reconciles vendor invoices", []string{"m365-e3", "ad-users", "sn-requester", "erp-ap"}},
		{"r-finmgr", "Finance Manager", "Finance", "Approves vendor payments", []string{"m365-e3", "ad-users", "sn-requester", "erp-approve"}},
		{"r-rcm", "Revenue Cycle Analyst", "Revenue Cycle", "Works claims, denials and billing", []string{"m365-e3", "ad-users", "sn-requester", "ehr-billing"}},
		{"r-desk", "IT Service Desk", "IT", "Tier 1 support and password resets", []string{"m365-e3", "ad-users", "sn-itil"}},
		{"r-iam", "IAM Engineer", "Security", "Runs identity lifecycle and access governance", []string{"m365-e3", "ad-users", "sn-itil", "gh-member", "aws-readonly"}},
	}

	s.SoDRules = []SoDRule{
		{"sod-1", "erp-vendor", "erp-ap", "Same person can create a vendor and enter invoices to it (fraud risk)"},
		{"sod-2", "erp-ap", "erp-approve", "Same person can enter and approve a payment"},
		{"sod-3", "aws-dev", "aws-admin", "Developer with prod admin can bypass change control"},
		{"sod-4", "ehr-billing", "ehr-clinical", "Billing staff should not edit clinical charts that drive charges"},
	}

	people := []Identity{
		{Name: "Omar Farouk", Email: "omar.farouk@demo.local", Department: "Engineering", Title: "Engineering Manager", Manager: "Leila Nasser", RoleID: "r-eng", StartDate: "2023-08-14"},
		{Name: "Daniel Brooks", Email: "daniel.brooks@demo.local", Department: "Sales", Title: "Account Executive", Manager: "Leila Nasser", RoleID: "r-sales", StartDate: "2024-01-08"},
		{Name: "Priya Raman", Email: "priya.raman@demo.local", Department: "Finance", Title: "AP Specialist", Manager: "Grace Kim", RoleID: "r-ap", StartDate: "2024-06-17"},
		{Name: "Grace Kim", Email: "grace.kim@demo.local", Department: "Finance", Title: "Finance Manager", Manager: "Leila Nasser", RoleID: "r-finmgr", StartDate: "2022-11-01"},
		{Name: "Marcus Lee", Email: "marcus.lee@demo.local", Department: "Revenue Cycle", Title: "Revenue Cycle Analyst", Manager: "Grace Kim", RoleID: "r-rcm", StartDate: "2025-02-10"},
		{Name: "Sofia Alvarez", Email: "sofia.alvarez@demo.local", Department: "IT", Title: "Service Desk Analyst", Manager: "Yusuf Ali", RoleID: "r-desk", StartDate: "2025-05-19"},
		{Name: "Yusuf Ali", Email: "yusuf.ali@demo.local", Department: "Security", Title: "IAM Engineer", Manager: "Leila Nasser", RoleID: "r-iam", StartDate: "2023-02-27"},
	}
	for i, p := range people {
		p.ID = "ID-" + itoa(i+1)
		p.Status = "active"
		p.ExternalID = "WD-" + itoa(10040+i*17) // Workday worker ID, as an IdP would send it
		p.Created = p.StartDate + "T09:00:00Z"
		p.Updated = p.Created
		s.Identities = append(s.Identities, p)
		for j, e := range s.role(p.RoleID).Entitlements {
			s.Grants = append(s.Grants, Grant{IdentityID: p.ID, EntitlementID: e, Source: "role",
				GrantedAt: p.StartDate + "T09:00:00Z", LastUsed: daysAgo((i*7+j*3)%25 + 1)})
		}
		s.JMLEvents = append(s.JMLEvents, JMLEvent{s.nextID("JML"), "joiner", p.ID, p.Name + " joined as " + p.Title, s.role(p.RoleID).Entitlements, []string{}, p.StartDate + "T09:00:00Z"})
	}
	// Grace's payment approval is privileged birthright (finding C6) and is in daily use.
	s.findGrant("ID-4", "erp-approve").LastUsed = daysAgo(1)

	// ---- Approved, request-based extra access ----
	type extra struct {
		id, ent, why, approver, reason string
		ago, used                      int
	}
	for _, x := range []extra{
		{"ID-7", "aws-admin", "Break-glass for IdP SCIM connector rotation", "leila.nasser", "Time-boxed, review in 90 days", 68, 12},
		{"ID-1", "gh-owner", "Own the GitHub org while the platform lead is on leave", "leila.nasser", "Revisit at Q4 review", 50, 3},
		{"ID-6", "ad-admins", "Unlock service accounts during after-hours escalations", "yusuf.ali", "Approved for on-call rotation", 260, 210}, // dormant: C12
	} {
		s.Requests = append(s.Requests, AccessRequest{s.nextID("REQ"), x.id, x.ent, x.why, "approved", "", daysAgo(x.ago + 1), x.approver, daysAgo(x.ago), x.reason})
		s.Grants = append(s.Grants, Grant{IdentityID: x.id, EntitlementID: x.ent, Source: "request", GrantedAt: daysAgo(x.ago), LastUsed: daysAgo(x.used)})
	}
	// ---- Pending requests ----
	s.Requests = append(s.Requests,
		AccessRequest{s.nextID("REQ"), "ID-3", "erp-approve", "Cover Grace's approvals during PTO", "pending", "sod-2: Same person can enter and approve a payment", daysAgo(3), "", "", ""},
		AccessRequest{s.nextID("REQ"), "ID-2", "sf-admin", "Need to edit page layouts for my team", "pending", "", daysAgo(2), "", "", ""},
		AccessRequest{s.nextID("REQ"), "ID-1", "aws-readonly", "Debug prod logs during on-call", "pending", "", daysAgo(1), "", "", ""},
	)

	// ---- JIT eligibility and session history ----
	s.Eligibility = []Eligibility{
		{"ID-7", "ad-admins", 60, "leila.nasser", daysAgo(120)},
		{"ID-7", "sn-admin", 120, "leila.nasser", daysAgo(120)},
		{"ID-1", "aws-admin", 60, "yusuf.ali", daysAgo(45)},
		{"ID-6", "sn-admin", 30, "yusuf.ali", daysAgo(30)},
	}
	sess := func(id, ent, why, ticket string, bg bool, mins, startedDaysAgo int, reviewed string) {
		start := nowT().AddDate(0, 0, -startedDaysAgo)
		end := start.Add(durMin(mins))
		p := PAMSession{ID: s.nextID("PIM"), IdentityID: id, EntitlementID: ent, Justification: why, Ticket: ticket, BreakGlass: bg,
			Minutes: mins, Status: "expired", StartedAt: fmtT(start), ExpiresAt: fmtT(end), EndedAt: fmtT(end), EndedBy: "system:expiry"}
		if reviewed != "" {
			p.ReviewedBy, p.ReviewNotes = "leila.nasser", reviewed
		}
		s.PAMSessions = append(s.PAMSessions, p)
	}
	sess("ID-1", "aws-admin", "Rotate prod KMS keys per change window", "CHG0031882", false, 45, 6, "")
	sess("ID-6", "sn-admin", "Fix broken catalog workflow for laptop requests", "INC0045120", false, 30, 1, "")
	sess("ID-7", "ad-admins", "IdP outage: emergency Domain Admin to restore federation trust", "", true, 30, 3, "") // unreviewed: C9

	// ---- Access certification history ----
	closed := Campaign{ID: s.nextID("CERT"), Name: "Q3 2026 privileged access review", Scope: "privileged", CreatedBy: "yassin.iam",
		CreatedAt: daysAgo(75), DueDate: daysAgo(61), Status: "closed", ClosedAt: daysAgo(62), AutoRevoke: true}
	s.Campaigns = append(s.Campaigns, closed)
	for _, it := range []struct{ id, ent, src, rev, dec, comment string }{
		{"ID-4", "erp-approve", "role", "Leila Nasser", "keep", "Role requirement for Finance Manager"},
		{"ID-7", "aws-admin", "request", "Leila Nasser", "keep", "Needed for SCIM connector; convert to JIT by Q4"},
		{"ID-6", "ad-admins", "request", "Yusuf Ali", "keep", "Still on on-call rotation"},
		{"ID-1", "aws-admin", "request", "Leila Nasser", "revoke", "Project finished; moved to JIT eligibility"},
	} {
		s.CertItems = append(s.CertItems, CertItem{ID: s.nextID("ITEM"), CampaignID: closed.ID, IdentityID: it.id, EntitlementID: it.ent, Source: it.src,
			Reviewer: it.rev, Privileged: true, Decision: it.dec, Comment: it.comment, DecidedBy: "manager", DecidedAt: daysAgo(64)})
	}
	if c, err := s.launchCampaign("yassin.iam", "Q4 2026 privileged access review", "privileged", "", 10, true); err == nil {
		c.CreatedAt = daysAgo(4)
		for i := range s.CertItems {
			if it := &s.CertItems[i]; it.CampaignID == c.ID && it.IdentityID == "ID-4" {
				it.Decision, it.Comment, it.DecidedBy, it.DecidedAt = "keep", "Required to release weekly vendor payments", "leila.nasser", daysAgo(2)
			}
		}
	}

	// ---- What reconciliation finds in the target systems ----
	s.TargetAccounts = []TargetAccount{
		{ID: s.nextID("ACC"), SystemID: "aws", AccountName: "svc-legacy-deploy", Type: "service", EntitlementID: "aws-admin", LastLogin: daysAgo(400), Status: "enabled", Note: "Created by a 2023 CI pipeline; access keys never rotated"},
		{ID: s.nextID("ACC"), SystemID: "erp", AccountName: "j.ortega", Type: "user", EntitlementID: "erp-vendor", LastLogin: daysAgo(140), Status: "enabled", Note: "Former contractor; never in Workday"},
		{ID: s.nextID("ACC"), SystemID: "github", AccountName: "dbrooks-sales", Type: "user", IdentityID: "ID-2", EntitlementID: "gh-owner", LastLogin: daysAgo(9), Status: "enabled", Note: "Invited directly by an org owner, bypassing SSO group sync"},
		{ID: s.nextID("ACC"), SystemID: "ehr", AccountName: "mlee.clinical", Type: "user", IdentityID: "ID-5", EntitlementID: "ehr-clinical", LastLogin: daysAgo(4), Status: "enabled", Note: "Local Epic account created by a clinic manager"},
		{ID: s.nextID("ACC"), SystemID: "servicenow", AccountName: "sn-integration", Type: "service", EntitlementID: "sn-admin", Owner: "Yusuf Ali", LastLogin: daysAgo(0), Status: "enabled", Note: "Entra ID provisioning connector"},
		{ID: s.nextID("ACC"), SystemID: "ad", AccountName: "svc-adsync", Type: "service", EntitlementID: "ad-users", Owner: "IAM Team", LastLogin: daysAgo(0), Status: "enabled", Note: "Directory sync agent"},
	}

	// ---- An active SCIM provisioning credential (hash only; plaintext was never stored) ----
	s.SCIMTokens = []SCIMToken{{ID: s.nextID("TOK"), Name: "Entra ID provisioning", Prefix: "scim_4b1e9c", HashStore: hashToken("seed-token-not-usable"),
		CreatedBy: "yassin.iam", CreatedAt: daysAgo(21), LastUsed: daysAgo(0), Requests: 1284}}

	s.audit("system", "seed", "tenant", "Demo tenant created with 7 identities, 7 roles, 10 systems")
	return s
}
