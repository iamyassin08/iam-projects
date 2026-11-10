package main

// Seed returns a realistic demo tenant: one HR source, one IdP, a directory,
// and SaaS/cloud apps, with RBAC roles and SoD rules. All names are fictional
// demo data; product names only label the type of system being simulated.
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
		{Name: "Amina Hassan", Email: "amina.hassan@demo.local", Department: "Engineering", Title: "Software Engineer II", Manager: "Omar Farouk", RoleID: "r-eng", StartDate: "2025-03-03"},
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
		s.Identities = append(s.Identities, p)
		for _, e := range s.role(p.RoleID).Entitlements {
			s.Grants = append(s.Grants, Grant{p.ID, e, "role", p.StartDate + "T09:00:00Z"})
		}
		s.JMLEvents = append(s.JMLEvents, JMLEvent{s.nextID("JML"), "joiner", p.ID, p.Name + " joined as " + p.Title, s.role(p.RoleID).Entitlements, []string{}, p.StartDate + "T09:00:00Z"})
	}
	// An approved, request-based extra grant (shows up in access reviews)
	s.Grants = append(s.Grants, Grant{"ID-8", "aws-admin", "request", "2026-09-02T15:00:00Z"})
	s.Requests = append(s.Requests,
		AccessRequest{s.nextID("REQ"), "ID-8", "aws-admin", "Break-glass for IdP SCIM connector rotation", "approved", "", "2026-09-02T14:10:00Z", "leila.nasser", "2026-09-02T15:00:00Z", "Time-boxed, review in 90 days"},
		AccessRequest{s.nextID("REQ"), "ID-4", "erp-approve", "Cover Grace's approvals during PTO", "pending", "sod-2: Same person can enter and approve a payment", "2026-11-06T16:20:00Z", "", "", ""},
		AccessRequest{s.nextID("REQ"), "ID-3", "sf-admin", "Need to edit page layouts for my team", "pending", "", "2026-11-07T10:05:00Z", "", "", ""},
		AccessRequest{s.nextID("REQ"), "ID-1", "aws-readonly", "Debug prod logs during on-call", "pending", "", "2026-11-08T08:45:00Z", "", "", ""},
	)
	s.audit("system", "seed", "tenant", "Demo tenant created with 8 identities, 7 roles, 10 systems")
	return s
}
