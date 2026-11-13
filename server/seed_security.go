package main

import (
	"time"
)

// seedSecurity adds the identity-security half of the demo tenant: IdP users
// with MFA, Conditional Access, a week of sign-ins hiding six attacks, a
// credential vault and cloud IAM policies. Like the governance seed, it ships
// with deliberate findings (C15–C20) for the lab.
func seedSecurity(s *State) {
	salt := func(u string) string { return "salt-" + u }
	user := func(username, idID, name string, groups []string, enrolled, bg bool) IdPUser {
		u := IdPUser{Username: username, IdentityID: idID, Name: name, Email: username + "@demo.local", Groups: groups,
			PasswordHash: hashPassword(DemoPassword, salt(username)), BreakGlass: bg, LastSignIn: daysAgo(1)}
		if enrolled {
			u.MFAEnrolled, u.MFAMethod, u.TOTPSecret = true, "totp", demoSecret(username)
		}
		return u
	}
	s.IdPUsers = []IdPUser{
		user("yusuf.ali", "ID-7", "Yusuf Ali", []string{"all-staff", "iam-admins", "approvers"}, true, false),
		user("omar.farouk", "ID-1", "Omar Farouk", []string{"all-staff", "engineering", "approvers"}, true, false),
		user("priya.raman", "ID-3", "Priya Raman", []string{"all-staff", "finance"}, true, false),
		user("sofia.alvarez", "ID-6", "Sofia Alvarez", []string{"all-staff", "service-desk"}, false, false),
		user("bg.admin", "", "Break-glass admin", []string{"break-glass"}, true, true),
	}
	s.IdPUsers[4].LastSignIn = ""

	s.CAPolicies = []CAPolicy{
		{ID: "CA001", Name: "Require MFA for administrators", State: "on", IncludeGroups: []string{"iam-admins"}, ExcludeGroups: []string{"break-glass"}, Apps: []string{"all"}, Grant: "mfa",
			Description: "Admins always prove a second factor, from anywhere."},
		{ID: "CA002", Name: "Require MFA for all users", State: "report-only", IncludeGroups: []string{"all-staff"}, ExcludeGroups: []string{"break-glass"}, Apps: []string{"all"}, Grant: "mfa",
			Description: "Baseline MFA for everyone. Left in report-only after a pilot (finding C15)."},
		{ID: "CA003", Name: "Block legacy authentication", State: "off", IncludeGroups: []string{"all"}, ExcludeGroups: []string{"break-glass"}, Apps: []string{"all"}, ClientApps: []string{"legacy"}, Grant: "block",
			Description: "IMAP, POP and basic-auth SMTP cannot do MFA, so they are blocked outright (finding C16)."},
		{ID: "CA004", Name: "Block sign-ins from sanctioned countries", State: "on", IncludeGroups: []string{"all"}, ExcludeGroups: []string{"break-glass"}, Apps: []string{"all"}, Countries: []string{"RU", "KP", "IR"}, Grant: "block",
			Description: "Geo-block for countries the business never operates from."},
		{ID: "CA005", Name: "MFA when sign-in risk is medium or high", State: "on", IncludeGroups: []string{"all"}, ExcludeGroups: []string{"break-glass"}, Apps: []string{"all"}, RiskLevels: []string{"medium", "high"}, Grant: "mfa",
			Description: "Risk-based step-up: unfamiliar country, anonymizer IP or recent failures."},
		{ID: "CA006", Name: "Block known-bad IPs (named location)", State: "on", IncludeGroups: []string{"all"}, Apps: []string{"all"}, BlockedIPs: true, Grant: "block",
			Description: "IPs added from identity threat alerts. Applies to everyone, break-glass included."},
		{ID: "CA007", Name: "Require MFA on unmanaged devices", State: "on", IncludeGroups: []string{"all-staff"}, ExcludeGroups: []string{"break-glass"}, Apps: []string{"all"}, Devices: []string{"unmanaged"}, Grant: "mfa",
			Description: "Personal phones and laptops always step up."},
	}
	s.BlockedIPs = []string{}

	seedSignIns(s)

	// ---- Credential vault ----
	vault := func(name, sys, account, ent string, rotatedAgo, every int) VaultSecret {
		return VaultSecret{ID: s.nextID("VLT"), Name: name, SystemID: sys, Account: account, EntitlementID: ent, Ciphertext: seal(newPassword()),
			Version: 3 + rotatedAgo%5, RotatedAt: daysAgo(rotatedAgo), RotationDays: every}
	}
	s.Vault = []VaultSecret{
		vault("Domain Admin (adm-yali)", "ad", `CORP\adm-yali`, "ad-admins", 6, 30),
		vault("ServiceNow platform admin", "servicenow", "sn-admin-01", "sn-admin", 12, 30),
		vault("AWS prod break-glass (root)", "aws", "root@acme-prod", "aws-admin", 124, 90), // C17 finding
		vault("NetSuite administrator", "erp", "ns-admin", "erp-approve", 20, 30),
	}

	// ---- Cloud IAM: AWS policies and principals ----
	s.CloudPrincipals = []CloudPrincipal{
		{ID: "user/omar.farouk", Type: "user", Name: "omar.farouk", IdentityID: "ID-1", Boundary: "pol-boundary"},
		{ID: "role/IAMEngineer", Type: "role", Name: "IAMEngineer (Yusuf Ali via SSO)", IdentityID: "ID-7"},
		{ID: "role/DataAnalyst", Type: "role", Name: "DataAnalyst (Revenue Cycle)", IdentityID: "ID-5"},
		{ID: "user/svc-legacy-deploy", Type: "user", Name: "svc-legacy-deploy (service)"},
	}
	s.CloudPolicies = []CloudPolicy{
		{ID: "pol-dev", Name: "DeveloperNonProd", Description: "Day-to-day developer access to non-prod Lambda, logs and the dev bucket. Explicitly denies prod data.", AttachedTo: []string{"user/omar.farouk"},
			Document: `{
  "Version": "2012-10-17",
  "Statement": [
    { "Sid": "LambdaDev", "Effect": "Allow", "Action": ["lambda:GetFunction", "lambda:UpdateFunctionCode", "lambda:InvokeFunction"],
      "Resource": "arn:aws:lambda:us-east-1:111122223333:function:dev-*",
      "Condition": { "StringEquals": { "aws:RequestedRegion": "us-east-1" } } },
    { "Sid": "Logs", "Effect": "Allow", "Action": ["logs:GetLogEvents", "logs:FilterLogEvents"], "Resource": "arn:aws:logs:us-east-1:111122223333:log-group:/aws/lambda/dev-*" },
    { "Sid": "DevBucket", "Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"], "Resource": ["arn:aws:s3:::acme-dev-artifacts", "arn:aws:s3:::acme-dev-artifacts/*"] },
    { "Sid": "NeverProdData", "Effect": "Deny", "Action": "s3:*", "Resource": ["arn:aws:s3:::acme-prod-*", "arn:aws:s3:::acme-prod-*/*"] }
  ]
}`},
		{ID: "pol-boundary", Name: "DeveloperBoundary", Description: "Permissions boundary: the most a developer can ever be given, whatever policies are attached later.", AttachedTo: []string{},
			Document: `{
  "Version": "2012-10-17",
  "Statement": [
    { "Sid": "Ceiling", "Effect": "Allow", "Action": ["lambda:*", "logs:*", "s3:*", "cloudwatch:*"], "Resource": "*" }
  ]
}`},
		{ID: "pol-analyst", Name: "ClaimsDataReadOnly", Description: "Read claims extracts from one prefix, only from the corporate network.", AttachedTo: []string{"role/DataAnalyst"},
			Document: `{
  "Version": "2012-10-17",
  "Statement": [
    { "Sid": "ReadClaimsExtracts", "Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::acme-rcm-extracts/claims/*",
      "Condition": { "IpAddress": { "aws:SourceIp": "73.120.44.0/24" } } },
    { "Sid": "ListPrefix", "Effect": "Allow", "Action": "s3:ListBucket", "Resource": "arn:aws:s3:::acme-rcm-extracts" }
  ]
}`},
		{ID: "pol-iam", Name: "IAMOperations", Description: "Lets the IAM team manage users and keys. Missing the MFA condition (finding C19).", AttachedTo: []string{"role/IAMEngineer"},
			Document: `{
  "Version": "2012-10-17",
  "Statement": [
    { "Sid": "ManageUsers", "Effect": "Allow", "Action": ["iam:CreateUser", "iam:DeleteUser", "iam:AttachUserPolicy", "iam:CreateAccessKey", "iam:DeleteAccessKey", "iam:List*", "iam:Get*"], "Resource": "*" },
    { "Sid": "PassAnyRole", "Effect": "Allow", "Action": "iam:PassRole", "Resource": "*" }
  ]
}`},
		{ID: "pol-legacy", Name: "LegacyDeployFullAccess", Description: "Attached in 2023 to a CI user so a pipeline 'just works'. Full admin (finding C18).", AttachedTo: []string{"user/svc-legacy-deploy"},
			Document: `{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow", "Action": "*", "Resource": "*" }
  ]
}`},
	}
	s.AzureAssignments = []AzureAssignment{
		{s.nextID("AZ"), "Platform Admins (group)", "group", "Owner", "mg-acme-root", "management-group", "eligible"},
		{s.nextID("AZ"), "omar.farouk", "user", "Owner", "sub-acme-prod", "subscription", "permanent"}, // C19 finding
		{s.nextID("AZ"), "Engineering (group)", "group", "Contributor", "rg-app-dev", "resource-group", "permanent"},
		{s.nextID("AZ"), "Revenue Cycle Analysts (group)", "group", "Storage Blob Data Reader", "rg-rcm-data", "resource-group", "permanent"},
		{s.nextID("AZ"), "sp-github-deploy", "service principal", "Contributor", "rg-app-prod", "resource-group", "permanent"},
		{s.nextID("AZ"), "IAM Team (group)", "group", "User Access Administrator", "sub-acme-prod", "subscription", "eligible"},
	}
}

// seedSignIns writes a week of normal activity with six attacks hidden in it.
func seedSignIns(s *State) {
	base := nowT()
	add := func(t time.Time, user, app, locKey, device, client, result, reason, mfa, risk string) {
		if t.After(base) {
			return
		}
		l := locByKey(locKey)
		s.SignIns = append(s.SignIns, SignIn{s.nextID("SI"), fmtT(t), user, app, l.IP, l.City, l.Country, device, client, result, reason, mfa, risk, []string{}, "seed"})
	}
	day := func(d, h, m int) time.Time {
		y, mo, dd := base.AddDate(0, 0, -d).Date()
		return time.Date(y, mo, dd, h, m, 0, 0, time.UTC)
	}
	// Baseline: weekday-style morning and afternoon sign-ins from Middle Tennessee.
	type person struct{ user, app, loc, mfa string }
	people := []person{
		{"yusuf.ali", "iam-projects", "nashville", "totp"}, {"omar.farouk", "github", "nashville", "totp"}, {"priya.raman", "erp", "clarksville", "totp"},
		{"sofia.alvarez", "servicenow", "clarksville", "none"}, {"daniel.brooks", "salesforce", "nashville", "push"}, {"grace.kim", "erp", "nashville", "push"},
		{"marcus.lee", "ehr", "clarksville", "push"},
	}
	for d := 7; d >= 0; d-- {
		for i, p := range people {
			add(day(d, 13+i%3, (i*11+d*7)%60), p.user, p.app, p.loc, "managed", "browser", "success", "", p.mfa, "low")
			add(day(d, 19, (i*13+d*5)%60), p.user, "m365", p.loc, "managed", "browser", "success", "", p.mfa, "low")
			if (i+d)%4 == 0 { // the odd typo
				add(day(d, 13+i%3, (i*11+d*7)%60).Add(-2*time.Minute), p.user, p.app, p.loc, "managed", "browser", "failure", "Invalid username or password", "none", "low")
			}
		}
	}
	// 1. Password spray from a Tor exit node (D1).
	t := day(2, 6, 0)
	for i, u := range []string{"omar.farouk", "daniel.brooks", "priya.raman", "grace.kim", "marcus.lee", "sofia.alvarez", "yusuf.ali", "admin", "administrator", "j.smith", "test.user", "leila.nasser"} {
		add(t.Add(time.Duration(i*40)*time.Second), u, "m365", "frankfurt-tor", "unmanaged", "browser", "failure", "Invalid username or password", "none", "high")
	}
	// 2. Brute force against one account, then smart lockout (D2).
	t = day(1, 11, 0)
	for i := 0; i < 11; i++ {
		res, why := "failure", "Invalid username or password"
		if i >= 5 {
			res, why = "locked", "Account locked after repeated failures (smart lockout)"
		}
		add(t.Add(time.Duration(i*35)*time.Second), "priya.raman", "erp", "amsterdam", "unmanaged", "browser", res, why, "none", "medium")
	}
	// 3. Impossible travel: Nashville then Lagos 39 minutes later (D3).
	add(day(3, 14, 2), "omar.farouk", "github", "nashville", "managed", "browser", "success", "", "totp", "low")
	add(day(3, 14, 41), "omar.farouk", "aws", "lagos", "unmanaged", "browser", "success", "", "push", "medium")
	// 4. MFA fatigue at 3am, then the user gives in (D4).
	t = day(1, 3, 10)
	for i := 0; i < 9; i++ {
		add(t.Add(time.Duration(i*95)*time.Second), "grace.kim", "m365", "lagos", "unmanaged", "browser", "mfa-denied", "User declined the MFA push", "push", "medium")
	}
	add(t.Add(16*time.Minute), "grace.kim", "m365", "lagos", "unmanaged", "browser", "success", "MFA push approved", "push", "medium")
	// 5. Legacy IMAP basic auth succeeds, skipping MFA (D5).
	add(day(4, 16, 20), "daniel.brooks", "m365", "london", "unmanaged", "legacy-imap", "success", "Basic authentication", "none", "medium")
	// 6. Orphaned contractor account still signing in to the ERP (D6).
	add(day(5, 15, 5), "j.ortega", "erp", "chicago", "unmanaged", "browser", "success", "Local NetSuite credentials", "none", "low")
}

// migrate fills sections added after a tenant was first created, so an
// existing data volume picks up new modules without a reset.
func migrate(s *State) bool {
	if s.IdPUsers != nil {
		return false
	}
	fresh := &State{Seq: s.Seq + 1000}
	seedSecurity(fresh)
	s.Seq = fresh.Seq
	s.IdPUsers, s.CAPolicies, s.BlockedIPs, s.SignIns = fresh.IdPUsers, fresh.CAPolicies, fresh.BlockedIPs, fresh.SignIns
	s.Vault, s.CloudPrincipals, s.CloudPolicies, s.AzureAssignments = fresh.Vault, fresh.CloudPrincipals, fresh.CloudPolicies, fresh.AzureAssignments
	s.AlertStates = []AlertState{}
	s.audit("system", "migrate", "tenant", "Added identity security modules: IdP, MFA, Conditional Access, sign-in log, vault, cloud IAM")
	return true
}

