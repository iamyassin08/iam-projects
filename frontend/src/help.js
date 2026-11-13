// Help center content. Each project lists the standard lab steps for it (in our
// own words), where each step is done in this app, the skills it proves, and a
// ready-to-paste prompt that turns any AI chatbot into a step-by-step mentor for
// doing the same lab on a real platform.

export const SOURCE_NOTE = 'Project list follows the widely shared "10 IAM Analyst Projects" roadmap (Artem Polynko, January 2026). Descriptions here are our own.'

export const LABS = [
  {
    n: 1, title: 'User lifecycle management (provisioning and deprovisioning)', guide: 'jml',
    summary: 'Simulate joiners, movers and leavers so access follows the person: exact birthright access on day one, old access removed when the job changes, everything removed on exit.',
    platforms: 'Entra ID free tenant or Okta Developer Edition',
    steps: [
      ['Stand up an identity tenant', 'The demo tenant is ready: Workday as HR source, Entra-style IdP, 10 connected systems.', 'systems', 'System map'],
      ['Prepare user data as CSV (role, department, status)', 'Load or edit the sample HR feed.', 'automation', 'Automation'],
      ['Provision joiners', 'Onboard someone and watch birthright access appear; or push a user over SCIM.', 'jml', 'Joiner · Mover · Leaver'],
      ['Simulate movers', 'Move Daniel Brooks from Sales to Engineering: Salesforce goes, GitHub arrives, in one event.', 'jml', 'Joiner · Mover · Leaver'],
      ['Deprovision leavers and verify removal', 'Offboard someone, then check C1 (zero access) and the orphan left in the manual app.', 'lab', 'Controls lab'],
      ['Review audit logs', 'Every grant and revoke with actor, target and reason; export CSV.', 'audit', 'Audit log'],
      ['Document workflows for your resume', 'Use the STAR story and bullet in the Project guide.', 'guide', 'Project guide'],
    ],
    outcomes: ['Joiner, mover and leaver processes end to end', 'Least privilege at onboarding and offboarding', 'Lifecycle at scale through SCIM and HR feeds', 'Audit-ready evidence of every change'],
  },
  {
    n: 2, title: 'Role-based access control design', guide: 'roles',
    summary: 'Map job functions to permissions, give access by role instead of by person, and prove people can reach only what their job needs.',
    platforms: 'Entra ID groups, AWS IAM roles or Okta groups',
    steps: [
      ['Choose a platform', 'The role matrix models it; the same design maps to Entra groups or AWS permission sets.', 'roles', 'Role matrix'],
      ['Define job roles and the permissions each needs', 'Seven roles across Engineering, Sales, Finance, Revenue Cycle, IT and Security.', 'roles', 'Role matrix'],
      ['Create roles (groups / policies / assignments)', 'Toggle a cell to add or remove an entitlement from a role; members re-sync instantly.', 'roles', 'Role matrix'],
      ['Assign users and validate access', 'Use the Access checker to ask "can this person use this, and why?"', 'roles', 'Role matrix → Access checker'],
      ['Test edge cases (unauthorized access must fail)', 'Try Priya + Payment Approver: denied, with the SoD rule it would break.', 'roles', 'Role matrix → Access checker'],
      ['Find and remove excessive permissions', 'Fix C6 (privileged birthright) and review requests that conflict with SoD.', 'requests', 'Access requests'],
      ['Document role definitions and mappings', 'The role matrix is the mapping; export the controls write-up from the lab.', 'lab', 'Controls lab'],
    ],
    outcomes: ['Scalable RBAC models', 'Job function → permission mapping', 'Less access sprawl and privilege creep', 'Structured access an auditor can follow'],
  },
  {
    n: 3, title: 'Single sign-on and federation', guide: 'sso',
    summary: 'Make an application trust an identity provider instead of keeping its own passwords, using OpenID Connect (or SAML), and validate the whole sign-in flow.',
    platforms: 'Entra ID or Okta Developer, with a test app',
    steps: [
      ['Create an identity provider tenant', 'Two are running: the built-in OpenID provider and Keycloak.', 'sso', 'Single sign-on'],
      ['Deploy a test app that supports SAML or OIDC', 'This console is the app (an OIDC relying party).', 'sso', 'Single sign-on'],
      ['Configure federation and exchange metadata', 'Read the discovery document and JWKS on the Protocol reference card; SAML assertion example alongside.', 'sso', 'Single sign-on → Protocol reference'],
      ['Create test users and assign app access', 'Demo users and their groups are on MFA & Conditional Access.', 'mfa', 'MFA & Conditional Access'],
      ['Validate login flows and token assertions', 'Sign in from the top bar, then read every claim in the Token inspector.', 'sso', 'Single sign-on → Token inspector'],
      ['Troubleshoot with logs and browser tools', 'Failed and blocked sign-ins land in the sign-in log with the reason.', 'monitoring', 'Identity threat detection'],
      ['Document the SSO architecture and flow', 'Play the PKCE sequence diagram; screenshot it for your portfolio.', 'sso', 'Single sign-on → Flow diagram'],
    ],
    outcomes: ['SAML and OpenID Connect flows', 'Secure federation (PKCE, state, nonce, signature checks)', 'Troubleshooting authentication', 'Fewer passwords through central identity'],
  },
  {
    n: 4, title: 'Multi-factor authentication deployment', guide: 'mfa',
    summary: 'Turn on MFA, write the policies that decide when it is required, and prove it stops sign-ins even when the password is known.',
    platforms: 'Entra ID (Conditional Access) or Okta (authentication policies)',
    steps: [
      ['Enable MFA', 'TOTP is built into the IdP; admins always need it (CA001).', 'mfa', 'MFA & Conditional Access'],
      ['Configure authentication / Conditional Access policies', 'Seven policies; switch any between On, Report-only and Off.', 'mfa', 'MFA & Conditional Access'],
      ['Enroll users with an authenticator app', 'Sign in as sofia.alvarez on an unmanaged device: you are made to scan a QR code.', 'sso', 'Single sign-on → Sign in'],
      ['Test successful and failed sign-ins', 'Wrong codes are denied; five bad passwords trigger smart lockout.', 'sso', 'Single sign-on → Sign in'],
      ['Simulate risky sign-ins (new device or location)', 'Use What If, or pick Lagos / Moscow / the Tor exit on the sign-in page.', 'mfa', 'MFA & Conditional Access → What If'],
      ['Review authentication logs', 'Every attempt with its result, MFA method, risk and policies.', 'monitoring', 'Identity threat detection → Sign-in log'],
      ['Document policy design and outcomes', 'Fix C15 and C16 and keep the before/after.', 'lab', 'Controls lab'],
    ],
    outcomes: ['Deploying and enforcing MFA', 'Conditional Access and risk-based step-up', 'Zero trust sign-in decisions', 'Validating policy through logs'],
  },
  {
    n: 5, title: 'Privileged access management fundamentals', guide: 'pam',
    summary: 'Keep admin rights away from everyday accounts, store shared admin credentials in a vault, require MFA for privileged actions, and log all of it.',
    platforms: 'Entra PIM, plus a vault (Bitwarden / 1Password for a lab, CyberArk or Delinea trials)',
    steps: [
      ['Separate standard and admin accounts', 'Admin credentials live as separate accounts (e.g. CORP\\adm-yali) in the vault, not on the daily user.', 'vault', 'Credential vault'],
      ['Restrict admin access by role or group', 'Admin rights are eligibility, not birthright; check C6.', 'pam', 'Just-in-time access'],
      ['Store privileged credentials in a vault', 'AES-256-GCM vault with fingerprints only, never plaintext in lists.', 'vault', 'Credential vault'],
      ['Enforce MFA for privileged actions', 'Vault checkout demands a fresh one-time code even when signed in.', 'vault', 'Credential vault → Check out'],
      ['Test elevation and access boundaries', 'Activate ServiceNow admin for Yusuf with a ticket; watch it expire; try checkout without it.', 'pam', 'Just-in-time access'],
      ['Review logs of privileged activity', 'pam.* and vault.* events in the audit log; review the break-glass session (C9).', 'audit', 'Audit log'],
      ['Document privileged workflows and controls', 'Rotate the overdue root credential (C17) and note the evidence.', 'lab', 'Controls lab'],
    ],
    outcomes: ['Risks of privileged accounts', 'Least privilege for admins (zero standing privilege)', 'Securing credentials and elevation', 'Auditing privileged activity'],
  },
  {
    n: 6, title: 'Access reviews and audit readiness', guide: 'certifications',
    summary: 'Prove permissions are still right: have managers recertify access, remove what is excessive, dormant or orphaned, and keep the evidence.',
    platforms: 'Entra ID Access Reviews, or exports reviewed in a spreadsheet',
    steps: [
      ['Export users and permissions', 'iamctl.py report, or the CSV export on Access reviews.', 'automation', 'Automation'],
      ['Review access against job roles', 'Run a campaign; managers decide keep or revoke per item.', 'certifications', 'Access reviews'],
      ['Find excessive, dormant or unnecessary access', 'Dormant access and reconciliation (orphans, rogue accounts).', 'risk', 'Risk & reconciliation'],
      ['Remove or adjust access', 'Revoke from the review, or remediate accounts in reconciliation.', 'risk', 'Risk & reconciliation'],
      ['Capture before and after evidence', 'The controls score and findings change live; the audit log keeps every decision.', 'lab', 'Controls lab'],
      ['Write a short access review report', 'Download the audit write-up from the Controls lab.', 'lab', 'Controls lab'],
      ['Store documentation for audit', 'CSV evidence + write-up; keep them with your portfolio screenshots.', 'certifications', 'Access reviews'],
    ],
    outcomes: ['Compliance through access governance', 'Finding and fixing excessive access', 'Audit-friendly documentation', 'How IAM maps to SOX, HIPAA and NIST'],
  },
  {
    n: 7, title: 'Cloud IAM policy design (AWS or Azure)', guide: 'cloud',
    summary: 'Write least-privilege cloud policies, attach them to identities, and test them so only intended actions succeed.',
    platforms: 'AWS free tier (IAM + policy simulator) or Azure (RBAC + PIM)',
    steps: [
      ['Create a free cloud account', 'The tenant models an AWS account (111122223333) and an Azure management-group hierarchy.', 'cloud', 'Cloud IAM'],
      ['Define roles and needed permissions', 'Developer, data analyst, IAM engineer, CI service account.', 'cloud', 'Cloud IAM → AWS policies'],
      ['Write custom least-privilege policies', 'Edit JSON policies; the linter flags wildcards, PassRole on *, missing MFA conditions.', 'cloud', 'Cloud IAM → AWS policies'],
      ['Attach policies to users, groups or roles', 'Each policy shows its principals; one principal has a permissions boundary.', 'cloud', 'Cloud IAM → AWS policies'],
      ['Test with a policy simulator', 'Run scenarios: allowed, explicit deny, implicit deny, boundary deny.', 'cloud', 'Cloud IAM → Policy simulator'],
      ['Remove over-permissive rules', 'Load the least-privilege fix for LegacyDeployFullAccess and IAMOperations (C18, C19).', 'cloud', 'Cloud IAM → AWS policies'],
      ['Document design decisions and test results', 'Screenshot simulator traces before and after.', 'cloud', 'Cloud IAM → Policy simulator'],
    ],
    outcomes: ['Least-privilege cloud policies', 'Cloud authorization models (deny wins, boundaries, scopes)', 'Smaller attack surface', 'Safe permission testing'],
  },
  {
    n: 8, title: 'Identity monitoring and anomaly detection', guide: 'monitoring',
    summary: 'Read sign-in logs like an analyst: spot spraying, guessing, impossible travel and MFA bombing, then investigate and respond.',
    platforms: 'Entra sign-in logs + Microsoft Sentinel (KQL), or Okta System Log',
    steps: [
      ['Turn on identity and authentication logging', 'Every sign-in to the built-in IdP is logged, next to a week of history.', 'monitoring', 'Identity threat detection'],
      ['Export or forward logs to an analysis tool', 'Export the sign-in log as CSV; each alert includes the KQL for Sentinel.', 'monitoring', 'Identity threat detection → Export CSV'],
      ['Review successful and failed sign-ins', 'Filter the log by result, user, IP or app.', 'monitoring', 'Identity threat detection → Sign-in log'],
      ['Spot repeated failures and unusual locations', 'Seven detection rules: spray, brute force, impossible travel, MFA fatigue and more.', 'monitoring', 'Identity threat detection → Alerts'],
      ['Correlate across users and time', 'The timeline shows spikes; alerts link all evidence events.', 'monitoring', 'Identity threat detection'],
      ['Flag suspicious behaviour for investigation', 'Triage an alert as investigating or closed, with notes.', 'monitoring', 'Identity threat detection → Triage'],
      ['Document findings and response', 'Block the IP, revoke sessions or reset MFA; C20 tracks untriaged alerts.', 'lab', 'Controls lab'],
    ],
    outcomes: ['Analysing authentication logs', 'Detecting abnormal access', 'Identity threat detection (MITRE ATT&CK)', 'Linking IAM to security operations'],
  },
  {
    n: 9, title: 'Open-source IAM deployment (Keycloak)', guide: 'keycloak',
    summary: 'Run your own identity provider to see how one works inside: realms, users, roles, clients, flows, keys and events.',
    platforms: 'Keycloak in Docker or on a server (here: keycloak.assafwahinc.com)',
    steps: [
      ['Deploy Keycloak', 'Running on Coolify at keycloak.assafwahinc.com; docker compose --profile keycloak for local.', 'sso', 'Single sign-on → Keycloak'],
      ['Create realms, users and roles', 'Realm "assafwah" as code: demo users, groups, realm roles.', 'sso', 'Single sign-on → Keycloak'],
      ['Configure authentication and authorization', 'TOTP required action, brute-force lockout, password policy, short tokens.', 'sso', 'Single sign-on → Keycloak'],
      ['Integrate an app over SAML or OIDC', 'IAM Projects is an OIDC client; a SAML test client is included in the realm file.', 'sso', 'Single sign-on → Keycloak'],
      ['Test login and access end to end', 'Top bar → Sign in → Keycloak, then inspect the Keycloak token.', 'sso', 'Single sign-on'],
      ['Review authentication and access logs', 'Keycloak admin → Events (login and admin events are on).', 'sso', 'Single sign-on → Keycloak'],
      ['Document architecture and configuration', 'docs/KEYCLOAK.md and the realm JSON in the repo.', 'sso', 'Single sign-on → Keycloak'],
    ],
    outcomes: ['How an IAM platform is built', 'Central user, role and access management', 'SAML and OIDC integrations', 'Vendor-neutral IAM experience'],
  },
  {
    n: 10, title: 'IAM automation with scripting', guide: 'automation',
    summary: 'Script routine identity work: provisioning, deprovisioning and access reports through APIs, safely and repeatably.',
    platforms: 'Python or PowerShell with Microsoft Graph, Okta API or SCIM',
    steps: [
      ['Pick Python or PowerShell', 'Both are in backend/scripts/: iamctl.py and IamCtl.ps1.', 'automation', 'Automation → The scripts'],
      ['Connect to the IAM platform\'s API', 'Generate a SCIM token; the scripts use SCIM 2.0 and the REST API.', 'scim', 'SCIM 2.0 provisioning'],
      ['Script user creation and removal', 'iamctl.py sync (joiners, leavers) and offboard.', 'automation', 'Automation'],
      ['Automate role / group assignment from input data', 'Movers are applied by changing group membership from the HR CSV.', 'automation', 'Automation → HR feed'],
      ['Generate access reports (CSV or JSON)', 'iamctl.py report and dormant; IamCtl.ps1 -Report.', 'automation', 'Automation → The scripts'],
      ['Test safely with sample users', 'Dry run first, in the browser or with the CLI; nothing changes until Apply.', 'automation', 'Automation → Dry run'],
      ['Document the automation', 'Audit entries say "via hr-feed"; copy the example run for your portfolio.', 'audit', 'Audit log'],
    ],
    outcomes: ['Automating IAM workflows', 'Using IAM APIs securely (scoped tokens)', 'Less manual work, fewer mistakes', 'Scalable identity operations'],
  },
]

export function mentorPrompt(lab) {
  const steps = lab.steps.map(([s], i) => `${i + 1}. ${s}`).join('\n')
  return `Act as a senior IAM engineer and my mentor. Walk me through this hands-on lab step by step:

PROJECT: ${lab.title}
GOAL: ${lab.summary}
SUGGESTED PLATFORM: ${lab.platforms}

Steps to cover:
${steps}

For every step, give me:
- environment setup and any tools to install
- the exact configuration (portal clicks, plus CLI / PowerShell / Python where it helps)
- the policies, roles or groups to create, with real examples
- test cases that prove access works and that unauthorized access fails (expected allow / deny)
- which logs to check and what I should see in them
- how to document it for my portfolio: screenshots to take, a short write-up, a STAR interview story and two resume bullets

Ask me which platform and free tier I am using before you start, then go one step at a time and wait for me to confirm before moving on.`
}

export const MASTER_PROMPT = `Act as a senior IAM engineer and career mentor. I am preparing for an entry-level IAM analyst role and building a hands-on portfolio. I will paste one lab at a time. For each lab: ask which platform I'm using (Entra ID, Okta, AWS, Azure or Keycloak), then walk me through environment setup, tools, configuration, policies to create, test cases to validate access, logs to review, and how to document the results for my resume. Keep each step short, wait for me to confirm before continuing, and point out common mistakes.`

export const HOW_TO = [
  ['Sign in', 'Use Sign in (top right). The built-in IdP users share the password Demo!2026 and the demo authenticator shows their codes. Keycloak demo users use Demo!2026-Keycloak.'],
  ['Change anything', 'The whole tenant is a sandbox: approve, revoke, toggle policies, edit cloud policies, apply HR feeds. Nothing connects to real systems.'],
  ['Start over', 'Security posture → Reset demo restores the seed data and its twelve audit findings.'],
  ['See your impact', 'The Controls lab re-runs 20 controls after every change; the audit log shows who did what.'],
  ['Fair use', 'Writes and sign-in attempts are rate limited per visitor, and the tenant has size caps. If you hit one, wait a moment or reset.'],
  ['Data', 'All people, companies and IP addresses are fictional. Product names only label the type of system being simulated.'],
]
