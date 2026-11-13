# IAM Projects: an identity governance platform, built and audited

**Live demo: [iam.assafwahinc.com](https://iam.assafwahinc.com)** · Go 1.24 (stdlib only) · React 18 · Tailwind CSS 4 · Preline UI

A working Identity & Access Management platform that does the real jobs of an IAM analyst and engineer: identity lifecycle with **SCIM 2.0**, **RBAC with segregation of duties**, **SSO through its own OpenID Connect provider and Keycloak**, **MFA and Conditional Access**, **just-in-time access with a credential vault**, **access certifications**, **AWS and Azure least-privilege policies**, **identity threat detection** and **Python/PowerShell automation**. Every control is a testable assertion over live state, mapped to **NIST SP 800-53 r5, SOX ITGC, HIPAA and CIS**.

**New here? Open the [Project guide](https://iam.assafwahinc.com/#guide).** It maps the 10 standard IAM analyst projects to the live modules, with screenshots, how each was built, the same steps on Entra ID / Okta / AWS, STAR interview stories and resume bullets.

![Security posture overview](docs/screenshots/overview.jpg)

> All people and data are fictional. Product names (Workday, Entra ID, Epic…) only label the *type* of system being simulated; nothing connects to real services.

## The 10 IAM analyst projects

| # | Project | Live module | Key skills |
|---|---|---|---|
| 1 | User lifecycle management | [Joiner · Mover · Leaver](https://iam.assafwahinc.com/#jml), [SCIM 2.0](https://iam.assafwahinc.com/#scim) | JML, birthright RBAC, SCIM 2.0, deprovisioning |
| 2 | Role-based access control | [Role matrix](https://iam.assafwahinc.com/#roles), [Access requests](https://iam.assafwahinc.com/#requests) | RBAC, SoD, request & approval |
| 3 | SSO & federation | [Single sign-on](https://iam.assafwahinc.com/#sso) | OIDC, OAuth 2.0 + PKCE, JWT/JWKS, SAML |
| 4 | MFA deployment | [MFA & Conditional Access](https://iam.assafwahinc.com/#mfa) | Conditional Access, TOTP, sign-in risk, legacy-auth block |
| 5 | Privileged access management | [Just-in-time access](https://iam.assafwahinc.com/#pam), [Credential vault](https://iam.assafwahinc.com/#vault) | JIT, break-glass, AES-GCM vault, step-up MFA, rotation |
| 6 | Access reviews & audit readiness | [Access reviews](https://iam.assafwahinc.com/#certifications), [Controls lab](https://iam.assafwahinc.com/#lab) | UAR campaigns, reconciliation, evidence |
| 7 | Cloud IAM policy design | [Cloud IAM](https://iam.assafwahinc.com/#cloud) | AWS policies, permissions boundaries, simulator, Azure RBAC + PIM |
| 8 | Identity monitoring & anomaly detection | [Identity threat detection](https://iam.assafwahinc.com/#monitoring) | Spray, brute force, impossible travel, MFA fatigue, KQL, ATT&CK |
| 9 | Open-source IAM (Keycloak) | [Single sign-on → Keycloak](https://iam.assafwahinc.com/#sso), [`keycloak/`](keycloak/) | Realm as code, OIDC clients, roles, MFA, lockout |
| 10 | IAM automation with scripting | [Automation](https://iam.assafwahinc.com/#automation), [`scripts/`](scripts/) | Python, PowerShell, SCIM/REST, reporting |

| Single sign-on (signed in, token inspector) | MFA & Conditional Access (What If) |
|---|---|
| ![SSO](docs/screenshots/sso.jpg) | ![MFA](docs/screenshots/mfa.jpg) |
| **Identity threat detection** | **Cloud IAM policy simulator** |
| ![Monitoring](docs/screenshots/monitoring.jpg) | ![Cloud](docs/screenshots/cloud.jpg) |
| **Credential vault (step-up MFA checkout)** | **Project guide** |
| ![Vault](docs/screenshots/vault.jpg) | ![Guide](docs/screenshots/guide.jpg) |

## What it does

| Module | IAM capability | Engineering highlights |
|---|---|---|
| **Joiner · Mover · Leaver** | Lifecycle management, birthright RBAC | Movers lose all access outside the new role in the same event, including approved exceptions. Leavers end JIT sessions and cancel requests. Manual systems leave an orphan behind, as in real life. |
| **SCIM 2.0 provisioning** | Inbound provisioning from Entra ID / Okta | RFC 7643/7644 `/Users` and `/Groups`, filters (`eq ne co sw ew pr`, `and`), paging, PATCH, discovery endpoints, SCIM error schema. Handles Entra's `"Replace"` / `"False"` quirks. Bearer tokens are 192-bit, stored as SHA-256 hashes, compared in constant time. |
| **Access requests** | Request & approval, SoD | SoD is evaluated when a request is raised; approving a conflict requires a written risk acceptance. |
| **Access reviews** | User access certification (SOX UAR) | Campaigns by scope, routed to managers; revoke on non-response at close; birthright revocations become exclusions so role re-sync honours them; CSV evidence export. |
| **Just-in-time access** | PAM / zero standing privilege | Eligibility with per-assignment max duration, ticket validation (`CHG`/`INC`/`RITM`), a goroutine that sweeps expired grants, 60-minute break-glass with mandatory post-use review. Elevations that would break SoD are refused. |
| **Role matrix** | RBAC engineering | Toggling a cell re-syncs every member; the API refuses roles that would contain both sides of an SoD rule. |
| **Risk & reconciliation** | Orphan / rogue account detection, dormant access | Classifies target-system accounts as orphan, rogue or unowned service account with severity; remediation by disable, assign owner or adopt (refused if it would legitimise an SoD violation). Additive, explainable risk score per identity. |
| **Single sign-on** | OIDC provider + relying party, Keycloak | Discovery, JWKS, `/authorize`, `/token`, `/userinfo`; auth code + **PKCE S256**, state, nonce; RS256 ID tokens verified against JWKS; hosted sign-in page; the same client federates with Keycloak (`OIDC_ISSUER`). Signed-in users become the audit actor. |
| **MFA & Conditional Access** | Zero-trust sign-in policy | Seven Entra-style policies (on / report-only / off) on group, app, country, device, client app and risk; What-If tool; RFC 6238 TOTP with QR enrolment during sign-in; PBKDF2 passwords; smart lockout; break-glass exclusion. |
| **Credential vault** | PAM: vaulting and rotation | AES-256-GCM with the key outside the state file; checkout requires the entitlement right now, a reason and step-up TOTP; exclusive 30-minute checkout; rotation at check-in or expiry. |
| **Cloud IAM** | AWS + Azure least privilege | Policy engine (explicit deny, allow, permissions boundary, wildcards, MFA / IP / region conditions), linter, simulator with a statement-by-statement trace; Azure scope hierarchy with permanent vs PIM-eligible assignments. |
| **Identity threat detection** | Sign-in analytics | A week of sign-ins hiding six attacks plus live sign-ins; seven rules mapped to MITRE ATT&CK with KQL; triage that blocks IPs in Conditional Access, revokes sessions, resets MFA. |
| **Automation** | Scripting | HR-feed reconciliation (dry run → apply) in the browser and in [`scripts/iamctl.py`](scripts/iamctl.py) over SCIM; [`IamCtl.ps1`](scripts/IamCtl.ps1) for reports and offboarding. |
| **Controls lab** | Continuous control monitoring | 20 controls in [`server/lab.go`](server/lab.go) run after every change, with framework mapping and a downloadable audit write-up. |
| **Audit log** | Evidence | Every action with actor, target and reason; SCIM changes attributed to the token (`scim:<name>`); CSV export. |

The tenant ships with **twelve deliberate audit findings**: privileged birthright, a manual app, an unreviewed break-glass session, an orphan and an ownerless service account, rogue access that breaks SoD, a dormant Domain Admin, MFA left in report-only, legacy auth allowed, an unrotated root credential, a `*:*` cloud policy, cloud admin without MFA, and untriaged identity alerts. The lab walks you through fixing each one: **Problem → Assumptions → Build → Test → Improve**.

| Just-in-time access | Risk & reconciliation |
|---|---|
| ![JIT](docs/screenshots/jit-access.jpg) | ![Risk](docs/screenshots/risk.jpg) |
| **Access reviews** | **SCIM 2.0 console** |
| ![Reviews](docs/screenshots/access-reviews.jpg) | ![SCIM](docs/screenshots/scim-console.jpg) |

## Controls

| ID | Control | Frameworks |
|---|---|---|
| C1 | Terminated identities hold zero access | NIST AC-2(3) · SOX access removal · HIPAA 164.308(a)(3)(ii)(C) |
| C2 | Role-based access matches the current role | NIST AC-2, AC-6 · SOX access modification |
| C3 | Every extra grant has an approved request | NIST AC-2(1) · SOX provisioning approval |
| C4 | SoD conflicts have a documented risk acceptance | NIST AC-5 · SOX segregation of duties |
| C5 | No role bakes in an SoD conflict | NIST AC-5, AC-6 |
| C6 | Privileged access is requested, not birthright | NIST AC-6(5), AC-6(1) · CIS 5.4 |
| C7 | Every system is owned and automatically provisioned | NIST CM-8, AC-2(1) |
| C8 | Expired JIT elevations are removed | NIST AC-2(2), AC-6(5) |
| C9 | Every break-glass session is reviewed | NIST AC-2(4), AU-6 · HIPAA 164.312(a)(2)(ii) |
| C10 | No orphaned or ownerless accounts in target systems | NIST AC-2(3), IA-4 |
| C11 | No access granted directly in apps, outside IAM | NIST AC-2, AC-6 |
| C12 | Standing privileged access is used within 90 days | NIST AC-2(3), AC-6(7) |
| C13 | Access reviews finish by their due date | NIST AC-2(j) · SOX user access review · HIPAA 164.308(a)(4)(ii)(C) |
| C14 | Provisioning tokens are rotated within 90 days | NIST IA-5(1), SC-12 |
| C15 | MFA is enforced and registered for every user | NIST IA-2(1), IA-2(2) · HIPAA 164.312(d) · CIS 6.3, 6.5 |
| C16 | Legacy authentication protocols are blocked | NIST IA-2, AC-17 · CIS 4.8 |
| C17 | Vaulted admin passwords are rotated on schedule and after use | NIST IA-5(1), AC-2(4) · CIS 5.2 |
| C18 | No cloud identity has `Action:*` on `Resource:*` | NIST AC-6, AC-6(10) · CIS 6.8 |
| C19 | Sensitive cloud permissions require MFA or PIM | NIST AC-6(5), IA-2(1) · CIS 6.5 |
| C20 | High-severity identity alerts are triaged | NIST IR-4, SI-4, AU-6 · HIPAA 164.308(a)(6)(ii) |

Reasoning for each mapping: [`docs/CONTROLS.md`](docs/CONTROLS.md).

## Architecture

```mermaid
flowchart LR
  IdP["Entra ID / Okta<br/>(SCIM client)"] -- "Bearer token<br/>/scim/v2" --> API
  CLI["iamctl.py / IamCtl.ps1"] -- "SCIM + REST" --> API
  UI["React + Tailwind + Preline<br/>(hash-routed SPA)"] -- "/api (session or X-Actor)" --> API
  KC["Keycloak<br/>keycloak.assafwahinc.com"] -- "OIDC discovery + JWKS" --> API
  subgraph API["Go 1.24 · net/http · no third-party modules"]
    L[lifecycle.go<br/>joiner · mover · leaver] --- S[scim.go]
    L --- C[certify.go]
    L --- P[pam.go + vault.go]
    L --- R[risk.go<br/>score · reconcile]
    I[idp.go + sso.go<br/>OIDC provider + RP] --- CA[conditional.go]
    I --- M[signins.go<br/>detections]
    CL[cloudiam.go] --- K[lab.go<br/>20 controls]
    L --- H[hrfeed.go]
  end
  API --> Store[("JSON state<br/>atomic write, mutex<br/>/data volume")]
```

- **One lifecycle code path.** The JML screen and SCIM call the same functions, so an IdP push is governed exactly like an analyst action.
- **Controls as code.** Each control is a pure function over state, unit-tested in [`server/features_test.go`](server/features_test.go) and [`server/lifecycle_test.go`](server/lifecycle_test.go), including time travel through a swappable clock for JIT expiry and overdue reviews.
- **Storage.** A single JSON document behind a `Store` type (write to tmp, then rename, under a mutex). Swappable for Postgres without touching handlers.
- **Deploy.** A multi-stage Dockerfile builds a small Alpine image serving the API and SPA on port 8080, deployed on Coolify behind a Cloudflare tunnel.

## Try it in 2 minutes

1. Open the [**Controls lab**](https://iam.assafwahinc.com/#lab): 8 of 20 controls pass.
1. [**Single sign-on**](https://iam.assafwahinc.com/#sso) → *Sign in with Assafwah IdP* as `yusuf.ali` / `Demo!2026`, finish MFA with the demo authenticator, then read your own ID token.
2. **Risk & reconciliation → Reconciliation**: disable `mlee.clinical` (rogue Epic access that breaks sod-4). C11 improves and Marcus Lee's risk drops from 60.
3. **Just-in-time access**: review Yusuf's break-glass session (C9 passes), then activate his ServiceNow admin for 5 minutes and watch it expire.
4. **SCIM 2.0**: generate a token, *Create user*, then *Deactivate, Entra style*. Check the audit log for `scim:` entries.

Or from a terminal (after generating a token in the UI):

```bash
TOKEN=scim_...   BASE=https://iam.assafwahinc.com/scim/v2
curl -s "$BASE/Users?filter=userName%20eq%20%22omar.farouk@demo.local%22" -H "Authorization: Bearer $TOKEN"
curl -s -X PATCH "$BASE/Users/ID-1" -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/scim+json' \
  -d '{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"Replace","path":"active","value":"False"}]}'
```

More in [`docs/SCIM.md`](docs/SCIM.md). Reset the demo any time from the home screen or with `POST /api/reset`.

## Run locally

```bash
docker compose up --build                 # → http://localhost:8080

# or, for development
cd server && go test ./... && go run .    # API on :8080
cd web && npm install && npm run dev      # UI on :5173, proxies /api, /scim, /idp and /auth
```

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `8080` | HTTP port |
| `DATA_PATH` | `./data/iam.json` (`/data/iam.json` in Docker) | Persisted state |
| `STATIC_DIR` | `../web/dist` (`/app/web` in Docker) | Built SPA |
| `PUBLIC_URL` | derived from request | Fixes OIDC issuer and redirect URI, e.g. `https://iam.assafwahinc.com` |
| `SESSION_SECRET` | random per boot | HMAC key for session cookies (set it so sign-ins survive redeploys) |
| `VAULT_KEY` | `vault.key` beside the data file | Base64 32-byte AES key for the credential vault |
| `OIDC_ISSUER` · `OIDC_CLIENT_ID` · `OIDC_CLIENT_SECRET` | unset | Turn on *Sign in with Keycloak* ([`docs/KEYCLOAK.md`](docs/KEYCLOAK.md)) |

## API

<details>
<summary>REST endpoints (<code>/api</code>, actor from <code>X-Actor</code>)</summary>

| Method | Path | Purpose |
|---|---|---|
| GET | `/summary` · `/catalog` · `/identities` · `/identities/{id}/access` · `/systems` · `/audit` | Read models |
| POST | `/jml/joiner` · `/jml/mover` · `/jml/leaver` | Lifecycle events |
| GET/POST | `/requests` · `/requests/{id}/approve` · `/requests/{id}/deny` | Access requests (reason required for SoD) |
| PUT | `/roles/{id}/entitlements` | Edit role, re-sync members (SoD-blocked) |
| POST | `/grants/revoke` | Remove one grant with a reason |
| GET/POST | `/certifications` · `/certifications/{id}` · `/certifications/{id}/items/{itemId}` · `/certifications/{id}/close` | Access reviews |
| GET/POST | `/pam` · `/pam/elevate` · `/pam/sessions/{id}/revoke` · `/pam/sessions/{id}/review` | JIT and break-glass |
| POST/DELETE | `/pam/eligibility` | Manage eligibility |
| GET/POST | `/risk` · `/reconciliation` · `/reconciliation/accounts/{id}` | Risk scores, drift, remediation |
| GET/POST/DELETE | `/scim/tokens` · `/scim/tokens/{id}` | Provisioning credentials |
| GET | `/me` · `/idp/users` · POST `/idp/users/{u}/reset-mfa` · `/disable` · `/enable` | Session and directory |
| GET/PUT/POST/DELETE | `/ca` · `/ca/policies/{id}` · `/ca/whatif` · `/ca/blocked-ips/{ip}` | Conditional Access |
| GET/POST | `/monitoring` · `/monitoring/alerts/{id}` | Sign-in log, detections, triage |
| GET/POST | `/vault` · `/vault/{id}/checkout` · `/checkin` · `/rotate` | Credential vault |
| GET/PUT/POST | `/cloud` · `/cloud/policies/{id}` · `/cloud/simulate` · `/cloud/azure/{id}/make-eligible` | Cloud IAM |
| POST/GET | `/automation/hr-feed` · `/automation/hr-feed/sample` | HR feed dry run / apply |
| GET | `/lab/checks` | Run all 20 controls |
| POST | `/reset` | Reseed the demo tenant |

</details>

<details>
<summary>OpenID Connect provider (<code>/idp</code>) and relying party (<code>/auth</code>)</summary>

`GET /idp/.well-known/openid-configuration` · `GET /idp/jwks` · `GET /idp/authorize` · `POST /idp/token` · `GET /idp/userinfo` · `GET /auth/login[?idp=keycloak]` · `GET /auth/callback` · `POST /auth/logout`. Details in [`docs/IDENTITY-SECURITY.md`](docs/IDENTITY-SECURITY.md).

</details>

<details>
<summary>SCIM 2.0 endpoints (<code>/scim/v2</code>, bearer token)</summary>

`GET /ServiceProviderConfig` · `GET /ResourceTypes` · `GET /Schemas` · `GET|POST /Users` · `GET|PUT|PATCH|DELETE /Users/{id}` · `GET /Groups` · `GET|PATCH /Groups/{id}`

</details>

## Repository

```
server/    Go API: main.go (routes) · lifecycle.go · scim.go · certify.go · pam.go · risk.go · lab.go · seed.go · store.go
           idp.go · sso.go · jose.go · conditional.go · signins.go · vault.go · cloudiam.go · hrfeed.go · seed_security.go · *_test.go
web/       React SPA: src/App.jsx (shell + nav) · src/ui.jsx · src/components.jsx · src/guide.js · src/pages/*.jsx (one per module)
scripts/   iamctl.py (Python, stdlib only) · IamCtl.ps1 · hr_feed_sample.csv
keycloak/  realm-assafwah.json (realm as code: client, roles, MFA, lockout)
docs/      LAB-FRAMEWORK.md · CONTROLS.md · SCIM.md · IAM-CONCEPTS.md · DEPLOY-COOLIFY.md · IDENTITY-SECURITY.md · KEYCLOAK.md
```

## Ideas to extend

Require sign-in for approvals (approver group) · SAML IdP endpoint · passkeys / WebAuthn · Postgres storage · outbound SCIM connectors to real apps · approval workflows for high-risk JIT roles · peer-group outlier analysis for risk · OAuth 2.0 client credentials for SCIM.

---

Built by **Yassin**: IAM engineering, identity governance, and full-stack development.
