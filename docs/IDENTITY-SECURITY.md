# Identity security modules

How projects 3, 4, 5, 7, 8 and 10 are built. All server code is Go standard library only.

## Built-in OpenID Connect provider (`backend/idp.go`, `backend/jose.go`)

| Endpoint | Purpose |
|---|---|
| `GET /idp/.well-known/openid-configuration` | Discovery |
| `GET /idp/jwks` | RSA-2048 public key (persisted in `idp-signing.pem` next to the data file) |
| `GET /idp/authorize` | Validates client, exact redirect URI, `response_type=code`, `openid` scope, **PKCE S256**; hands off to the hosted sign-in page `/#signin?txn=…` |
| `POST /idp/api/txn/{id}/password · /mfa · /enroll` | Hosted sign-in steps: PBKDF2-SHA256 password check, smart lockout, Conditional Access, TOTP, enrolment |
| `POST /idp/token` | Client secret (basic or post), single-use 60 s code, redirect URI match, PKCE verifier → RS256 `id_token` + `access_token` |
| `GET /idp/userinfo` | Bearer access token, verified |

The console is the relying party (`backend/sso.go`): `/auth/login` → state, nonce and PKCE verifier in an HMAC-signed HttpOnly cookie; `/auth/callback` checks state, redeems the code, verifies signature, `iss`, `aud`, `exp` and `nonce`, then issues an 8-hour session cookie. With `OIDC_ISSUER` set, the same code uses Keycloak's discovery and JWKS. A signed-in user is the `actor` on every audit entry. Revoking sessions (alert response, leaver, disabled user) invalidates cookies issued before that moment.

Demo users share the password `Demo!2026`. TOTP secrets are deterministic for the demo so the in-app virtual authenticator works after a reset; real deployments use `newTOTPSecret()`.

## Conditional Access (`backend/conditional.go`)

Policies have assignments (include / exclude groups, apps), conditions (client app, countries, outside trusted countries, blocked IP list, sign-in risk, device) and a grant (block or MFA). States: on, report-only, off. Evaluation: block > MFA > allow; report-only results are logged, not enforced. `POST /api/ca/whatif` evaluates without signing in.

## Sign-in log and detections (`backend/signins.go`)

| Rule | Logic | ATT&CK |
|---|---|---|
| D1 Password spray | One IP, failures against ≥5 accounts in 30 min | T1110.003 |
| D2 Brute force | One account, ≥8 failed/locked in 15 min (critical if later success from same IP) | T1110.001 |
| D3 Impossible travel | Consecutive successes, different countries, >500 km at >900 km/h; one alert per user per 24 h | T1078 |
| D4 MFA fatigue | ≥5 MFA denials in 30 min (critical if a later approval) | T1621 |
| D5 Legacy auth | Successful IMAP/POP/basic SMTP sign-in | T1078 |
| D6 No active HR record | Success by an account with no active identity, or after termination | T1078.003 |
| D7 Break-glass used | Any attempt by the emergency account | T1078.004 |

Triage (`POST /api/monitoring/alerts/{id}`) requires notes to close, and can block the IP (CA006), revoke sessions, reset MFA or disable the user.

## Credential vault (`backend/vault.go`)

AES-256-GCM, key from `VAULT_KEY` (base64, 32 bytes) or `vault.key` (0600) next to the data file, never inside `iam.json`. Checkout needs: an active identity that **currently holds** the entitlement (JIT or standing), a reason, and a fresh TOTP from that person's MFA method. Exclusive, 30 minutes, then rotated by the expiry sweeper; check-in rotates immediately.

## Cloud IAM (`backend/cloudiam.go`)

AWS evaluation subset: explicit Deny → implicit deny without an Allow → permissions boundary must also allow. `Action`/`NotAction`/`Resource` wildcards; `Bool`, `StringEquals`, `StringNotEquals`, `StringLike`, `IpAddress`, `NotIpAddress` on `aws:MultiFactorAuthPresent`, `aws:SourceIp`, `aws:RequestedRegion`. Not modelled: SCPs, resource-based policies, session policies. The linter flags `*:*`, service wildcards on `*`, `iam:PassRole` on `*`, Allow+NotAction and sensitive actions without MFA. Azure: role assignments by scope with permanent vs PIM-eligible.

## Automation (`backend/hrfeed.go`, `backend/scripts/`)

`POST /api/automation/hr-feed {csv, apply}` plans (and optionally applies) joiner / mover / update / leaver through the shared lifecycle functions. `backend/scripts/iamctl.py` does the same over the public SCIM API (`sync`, `report`, `dormant`, `offboard`); `backend/scripts/IamCtl.ps1` covers reporting and offboarding.

## Environment variables

| Variable | Purpose |
|---|---|
| `PUBLIC_URL` | Fixes the issuer and redirect URI (e.g. `https://iam.assafwahinc.com`) instead of deriving them from the request |
| `SESSION_SECRET` | HMAC key for session cookies; set it so sessions survive restarts |
| `IDP_CLIENT_SECRET` | Built-in IdP client secret (random per boot if unset) |
| `VAULT_KEY` | Vault encryption key (base64 32 bytes) |
| `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET` | Enable "Sign in with Keycloak" |
