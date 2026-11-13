# Keycloak (project 9): keycloak.assafwahinc.com

`keycloak/realm-assafwah.json` is the identity provider as code: realm `assafwah`, one OIDC client for IAM Projects, roles from groups, MFA and lockout. No secrets are in the file: Keycloak generates the client secret on import.

| Setting | Value | Why |
|---|---|---|
| Realm | `assafwah` | Its own tenant, separate from `master` (admin only) |
| Client | `iam-projects` | Confidential, authorization code only, **PKCE S256**, exact redirect URIs (`https://iam.assafwahinc.com/auth/callback`, `http://localhost:8080/auth/callback`), no password grant |
| Roles | `iam-admin`, `approver` | Granted through groups (`iam-admins`, `approvers`), so access follows membership |
| Groups mapper | `groups` claim in ID + access tokens | The console reads it, plus `realm_access.roles` |
| MFA | `CONFIGURE_TOTP` required action on every demo user | Enrol an authenticator at first sign-in |
| Brute force | 5 failures, wait up to 15 min | Same smart-lockout idea as the built-in IdP |
| Password policy | 12+ chars, upper, lower, digit, special, not username, history 5 | NIST 800-63B-aligned length |
| Tokens | access 15 min, SSO idle 30 min, refresh tokens rotated | Short-lived credentials |
| Events | login + admin events kept 30 days | Evidence for monitoring |

Demo users: `yusuf.ali` (iam-admins), `omar.farouk` (engineering, approvers), `sofia.alvarez` (service-desk). Password `Demo!2026-Keycloak`.

## Set it up on keycloak.assafwahinc.com (5 minutes)

1. **Secure the admin account first.** Sign in to the admin console, open *master* realm → Users → your admin → Credentials → reset to a long unique password, and add OTP for the admin (Credentials → Set up authenticator). A public Keycloak with a guessable admin password will be found by scanners.
2. **Import the realm.** Realm dropdown (top-left) → *Create realm* → *Browse* → `keycloak/realm-assafwah.json` → *Create*.
3. **Copy the client secret.** Realm `assafwah` → Clients → `iam-projects` → Credentials → copy *Client secret*.
4. **Tell IAM Projects about it.** Coolify → IAM Projects → Environment variables:

   | Variable | Value |
   |---|---|
   | `OIDC_ISSUER` | `https://keycloak.assafwahinc.com/realms/assafwah` |
   | `OIDC_CLIENT_ID` | `iam-projects` |
   | `OIDC_CLIENT_SECRET` | the secret from step 3 |
   | `PUBLIC_URL` | `https://iam.assafwahinc.com` |
   | `SESSION_SECRET` | `openssl rand -base64 32` |

   Redeploy. **Single sign-on → Sign in with Keycloak** is now enabled.
5. **Test:** sign in as `yusuf.ali` / `Demo!2026-Keycloak`, enrol TOTP, land back on the console signed in, and inspect the Keycloak ID token. Then fail five passwords for `omar.farouk` and check Realm → Events → User events for `LOGIN_ERROR` and the temporary lockout.

Check it from a terminal: `curl https://keycloak.assafwahinc.com/realms/assafwah/.well-known/openid-configuration` must return JSON whose `issuer` is exactly `https://keycloak.assafwahinc.com/realms/assafwah`. If it shows `http://` or an internal host, set `KC_HOSTNAME=https://keycloak.assafwahinc.com` and `KC_PROXY_HEADERS=xforwarded` on the Keycloak service.

## Production checklist

- `start` (not `start-dev`), PostgreSQL, `KC_HOSTNAME`, `KC_PROXY_HEADERS=xforwarded`, `KC_HTTP_ENABLED=true` behind Coolify's TLS proxy.
- Restrict `/admin` to your IP in the proxy if possible; never leave the bootstrap admin with a default password.
- Back up Postgres; export the realm after changes (`kc.sh export --realm assafwah --file realm.json`) and commit it without secrets.

## Run locally instead

```bash
docker compose --profile keycloak up -d keycloak     # http://localhost:8081, realm imported at start
# copy the iam-projects client secret from the local admin console, then:
cd server && OIDC_ISSUER=http://localhost:8081/realms/assafwah OIDC_CLIENT_ID=iam-projects OIDC_CLIENT_SECRET=<secret> go run .
```

Run the Go server on the host for local Keycloak: the token `iss` must match the URL the browser used (`localhost:8081`).

## What to screenshot for the portfolio

Realm settings → Security defenses (brute force) · Clients → iam-projects (PKCE, redirect URIs) · Users → yusuf.ali → Groups and Role mapping · Events → a failed and a successful login · the console's token inspector after signing in with Keycloak.
