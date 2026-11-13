# Lab framework — practice the lifecycle, not perfection

Each module is worked through the same five steps. The goal is to show the *reasoning* an IAM analyst
uses, not to build a perfect product.

| Step | Question it answers |
|---|---|
| **Problem** | What goes wrong in a real company if nobody owns this? |
| **Assumptions** | What do we take as true so we can start building? |
| **Build** | What is the smallest thing that solves it? |
| **Test** | How do we prove it works — and which control check backs it up? |
| **Improve** | What would v2 look like in a real environment? |

The **Controls lab** page (`#lab`) shows all of this live, runs the control checks against the current
state, and exports a Markdown write-up (`iam-lab-writeup.md`) you can attach to a portfolio or interview.

---

## 1. JML workflow (`#jml`)

**Problem.** People join, change jobs and leave every week. Access must follow them on day one, on the
day of a move, and on the last day. Late or missed changes become orphaned accounts and access creep.

**Assumptions**
- HR (simulated Workday) is the source of truth for who works here and in what job.
- Each job maps to exactly one role that defines birthright access.
- A leaver loses everything the same day.

**Build**
- **Joiner** → create the identity, grant every entitlement in the role (`source: role`).
- **Mover** → grant new-role access, revoke anything not in the new role, *including* request-based extras.
- **Leaver** → set `terminated`, revoke all grants, auto-cancel open requests.

**Test**
1. Onboard a joiner. Their grants should equal the role exactly.
2. Move Omar Farouk from *Software Engineer* to *Revenue Cycle Analyst*. `aws-dev` and `gh-member` must be revoked.
3. Terminate Yusuf Ali (who holds an extra `aws-admin` grant). Run **C1** and **C2**.

**Improve**
- Trigger JML from HR webhooks instead of a form.
- Pre-hire accounts that stay disabled until the start date.
- Mailbox retention and manager delegation for leavers.

**Controls:** C1 (leavers hold zero access), C2 (role access matches current role).

---

## 2. Access request (`#requests`)

**Problem.** Roles never cover everything. People need extra access, and someone accountable has to decide —
with a record an auditor can sample later.

**Assumptions**
- Every request needs a business justification.
- Approvers see SoD conflicts *before* they decide.
- A conflicting request can be approved only with a written risk acceptance.

**Build**
- The request form requires a justification; duplicates and already-held access are rejected (409).
- The SoD check runs against the person's current grants when the request is created.
- Approve → provision with `source: request`. Deny → nothing changes. Both are audited.

**Test**
1. Try to approve Priya Raman's `erp-approve` request with no reason. The API must refuse it (sod-2).
2. Approve it with a documented reason (owner, compensating control, expiry). Run **C4**.
3. Request an entitlement someone already has. Expect a 409.

**Improve**
- Two-step approval: manager, then system owner.
- Time-boxed privileged access with automatic expiry.
- Quarterly access certification campaigns.

**Controls:** C3 (every extra grant has an approved request), C4 (SoD conflicts have a risk acceptance).

---

## 3. Role matrix (`#roles`)

**Problem.** Roles drift. Someone adds "just one more" entitlement and suddenly every member holds admin.

**Assumptions**
- A role holds only what *everyone* in that job needs.
- Privileged entitlements are never birthright.
- A role must never contain both sides of an SoD rule.

**Build**
- A roles × entitlements grid. Toggling a cell re-syncs every active member (role-sourced grants only).
- Adding an entitlement that would complete an SoD pair inside the role is blocked by the server (409).

**Test**
1. Add *Vendor Master* to *AP Specialist*. It must be blocked by sod-1.
2. Look at **C6**: *Finance Manager* has *Payment Approver* as birthright. This is a deliberate seeded finding.
3. Remove it from the role and re-run the checks.

**Improve**
- Role mining from what people actually hold.
- Versioned roles with approval for role changes.
- A blast-radius preview before saving.

**Controls:** C5 (no role contains an SoD conflict), C6 (privileged access is never birthright).

---

## 4. System map (`#systems`)

**Problem.** You can't govern access to apps you don't know about, and you can't deprovision what isn't connected.

**Assumptions**
- Every app has a named owner.
- Apps should federate through the IdP (SAML/OIDC) and be provisioned by SCIM or API.
- Criticality drives how often access is reviewed.

**Build**
- An inventory with auth protocol, provisioning method, owner, criticality, user count and privileged-grant count.
- A flow view: HR source → IdP → directory → apps → cloud.

**Test**
1. **C7** flags *Epic EHR* as manually provisioned. This is a deliberate seeded finding.
2. Terminate someone and confirm user counts drop.

**Improve**
- Discover shadow IT from SSO logs and expense data.
- Replace manual apps with SCIM connectors.
- Track review status per app.

**Controls:** C7 (every system is owned and automatically provisioned).

---

## 5. SCIM 2.0 provisioning (`#scim`)

**Problem.** The IdP, not a person, should create and remove accounts. Every app that can't accept SCIM becomes a manual ticket.

**Assumptions**
- Users map to identities; Groups map to RBAC roles.
- The IdP authenticates with a long random bearer token.
- IdPs differ: Entra ID sends `"Replace"` and `"False"` as strings.

**Build**
- RFC 7644 `/Users` and `/Groups` with filter, paging and PATCH; discovery endpoints; SCIM error schema.
- `active=false` or `DELETE` runs the leaver flow; a group add runs the mover flow.
- Tokens hashed with SHA-256, compared in constant time, revocable. See [`SCIM.md`](SCIM.md).

**Test**
1. Generate a token, `POST /Users` with `groups:[{"value":"r-ap"}]`, and confirm birthright grants.
2. `PATCH active "False"` Entra-style; C1 still passes.
3. Revoke the token; the next call returns 401.

**Improve:** OAuth 2.0 client credentials, ETags, a bulk endpoint for initial loads.

**Controls:** C14 (token rotation), C1.

---

## 6. Access reviews (`#certifications`)

**Problem.** Access accumulates. Auditors expect every in-scope grant to be re-justified periodically by someone accountable.

**Assumptions**
- The manager reviews their reports' access.
- A revoke must remove access, not just record an opinion.
- Silence is not approval.

**Build**
- Campaigns snapshot grants by scope: all, privileged, exceptions only, or a single app. JIT grants are excluded because they are reviewed per session.
- Revoking birthright records an *exclusion* so role re-syncs don't re-grant it (C2 honours it).
- Closing with *revoke on non-response* removes everything undecided. Export CSV evidence.

**Test**
1. In the Q4 privileged review, revoke Sofia Alvarez's Domain Admin (unused 210 days). C12 passes.
2. Launch an all-access campaign, decide a few items, and close it. Undecided items are revoked.

**Improve:** multi-level reviews (manager, then app owner), reminders and delegation, risk-triggered micro-certifications.

**Controls:** C13 (reviews finish on time).

---

## 7. Just-in-time privileged access (`#pam`)

**Problem.** Standing admin rights are the most valuable thing an attacker can steal, and most of the time nobody needs them.

**Assumptions**
- Admins are *eligible*, not assigned.
- Every activation has a ticket and a time limit.
- Emergencies happen, so break-glass exists, and it is reviewed afterwards.

**Build**
- Eligibility with a per-assignment maximum duration.
- Activation creates a `jit` grant with `expiresAt`; a goroutine sweeps expired grants every 15 seconds.
- Break-glass skips eligibility and ticket checks, is capped at 60 minutes, and is flagged until reviewed.
- Elevations that would complete an SoD pair are refused.

**Test**
1. Activate Yusuf Ali's ServiceNow Platform Admin for 5 minutes and watch it expire.
2. Try Omar Farouk's AWS admin: refused, because his birthright `aws-dev` plus `aws-admin` breaks sod-3.
3. Review the seeded break-glass session. C9 passes.

**Improve:** approval for high-risk roles, session recording, credential vaulting.

**Controls:** C8 (expiry enforced), C9 (break-glass reviewed), C6.

---

## 8. Risk & reconciliation (`#risk`)

**Problem.** IAM only knows what it granted. Accounts created directly in apps, and accounts that deprovisioning missed, are invisible without reconciliation.

**Assumptions**
- Target systems can be read, even when IAM can't write to them.
- Every account maps to an identity, or to an owner if it is a service account.
- Unused privilege is risk without benefit.

**Build**
- Classify target accounts as **orphan** (no HR match, or owner terminated), **rogue** (access the IAM never granted) or **unowned service**, with severity.
- Remediate by disable, assign owner, or adopt as a retro-approved request. Adoption is refused if it would legitimise an SoD violation.
- An additive risk score per identity where every point traces to a factor.

**Test**
1. Disable `mlee.clinical` (rogue Epic clinical access that breaks sod-4). Marcus Lee drops from 60.
2. Assign an owner to `svc-legacy-deploy`; disable `j.ortega` and `dbrooks-sales`. C10 and C11 pass.
3. Terminate Marcus Lee: his Epic account (a manual system) reappears as an orphan.

**Improve:** real read connectors, peer-group outlier analysis, feeding risk into review campaigns.

**Controls:** C10, C11, C12.

---

## The 14 control checks

`GET /api/lab/checks` runs every control in [`backend/lab.go`](../backend/lab.go) against the current state. The seed tenant starts at **8 / 14** on purpose. The full list, framework mapping and the seeded findings are in [`CONTROLS.md`](CONTROLS.md).

## Visuals on the Controls lab page

- **AuthN vs AuthZ.** Authentication proves who you are (SAML, OIDC, MFA). Authorization decides what you can do (roles, entitlements, policy). This platform is mostly AuthZ, fed by an IdP that does AuthN.
- **Policy binding.** Identity → role / request / JIT → entitlement. Every grant records its `source`, so provenance is always auditable.
- **Resource hierarchy.** Organization → system → entitlement. Least privilege lives at the bottom.
