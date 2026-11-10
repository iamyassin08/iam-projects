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

The **Lab guide** page (`#lab`) shows all of this live, runs the control checks against the current
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

## The 7 control checks

`GET /api/lab/checks` (implemented in `server/lab.go`) runs read-only assertions over the current state:

| ID | Control | Module |
|---|---|---|
| C1 | Terminated identities hold zero access | JML |
| C2 | Role-based access matches the current role | JML |
| C3 | Every extra grant has an approved request | Requests |
| C4 | SoD conflicts have a documented risk acceptance | Requests |
| C5 | No role bakes in an SoD conflict | Roles |
| C6 | Privileged access is requested, not birthright | Roles |
| C7 | Every system is owned and automatically provisioned | Systems |

The seed tenant starts at **5/7 passing** on purpose. C6 and C7 are findings for you to fix.

## Visuals on the Lab page

- **AuthN vs AuthZ.** Authentication proves who you are (SAML, OIDC, MFA). Authorization decides what you can do (roles, entitlements, policies). This lab is mostly AuthZ.
- **Policy binding.** Identity → role → entitlement. A grant's `source` is either `role` (birthright) or `request`.
- **Resource hierarchy.** Organization → system → entitlement. Permissions live on resources inside systems.
