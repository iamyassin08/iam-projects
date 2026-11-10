# Controls and framework mapping

Each control is a read-only function over the current state (`runChecks` in [`server/lab.go`](../server/lab.go)). It runs on every request to `/api/lab/checks` and is unit-tested. A control passes when it produces no findings.

Mappings use NIST SP 800-53 Rev. 5 control identifiers, SOX IT general control (ITGC) areas, the HIPAA Security Rule (45 CFR 164) and CIS Controls v8. They show which requirement each check produces evidence for. They are not a claim of compliance.

| ID | Control | Why it matters | Mapping and reasoning |
|---|---|---|---|
| C1 | Terminated identities hold zero access | Orphaned access after termination is the most common audit finding. | **AC-2(3)** disable accounts; **SOX** access removal; **HIPAA 164.308(a)(3)(ii)(C)** termination procedures. |
| C2 | Role-based access matches the current role | Access creep comes from movers who keep old access. | **AC-2** account management (modification); **AC-6** least privilege. Reviewer exclusions from certifications are honoured. |
| C3 | Every extra grant has an approved request | Auditors sample grants and ask who approved them. | **AC-2(1)** automated account management with authorization; **SOX** provisioning approval. |
| C4 | SoD conflicts have a documented risk acceptance | Toxic combinations may exist only as owned exceptions. | **AC-5** separation of duties; **SOX** SoD. |
| C5 | No role bakes in an SoD conflict | A toxic role makes every member a finding. | **AC-5**, **AC-6**. |
| C6 | Privileged access is requested, not birthright | Admin rights need a person, a reason and an expiry. | **AC-6(5)** privileged accounts; **AC-6(1)** authorize access to security functions; **CIS 5.4** restrict admin privileges. |
| C7 | Every system is owned and automatically provisioned | Manual apps are where deprovisioning gets missed. | **CM-8** system component inventory; **AC-2(1)** automated account management. |
| C8 | Expired JIT elevations are removed | Time-boxed access only works if expiry is enforced. | **AC-2(2)** automated temporary account management; **AC-6(5)**. |
| C9 | Every break-glass session is reviewed | Emergency access bypasses approval, so it is reviewed afterwards. | **AC-2(4)** automated audit actions; **AU-6** audit record review; **HIPAA 164.312(a)(2)(ii)** emergency access procedure. |
| C10 | No orphaned or ownerless accounts in target systems | Reconciliation finds what deprovisioning missed. | **AC-2(3)**; **IA-4** identifier management (every account traces to an owner). |
| C11 | No access granted directly in apps, outside IAM | If IAM did not grant it, nobody approved it. | **AC-2** account management; **AC-6**; **SOX** unauthorized access. |
| C12 | Standing privileged access is used within 90 days | Unused admin rights are risk without benefit. | **AC-2(3)** disable inactive accounts; **AC-6(7)** review of user privileges. |
| C13 | Access reviews finish by their due date | An overdue review is a missed control for the period. | **AC-2(j)** periodic account review; **SOX** user access review; **HIPAA 164.308(a)(4)(ii)(C)** access establishment and modification. |
| C14 | Provisioning tokens are rotated within 90 days | A long-lived bearer token is a standing credential to create and delete users. | **IA-5(1)** authenticator management; **SC-12** key management. |

## Seeded findings

The demo tenant starts at **8 / 14**. Each failing control has a remediation path in the UI:

| Control | Seeded cause | Fix in the app |
|---|---|---|
| C6 | Finance Manager role grants Payment Approver as birthright | Role matrix: remove it; give Grace JIT eligibility instead |
| C7 | Epic EHR is provisioned manually | Structural; document as a known exception (stays failing by design) |
| C9 | Yusuf Ali's break-glass Domain Admin session was never reviewed | Just-in-time access → *Review now* |
| C10 | `j.ortega` in NetSuite (never in HR) and `svc-legacy-deploy` in AWS (no owner) | Reconciliation → *Disable* / *Owner* |
| C11 | `dbrooks-sales` is a GitHub Org Owner and `mlee.clinical` holds Epic clinical access, both created outside IAM | Reconciliation → *Disable* (adopting `mlee.clinical` is refused: it would legitimise sod-4) |
| C12 | Sofia Alvarez's Domain Admin is unused for 210 days | Dormant access → *Revoke*, or revoke it in the Q4 access review |
