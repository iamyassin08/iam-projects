# How each module maps to real IAM work

This lab simulates the systems an IAM team runs every day. The names (Workday, Entra ID, ServiceNow and
others) only label the *type* of system. Nothing here connects to a real service.

## Core vocabulary

| Term | In this lab | In real life |
|---|---|---|
| **Identity** | A row in the directory (`Identity`) | A worker record from HR, mirrored into the IdP and directory |
| **Entitlement** | A single permission in one system (`Entitlement`) | An AD group, an app role, a license, an AWS permission set |
| **Role** | A named bundle of entitlements (`Role`) | A business role in an IGA tool (SailPoint, Saviynt, Entra ID Governance) |
| **Grant** | An identity holding an entitlement, with `source` = `role` or `request` | An assignment, with provenance for audits |
| **Birthright access** | Everything in the identity's role | Access granted automatically on hire |
| **SoD rule** | Two entitlements nobody should hold together | Toxic-combination policies in ERP, finance and healthcare systems |
| **Privileged** | A flag on an entitlement | Admin rights, usually handled by PAM (CyberArk, Entra PIM) |

## JML → identity lifecycle management

- **Joiner** = an HR hire event triggers account creation and birthright provisioning. In real life this is a
  Workday → Entra ID inbound provisioning job, followed by SCIM pushes to SaaS apps.
- **Mover** = a job change. The hardest lifecycle event. Most access creep comes from movers who keep their old access.
  This lab revokes anything outside the new role, including request-based access, which forces re-requesting.
- **Leaver** = a termination. The account is disabled and all access revoked the same day. Open requests are cancelled.
  Auditors test this by sampling terminations and checking each system.

## Access requests → access governance

- Requests carry a **justification**, an **approver** and a **decision reason**. That is the evidence trail.
- **SoD** is checked at request time, so approvers make an informed decision.
- Approving a conflict requires a **risk acceptance**, which mirrors how real SoD exceptions are owned and documented.
- Next steps in a real program: manager → owner approval chains, time-boxed access, and periodic **access certifications**.

## Role matrix → RBAC and least privilege

- Roles should contain only what *every* member needs. Everything else is requested.
- Changing a role changes access for all members at once. That blast radius is why role changes need governance.
- The server blocks a role that would contain both sides of an SoD rule. Check C6 flags privileged birthright access.

## System map → application onboarding

- **Auth protocol**: how users sign in. SAML and OIDC federate through the IdP; LDAP and Kerberos are directory-based.
- **Provisioning**: how accounts get created and removed. SCIM or API is automatic. *Manual* means a ticket, which is where leavers get missed.
- **Owner** and **criticality** decide who approves access and how often it is reviewed.

## Audit log → evidence

Every grant, revoke, decision and role change is written with actor, action, target and detail. The log can
be filtered and exported to CSV. This is what you hand an auditor for an access review or a SOX/HIPAA sample.

## Skills this demonstrates

- Lifecycle automation (JML) and why the mover case matters most.
- Access request design with SoD-aware approvals.
- RBAC role design and least privilege.
- Application inventory, federation and provisioning methods.
- Writing controls as testable assertions (`server/lab.go`).
