# SCIM 2.0 service provider

IAM Projects exposes a SCIM 2.0 API ([RFC 7643](https://www.rfc-editor.org/rfc/rfc7643) schema, [RFC 7644](https://www.rfc-editor.org/rfc/rfc7644) protocol) so an identity provider can provision identities into it. The implementation is [`backend/scim.go`](../backend/scim.go); tests are in [`backend/features_test.go`](../backend/features_test.go).

**Base URL:** `https://iam.assafwahinc.com/scim/v2` (or `http://localhost:8080/scim/v2`)

## Mapping to the IAM model

| SCIM | IAM Projects | Lifecycle effect |
|---|---|---|
| `POST /Users` | New identity | **Joiner**: role from `groups[0].value` grants birthright access |
| `PATCH /Users/{id}` `active=false`, or `DELETE` | Identity terminated | **Leaver**: revoke all access, end JIT sessions, cancel requests |
| `PATCH /Users/{id}` `active=true` | Identity re-activated | **Rehire**: birthright restored |
| `PATCH /Groups/{roleId}` add member | Identity moved into role | **Mover**: access outside the new role revoked |
| `PATCH /Groups/{roleId}` remove member | Identity has no role | Role access removed |
| `userName`, `emails[primary]` | `email` | |
| `externalId` | `externalId` (e.g. Workday worker ID) | |
| `enterprise:department`, `enterprise:manager` | `department`, `manager` | |

Every SCIM change runs through the same lifecycle functions as the UI and is written to the audit log as `scim:<token name>`.

## Authentication

Create a token in the UI (**SCIM 2.0 provisioning → Generate token**) or with `POST /api/scim/tokens {"name": "..."}`. Tokens are 192-bit random values (`scim_` plus 48 hex characters). Only a SHA-256 hash is persisted, comparison is constant-time, and revoked tokens get `401` with `WWW-Authenticate: Bearer`. Control **C14** fails when an active token is older than 90 days.

## Supported features

- Discovery: `/ServiceProviderConfig`, `/ResourceTypes`, `/Schemas`
- Filtering: `eq`, `ne`, `co`, `sw`, `ew`, `pr`, joined with `and`, on `userName`, `externalId`, `displayName`, `name.givenName`, `name.familyName`, `title`, `active`, `emails.value`, `department`, `groups.value`. Anything else returns `400 invalidFilter`.
- Paging: `startIndex` (1-based) and `count` (max 200)
- PATCH: `add`, `replace`, `remove`, with or without `path`. Op names are case-insensitive and booleans may be strings, because Entra ID sends `{"op":"Replace","path":"active","value":"False"}`.
- Errors use `urn:ietf:params:scim:api:messages:2.0:Error` with `scimType` (`uniqueness`, `invalidFilter`, `invalidSyntax`, `invalidValue`).
- Not supported: bulk, sort, ETags, password change, creating groups (roles are designed in the role matrix).

## Examples

```bash
TOKEN=scim_...; BASE=https://iam.assafwahinc.com/scim/v2
H=(-H "Authorization: Bearer $TOKEN" -H "Content-Type: application/scim+json")

# Joiner
curl -s "${H[@]}" -X POST "$BASE/Users" -d '{
  "schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
  "userName":"nadia.karim@demo.local","externalId":"WD-20991",
  "name":{"givenName":"Nadia","familyName":"Karim"},"title":"AP Specialist","active":true,
  "groups":[{"value":"r-ap"}],
  "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"department":"Finance","manager":{"displayName":"Grace Kim"}}}'

# Lookup the way Entra ID does before creating
curl -s "${H[@]}" "$BASE/Users?filter=userName%20eq%20%22nadia.karim@demo.local%22"

# Mover: put the user in the Account Executive role
curl -s "${H[@]}" -X PATCH "$BASE/Groups/r-sales" -d '{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
  "Operations":[{"op":"add","path":"members","value":[{"value":"ID-123"}]}]}'

# Leaver, Entra ID style
curl -s "${H[@]}" -X PATCH "$BASE/Users/ID-123" -d '{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
  "Operations":[{"op":"Replace","path":"active","value":"False"}]}'
```

## Connecting Microsoft Entra ID

1. Entra admin center → Enterprise applications → New application → *Create your own* (non-gallery).
2. Provisioning → Automatic. **Tenant URL** = the base URL above; **Secret token** = a token from the console. *Test connection* calls `GET /Users?filter=userName eq "<random>"`, which returns an empty list.
3. Attribute mappings: `userPrincipalName → userName`, `objectId → externalId`, `jobTitle → title`, `department → enterprise:department`, `manager → enterprise:manager`, and `Switch([IsSoftDeleted]…) → active`.
4. Assign users and groups, then start provisioning. Changes appear in the JML history and audit log as `scim:<token name>`.
