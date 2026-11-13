#!/usr/bin/env python3
"""iamctl: IAM automation for the IAM Projects tenant (Python 3.9+, standard library only).

Joiner / mover / leaver from an HR CSV over SCIM 2.0, plus access reporting.

    export IAM_BASE_URL=https://iam.assafwahinc.com
    export IAM_SCIM_TOKEN=scim_...           # generate one on the SCIM 2.0 page

    python3 iamctl.py sync hr_feed.csv           # dry run: print the plan
    python3 iamctl.py sync hr_feed.csv --apply   # make the changes
    python3 iamctl.py report --out access.csv    # who has what, with risk flags
    python3 iamctl.py dormant --days 90          # unused access to revoke
    python3 iamctl.py offboard omar.farouk@demo.local

HR feed columns: employee_id,name,email,department,title,manager,role_id,status
"""
import argparse
import csv
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

BASE = os.environ.get("IAM_BASE_URL", "https://iam.assafwahinc.com").rstrip("/")
TOKEN = os.environ.get("IAM_SCIM_TOKEN", "")
ACTOR = os.environ.get("IAM_ACTOR", "iamctl")
SCIM_USER = "urn:ietf:params:scim:schemas:core:2.0:User"
ENTERPRISE = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
PATCH = "urn:ietf:params:scim:api:messages:2.0:PatchOp"


class ApiError(Exception):
    pass


def call(method, path, body=None, scim=False):
    """One HTTP call. SCIM calls carry the bearer token; REST calls carry X-Actor for the audit log."""
    headers = {"Accept": "application/json", "X-Actor": ACTOR}
    if scim:
        if not TOKEN:
            raise ApiError("IAM_SCIM_TOKEN is not set (generate a token on the SCIM 2.0 page)")
        headers["Authorization"] = f"Bearer {TOKEN}"
        headers["Content-Type"] = "application/scim+json"
    elif body is not None:
        headers["Content-Type"] = "application/json"
    data = json.dumps(body).encode() if body is not None else None
    prefix = "/scim/v2" if scim else "/api"
    req = urllib.request.Request(BASE + prefix + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=20) as res:
            raw = res.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")
        try:
            j = json.loads(detail)
            detail = j.get("detail") or j.get("error") or detail
        except ValueError:
            pass
        raise ApiError(f"{method} {prefix}{path} -> {e.code}: {detail}") from None


def find_user(employee_id, email):
    for attr, val in (("externalId", employee_id), ("userName", email)):
        if not val:
            continue
        q = urllib.parse.quote(f'{attr} eq "{val}"')
        res = call("GET", f"/Users?filter={q}", scim=True)
        if res.get("Resources"):
            return res["Resources"][0]
    return None


def plan_row(row, user):
    """Compare one HR row with the SCIM user and decide what to do."""
    status = row["status"].strip().lower()
    if user is None:
        return ("skip", "terminated in HR, never provisioned") if status == "terminated" else ("joiner", f"create with role {row['role_id']}")
    active = user.get("active", False)
    if active and status == "terminated":
        return "leaver", "deactivate and revoke all access"
    if not active and status == "active":
        return "skip", "rehire: review manually so old access is not restored"
    if not active:
        return "noop", "already inactive"
    changes = []
    groups = [g["value"] for g in user.get("groups", [])]
    if row["role_id"] and row["role_id"] not in groups:
        changes.append(f"role {groups[0] if groups else '-'} -> {row['role_id']}")
    if row["title"] and row["title"] != user.get("title"):
        changes.append(f"title -> {row['title']}")
    dept = user.get(ENTERPRISE, {}).get("department")
    if row["department"] and row["department"] != dept:
        changes.append(f"department -> {row['department']}")
    if not changes:
        return "noop", "in sync"
    return ("mover" if changes[0].startswith("role") else "update"), "; ".join(changes)


def apply_row(action, row, user):
    if action == "joiner":
        given, _, family = row["name"].partition(" ")
        call("POST", "/Users", {
            "schemas": [SCIM_USER, ENTERPRISE], "userName": row["email"], "externalId": row["employee_id"],
            "name": {"givenName": given, "familyName": family}, "displayName": row["name"], "title": row["title"],
            "active": True, "emails": [{"value": row["email"], "primary": True}], "groups": [{"value": row["role_id"]}],
            ENTERPRISE: {"department": row["department"], "manager": {"displayName": row["manager"]}},
        }, scim=True)
    elif action == "leaver":
        call("PATCH", f"/Users/{user['id']}", {"schemas": [PATCH], "Operations": [{"op": "replace", "path": "active", "value": False}]}, scim=True)
    elif action in ("mover", "update"):
        ops = [{"op": "replace", "path": "title", "value": row["title"]},
               {"op": "replace", "path": f"{ENTERPRISE}:department", "value": row["department"]}]
        call("PATCH", f"/Users/{user['id']}", {"schemas": [PATCH], "Operations": ops}, scim=True)
        if action == "mover":  # adding the user to the new role's group triggers the mover event
            call("PATCH", f"/Groups/{row['role_id']}", {"schemas": [PATCH], "Operations": [{"op": "add", "path": "members", "value": [{"value": user["id"]}]}]}, scim=True)


def cmd_sync(args):
    with open(args.feed, newline="", encoding="utf-8-sig") as f:
        rows = [{k.strip().lower(): (v or "").strip() for k, v in r.items()} for r in csv.DictReader(f)]
    need = {"employee_id", "name", "email", "department", "title", "manager", "role_id", "status"}
    missing = need - set(rows[0].keys() if rows else [])
    if missing:
        sys.exit(f"feed is missing columns: {', '.join(sorted(missing))}")
    counts, failures = {}, 0
    print(f"{'ACTION':8} {'EMPLOYEE':10} {'NAME':22} DETAIL")
    for row in rows:
        try:
            user = find_user(row["employee_id"], row["email"])
            action, detail = plan_row(row, user)
            if args.apply and action in ("joiner", "mover", "update", "leaver"):
                apply_row(action, row, user)
        except ApiError as e:
            action, detail, failures = "error", str(e), failures + 1
        counts[action] = counts.get(action, 0) + 1
        print(f"{action:8} {row['employee_id']:10} {row['name'][:22]:22} {detail}")
    mode = "APPLIED" if args.apply else "DRY RUN (add --apply to make changes)"
    print("\n" + mode + ": " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    return 1 if failures else 0


def access_rows():
    cat = call("GET", "/catalog")
    ents = {e["id"]: e for e in cat["entitlements"]}
    systems = {s["id"]: s["name"] for s in cat["systems"]}
    roles = {r["id"]: r["name"] for r in cat["roles"]}
    now = datetime.now(timezone.utc)
    rows = []
    for p in call("GET", "/identities"):
        if p["status"] != "active":
            continue
        for g in call("GET", f"/identities/{p['id']}/access"):
            e = ents.get(g["entitlementId"], {})
            last = g.get("lastUsed")
            unused = (now - datetime.fromisoformat(last.replace("Z", "+00:00"))).days if last else None
            flags = []
            if e.get("privileged") and g["source"] == "role":
                flags.append("privileged-birthright")
            if e.get("privileged") and g["source"] == "request":
                flags.append("standing-privileged")
            if unused is not None and unused >= 90:
                flags.append("dormant")
            rows.append({"identity": p["name"], "email": p["email"], "department": p["department"], "role": roles.get(p["roleId"], p["roleId"]),
                         "system": systems.get(e.get("systemId"), ""), "entitlement": e.get("name", g["entitlementId"]),
                         "privileged": bool(e.get("privileged")), "source": g["source"], "granted": g["grantedAt"][:10],
                         "last_used": (last or "")[:10], "days_unused": "" if unused is None else unused, "flags": " ".join(flags)})
    return rows


def cmd_report(args):
    rows = access_rows()
    out = open(args.out, "w", newline="") if args.out else sys.stdout
    if args.format == "json":
        json.dump(rows, out, indent=2)
    else:
        w = csv.DictWriter(out, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    if args.out:
        out.close()
        flagged = sum(1 for r in rows if r["flags"])
        print(f"wrote {len(rows)} grants for {len({r['email'] for r in rows})} people to {args.out} ({flagged} flagged)")
    return 0


def cmd_dormant(args):
    rows = [r for r in access_rows() if r["days_unused"] != "" and r["days_unused"] >= args.days]
    for r in sorted(rows, key=lambda r: -r["days_unused"]):
        print(f"{r['days_unused']:>4}d  {r['identity']:18} {r['system']:24} {r['entitlement']}{'  [PRIVILEGED]' if r['privileged'] else ''}")
    print(f"\n{len(rows)} grant(s) unused for {args.days}+ days. Revoke them, or move admin rights to JIT.")
    return 0


def cmd_offboard(args):
    user = find_user("", args.email)
    if not user:
        sys.exit(f"no user {args.email}")
    if not user.get("active"):
        print(f"{args.email} is already inactive")
        return 0
    call("PATCH", f"/Users/{user['id']}", {"schemas": [PATCH], "Operations": [{"op": "replace", "path": "active", "value": False}]}, scim=True)
    print(f"deactivated {args.email}: access revoked, IdP sign-in disabled, sessions killed")
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("sync", help="reconcile an HR CSV feed (joiner/mover/leaver) over SCIM")
    s.add_argument("feed")
    s.add_argument("--apply", action="store_true", help="make the changes (default is a dry run)")
    r = sub.add_parser("report", help="export every active grant with risk flags")
    r.add_argument("--out")
    r.add_argument("--format", choices=["csv", "json"], default="csv")
    d = sub.add_parser("dormant", help="list access unused for N days")
    d.add_argument("--days", type=int, default=90)
    o = sub.add_parser("offboard", help="emergency leaver: deactivate one user")
    o.add_argument("email")
    args = ap.parse_args()
    try:
        return {"sync": cmd_sync, "report": cmd_report, "dormant": cmd_dormant, "offboard": cmd_offboard}[args.cmd](args)
    except ApiError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
