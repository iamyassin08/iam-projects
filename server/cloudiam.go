package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"path"
	"slices"
	"strings"
)

// Cloud IAM policy design and testing.
//
// AWS: a faithful subset of IAM policy evaluation: explicit Deny wins, then an
// Allow in an identity policy is required, and a permissions boundary (if set)
// must also allow. Wildcards (* and ?) in Action / Resource, Action and NotAction,
// and the condition operators Bool, StringEquals, StringLike and IpAddress.
// A linter flags the misconfigurations auditors and attackers look for.
//
// Azure: RBAC role assignments along the scope hierarchy (management group →
// subscription → resource group), with PIM-eligible versus permanent assignments.

type CloudPolicy struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Document    string   `json:"document"` // JSON policy document
	AttachedTo  []string `json:"attachedTo"`
}

type CloudPrincipal struct {
	ID         string `json:"id"` // arn-like: user/omar.farouk
	Type       string `json:"type"`
	Name       string `json:"name"`
	IdentityID string `json:"identityId,omitempty"`
	Boundary   string `json:"boundary,omitempty"` // policy id used as permissions boundary
}

type AzureAssignment struct {
	ID        string `json:"id"`
	Principal string `json:"principal"`
	Kind      string `json:"kind"` // user | group | service principal
	Role      string `json:"role"`
	Scope     string `json:"scope"`
	ScopeType string `json:"scopeType"` // management-group | subscription | resource-group
	Type      string `json:"type"`      // permanent | eligible
}

// ---------- policy document model ----------

type strList []string

func (s *strList) UnmarshalJSON(b []byte) error {
	var one string
	if json.Unmarshal(b, &one) == nil {
		*s = []string{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return fmt.Errorf("expected a string or list of strings")
	}
	*s = many
	return nil
}

type statement struct {
	Sid       string                        `json:"Sid"`
	Effect    string                        `json:"Effect"`
	Action    strList                       `json:"Action"`
	NotAction strList                       `json:"NotAction"`
	Resource  strList                       `json:"Resource"`
	Condition map[string]map[string]strList `json:"Condition"`
}

type policyDoc struct {
	Version   string      `json:"Version"`
	Statement []statement `json:"Statement"`
}

func parsePolicy(doc string) (policyDoc, error) {
	var raw struct {
		Version   string          `json:"Version"`
		Statement json.RawMessage `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(doc), &raw); err != nil {
		return policyDoc{}, fmt.Errorf("invalid JSON: %v", err)
	}
	var p policyDoc
	p.Version = raw.Version
	var one statement
	if err := json.Unmarshal(raw.Statement, &p.Statement); err != nil {
		if err2 := json.Unmarshal(raw.Statement, &one); err2 != nil {
			return p, fmt.Errorf("Statement must be an object or array: %v", err)
		}
		p.Statement = []statement{one}
	}
	if len(p.Statement) == 0 {
		return p, fmt.Errorf("policy has no statements")
	}
	for i, st := range p.Statement {
		if st.Effect != "Allow" && st.Effect != "Deny" {
			return p, fmt.Errorf("statement %d: Effect must be Allow or Deny", i+1)
		}
		if len(st.Action) == 0 && len(st.NotAction) == 0 {
			return p, fmt.Errorf("statement %d: Action or NotAction is required", i+1)
		}
		if len(st.Resource) == 0 {
			return p, fmt.Errorf("statement %d: Resource is required", i+1)
		}
	}
	return p, nil
}

// wild matches IAM-style wildcards: * any run, ? one character. Actions are case-insensitive.
func wild(pattern, s string, fold bool) bool {
	if fold {
		pattern, s = strings.ToLower(pattern), strings.ToLower(s)
	}
	ok, err := path.Match(strings.ReplaceAll(pattern, "/", "\x00"), strings.ReplaceAll(s, "/", "\x00"))
	return err == nil && ok
}

func anyWild(patterns []string, s string, fold bool) bool {
	return slices.ContainsFunc(patterns, func(p string) bool { return wild(p, s, fold) })
}

type simCtx struct {
	MFA      bool   `json:"mfa"`
	SourceIP string `json:"sourceIp"`
	Region   string `json:"region"`
}

func (c simCtx) key(k string) []string {
	switch strings.ToLower(k) {
	case "aws:multifactorauthpresent":
		return []string{fmt.Sprint(c.MFA)}
	case "aws:sourceip":
		return []string{c.SourceIP}
	case "aws:requestedregion":
		return []string{c.Region}
	}
	return nil
}

// condOK evaluates a Condition block; every operator and key must match.
func condOK(cond map[string]map[string]strList, c simCtx) (bool, string) {
	for op, kv := range cond {
		for k, want := range kv {
			have := c.key(k)
			if have == nil {
				return false, fmt.Sprintf("condition key %s not present", k)
			}
			ok := false
			for _, w := range want {
				switch op {
				case "Bool", "StringEquals":
					ok = ok || strings.EqualFold(have[0], w)
				case "StringNotEquals":
					ok = ok || !strings.EqualFold(have[0], w)
				case "StringLike":
					ok = ok || wild(w, have[0], false)
				case "IpAddress", "NotIpAddress":
					_, n, err := net.ParseCIDR(w)
					ip := net.ParseIP(have[0])
					in := err == nil && ip != nil && n.Contains(ip)
					ok = ok || (op == "IpAddress" && in) || (op == "NotIpAddress" && !in)
				default:
					return false, "unsupported operator " + op
				}
			}
			if !ok {
				return false, fmt.Sprintf("%s %s=%v not satisfied (have %s)", op, k, []string(want), have[0])
			}
		}
	}
	return true, ""
}

type stmtTrace struct {
	Policy  string `json:"policy"`
	Sid     string `json:"sid"`
	Effect  string `json:"effect"`
	Matched bool   `json:"matched"`
	Why     string `json:"why"`
	Layer   string `json:"layer"` // identity | boundary
}

// matchStatements returns traces and whether any Allow / Deny matched.
func matchStatements(pol CloudPolicy, layer, action, resource string, c simCtx) (traces []stmtTrace, allow, deny bool) {
	doc, err := parsePolicy(pol.Document)
	if err != nil {
		return []stmtTrace{{pol.Name, "", "", false, "policy does not parse: " + err.Error(), layer}}, false, false
	}
	for i, st := range doc.Statement {
		t := stmtTrace{Policy: pol.Name, Sid: firstNonEmpty(st.Sid, fmt.Sprintf("#%d", i+1)), Effect: st.Effect, Layer: layer}
		actOK := (len(st.Action) > 0 && anyWild(st.Action, action, true)) || (len(st.NotAction) > 0 && !anyWild(st.NotAction, action, true))
		switch {
		case !actOK:
			t.Why = "action not covered"
		case !anyWild(st.Resource, resource, false):
			t.Why = "resource not covered"
		default:
			if ok, why := condOK(st.Condition, c); !ok {
				t.Why = why
			} else {
				t.Matched, t.Why = true, "action, resource and conditions match"
				if st.Effect == "Deny" {
					deny = true
				} else {
					allow = true
				}
			}
		}
		traces = append(traces, t)
	}
	return
}

type simResult struct {
	Decision string      `json:"decision"` // allowed | explicit-deny | implicit-deny | boundary-deny
	Reason   string      `json:"reason"`
	Trace    []stmtTrace `json:"trace"`
}

func (s *State) simulate(principalID, action, resource string, c simCtx) (simResult, error) {
	var pr *CloudPrincipal
	for i := range s.CloudPrincipals {
		if s.CloudPrincipals[i].ID == principalID {
			pr = &s.CloudPrincipals[i]
		}
	}
	if pr == nil {
		return simResult{}, httpErr{404, "principal not found"}
	}
	res := simResult{Trace: []stmtTrace{}}
	allow, deny := false, false
	for _, p := range s.CloudPolicies {
		if !slices.Contains(p.AttachedTo, pr.ID) {
			continue
		}
		tr, a, d := matchStatements(p, "identity", action, resource, c)
		res.Trace = append(res.Trace, tr...)
		allow, deny = allow || a, deny || d
	}
	bAllow, bDeny := true, false
	if pr.Boundary != "" {
		if bp := s.cloudPolicy(pr.Boundary); bp != nil {
			tr, a, d := matchStatements(*bp, "boundary", action, resource, c)
			res.Trace = append(res.Trace, tr...)
			bAllow, bDeny = a, d
		}
	}
	switch {
	case deny || bDeny:
		res.Decision, res.Reason = "explicit-deny", "An explicit Deny matched. Deny always wins."
	case !allow:
		res.Decision, res.Reason = "implicit-deny", "No Allow statement matched, so access is denied by default."
	case !bAllow:
		res.Decision, res.Reason = "boundary-deny", "An identity policy allows it, but the permissions boundary does not."
	default:
		res.Decision, res.Reason = "allowed", "Allowed by an identity policy and not blocked by any Deny or boundary."
	}
	return res, nil
}

func (s *State) cloudPolicy(id string) *CloudPolicy {
	for i := range s.CloudPolicies {
		if s.CloudPolicies[i].ID == id {
			return &s.CloudPolicies[i]
		}
	}
	return nil
}

// ---------- linting ----------

type lintFinding struct {
	PolicyID string `json:"policyId"`
	Sid      string `json:"sid"`
	Severity string `json:"severity"`
	Rule     string `json:"rule"`
	Detail   string `json:"detail"`
	Fix      string `json:"fix"`
}

var sensitiveActions = []string{"iam:*", "iam:CreateUser", "iam:AttachUserPolicy", "iam:PutUserPolicy", "iam:CreateAccessKey", "iam:PassRole", "kms:Decrypt", "organizations:*", "sts:AssumeRole"}

func lintPolicy(p CloudPolicy) []lintFinding {
	out := []lintFinding{}
	doc, err := parsePolicy(p.Document)
	if err != nil {
		return append(out, lintFinding{p.ID, "", "high", "invalid", err.Error(), "Fix the JSON so the policy can be evaluated"})
	}
	for i, st := range doc.Statement {
		sid := firstNonEmpty(st.Sid, fmt.Sprintf("#%d", i+1))
		if st.Effect != "Allow" {
			continue
		}
		f := func(sev, rule, detail, fix string) { out = append(out, lintFinding{p.ID, sid, sev, rule, detail, fix}) }
		allRes := slices.Contains(st.Resource, "*")
		if slices.Contains(st.Action, "*") && allRes {
			f("critical", "full-admin", `Allows "*" on "*": full administrator.`, "Replace with the specific actions the job needs, scoped to named resources")
			continue
		}
		if len(st.NotAction) > 0 {
			f("medium", "allow-notaction", "Allow with NotAction grants everything except the listed actions, including services added later.", "Use an explicit Action list")
		}
		for _, a := range st.Action {
			if strings.HasSuffix(a, ":*") && allRes {
				f("high", "service-wildcard", fmt.Sprintf("%s on every resource.", a), "List specific actions and scope Resource to ARNs")
			}
		}
		if slices.ContainsFunc(st.Action, func(a string) bool { return strings.EqualFold(a, "iam:PassRole") }) && allRes {
			f("high", "passrole-star", "iam:PassRole on * lets the holder hand any role (including admin) to a service they control.", "Restrict Resource to the specific role ARNs")
		}
		touchesSensitive := slices.ContainsFunc(st.Action, func(a string) bool {
			return slices.ContainsFunc(sensitiveActions, func(sa string) bool { return wild(a, sa, true) || wild(sa, a, true) })
		})
		mfa := false
		for _, kv := range st.Condition {
			for k := range kv {
				if strings.EqualFold(k, "aws:MultiFactorAuthPresent") {
					mfa = true
				}
			}
		}
		if touchesSensitive && !mfa {
			f("high", "sensitive-no-mfa", "Sensitive IAM / key actions are allowed without an MFA condition.", `Add "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}`)
		}
	}
	return out
}

func (s *State) azureFindings() []map[string]string {
	out := []map[string]string{}
	for _, a := range s.AzureAssignments {
		priv := a.Role == "Owner" || a.Role == "User Access Administrator" || a.Role == "Contributor"
		broad := a.ScopeType == "subscription" || a.ScopeType == "management-group"
		if priv && broad && a.Type == "permanent" {
			out = append(out, map[string]string{"assignmentId": a.ID, "severity": "high",
				"detail": fmt.Sprintf("%s has permanent %s at %s scope (%s).", a.Principal, a.Role, a.ScopeType, a.Scope),
				"fix":    "Make it PIM-eligible (just-in-time) or narrow the scope to a resource group"})
		}
		if priv && a.Kind == "user" && a.ScopeType != "resource-group" {
			out = append(out, map[string]string{"assignmentId": a.ID, "severity": "medium",
				"detail": fmt.Sprintf("%s is assigned %s directly as a user.", a.Principal, a.Role),
				"fix":    "Assign roles to groups so access reviews and JML apply"})
		}
	}
	return out
}

// ---------- API ----------

func registerCloud(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/cloud", func(w http.ResponseWriter, r *http.Request) {
		store.View(func(s *State) {
			findings := []lintFinding{}
			for _, p := range s.CloudPolicies {
				findings = append(findings, lintPolicy(p)...)
			}
			writeJSON(w, 200, map[string]any{"principals": s.CloudPrincipals, "policies": s.CloudPolicies, "findings": findings,
				"azure": s.AzureAssignments, "azureFindings": s.azureFindings()})
		})
	})
	mux.HandleFunc("PUT /api/cloud/policies/{id}", func(w http.ResponseWriter, r *http.Request) {
		var in struct{ Document, Reason string }
		if err := decode(r, &in); err != nil {
			fail(w, 400, "invalid JSON")
			return
		}
		if _, err := parsePolicy(in.Document); err != nil {
			fail(w, 400, err.Error())
			return
		}
		var out []lintFinding
		err := store.Update(func(s *State) error {
			p := s.cloudPolicy(r.PathValue("id"))
			if p == nil {
				return httpErr{404, "policy not found"}
			}
			before := len(lintPolicy(*p))
			var pretty any
			_ = json.Unmarshal([]byte(in.Document), &pretty)
			b, _ := json.MarshalIndent(pretty, "", "  ")
			p.Document = string(b)
			out = lintPolicy(*p)
			s.audit(actor(r), "cloud.policy.updated", p.ID, fmt.Sprintf("%s edited (%d → %d findings) %s", p.Name, before, len(out), in.Reason))
			return nil
		})
		if err != nil {
			respondErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"findings": out})
	})
	mux.HandleFunc("POST /api/cloud/simulate", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Principal, Action, Resource string
			Context                     simCtx
		}
		if err := decode(r, &in); err != nil || in.Action == "" || in.Resource == "" {
			fail(w, 400, "principal, action and resource are required")
			return
		}
		store.View(func(s *State) {
			res, err := s.simulate(in.Principal, in.Action, in.Resource, in.Context)
			if err != nil {
				respondErr(w, err)
				return
			}
			writeJSON(w, 200, res)
		})
	})
	mux.HandleFunc("POST /api/cloud/azure/{id}/make-eligible", func(w http.ResponseWriter, r *http.Request) {
		err := store.Update(func(s *State) error {
			for i := range s.AzureAssignments {
				if a := &s.AzureAssignments[i]; a.ID == r.PathValue("id") {
					a.Type = "eligible"
					s.audit(actor(r), "azure.pim.converted", a.ID, fmt.Sprintf("%s %s at %s is now PIM-eligible (no standing access)", a.Principal, a.Role, a.Scope))
					return nil
				}
			}
			return httpErr{404, "assignment not found"}
		})
		if err != nil {
			respondErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]string{"status": "eligible"})
	})
}
