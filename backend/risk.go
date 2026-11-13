package main

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// Identity risk scoring and target-system reconciliation.
//
// Reconciliation compares what IAM believes (grants derived from HR + roles +
// approved requests) with what actually exists in each target system. Drift
// shows up as:
//   orphan           an enabled account whose owner left, or who was never in HR
//   rogue            access created directly in the app, outside IAM
//   unowned-service  a service account nobody is accountable for
// plus dormant grants: entitlements not exercised in DormantDays.

const DormantDays = 90

type TargetAccount struct {
	ID            string `json:"id"`
	SystemID      string `json:"systemId"`
	AccountName   string `json:"accountName"`
	Type          string `json:"type"` // user | service
	IdentityID    string `json:"identityId,omitempty"`
	EntitlementID string `json:"entitlementId,omitempty"` // permission held in the target
	Owner         string `json:"owner,omitempty"`         // accountable person for service accounts
	LastLogin     string `json:"lastLogin,omitempty"`
	Status        string `json:"status"` // enabled | disabled
	Note          string `json:"note,omitempty"`
}

type reconRow struct {
	TargetAccount
	Finding  string `json:"finding"` // ok | orphan | rogue | unowned-service | disabled
	Severity string `json:"severity"`
	Detail   string `json:"detail"`
}

func (s *State) classify(a TargetAccount) reconRow {
	row := reconRow{TargetAccount: a, Finding: "ok", Severity: "none"}
	if a.Status != "enabled" {
		row.Finding, row.Detail = "disabled", "Disabled in target"
		return row
	}
	e := s.entitlement(a.EntitlementID)
	priv := e != nil && e.Privileged
	sev := func(base string) string {
		if priv {
			return "critical"
		}
		return base
	}
	if a.Type == "service" {
		if strings.TrimSpace(a.Owner) == "" {
			row.Finding, row.Severity, row.Detail = "unowned-service", sev("high"), "Service account with no accountable owner"
		} else {
			row.Detail = "Owned by " + a.Owner
		}
		return row
	}
	id := s.identity(a.IdentityID)
	switch {
	case id == nil:
		row.Finding, row.Severity, row.Detail = "orphan", sev("high"), "No matching identity in the HR source of truth"
	case id.Status != "active":
		row.Finding, row.Severity, row.Detail = "orphan", sev("high"), id.Name+" was terminated but this account is still enabled"
	case a.EntitlementID != "" && !s.hasGrant(id.ID, a.EntitlementID):
		row.Finding, row.Severity, row.Detail = "rogue", sev("high"), fmt.Sprintf("%s holds %s in the app with no IAM grant", id.Name, entName(s, a.EntitlementID))
		if r := s.sodConflict(id.ID, a.EntitlementID); r != nil {
			row.Detail += " and it breaks " + r.ID
			row.Severity = "critical"
		}
	default:
		row.Detail = "Matches " + id.Name
	}
	return row
}

func entName(s *State, id string) string {
	if e := s.entitlement(id); e != nil {
		return e.Name
	}
	return id
}

type dormantRow struct {
	IdentityID    string `json:"identityId"`
	EntitlementID string `json:"entitlementId"`
	Source        string `json:"source"`
	Privileged    bool   `json:"privileged"`
	LastUsed      string `json:"lastUsed"`
	DaysUnused    int    `json:"daysUnused"`
}

func (s *State) dormant() []dormantRow {
	out := []dormantRow{}
	for _, g := range s.Grants {
		if g.LastUsed == "" || g.Source == "jit" {
			continue
		}
		id := s.identity(g.IdentityID)
		if id == nil || id.Status != "active" {
			continue
		}
		days := int(nowT().Sub(parseT(g.LastUsed)).Hours() / 24)
		if days >= DormantDays {
			e := s.entitlement(g.EntitlementID)
			out = append(out, dormantRow{g.IdentityID, g.EntitlementID, g.Source, e != nil && e.Privileged, g.LastUsed, days})
		}
	}
	sort.SliceStable(out, func(a, b int) bool { return out[a].DaysUnused > out[b].DaysUnused })
	return out
}

// ---------- risk ----------

type riskFactor struct {
	Label  string `json:"label"`
	Points int    `json:"points"`
}

type riskRow struct {
	IdentityID string       `json:"identityId"`
	Name       string       `json:"name"`
	Department string       `json:"department"`
	RoleID     string       `json:"roleId"`
	Score      int          `json:"score"`
	Level      string       `json:"level"`
	Factors    []riskFactor `json:"factors"`
	Grants     int          `json:"grants"`
	Privileged int          `json:"privileged"`
}

func level(n int) string {
	switch {
	case n >= 75:
		return "critical"
	case n >= 50:
		return "high"
	case n >= 25:
		return "medium"
	}
	return "low"
}

// riskScores is a transparent, additive model: every point traces to a factor
// an analyst can act on. Capped at 100.
func riskScores(s *State) []riskRow {
	dormant := map[string]bool{}
	for _, d := range s.dormant() {
		dormant[d.IdentityID+"|"+d.EntitlementID] = true
	}
	out := []riskRow{}
	for _, id := range s.Identities {
		if id.Status != "active" {
			continue
		}
		row := riskRow{IdentityID: id.ID, Name: id.Name, Department: id.Department, RoleID: id.RoleID}
		add := func(label string, pts int) { row.Factors = append(row.Factors, riskFactor{label, pts}) }
		for _, g := range s.grantsFor(id.ID) {
			row.Grants++
			e := s.entitlement(g.EntitlementID)
			if e == nil {
				continue
			}
			if e.Privileged {
				row.Privileged++
				switch g.Source {
				case "jit":
					add("Active JIT elevation: "+e.Name, 5)
				default:
					add("Standing privileged access: "+e.Name, 20)
				}
			} else if g.Source == "request" {
				add("Access outside role: "+e.Name, 4)
			}
			if dormant[id.ID+"|"+e.ID] {
				pts := 5
				if e.Privileged {
					pts = 15
				}
				add(fmt.Sprintf("Unused %d+ days: %s", DormantDays, e.Name), pts)
			}
		}
		seen := map[string]bool{}
		for _, r := range s.SoDRules {
			if s.hasGrant(id.ID, r.A) && s.hasGrant(id.ID, r.B) && !seen[r.ID] {
				seen[r.ID] = true
				add("SoD violation "+r.ID, 25)
			}
		}
		for _, a := range s.TargetAccounts {
			if a.IdentityID == id.ID {
				if c := s.classify(a); c.Finding == "rogue" {
					pts := 20
					if e := s.entitlement(a.EntitlementID); e != nil && e.Privileged {
						pts = 35
					}
					add("Rogue account in "+sysName(s, a.SystemID)+": "+a.AccountName, pts)
					if r := s.sodConflict(id.ID, a.EntitlementID); r != nil {
						add("SoD violation "+r.ID+" via rogue account", 25)
					}
				}
			}
		}
		for _, p := range s.PAMSessions {
			if p.IdentityID == id.ID && p.BreakGlass && p.ReviewedBy == "" {
				add("Unreviewed break-glass use ("+p.ID+")", 15)
			}
		}
		for _, f := range row.Factors {
			row.Score += f.Points
		}
		if row.Score > 100 {
			row.Score = 100
		}
		if row.Factors == nil {
			row.Factors = []riskFactor{}
		}
		row.Level = level(row.Score)
		out = append(out, row)
	}
	sort.SliceStable(out, func(a, b int) bool { return out[a].Score > out[b].Score })
	return out
}

func sysName(s *State, id string) string {
	if x := s.system(id); x != nil {
		return x.Name
	}
	return id
}

// ---------- handlers ----------

func getRisk(w http.ResponseWriter, r *http.Request) {
	store.View(func(s *State) {
		rows := riskScores(s)
		sum, dist := 0, map[string]int{"low": 0, "medium": 0, "high": 0, "critical": 0}
		for _, x := range rows {
			sum += x.Score
			dist[x.Level]++
		}
		avg := 0
		if len(rows) > 0 {
			avg = sum / len(rows)
		}
		writeJSON(w, 200, map[string]any{"identities": rows, "average": avg, "distribution": dist})
	})
}

func getReconciliation(w http.ResponseWriter, r *http.Request) {
	store.View(func(s *State) {
		rows := []reconRow{}
		counts := map[string]int{}
		for _, a := range s.TargetAccounts {
			c := s.classify(a)
			counts[c.Finding]++
			rows = append(rows, c)
		}
		rank := map[string]int{"critical": 0, "high": 1, "medium": 2, "none": 3}
		sort.SliceStable(rows, func(a, b int) bool { return rank[rows[a].Severity] < rank[rows[b].Severity] })
		writeJSON(w, 200, map[string]any{"accounts": rows, "dormant": s.dormant(), "counts": counts, "dormantDays": DormantDays})
	})
}

// postAccountAction remediates a reconciliation finding.
//
//	disable       turn the account off in the target
//	assign-owner  give a service account an accountable owner
//	adopt         bring rogue access under governance as an approved request grant
func postAccountAction(w http.ResponseWriter, r *http.Request) {
	var in struct{ Action, Owner, Reason string }
	if err := decode(r, &in); err != nil {
		fail(w, 400, "invalid JSON")
		return
	}
	if strings.TrimSpace(in.Reason) == "" {
		fail(w, 400, "a reason is required for every remediation")
		return
	}
	aid := r.PathValue("id")
	err := store.Update(func(s *State) error {
		var a *TargetAccount
		for i := range s.TargetAccounts {
			if s.TargetAccounts[i].ID == aid {
				a = &s.TargetAccounts[i]
			}
		}
		if a == nil {
			return httpErr{404, "account not found"}
		}
		switch in.Action {
		case "disable":
			a.Status = "disabled"
			a.Note = "Disabled: " + in.Reason
		case "assign-owner":
			if a.Type != "service" || strings.TrimSpace(in.Owner) == "" {
				return httpErr{400, "owners are assigned to service accounts; provide an owner"}
			}
			a.Owner = in.Owner
			a.Note = "Owner assigned: " + in.Reason
		case "adopt":
			if s.classify(*a).Finding != "rogue" {
				return httpErr{400, "only rogue accounts can be adopted"}
			}
			if rule := s.sodConflict(a.IdentityID, a.EntitlementID); rule != nil {
				return httpErr{409, "cannot adopt: it would legitimise an SoD violation (" + rule.ID + "). Disable it instead"}
			}
			req := AccessRequest{s.nextID("REQ"), a.IdentityID, a.EntitlementID, "Adopted from reconciliation: " + in.Reason, "approved", "", now(), actor(r), now(), "Retro-approved during reconciliation"}
			s.Requests = append(s.Requests, req)
			s.Grants = append(s.Grants, Grant{IdentityID: a.IdentityID, EntitlementID: a.EntitlementID, Source: "request", GrantedAt: now(), LastUsed: a.LastLogin})
			a.Note = "Adopted under " + req.ID
		default:
			return httpErr{400, "action must be disable, assign-owner or adopt"}
		}
		s.audit(actor(r), "recon."+in.Action, a.ID, fmt.Sprintf("%s in %s: %s", a.AccountName, sysName(s, a.SystemID), in.Reason))
		return nil
	})
	if err != nil {
		respondErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]string{"status": "ok"})
}
