package main

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// Access certifications (user access reviews). A campaign snapshots the grants
// in scope and routes each one to the identity's manager, who must keep or
// revoke it. Revocation is enforced immediately; on close, undecided items can
// be revoked automatically ("revoke on non-response"), which is what auditors
// expect for SOX in-scope applications.

type Campaign struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Scope      string `json:"scope"` // all | privileged | requested | system
	SystemID   string `json:"systemId,omitempty"`
	CreatedBy  string `json:"createdBy"`
	CreatedAt  string `json:"createdAt"`
	DueDate    string `json:"dueDate"`
	Status     string `json:"status"` // active | closed
	ClosedAt   string `json:"closedAt,omitempty"`
	AutoRevoke bool   `json:"autoRevoke"`
}

type CertItem struct {
	ID            string `json:"id"`
	CampaignID    string `json:"campaignId"`
	IdentityID    string `json:"identityId"`
	EntitlementID string `json:"entitlementId"`
	Source        string `json:"source"`
	Reviewer      string `json:"reviewer"`
	Privileged    bool   `json:"privileged"`
	LastUsed      string `json:"lastUsed,omitempty"`
	SoD           string `json:"sod,omitempty"`
	Decision      string `json:"decision"` // pending | keep | revoke
	Comment       string `json:"comment,omitempty"`
	DecidedBy     string `json:"decidedBy,omitempty"`
	DecidedAt     string `json:"decidedAt,omitempty"`
}

type campaignStats struct {
	Campaign
	Total    int  `json:"total"`
	Decided  int  `json:"decided"`
	Kept     int  `json:"kept"`
	Revoked  int  `json:"revoked"`
	Percent  int  `json:"percent"`
	Overdue  bool `json:"overdue"`
	Reviewer int  `json:"reviewers"`
}

func (s *State) campaign(id string) *Campaign {
	for i := range s.Campaigns {
		if s.Campaigns[i].ID == id {
			return &s.Campaigns[i]
		}
	}
	return nil
}

func (s *State) stats(c Campaign) campaignStats {
	st := campaignStats{Campaign: c}
	reviewers := map[string]bool{}
	for _, it := range s.CertItems {
		if it.CampaignID != c.ID {
			continue
		}
		st.Total++
		reviewers[it.Reviewer] = true
		switch it.Decision {
		case "keep":
			st.Decided++
			st.Kept++
		case "revoke":
			st.Decided++
			st.Revoked++
		}
	}
	if st.Total > 0 {
		st.Percent = st.Decided * 100 / st.Total
	}
	st.Reviewer = len(reviewers)
	st.Overdue = c.Status == "active" && nowT().After(parseT(c.DueDate))
	return st
}

// sodFor names the SoD rule this grant participates in for this identity, if any.
func (s *State) sodFor(identityID, entID string) string {
	for _, r := range s.SoDRules {
		if (r.A == entID && s.hasGrant(identityID, r.B)) || (r.B == entID && s.hasGrant(identityID, r.A)) {
			return r.ID
		}
	}
	return ""
}

func (s *State) launchCampaign(actor, name, scope, systemID string, dueDays int, autoRevoke bool) (*Campaign, error) {
	if strings.TrimSpace(name) == "" {
		return nil, httpErr{400, "campaign name is required"}
	}
	if dueDays <= 0 {
		dueDays = 14
	}
	if scope == "system" && s.system(systemID) == nil {
		return nil, httpErr{400, "choose a system for a system-scoped campaign"}
	}
	c := Campaign{ID: s.nextID("CERT"), Name: name, Scope: scope, SystemID: systemID, CreatedBy: actor,
		CreatedAt: now(), DueDate: nowT().AddDate(0, 0, dueDays).Format("2006-01-02T15:04:05Z07:00"), Status: "active", AutoRevoke: autoRevoke}
	n := 0
	for _, g := range s.Grants {
		id := s.identity(g.IdentityID)
		e := s.entitlement(g.EntitlementID)
		if id == nil || e == nil || id.Status != "active" || g.Source == "jit" {
			continue // JIT access is already time-boxed; it is reviewed per session instead
		}
		switch scope {
		case "privileged":
			if !e.Privileged {
				continue
			}
		case "requested":
			if g.Source != "request" {
				continue
			}
		case "system":
			if e.SystemID != systemID {
				continue
			}
		case "all":
		default:
			return nil, httpErr{400, "scope must be all, privileged, requested or system"}
		}
		reviewer := id.Manager
		if reviewer == "" {
			reviewer = "IAM Team"
		}
		s.CertItems = append(s.CertItems, CertItem{ID: s.nextID("ITEM"), CampaignID: c.ID, IdentityID: id.ID, EntitlementID: e.ID,
			Source: g.Source, Reviewer: reviewer, Privileged: e.Privileged, LastUsed: g.LastUsed, SoD: s.sodFor(id.ID, e.ID), Decision: "pending"})
		n++
	}
	if n == 0 {
		return nil, httpErr{400, "no active grants match that scope"}
	}
	s.Campaigns = append(s.Campaigns, c)
	s.audit(actor, "cert.launched", c.ID, fmt.Sprintf("%s: %d items in scope (%s)", c.Name, n, scope))
	return s.campaign(c.ID), nil
}

func (s *State) decide(actor string, it *CertItem, decision, comment string) error {
	if decision != "keep" && decision != "revoke" {
		return httpErr{400, "decision must be keep or revoke"}
	}
	if decision == "revoke" && strings.TrimSpace(comment) == "" && !strings.HasPrefix(actor, "system") {
		return httpErr{400, "a comment is required when revoking"}
	}
	if decision == "keep" && it.SoD != "" && strings.TrimSpace(comment) == "" {
		return httpErr{400, "this grant is part of an SoD conflict; keeping it needs a comment"}
	}
	it.Decision, it.Comment, it.DecidedBy, it.DecidedAt = decision, comment, actor, now()
	if decision == "revoke" {
		if g := s.findGrant(it.IdentityID, it.EntitlementID); g != nil {
			if g.Source == "role" {
				// Birthright revoked by a reviewer: hold an exclusion so role re-sync doesn't re-grant it.
				s.Exclusions = append(s.Exclusions, Exclusion{it.IdentityID, it.EntitlementID, it.CampaignID, comment, now()})
			}
			s.revoke(it.IdentityID, it.EntitlementID, "")
		}
	}
	s.audit(actor, "cert."+decision, it.ID, fmt.Sprintf("%s for %s in %s %s", it.EntitlementID, it.IdentityID, it.CampaignID, comment))
	return nil
}

// ---------- handlers ----------

func getCampaigns(w http.ResponseWriter, r *http.Request) {
	store.View(func(s *State) {
		out := []campaignStats{}
		for _, c := range s.Campaigns {
			out = append(out, s.stats(c))
		}
		sort.SliceStable(out, func(a, b int) bool { return out[a].CreatedAt > out[b].CreatedAt })
		writeJSON(w, 200, out)
	})
}

func getCampaign(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	store.View(func(s *State) {
		c := s.campaign(id)
		if c == nil {
			fail(w, 404, "campaign not found")
			return
		}
		items := []CertItem{}
		for _, it := range s.CertItems {
			if it.CampaignID == id {
				items = append(items, it)
			}
		}
		writeJSON(w, 200, map[string]any{"campaign": s.stats(*c), "items": items})
	})
}

func postCampaign(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name, Scope, SystemID string
		DueDays               int
		AutoRevoke            bool
	}
	if err := decode(r, &in); err != nil {
		fail(w, 400, "invalid JSON")
		return
	}
	var out Campaign
	err := store.Update(func(s *State) error {
		c, err := s.launchCampaign(actor(r), in.Name, in.Scope, in.SystemID, in.DueDays, in.AutoRevoke)
		if err != nil {
			return err
		}
		out = *c
		return nil
	})
	if err != nil {
		respondErr(w, err)
		return
	}
	writeJSON(w, 201, out)
}

func postCertDecision(w http.ResponseWriter, r *http.Request) {
	var in struct{ Decision, Comment string }
	if err := decode(r, &in); err != nil {
		fail(w, 400, "invalid JSON")
		return
	}
	cid, iid := r.PathValue("id"), r.PathValue("itemId")
	var out CertItem
	err := store.Update(func(s *State) error {
		c := s.campaign(cid)
		if c == nil {
			return httpErr{404, "campaign not found"}
		}
		if c.Status != "active" {
			return httpErr{409, "campaign is closed"}
		}
		for i := range s.CertItems {
			it := &s.CertItems[i]
			if it.ID == iid && it.CampaignID == cid {
				if it.Decision != "pending" {
					return httpErr{409, "item already decided"}
				}
				if err := s.decide(actor(r), it, in.Decision, in.Comment); err != nil {
					return err
				}
				out = *it
				return nil
			}
		}
		return httpErr{404, "item not found"}
	})
	if err != nil {
		respondErr(w, err)
		return
	}
	writeJSON(w, 200, out)
}

func postCloseCampaign(w http.ResponseWriter, r *http.Request) {
	cid := r.PathValue("id")
	var out campaignStats
	err := store.Update(func(s *State) error {
		c := s.campaign(cid)
		if c == nil {
			return httpErr{404, "campaign not found"}
		}
		if c.Status != "active" {
			return httpErr{409, "campaign already closed"}
		}
		auto := 0
		for i := range s.CertItems {
			it := &s.CertItems[i]
			if it.CampaignID == cid && it.Decision == "pending" && c.AutoRevoke {
				s.decide("system:revoke-on-non-response", it, "revoke", "No reviewer response by close")
				auto++
			}
		}
		c.Status, c.ClosedAt = "closed", now()
		s.audit(actor(r), "cert.closed", c.ID, fmt.Sprintf("%s closed; %d undecided items auto-revoked", c.Name, auto))
		out = s.stats(*c)
		return nil
	})
	if err != nil {
		respondErr(w, err)
		return
	}
	writeJSON(w, 200, out)
}
