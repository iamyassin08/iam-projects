package main

import (
	"fmt"
	"log"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Just-in-time (JIT) privileged access, modelled on Entra PIM / CyberArk:
// nobody holds admin rights permanently. Eligible people activate a role for a
// bounded window with a justification and a change ticket; the grant expires
// on its own. Break-glass bypasses eligibility for emergencies, is capped at
// 60 minutes, and must be reviewed afterwards.

type Eligibility struct {
	IdentityID    string `json:"identityId"`
	EntitlementID string `json:"entitlementId"`
	MaxMinutes    int    `json:"maxMinutes"`
	AddedBy       string `json:"addedBy"`
	AddedAt       string `json:"addedAt"`
}

type PAMSession struct {
	ID            string `json:"id"`
	IdentityID    string `json:"identityId"`
	EntitlementID string `json:"entitlementId"`
	Justification string `json:"justification"`
	Ticket        string `json:"ticket,omitempty"`
	BreakGlass    bool   `json:"breakGlass"`
	Minutes       int    `json:"minutes"`
	Status        string `json:"status"` // active | expired | revoked
	StartedAt     string `json:"startedAt"`
	ExpiresAt     string `json:"expiresAt"`
	EndedAt       string `json:"endedAt,omitempty"`
	EndedBy       string `json:"endedBy,omitempty"`
	ReviewedBy    string `json:"reviewedBy,omitempty"`
	ReviewNotes   string `json:"reviewNotes,omitempty"`
}

const breakGlassMaxMinutes = 60

var ticketRe = regexp.MustCompile(`^(CHG|INC|RITM)\d{4,}$`)

func (s *State) eligible(identityID, entID string) *Eligibility {
	for i := range s.Eligibility {
		if s.Eligibility[i].IdentityID == identityID && s.Eligibility[i].EntitlementID == entID {
			return &s.Eligibility[i]
		}
	}
	return nil
}

func (s *State) session(id string) *PAMSession {
	for i := range s.PAMSessions {
		if s.PAMSessions[i].ID == id {
			return &s.PAMSessions[i]
		}
	}
	return nil
}

type elevateReq struct {
	IdentityID, EntitlementID, Justification, Ticket string
	Minutes                                          int
	BreakGlass                                       bool
}

func (s *State) elevate(actor string, in elevateReq) (*PAMSession, error) {
	id := s.identity(in.IdentityID)
	if id == nil || id.Status != "active" {
		return nil, httpErr{404, "active identity not found"}
	}
	e := s.entitlement(in.EntitlementID)
	if e == nil || !e.Privileged {
		return nil, httpErr{400, "JIT applies to privileged entitlements only"}
	}
	if strings.TrimSpace(in.Justification) == "" {
		return nil, httpErr{400, "a justification is required"}
	}
	if g := s.findGrant(id.ID, e.ID); g != nil {
		if g.Source == "jit" {
			return nil, httpErr{409, id.Name + " already has an active elevation for " + e.Name}
		}
		return nil, httpErr{409, id.Name + " already has standing " + e.Name + " access; remove it and use JIT instead"}
	}
	max := breakGlassMaxMinutes
	if !in.BreakGlass {
		el := s.eligible(id.ID, e.ID)
		if el == nil {
			return nil, httpErr{403, id.Name + " is not eligible for " + e.Name + ". Request eligibility, or use break-glass in an emergency"}
		}
		max = el.MaxMinutes
		in.Ticket = strings.ToUpper(strings.TrimSpace(in.Ticket))
		if !ticketRe.MatchString(in.Ticket) {
			return nil, httpErr{400, "a change or incident ticket is required (e.g. CHG0012345 or INC0045678)"}
		}
	}
	if in.Minutes <= 0 || in.Minutes > max {
		return nil, httpErr{400, fmt.Sprintf("duration must be between 1 and %d minutes", max)}
	}
	if rule := s.sodConflict(id.ID, e.ID); rule != nil {
		return nil, httpErr{409, "elevation would create an SoD conflict (" + rule.ID + ": " + rule.Description + ")"}
	}
	start := nowT()
	p := PAMSession{ID: s.nextID("PIM"), IdentityID: id.ID, EntitlementID: e.ID, Justification: in.Justification,
		Ticket: in.Ticket, BreakGlass: in.BreakGlass, Minutes: in.Minutes, Status: "active",
		StartedAt: start.Format(time.RFC3339), ExpiresAt: start.Add(time.Duration(in.Minutes) * time.Minute).Format(time.RFC3339)}
	s.PAMSessions = append(s.PAMSessions, p)
	s.Grants = append(s.Grants, Grant{IdentityID: id.ID, EntitlementID: e.ID, Source: "jit", GrantedAt: p.StartedAt, ExpiresAt: p.ExpiresAt, LastUsed: p.StartedAt})
	kind := "pam.elevated"
	if in.BreakGlass {
		kind = "pam.breakglass"
	}
	s.audit(actor, kind, p.ID, fmt.Sprintf("%s activated %s for %d min (%s) %s", id.Name, e.Name, in.Minutes, orDash(in.Ticket), in.Justification))
	return s.session(p.ID), nil
}

func (s *State) endSession(p *PAMSession, status, by string) {
	s.revoke(p.IdentityID, p.EntitlementID, "jit")
	p.Status, p.EndedAt, p.EndedBy = status, now(), by
}

// sweepExpired removes elevations whose window has passed. Returns how many ended.
func (s *State) sweepExpired() int {
	n := 0
	t := nowT()
	for i := range s.PAMSessions {
		p := &s.PAMSessions[i]
		if p.Status == "active" && !t.Before(parseT(p.ExpiresAt)) {
			s.endSession(p, "expired", "system:expiry")
			s.audit("system:expiry", "pam.expired", p.ID, fmt.Sprintf("%s for %s expired after %d min", p.EntitlementID, p.IdentityID, p.Minutes))
			n++
		}
	}
	// Belt and braces: any orphaned jit grant past its expiry is removed too.
	kept := s.Grants[:0]
	for _, g := range s.Grants {
		if g.Source == "jit" && g.ExpiresAt != "" && !t.Before(parseT(g.ExpiresAt)) {
			n++
			continue
		}
		kept = append(kept, g)
	}
	s.Grants = kept
	return n
}

func expirySweeper(every time.Duration) {
	for range time.Tick(every) {
		var n int
		store.View(func(s *State) {
			for _, p := range s.PAMSessions {
				if p.Status == "active" && !nowT().Before(parseT(p.ExpiresAt)) {
					n++
				}
			}
			for _, v := range s.Vault {
				if v.CheckedOutBy != "" && !nowT().Before(parseT(v.CheckoutExpires)) {
					n++
				}
			}
		})
		if n == 0 {
			continue
		}
		if err := store.Update(func(s *State) error { s.sweepExpired(); s.sweepCheckouts(); return nil }); err != nil {
			log.Printf("expiry sweep: %v", err)
		}
	}
}

// ---------- handlers ----------

func getPAM(w http.ResponseWriter, r *http.Request) {
	store.View(func(s *State) {
		ses := append([]PAMSession{}, s.PAMSessions...)
		sort.SliceStable(ses, func(a, b int) bool { return ses[a].StartedAt > ses[b].StartedAt })
		writeJSON(w, 200, map[string]any{"eligibility": s.Eligibility, "sessions": ses, "breakGlassMaxMinutes": breakGlassMaxMinutes, "serverTime": now()})
	})
}

func postElevate(w http.ResponseWriter, r *http.Request) {
	var in elevateReq
	if err := decode(r, &in); err != nil {
		fail(w, 400, "invalid JSON")
		return
	}
	var out PAMSession
	err := store.Update(func(s *State) error {
		p, err := s.elevate(actor(r), in)
		if err != nil {
			return err
		}
		out = *p
		return nil
	})
	if err != nil {
		respondErr(w, err)
		return
	}
	writeJSON(w, 201, out)
}

func postEndSession(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	err := store.Update(func(s *State) error {
		p := s.session(id)
		if p == nil {
			return httpErr{404, "session not found"}
		}
		if p.Status != "active" {
			return httpErr{409, "session already " + p.Status}
		}
		s.endSession(p, "revoked", actor(r))
		s.audit(actor(r), "pam.revoked", p.ID, fmt.Sprintf("Ended %s for %s early", p.EntitlementID, p.IdentityID))
		return nil
	})
	if err != nil {
		respondErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]string{"status": "revoked"})
}

func postReviewSession(w http.ResponseWriter, r *http.Request) {
	var in struct{ Notes string }
	if err := decode(r, &in); err != nil || strings.TrimSpace(in.Notes) == "" {
		fail(w, 400, "review notes are required")
		return
	}
	id := r.PathValue("id")
	err := store.Update(func(s *State) error {
		p := s.session(id)
		if p == nil {
			return httpErr{404, "session not found"}
		}
		if !p.BreakGlass {
			return httpErr{400, "only break-glass sessions need a post-use review"}
		}
		if p.ReviewedBy != "" {
			return httpErr{409, "already reviewed"}
		}
		p.ReviewedBy, p.ReviewNotes = actor(r), in.Notes
		s.audit(actor(r), "pam.reviewed", p.ID, "Break-glass reviewed: "+in.Notes)
		return nil
	})
	if err != nil {
		respondErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]string{"status": "reviewed"})
}

func postEligibility(w http.ResponseWriter, r *http.Request) {
	var in struct {
		IdentityID, EntitlementID string
		MaxMinutes                int
	}
	if err := decode(r, &in); err != nil {
		fail(w, 400, "invalid JSON")
		return
	}
	err := store.Update(func(s *State) error {
		id := s.identity(in.IdentityID)
		e := s.entitlement(in.EntitlementID)
		if id == nil || id.Status != "active" || e == nil {
			return httpErr{400, "active identity and entitlement required"}
		}
		if !e.Privileged {
			return httpErr{400, "eligibility is only for privileged entitlements"}
		}
		if in.MaxMinutes < 15 || in.MaxMinutes > 480 {
			return httpErr{400, "max duration must be 15–480 minutes"}
		}
		if s.eligible(id.ID, e.ID) != nil {
			return httpErr{409, "already eligible"}
		}
		s.Eligibility = append(s.Eligibility, Eligibility{id.ID, e.ID, in.MaxMinutes, actor(r), now()})
		s.audit(actor(r), "pam.eligibility.added", id.ID, fmt.Sprintf("%s eligible for %s (max %d min)", id.Name, e.Name, in.MaxMinutes))
		return nil
	})
	if err != nil {
		respondErr(w, err)
		return
	}
	writeJSON(w, 201, map[string]string{"status": "added"})
}

func deleteEligibility(w http.ResponseWriter, r *http.Request) {
	idn, ent := r.URL.Query().Get("identityId"), r.URL.Query().Get("entitlementId")
	err := store.Update(func(s *State) error {
		for i, e := range s.Eligibility {
			if e.IdentityID == idn && e.EntitlementID == ent {
				s.Eligibility = append(s.Eligibility[:i], s.Eligibility[i+1:]...)
				s.audit(actor(r), "pam.eligibility.removed", idn, ent+" eligibility removed")
				return nil
			}
		}
		return httpErr{404, "eligibility not found"}
	})
	if err != nil {
		respondErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]string{"status": "removed"})
}
