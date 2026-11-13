package main

import (
	"net/http"
	"slices"
	"strings"
	"time"
)

// Conditional Access, modelled on Entra ID: each policy has assignments
// (users/groups, apps), conditions (location, client app, device, sign-in
// risk) and a grant control (block or require MFA). Policies can be On,
// Report-only (evaluated and logged, never enforced) or Off. Block wins over
// MFA; MFA wins over allow.

type CAPolicy struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Description   string   `json:"description"`
	State         string   `json:"state"` // on | report-only | off
	IncludeGroups []string `json:"includeGroups"`
	ExcludeGroups []string `json:"excludeGroups"`
	Apps          []string `json:"apps"`
	ClientApps    []string `json:"clientApps,omitempty"`   // e.g. legacy
	Countries     []string `json:"countries,omitempty"`    // applies when sign-in country is in list
	NotCountries  []string `json:"notCountries,omitempty"` // applies when country is NOT in list (trusted locations)
	BlockedIPs    bool     `json:"blockedIps,omitempty"`   // applies when IP is on the blocked named location
	RiskLevels    []string `json:"riskLevels,omitempty"`
	Devices       []string `json:"devices,omitempty"` // managed | unmanaged
	Grant         string   `json:"grant"`             // block | mfa
}

type signInCtx struct {
	Username   string   `json:"username"`
	Groups     []string `json:"groups"`
	App        string   `json:"app"`
	Location   Location `json:"location"`
	Device     string   `json:"device"`
	Client     string   `json:"client"`
	Risk       string   `json:"risk"`
	BreakGlass bool     `json:"breakGlass"`
}

type caResult struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	State   string   `json:"state"`
	Applies bool     `json:"applies"`
	Grant   string   `json:"grant"`
	Why     []string `json:"why"`
}

type caEval struct {
	Decision   string     `json:"decision"` // allow | mfa | block
	BlockedBy  []string   `json:"blockedBy"`
	MFABy      []string   `json:"mfaBy"`
	ReportOnly []string   `json:"reportOnly"`
	Applied    []string   `json:"applied"`
	Risk       string     `json:"risk"`
	Results    []caResult `json:"results"`
}

func (s *State) caPolicy(id string) *CAPolicy {
	for i := range s.CAPolicies {
		if s.CAPolicies[i].ID == id {
			return &s.CAPolicies[i]
		}
	}
	return nil
}

func inAny(list, have []string) bool {
	for _, x := range list {
		if x == "all" || slices.Contains(have, x) {
			return true
		}
	}
	return false
}

func (s *State) evaluateCA(ctx signInCtx) caEval {
	ev := caEval{Decision: "allow", BlockedBy: []string{}, MFABy: []string{}, ReportOnly: []string{}, Applied: []string{}, Risk: ctx.Risk, Results: []caResult{}}
	for _, p := range s.CAPolicies {
		r := caResult{ID: p.ID, Name: p.Name, State: p.State, Grant: p.Grant, Applies: true, Why: []string{}}
		miss := func(why string) { r.Applies = false; r.Why = append(r.Why, "✗ "+why) }
		hit := func(why string) { r.Why = append(r.Why, "✓ "+why) }

		if p.State == "off" {
			miss("policy is off")
		}
		if inAny(p.IncludeGroups, ctx.Groups) {
			hit("user in " + strings.Join(p.IncludeGroups, ", "))
		} else {
			miss("user not in " + strings.Join(p.IncludeGroups, ", "))
		}
		if len(p.ExcludeGroups) > 0 && inAny(p.ExcludeGroups, ctx.Groups) {
			miss("user excluded (" + strings.Join(p.ExcludeGroups, ", ") + ")")
		}
		if !(slices.Contains(p.Apps, "all") || slices.Contains(p.Apps, ctx.App)) {
			miss("app " + ctx.App + " not targeted")
		}
		if len(p.ClientApps) > 0 {
			if slices.ContainsFunc(p.ClientApps, func(c string) bool { return strings.HasPrefix(ctx.Client, c) }) {
				hit("client app is " + ctx.Client)
			} else {
				miss("client app " + ctx.Client + " not in scope")
			}
		}
		if len(p.Countries) > 0 {
			if slices.Contains(p.Countries, ctx.Location.Country) {
				hit("location " + ctx.Location.CountryName + " is in scope")
			} else {
				miss("location " + ctx.Location.CountryName + " not in scope")
			}
		}
		if len(p.NotCountries) > 0 {
			if slices.Contains(p.NotCountries, ctx.Location.Country) {
				miss("trusted location (" + ctx.Location.CountryName + ")")
			} else {
				hit("outside trusted locations (" + ctx.Location.CountryName + ")")
			}
		}
		if p.BlockedIPs {
			if slices.Contains(s.BlockedIPs, ctx.Location.IP) {
				hit("IP " + ctx.Location.IP + " is on the blocked list")
			} else {
				miss("IP not on the blocked list")
			}
		}
		if len(p.RiskLevels) > 0 {
			if slices.Contains(p.RiskLevels, ctx.Risk) {
				hit("sign-in risk is " + ctx.Risk)
			} else {
				miss("sign-in risk " + ctx.Risk + " below threshold")
			}
		}
		if len(p.Devices) > 0 {
			if slices.Contains(p.Devices, ctx.Device) {
				hit("device is " + ctx.Device)
			} else {
				miss("device is " + ctx.Device)
			}
		}
		ev.Results = append(ev.Results, r)
		if !r.Applies {
			continue
		}
		if p.State == "report-only" {
			ev.ReportOnly = append(ev.ReportOnly, p.ID+" would "+p.Grant)
			continue
		}
		ev.Applied = append(ev.Applied, p.ID)
		if p.Grant == "block" {
			ev.BlockedBy = append(ev.BlockedBy, p.ID+" "+p.Name)
		} else {
			ev.MFABy = append(ev.MFABy, p.ID+" "+p.Name)
		}
	}
	switch {
	case len(ev.BlockedBy) > 0:
		ev.Decision = "block"
	case len(ev.MFABy) > 0:
		ev.Decision = "mfa"
	}
	return ev
}

// signInRisk is a simple, explainable stand-in for Entra ID Protection.
func (s *State) signInRisk(ctx signInCtx) string {
	if ctx.Location.Anonymizer || slices.Contains(s.BlockedIPs, ctx.Location.IP) {
		return "high"
	}
	recent := 0
	cut := nowT().Add(-30 * time.Minute)
	for _, e := range s.SignIns {
		if e.Username == ctx.Username && e.Result != "success" && parseT(e.At).After(cut) {
			recent++
		}
	}
	if ctx.Location.Country != "US" || recent >= 3 {
		return "medium"
	}
	return "low"
}

// ---------- API ----------

func registerCA(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/ca", func(w http.ResponseWriter, r *http.Request) {
		store.View(func(s *State) {
			writeJSON(w, 200, map[string]any{"policies": s.CAPolicies, "blockedIps": s.BlockedIPs, "locations": Locations})
		})
	})
	mux.HandleFunc("PUT /api/ca/policies/{id}", func(w http.ResponseWriter, r *http.Request) {
		var in struct{ State string }
		if err := decode(r, &in); err != nil || !slices.Contains([]string{"on", "report-only", "off"}, in.State) {
			fail(w, 400, "state must be on, report-only or off")
			return
		}
		var out CAPolicy
		err := store.Update(func(s *State) error {
			p := s.caPolicy(r.PathValue("id"))
			if p == nil {
				return httpErr{404, "policy not found"}
			}
			old := p.State
			p.State = in.State
			s.audit(actor(r), "ca.policy.updated", p.ID, p.Name+": "+old+" → "+in.State)
			out = *p
			return nil
		})
		if err != nil {
			respondErr(w, err)
			return
		}
		writeJSON(w, 200, out)
	})
	mux.HandleFunc("POST /api/ca/whatif", func(w http.ResponseWriter, r *http.Request) {
		var in pwIn
		_ = decode(r, &in)
		store.View(func(s *State) {
			ctx := signInCtx{Username: strings.ToLower(in.Username), App: orDefault(r.URL.Query().Get("app"), "iam-projects"),
				Location: locByKey(in.Location), Device: orDefault(in.Device, "managed"), Client: orDefault(in.Client, "browser")}
			if u := s.idpUser(ctx.Username); u != nil {
				ctx.Groups, ctx.BreakGlass = u.Groups, u.BreakGlass
			}
			ctx.Risk = s.signInRisk(ctx)
			writeJSON(w, 200, s.evaluateCA(ctx))
		})
	})
	mux.HandleFunc("DELETE /api/ca/blocked-ips/{ip}", func(w http.ResponseWriter, r *http.Request) {
		_ = store.Update(func(s *State) error {
			s.BlockedIPs = slices.DeleteFunc(s.BlockedIPs, func(x string) bool { return x == r.PathValue("ip") })
			s.audit(actor(r), "ca.namedlocation.updated", "blocked-ips", "Removed "+r.PathValue("ip"))
			return nil
		})
		writeJSON(w, 200, map[string]string{"status": "removed"})
	})
}
