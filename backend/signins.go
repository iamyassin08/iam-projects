package main

import (
	"fmt"
	"math"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"
)

// Identity threat detection over the sign-in log. Every attempt against the
// built-in IdP is logged here next to a week of seeded history that hides six
// classic identity attacks. Detections are pure functions over the log (like a
// scheduled analytics rule in Sentinel); each alert carries the evidence, the
// MITRE ATT&CK technique and the KQL you would run to hunt for it.

type SignIn struct {
	ID       string   `json:"id"`
	At       string   `json:"at"`
	Username string   `json:"username"`
	App      string   `json:"app"`
	IP       string   `json:"ip"`
	City     string   `json:"city"`
	Country  string   `json:"country"`
	Device   string   `json:"device"`
	Client   string   `json:"client"` // browser | mobile | legacy-imap | legacy-smtp
	Result   string   `json:"result"` // success | failure | blocked | mfa-denied | locked
	Reason   string   `json:"reason,omitempty"`
	MFA      string   `json:"mfa"` // none | totp | push
	Risk     string   `json:"risk"`
	Policies []string `json:"policies"`
	Source   string   `json:"source"` // seed | live
}

type AlertState struct {
	AlertID string   `json:"alertId"`
	Status  string   `json:"status"` // open | investigating | closed-true-positive | closed-false-positive
	Notes   string   `json:"notes"`
	By      string   `json:"by"`
	At      string   `json:"at"`
	Actions []string `json:"actions"`
}

type Alert struct {
	ID          string   `json:"id"`
	Rule        string   `json:"rule"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"` // low | medium | high | critical
	Technique   string   `json:"technique"`
	Tactic      string   `json:"tactic"`
	User        string   `json:"user"`
	IP          string   `json:"ip"`
	FirstSeen   string   `json:"firstSeen"`
	LastSeen    string   `json:"lastSeen"`
	Summary     string   `json:"summary"`
	Evidence    []string `json:"evidence"`
	KQL         string   `json:"kql"`
	Response    []string `json:"response"`
	Status      string   `json:"status"`
	Notes       string   `json:"notes"`
	TriagedBy   string   `json:"triagedBy,omitempty"`
	TriagedAt   string   `json:"triagedAt,omitempty"`
	ActionsDone []string `json:"actionsDone"`
}

func (s *State) recordSignIn(ctx signInCtx, result, reason, mfa string, policies []string, source string) {
	if policies == nil {
		policies = []string{}
	}
	if ctx.Risk == "" {
		ctx.Risk = s.signInRisk(ctx)
	}
	s.SignIns = append(s.SignIns, SignIn{s.nextID("SI"), now(), ctx.Username, ctx.App, ctx.Location.IP, ctx.Location.City, ctx.Location.Country,
		ctx.Device, ctx.Client, result, reason, mfa, ctx.Risk, policies, source})
	if len(s.SignIns) > 3000 {
		s.SignIns = s.SignIns[len(s.SignIns)-3000:]
	}
}

// lockedUntil implements smart lockout: 5 failures in 15 minutes locks the account for 15 minutes.
func (s *State) lockedUntil(username string) time.Time {
	cut := nowT().Add(-15 * time.Minute)
	n := 0
	var last time.Time
	for _, e := range s.SignIns {
		if e.Username == username && e.Result == "failure" && parseT(e.At).After(cut) {
			n++
			last = parseT(e.At)
		}
	}
	if n >= 5 && nowT().Before(last.Add(15*time.Minute)) {
		return last.Add(15 * time.Minute)
	}
	return time.Time{}
}

// ---------- detections ----------

func haversineKm(a, b Location) float64 {
	const R = 6371.0
	toRad := func(d float64) float64 { return d * math.Pi / 180 }
	dLat, dLon := toRad(b.Lat-a.Lat), toRad(b.Lon-a.Lon)
	h := math.Sin(dLat/2)*math.Sin(dLat/2) + math.Cos(toRad(a.Lat))*math.Cos(toRad(b.Lat))*math.Sin(dLon/2)*math.Sin(dLon/2)
	return 2 * R * math.Asin(math.Sqrt(h))
}

func (s *State) detect() []Alert {
	ev := append([]SignIn{}, s.SignIns...)
	sort.SliceStable(ev, func(a, b int) bool { return ev[a].At < ev[b].At })
	out := []Alert{}
	add := func(a Alert) {
		a.ID = a.Rule + ":" + a.Evidence[0]
		a.Status, a.ActionsDone = "open", []string{}
		for _, st := range s.AlertStates {
			if st.AlertID == a.ID {
				a.Status, a.Notes, a.TriagedBy, a.TriagedAt, a.ActionsDone = st.Status, st.Notes, st.By, st.At, st.Actions
			}
		}
		out = append(out, a)
	}
	ids := func(xs []SignIn) []string {
		o := []string{}
		for _, x := range xs {
			o = append(o, x.ID)
		}
		return o
	}
	failed := func(e SignIn) bool { return e.Result == "failure" || e.Result == "locked" }

	// D1 password spray: one IP, failures against 5+ distinct accounts within 30 minutes.
	byIP := map[string][]SignIn{}
	for _, e := range ev {
		if failed(e) {
			byIP[e.IP] = append(byIP[e.IP], e)
		}
	}
	for ip, xs := range byIP {
		for i := 0; i < len(xs); {
			j := i
			users := map[string]bool{}
			for j < len(xs) && parseT(xs[j].At).Sub(parseT(xs[i].At)) <= 30*time.Minute {
				users[xs[j].Username] = true
				j++
			}
			if len(users) >= 5 {
				c := xs[i:j]
				add(Alert{Rule: "D1", Title: "Password spray from a single IP", Severity: "high", Technique: "T1110.003 Password Spraying", Tactic: "Credential Access",
					IP: ip, FirstSeen: c[0].At, LastSeen: c[len(c)-1].At, Evidence: ids(c),
					Summary:  fmt.Sprintf("%d failed sign-ins against %d different accounts from %s (%s) in %s.", len(c), len(users), ip, c[0].City, mins(parseT(c[len(c)-1].At).Sub(parseT(c[0].At)))),
					KQL:      "SigninLogs\n| where TimeGenerated > ago(7d) and ResultType != 0\n| summarize Accounts = dcount(UserPrincipalName), Attempts = count() by IPAddress, bin(TimeGenerated, 30m)\n| where Accounts >= 5",
					Response: []string{"block-ip", "Check whether any targeted account later signed in successfully from this IP", "Confirm smart lockout and banned-password list are on"}})
				i = j
			} else {
				i++
			}
		}
	}

	// D2 brute force: one account, 8+ failures within 15 minutes.
	byUser := map[string][]SignIn{}
	for _, e := range ev {
		if failed(e) {
			byUser[e.Username] = append(byUser[e.Username], e)
		}
	}
	for u, xs := range byUser {
		for i := 0; i < len(xs); {
			j := i
			for j < len(xs) && parseT(xs[j].At).Sub(parseT(xs[i].At)) <= 15*time.Minute {
				j++
			}
			if j-i >= 8 {
				c := xs[i:j]
				sev := "medium"
				for _, e := range ev {
					if e.Username == u && e.Result == "success" && e.IP == c[0].IP && e.At > c[len(c)-1].At && parseT(e.At).Sub(parseT(c[len(c)-1].At)) < time.Hour {
						sev = "critical"
					}
				}
				add(Alert{Rule: "D2", Title: "Brute force against one account", Severity: sev, Technique: "T1110.001 Password Guessing", Tactic: "Credential Access",
					User: u, IP: c[0].IP, FirstSeen: c[0].At, LastSeen: c[len(c)-1].At, Evidence: ids(c),
					Summary:  fmt.Sprintf("%d failed or locked sign-ins for %s from %s in %s. Smart lockout engaged.", len(c), u, c[0].City, mins(parseT(c[len(c)-1].At).Sub(parseT(c[0].At)))),
					KQL:      "SigninLogs\n| where TimeGenerated > ago(7d) and ResultType in (50126, 50053)\n| summarize Failures = count() by UserPrincipalName, IPAddress, bin(TimeGenerated, 15m)\n| where Failures >= 8",
					Response: []string{"block-ip", "Confirm the user still controls the account", "reset-mfa"}})
				i = j
			} else {
				i++
			}
		}
	}

	// D3 impossible travel: two successful sign-ins whose implied speed beats an airliner.
	succ := map[string][]SignIn{}
	for _, e := range ev {
		if e.Result == "success" {
			succ[e.Username] = append(succ[e.Username], e)
		}
	}
	for u, xs := range succ {
		var lastAlert time.Time // one alert per user per 24h: the return leg is the same incident
		for i := 1; i < len(xs); i++ {
			a, b := xs[i-1], xs[i]
			if !lastAlert.IsZero() && parseT(b.At).Sub(lastAlert) < 24*time.Hour {
				continue
			}
			la, lb := locByIP(a.IP), locByIP(b.IP)
			if la == nil || lb == nil || la.Country == lb.Country {
				continue
			}
			km := haversineKm(*la, *lb)
			hrs := parseT(b.At).Sub(parseT(a.At)).Hours()
			if km > 500 && (hrs <= 0 || km/hrs > 900) {
				lastAlert = parseT(b.At)
				add(Alert{Rule: "D3", Title: "Impossible travel", Severity: "high", Technique: "T1078 Valid Accounts", Tactic: "Initial Access",
					User: u, IP: b.IP, FirstSeen: a.At, LastSeen: b.At, Evidence: []string{a.ID, b.ID},
					Summary:  fmt.Sprintf("%s signed in from %s, then %s %.0f minutes later: %.0f km, about %.0f km/h.", u, a.City, b.City, hrs*60, km, km/math.Max(hrs, 0.01)),
					KQL:      "SigninLogs\n| where ResultType == 0\n| project TimeGenerated, UserPrincipalName, IPAddress, Lat = toreal(LocationDetails.geoCoordinates.latitude), Lon = toreal(LocationDetails.geoCoordinates.longitude)\n| sort by UserPrincipalName asc, TimeGenerated asc\n| extend PrevLat = prev(Lat), PrevLon = prev(Lon), PrevTime = prev(TimeGenerated), PrevUser = prev(UserPrincipalName)\n| where UserPrincipalName == PrevUser\n| extend Km = geo_distance_2points(Lon, Lat, PrevLon, PrevLat) / 1000, Hours = datetime_diff('minute', TimeGenerated, PrevTime) / 60.0\n| where Km > 500 and Km / Hours > 900",
					Response: []string{"revoke-sessions", "Contact the user out of band: are they travelling or on a VPN?", "reset-mfa", "block-ip"}})
			}
		}
	}

	// D4 MFA fatigue: 5+ denied MFA prompts within 30 minutes.
	mfaDen := map[string][]SignIn{}
	for _, e := range ev {
		if e.Result == "mfa-denied" {
			mfaDen[e.Username] = append(mfaDen[e.Username], e)
		}
	}
	for u, xs := range mfaDen {
		for i := 0; i < len(xs); {
			j := i
			for j < len(xs) && parseT(xs[j].At).Sub(parseT(xs[i].At)) <= 30*time.Minute {
				j++
			}
			if j-i >= 5 {
				c := xs[i:j]
				sev, tail := "high", ""
				for _, e := range ev {
					if e.Username == u && e.Result == "success" && e.MFA != "none" && e.At > c[len(c)-1].At && parseT(e.At).Sub(parseT(c[len(c)-1].At)) < 30*time.Minute {
						sev, tail = "critical", " The user then approved a prompt: treat the account as compromised."
						c = append(append([]SignIn{}, c...), e)
						break
					}
				}
				add(Alert{Rule: "D4", Title: "MFA fatigue (prompt bombing)", Severity: sev, Technique: "T1621 Multi-Factor Authentication Request Generation", Tactic: "Credential Access",
					User: u, IP: c[0].IP, FirstSeen: c[0].At, LastSeen: c[len(c)-1].At, Evidence: ids(c),
					Summary:  fmt.Sprintf("%d MFA prompts denied for %s from %s within %s.%s", j-i, u, c[0].City, mins(parseT(xs[j-1].At).Sub(parseT(xs[i].At))), tail),
					KQL:      "SigninLogs\n| where ResultType == 500121  // MFA denied\n| summarize Denied = count(), IPs = make_set(IPAddress) by UserPrincipalName, bin(TimeGenerated, 30m)\n| where Denied >= 5",
					Response: []string{"revoke-sessions", "reset-mfa", "block-ip", "Move the user to number matching or phishing-resistant MFA"}})
				i = j
			} else {
				i++
			}
		}
	}

	// D5 legacy authentication succeeded (basic auth can't do MFA).
	for _, e := range ev {
		if strings.HasPrefix(e.Client, "legacy") && e.Result == "success" {
			add(Alert{Rule: "D5", Title: "Legacy authentication succeeded", Severity: "medium", Technique: "T1078 Valid Accounts", Tactic: "Defense Evasion",
				User: e.Username, IP: e.IP, FirstSeen: e.At, LastSeen: e.At, Evidence: []string{e.ID},
				Summary:  fmt.Sprintf("%s signed in to %s over %s from %s. Legacy protocols bypass MFA and Conditional Access grant controls.", e.Username, e.App, e.Client, e.City),
				KQL:      "SigninLogs\n| where ClientAppUsed in (\"IMAP4\", \"POP3\", \"Authenticated SMTP\", \"Exchange ActiveSync\", \"Other clients\")\n| where ResultType == 0\n| summarize count() by UserPrincipalName, ClientAppUsed, IPAddress",
				Response: []string{"Turn on CA003 Block legacy authentication", "revoke-sessions"}})
		}
	}

	// D6 sign-in by an account with no active HR identity (orphan, or a leaver after termination).
	known := map[string]*Identity{}
	for i := range s.Identities {
		known[strings.SplitN(s.Identities[i].Email, "@", 2)[0]] = &s.Identities[i]
	}
	orphanHits := map[string][]SignIn{}
	order := []string{}
	for _, e := range ev {
		if e.Result != "success" || strings.HasPrefix(e.Username, "svc-") {
			continue
		}
		if u := s.idpUser(e.Username); u != nil && u.BreakGlass {
			continue
		}
		id := known[e.Username]
		if id == nil || (id.Status == "terminated" && e.At > id.Updated) {
			if orphanHits[e.Username] == nil {
				order = append(order, e.Username)
			}
			orphanHits[e.Username] = append(orphanHits[e.Username], e)
		}
	}
	for _, u := range order {
		xs := orphanHits[u]
		e := xs[len(xs)-1]
		why := "has no identity in Workday. Likely an orphaned account that deprovisioning missed."
		if known[u] != nil {
			why = "was terminated in HR before this sign-in. Deprovisioning did not reach this app."
		}
		add(Alert{Rule: "D6", Title: "Sign-in by an account with no active HR record", Severity: "high", Technique: "T1078.003 Local Accounts", Tactic: "Persistence",
			User: u, IP: e.IP, FirstSeen: xs[0].At, LastSeen: e.At, Evidence: ids(xs),
			Summary:  fmt.Sprintf("%s signed in to %s from %s (%d time(s)) but %s", u, e.App, e.City, len(xs), why),
			KQL:      "let hr = externaldata(upn:string) [@\"https://hr-export/active.csv\"];\nSigninLogs\n| where ResultType == 0 and UserPrincipalName !in (hr)\n| summarize LastSeen = max(TimeGenerated) by UserPrincipalName, AppDisplayName",
			Response: []string{"disable-user", "Disable the account in the target app (Risk & reconciliation)", "Find who created it"}})
	}

	// D7 break-glass account used: always alert, it should be a rare and reviewed event.
	for _, e := range ev {
		if u := s.idpUser(e.Username); u != nil && u.BreakGlass && (e.Result == "success" || e.Result == "failure") {
			add(Alert{Rule: "D7", Title: "Emergency access (break-glass) account used", Severity: "critical", Technique: "T1078.004 Cloud Accounts", Tactic: "Privilege Escalation",
				User: e.Username, IP: e.IP, FirstSeen: e.At, LastSeen: e.At, Evidence: []string{e.ID},
				Summary:  fmt.Sprintf("Break-glass account %s attempted sign-in (%s) from %s. Confirm there is a declared emergency.", e.Username, e.Result, e.City),
				KQL:      "SigninLogs\n| where UserPrincipalName in (\"bg.admin@assafwah.demo\")\n| project TimeGenerated, ResultType, IPAddress, AppDisplayName",
				Response: []string{"Confirm an incident ticket exists", "Rotate the break-glass credential after use", "revoke-sessions"}})
		}
	}

	rank := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}
	sort.SliceStable(out, func(a, b int) bool {
		if (out[a].Status == "open") != (out[b].Status == "open") {
			return out[a].Status == "open"
		}
		if rank[out[a].Severity] != rank[out[b].Severity] {
			return rank[out[a].Severity] < rank[out[b].Severity]
		}
		return out[a].LastSeen > out[b].LastSeen
	})
	return out
}

// ---------- API ----------

func registerMonitoring(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/monitoring", getMonitoring)
	mux.HandleFunc("POST /api/monitoring/alerts/{id}", postTriage)
}

func getMonitoring(w http.ResponseWriter, r *http.Request) {
	store.View(func(s *State) {
		ev := append([]SignIn{}, s.SignIns...)
		sort.SliceStable(ev, func(a, b int) bool { return ev[a].At > ev[b].At })
		// 6-hour buckets over the last 7 days
		start := nowT().Truncate(6 * time.Hour).Add(-27 * 6 * time.Hour)
		buckets := make([]map[string]any, 28)
		for i := range buckets {
			buckets[i] = map[string]any{"start": fmtT(start.Add(time.Duration(i) * 6 * time.Hour)), "success": 0, "failure": 0, "blocked": 0, "mfaDenied": 0}
		}
		countries, users := map[string]int{}, map[string]bool{}
		fails, mfa, succ := 0, 0, 0
		for _, e := range ev {
			t := parseT(e.At)
			if t.Before(start) {
				continue
			}
			i := int(t.Sub(start) / (6 * time.Hour))
			if i >= 0 && i < 28 {
				k := map[string]string{"success": "success", "failure": "failure", "locked": "failure", "blocked": "blocked", "mfa-denied": "mfaDenied"}[e.Result]
				buckets[i][k] = buckets[i][k].(int) + 1
			}
			countries[e.Country]++
			users[e.Username] = true
			switch e.Result {
			case "success":
				succ++
				if e.MFA != "none" {
					mfa++
				}
			case "failure", "locked", "mfa-denied", "blocked":
				fails++
			}
		}
		n := len(ev)
		if n > 400 {
			ev = ev[:400]
		}
		mfaPct := 0
		if succ > 0 {
			mfaPct = mfa * 100 / succ
		}
		writeJSON(w, 200, map[string]any{
			"signIns": ev, "alerts": s.detect(), "timeline": buckets, "countries": countries,
			"stats": map[string]int{"total": n, "failed": fails, "users": len(users), "mfaPercent": mfaPct, "countries": len(countries)},
		})
	})
}

func postTriage(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Status, Notes string
		Actions       []string
	}
	if err := decode(r, &in); err != nil || !slices.Contains([]string{"open", "investigating", "closed-true-positive", "closed-false-positive"}, in.Status) {
		fail(w, 400, "status must be open, investigating, closed-true-positive or closed-false-positive")
		return
	}
	if strings.HasPrefix(in.Status, "closed") && strings.TrimSpace(in.Notes) == "" {
		fail(w, 400, "closing an alert requires investigation notes")
		return
	}
	id := r.PathValue("id")
	var out Alert
	err := store.Update(func(s *State) error {
		var a *Alert
		for _, x := range s.detect() {
			if x.ID == id {
				a = &x
				break
			}
		}
		if a == nil {
			return httpErr{404, "alert not found"}
		}
		done := []string{}
		for _, act := range in.Actions {
			switch act {
			case "block-ip":
				if a.IP != "" && !slices.Contains(s.BlockedIPs, a.IP) {
					s.BlockedIPs = append(s.BlockedIPs, a.IP)
					s.audit(actor(r), "ca.namedlocation.updated", "blocked-ips", "Blocked "+a.IP+" from alert "+a.ID)
				}
				done = append(done, "Blocked IP "+a.IP+" (CA006)")
			case "revoke-sessions":
				if a.User != "" {
					revokeSessions(a.User)
					s.audit(actor(r), "idp.sessions.revoked", a.User, "All sessions and refresh tokens revoked from alert "+a.ID)
					done = append(done, "Revoked sessions for "+a.User)
				}
			case "reset-mfa":
				if u := s.idpUser(a.User); u != nil {
					u.MFAEnrolled, u.TOTPSecret, u.MFAMethod = false, "", ""
					s.audit(actor(r), "mfa.reset", u.Username, "MFA reset from alert "+a.ID)
					done = append(done, "Reset MFA for "+a.User)
				} else {
					done = append(done, "MFA reset requested for "+a.User+" (directory ticket)")
				}
			case "disable-user":
				if u := s.idpUser(a.User); u != nil {
					u.Disabled = true
				}
				revokeSessions(a.User)
				s.audit(actor(r), "idp.user.disabled", a.User, "Disabled from alert "+a.ID)
				done = append(done, "Disabled "+a.User)
			}
		}
		prev := []string{}
		for i, st := range s.AlertStates {
			if st.AlertID == id {
				prev = st.Actions
				s.AlertStates = append(s.AlertStates[:i], s.AlertStates[i+1:]...)
				break
			}
		}
		s.AlertStates = append(s.AlertStates, AlertState{id, in.Status, in.Notes, actor(r), now(), append(prev, done...)})
		s.audit(actor(r), "alert."+in.Status, id, a.Title+": "+in.Notes)
		a.Status, a.Notes = in.Status, in.Notes
		out = *a
		return nil
	})
	if err != nil {
		respondErr(w, err)
		return
	}
	writeJSON(w, 200, out)
}

func mins(d time.Duration) string {
	m := int(d.Round(time.Minute).Minutes())
	if m < 1 {
		return "under a minute"
	}
	return fmt.Sprintf("%d min", m)
}
