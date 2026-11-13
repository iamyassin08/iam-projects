package main

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"strings"
)

// HR feed reconciliation: the same job scripts/iamctl.py does over the API,
// built into the server so it can be previewed in the browser. Each CSV row is
// compared with the directory and turned into a plan of joiner / mover /
// update / leaver actions. Dry-run first, then apply through the one lifecycle
// code path the UI and SCIM use.

type feedAction struct {
	Row        int      `json:"row"`
	Action     string   `json:"action"` // joiner | mover | update | leaver | noop | skip | error
	EmployeeID string   `json:"employeeId"`
	Name       string   `json:"name"`
	Changes    []string `json:"changes"`
	Detail     string   `json:"detail"`
}

var feedCols = []string{"employee_id", "name", "email", "department", "title", "manager", "role_id", "status"}

func (s *State) planFeed(text string) ([]feedAction, []string, error) {
	rd := csv.NewReader(strings.NewReader(strings.TrimSpace(text)))
	rd.TrimLeadingSpace = true
	rows, err := rd.ReadAll()
	if err != nil {
		return nil, nil, httpErr{400, "CSV parse error: " + err.Error()}
	}
	if len(rows) < 2 {
		return nil, nil, httpErr{400, "the feed needs a header row and at least one employee"}
	}
	col := map[string]int{}
	for i, h := range rows[0] {
		col[strings.ToLower(strings.TrimSpace(h))] = i
	}
	for _, c := range feedCols {
		if _, ok := col[c]; !ok {
			return nil, nil, httpErr{400, "missing column: " + c + " (expected " + strings.Join(feedCols, ",") + ")"}
		}
	}
	get := func(r []string, c string) string {
		if col[c] < len(r) {
			return strings.TrimSpace(r[col[c]])
		}
		return ""
	}
	plan := []feedAction{}
	seen := map[string]bool{}
	for n, r := range rows[1:] {
		a := feedAction{Row: n + 2, EmployeeID: get(r, "employee_id"), Name: get(r, "name"), Changes: []string{}}
		status := strings.ToLower(get(r, "status"))
		var id *Identity
		for i := range s.Identities {
			if (a.EmployeeID != "" && s.Identities[i].ExternalID == a.EmployeeID) || strings.EqualFold(s.Identities[i].Email, get(r, "email")) {
				id = &s.Identities[i]
			}
		}
		if id != nil {
			seen[id.ID] = true
		}
		switch {
		case a.EmployeeID == "" || a.Name == "":
			a.Action, a.Detail = "error", "employee_id and name are required"
		case status != "active" && status != "terminated":
			a.Action, a.Detail = "error", "status must be active or terminated"
		case id == nil && status == "terminated":
			a.Action, a.Detail = "skip", "terminated in HR and never provisioned"
		case id == nil:
			if s.role(get(r, "role_id")) == nil {
				a.Action, a.Detail = "error", "unknown role_id "+get(r, "role_id")
				break
			}
			a.Action, a.Detail = "joiner", "create identity and grant birthright access for "+s.role(get(r, "role_id")).Name
		case id.Status == "terminated" && status == "active":
			a.Action, a.Detail = "skip", "rehire: needs manual review (Joiner · Mover · Leaver → Rehire) so old access isn't silently restored"
		case id.Status == "active" && status == "terminated":
			a.Action, a.Detail = "leaver", fmt.Sprintf("terminate %s and revoke %d grants", id.Name, len(s.grantsFor(id.ID)))
		case id.Status == "terminated":
			a.Action, a.Detail = "noop", "already terminated"
		default:
			if rid := get(r, "role_id"); rid != id.RoleID {
				if s.role(rid) == nil {
					a.Action, a.Detail = "error", "unknown role_id "+rid
					break
				}
				a.Action = "mover"
				a.Changes = append(a.Changes, fmt.Sprintf("role: %s → %s", s.role(id.RoleID).Name, s.role(rid).Name))
			}
			if v := get(r, "title"); v != "" && v != id.Title {
				a.Changes = append(a.Changes, fmt.Sprintf("title: %s → %s", id.Title, v))
			}
			if v := get(r, "department"); v != "" && v != id.Department {
				a.Changes = append(a.Changes, fmt.Sprintf("department: %s → %s", id.Department, v))
			}
			if v := get(r, "manager"); v != "" && v != id.Manager {
				a.Changes = append(a.Changes, fmt.Sprintf("manager: %s → %s", id.Manager, v))
			}
			switch {
			case a.Action == "mover":
				a.Detail = "role change: revoke old role access, grant new birthright"
			case len(a.Changes) > 0:
				a.Action, a.Detail = "update", "attribute update only (access unchanged)"
			default:
				a.Action, a.Detail = "noop", "in sync"
			}
		}
		plan = append(plan, a)
	}
	warnings := []string{}
	for _, i := range s.Identities {
		if i.Status == "active" && !seen[i.ID] {
			warnings = append(warnings, fmt.Sprintf("%s (%s) is active in IAM but missing from the feed. Not auto-terminated: confirm with HR first.", i.Name, i.ExternalID))
		}
	}
	return plan, warnings, nil
}

func (s *State) applyFeed(actor, text string) ([]feedAction, []string, error) {
	plan, warn, err := s.planFeed(text)
	if err != nil {
		return nil, nil, err
	}
	rd := csv.NewReader(strings.NewReader(strings.TrimSpace(text)))
	rd.TrimLeadingSpace = true
	rows, _ := rd.ReadAll()
	col := map[string]int{}
	for i, h := range rows[0] {
		col[strings.ToLower(strings.TrimSpace(h))] = i
	}
	get := func(r []string, c string) string {
		if col[c] < len(r) {
			return strings.TrimSpace(r[col[c]])
		}
		return ""
	}
	by := actor + " via hr-feed"
	for i := range plan {
		a := &plan[i]
		r := rows[a.Row-1]
		var id *Identity
		for j := range s.Identities {
			if s.Identities[j].ExternalID == a.EmployeeID || strings.EqualFold(s.Identities[j].Email, get(r, "email")) {
				id = &s.Identities[j]
			}
		}
		var e error
		switch a.Action {
		case "joiner":
			_, e = s.createIdentity(by, newIdentity{a.Name, get(r, "email"), get(r, "department"), get(r, "title"), get(r, "manager"), get(r, "role_id"), "", a.EmployeeID})
		case "mover":
			_, e = s.moveIdentity(by, id.ID, get(r, "role_id"), get(r, "title"), get(r, "department"))
			if e == nil && get(r, "manager") != "" {
				id.Manager = get(r, "manager")
			}
		case "update":
			id.Title, id.Department = orDefault(get(r, "title"), id.Title), orDefault(get(r, "department"), id.Department)
			id.Manager, id.Updated = orDefault(get(r, "manager"), id.Manager), now()
			s.audit(by, "identity.updated", id.ID, strings.Join(a.Changes, "; "))
		case "leaver":
			_, e = s.terminateIdentity(by, id.ID, "")
		}
		if e != nil {
			a.Action, a.Detail = "error", e.Error()
		}
	}
	s.audit(actor, "hrfeed.applied", "hr-feed", fmt.Sprintf("Processed %d rows", len(plan)))
	return plan, warn, nil
}

func registerFeed(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/automation/hr-feed", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			CSV   string `json:"csv"`
			Apply bool   `json:"apply"`
		}
		if err := decode(r, &in); err != nil {
			fail(w, 400, "invalid JSON")
			return
		}
		var plan []feedAction
		var warn []string
		var err error
		if in.Apply {
			err = store.Update(func(s *State) (e error) { plan, warn, e = s.applyFeed(actor(r), in.CSV); return })
		} else {
			store.View(func(s *State) { plan, warn, err = s.planFeed(in.CSV) })
		}
		if err != nil {
			respondErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"plan": plan, "warnings": warn, "applied": in.Apply})
	})
	mux.HandleFunc("GET /api/automation/hr-feed/sample", func(w http.ResponseWriter, r *http.Request) {
		store.View(func(s *State) {
			var b strings.Builder
			b.WriteString(strings.Join(feedCols, ",") + "\n")
			for _, i := range s.Identities {
				if i.Status != "active" {
					continue
				}
				role, title, dept, status := i.RoleID, i.Title, i.Department, "active"
				switch i.ID {
				case "ID-2": // mover: sales → engineering
					role, title, dept = "r-eng", "Solutions Engineer", "Engineering"
				case "ID-5": // leaver
					status = "terminated"
				case "ID-6":
					title = "Senior Service Desk Analyst"
				}
				fmt.Fprintf(&b, "%s,%s,%s,%s,%s,%s,%s,%s\n", i.ExternalID, i.Name, i.Email, dept, title, i.Manager, role, status)
			}
			b.WriteString("WD-10300,Amina Yusuf,amina.yusuf@demo.local,Finance,AP Specialist,Grace Kim,r-ap,active\n")
			b.WriteString("WD-10301,Tom Becker,tom.becker@demo.local,Sales,Account Executive,Leila Nasser,r-sales,terminated\n")
			w.Header().Set("Content-Type", "text/csv")
			_, _ = w.Write([]byte(b.String()))
		})
	})
}
