package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// SCIM 2.0 service provider (RFC 7643 schema, RFC 7644 protocol).
//
// Users  ↔ identities. POST = joiner, PATCH active=false or DELETE = leaver,
//          PATCH active=true = rehire. Every change runs through the same
//          lifecycle code as the JML screen, so controls apply equally.
// Groups ↔ roles. Adding a member to a group moves that identity into the
//          role (mover); removing them strips role-based access.
//
// Auth is a bearer token. Only a SHA-256 hash is stored; the plaintext is shown
// once at creation, the way Entra ID / Okta provisioning secrets work.

const (
	schemaUser       = "urn:ietf:params:scim:schemas:core:2.0:User"
	schemaGroup      = "urn:ietf:params:scim:schemas:core:2.0:Group"
	schemaEnterprise = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
	schemaList       = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	schemaPatch      = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	schemaError      = "urn:ietf:params:scim:api:messages:2.0:Error"
	scimBase         = "/scim/v2"
)

type SCIMToken struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Prefix    string `json:"prefix"`
	HashStore string `json:"hash,omitempty"` // SHA-256 of the token; persisted, never returned by the API
	CreatedBy string `json:"createdBy"`
	CreatedAt string `json:"createdAt"`
	LastUsed  string `json:"lastUsed,omitempty"`
	Requests  int    `json:"requests"`
	Revoked   bool   `json:"revoked"`
}

func hashToken(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

// ---------- token admin (/api/scim/tokens) ----------

func getTokens(w http.ResponseWriter, r *http.Request) {
	store.View(func(s *State) {
		out := []map[string]any{}
		for _, t := range s.SCIMTokens {
			out = append(out, map[string]any{"id": t.ID, "name": t.Name, "prefix": t.Prefix, "createdBy": t.CreatedBy,
				"createdAt": t.CreatedAt, "lastUsed": t.LastUsed, "requests": t.Requests, "revoked": t.Revoked,
				"ageDays": int(nowT().Sub(parseT(t.CreatedAt)).Hours() / 24)})
		}
		writeJSON(w, 200, out)
	})
}

func postToken(w http.ResponseWriter, r *http.Request) {
	var in struct{ Name string }
	if err := decode(r, &in); err != nil || strings.TrimSpace(in.Name) == "" {
		fail(w, 400, "a token name is required (e.g. \"Entra ID provisioning\")")
		return
	}
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		fail(w, 500, "could not generate token")
		return
	}
	plain := "scim_" + hex.EncodeToString(buf)
	if len(in.Name) > 80 {
		in.Name = in.Name[:80]
	}
	var tok SCIMToken
	err := store.Update(func(s *State) error {
		if err := s.atCapacity("token"); err != nil {
			return err
		}
		tok = SCIMToken{ID: s.nextID("TOK"), Name: in.Name, Prefix: plain[:12], HashStore: hashToken(plain), CreatedBy: actor(r), CreatedAt: now()}
		s.SCIMTokens = append(s.SCIMTokens, tok)
		s.audit(actor(r), "scim.token.created", tok.ID, fmt.Sprintf("%s (%s…)", tok.Name, tok.Prefix))
		return nil
	})
	if err != nil {
		respondErr(w, err)
		return
	}
	writeJSON(w, 201, map[string]any{"id": tok.ID, "name": tok.Name, "prefix": tok.Prefix, "token": plain,
		"note": "Copy this now. Only a SHA-256 hash is stored, so it cannot be shown again."})
}

func deleteToken(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	err := store.Update(func(s *State) error {
		for i := range s.SCIMTokens {
			if s.SCIMTokens[i].ID == id {
				s.SCIMTokens[i].Revoked = true
				s.audit(actor(r), "scim.token.revoked", id, s.SCIMTokens[i].Name)
				return nil
			}
		}
		return httpErr{404, "token not found"}
	})
	if err != nil {
		respondErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]string{"status": "revoked"})
}

// ---------- protocol plumbing ----------

func scimJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func scimErr(w http.ResponseWriter, code int, scimType, detail string) {
	body := map[string]any{"schemas": []string{schemaError}, "status": strconv.Itoa(code), "detail": detail}
	if scimType != "" {
		body["scimType"] = scimType
	}
	scimJSON(w, code, body)
}

func scimFromErr(w http.ResponseWriter, err error) {
	if he, ok := err.(httpErr); ok {
		t := ""
		if he.code == 409 {
			t = "uniqueness"
		}
		scimErr(w, he.code, t, he.msg)
		return
	}
	scimErr(w, 500, "", err.Error())
}

type scimHandler func(w http.ResponseWriter, r *http.Request, actor string)

// scimAuth validates the bearer token in constant time and records usage.
func scimAuth(h scimHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw := strings.TrimSpace(r.Header.Get("Authorization"))
		if !strings.HasPrefix(strings.ToLower(raw), "bearer ") {
			w.Header().Set("WWW-Authenticate", `Bearer realm="scim"`)
			scimErr(w, 401, "", "missing bearer token")
			return
		}
		want := hashToken(strings.TrimSpace(raw[7:]))
		name := ""
		_ = store.Update(func(s *State) error {
			for i := range s.SCIMTokens {
				t := &s.SCIMTokens[i]
				if !t.Revoked && subtle.ConstantTimeCompare([]byte(t.HashStore), []byte(want)) == 1 {
					t.LastUsed, name = now(), t.Name
					t.Requests++
				}
			}
			return nil
		})
		if name == "" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="scim", error="invalid_token"`)
			scimErr(w, 401, "", "invalid or revoked token")
			return
		}
		h(w, r, "scim:"+name)
	}
}

func registerSCIM(mux *http.ServeMux) {
	mux.HandleFunc("GET "+scimBase+"/ServiceProviderConfig", scimAuth(scimSPConfig))
	mux.HandleFunc("GET "+scimBase+"/ResourceTypes", scimAuth(scimResourceTypes))
	mux.HandleFunc("GET "+scimBase+"/Schemas", scimAuth(scimSchemas))
	mux.HandleFunc("GET "+scimBase+"/Users", scimAuth(scimListUsers))
	mux.HandleFunc("POST "+scimBase+"/Users", scimAuth(scimCreateUser))
	mux.HandleFunc("GET "+scimBase+"/Users/{id}", scimAuth(scimGetUser))
	mux.HandleFunc("PUT "+scimBase+"/Users/{id}", scimAuth(scimPutUser))
	mux.HandleFunc("PATCH "+scimBase+"/Users/{id}", scimAuth(scimPatchUser))
	mux.HandleFunc("DELETE "+scimBase+"/Users/{id}", scimAuth(scimDeleteUser))
	mux.HandleFunc("GET "+scimBase+"/Groups", scimAuth(scimListGroups))
	mux.HandleFunc("GET "+scimBase+"/Groups/{id}", scimAuth(scimGetGroup))
	mux.HandleFunc("PATCH "+scimBase+"/Groups/{id}", scimAuth(scimPatchGroup))
	mux.HandleFunc("POST "+scimBase+"/Groups", scimAuth(func(w http.ResponseWriter, r *http.Request, _ string) {
		scimErr(w, 501, "", "groups map to RBAC roles, which are designed in the role matrix, not created over SCIM")
	}))
}

// ---------- discovery ----------

func scimSPConfig(w http.ResponseWriter, r *http.Request, _ string) {
	scimJSON(w, 200, map[string]any{
		"schemas":          []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		"documentationUri": "https://github.com/iamyassin08/iam-projects/blob/main/docs/SCIM.md",
		"patch":            map[string]bool{"supported": true},
		"bulk":             map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":           map[string]any{"supported": true, "maxResults": 200},
		"changePassword":   map[string]bool{"supported": false},
		"sort":             map[string]bool{"supported": false},
		"etag":             map[string]bool{"supported": false},
		"authenticationSchemes": []map[string]any{{"type": "oauthbearertoken", "name": "Bearer token",
			"description": "Static bearer token issued in the IAM Projects console", "primary": true}},
	})
}

func scimResourceTypes(w http.ResponseWriter, r *http.Request, _ string) {
	rt := []map[string]any{
		{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"}, "id": "User", "name": "User", "endpoint": "/Users",
			"schema": schemaUser, "schemaExtensions": []map[string]any{{"schema": schemaEnterprise, "required": false}}},
		{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"}, "id": "Group", "name": "Group", "endpoint": "/Groups", "schema": schemaGroup},
	}
	scimJSON(w, 200, listResp(len(rt), 1, toAny(rt)))
}

func scimSchemas(w http.ResponseWriter, r *http.Request, _ string) {
	attr := func(n, t string, req bool) map[string]any {
		return map[string]any{"name": n, "type": t, "required": req, "mutability": "readWrite", "multiValued": false}
	}
	sc := []map[string]any{
		{"id": schemaUser, "name": "User", "attributes": []any{attr("userName", "string", true), attr("name", "complex", false),
			attr("displayName", "string", false), attr("title", "string", false), attr("active", "boolean", false), attr("emails", "complex", false), attr("externalId", "string", false)}},
		{"id": schemaEnterprise, "name": "EnterpriseUser", "attributes": []any{attr("department", "string", false), attr("manager", "complex", false)}},
		{"id": schemaGroup, "name": "Group", "attributes": []any{attr("displayName", "string", true), attr("members", "complex", false)}},
	}
	scimJSON(w, 200, listResp(len(sc), 1, toAny(sc)))
}

func toAny[T any](in []T) []any {
	out := make([]any, len(in))
	for i := range in {
		out[i] = in[i]
	}
	return out
}

func listResp(total, start int, res []any) map[string]any {
	return map[string]any{"schemas": []string{schemaList}, "totalResults": total, "startIndex": start, "itemsPerPage": len(res), "Resources": res}
}

// ---------- mapping ----------

func splitName(full string) (string, string) {
	parts := strings.Fields(full)
	if len(parts) == 0 {
		return "", ""
	}
	return parts[0], strings.Join(parts[1:], " ")
}

func (s *State) scimUser(r *http.Request, id Identity) map[string]any {
	given, family := splitName(id.Name)
	u := map[string]any{
		"schemas":     []string{schemaUser, schemaEnterprise},
		"id":          id.ID,
		"userName":    id.Email,
		"name":        map[string]string{"givenName": given, "familyName": family, "formatted": id.Name},
		"displayName": id.Name,
		"title":       id.Title,
		"active":      id.Status == "active",
		"emails":      []map[string]any{{"value": id.Email, "type": "work", "primary": true}},
		schemaEnterprise: map[string]any{
			"department": id.Department,
			"manager":    map[string]string{"displayName": id.Manager},
		},
		"meta": map[string]string{"resourceType": "User", "created": firstNonEmpty(id.Created, id.StartDate+"T09:00:00Z"),
			"lastModified": firstNonEmpty(id.Updated, id.Created, id.StartDate+"T09:00:00Z"), "location": baseURL(r) + scimBase + "/Users/" + id.ID},
	}
	if id.ExternalID != "" {
		u["externalId"] = id.ExternalID
	}
	if ro := s.role(id.RoleID); ro != nil {
		u["groups"] = []map[string]string{{"value": ro.ID, "display": ro.Name, "$ref": baseURL(r) + scimBase + "/Groups/" + ro.ID}}
	}
	return u
}

func (s *State) scimGroup(r *http.Request, ro Role) map[string]any {
	members := []map[string]string{}
	for _, i := range s.Identities {
		if i.RoleID == ro.ID && i.Status == "active" {
			members = append(members, map[string]string{"value": i.ID, "display": i.Name, "$ref": baseURL(r) + scimBase + "/Users/" + i.ID})
		}
	}
	return map[string]any{"schemas": []string{schemaGroup}, "id": ro.ID, "displayName": ro.Name, "members": members,
		"meta": map[string]string{"resourceType": "Group", "location": baseURL(r) + scimBase + "/Groups/" + ro.ID}}
}

func baseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

func firstNonEmpty(v ...string) string {
	for _, x := range v {
		if x != "" {
			return x
		}
	}
	return ""
}

// ---------- filtering: attrPath op value (eq, ne, co, sw, ew, pr) joined by "and" ----------

var filterRe = regexp.MustCompile(`(?i)^\s*([\w.:$-]+)\s+(eq|ne|co|sw|ew|pr)\s*(.*?)\s*$`)

type cond struct{ attr, op, val string }

func parseFilter(f string) ([]cond, error) {
	if strings.TrimSpace(f) == "" {
		return nil, nil
	}
	if regexp.MustCompile(`(?i)\s(or|not)\s|\[`).MatchString(f) {
		return nil, fmt.Errorf("only 'and' combinations of simple comparisons are supported")
	}
	var out []cond
	for _, part := range regexp.MustCompile(`(?i)\s+and\s+`).Split(f, -1) {
		m := filterRe.FindStringSubmatch(part)
		if m == nil {
			return nil, fmt.Errorf("cannot parse filter %q", part)
		}
		val := strings.Trim(m[3], `"`)
		out = append(out, cond{strings.ToLower(m[1]), strings.ToLower(m[2]), val})
	}
	return out, nil
}

func match(have []string, c cond) bool {
	if c.op == "pr" {
		for _, h := range have {
			if h != "" {
				return true
			}
		}
		return false
	}
	any := false
	for _, h := range have {
		hl, vl := strings.ToLower(h), strings.ToLower(c.val)
		var ok bool
		switch c.op {
		case "eq":
			ok = hl == vl
		case "ne":
			ok = hl != vl
		case "co":
			ok = strings.Contains(hl, vl)
		case "sw":
			ok = strings.HasPrefix(hl, vl)
		case "ew":
			ok = strings.HasSuffix(hl, vl)
		}
		if ok {
			any = true
		}
	}
	return any
}

func userAttr(id Identity, attr string) []string {
	attr = strings.TrimPrefix(attr, strings.ToLower(schemaUser)+":")
	switch attr {
	case "username", "emails.value", "emails":
		return []string{id.Email}
	case "externalid":
		return []string{id.ExternalID}
	case "displayname", "name.formatted":
		return []string{id.Name}
	case "name.givenname":
		g, _ := splitName(id.Name)
		return []string{g}
	case "name.familyname":
		_, f := splitName(id.Name)
		return []string{f}
	case "title":
		return []string{id.Title}
	case "active":
		return []string{strconv.FormatBool(id.Status == "active")}
	case "id":
		return []string{id.ID}
	case strings.ToLower(schemaEnterprise) + ":department", "department":
		return []string{id.Department}
	case "groups.value", "groups":
		return []string{id.RoleID}
	}
	return []string{}
}

func paging(r *http.Request, total int) (int, int) {
	start, _ := strconv.Atoi(r.URL.Query().Get("startIndex"))
	if start < 1 {
		start = 1
	}
	count := 100
	if c := r.URL.Query().Get("count"); c != "" {
		count, _ = strconv.Atoi(c)
	}
	if count < 0 {
		count = 0
	}
	if count > 200 {
		count = 200
	}
	return start, count
}

// ---------- Users ----------

func scimListUsers(w http.ResponseWriter, r *http.Request, _ string) {
	conds, err := parseFilter(r.URL.Query().Get("filter"))
	if err != nil {
		scimErr(w, 400, "invalidFilter", err.Error())
		return
	}
	store.View(func(s *State) {
		matched := []Identity{}
		for _, id := range s.Identities {
			ok := true
			for _, c := range conds {
				if !match(userAttr(id, c.attr), c) {
					ok = false
					break
				}
			}
			if ok {
				matched = append(matched, id)
			}
		}
		sort.SliceStable(matched, func(a, b int) bool { return matched[a].ID < matched[b].ID })
		start, count := paging(r, len(matched))
		res := []any{}
		for i := start - 1; i < len(matched) && len(res) < count; i++ {
			res = append(res, s.scimUser(r, matched[i]))
		}
		scimJSON(w, 200, listResp(len(matched), start, res))
	})
}

func scimGetUser(w http.ResponseWriter, r *http.Request, _ string) {
	store.View(func(s *State) {
		id := s.identity(r.PathValue("id"))
		if id == nil {
			scimErr(w, 404, "", "User "+r.PathValue("id")+" not found")
			return
		}
		scimJSON(w, 200, s.scimUser(r, *id))
	})
}

// scimUserIn is the subset of the User resource we accept on create/replace.
type scimUserIn struct {
	UserName    string          `json:"userName"`
	ExternalID  string          `json:"externalId"`
	DisplayName string          `json:"displayName"`
	Title       string          `json:"title"`
	Active      json.RawMessage `json:"active"`
	Name        struct {
		GivenName  string `json:"givenName"`
		FamilyName string `json:"familyName"`
		Formatted  string `json:"formatted"`
	} `json:"name"`
	Emails []struct {
		Value   string `json:"value"`
		Primary bool   `json:"primary"`
	} `json:"emails"`
	Groups []struct {
		Value string `json:"value"`
	} `json:"groups"`
	Enterprise struct {
		Department string `json:"department"`
		Manager    struct {
			Value       string `json:"value"`
			DisplayName string `json:"displayName"`
		} `json:"manager"`
	} `json:"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"`
}

// boolish accepts true/false and the string forms some IdPs send ("False").
func boolish(raw json.RawMessage, def bool) bool {
	if len(raw) == 0 {
		return def
	}
	var b bool
	if json.Unmarshal(raw, &b) == nil {
		return b
	}
	var str string
	if json.Unmarshal(raw, &str) == nil {
		return strings.EqualFold(str, "true")
	}
	return def
}

func (u scimUserIn) fullName() string {
	switch {
	case u.Name.Formatted != "":
		return u.Name.Formatted
	case u.Name.GivenName != "" || u.Name.FamilyName != "":
		return strings.TrimSpace(u.Name.GivenName + " " + u.Name.FamilyName)
	default:
		return u.DisplayName
	}
}

func (u scimUserIn) email() string {
	for _, e := range u.Emails {
		if e.Primary {
			return e.Value
		}
	}
	if len(u.Emails) > 0 {
		return u.Emails[0].Value
	}
	return u.UserName
}

func (s *State) managerName(m struct {
	Value       string `json:"value"`
	DisplayName string `json:"displayName"`
}) string {
	if m.DisplayName != "" {
		return m.DisplayName
	}
	if id := s.identity(m.Value); id != nil {
		return id.Name
	}
	return ""
}

func scimCreateUser(w http.ResponseWriter, r *http.Request, actor string) {
	var in scimUserIn
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&in); err != nil {
		scimErr(w, 400, "invalidSyntax", "request body is not valid JSON")
		return
	}
	if strings.TrimSpace(in.UserName) == "" {
		scimErr(w, 400, "invalidValue", "userName is required")
		return
	}
	var out map[string]any
	err := store.Update(func(s *State) error {
		for _, i := range s.Identities {
			if strings.EqualFold(i.Email, in.UserName) && i.Status == "active" {
				return httpErr{409, "userName " + in.UserName + " already exists"}
			}
		}
		role := ""
		if len(in.Groups) > 0 {
			role = in.Groups[0].Value
		}
		name := in.fullName()
		if name == "" {
			name = strings.Split(in.UserName, "@")[0]
		}
		id, err := s.createIdentity(actor, newIdentity{Name: name, Email: in.UserName, Department: in.Enterprise.Department,
			Title: in.Title, Manager: s.managerName(in.Enterprise.Manager), RoleID: role, ExternalID: in.ExternalID})
		if err != nil {
			return err
		}
		if !boolish(in.Active, true) {
			if _, err := s.terminateIdentity(actor, id.ID, ""); err != nil {
				return err
			}
		}
		out = s.scimUser(r, *s.identity(id.ID))
		return nil
	})
	if err != nil {
		scimFromErr(w, err)
		return
	}
	w.Header().Set("Location", out["meta"].(map[string]string)["location"])
	scimJSON(w, 201, out)
}

// applyActive turns a SCIM active flag into the matching lifecycle event.
func (s *State) applyActive(actor string, id *Identity, active bool) error {
	switch {
	case !active && id.Status == "active":
		_, err := s.terminateIdentity(actor, id.ID, "")
		return err
	case active && id.Status != "active":
		_, err := s.rehireIdentity(actor, id.ID)
		return err
	}
	return nil
}

func scimPutUser(w http.ResponseWriter, r *http.Request, actor string) {
	var in scimUserIn
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&in); err != nil {
		scimErr(w, 400, "invalidSyntax", "request body is not valid JSON")
		return
	}
	var out map[string]any
	err := store.Update(func(s *State) error {
		id := s.identity(r.PathValue("id"))
		if id == nil {
			return httpErr{404, "User not found"}
		}
		if n := in.fullName(); n != "" {
			id.Name = n
		}
		if e := in.email(); e != "" {
			id.Email = e
		}
		id.Title, id.ExternalID = in.Title, firstNonEmpty(in.ExternalID, id.ExternalID)
		if in.Enterprise.Department != "" {
			id.Department = in.Enterprise.Department
		}
		if m := s.managerName(in.Enterprise.Manager); m != "" {
			id.Manager = m
		}
		id.Updated = now()
		s.audit(actor, "scim.user.replaced", id.ID, "Attributes replaced by IdP")
		if err := s.applyActive(actor, id, boolish(in.Active, id.Status == "active")); err != nil {
			return err
		}
		out = s.scimUser(r, *s.identity(id.ID))
		return nil
	})
	if err != nil {
		scimFromErr(w, err)
		return
	}
	scimJSON(w, 200, out)
}

type patchOp struct {
	Op    string          `json:"op"`
	Path  string          `json:"path"`
	Value json.RawMessage `json:"value"`
}

type patchReq struct {
	Schemas    []string  `json:"schemas"`
	Operations []patchOp `json:"Operations"`
}

func str(raw json.RawMessage) string {
	var v string
	if json.Unmarshal(raw, &v) == nil {
		return v
	}
	return strings.Trim(string(raw), `"`)
}

func (s *State) patchUserAttr(actor string, id *Identity, path string, val json.RawMessage) error {
	switch strings.ToLower(path) {
	case "active":
		return s.applyActive(actor, id, boolish(val, id.Status == "active"))
	case "title":
		id.Title = str(val)
	case "displayname", "name.formatted":
		id.Name = str(val)
	case "name.givenname":
		_, f := splitName(id.Name)
		id.Name = strings.TrimSpace(str(val) + " " + f)
	case "name.familyname":
		g, _ := splitName(id.Name)
		id.Name = strings.TrimSpace(g + " " + str(val))
	case "username", `emails[type eq "work"].value`, "emails":
		id.Email = str(val)
	case "externalid":
		id.ExternalID = str(val)
	case strings.ToLower(schemaEnterprise) + ":department", "department":
		id.Department = str(val)
	case strings.ToLower(schemaEnterprise) + ":manager", strings.ToLower(schemaEnterprise) + ":manager.value":
		var m struct {
			Value       string `json:"value"`
			DisplayName string `json:"displayName"`
		}
		if json.Unmarshal(val, &m) != nil {
			m.Value = str(val)
		}
		id.Manager = s.managerName(m)
	default:
		return httpErr{400, "unsupported patch path: " + path}
	}
	return nil
}

func scimPatchUser(w http.ResponseWriter, r *http.Request, actor string) {
	var in patchReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&in); err != nil || len(in.Operations) == 0 {
		scimErr(w, 400, "invalidSyntax", "expected a PatchOp with Operations")
		return
	}
	var out map[string]any
	err := store.Update(func(s *State) error {
		id := s.identity(r.PathValue("id"))
		if id == nil {
			return httpErr{404, "User not found"}
		}
		for _, op := range in.Operations {
			switch strings.ToLower(op.Op) { // Entra ID sends "Replace", Okta sends "replace"
			case "replace", "add":
				if op.Path == "" { // value is an object of attributes
					var m map[string]json.RawMessage
					if err := json.Unmarshal(op.Value, &m); err != nil {
						return httpErr{400, "replace without path needs an object value"}
					}
					keys := make([]string, 0, len(m))
					for k := range m {
						keys = append(keys, k)
					}
					sort.Slice(keys, func(a, b int) bool { return keys[a] != "active" && keys[b] == "active" }) // apply active last
					for _, k := range keys {
						if err := s.patchUserAttr(actor, id, k, m[k]); err != nil {
							return err
						}
					}
				} else if err := s.patchUserAttr(actor, id, op.Path, op.Value); err != nil {
					return err
				}
			case "remove":
				if err := s.patchUserAttr(actor, id, op.Path, json.RawMessage(`""`)); err != nil {
					return err
				}
			default:
				return httpErr{400, "unsupported op " + op.Op}
			}
		}
		id.Updated = now()
		s.audit(actor, "scim.user.patched", id.ID, fmt.Sprintf("%d operation(s) applied", len(in.Operations)))
		out = s.scimUser(r, *s.identity(id.ID))
		return nil
	})
	if err != nil {
		scimFromErr(w, err)
		return
	}
	scimJSON(w, 200, out)
}

func scimDeleteUser(w http.ResponseWriter, r *http.Request, actor string) {
	err := store.Update(func(s *State) error {
		id := s.identity(r.PathValue("id"))
		if id == nil {
			return httpErr{404, "User not found"}
		}
		if id.Status != "active" {
			return nil // idempotent
		}
		_, err := s.terminateIdentity(actor, id.ID, "")
		return err
	})
	if err != nil {
		scimFromErr(w, err)
		return
	}
	w.WriteHeader(204)
}

// ---------- Groups ----------

func scimListGroups(w http.ResponseWriter, r *http.Request, _ string) {
	conds, err := parseFilter(r.URL.Query().Get("filter"))
	if err != nil {
		scimErr(w, 400, "invalidFilter", err.Error())
		return
	}
	store.View(func(s *State) {
		res := []any{}
		for _, ro := range s.Roles {
			ok := true
			for _, c := range conds {
				var have []string
				switch c.attr {
				case "displayname":
					have = []string{ro.Name}
				case "id":
					have = []string{ro.ID}
				case "members.value", "members":
					for _, i := range s.Identities {
						if i.RoleID == ro.ID && i.Status == "active" {
							have = append(have, i.ID)
						}
					}
				}
				if !match(have, c) {
					ok = false
				}
			}
			if ok {
				res = append(res, s.scimGroup(r, ro))
			}
		}
		start, count := paging(r, len(res))
		total := len(res)
		if start-1 < len(res) {
			res = res[start-1:]
		} else {
			res = []any{}
		}
		if len(res) > count {
			res = res[:count]
		}
		scimJSON(w, 200, listResp(total, start, res))
	})
}

func scimGetGroup(w http.ResponseWriter, r *http.Request, _ string) {
	store.View(func(s *State) {
		ro := s.role(r.PathValue("id"))
		if ro == nil {
			scimErr(w, 404, "", "Group not found")
			return
		}
		scimJSON(w, 200, s.scimGroup(r, *ro))
	})
}

var memberPathRe = regexp.MustCompile(`(?i)^members\[value eq "([^"]+)"\]$`)

func scimPatchGroup(w http.ResponseWriter, r *http.Request, actor string) {
	var in patchReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&in); err != nil || len(in.Operations) == 0 {
		scimErr(w, 400, "invalidSyntax", "expected a PatchOp with Operations")
		return
	}
	var out map[string]any
	err := store.Update(func(s *State) error {
		ro := s.role(r.PathValue("id"))
		if ro == nil {
			return httpErr{404, "Group not found"}
		}
		members := func(raw json.RawMessage) []string {
			var arr []struct {
				Value string `json:"value"`
			}
			_ = json.Unmarshal(raw, &arr)
			ids := []string{}
			for _, m := range arr {
				ids = append(ids, m.Value)
			}
			return ids
		}
		for _, op := range in.Operations {
			o := strings.ToLower(op.Op)
			switch {
			case (o == "add" || o == "replace") && strings.EqualFold(op.Path, "members"):
				for _, mid := range members(op.Value) {
					if id := s.identity(mid); id != nil && id.RoleID != ro.ID {
						if _, err := s.moveIdentity(actor, mid, ro.ID, "", ""); err != nil {
							return err
						}
					}
				}
			case o == "remove":
				ids := members(op.Value)
				if m := memberPathRe.FindStringSubmatch(op.Path); m != nil {
					ids = append(ids, m[1])
				}
				for _, mid := range ids {
					if id := s.identity(mid); id != nil && id.RoleID == ro.ID && id.Status == "active" {
						if _, err := s.moveIdentity(actor, mid, "", "", ""); err != nil {
							return err
						}
					}
				}
			case (o == "replace" || o == "add") && strings.EqualFold(op.Path, "displayName"):
				return httpErr{400, "role names are managed in the role matrix"}
			default:
				return httpErr{400, "unsupported group operation " + op.Op + " " + op.Path}
			}
		}
		out = s.scimGroup(r, *ro)
		return nil
	})
	if err != nil {
		scimFromErr(w, err)
		return
	}
	scimJSON(w, 200, out)
}
