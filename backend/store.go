package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ---------- Domain types ----------

type Identity struct {
	ID         string `json:"id"`
	ExternalID string `json:"externalId,omitempty"` // set by an upstream IdP over SCIM
	Name       string `json:"name"`
	Email      string `json:"email"`
	Department string `json:"department"`
	Title      string `json:"title"`
	Manager    string `json:"manager"`
	RoleID     string `json:"roleId"`
	Status     string `json:"status"` // active | terminated
	StartDate  string `json:"startDate"`
	EndDate    string `json:"endDate,omitempty"`
	Created    string `json:"created,omitempty"`
	Updated    string `json:"updated,omitempty"`
}

type Role struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Department   string   `json:"department"`
	Description  string   `json:"description"`
	Entitlements []string `json:"entitlements"`
}

type System struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Category     string `json:"category"`     // hris | idp | directory | app | cloud
	AuthProtocol string `json:"authProtocol"` // SAML | OIDC | LDAP | Kerberos | n/a
	Provisioning string `json:"provisioning"` // SCIM | API | Manual | Source
	Owner        string `json:"owner"`
	Criticality  string `json:"criticality"` // low | medium | high
}

type Entitlement struct {
	ID         string `json:"id"`
	SystemID   string `json:"systemId"`
	Name       string `json:"name"`
	Privileged bool   `json:"privileged"`
}

type Grant struct {
	IdentityID    string `json:"identityId"`
	EntitlementID string `json:"entitlementId"`
	Source        string `json:"source"` // role | request | jit
	GrantedAt     string `json:"grantedAt"`
	ExpiresAt     string `json:"expiresAt,omitempty"` // only for jit
	LastUsed      string `json:"lastUsed,omitempty"`  // last sign-in that exercised this entitlement
}

type AccessRequest struct {
	ID            string `json:"id"`
	IdentityID    string `json:"identityId"`
	EntitlementID string `json:"entitlementId"`
	Justification string `json:"justification"`
	Status        string `json:"status"` // pending | approved | denied
	SoDConflict   string `json:"sodConflict,omitempty"`
	RequestedAt   string `json:"requestedAt"`
	DecidedBy     string `json:"decidedBy,omitempty"`
	DecidedAt     string `json:"decidedAt,omitempty"`
	Reason        string `json:"reason,omitempty"`
}

type SoDRule struct {
	ID          string `json:"id"`
	A           string `json:"a"`
	B           string `json:"b"`
	Description string `json:"description"`
}

type JMLEvent struct {
	ID         string   `json:"id"`
	Type       string   `json:"type"` // joiner | mover | leaver | rehire
	IdentityID string   `json:"identityId"`
	Summary    string   `json:"summary"`
	Granted    []string `json:"granted"`
	Revoked    []string `json:"revoked"`
	At         string   `json:"at"`
}

type AuditEntry struct {
	ID     string `json:"id"`
	At     string `json:"at"`
	Actor  string `json:"actor"`
	Action string `json:"action"`
	Target string `json:"target"`
	Detail string `json:"detail"`
}

// Exclusion records a birthright entitlement that a reviewer revoked in a
// certification. Role re-syncs honour it until the identity changes role.
type Exclusion struct {
	IdentityID    string `json:"identityId"`
	EntitlementID string `json:"entitlementId"`
	CampaignID    string `json:"campaignId"`
	Reason        string `json:"reason"`
	At            string `json:"at"`
}

type State struct {
	Seq            int             `json:"seq"`
	Identities     []Identity      `json:"identities"`
	Roles          []Role          `json:"roles"`
	Systems        []System        `json:"systems"`
	Entitlements   []Entitlement   `json:"entitlements"`
	Grants         []Grant         `json:"grants"`
	Requests       []AccessRequest `json:"requests"`
	SoDRules       []SoDRule       `json:"sodRules"`
	JMLEvents      []JMLEvent      `json:"jmlEvents"`
	Audit          []AuditEntry    `json:"audit"`
	Exclusions     []Exclusion     `json:"exclusions"`
	Campaigns      []Campaign      `json:"campaigns"`
	CertItems      []CertItem      `json:"certItems"`
	Eligibility    []Eligibility   `json:"eligibility"`
	PAMSessions    []PAMSession    `json:"pamSessions"`
	SCIMTokens     []SCIMToken     `json:"scimTokens"`
	TargetAccounts []TargetAccount `json:"targetAccounts"`

	// Identity security (IdP, MFA, Conditional Access, threat detection, vault, cloud IAM)
	IdPUsers         []IdPUser         `json:"idpUsers"`
	CAPolicies       []CAPolicy        `json:"caPolicies"`
	BlockedIPs       []string          `json:"blockedIps"`
	SignIns          []SignIn          `json:"signIns"`
	AlertStates      []AlertState      `json:"alertStates"`
	Vault            []VaultSecret     `json:"vault"`
	CloudPrincipals  []CloudPrincipal  `json:"cloudPrincipals"`
	CloudPolicies    []CloudPolicy     `json:"cloudPolicies"`
	AzureAssignments []AzureAssignment `json:"azureAssignments"`
}

// ---------- Store: JSON file persisted on a Docker volume ----------

type Store struct {
	mu   sync.Mutex
	path string
	s    *State
}

func OpenStore(path string) (*Store, error) {
	st := &Store{path: path}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		st.s = Seed()
		return st, st.save()
	}
	if err != nil {
		return nil, err
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	st.s = &s
	m1, m2 := migrate(st.s), syncDemoPasswords(st.s)
	if m1 || m2 {
		return st, st.save()
	}
	return st, nil
}

func (st *Store) save() error {
	if err := os.MkdirAll(filepath.Dir(st.path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(st.s, "", "  ")
	if err != nil {
		return err
	}
	tmp := st.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, st.path)
}

// Update runs fn under lock and persists if fn succeeds.
func (st *Store) Update(fn func(s *State) error) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	if err := fn(st.s); err != nil {
		return err
	}
	return st.save()
}

// View runs fn under lock without persisting.
func (st *Store) View(fn func(s *State)) {
	st.mu.Lock()
	defer st.mu.Unlock()
	fn(st.s)
}

func (st *Store) Reset() error {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.s = Seed()
	return st.save()
}

// ---------- helpers on State ----------

// clock is swappable so tests can move time forward (JIT expiry, overdue reviews).
var clock = time.Now

func nowT() time.Time { return clock().UTC() }
func now() string     { return nowT().Format(time.RFC3339) }

func parseT(s string) time.Time {
	t, _ := time.Parse(time.RFC3339, s)
	return t
}

func daysAgo(d int) string { return nowT().AddDate(0, 0, -d).Format(time.RFC3339) }

func (s *State) nextID(prefix string) string {
	s.Seq++
	return prefix + "-" + itoa(s.Seq)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func (s *State) identity(id string) *Identity {
	for i := range s.Identities {
		if s.Identities[i].ID == id {
			return &s.Identities[i]
		}
	}
	return nil
}

func (s *State) role(id string) *Role {
	for i := range s.Roles {
		if s.Roles[i].ID == id {
			return &s.Roles[i]
		}
	}
	return nil
}

func (s *State) system(id string) *System {
	for i := range s.Systems {
		if s.Systems[i].ID == id {
			return &s.Systems[i]
		}
	}
	return nil
}

func (s *State) entitlement(id string) *Entitlement {
	for i := range s.Entitlements {
		if s.Entitlements[i].ID == id {
			return &s.Entitlements[i]
		}
	}
	return nil
}

func (s *State) findGrant(identityID, entID string) *Grant {
	for i := range s.Grants {
		if s.Grants[i].IdentityID == identityID && s.Grants[i].EntitlementID == entID {
			return &s.Grants[i]
		}
	}
	return nil
}

func (s *State) hasGrant(identityID, entID string) bool { return s.findGrant(identityID, entID) != nil }

func (s *State) grant(identityID, entID, source string) bool {
	if s.hasGrant(identityID, entID) {
		return false
	}
	if source == "role" && s.excluded(identityID, entID) {
		return false
	}
	s.Grants = append(s.Grants, Grant{IdentityID: identityID, EntitlementID: entID, Source: source, GrantedAt: now()})
	return true
}

// revoke removes a grant; if onlySource != "" only grants from that source are removed.
func (s *State) revoke(identityID, entID, onlySource string) bool {
	for i, g := range s.Grants {
		if g.IdentityID == identityID && g.EntitlementID == entID && (onlySource == "" || g.Source == onlySource) {
			s.Grants = append(s.Grants[:i], s.Grants[i+1:]...)
			return true
		}
	}
	return false
}

func (s *State) grantsFor(identityID string) []Grant {
	out := []Grant{}
	for _, g := range s.Grants {
		if g.IdentityID == identityID {
			out = append(out, g)
		}
	}
	return out
}

func (s *State) excluded(identityID, entID string) bool {
	for _, x := range s.Exclusions {
		if x.IdentityID == identityID && x.EntitlementID == entID {
			return true
		}
	}
	return false
}

func (s *State) clearExclusions(identityID string) {
	out := s.Exclusions[:0]
	for _, x := range s.Exclusions {
		if x.IdentityID != identityID {
			out = append(out, x)
		}
	}
	s.Exclusions = out
}

func (s *State) audit(actor, action, target, detail string) {
	if len(detail) > 600 {
		detail = detail[:600] + "…"
	}
	if len(actor) > 80 {
		actor = actor[:80]
	}
	s.Audit = append([]AuditEntry{{s.nextID("AUD"), now(), actor, action, target, detail}}, s.Audit...)
	if len(s.Audit) > 1000 {
		s.Audit = s.Audit[:1000]
	}
}

// sodConflict returns the first SoD rule violated if identity also held entID.
func (s *State) sodConflict(identityID, entID string) *SoDRule {
	for i, r := range s.SoDRules {
		other := ""
		if r.A == entID {
			other = r.B
		} else if r.B == entID {
			other = r.A
		}
		if other != "" && s.hasGrant(identityID, other) {
			return &s.SoDRules[i]
		}
	}
	return nil
}

func fmtT(t time.Time) string    { return t.UTC().Format(time.RFC3339) }
func durMin(m int) time.Duration { return time.Duration(m) * time.Minute }
