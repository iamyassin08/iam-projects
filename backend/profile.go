package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// Self-service profile for whoever is signed in: display details, an avatar,
// preferences, and a view of their own access, sign-ins and actions. Also the
// self-service security actions a real portal offers (sign out everywhere,
// reset MFA, export my data). Requires an SSO session.

type ProfilePrefs struct {
	Landing      string `json:"landing"`      // page id to open on arrival
	ReduceMotion bool   `json:"reduceMotion"` // turn off animations
	Collapsed    bool   `json:"collapsed"`    // start with the sidebar collapsed
}

type Profile struct {
	Username    string       `json:"username"`
	DisplayName string       `json:"displayName"`
	Title       string       `json:"title"`
	Bio         string       `json:"bio"`
	Location    string       `json:"location"`
	Timezone    string       `json:"timezone"`
	Website     string       `json:"website"`
	Avatar      string       `json:"avatar"` // data:image/...;base64, small
	Prefs       ProfilePrefs `json:"prefs"`
	UpdatedAt   string       `json:"updatedAt"`
}

const (
	maxProfiles  = 200
	maxAvatarLen = 200 << 10 // ~150 KB image once base64 encoded
)

var avatarRe = regexp.MustCompile(`^data:image/(png|jpeg|webp);base64,[A-Za-z0-9+/=]+$`)
var landingPages = []string{"", "home", "guide", "help", "jml", "scim", "automation", "sso", "mfa", "requests", "certifications", "roles", "pam", "vault", "cloud", "monitoring", "risk", "systems", "audit", "lab", "profile"}

func (s *State) profile(username string) *Profile {
	for i := range s.Profiles {
		if s.Profiles[i].Username == username {
			return &s.Profiles[i]
		}
	}
	return nil
}

func requireSession(w http.ResponseWriter, r *http.Request) *session {
	sess := currentSession(r)
	if sess == nil {
		fail(w, http.StatusUnauthorized, "sign in to use your profile")
	}
	return sess
}

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len([]rune(s)) > n {
		return string([]rune(s)[:n])
	}
	return s
}

func (s *State) profileView(sess *session) map[string]any {
	p := Profile{Username: sess.Username, DisplayName: sess.Name, Timezone: "America/Chicago"}
	if sp := s.profile(sess.Username); sp != nil {
		p = *sp
	}
	acct := map[string]any{"username": sess.Username, "name": sess.Name, "email": sess.Email, "groups": sess.Groups,
		"amr": sess.AMR, "idp": sess.IdP, "admin": slices.Contains(sess.Groups, "iam-admins") || slices.Contains(sess.Groups, "iam-admin")}
	var identityID string
	if u := s.idpUser(sess.Username); u != nil {
		acct["mfaEnrolled"], acct["mfaMethod"], acct["lastSignIn"], identityID = u.MFAEnrolled, u.MFAMethod, u.LastSignIn, u.IdentityID
		acct["builtIn"] = true
	}
	if identityID == "" {
		for _, i := range s.Identities {
			if strings.EqualFold(strings.SplitN(i.Email, "@", 2)[0], sess.Username) {
				identityID = i.ID
			}
		}
	}
	access := []map[string]any{}
	if id := s.identity(identityID); id != nil {
		acct["identity"] = map[string]any{"id": id.ID, "name": id.Name, "title": id.Title, "department": id.Department, "manager": id.Manager, "role": roleName(s.role(id.RoleID)), "status": id.Status, "startDate": id.StartDate}
		for _, g := range s.grantsFor(id.ID) {
			e := s.entitlement(g.EntitlementID)
			if e == nil {
				continue
			}
			access = append(access, map[string]any{"entitlementId": e.ID, "name": e.Name, "system": sysName(s, e.SystemID), "privileged": e.Privileged, "source": g.Source, "grantedAt": g.GrantedAt, "expiresAt": g.ExpiresAt, "lastUsed": g.LastUsed})
		}
	}
	signins := []SignIn{}
	for i := len(s.SignIns) - 1; i >= 0 && len(signins) < 12; i-- {
		if s.SignIns[i].Username == sess.Username {
			signins = append(signins, s.SignIns[i])
		}
	}
	actions := []AuditEntry{}
	for _, a := range s.Audit {
		if a.Actor == sess.Username && len(actions) < 15 {
			actions = append(actions, a)
		}
	}
	sort.SliceStable(access, func(a, b int) bool { return access[a]["system"].(string) < access[b]["system"].(string) })
	return map[string]any{"profile": p, "account": acct, "access": access, "signIns": signins, "actions": actions}
}

func registerProfile(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/profile", func(w http.ResponseWriter, r *http.Request) {
		sess := requireSession(w, r)
		if sess == nil {
			return
		}
		store.View(func(s *State) { writeJSON(w, 200, s.profileView(sess)) })
	})

	mux.HandleFunc("PUT /api/profile", func(w http.ResponseWriter, r *http.Request) {
		sess := requireSession(w, r)
		if sess == nil {
			return
		}
		var in Profile
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxAvatarLen+16<<10)).Decode(&in); err != nil {
			fail(w, 400, "invalid profile (is the image too large?)")
			return
		}
		if in.Avatar != "" && (len(in.Avatar) > maxAvatarLen || !avatarRe.MatchString(in.Avatar)) {
			fail(w, 400, "avatar must be a PNG, JPEG or WebP image under 150 KB")
			return
		}
		if in.Website != "" && !strings.HasPrefix(in.Website, "https://") {
			fail(w, 400, "website must start with https://")
			return
		}
		if !slices.Contains(landingPages, in.Prefs.Landing) {
			in.Prefs.Landing = ""
		}
		var out map[string]any
		err := store.Update(func(s *State) error {
			p := s.profile(sess.Username)
			if p == nil {
				if len(s.Profiles) >= maxProfiles {
					return httpErr{429, tenantFull}
				}
				s.Profiles = append(s.Profiles, Profile{Username: sess.Username})
				p = &s.Profiles[len(s.Profiles)-1]
			}
			changed := []string{}
			set := func(field string, dst *string, v string, n int) {
				v = clip(v, n)
				if *dst != v {
					*dst = v
					changed = append(changed, field)
				}
			}
			set("display name", &p.DisplayName, in.DisplayName, 60)
			set("title", &p.Title, in.Title, 80)
			set("bio", &p.Bio, in.Bio, 400)
			set("location", &p.Location, in.Location, 60)
			set("timezone", &p.Timezone, in.Timezone, 40)
			set("website", &p.Website, in.Website, 120)
			if p.Avatar != in.Avatar {
				p.Avatar = in.Avatar
				changed = append(changed, "avatar")
			}
			if p.Prefs != in.Prefs {
				p.Prefs = in.Prefs
				changed = append(changed, "preferences")
			}
			p.UpdatedAt = now()
			if len(changed) > 0 {
				s.audit(sess.Username, "profile.updated", sess.Username, "Updated "+strings.Join(changed, ", "))
			}
			out = s.profileView(sess)
			return nil
		})
		if err != nil {
			respondErr(w, err)
			return
		}
		writeJSON(w, 200, out)
	})

	mux.HandleFunc("DELETE /api/profile", func(w http.ResponseWriter, r *http.Request) {
		sess := requireSession(w, r)
		if sess == nil {
			return
		}
		_ = store.Update(func(s *State) error {
			s.Profiles = slices.DeleteFunc(s.Profiles, func(p Profile) bool { return p.Username == sess.Username })
			s.audit(sess.Username, "profile.reset", sess.Username, "Profile customisations removed")
			return nil
		})
		writeJSON(w, 200, map[string]string{"status": "reset"})
	})

	mux.HandleFunc("GET /api/profile/export", func(w http.ResponseWriter, r *http.Request) {
		sess := requireSession(w, r)
		if sess == nil {
			return
		}
		store.View(func(s *State) {
			w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-data.json"`, sess.Username))
			writeJSON(w, 200, s.profileView(sess))
		})
	})

	mux.HandleFunc("POST /api/profile/signout-everywhere", func(w http.ResponseWriter, r *http.Request) {
		sess := requireSession(w, r)
		if sess == nil {
			return
		}
		revokeSessions(sess.Username)
		_ = store.Update(func(s *State) error {
			s.audit(sess.Username, "idp.sessions.revoked", sess.Username, "Signed out of every session (self-service)")
			return nil
		})
		http.SetCookie(w, &http.Cookie{Name: "iam_session", Value: "", Path: "/", MaxAge: -1})
		writeJSON(w, 200, map[string]string{"status": "signed out everywhere"})
	})

	mux.HandleFunc("POST /api/profile/reset-mfa", func(w http.ResponseWriter, r *http.Request) {
		sess := requireSession(w, r)
		if sess == nil {
			return
		}
		err := store.Update(func(s *State) error {
			u := s.idpUser(sess.Username)
			if u == nil {
				return httpErr{400, "MFA for this account is managed by Keycloak (Account console → Signing in)"}
			}
			u.MFAEnrolled, u.TOTPSecret, u.MFAMethod = false, "", ""
			s.audit(sess.Username, "mfa.reset", sess.Username, "Self-service MFA reset; re-registration at next sign-in")
			return nil
		})
		if err != nil {
			respondErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]string{"status": "MFA reset"})
	})
}
