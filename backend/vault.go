package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Credential vault (the "PAM" half of privileged access, like CyberArk or
// Delinea): shared admin passwords live encrypted with AES-256-GCM, are never
// shown in lists, and can only be checked out by someone who holds the matching
// privileged access right now (JIT elevation or standing grant) and passes a
// step-up MFA challenge. Every checkout is time-boxed and the password rotates
// automatically when it is checked in or the window lapses.

type VaultSecret struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	SystemID        string `json:"systemId"`
	Account         string `json:"account"`
	EntitlementID   string `json:"entitlementId"`
	Ciphertext      string `json:"ciphertext"`
	Version         int    `json:"version"`
	RotatedAt       string `json:"rotatedAt"`
	RotationDays    int    `json:"rotationDays"`
	CheckedOutBy    string `json:"checkedOutBy,omitempty"`
	CheckoutReason  string `json:"checkoutReason,omitempty"`
	CheckoutExpires string `json:"checkoutExpires,omitempty"`
	Checkouts       int    `json:"checkouts"`
}

const checkoutMinutes = 30

var vaultKey []byte

// loadVaultKey reads VAULT_KEY (base64, 32 bytes) or a key file kept apart from the state file.
func loadVaultKey(dataPath string) {
	if v := os.Getenv("VAULT_KEY"); v != "" {
		if k, err := base64.StdEncoding.DecodeString(v); err == nil && len(k) == 32 {
			vaultKey = k
			return
		}
	}
	p := filepath.Join(filepath.Dir(dataPath), "vault.key")
	if b, err := os.ReadFile(p); err == nil && len(b) == 32 {
		vaultKey = b
		return
	}
	vaultKey = make([]byte, 32)
	_, _ = rand.Read(vaultKey)
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	_ = os.WriteFile(p, vaultKey, 0o600)
}

func ensureVaultKey() {
	if vaultKey == nil {
		vaultKey = make([]byte, 32)
		_, _ = rand.Read(vaultKey)
	}
}

func seal(plain string) string {
	ensureVaultKey()
	blk, _ := aes.NewCipher(vaultKey)
	gcm, _ := cipher.NewGCM(blk)
	nonce := make([]byte, gcm.NonceSize())
	_, _ = rand.Read(nonce)
	return base64.StdEncoding.EncodeToString(gcm.Seal(nonce, nonce, []byte(plain), nil))
}

func unseal(ct string) (string, error) {
	ensureVaultKey()
	b, err := base64.StdEncoding.DecodeString(ct)
	if err != nil {
		return "", err
	}
	blk, _ := aes.NewCipher(vaultKey)
	gcm, _ := cipher.NewGCM(blk)
	if len(b) < gcm.NonceSize() {
		return "", errors.New("ciphertext too short")
	}
	p, err := gcm.Open(nil, b[:gcm.NonceSize()], b[gcm.NonceSize():], nil)
	if err != nil {
		return "", errors.New("vault key mismatch: rotate this credential to re-seal it")
	}
	return string(p), nil
}

func newPassword() string {
	const alpha = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*-_"
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = alpha[int(b[i])%len(alpha)]
	}
	return string(b)
}

func (s *State) vaultSecret(id string) *VaultSecret {
	for i := range s.Vault {
		if s.Vault[i].ID == id {
			return &s.Vault[i]
		}
	}
	return nil
}

func (s *State) rotate(v *VaultSecret, by, why string) {
	v.Ciphertext = seal(newPassword())
	v.Version++
	v.RotatedAt = now()
	v.CheckedOutBy, v.CheckoutReason, v.CheckoutExpires = "", "", ""
	s.audit(by, "vault.rotated", v.ID, fmt.Sprintf("%s rotated to v%d (%s)", v.Name, v.Version, why))
}

// sweepCheckouts auto-checks-in and rotates credentials whose window has lapsed.
func (s *State) sweepCheckouts() int {
	n := 0
	for i := range s.Vault {
		v := &s.Vault[i]
		if v.CheckedOutBy != "" && !nowT().Before(parseT(v.CheckoutExpires)) {
			s.rotate(v, "system:vault", "checkout window expired")
			n++
		}
	}
	return n
}

type checkoutIn struct {
	IdentityID, Reason, Code string
}

func (s *State) checkout(actor, id string, in checkoutIn) (string, *VaultSecret, error) {
	v := s.vaultSecret(id)
	if v == nil {
		return "", nil, httpErr{404, "credential not found"}
	}
	if v.CheckedOutBy != "" {
		return "", nil, httpErr{409, "already checked out by " + v.CheckedOutBy + " until " + v.CheckoutExpires + " (exclusive checkout)"}
	}
	who := s.identity(in.IdentityID)
	if who == nil || who.Status != "active" {
		return "", nil, httpErr{404, "active identity not found"}
	}
	if strings.TrimSpace(in.Reason) == "" {
		return "", nil, httpErr{400, "a reason is required"}
	}
	g := s.findGrant(who.ID, v.EntitlementID)
	if g == nil {
		return "", nil, httpErr{403, fmt.Sprintf("%s does not hold %s right now. Activate it with just-in-time access first", who.Name, entName(s, v.EntitlementID))}
	}
	var u *IdPUser
	for i := range s.IdPUsers {
		if s.IdPUsers[i].IdentityID == who.ID {
			u = &s.IdPUsers[i]
		}
	}
	if u == nil || !u.MFAEnrolled {
		return "", nil, httpErr{403, who.Name + " has no MFA method registered; step-up authentication is required for vault checkout"}
	}
	if !verifyTOTP(u.TOTPSecret, in.Code) {
		s.audit(actor, "vault.stepup.failed", v.ID, who.Name+" failed the step-up MFA challenge")
		return "", nil, httpErr{401, "step-up MFA failed: the one-time code is not valid"}
	}
	pw, err := unseal(v.Ciphertext)
	if err != nil {
		return "", nil, httpErr{500, err.Error()}
	}
	v.CheckedOutBy, v.CheckoutReason = who.Name, in.Reason
	v.CheckoutExpires = fmtT(nowT().Add(checkoutMinutes * time.Minute))
	v.Checkouts++
	via := g.Source
	s.audit(actor, "vault.checkout", v.ID, fmt.Sprintf("%s checked out %s for %d min (holds access via %s, MFA verified): %s", who.Name, v.Name, checkoutMinutes, via, in.Reason))
	return pw, v, nil
}

// ---------- API ----------

func registerVault(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/vault", func(w http.ResponseWriter, r *http.Request) {
		store.View(func(s *State) {
			out := []map[string]any{}
			for _, v := range s.Vault {
				age := int(nowT().Sub(parseT(v.RotatedAt)).Hours() / 24)
				out = append(out, map[string]any{"id": v.ID, "name": v.Name, "systemId": v.SystemID, "account": v.Account, "entitlementId": v.EntitlementID,
					"version": v.Version, "rotatedAt": v.RotatedAt, "rotationDays": v.RotationDays, "ageDays": age, "overdue": age > v.RotationDays,
					"checkedOutBy": v.CheckedOutBy, "checkoutReason": v.CheckoutReason, "checkoutExpires": v.CheckoutExpires, "checkouts": v.Checkouts,
					"fingerprint": v.Ciphertext[:12] + "…"})
			}
			writeJSON(w, 200, out)
		})
	})
	mux.HandleFunc("POST /api/vault/{id}/checkout", func(w http.ResponseWriter, r *http.Request) {
		var in checkoutIn
		if err := decode(r, &in); err != nil {
			fail(w, 400, "invalid JSON")
			return
		}
		var pw, exp string
		var rotErr error
		err := store.Update(func(s *State) error {
			p, v, err := s.checkout(actor(r), r.PathValue("id"), in)
			if err != nil {
				if he, ok := err.(httpErr); ok && he.code == 401 {
					rotErr = err // persist the failed-attempt audit entry, then report
					return nil
				}
				return err
			}
			pw, exp = p, v.CheckoutExpires
			return nil
		})
		if err == nil {
			err = rotErr
		}
		if err != nil {
			respondErr(w, err)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, 200, map[string]string{"password": pw, "expiresAt": exp, "note": "Shown once. It rotates automatically at check-in or expiry."})
	})
	mux.HandleFunc("POST /api/vault/{id}/checkin", func(w http.ResponseWriter, r *http.Request) {
		err := store.Update(func(s *State) error {
			v := s.vaultSecret(r.PathValue("id"))
			if v == nil {
				return httpErr{404, "credential not found"}
			}
			if v.CheckedOutBy == "" {
				return httpErr{409, "not checked out"}
			}
			s.audit(actor(r), "vault.checkin", v.ID, v.Name+" checked in by "+v.CheckedOutBy)
			s.rotate(v, "system:vault", "rotate on check-in")
			return nil
		})
		if err != nil {
			respondErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]string{"status": "checked in and rotated"})
	})
	mux.HandleFunc("POST /api/vault/{id}/rotate", func(w http.ResponseWriter, r *http.Request) {
		err := store.Update(func(s *State) error {
			v := s.vaultSecret(r.PathValue("id"))
			if v == nil {
				return httpErr{404, "credential not found"}
			}
			s.rotate(v, actor(r), "manual rotation")
			return nil
		})
		if err != nil {
			respondErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]string{"status": "rotated"})
	})
}
