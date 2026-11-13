package main

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Minimal JOSE + TOTP toolkit on the Go standard library: RS256 JWTs, JWKS,
// and RFC 6238 one-time passwords. Enough to run a real OpenID Connect
// provider and relying party without third-party code.

var b64 = base64.RawURLEncoding

// ---------- signing key ----------

type signingKey struct {
	kid  string
	priv *rsa.PrivateKey
}

// loadOrCreateKey keeps the IdP's RSA key next to the data file so tokens
// survive restarts. A fresh key is generated on first boot.
func loadOrCreateKey(path string) (*signingKey, error) {
	if b, err := os.ReadFile(path); err == nil {
		if blk, _ := pem.Decode(b); blk != nil {
			if k, err := x509.ParsePKCS1PrivateKey(blk.Bytes); err == nil {
				return newSigningKey(k), nil
			}
		}
	}
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		return nil, err
	}
	return newSigningKey(k), nil
}

func newSigningKey(k *rsa.PrivateKey) *signingKey {
	sum := sha256.Sum256(k.PublicKey.N.Bytes())
	return &signingKey{kid: b64.EncodeToString(sum[:8]), priv: k}
}

func (k *signingKey) jwk() map[string]any {
	e := big.NewInt(int64(k.priv.PublicKey.E)).Bytes()
	return map[string]any{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": k.kid,
		"n": b64.EncodeToString(k.priv.PublicKey.N.Bytes()), "e": b64.EncodeToString(e)}
}

func (k *signingKey) sign(claims map[string]any) (string, error) {
	h, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": k.kid})
	c, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	input := b64.EncodeToString(h) + "." + b64.EncodeToString(c)
	sum := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, k.priv, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return input + "." + b64.EncodeToString(sig), nil
}

// ---------- verification ----------

type jwks struct {
	Keys []struct {
		Kty, Kid, N, E, Alg string
	} `json:"keys"`
}

func (j jwks) key(kid string) (*rsa.PublicKey, error) {
	for _, k := range j.Keys {
		if k.Kty != "RSA" || (kid != "" && k.Kid != kid) {
			continue
		}
		n, err1 := b64.DecodeString(k.N)
		e, err2 := b64.DecodeString(k.E)
		if err1 != nil || err2 != nil {
			continue
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}, nil
	}
	return nil, fmt.Errorf("no RSA key %q in JWKS", kid)
}

// decodeJWT splits a compact JWT without verifying it (for inspection).
func decodeJWT(tok string) (header, claims map[string]any, err error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return nil, nil, errors.New("malformed JWT")
	}
	hb, err := b64.DecodeString(parts[0])
	if err != nil {
		return nil, nil, err
	}
	cb, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, nil, err
	}
	if err := json.Unmarshal(hb, &header); err != nil {
		return nil, nil, err
	}
	if err := json.Unmarshal(cb, &claims); err != nil {
		return nil, nil, err
	}
	return header, claims, nil
}

// verifyJWT checks an RS256 signature against a JWKS plus iss / aud / exp.
func verifyJWT(tok string, set jwks, issuer, audience string) (map[string]any, error) {
	header, claims, err := decodeJWT(tok)
	if err != nil {
		return nil, err
	}
	if header["alg"] != "RS256" {
		return nil, fmt.Errorf("unexpected alg %v (only RS256 accepted)", header["alg"])
	}
	kid, _ := header["kid"].(string)
	pub, err := set.key(kid)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(tok, ".")
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig); err != nil {
		return nil, errors.New("signature verification failed")
	}
	if iss, _ := claims["iss"].(string); iss != issuer {
		return nil, fmt.Errorf("issuer mismatch: %q", iss)
	}
	if !audContains(claims["aud"], audience) {
		return nil, errors.New("audience mismatch")
	}
	exp, _ := claims["exp"].(float64)
	if int64(exp) < nowT().Unix()-30 {
		return nil, errors.New("token expired")
	}
	return claims, nil
}

func audContains(aud any, want string) bool {
	switch v := aud.(type) {
	case string:
		return v == want
	case []any:
		for _, a := range v {
			if a == want {
				return true
			}
		}
	}
	return false
}

// ---------- random + PKCE ----------

func randToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b64.EncodeToString(b)
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return b64.EncodeToString(sum[:])
}

// ---------- HMAC-signed cookies ----------

var cookieKey = func() []byte {
	if k := os.Getenv("SESSION_SECRET"); k != "" {
		return []byte(k)
	}
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return b
}()

func sealCookie(v any) string {
	j, _ := json.Marshal(v)
	p := b64.EncodeToString(j)
	m := hmac.New(sha256.New, cookieKey)
	m.Write([]byte(p))
	return p + "." + b64.EncodeToString(m.Sum(nil))
}

func openCookie(s string, v any) bool {
	i := strings.LastIndexByte(s, '.')
	if i < 0 {
		return false
	}
	m := hmac.New(sha256.New, cookieKey)
	m.Write([]byte(s[:i]))
	want := b64.EncodeToString(m.Sum(nil))
	if !hmac.Equal([]byte(want), []byte(s[i+1:])) {
		return false
	}
	j, err := b64.DecodeString(s[:i])
	return err == nil && json.Unmarshal(j, v) == nil
}

// ---------- TOTP (RFC 6238, SHA-1, 6 digits, 30 s) ----------

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func newTOTPSecret() string {
	b := make([]byte, 20)
	_, _ = rand.Read(b)
	return b32.EncodeToString(b)
}

func totpAt(secret string, t time.Time) string {
	key, err := b32.DecodeString(strings.ToUpper(strings.ReplaceAll(secret, " ", "")))
	if err != nil {
		return ""
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(t.Unix()/30))
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	h := m.Sum(nil)
	off := h[len(h)-1] & 0x0f
	code := (binary.BigEndian.Uint32(h[off:off+4]) & 0x7fffffff) % 1000000
	return fmt.Sprintf("%06d", code)
}

// verifyTOTP accepts the current step and one step either side for clock skew.
func verifyTOTP(secret, code string) bool {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return false
	}
	t := nowT()
	for _, d := range []time.Duration{0, -30 * time.Second, 30 * time.Second} {
		if hmac.Equal([]byte(totpAt(secret, t.Add(d))), []byte(code)) {
			return true
		}
	}
	return false
}
