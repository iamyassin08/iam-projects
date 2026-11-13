package main

import (
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Hardening for a public, unauthenticated demo: security headers, per-IP rate
// limits on anything that changes state or tries a password, caps that stop the
// state file growing without bound, and an optional scheduled reset.

// ---------- security headers ----------

const csp = "default-src 'self'; " +
	"script-src 'self'; " +
	"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
	"font-src 'self' https://fonts.gstatic.com; " +
	"img-src 'self' data: blob:; " +
	"connect-src 'self'; " +
	"frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'"

func secure(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("Content-Security-Policy", csp)
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("X-Frame-Options", "DENY")
		hd.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		hd.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
		hd.Set("Cross-Origin-Opener-Policy", "same-origin")
		if secureCookie(r) {
			hd.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/idp/") || strings.HasPrefix(r.URL.Path, "/auth/") || strings.HasPrefix(r.URL.Path, "/scim/") {
			hd.Set("Cache-Control", "no-store")
		}
		h.ServeHTTP(w, r)
	})
}

// ---------- per-IP rate limiting ----------

// clientIP prefers Cloudflare's header, then the first X-Forwarded-For hop.
func clientIP(r *http.Request) string {
	if v := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); v != "" {
		return v
	}
	if v := r.Header.Get("X-Forwarded-For"); v != "" {
		return strings.TrimSpace(strings.Split(v, ",")[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

type bucket struct {
	tokens float64
	last   time.Time
}

type limiter struct {
	mu    sync.Mutex
	rate  float64 // tokens per second
	burst float64
	m     map[string]*bucket
}

func newLimiter(perMinute, burst int) *limiter {
	return &limiter{rate: float64(perMinute) / 60, burst: float64(burst), m: map[string]*bucket{}}
}

func (l *limiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	b := l.m[key]
	if b == nil {
		if len(l.m) > 20000 { // drop stale entries rather than grow forever
			for k, v := range l.m {
				if now.Sub(v.last) > 10*time.Minute {
					delete(l.m, k)
				}
			}
		}
		b = &bucket{tokens: l.burst, last: now}
		l.m[key] = b
	}
	b.tokens = min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.rate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

var (
	writeLimit = newLimiter(120, 40) // state-changing API / SCIM calls
	authLimit  = newLimiter(30, 10)  // password, MFA, token and login attempts
)

func rateLimit(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		var l *limiter
		switch {
		case strings.HasPrefix(p, "/idp/api/txn/") && r.Method == http.MethodPost, p == "/idp/token", p == "/auth/login":
			l = authLimit
		case r.Method != http.MethodGet && r.Method != http.MethodHead && (strings.HasPrefix(p, "/api/") || strings.HasPrefix(p, "/scim/")):
			l = writeLimit
		}
		if l != nil && !l.allow(clientIP(r)) {
			w.Header().Set("Retry-After", "30")
			fail(w, http.StatusTooManyRequests, "too many requests from your address; slow down and try again shortly")
			return
		}
		h.ServeHTTP(w, r)
	})
}

// ---------- growth caps for the shared demo tenant ----------

const (
	maxIdentities = 300
	maxRequests   = 1000
	maxCampaigns  = 60
	maxSCIMTokens = 25
	tenantFull    = "the demo tenant is full; use Reset demo on the Security posture page"
)

func (s *State) atCapacity(what string) error {
	n, max := 0, 0
	switch what {
	case "identity":
		n, max = len(s.Identities), maxIdentities
	case "request":
		n, max = len(s.Requests), maxRequests
	case "campaign":
		n, max = len(s.Campaigns), maxCampaigns
	case "token":
		for _, t := range s.SCIMTokens {
			if !t.Revoked {
				n++
			}
		}
		max = maxSCIMTokens
	}
	if n >= max {
		return httpErr{http.StatusTooManyRequests, tenantFull}
	}
	return nil
}

// ---------- housekeeping ----------

// pruneMemory drops expired authorization transactions, codes and token views.
func pruneMemory() {
	now := nowT()
	idpMem.Lock()
	for k, v := range idpMem.txns {
		if now.After(v.Expires) {
			delete(idpMem.txns, k)
		}
	}
	for k, v := range idpMem.codes {
		if now.After(v.Expires) {
			delete(idpMem.codes, k)
		}
	}
	idpMem.Unlock()
	tokenStore.Lock()
	for k, v := range tokenStore.m {
		if at, ok := v["storedAt"].(int64); ok && now.Unix()-at > 8*3600 {
			delete(tokenStore.m, k)
		}
	}
	tokenStore.Unlock()
}

// housekeeping runs pruning every few minutes and, if DEMO_RESET_HOURS is set,
// reseeds the public demo on that schedule so vandalism doesn't stick.
func housekeeping() {
	hours, _ := strconv.Atoi(os.Getenv("DEMO_RESET_HOURS"))
	last := time.Now()
	for range time.Tick(5 * time.Minute) {
		pruneMemory()
		if hours > 0 && time.Since(last) >= time.Duration(hours)*time.Hour {
			if err := store.Reset(); err != nil {
				log.Printf("scheduled reset: %v", err)
			} else {
				log.Printf("scheduled demo reset (every %dh)", hours)
			}
			last = time.Now()
		}
	}
}

func newServer(port string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              ":" + port,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}
}
