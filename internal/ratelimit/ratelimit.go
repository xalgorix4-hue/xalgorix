// Package ratelimit provides a per-domain token-bucket rate limiter
// for outbound HTTP requests made by Xalgorix tools.
//
// Configuration (via env or ~/.xalgorix.env):
//
//	XALGORIX_RATE_RPS   – sustained requests per second per domain (default 10)
//	XALGORIX_RATE_BURST – burst size per domain                    (default 20)
//
// Set XALGORIX_RATE_RPS=0 to disable rate limiting entirely.
package ratelimit

import (
	"net/url"
	"sync"

	"golang.org/x/time/rate"
)

// Limiter is a concurrency-safe, per-domain rate limiter.
type Limiter struct {
	mu       sync.Mutex
	limiters map[string]*rate.Limiter
	rps      float64
	burst    int
}

// New creates a Limiter with the given sustained rate (requests/sec) and
// burst size. If rps <= 0 the limiter is disabled (all requests pass
// through immediately).
func New(rps float64, burst int) *Limiter {
	if burst < 1 {
		burst = 1
	}
	return &Limiter{
		limiters: make(map[string]*rate.Limiter),
		rps:      rps,
		burst:    burst,
	}
}

// domain extracts the hostname from rawURL, falling back to rawURL itself
// if parsing fails so we never panic on malformed input.
func domain(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return rawURL
	}
	return u.Hostname()
}

// limiterFor returns (or lazily creates) the per-domain *rate.Limiter.
func (l *Limiter) limiterFor(host string) *rate.Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()

	if rl, ok := l.limiters[host]; ok {
		return rl
	}
	rl := rate.NewLimiter(rate.Limit(l.rps), l.burst)
	l.limiters[host] = rl
	return rl
}

// Wait blocks until a token is available for the domain extracted from
// targetURL, or returns immediately when rate limiting is disabled.
func (l *Limiter) Wait(targetURL string) {
	if l.rps <= 0 {
		return
	}
	host := domain(targetURL)
	rl := l.limiterFor(host)
	_ = rl.Wait(nil) //nolint:errcheck // context is nil — never returns an error
}

// Allow reports whether a token is immediately available for targetURL
// without blocking. Returns true when rate limiting is disabled.
func (l *Limiter) Allow(targetURL string) bool {
	if l.rps <= 0 {
		return true
	}
	return l.limiterFor(domain(targetURL)).Allow()
}

// Reset discards all per-domain limiters, restoring each domain's bucket
// to its full burst capacity. Useful between scan sessions.
func (l *Limiter) Reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.limiters = make(map[string]*rate.Limiter)
}
