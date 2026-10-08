package gate

import (
	"context"
	"sync"
	"time"
)

// provider is one destination family: a third-party source with its literal
// hosts and compiled ceilings, or an asset's own site. A throttle in the
// engagement file only lowers a ceiling (docs/spec/scope.md, "Throttle,
// timeouts and retries").
type provider struct {
	// source is the name the audit line and the report give the source;
	// empty for an asset's own site.
	source string
	// operator is who runs a public source, printed with what it was sent.
	operator    string
	hosts       []string
	web         bool
	concurrency int
	rate        float64 // requests per second
	timeout     time.Duration
	// floor stops the provider while a fifth of its rate limit is left:
	// a GitHub token is often a person's, shared with their CI.
	floor bool
}

// providers is the declared list of sources (docs/spec/scope.md,
// "Third-party sources"). DNS is the gate's own resolution, paced by
// dnsRate.
var providers = map[string]provider{
	"github": {source: "api.github.com", hosts: []string{"api.github.com"}, concurrency: 1, rate: 10, floor: true},
	"google": {source: "google", hosts: []string{"admin.googleapis.com", "oauth2.googleapis.com"}, concurrency: 2, rate: 5},
	"crt.sh": {source: "crt.sh", operator: "Sectigo", hosts: []string{"crt.sh"}, concurrency: 1, rate: 1, timeout: 60 * time.Second},
	"web":    {web: true},
}

const (
	dnsRate = 20 // queries per second
	// addrRate caps requests to one address across assets: CDNs share
	// addresses, so per-asset throttles alone could add up on one server.
	addrRate = 5
)

// limiter paces requests to a rate and bounds how many are in flight.
type limiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
	sem      chan struct{}
}

func newLimiter(rate float64, concurrency int) *limiter {
	if concurrency < 1 {
		concurrency = 1
	}
	l := &limiter{sem: make(chan struct{}, concurrency)}
	if rate > 0 {
		l.interval = time.Duration(float64(time.Second) / rate)
	}
	return l
}

// acquire waits for a slot and the next tick. The caller releases the slot
// when its request ends.
func (l *limiter) acquire(ctx context.Context, now func() time.Time, sleep func(context.Context, time.Duration) error) (func(), error) {
	select {
	case l.sem <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	release := func() { <-l.sem }
	l.mu.Lock()
	t := now()
	at := l.next
	if at.Before(t) {
		at = t
	}
	l.next = at.Add(l.interval)
	l.mu.Unlock()
	if wait := at.Sub(t); wait > 0 {
		if err := sleep(ctx, wait); err != nil {
			release()
			return nil, err
		}
	}
	return release, nil
}

// limiters holds one limiter per key, created on first use.
type limiters struct {
	mu sync.Mutex
	m  map[string]*limiter
}

func (ls *limiters) get(key string, rate float64, concurrency int) *limiter {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	if ls.m == nil {
		ls.m = map[string]*limiter{}
	}
	l, ok := ls.m[key]
	if !ok {
		l = newLimiter(rate, concurrency)
		ls.m[key] = l
	}
	return l
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
