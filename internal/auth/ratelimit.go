package auth

import (
	"sync"
	"time"
)

// RateLimiter is an in-memory token-bucket limiter keyed by string (e.g.
// "ip:203.0.113.9" or "user:alice"). It is safe for concurrent use.
type RateLimiter struct {
	mu      sync.Mutex
	rate    float64 // tokens per second
	burst   float64
	buckets map[string]*bucket
	now     func() time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

// maxBuckets bounds memory; full buckets are pruned when exceeded.
const maxBuckets = 50_000

// NewRateLimiter allows perMinute events per key per minute, with bursts up
// to perMinute. perMinute <= 0 disables limiting.
func NewRateLimiter(perMinute int) *RateLimiter {
	return &RateLimiter{
		rate:    float64(perMinute) / 60,
		burst:   float64(perMinute),
		buckets: map[string]*bucket{},
		now:     time.Now,
	}
}

// Allow consumes one token for key and reports whether it was available.
func (l *RateLimiter) Allow(key string) bool {
	if l == nil || l.burst <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= maxBuckets {
			l.pruneLocked(now)
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	b.tokens = min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.rate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Prune drops buckets that have refilled completely.
func (l *RateLimiter) Prune() {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pruneLocked(l.now())
}

func (l *RateLimiter) pruneLocked(now time.Time) {
	for k, b := range l.buckets {
		if b.tokens+now.Sub(b.last).Seconds()*l.rate >= l.burst {
			delete(l.buckets, k)
		}
	}
}
