// Package ratelimit provides a minimal token-bucket limiter with no external
// dependencies, used to keep active scanning polite.
package ratelimit

import (
	"context"
	"sync"
	"time"
)

// Limiter is a token-bucket rate limiter. A nil *Limiter allows everything,
// so callers can use an unlimited limiter by passing nil.
type Limiter struct {
	mu     sync.Mutex
	rate   float64 // tokens per second
	burst  float64
	tokens float64
	last   time.Time
}

// New returns a limiter allowing ratePerSec requests per second. A rate of 0
// or less returns nil, meaning unlimited.
func New(ratePerSec float64) *Limiter {
	if ratePerSec <= 0 {
		return nil
	}
	burst := ratePerSec
	if burst < 1 {
		burst = 1
	}
	return &Limiter{rate: ratePerSec, burst: burst, tokens: burst, last: time.Now()}
}

// Wait blocks until a token is available or ctx is cancelled.
func (l *Limiter) Wait(ctx context.Context) error {
	if l == nil {
		return nil
	}
	for {
		l.mu.Lock()
		now := time.Now()
		l.tokens += now.Sub(l.last).Seconds() * l.rate
		l.last = now
		if l.tokens > l.burst {
			l.tokens = l.burst
		}
		if l.tokens >= 1 {
			l.tokens--
			l.mu.Unlock()
			return nil
		}
		wait := time.Duration((1 - l.tokens) / l.rate * float64(time.Second))
		l.mu.Unlock()

		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
