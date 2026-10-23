package executor

import (
	"context"
	"fmt"
	"sync"
	"time"
)

type httpBudgetKey struct{}

// maxHTTPRequestsPerTarget bounds read-only GETs against one authorized
// target per task. It must cover the curated detection template set (nuclei
// allows up to a few thousand bundled templates) plus the baseline header
// checks and the preflight root GET; the request rate still paces them.
const maxHTTPRequestsPerTarget = 8000

type httpBudget struct {
	mu              sync.Mutex
	next            time.Time
	rate, perTarget int
	requests        map[string]int
}

// One task shares a request/connection budget across preflight, engine proxy,
// and native checks. HTTPS templates are additionally bounded by the validated
// one-GET-per-template whitelist and the engine request rate.
func withHTTPBudget(ctx context.Context, rate, perTarget int) context.Context {
	if ctx.Value(httpBudgetKey{}) != nil {
		return ctx
	}
	if rate < 1 || rate > 250 {
		rate = 5
	}
	return context.WithValue(ctx, httpBudgetKey{}, &httpBudget{rate: rate, perTarget: perTarget, requests: map[string]int{}})
}
func takeHTTPRequest(ctx context.Context, target string) error {
	b, ok := ctx.Value(httpBudgetKey{}).(*httpBudget)
	if !ok {
		return nil
	}
	canonical, err := numericTarget(target)
	if err != nil {
		return err
	}
	b.mu.Lock()
	if b.requests[canonical] >= b.perTarget {
		b.mu.Unlock()
		return fmt.Errorf("HTTP request budget exhausted for scoped endpoint")
	}
	b.requests[canonical]++
	delay := time.Until(b.next)
	if delay < 0 {
		delay = 0
	}
	b.next = time.Now().Add(delay + time.Second/time.Duration(b.rate))
	b.mu.Unlock()
	return waitSmall(ctx, delay)
}
func httpRequestRate(ctx context.Context, fallback int) int {
	if b, ok := ctx.Value(httpBudgetKey{}).(*httpBudget); ok {
		return b.rate
	}
	return fallback
}
