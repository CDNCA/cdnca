package statuspagehttp

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/statuspage"
)

func TestSourceLimiter(t *testing.T) {
	now := time.Unix(1000, 0)
	limiter := &sourceLimiter{counts: map[string]int{}, now: func() time.Time { return now }, maximum: 2}
	if !limiter.allow("a") || !limiter.allow("a") || limiter.allow("a") || !limiter.allow("b") {
		t.Fatal("per-source limit")
	}
	now = now.Add(limitWindow)
	if !limiter.allow("a") {
		t.Fatal("window reset")
	}
}

func TestPublicCacheServesSnapshotAndStale(t *testing.T) {
	now := time.Unix(1000, 0)
	builds, fail := 0, false
	cache := &publicCache{now: func() time.Time { return now }, build: func(context.Context) (statuspage.PublicView, error) {
		builds++
		if fail {
			return statuspage.PublicView{}, errors.New("down")
		}
		return statuspage.PublicView{Schema: statuspage.PublicSchema}, nil
	}}
	first, err := cache.get(t.Context())
	if err != nil || first.etag == "" {
		t.Fatal(err)
	}
	now = now.Add(10 * time.Second)
	if _, _ = cache.get(t.Context()); builds != 1 {
		t.Fatalf("rebuilt inside the TTL: %d", builds)
	}
	fail, now = true, now.Add(time.Minute)
	if stale, err := cache.get(t.Context()); err != nil || stale != first {
		t.Fatalf("stale not served: %v", err)
	}
	now = now.Add(staleTTL)
	if _, err := cache.get(t.Context()); err == nil {
		t.Fatal("stale beyond staleTTL served")
	}
}

func TestPublicCacheDisabled(t *testing.T) {
	cache := &publicCache{now: time.Now, build: func(context.Context) (statuspage.PublicView, error) {
		return statuspage.PublicView{}, statuspage.ErrDisabled
	}}
	current, err := cache.get(t.Context())
	if err != nil || !current.disabled {
		t.Fatalf("disabled snapshot: %+v %v", current, err)
	}
}

func TestNoneMatchWeak(t *testing.T) {
	if !noneMatch(`W/"abc", "x"`, `"abc"`) || noneMatch(`"abd"`, `"abc"`) {
		t.Fatal("noneMatch")
	}
}
