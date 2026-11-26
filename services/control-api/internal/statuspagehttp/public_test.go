package statuspagehttp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
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

// 管理员写入后快照立即作废；作废的快照也不能在重建失败时当旧数据兜底。
func TestPublicCacheInvalidate(t *testing.T) {
	now := time.Unix(1000, 0)
	builds, enabled, fail := 0, true, false
	cache := &publicCache{now: func() time.Time { return now }, build: func(context.Context) (statuspage.PublicView, error) {
		builds++
		switch {
		case fail:
			return statuspage.PublicView{}, errors.New("down")
		case !enabled:
			return statuspage.PublicView{}, statuspage.ErrDisabled
		}
		return statuspage.PublicView{Schema: statuspage.PublicSchema}, nil
	}}
	if current, err := cache.get(t.Context()); err != nil || current.disabled {
		t.Fatalf("open: %+v %v", current, err)
	}
	enabled, now = false, now.Add(time.Second)
	cache.invalidate()
	if current, err := cache.get(t.Context()); err != nil || !current.disabled || builds != 2 {
		t.Fatalf("closed inside the TTL: %+v %v builds=%d", current, err, builds)
	}
	enabled = true
	cache.invalidate()
	if current, err := cache.get(t.Context()); err != nil || current.disabled || builds != 3 {
		t.Fatalf("reopened: %+v %v builds=%d", current, err, builds)
	}
	if _, _ = cache.get(t.Context()); builds != 3 {
		t.Fatalf("no write, still cached: builds=%d", builds)
	}
	fail = true
	cache.invalidate()
	if _, err := cache.get(t.Context()); err == nil {
		t.Fatal("invalidated snapshot served as stale")
	}
}

// A rebuild that read the store before the write is not kept: the next request rebuilds.
func TestPublicCacheRebuildRacingAWrite(t *testing.T) {
	builds := 0
	var cache *publicCache
	cache = &publicCache{now: time.Now, build: func(context.Context) (statuspage.PublicView, error) {
		builds++
		if builds == 1 {
			cache.invalidate() // the save commits while this build is in flight
		}
		return statuspage.PublicView{Schema: statuspage.PublicSchema}, nil
	}}
	_, _ = cache.get(t.Context())
	_, _ = cache.get(t.Context())
	if builds != 2 {
		t.Fatalf("builds=%d, want the racing snapshot dropped", builds)
	}
}

func TestPublicCacheHeaders(t *testing.T) {
	enabled := true
	handler := &Handler{
		sourceIP: func(*http.Request) string { return "203.0.113.1" },
		limiter:  &sourceLimiter{counts: map[string]int{}, now: time.Now, maximum: limitPerSource},
		cache: &publicCache{now: time.Now, build: func(context.Context) (statuspage.PublicView, error) {
			if !enabled {
				return statuspage.PublicView{}, statuspage.ErrDisabled
			}
			return statuspage.PublicView{Schema: statuspage.PublicSchema}, nil
		}},
	}
	get := func(etag string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodGet, PublicRoute, nil)
		if etag != "" {
			request.Header.Set("If-None-Match", etag)
		}
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		return recorder
	}
	open := get("")
	etag := open.Header().Get("ETag")
	if open.Code != http.StatusOK || open.Header().Get("Cache-Control") != "public, no-cache" || etag == "" {
		t.Fatalf("open: %d %q %q", open.Code, open.Header().Get("Cache-Control"), etag)
	}
	if again := get(etag); again.Code != http.StatusNotModified || again.Header().Get("Cache-Control") != "public, no-cache" {
		t.Fatalf("304: %d %q", again.Code, again.Header().Get("Cache-Control"))
	}
	enabled = false
	handler.written()
	if closed := get(etag); closed.Code != http.StatusNotFound || closed.Header().Get("Cache-Control") != "no-store" ||
		closed.Header().Get("ETag") != "" {
		t.Fatalf("closed: %d %q %q", closed.Code, closed.Header().Get("Cache-Control"), closed.Header().Get("ETag"))
	}
}

func TestNoneMatchWeak(t *testing.T) {
	if !noneMatch(`W/"abc", "x"`, `"abc"`) || noneMatch(`"abd"`, `"abc"`) {
		t.Fatal("noneMatch")
	}
}
