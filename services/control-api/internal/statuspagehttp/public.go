package statuspagehttp

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/statuspage"
)

const (
	snapshotTTL    = 30 * time.Second
	staleTTL       = 5 * time.Minute
	limitWindow    = time.Minute
	limitPerSource = 60
	limitSources   = 50000
)

type snapshot struct {
	body     []byte
	etag     string
	disabled bool
	builtAt  time.Time
}

// publicCache rebuilds the public view at most once per snapshotTTL; a
// failed rebuild keeps serving the last good one for up to staleTTL.
type publicCache struct {
	mu      sync.Mutex
	current *snapshot
	build   func(context.Context) (statuspage.PublicView, error)
	now     func() time.Time
}

func (c *publicCache) get(ctx context.Context) (*snapshot, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if c.current != nil && now.Sub(c.current.builtAt) < snapshotTTL {
		return c.current, nil
	}
	view, err := c.build(ctx)
	switch {
	case errors.Is(err, statuspage.ErrDisabled):
		c.current = &snapshot{disabled: true, builtAt: now}
		return c.current, nil
	case err != nil:
		if c.current != nil && now.Sub(c.current.builtAt) < staleTTL {
			return c.current, nil
		}
		return nil, err
	}
	body, err := json.Marshal(view)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(body)
	c.current = &snapshot{body: body, etag: `"` + base64.RawURLEncoding.EncodeToString(digest[:16]) + `"`, builtAt: now}
	return c.current, nil
}

// sourceLimiter allows limitPerSource requests per source per fixed minute
// window; once limitSources sources are tracked, new ones are refused until
// the window resets.
type sourceLimiter struct {
	mu      sync.Mutex
	start   time.Time
	counts  map[string]int
	now     func() time.Time
	maximum int
}

func (l *sourceLimiter) allow(source string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if now.Sub(l.start) >= limitWindow || now.Before(l.start) {
		l.start, l.counts = now, map[string]int{}
	}
	count, known := l.counts[source]
	if !known && len(l.counts) >= limitSources || count >= l.maximum {
		return false
	}
	l.counts[source] = count + 1
	return true
}

func (h *Handler) public(w http.ResponseWriter, r *http.Request, requestID string) {
	header := w.Header()
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		header.Set("Allow", "GET, HEAD")
		header.Set("Cache-Control", "no-store")
		writeError(w, requestID, http.StatusMethodNotAllowed, "status_page_method_not_allowed")
		return
	}
	if !h.limiter.allow(h.sourceIP(r)) {
		header.Set("Retry-After", strconv.Itoa(int(limitWindow.Seconds())))
		header.Set("Cache-Control", "no-store")
		writeError(w, requestID, http.StatusTooManyRequests, "status_page_rate_limited")
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 10*time.Second)
	defer cancel()
	current, err := h.cache.get(ctx)
	if err != nil {
		header.Set("Cache-Control", "no-store")
		writeError(w, requestID, http.StatusServiceUnavailable, "status_page_unavailable")
		return
	}
	header.Set("Cache-Control", "public, max-age=30")
	if current.disabled {
		writeError(w, requestID, http.StatusNotFound, "status_page_disabled")
		return
	}
	header.Set("ETag", current.etag)
	if noneMatch(r.Header.Get("If-None-Match"), current.etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	header.Set("Content-Type", "application/json")
	header.Set("Content-Length", strconv.Itoa(len(current.body)))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write(current.body)
	}
}

// noneMatch compares weakly (RFC 9110 13.1.2): a gzipping proxy weakens the ETag.
func noneMatch(header, quoted string) bool {
	for _, tag := range strings.Split(header, ",") {
		if strings.TrimPrefix(strings.TrimSpace(tag), "W/") == quoted {
			return true
		}
	}
	return false
}
