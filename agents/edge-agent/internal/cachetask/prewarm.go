package cachetask

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"
)

type tokenBucket struct {
	mu     sync.Mutex
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
}

func newTokenBucket(rate float64, burst int) *tokenBucket {
	now := time.Now()
	return &tokenBucket{rate: rate, burst: float64(burst), tokens: float64(burst), last: now}
}

func (b *tokenBucket) wait(ctx context.Context) error {
	for {
		b.mu.Lock()
		now := time.Now()
		elapsed := now.Sub(b.last).Seconds()
		if elapsed > 0 {
			b.tokens += elapsed * b.rate
			if b.tokens > b.burst {
				b.tokens = b.burst
			}
			b.last = now
		}
		if b.tokens >= 1 {
			b.tokens--
			b.mu.Unlock()
			return nil
		}
		wait := time.Duration((1-b.tokens)/b.rate*float64(time.Second)) + time.Nanosecond
		b.mu.Unlock()
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}

type prewarmOutcome struct {
	status     ItemStatus
	code       string
	affected   int
	bytes      int64
	retryable  bool
	retryAfter string
}

func (m *Manager) prewarm(ctx context.Context, task normalizedTask, target normalizedTarget,
	taskRate *tokenBucket, byteAllowance int64) prewarmOutcome {
	site := target.Site
	siteRate, releaseSiteRate, err := m.siteLimiter(siteLimiterIdentity(site))
	if err != nil {
		return prewarmOutcome{status: ItemFailed, code: CodePrewarmUpstream, retryable: true}
	}
	defer releaseSiteRate()
	publicURL, err := url.Parse(target.RequestURL)
	if err != nil {
		return prewarmOutcome{status: ItemFailed, code: CodePrewarmUpstream}
	}
	internalURL := *publicURL
	internalURL.Scheme = "http"
	internalURL.Path = site.PrewarmPathPrefix + publicURL.Path[1:]
	if publicURL.RawPath != "" {
		internalURL.RawPath = site.PrewarmPathPrefix + publicURL.RawPath[1:]
	}
	// The target's own host (an alias or a name under a wildcard), never the
	// "*." key domain; the prewarm location forwards it as the origin Host.
	host := target.RequestHost
	if host == "" {
		host = site.Domain
	}
	internalURL.Host = net.JoinHostPort(host, strconv.Itoa(int(site.PrewarmPort)))
	loopback := net.JoinHostPort(m.config.LoopbackAddress.String(), strconv.Itoa(int(site.PrewarmPort)))
	dialer := &net.Dialer{Timeout: m.config.RequestTimeout, KeepAlive: -1}
	transport := &http.Transport{
		Proxy: nil, DisableCompression: true, DisableKeepAlives: true,
		MaxResponseHeaderBytes: 64 << 10, ResponseHeaderTimeout: m.config.RequestTimeout,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			if network != "tcp" && network != "tcp4" && network != "tcp6" {
				return nil, errors.New("unsupported prewarm network")
			}
			return dialer.DialContext(ctx, "tcp", loopback)
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	doRequest := func(resourceAllowance, missAllowance int64) (prewarmOutcome, string) {
		if resourceAllowance <= 0 {
			return prewarmOutcome{status: ItemFailed, code: CodePrewarmResponseTooLarge}, ""
		}
		for _, limiter := range []*tokenBucket{m.globalRate, siteRate, taskRate} {
			if err := limiter.wait(ctx); err != nil {
				return prewarmOutcome{status: ItemFailed, code: contextFailureCode(ctx)}, ""
			}
		}
		if !m.activeSiteBindingMatches(ctx, task) {
			return prewarmOutcome{status: ItemFailed, code: CodeSiteContextStale}, ""
		}
		return m.withActiveReleaseLease(ctx, task, func() (prewarmOutcome, string) {
			requestContext, cancel := context.WithTimeout(ctx, m.config.RequestTimeout)
			defer cancel()
			request, err := http.NewRequestWithContext(requestContext, http.MethodGet, internalURL.String(), nil)
			if err != nil {
				return prewarmOutcome{status: ItemFailed, code: CodePrewarmUpstream}, ""
			}
			request.Host = host
			request.Header.Set("User-Agent", "")
			request.Header.Set("X-CDNCA-Internal-Cache-Task", CacheKeyVersion)
			request.Header.Set("X-CDNCA-Cache-Namespace", site.CacheIdentity)
			return executePrewarmRequest(ctx, requestContext, client, request, site, m.allowedStatuses,
				resourceAllowance, missAllowance)
		})
	}

	before, failure := m.prewarmCacheSnapshotWithActiveRelease(ctx, task, target)
	if failure != nil {
		return *failure
	}
	first, firstState := doRequest(byteAllowance, byteAllowance)
	if first.status == ItemFailed {
		return first
	}
	if firstState == "HIT" {
		return m.prewarmHitOutcome(ctx, task, target, before, false, first, ItemSkipped, CodeAlreadyCached)
	}
	second, secondState := doRequest(byteAllowance, byteAllowance-first.bytes)
	if secondState == "MISS" {
		second.bytes += first.bytes
	} else {
		second.bytes = max(first.bytes, second.bytes)
	}
	if second.status == ItemFailed {
		return second
	}
	if secondState != "HIT" {
		return prewarmOutcome{status: ItemFailed, code: CodePrewarmNotCacheable, bytes: second.bytes}
	}
	return m.prewarmHitOutcome(ctx, task, target, before, true, second, ItemSuccess, CodePrewarmed)
}

func (m *Manager) prewarmHitOutcome(ctx context.Context, task normalizedTask, target normalizedTarget,
	before prewarmCacheSnapshot, requireChange bool, response prewarmOutcome, status ItemStatus, code string) prewarmOutcome {
	verified, _ := m.withActiveReleaseLease(ctx, task, func() (prewarmOutcome, string) {
		after, err := m.prewarmCacheSnapshot(ctx, target)
		if err != nil {
			return prewarmEvidenceFailure(ctx, err), ""
		}
		if len(after) == 0 || requireChange && samePrewarmCacheSnapshot(before, after) {
			return prewarmOutcome{status: ItemFailed, code: CodePrewarmNotCacheable}, ""
		}
		return prewarmOutcome{status: status, code: code}, ""
	})
	verified.bytes = response.bytes
	return verified
}

type prewarmCacheIdentity struct {
	size   int64
	device uint64
	inode  uint64
}

type prewarmCacheSnapshot map[string]prewarmCacheIdentity

func (m *Manager) prewarmCacheSnapshotWithActiveRelease(ctx context.Context, task normalizedTask,
	target normalizedTarget) (prewarmCacheSnapshot, *prewarmOutcome) {
	var snapshot prewarmCacheSnapshot
	outcome, _ := m.withActiveReleaseLease(ctx, task, func() (prewarmOutcome, string) {
		var err error
		snapshot, err = m.prewarmCacheSnapshot(ctx, target)
		if err != nil {
			return prewarmEvidenceFailure(ctx, err), ""
		}
		return prewarmOutcome{}, ""
	})
	if outcome.code != "" {
		return nil, &outcome
	}
	return snapshot, nil
}

func prewarmEvidenceFailure(ctx context.Context, err error) prewarmOutcome {
	if ctx.Err() != nil {
		return prewarmOutcome{status: ItemFailed, code: contextFailureCode(ctx)}
	}
	var operation *operationError
	if errors.As(err, &operation) {
		switch operation.code {
		case CodeCacheLayoutUnsafe, CodeCacheMetadataInvalid:
			return prewarmOutcome{status: ItemFailed, code: operation.code}
		case CodePurgeScanBudgetExceeded:
			return prewarmOutcome{status: ItemFailed, code: CodePrewarmNotCacheable}
		}
	}
	return prewarmOutcome{status: ItemFailed, code: CodePrewarmUpstream, retryable: true}
}

func (m *Manager) prewarmCacheSnapshot(ctx context.Context, target normalizedTarget) (prewarmCacheSnapshot, error) {
	budget := newCacheScanBudget(ResourceBudget{
		MaxScanEntries:  m.config.MaxScanEntries,
		MaxScanBytes:    m.config.MaxScanBytes,
		MaxScanDuration: m.config.MaxScanDuration,
	})
	snapshot := make(prewarmCacheSnapshot)
	if !cachePolicyProjectedKey(target.Site) {
		entry, err := m.exactEntry(ctx, target.Site, target, budget)
		if err == nil && validPrewarmCacheEntry(entry) {
			snapshot[entry.relative] = prewarmCacheIdentity{entry.size, entry.device, entry.inode}
		}
		return snapshot, err
	}
	err := m.walkEntries(ctx, target.Site, budget, func(entry cacheEntry) error {
		if purgeMatchPolicy(ActionPurgeExact, target, entry) && validPrewarmCacheEntry(&entry) {
			snapshot[entry.relative] = prewarmCacheIdentity{entry.size, entry.device, entry.inode}
		}
		return nil
	})
	return snapshot, err
}

func validPrewarmCacheEntry(entry *cacheEntry) bool {
	return entry != nil && entry.root != "" && entry.relative != "" && entry.size > 0 &&
		entry.device != 0 && entry.inode != 0
}

func samePrewarmCacheSnapshot(left, right prewarmCacheSnapshot) bool {
	if len(left) != len(right) {
		return false
	}
	for path, identity := range left {
		if right[path] != identity {
			return false
		}
	}
	return true
}

func (m *Manager) withActiveReleaseLease(ctx context.Context, task normalizedTask,
	operation func() (prewarmOutcome, string)) (prewarmOutcome, string) {
	releaseActive, err := m.lockActiveRelease(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return prewarmOutcome{status: ItemFailed, code: contextFailureCode(ctx)}, ""
		}
		return prewarmOutcome{status: ItemFailed, code: CodeSiteContextStale}, ""
	}
	defer releaseActive()
	if !m.activeSiteBindingMatches(ctx, task) {
		return prewarmOutcome{status: ItemFailed, code: CodeSiteContextStale}, ""
	}
	return operation()
}

type prewarmDoer interface {
	Do(*http.Request) (*http.Response, error)
}

func executePrewarmRequest(ctx, requestContext context.Context, client prewarmDoer, request *http.Request,
	site SiteContext, allowedStatuses map[int]struct{}, resourceAllowance, missAllowance int64) (prewarmOutcome, string) {
	response, err := client.Do(request)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(requestContext.Err(), context.DeadlineExceeded) {
			return prewarmOutcome{status: ItemFailed, code: CodePrewarmTimeout, retryable: true}, ""
		}
		if ctx.Err() != nil {
			return prewarmOutcome{status: ItemFailed, code: contextFailureCode(ctx)}, ""
		}
		return prewarmOutcome{status: ItemFailed, code: CodePrewarmUpstream, retryable: true}, ""
	}
	bodyClosed := false
	defer func() {
		if !bodyClosed {
			_ = response.Body.Close()
		}
	}()
	if response.StatusCode >= 300 && response.StatusCode <= 399 {
		return prewarmOutcome{status: ItemFailed, code: CodePrewarmRedirect}, ""
	}
	if _, allowed := allowedStatuses[response.StatusCode]; !allowed {
		retryAfter := ""
		if values := response.Header.Values("Retry-After"); len(values) == 1 {
			retryAfter = values[0]
		}
		return prewarmOutcome{
			status: ItemFailed, code: CodePrewarmStatus,
			retryable:  response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= 500,
			retryAfter: retryAfter,
		}, ""
	}
	versionValues := response.Header.Values("X-CDNCA-Config-Version")
	if len(versionValues) != 1 || versionValues[0] != site.ConfigVersionID {
		return prewarmOutcome{status: ItemFailed, code: CodeSiteContextStale}, ""
	}
	namespaceValues := response.Header.Values("X-CDNCA-Cache-Namespace")
	if len(namespaceValues) != 1 || namespaceValues[0] != site.CacheIdentity {
		return prewarmOutcome{status: ItemFailed, code: CodeSiteContextStale}, ""
	}
	cacheValues := response.Header.Values("X-CDN-Cache")
	if len(cacheValues) != 1 {
		return prewarmOutcome{status: ItemFailed, code: CodePrewarmNotCacheable}, ""
	}
	cacheState, cacheable := prewarmCacheState(cacheValues[0])
	if !cacheable {
		return prewarmOutcome{status: ItemFailed, code: CodePrewarmNotCacheable}, ""
	}
	bodyAllowance := resourceAllowance
	if cacheState == "MISS" && missAllowance < bodyAllowance {
		bodyAllowance = missAllowance
	}
	written, exceeded, err := readAndClosePrewarmBody(response.Body, bodyAllowance)
	bodyClosed = true
	if exceeded {
		return prewarmOutcome{status: ItemFailed, code: CodePrewarmResponseTooLarge, bytes: bodyAllowance}, cacheState
	}
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(requestContext.Err(), context.DeadlineExceeded) {
			return prewarmOutcome{status: ItemFailed, code: CodePrewarmTimeout, bytes: written, retryable: true}, cacheState
		}
		if ctx.Err() != nil {
			return prewarmOutcome{status: ItemFailed, code: contextFailureCode(ctx), bytes: written}, cacheState
		}
		return prewarmOutcome{status: ItemFailed, code: CodePrewarmUpstream, bytes: written, retryable: true}, cacheState
	}
	if cacheState == "HIT" {
		return prewarmOutcome{status: ItemSkipped, code: CodeAlreadyCached, bytes: written}, cacheState
	}
	return prewarmOutcome{status: ItemSuccess, code: CodePrewarmed, bytes: written}, cacheState
}

// prewarmCacheState folds the cache status a prewarm reads (ge-cache H:
// X-CDN-Cache names STALE/UPDATING/REVALIDATED/EXPIRED) to the two states
// prewarm reasons about: MISS (this request filled the object: MISS, EXPIRED)
// or HIT (an object was already there: HIT, REVALIDATED, STALE, UPDATING).
// BYPASS and anything else is not cacheable.
func prewarmCacheState(value string) (string, bool) {
	switch value {
	case "MISS", "EXPIRED":
		return "MISS", true
	case "HIT", "REVALIDATED", "STALE", "UPDATING":
		return "HIT", true
	default:
		return "", false
	}
}

func retryDelayWithServerHint(local time.Duration, raw string, now time.Time, maximum time.Duration) time.Duration {
	server := time.Duration(0)
	if raw != "" {
		if seconds, err := strconv.ParseUint(raw, 10, 31); err == nil && seconds > 0 {
			server = time.Duration(seconds) * time.Second
		} else if when, err := http.ParseTime(raw); err == nil && when.After(now) {
			server = when.Sub(now)
		}
	}
	if server > maximum {
		server = maximum
	}
	if server > local {
		return server
	}
	return local
}

func readAndClosePrewarmBody(body io.ReadCloser, allowance int64) (int64, bool, error) {
	written, readErr := io.Copy(io.Discard, io.LimitReader(body, allowance+1))
	closeErr := body.Close()
	if readErr != nil {
		return written, written > allowance, readErr
	}
	return written, written > allowance, closeErr
}

func contextFailureCode(ctx context.Context) string {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return CodeTaskDeadlineExceeded
	}
	return CodeTaskCancelled
}
