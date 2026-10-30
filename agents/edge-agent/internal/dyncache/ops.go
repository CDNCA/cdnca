package dyncache

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Site is what an operation needs of one site's cache (its site object's
// cache section and listeners).
type Site struct {
	SiteID    string
	Prefix    string // cache.key_prefix
	Token     string // cache.generation (ge-cache CacheGeneration)
	Domain    string // cache.domain
	KeyByHost bool
	// Names the site serves (primary, aliases, "*." wildcards) and its
	// listener ports with their scheme.
	Names     []string
	Ports     map[int]string // port -> "http" | "https"
	Projected bool           // policy key is the projected form (query/vary digests)
	// Sliced: objects are slices (keys end in |slice=<range>): an exact URL
	// is every slice of it, found by a zone scan.
	Sliced bool
	// QuotaBytes is the soft quota (policy.disk_quota_bytes).
	QuotaBytes int64
}

func (site Site) serves(host string) bool {
	for _, name := range site.Names {
		if name == host || strings.HasPrefix(name, "*.") && strings.HasSuffix(host, name[1:]) && len(host) > len(name)-1 {
			return true
		}
	}
	return false
}

// Target is one purge target: a URL the site serves.
type Target struct {
	Host string
	Port int
	// URI is the path and query as the cache key's policy key names them
	// ($uri$is_args$args: percent-decoded path, raw query).
	URI  string
	Path string
	// WildcardSuffix (purge only, CACHE_WILDCARD_PURGE): the URL named
	// "*.<suffix>"; the target covers every host under suffix the site keys.
	WildcardSuffix string
}

// servesWildcard: a purge of "*.<suffix>" stays within the site: it serves
// "*.<suffix>", a wildcard covering every host under suffix, or names under
// suffix (control plane cachecontrol servesWildcard is the same rule).
func (site Site) servesWildcard(suffix string) bool {
	for _, name := range site.Names {
		if name == "*."+suffix || strings.HasSuffix(name, "."+suffix) ||
			strings.HasPrefix(name, "*.") && strings.HasSuffix(suffix, name[1:]) {
			return true
		}
	}
	return false
}

// ParseTarget normalizes a purge URL against the site.
func ParseTarget(site Site, raw string, prefix bool) (Target, error) {
	value, err := url.Parse(raw)
	if err != nil || value.Host == "" || value.User != nil || value.Fragment != "" {
		return Target{}, fmt.Errorf("%w: target %q", ErrInvalid, raw)
	}
	host := strings.ToLower(value.Hostname())
	port := 0
	if value.Port() != "" {
		port, err = strconv.Atoi(value.Port())
		if err != nil {
			return Target{}, fmt.Errorf("%w: target port %q", ErrInvalid, raw)
		}
	} else if value.Scheme == "https" {
		port = 443
	} else {
		port = 80
	}
	suffix, wildcard := strings.CutPrefix(host, "*.")
	if wildcard && (strings.Contains(suffix, "*") || !strings.Contains(suffix, ".") || !site.servesWildcard(suffix)) ||
		!wildcard && strings.Contains(host, "*") {
		return Target{}, fmt.Errorf("%w: %q is not served by the site", ErrInvalid, raw)
	}
	if scheme, ok := site.Ports[port]; !ok || scheme != value.Scheme || !wildcard && !site.serves(host) {
		return Target{}, fmt.Errorf("%w: %q is not served by the site", ErrInvalid, raw)
	}
	path := value.Path
	if path == "" {
		path = "/"
	}
	if prefix && value.RawQuery != "" {
		return Target{}, fmt.Errorf("%w: a prefix has no query", ErrInvalid)
	}
	uri := path
	if value.ForceQuery || value.RawQuery != "" {
		uri += "?" + value.RawQuery
	}
	target := Target{Host: host, Port: port, URI: uri, Path: path}
	if wildcard {
		target.WildcardSuffix = suffix
	}
	return target, nil
}

// hostMatches: the key's host field belongs to the target. A wildcard target
// covers every keyed host under its suffix (or the wildcard name itself); a
// site keyed by its domain only when that domain is under the wildcard.
func (target Target) hostMatches(site Site, keyHost string) bool {
	if target.WildcardSuffix == "" {
		return keyHost == site.keyName(target.Host)
	}
	under := func(name string) bool {
		return name == "*."+target.WildcardSuffix || strings.HasSuffix(name, "."+target.WildcardSuffix)
	}
	if site.KeyByHost {
		return under(keyHost)
	}
	return keyHost == site.Domain && under(site.Domain)
}

// keyName is the host field the site's keys carry for a request to host.
func (site Site) keyName(host string) string {
	if site.KeyByHost {
		return host
	}
	return site.Domain
}

// matches reports whether an object of the site belongs to the target.
// Every generation and freshness token of the site is matched: an object of
// an earlier generation is not served any more but still holds disk.
func (target Target) matches(site Site, key Key, prefix bool) bool {
	if key.Prefix != site.Prefix || key.Port != target.Port || !target.hostMatches(site, key.Host) {
		return false
	}
	if prefix {
		directory := strings.TrimSuffix(target.Path, "/") + "/"
		return key.Path == target.Path || strings.HasPrefix(key.Path, directory)
	}
	if site.Projected {
		// projected keys carry digests of the query and vary headers: every
		// variant of the path is the URL's object
		return key.Path == target.Path
	}
	return key.PolicyKey == target.URI
}

// Result of a purge.
type Result struct {
	Affected int
	Bytes    int64
}

// Purge removes the objects of the targets (exact URLs or prefixes) of one
// site. Only the site's zone is read, and only files whose key carries the
// site's prefix are removed.
// generations, when given, enables the exact fast path: a plain key's file
// is md5 of the current-generation key, so no zone scan is needed (objects
// of earlier generations are unreachable already).
func (zones Zones) Purge(ctx context.Context, site Site, targets []Target, prefix bool, generations *Generations) (Result, error) {
	var result Result
	wildcard := false
	for _, target := range targets {
		wildcard = wildcard || target.WildcardSuffix != ""
	}
	if !site.Projected && !site.Sliced && !prefix && !wildcard && generations != nil {
		if generation, ok := generations.Current(site.Prefix); ok {
			fast := result
			if err := zones.purgeExactFast(ctx, site, targets, generation, &fast); err == nil {
				return fast, nil
			} else if !errors.Is(err, errNeedScan) {
				return result, err
			}
		}
	}
	err := zones.Walk(ctx, site.Prefix, func(entry Entry) error {
		for _, target := range targets {
			if target.matches(site, entry.Key, prefix) {
				removed, err := remove(entry)
				if err != nil {
					return err
				}
				if removed {
					result.Affected++
					result.Bytes += entry.Size
				}
				return nil
			}
		}
		return nil
	})
	return result, err
}

// errNeedScan: the fast path found a file it cannot vouch for.
var errNeedScan = errors.New("scan needed")

func (zones Zones) purgeExactFast(ctx context.Context, site Site, targets []Target, generation uint64, result *Result) error {
	dir, err := zones.ZoneOf(site.Prefix)
	if err != nil {
		return err
	}
	for _, target := range targets {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		key := site.Prefix + "|" + site.Token + "|" + strconv.FormatUint(generation, 10) + "|" + site.keyName(target.Host) + "|" +
			strconv.Itoa(target.Port) + "|" + target.URI
		path := FilePath(dir, key)
		raw, info, err := readKey(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || raw != key {
			return errNeedScan
		}
		parsed, _ := ParseKey(raw)
		entry := entryOf(path, parsed, info)
		removed, err := remove(entry)
		if err != nil {
			return err
		}
		if removed {
			result.Affected++
			result.Bytes += entry.Size
		}
	}
	return nil
}

// PurgeSite empties a site: the purge generation is bumped first (every
// object of the site is unreachable at once, other sites untouched), then the
// site's old objects are removed in the background of the caller.
func (zones Zones) PurgeSite(ctx context.Context, generations *Generations, site Site) (uint64, Result, error) {
	generation, err := generations.Bump(ctx, site.Prefix)
	if err != nil {
		return 0, Result{}, err
	}
	var result Result
	err = zones.Walk(ctx, site.Prefix, func(entry Entry) error {
		if entry.Key.Generation >= generation {
			return nil
		}
		removed, err := remove(entry)
		if err != nil {
			return err
		}
		if removed {
			result.Affected++
			result.Bytes += entry.Size
		}
		return nil
	})
	return generation, result, err
}

// Generations is the per-site purge generation store: a file the agent owns
// (survives restarts) mirrored into the cache module's shared dictionary
// through the control socket. Monotonic per site.
type Generations struct {
	Path    string // JSON {"<prefix>": n}
	Control Control
	mu      sync.Mutex
	values  map[string]uint64
}

// Control posts to the dynamic routing control socket (cdnca_site_admin
// server; the cache module serves /cache/).
type Control interface {
	Post(ctx context.Context, path string, body []byte) ([]byte, error)
}

func (generations *Generations) load() error {
	if generations.values != nil {
		return nil
	}
	generations.values = map[string]uint64{}
	raw, err := os.ReadFile(generations.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, &generations.values)
}

func (generations *Generations) save() error {
	raw, err := json.Marshal(generations.values)
	if err != nil {
		return err
	}
	temporary := generations.Path + ".tmp"
	if err := os.WriteFile(temporary, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, generations.Path)
}

// Current is a site's generation.
func (generations *Generations) Current(prefix string) (uint64, bool) {
	generations.mu.Lock()
	defer generations.mu.Unlock()
	if generations.load() != nil {
		return 0, false
	}
	return generations.values[prefix], true
}

// Sync pushes every generation to the node (after an OpenResty start or a
// shared dictionary resize); until it has run, the node does not cache.
func (generations *Generations) Sync(ctx context.Context) error {
	generations.mu.Lock()
	defer generations.mu.Unlock()
	if err := generations.load(); err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]any{"generations": generations.values, "replace": true})
	_, err := generations.Control.Post(ctx, "/cache/generations", body)
	return err
}

// Bump makes a site's objects unreachable: generation+1, persisted before
// the node sees it (a crash between the two leaves the node behind, Sync on
// restart repairs it; the node never runs ahead of the file).
func (generations *Generations) Bump(ctx context.Context, prefix string) (uint64, error) {
	generations.mu.Lock()
	defer generations.mu.Unlock()
	if err := generations.load(); err != nil {
		return 0, err
	}
	next := generations.values[prefix] + 1
	generations.values[prefix] = next
	if err := generations.save(); err != nil {
		generations.values[prefix] = next - 1
		return 0, err
	}
	body, _ := json.Marshal(map[string]any{"generations": map[string]uint64{prefix: next}})
	if _, err := generations.Control.Post(ctx, "/cache/generations", body); err != nil {
		return 0, err
	}
	return next, nil
}

// UnixControl posts over the control unix socket.
type UnixControl struct{ Socket string }

func (control UnixControl) Post(ctx context.Context, path string, body []byte) ([]byte, error) {
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", control.Socket)
	}}, Timeout: 10 * time.Second}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://cdnca-site-admin"+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	answer, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if response.StatusCode != http.StatusOK {
		return answer, fmt.Errorf("control %s: %d %s", path, response.StatusCode, bytes.TrimSpace(answer))
	}
	return answer, nil
}

// Prewarm fetches a URL through the node's own shared server (loopback, the
// public port), as a visitor would, with the agent's prewarm token: the
// request is selected, keyed and cached exactly like a visitor's. It
// succeeds when a second fetch is a HIT on the same key.
type Prewarmer struct {
	Token   string
	Address string // loopback address, e.g. "127.0.0.1"
	Timeout time.Duration
	// MaxBytes bounds one object (ge-cache 10: configurable).
	MaxBytes int64
}

// PrewarmResult of one URL. Bytes is the object's size (the first read),
// not what the prewarm read in total (the verifying read is not counted).
type PrewarmResult struct {
	// PREWARMED | ALREADY_CACHED | NOT_CACHEABLE | STATUS | REDIRECT | UPSTREAM |
	// TIMEOUT | TOO_LARGE | TASK_BYTES | SITE_MISMATCH
	Code  string
	Key   string
	Bytes int64
}

// PrewarmBudget is one task's share of the node's prewarm limits
// (CACHEFLOW-E02, node cache_task settings); zero fields keep the
// prewarmer's own.
//   - MaxObjectBytes bounds one object (TOO_LARGE).
//   - Remaining is the task's byte allowance: every read, the verifying one
//     too, spends what it read; none left is TASK_BYTES before a request.
//   - Wait runs before every request (the task's rate).
//   - Timeout bounds one request (TIMEOUT).
type PrewarmBudget struct {
	MaxObjectBytes int64
	Remaining      *int64
	Wait           func(context.Context) error
	Timeout        time.Duration
}

func (prewarmer Prewarmer) Prewarm(ctx context.Context, site Site, target Target, scheme string) PrewarmResult {
	return prewarmer.PrewarmWithin(ctx, site, target, scheme, PrewarmBudget{})
}

// PrewarmWithin is Prewarm within a task's budget.
func (prewarmer Prewarmer) PrewarmWithin(ctx context.Context, site Site, target Target, scheme string, budget PrewarmBudget) PrewarmResult {
	if budget.MaxObjectBytes > 0 {
		prewarmer.MaxBytes = budget.MaxObjectBytes
	}
	if budget.Timeout > 0 {
		prewarmer.Timeout = budget.Timeout
	}
	read := func() (fetched, string) {
		if budget.Remaining != nil && *budget.Remaining <= 0 {
			return fetched{}, "TASK_BYTES"
		}
		if budget.Wait != nil {
			if err := budget.Wait(ctx); err != nil {
				return fetched{}, "UPSTREAM"
			}
		}
		value, err := prewarmer.fetch(ctx, site, target, scheme, budget.Remaining)
		if err != nil {
			var timeout interface{ Timeout() bool }
			if ctx.Err() == nil && errors.As(err, &timeout) && timeout.Timeout() {
				return fetched{}, "TIMEOUT"
			}
			return fetched{}, "UPSTREAM"
		}
		return value, ""
	}
	first, failed := read()
	if failed != "" {
		return PrewarmResult{Code: failed}
	}
	if first.code != "" {
		return PrewarmResult{Code: first.code, Bytes: first.bytes}
	}
	if first.cache == "HIT" {
		return PrewarmResult{Code: "ALREADY_CACHED", Key: first.key, Bytes: first.bytes}
	}
	second, failed := read()
	if failed != "" {
		return PrewarmResult{Code: failed, Bytes: first.bytes}
	}
	if second.code == "TASK_BYTES" {
		return PrewarmResult{Code: second.code, Bytes: first.bytes}
	}
	if second.code != "" || second.cache != "HIT" || second.key != first.key {
		return PrewarmResult{Code: "NOT_CACHEABLE", Bytes: first.bytes}
	}
	return PrewarmResult{Code: "PREWARMED", Key: first.key, Bytes: first.bytes}
}

type fetched struct {
	code, cache, key string
	bytes            int64
}

// fetch reads one response; remaining (nil: unbounded) is the task's byte
// allowance the body spends.
func (prewarmer Prewarmer) fetch(ctx context.Context, site Site, target Target, scheme string, remaining *int64) (fetched, error) {
	dialer := &net.Dialer{Timeout: prewarmer.Timeout}
	address := net.JoinHostPort(prewarmer.Address, strconv.Itoa(target.Port))
	transport := &http.Transport{
		Proxy: nil, DisableCompression: true, DisableKeepAlives: true, ForceAttemptHTTP2: false,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp", address)
		},
		// the agent fetches its own node by loopback: the certificate is the
		// site's, the name is the target host (SNI routes the handshake)
		TLSClientConfig:       tlsFor(target.Host),
		ResponseHeaderTimeout: prewarmer.Timeout,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: prewarmer.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+net.JoinHostPort(target.Host, strconv.Itoa(target.Port))+target.URI, nil)
	if err != nil {
		return fetched{}, err
	}
	request.Header.Set("User-Agent", "")
	request.Header.Set("X-Cdnca-Cache-Task", prewarmer.Token)
	response, err := client.Do(request)
	if err != nil {
		return fetched{}, err
	}
	defer response.Body.Close()
	if response.Header.Get("X-Cdnca-Site") != site.SiteID {
		return fetched{code: "SITE_MISMATCH"}, nil
	}
	if response.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
		if response.StatusCode >= 300 && response.StatusCode < 400 {
			return fetched{code: "REDIRECT"}, nil
		}
		return fetched{code: "STATUS"}, nil
	}
	limit := prewarmer.MaxBytes
	if remaining != nil {
		limit = min(limit, *remaining)
	}
	written, err := io.Copy(io.Discard, io.LimitReader(response.Body, limit+1))
	if remaining != nil {
		*remaining -= min(written, *remaining)
	}
	if err != nil {
		return fetched{}, err
	}
	if written > prewarmer.MaxBytes {
		return fetched{code: "TOO_LARGE", bytes: written}, nil
	}
	if written > limit {
		return fetched{code: "TASK_BYTES", bytes: written}, nil
	}
	result := fetched{cache: response.Header.Get("X-CDN-Cache"), key: response.Header.Get("X-Cdnca-Cache-Key"), bytes: written}
	if result.key == "" || (result.cache != "MISS" && result.cache != "HIT") {
		return fetched{code: "NOT_CACHEABLE", bytes: written}, nil
	}
	return result, nil
}

// CleanResult of a soft quota pass.
type CleanResult struct {
	Sites   int // sites over quota
	Removed int
	Bytes   int64
}

// CleanQuota enforces the soft quotas (a site's cache capacity
// is a soft quota on the shared pool; the zone max_size is the only hard
// limit): every site over its quota loses its least recently used objects
// until it is at low (fraction of the quota, e.g. 0.9). Sites without a
// known quota (not in sites) are left to the cache manager.
func (zones Zones) CleanQuota(ctx context.Context, sites map[string]Site, low float64) (CleanResult, error) {
	perSite := map[string][]Entry{}
	totals := map[string]int64{}
	if err := zones.WalkAll(ctx, func(entry Entry) error {
		site, known := sites[entry.Key.Prefix]
		if !known || site.QuotaBytes <= 0 {
			return nil
		}
		perSite[entry.Key.Prefix] = append(perSite[entry.Key.Prefix], entry)
		totals[entry.Key.Prefix] += entry.Size
		return nil
	}); err != nil {
		return CleanResult{}, err
	}
	var result CleanResult
	for prefix, entries := range perSite {
		quota := sites[prefix].QuotaBytes
		if totals[prefix] <= quota {
			continue
		}
		result.Sites++
		target := int64(float64(quota) * low)
		sortByAccess(entries)
		total := totals[prefix]
		for _, entry := range entries {
			if total <= target {
				break
			}
			if ctx.Err() != nil {
				return result, ctx.Err()
			}
			removed, err := remove(entry)
			if err != nil {
				return result, err
			}
			total -= entry.Size
			if removed {
				result.Removed++
				result.Bytes += entry.Size
			}
		}
	}
	return result, nil
}

// SetPrewarmToken pushes the agent's prewarm token to the node.
func SetPrewarmToken(ctx context.Context, control Control, token string) error {
	_, err := control.Post(ctx, "/cache/prewarm-token", []byte(token))
	return err
}

// tlsFor: the agent fetches its own node over loopback; SNI routes the
// handshake to the site. The node's certificate is not verified here (the
// agent installed it; a loopback peer cannot be anyone else).
func tlsFor(host string) *tls.Config {
	return &tls.Config{ServerName: host, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12} //nolint:gosec // loopback to the agent's own node
}
