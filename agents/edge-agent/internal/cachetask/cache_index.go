package cachetask

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"golang.org/x/sys/unix"
)

const maxCacheMetadataBytes = 64 << 10

type operationError struct {
	code string
	err  error
}

func (e *operationError) Error() string { return e.code }
func (e *operationError) Unwrap() error { return e.err }

// cacheKeyKind distinguishes the on-disk proxy_cache_key layouts rendered by
// libs/edgeconfig: the plain v2 key, the same key behind the cache freshness
// generation|token prefix, the freshness request identity (v=1|...) and the
// Range slice key stored under shared/range/<identity>.
type cacheKeyKind int

const (
	cacheKeyPlain cacheKeyKind = iota
	cacheKeyFreshness
	cacheKeyFreshnessIdentity
	cacheKeyRange
)

type cacheKey struct {
	kind          cacheKeyKind
	tenantID      string
	siteID        string
	configVersion string
	domain        string
	port          uint16
	uri           string
	path          string
}

type cacheEntry struct {
	root string
	// area is "" for the site cache namespace or rangeAreaPrefix+<identity>
	// for a listener's Range slice cache directory.
	area     string
	relative string
	key      cacheKey
	size     int64
	device   uint64
	inode    uint64
}

type cacheScanBudget struct {
	maxEntries int
	maxBytes   int64
	deadline   time.Time
	entries    int
	bytes      int64
}

func (b *cacheScanBudget) check(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !time.Now().Before(b.deadline) {
		return &operationError{code: CodePurgeScanBudgetExceeded, err: ErrInvalidState}
	}
	return nil
}

func newCacheScanBudget(budget ResourceBudget) *cacheScanBudget {
	return &cacheScanBudget{
		maxEntries: budget.MaxScanEntries,
		maxBytes:   budget.MaxScanBytes,
		deadline:   time.Now().Add(budget.MaxScanDuration),
	}
}

func (b *cacheScanBudget) chargeEntry(ctx context.Context) error {
	if err := b.check(ctx); err != nil {
		return err
	}
	if b.entries >= b.maxEntries {
		return &operationError{code: CodePurgeScanBudgetExceeded, err: ErrInvalidState}
	}
	b.entries++
	return nil
}

func (b *cacheScanBudget) chargeBytes(ctx context.Context, value int64) error {
	if err := b.check(ctx); err != nil {
		return err
	}
	if value < 0 || value > b.maxBytes-b.bytes {
		return &operationError{code: CodePurgeScanBudgetExceeded, err: ErrInvalidState}
	}
	b.bytes += value
	return nil
}

func (s *diskStore) cacheSiteRoot(site SiteContext) (string, bool, error) {
	if err := requirePrivateDirectory(s.cacheRoot); err != nil {
		return "", false, &operationError{code: CodeCacheLayoutUnsafe, err: err}
	}
	root := filepath.Join(s.cacheRoot, site.CacheIdentity)
	info, err := os.Lstat(root)
	if errors.Is(err, os.ErrNotExist) {
		return root, false, nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", false, &operationError{code: CodeCacheLayoutUnsafe, err: err}
	}
	return root, true, nil
}

const rangeAreaPrefix = "range/"

// rangeCacheAreas lists the Range slice cache directories that exist for the
// site's listeners. nginx creates them on demand, so an absent directory means
// the listener never stored a slice.
func (s *diskStore) rangeCacheAreas(site SiteContext) ([]string, error) {
	areas := make([]string, 0)
	for _, listener := range site.Listeners {
		area := rangeAreaPrefix + edgeconfig.RangeCacheIdentity(site.TenantID, site.SiteID, listener.Domain, listener.ListenPort)
		info, err := os.Lstat(filepath.Join(s.stateRoot, "shared", area))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o022 != 0 {
			return nil, &operationError{code: CodeCacheLayoutUnsafe, err: err}
		}
		areas = append(areas, area)
	}
	return areas, nil
}

// cacheAreaRoot resolves a cache area to its directory. Range areas must belong
// to one of the site's listeners.
func (s *diskStore) cacheAreaRoot(site SiteContext, area string) (string, bool) {
	if area == "" {
		return filepath.Join(s.cacheRoot, site.CacheIdentity), true
	}
	for _, listener := range site.Listeners {
		if area == rangeAreaPrefix+edgeconfig.RangeCacheIdentity(site.TenantID, site.SiteID, listener.Domain, listener.ListenPort) {
			return filepath.Join(s.stateRoot, "shared", area), true
		}
	}
	return "", false
}

// purgeNeedsScan reports whether an exact purge must scan instead of probing
// the computed plain key path: projected keys, cache freshness keys (their
// generation|token prefix lives only in OpenResty shared memory) and Range
// slices (one file per slice) cannot be addressed directly.
func (s *diskStore) purgeNeedsScan(site SiteContext) (bool, error) {
	if cachePolicyProjectedKey(site) {
		return true, nil
	}
	for _, listener := range site.Listeners {
		if listener.CacheFreshness {
			return true, nil
		}
	}
	areas, err := s.rangeCacheAreas(site)
	return len(areas) > 0, err
}

func (s *diskStore) walkCacheEntries(ctx context.Context, site SiteContext, budget *cacheScanBudget,
	visit func(cacheEntry) error) error {
	root, exists, err := s.cacheSiteRoot(site)
	if err != nil {
		return err
	}
	if exists {
		if err := s.walkCacheDirectory(ctx, site, budget, root, "", root, 0, visit); err != nil {
			return err
		}
	}
	areas, err := s.rangeCacheAreas(site)
	if err != nil {
		return err
	}
	for _, area := range areas {
		areaRoot := filepath.Join(s.stateRoot, "shared", area)
		if err := s.walkCacheDirectory(ctx, site, budget, areaRoot, area, areaRoot, 0, visit); err != nil {
			return err
		}
	}
	return nil
}

const cacheScanReadBatch = 64

func (s *diskStore) walkCacheDirectory(ctx context.Context, site SiteContext, budget *cacheScanBudget,
	root, area, directory string, depth int, visit func(cacheEntry) error) error {
	file, err := os.OpenFile(directory, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return &operationError{code: CodeCacheLayoutUnsafe, err: err}
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.IsDir() {
		return &operationError{code: CodeCacheLayoutUnsafe, err: err}
	}
	for {
		entries, readErr := file.ReadDir(cacheScanReadBatch)
		for _, entry := range entries {
			if err := budget.chargeEntry(ctx); err != nil {
				return err
			}
			entryInfo, err := entry.Info()
			if err != nil || entryInfo.Mode()&os.ModeSymlink != 0 {
				return &operationError{code: CodeCacheLayoutUnsafe, err: err}
			}
			path := filepath.Join(directory, entry.Name())
			if entryInfo.IsDir() {
				if depth >= 2 {
					return &operationError{code: CodeCacheLayoutUnsafe, err: ErrInvalidState}
				}
				if err := s.walkCacheDirectory(ctx, site, budget, root, area, path, depth+1, visit); err != nil {
					return err
				}
				continue
			}
			if !entryInfo.Mode().IsRegular() {
				return &operationError{code: CodeCacheLayoutUnsafe, err: ErrInvalidState}
			}
			relative, err := filepath.Rel(root, path)
			if err != nil || relative == "." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
				return &operationError{code: CodeCacheLayoutUnsafe, err: ErrInvalidState}
			}
			digest, cacheFile := cacheDigestFromPath(relative)
			if !cacheFile {
				continue
			}
			candidate, err := cacheEntryFromFile(ctx, path, root, area, relative, digest, site, entryInfo, budget)
			if err != nil {
				return err
			}
			if err := visit(candidate); err != nil {
				return err
			}
		}
		if errors.Is(readErr, io.EOF) {
			return nil
		}
		if readErr != nil {
			return &operationError{code: CodeCacheLayoutUnsafe, err: readErr}
		}
	}
}

func (s *diskStore) exactCacheEntry(ctx context.Context, site SiteContext, target normalizedTarget,
	budget *cacheScanBudget) (*cacheEntry, error) {
	root, exists, err := s.cacheSiteRoot(site)
	if err != nil || !exists {
		return nil, err
	}
	keyed := site
	keyed.Domain = targetKeyDomain(target)
	keyValue := cacheKeyValue(keyed, target.URI)
	path := nginxCachePath(root, keyValue)
	relative, err := filepath.Rel(root, path)
	if err != nil {
		return nil, &operationError{code: CodeCacheLayoutUnsafe, err: err}
	}
	parts := strings.Split(filepath.ToSlash(relative), "/")
	current := root
	for _, part := range parts[:len(parts)-1] {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return nil, &operationError{code: CodeCacheLayoutUnsafe, err: err}
		}
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, &operationError{code: CodeCacheLayoutUnsafe, err: err}
	}
	if err := budget.chargeEntry(ctx); err != nil {
		return nil, err
	}
	digest, valid := cacheDigestFromPath(relative)
	if !valid {
		return nil, &operationError{code: CodeCacheLayoutUnsafe, err: ErrInvalidState}
	}
	entry, err := cacheEntryFromFile(ctx, path, root, "", relative, digest, site, info, budget)
	if err != nil {
		return nil, err
	}
	if entry.key.kind != cacheKeyPlain || entry.key.uri != target.URI {
		return nil, &operationError{code: CodeCacheMetadataInvalid, err: ErrInvalidState}
	}
	return &entry, nil
}

func cacheEntryFromFile(ctx context.Context, path, root, area, relative, digest string, site SiteContext, info os.FileInfo,
	budget *cacheScanBudget) (cacheEntry, error) {
	readBytes := min(info.Size(), int64(maxCacheMetadataBytes))
	if err := budget.chargeBytes(ctx, readBytes); err != nil {
		return cacheEntry{}, err
	}
	key, currentInfo, err := readCacheKey(path, digest, readBytes)
	if err != nil {
		return cacheEntry{}, &operationError{code: CodeCacheMetadataInvalid, err: err}
	}
	currentDevice, currentInode, currentLinks := fileIdentity(currentInfo)
	indexedDevice, indexedInode, indexedLinks := fileIdentity(info)
	if currentInfo.Size() != info.Size() || currentDevice != indexedDevice || currentInode != indexedInode || currentLinks != indexedLinks {
		return cacheEntry{}, &operationError{code: CodeCacheEntryChanged, err: ErrInvalidState}
	}
	if err := budget.check(ctx); err != nil {
		return cacheEntry{}, err
	}
	if !cacheKeyMatchesSite(key, site, area) {
		return cacheEntry{}, &operationError{code: CodeCacheMetadataInvalid, err: ErrInvalidState}
	}
	device, inode, links := fileIdentity(info)
	if links > 1 {
		return cacheEntry{}, &operationError{code: CodeCacheLayoutUnsafe, err: ErrInvalidState}
	}
	return cacheEntry{
		root: root, area: area, relative: relative, key: key, size: info.Size(), device: device, inode: inode,
	}, nil
}

func cacheDigestFromPath(relative string) (string, bool) {
	parts := strings.Split(filepath.ToSlash(relative), "/")
	if len(parts) != 3 || len(parts[0]) != 1 || len(parts[1]) != 2 || len(parts[2]) != md5.Size*2 ||
		!lowerHex(parts[0]) || !lowerHex(parts[1]) || !lowerHex(parts[2]) {
		return "", false
	}
	digest := parts[2]
	if parts[0] != digest[len(digest)-1:] || parts[1] != digest[len(digest)-3:len(digest)-1] {
		return "", false
	}
	return digest, true
}

func lowerHex(value string) bool {
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func readCacheKey(path, expectedDigest string, limit int64) (cacheKey, os.FileInfo, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return cacheKey{}, nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 {
		return cacheKey{}, nil, ErrInvalidState
	}
	header, err := io.ReadAll(io.LimitReader(file, limit))
	if err != nil {
		return cacheKey{}, nil, err
	}
	const marker = "\nKEY: "
	for offset := 0; ; {
		index := bytes.Index(header[offset:], []byte(marker))
		if index < 0 {
			break
		}
		start := offset + index + len(marker)
		endOffset := bytes.IndexByte(header[start:], '\n')
		if endOffset < 0 {
			break
		}
		keyBytes := header[start : start+endOffset]
		digest := md5.Sum(keyBytes)
		if hex.EncodeToString(digest[:]) == expectedDigest {
			key, parseErr := parseCacheKey(string(keyBytes))
			return key, info, parseErr
		}
		offset = start + endOffset + 1
		if offset >= len(header) {
			break
		}
	}
	return cacheKey{}, nil, ErrInvalidState
}

func parseCacheKey(value string) (cacheKey, error) {
	if strings.HasPrefix(value, CacheKeyVersion+"|") {
		return parsePlainCacheKey(value)
	}
	if strings.HasPrefix(value, "v=") {
		return parseRangeCacheKey(value)
	}
	// Cache freshness: "<generation>|<object token>|<identity>"; both prefixes
	// are 64 lower-hex values, or empty when the guard failed closed.
	parts := strings.SplitN(value, "|", 3)
	if len(parts) != 3 || !freshnessTokenField(parts[0]) || !freshnessTokenField(parts[1]) {
		return cacheKey{}, ErrInvalidState
	}
	if strings.HasPrefix(parts[2], CacheKeyVersion+"|") {
		key, err := parsePlainCacheKey(parts[2])
		key.kind = cacheKeyFreshness
		return key, err
	}
	return parseFreshnessIdentityKey(parts[2])
}

func freshnessTokenField(value string) bool {
	return value == "" || len(value) == 64 && lowerHex(value)
}

func parsePlainCacheKey(value string) (cacheKey, error) {
	parts := strings.SplitN(value, "|", 7)
	if len(parts) != 7 || parts[0] != CacheKeyVersion || !idPattern.MatchString(parts[1]) ||
		!idPattern.MatchString(parts[2]) || !idPattern.MatchString(parts[3]) ||
		!validSiteName(parts[4]) {
		return cacheKey{}, ErrInvalidState
	}
	port, err := strconv.ParseUint(parts[5], 10, 16)
	if err != nil || port == 0 {
		return cacheKey{}, ErrInvalidState
	}
	uri := parts[6]
	if uri == "" || uri[0] != '/' {
		return cacheKey{}, ErrInvalidState
	}
	requestPath := uri
	if index := strings.IndexByte(uri, '?'); index >= 0 {
		requestPath = uri[:index]
	}
	if !validCacheURI(uri, requestPath) {
		return cacheKey{}, ErrInvalidState
	}
	return cacheKey{
		kind: cacheKeyPlain, tenantID: parts[1], siteID: parts[2], configVersion: parts[3],
		domain: parts[4], port: uint16(port), uri: uri, path: requestPath,
	}, nil
}

// splitTaggedFields splits "name=value|..." whose last field (the raw request
// URI) may itself contain '|'.
func splitTaggedFields(value string, names ...string) ([]string, bool) {
	parts := strings.SplitN(value, "|", len(names))
	if len(parts) != len(names) {
		return nil, false
	}
	for index, name := range names {
		if !strings.HasPrefix(parts[index], name+"=") {
			return nil, false
		}
		parts[index] = strings.TrimPrefix(parts[index], name+"=")
	}
	return parts, true
}

// parseFreshnessIdentityKey parses
// v=1|tenant=|site=|config=<revision>|scheme=|host=|port=|method=|request=<request_uri>.
func parseFreshnessIdentityKey(value string) (cacheKey, error) {
	fields, ok := splitTaggedFields(value, "v", "tenant", "site", "config", "scheme", "host", "port", "method", "request")
	if !ok || fields[0] != "1" || !idPattern.MatchString(fields[1]) || !idPattern.MatchString(fields[2]) ||
		(fields[4] != "http" && fields[4] != "https") || (fields[7] != "GET" && fields[7] != "BYPASS") {
		return cacheKey{}, ErrInvalidState
	}
	if revision, err := strconv.ParseUint(fields[3], 10, 64); err != nil || revision == 0 {
		return cacheKey{}, ErrInvalidState
	}
	key, err := requestCacheKey(fields[5], fields[6], fields[8])
	key.kind, key.tenantID, key.siteID = cacheKeyFreshnessIdentity, fields[1], fields[2]
	return key, err
}

// parseRangeCacheKey parses
// v=<config version>|policy=|tenant=|site=|range=|scheme=|host=|port=|request=<request_uri>.
func parseRangeCacheKey(value string) (cacheKey, error) {
	fields, ok := splitTaggedFields(value, "v", "policy", "tenant", "site", "range", "scheme", "host", "port", "request")
	if !ok || !idPattern.MatchString(fields[0]) || !idPattern.MatchString(fields[2]) || !idPattern.MatchString(fields[3]) ||
		(fields[5] != "http" && fields[5] != "https") {
		return cacheKey{}, ErrInvalidState
	}
	if policy, err := strconv.ParseUint(fields[1], 10, 64); err != nil || policy == 0 {
		return cacheKey{}, ErrInvalidState
	}
	key, err := requestCacheKey(fields[6], fields[7], fields[8])
	key.kind, key.tenantID, key.siteID, key.configVersion = cacheKeyRange, fields[2], fields[3], fields[0]
	return key, err
}

// requestCacheKey maps nginx's raw $request_uri onto the purge comparison form
// used by plain keys ($uri$is_args$args): percent-decoded path, raw query.
func requestCacheKey(host, port, requestURI string) (cacheKey, error) {
	parsedPort, err := strconv.ParseUint(port, 10, 16)
	if err != nil || parsedPort == 0 || !domainPattern.MatchString(host) || requestURI == "" || requestURI[0] != '/' {
		return cacheKey{}, ErrInvalidState
	}
	rawPath, query, hasQuery := strings.Cut(requestURI, "?")
	requestPath, err := url.PathUnescape(rawPath)
	if err != nil || requestPath == "" || requestPath[0] != '/' {
		return cacheKey{}, ErrInvalidState
	}
	uri := requestPath
	if hasQuery {
		uri += "?" + query
	}
	if !validCacheURI(uri, requestPath) {
		return cacheKey{}, ErrInvalidState
	}
	return cacheKey{domain: host, port: uint16(parsedPort), uri: uri, path: requestPath}, nil
}

// cacheKeyMatchesSite checks that a key found in area belongs to the site. The
// site namespace is per config version, so plain keys must carry it; freshness
// identity keys carry the mutable revision instead, which (like Range slices
// written by earlier versions of the same listener) is not an identity.
func cacheKeyMatchesSite(key cacheKey, site SiteContext, area string) bool {
	if key.tenantID != site.TenantID || key.siteID != site.SiteID {
		return false
	}
	if area != "" {
		if key.kind != cacheKeyRange {
			return false
		}
		for _, listener := range site.Listeners {
			if cacheKeyDomainMatches(key, site, listener) && key.port == listener.ListenPort &&
				area == rangeAreaPrefix+edgeconfig.RangeCacheIdentity(site.TenantID, site.SiteID, listener.Domain, listener.ListenPort) {
				return true
			}
		}
		return false
	}
	if key.kind == cacheKeyRange || key.kind != cacheKeyFreshnessIdentity && key.configVersion != site.cacheKeyVersion() {
		return false
	}
	for _, listener := range site.Listeners {
		if !listener.CacheEnabled || !cacheKeyDomainMatches(key, site, listener) {
			continue
		}
		// The freshness identity uses $server_port, so prewarm fills carry the
		// loopback prewarm port.
		if key.port == listener.ListenPort ||
			key.kind == cacheKeyFreshnessIdentity && listener.PrewarmPort != 0 && key.port == listener.PrewarmPort {
			return true
		}
	}
	if len(site.Listeners) != 0 {
		return false
	}
	return key.domain == site.Domain && key.port == site.ListenPort && site.CacheEnabled
}

func validCacheURI(uri, requestPath string) bool {
	if uri == "" || uri[0] != '/' || requestPath == "" || requestPath[0] != '/' || len(uri) > maxCacheMetadataBytes {
		return false
	}
	for _, value := range []string{uri, requestPath} {
		for index := 0; index < len(value); index++ {
			if value[index] < 0x20 || value[index] == 0x7f {
				return false
			}
		}
	}
	return true
}

func fileIdentity(info os.FileInfo) (device, inode, links uint64) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, 1
	}
	return uint64(stat.Dev), uint64(stat.Ino), uint64(stat.Nlink)
}

func purgeMatches(action Action, target normalizedTarget, entries []cacheEntry) []cacheEntry {
	matches := make([]cacheEntry, 0)
	for _, entry := range entries {
		if purgeMatch(action, target, entry) {
			matches = append(matches, entry)
		}
	}
	return matches
}

// cacheKeyDomainMatches: plain keys name the listener's domain (the site's
// key prefix), or for a host-keyed site the request's host; Range and
// freshness identity keys name the request's $host. A request's host is any
// host the site serves (aliases, names under a wildcard).
func cacheKeyDomainMatches(key cacheKey, site SiteContext, listener ListenerContext) bool {
	if key.kind == cacheKeyRange || key.kind == cacheKeyFreshnessIdentity || site.KeyByHost {
		return key.domain == listener.Domain || siteServes(site, listener, key.domain)
	}
	return key.domain == listener.Domain
}

// targetKeyDomain is the domain field of a target's plain cache key: the URL's
// own host for a host-keyed site, else the listener's domain.
func targetKeyDomain(target normalizedTarget) string {
	if target.Site.KeyByHost && target.RequestHost != "" {
		return target.RequestHost
	}
	return target.Site.Domain
}

// targetKeyDomainMatches: a host-keyed site's plain key names exactly the
// target's host (other hosts keep their own objects); a wildcard target
// names every host under its suffix.
func targetKeyDomainMatches(key cacheKey, target normalizedTarget) bool {
	if target.WildcardSuffix != "" {
		if strings.HasSuffix(key.domain, "."+target.WildcardSuffix) || key.domain == "*."+target.WildcardSuffix {
			return true
		}
		// A site keyed by its domain: the wildcard covers the site's domain
		// when that domain is under (or is) the wildcard.
		return !target.Site.KeyByHost && key.domain == target.Site.Domain &&
			(strings.HasSuffix(target.Site.Domain, "."+target.WildcardSuffix) || target.Site.Domain == "*."+target.WildcardSuffix)
	}
	if target.Site.KeyByHost && (key.kind == cacheKeyPlain || key.kind == cacheKeyFreshness) {
		return key.domain == targetKeyDomain(target)
	}
	return cacheKeyDomainMatches(key, target.Site, ListenerContext{Domain: target.Site.Domain})
}

func purgeMatch(action Action, target normalizedTarget, entry cacheEntry) bool {
	if action != ActionPurgeSite && (!targetKeyDomainMatches(entry.key, target) || !target.matchesPort(entry.key.port)) {
		return false
	}
	switch action {
	case ActionPurgeExact:
		return entry.key.uri == target.URI
	case ActionPurgePrefix:
		return entry.key.path == target.Path || strings.HasPrefix(entry.key.path, strings.TrimSuffix(target.Path, "/")+"/") ||
			(strings.HasSuffix(target.Path, "/") && strings.HasPrefix(entry.key.path, target.Path))
	case ActionPurgeSite:
		return true
	default:
		return false
	}
}

func removeCacheEntries(entries, removed []cacheEntry) []cacheEntry {
	if len(removed) == 0 {
		return entries
	}
	removedPaths := make(map[string]struct{}, len(removed))
	for _, entry := range removed {
		removedPaths[entry.relative] = struct{}{}
	}
	kept := entries[:0]
	for _, entry := range entries {
		if _, deleted := removedPaths[entry.relative]; !deleted {
			kept = append(kept, entry)
		}
	}
	return kept
}

func deleteCacheEntries(ctx context.Context, entries []cacheEntry) (int, error) {
	return deleteCacheEntriesWith(ctx, entries, unlinkCacheEntry)
}

func deleteCacheEntriesWith(ctx context.Context, entries []cacheEntry, unlink func(cacheEntry) (bool, error)) (int, error) {
	deleted := 0
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return deleted, err
		}
		removed, err := unlink(entry)
		if removed {
			deleted++
		}
		if err != nil {
			return deleted, err
		}
		if err := ctx.Err(); err != nil {
			return deleted, err
		}
	}
	return deleted, nil
}

func unlinkCacheEntry(entry cacheEntry) (bool, error) {
	return unlinkCacheEntryWithFsync(entry, unix.Fsync)
}

func unlinkCacheEntryWithFsync(entry cacheEntry, fsyncParent func(int) error) (bool, error) {
	parts := strings.Split(filepath.ToSlash(entry.relative), "/")
	if len(parts) != 3 {
		return false, &operationError{code: CodeCacheEntryChanged, err: ErrInvalidState}
	}
	rootFD, err := unix.Open(entry.root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return false, &operationError{code: CodeCacheEntryChanged, err: err}
	}
	defer unix.Close(rootFD)
	parentFD := rootFD
	opened := make([]int, 0, len(parts)-1)
	defer func() {
		for index := len(opened) - 1; index >= 0; index-- {
			_ = unix.Close(opened[index])
		}
	}()
	for _, part := range parts[:len(parts)-1] {
		if part == "" || part == "." || part == ".." {
			return false, &operationError{code: CodeCacheEntryChanged, err: ErrInvalidState}
		}
		childFD, err := unix.Openat(parentFD, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return false, &operationError{code: CodeCacheEntryChanged, err: err}
		}
		opened = append(opened, childFD)
		parentFD = childFD
	}
	var stat unix.Stat_t
	err = unix.Fstatat(parentFD, parts[len(parts)-1], &stat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	if err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || uint64(stat.Dev) != entry.device ||
		uint64(stat.Ino) != entry.inode || int64(stat.Size) != entry.size || uint64(stat.Nlink) > 1 {
		return false, &operationError{code: CodeCacheEntryChanged, err: err}
	}
	if err := unix.Unlinkat(parentFD, parts[len(parts)-1], 0); err != nil {
		return false, &operationError{code: CodeCacheDeleteFailed, err: err}
	}
	if err := fsyncParent(parentFD); err != nil {
		return false, &operationError{code: CodeCacheDeleteFailed, err: err}
	}
	return true, nil
}

func syncCacheParent(root, relative string, fsyncParent func(int) error) error {
	parts := strings.Split(filepath.ToSlash(relative), "/")
	if len(parts) != 3 {
		return ErrInvalidState
	}
	rootFD, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer unix.Close(rootFD)
	parentFD := rootFD
	opened := make([]int, 0, len(parts)-1)
	defer func() {
		for index := len(opened) - 1; index >= 0; index-- {
			_ = unix.Close(opened[index])
		}
	}()
	for _, part := range parts[:len(parts)-1] {
		if part == "" || part == "." || part == ".." {
			return ErrInvalidState
		}
		childFD, err := unix.Openat(parentFD, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		opened = append(opened, childFD)
		parentFD = childFD
	}
	return fsyncParent(parentFD)
}

func nginxCachePath(root, key string) string {
	digest := md5.Sum([]byte(key))
	value := hex.EncodeToString(digest[:])
	return filepath.Join(root, value[len(value)-1:], value[len(value)-3:len(value)-1], value)
}

func cacheKeyValue(site SiteContext, uri string) string {
	return fmt.Sprintf("%s|%s|%s|%s|%s|%d|%s", CacheKeyVersion, site.TenantID, site.SiteID,
		site.cacheKeyVersion(), site.Domain, site.ListenPort, uri)
}
