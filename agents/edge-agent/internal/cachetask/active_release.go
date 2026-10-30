package cachetask

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"syscall"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

const (
	activeReleaseManifestFile = ".release-manifest.json"
	// siteRuntimeDocumentFile marks a site runtime v2 release: the node compiles
	// its nginx.conf and cache identity into a derived release named by the
	// same digest under <deployment root>/../site-runtime/releases.
	siteRuntimeDocumentFile = "site-runtime.v2.json"
)

type ActiveReleaseResolver struct {
	root string
	// siteRuntimeRoot is the site runtime adapter's state root (derived releases).
	siteRuntimeRoot string
}

func NewActiveReleaseResolver(stateRoot string) (*ActiveReleaseResolver, error) {
	if stateRoot == "" || !filepath.IsAbs(stateRoot) || filepath.Clean(stateRoot) != stateRoot ||
		stateRoot == string(filepath.Separator) {
		return nil, ErrInvalidState
	}
	info, err := os.Lstat(stateRoot)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, ErrInvalidState
	}
	realRoot, err := filepath.EvalSymlinks(stateRoot)
	if err != nil || realRoot == string(filepath.Separator) {
		return nil, ErrInvalidState
	}
	return &ActiveReleaseResolver{root: realRoot, siteRuntimeRoot: filepath.Join(filepath.Dir(realRoot), "site-runtime")}, nil
}

func (resolver *ActiveReleaseResolver) ResolveSite(ctx context.Context, tenantID, siteID, versionID string,
	revision uint64) (SiteContext, error) {
	if resolver == nil || ctx == nil {
		return SiteContext{}, ErrSiteNotFound
	}
	if err := ctx.Err(); err != nil {
		return SiteContext{}, err
	}
	roots, err := resolver.candidateRoots(tenantID)
	if err != nil {
		return SiteContext{}, ErrSiteNotFound
	}
	for _, root := range roots {
		site, err := resolver.resolveAt(ctx, root, tenantID, siteID, versionID, revision)
		if err == nil {
			return site, nil
		}
		if ctx.Err() != nil {
			return SiteContext{}, ctx.Err()
		}
	}
	return SiteContext{}, ErrSiteNotFound
}

// resolveAt resolves the site from one release root's current release,
// retrying once if current moves while it is read.
func (resolver *ActiveReleaseResolver) resolveAt(ctx context.Context, root, tenantID, siteID, versionID string,
	revision uint64) (SiteContext, error) {
	for attempt := 0; attempt < 2; attempt++ {
		target, release, err := currentReleaseAt(root)
		if err != nil {
			return SiteContext{}, ErrSiteNotFound
		}
		manifest, freshness, err := resolver.cacheManifest(ctx, release, filepath.Base(target))
		if err != nil {
			if ctx.Err() != nil {
				return SiteContext{}, ctx.Err()
			}
			return SiteContext{}, ErrSiteNotFound
		}
		current, _, err := currentReleaseAt(root)
		if err != nil {
			return SiteContext{}, ErrSiteNotFound
		}
		if current != target {
			continue
		}
		return siteFromManifest(manifest, freshness, filepath.Base(target), tenantID, siteID, versionID, revision)
	}
	return SiteContext{}, ErrSiteNotFound
}

// multiScope reports whether the deployment root holds one state machine per
// configuration scope (deployment.MultiScopeManager) instead of one release.
func (resolver *ActiveReleaseResolver) multiScope() bool {
	info, err := os.Lstat(filepath.Join(resolver.root, "scopes"))
	return err == nil && info.Mode()&os.ModeSymlink == 0 && info.IsDir()
}

// candidateRoots returns the release roots that may serve tenantID. On a
// multi-scope node the deployment state is kept per configuration scope
// (scopes/<scope id>), which is a different identifier from the tenant id
// carried by cache commands and the cache manifest. Every scope is a
// candidate; siteFromManifest accepts only the scope whose current release
// names this tenant, site and config version, so another tenant's scope and
// the legacy single release are never used.
func (resolver *ActiveReleaseResolver) candidateRoots(tenantID string) ([]string, error) {
	if !resolver.multiScope() {
		return []string{resolver.root}, nil
	}
	if !idPattern.MatchString(tenantID) {
		return nil, ErrSiteNotFound
	}
	scopes := filepath.Join(resolver.root, "scopes")
	entries, err := os.ReadDir(scopes)
	if err != nil {
		return nil, ErrSiteNotFound
	}
	roots := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !idPattern.MatchString(entry.Name()) {
			continue
		}
		roots = append(roots, filepath.Join(scopes, entry.Name()))
	}
	return roots, nil
}

// lockActiveRelease holds a shared lease that activation takes exclusively:
// the single release's activation lock, or the node activation lock that
// serializes every scope on a multi-scope node.
func (resolver *ActiveReleaseResolver) lockActiveRelease(ctx context.Context) (func(), error) {
	if resolver == nil || ctx == nil {
		return nil, ErrInvalidState
	}
	path := filepath.Join(resolver.root, "node-activation.lock")
	if !resolver.multiScope() {
		state := filepath.Join(resolver.root, "state")
		info, err := os.Lstat(state)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return nil, ErrInvalidState
		}
		path = filepath.Join(state, "activation.lock")
	}
	file, err := os.OpenFile(path, os.O_RDWR|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrInvalidState
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, ErrInvalidState
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		err = syscall.Flock(int(file.Fd()), syscall.LOCK_SH|syscall.LOCK_NB)
		if err == nil {
			return func() {
				_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
				_ = file.Close()
			}, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			_ = file.Close()
			return nil, ErrInvalidState
		}
		select {
		case <-ctx.Done():
			_ = file.Close()
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

func currentReleaseAt(root string) (string, string, error) {
	current := filepath.Join(root, "current")
	info, err := os.Lstat(current)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return "", "", ErrInvalidState
	}
	target, err := os.Readlink(current)
	if err != nil {
		return "", "", err
	}
	digest := filepath.Base(target)
	if target != filepath.Join("releases", digest) || len(digest) != sha256.Size*2 || !lowerHex(digest) {
		return "", "", ErrInvalidState
	}
	release := filepath.Join(root, target)
	info, err = os.Lstat(release)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", "", ErrInvalidState
	}
	return target, release, nil
}

// cacheManifest returns the validated cache policy manifest of a site runtime
// v2 release (site runtime releases carry no cache freshness policies, so the
// listener map is empty).
func (resolver *ActiveReleaseResolver) cacheManifest(ctx context.Context, release, digest string) (edgeconfig.CachePolicyManifest, map[int]bool, error) {
	manifestBytes, err := readActiveRegularFile(ctx, filepath.Join(release, activeReleaseManifestFile), 8<<20)
	if err != nil || edgeconfig.RejectDuplicateJSONKeys(manifestBytes) != nil {
		return edgeconfig.CachePolicyManifest{}, nil, ErrInvalidState
	}
	decoder := json.NewDecoder(bytes.NewReader(manifestBytes))
	decoder.DisallowUnknownFields()
	var manifest edgeconfig.Manifest
	if decoder.Decode(&manifest) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return edgeconfig.CachePolicyManifest{}, nil, ErrInvalidState
	}
	manifest, err = edgeconfig.NormalizeManifest(manifest)
	if err != nil {
		return edgeconfig.CachePolicyManifest{}, nil, ErrInvalidState
	}
	manifestDigest, err := edgeconfig.ManifestDigest(manifest)
	if err != nil || manifestDigest != digest {
		return edgeconfig.CachePolicyManifest{}, nil, ErrInvalidState
	}
	// Only site runtime v2 releases exist (1.0.35): the cache identity is in
	// the node-compiled derived release.
	for _, file := range manifest.Files {
		if file.Path == siteRuntimeDocumentFile {
			return resolver.siteRuntimeCacheManifest(ctx, manifestBytes, digest)
		}
	}
	return edgeconfig.CachePolicyManifest{}, nil, ErrInvalidState
}

func readManifestContent(ctx context.Context, release string, file edgeconfig.FileManifest, limit int64) ([]byte, error) {
	if file.Size < 1 || file.Size > limit {
		return nil, ErrInvalidState
	}
	content, err := readActiveRegularFile(ctx, filepath.Join(release, filepath.FromSlash(file.Path)), limit)
	if err != nil || int64(len(content)) != file.Size {
		return nil, ErrInvalidState
	}
	digest := sha256.Sum256(content)
	if hex.EncodeToString(digest[:]) != file.SHA256 {
		return nil, ErrInvalidState
	}
	return content, nil
}

func siteFromManifest(manifest edgeconfig.CachePolicyManifest, freshness map[int]bool, activeReleaseSHA256, tenantID, siteID, versionID string,
	revision uint64) (SiteContext, error) {
	if manifest.TenantID != tenantID || manifest.ConfigVersionID != versionID || manifest.ConfigRevision != revision {
		return SiteContext{}, ErrSiteNotFound
	}
	listeners := make([]ListenerContext, 0)
	var namespace string
	var firstPolicy *edgeconfig.CachePolicyDocument
	var domain string
	var domains []string
	keyByHost := false
	generation := ""
	for index, listener := range manifest.Listeners {
		if listener.SiteID != siteID {
			continue
		}
		if namespace == "" {
			namespace = listener.NamespaceID
			domain = listener.Domain
			domains = listener.Domains
			keyByHost = listener.KeyByHost
			generation = listener.CacheGeneration
			policy := listener.Policy
			firstPolicy = &policy
		} else if listener.NamespaceID != namespace || listener.Domain != domain || !slices.Equal(domains, listener.Domains) ||
			listener.KeyByHost != keyByHost || listener.CacheGeneration != generation ||
			!reflect.DeepEqual(*firstPolicy, listener.Policy) {
			return SiteContext{}, ErrSiteNotFound
		}
		listeners = append(listeners, ListenerContext{
			Domain: listener.Domain, Scheme: string(listener.Protocol), ListenPort: listener.ListenPort,
			PrewarmPort: listener.PrewarmPort, PrewarmPathPrefix: listener.PrewarmPathPrefix,
			CacheEnabled: listener.Policy.Mode != edgeconfig.CacheDisabled, CacheFreshness: freshness[index],
		})
	}
	expected := CacheNamespaceID(tenantID, siteID, versionID)
	if generation != "" {
		expected = edgeconfig.CacheSiteNamespaceID(tenantID, siteID)
	}
	if len(listeners) == 0 || namespace != expected {
		return SiteContext{}, ErrSiteNotFound
	}
	site, valid := normalizeSiteContext(SiteContext{
		TenantID: tenantID, SiteID: siteID, ConfigVersionID: versionID, ConfigRevision: revision,
		ActiveReleaseSHA256: activeReleaseSHA256, NginxSHA256: manifest.NginxSHA256,
		CacheIdentity: namespace, QueryMode: firstPolicy.QueryMode,
		QueryNames:      append([]string(nil), firstPolicy.QueryNames...),
		VaryHeaders:     append([]string(nil), firstPolicy.VaryHeaders...),
		CacheRules:      append([]edgeconfig.CacheRuleDocument(nil), firstPolicy.Rules...),
		Listeners:       listeners,
		Domains:         slices.Clone(domains),
		KeyByHost:       keyByHost,
		CacheGeneration: generation,
	})
	if !valid {
		return SiteContext{}, ErrSiteNotFound
	}
	return site, nil
}

var readActiveRegularOpen = func(path string, flag int, perm os.FileMode) (*os.File, error) {
	return os.OpenFile(path, flag, perm)
}

func readActiveRegularFile(ctx context.Context, path string, limit int64) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	file, err := readActiveRegularOpen(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > limit {
		return nil, ErrInvalidState
	}
	content, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(content)) != info.Size() {
		return nil, ErrInvalidState
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return content, nil
}

var _ SiteResolver = (*ActiveReleaseResolver)(nil)

// siteRuntimeCacheManifest reads a site runtime v2 release's cache identity
// from the node-compiled derived release of the same signed digest: the
// derived release carries the signed manifest unchanged, the compiled
// nginx.conf and the cache manifest bound to it. Site runtime releases carry
// no cache freshness policies.
func (resolver *ActiveReleaseResolver) siteRuntimeCacheManifest(ctx context.Context, signedManifest []byte,
	digest string) (edgeconfig.CachePolicyManifest, map[int]bool, error) {
	derived := filepath.Join(resolver.siteRuntimeRoot, "releases", digest)
	info, err := os.Lstat(derived)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return edgeconfig.CachePolicyManifest{}, nil, ErrInvalidState
	}
	manifest, err := readActiveRegularFile(ctx, filepath.Join(derived, activeReleaseManifestFile), 8<<20)
	if err != nil || !bytes.Equal(manifest, signedManifest) {
		return edgeconfig.CachePolicyManifest{}, nil, ErrInvalidState
	}
	policy, err := readActiveRegularFile(ctx, filepath.Join(derived, filepath.FromSlash(edgeconfig.CachePolicyManifestPath)), 1<<20)
	if err != nil {
		return edgeconfig.CachePolicyManifest{}, nil, ErrInvalidState
	}
	nginx, err := readActiveRegularFile(ctx, filepath.Join(derived, "nginx.conf"), 8<<20)
	if err != nil {
		return edgeconfig.CachePolicyManifest{}, nil, ErrInvalidState
	}
	keyModule, err := readActiveRegularFile(ctx, filepath.Join(derived, filepath.FromSlash(edgeconfig.CachePolicyKeyModulePath)), 256<<10)
	if err != nil {
		return edgeconfig.CachePolicyManifest{}, nil, ErrInvalidState
	}
	parsed, err := edgeconfig.ParseSiteRuntimeCacheRelease(policy, nginx, keyModule)
	if err != nil {
		return edgeconfig.CachePolicyManifest{}, nil, ErrInvalidState
	}
	return parsed, map[int]bool{}, nil
}
