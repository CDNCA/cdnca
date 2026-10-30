package controlupgrade

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	// ErrArtifactUnavailable: the license origin could not deliver the signed
	// artifact, or the local cache could not store it.
	ErrArtifactUnavailable = errors.New("control upgrade artifact unavailable")
	// ErrArtifactInvalid: the delivered bytes do not match the signed manifest.
	ErrArtifactInvalid = errors.New("control upgrade artifact does not match its signed manifest")
)

// ArtifactCache keeps node upgrade artifacts on the control plane so nodes
// download from the console origin instead of the license server. Files are
// content addressed (<root>/<sha256 hex>) and only become visible after their
// size and SHA-256 match the license-signed manifest; integrity on the node is
// still enforced against the same signed digest carried by the execution.
type ArtifactCache struct {
	root    string
	baseURL string
	client  *http.Client
	mu      sync.Mutex
}

func NewArtifactCache(root, publicBaseURL string, client *http.Client) (*ArtifactCache, error) {
	if client == nil || !filepath.IsAbs(root) || filepath.Clean(root) != root || root == string(filepath.Separator) {
		return nil, ErrInvalidInput
	}
	parsed, err := url.Parse(publicBaseURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Host != strings.ToLower(parsed.Host) ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" ||
		strings.HasSuffix(publicBaseURL, "/") || parsed.String() != publicBaseURL {
		return nil, ErrInvalidInput
	}
	// 0755: the console web server serves this directory under /downloads/.
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, fmt.Errorf("create artifact cache root: %w", err)
	}
	if info, err := os.Lstat(root); err != nil || !info.IsDir() {
		return nil, fmt.Errorf("%w: artifact cache root must be a directory", ErrInvalidInput)
	}
	if err := os.Chmod(root, 0o755); err != nil {
		return nil, fmt.Errorf("set artifact cache root mode: %w", err)
	}
	return &ArtifactCache{root: root, baseURL: publicBaseURL, client: client}, nil
}

// Ensure returns the console URL of the artifact, fetching it from sourceURL
// first when it is not cached yet.
func (cache *ArtifactCache) Ensure(ctx context.Context, sourceURL, digest string, size int64) (string, error) {
	sum, err := base64.RawURLEncoding.DecodeString(digest)
	if err != nil || len(sum) != sha256.Size || size < 1 || size > entitlement.MaxUpgradeArtifactBytes {
		return "", ErrArtifactInvalid
	}
	name := hex.EncodeToString(sum)
	path := filepath.Join(cache.root, name)
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if info, err := os.Lstat(path); err == nil {
		if info.Mode().IsRegular() && info.Size() == size {
			// A hit counts as recent use so Prune keeps it while the plan that
			// asked for it is still being created.
			now := time.Now()
			_ = os.Chtimes(path, now, now)
			return cache.baseURL + "/" + name, nil
		}
		return "", ErrArtifactInvalid
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", ErrArtifactUnavailable
	}
	if err := cache.fetch(ctx, sourceURL, sum, size, path); err != nil {
		return "", err
	}
	return cache.baseURL + "/" + name, nil
}

func (cache *ArtifactCache) fetch(ctx context.Context, sourceURL string, sum []byte, size int64, path string) error {
	parsed, err := url.Parse(sourceURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return ErrArtifactInvalid
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return ErrArtifactInvalid
	}
	request.Header.Set("Accept-Encoding", "identity")
	response, err := cache.client.Do(request)
	if err != nil {
		return fmt.Errorf("%w: fetch %s", ErrArtifactUnavailable, parsed.Host)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: %s returned status %d", ErrArtifactUnavailable, parsed.Host, response.StatusCode)
	}
	if response.ContentLength >= 0 && response.ContentLength != size {
		return ErrArtifactInvalid
	}
	temporary, err := os.CreateTemp(cache.root, ".partial-*")
	if err != nil {
		return ErrArtifactUnavailable
	}
	defer os.Remove(temporary.Name())
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(temporary, hash), io.LimitReader(response.Body, size+1))
	syncErr := temporary.Sync()
	closeErr := temporary.Close()
	if copyErr != nil {
		return fmt.Errorf("%w: read %s", ErrArtifactUnavailable, parsed.Host)
	}
	if written != size || !bytesEqual(hash.Sum(nil), sum) {
		return ErrArtifactInvalid
	}
	// control-api runs with UMask=0077; the console web server must read it.
	if syncErr != nil || closeErr != nil || os.Chmod(temporary.Name(), 0o644) != nil ||
		os.Rename(temporary.Name(), path) != nil {
		return ErrArtifactUnavailable
	}
	if directory, err := os.Open(cache.root); err == nil {
		_ = directory.Sync()
		_ = directory.Close()
	}
	return nil
}

func bytesEqual(left, right []byte) bool {
	return len(left) == len(right) && string(left) == string(right)
}

func (cache *ArtifactCache) ensureManifest(ctx context.Context, manifest entitlement.ArtifactManifestV2) error {
	_, err := cache.Ensure(ctx, manifest.DownloadURL, manifest.SHA256Digest, manifest.ArtifactSizeBytes)
	return err
}

// artifactPruneMinAge keeps files written or hit within this window: a plan
// caches its artifacts before it becomes durable, so a concurrent Prune must
// not remove them in between.
const artifactPruneMinAge = time.Hour

// Prune removes cached artifacts whose hex digest is not in keep and that were
// not written or hit within artifactPruneMinAge, plus leftover partial
// downloads (none is in flight while the lock is held). It returns the number
// of removed files.
func (cache *ArtifactCache) Prune(keep map[string]bool) (int, error) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	entries, err := os.ReadDir(cache.root)
	if err != nil {
		return 0, fmt.Errorf("read artifact cache: %w", err)
	}
	cutoff := time.Now().Add(-artifactPruneMinAge)
	removed := 0
	for _, entry := range entries {
		name := entry.Name()
		partial := strings.HasPrefix(name, ".partial-")
		if !partial && (!validArtifactFileName(name) || keep[name]) {
			continue
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || !partial && info.ModTime().After(cutoff) {
			continue
		}
		if err := os.Remove(filepath.Join(cache.root, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return removed, fmt.Errorf("remove cached artifact: %w", err)
		}
		removed++
	}
	return removed, nil
}

func validArtifactFileName(name string) bool {
	decoded, err := hex.DecodeString(name)
	return err == nil && len(decoded) == sha256.Size && hex.EncodeToString(decoded) == name
}

// artifactFileName maps a manifest digest (base64url SHA-256) to its cache name.
func artifactFileName(digest string) (string, bool) {
	sum, err := base64.RawURLEncoding.DecodeString(digest)
	if err != nil || len(sum) != sha256.Size {
		return "", false
	}
	return hex.EncodeToString(sum), true
}

// planArtifacts is the part of a stored rollout plan snapshot that decides
// which cached artifacts it still needs.
type planArtifacts struct {
	State                PlanState
	SHA256Digest         string
	RollbackSHA256Digest string
	ForwardProfile       struct {
		Platform     string `json:"platform"`
		Architecture string `json:"architecture"`
	}
}

// retainedArtifactNames keeps both artifacts of every unfinished plan, and of
// the newest finished plan per platform/architecture: its forward artifact is
// the version nodes run now, its rollback artifact the previous one. plans
// must be ordered newest first.
func retainedArtifactNames(plans []planArtifacts) map[string]bool {
	keep := map[string]bool{}
	add := func(plan planArtifacts) {
		for _, digest := range []string{plan.SHA256Digest, plan.RollbackSHA256Digest} {
			if name, ok := artifactFileName(digest); ok {
				keep[name] = true
			}
		}
	}
	latestFinished := map[[2]string]bool{}
	for _, plan := range plans {
		if plan.State != PlanCompleted && plan.State != PlanFailed {
			add(plan)
			continue
		}
		cohort := [2]string{plan.ForwardProfile.Platform, plan.ForwardProfile.Architecture}
		if !latestFinished[cohort] {
			latestFinished[cohort] = true
			add(plan)
		}
	}
	return keep
}

// PruneUnreferenced removes cached artifacts no stored plan still needs
// (retainedArtifactNames). Any read or decode failure removes nothing.
func (cache *ArtifactCache) PruneUnreferenced(ctx context.Context, pool *pgxpool.Pool) (int, error) {
	rows, err := pool.Query(ctx, `SELECT canonical_snapshot_bytes FROM control_upgrade_rollout_plans
		ORDER BY updated_at DESC, id`)
	if err != nil {
		return 0, fmt.Errorf("read rollout plans: %w", err)
	}
	var plans []planArtifacts
	for rows.Next() {
		var snapshot []byte
		var plan planArtifacts
		if err := rows.Scan(&snapshot); err != nil {
			rows.Close()
			return 0, fmt.Errorf("read rollout plan: %w", err)
		}
		if err := json.Unmarshal(snapshot, &plan); err != nil || plan.State == "" {
			rows.Close()
			return 0, fmt.Errorf("%w: rollout plan snapshot", ErrInvalidPlan)
		}
		plans = append(plans, plan)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("read rollout plans: %w", err)
	}
	return cache.Prune(retainedArtifactNames(plans))
}
