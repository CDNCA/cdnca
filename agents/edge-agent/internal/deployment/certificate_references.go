package deployment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/certstore"
	"github.com/google/uuid"
)

const siteRuntimeV2File = "site-runtime.v2.json"

var errCertificateReferenceRecovery = errors.New("certificate reference recovery failed")

type CertificateVersionStore interface {
	CertificateVersionReferences(context.Context) (certstore.CertificateVersionReferences, error)
	SetCertificateVersionReferences(context.Context, certstore.CertificateVersionReferences) error
	ResolveCertificateVersion(context.Context, certstore.CertificateResolveRequest) (certstore.ResolvedCertificateVersion, error)
}

type certificateReleaseReferences struct {
	versions    []string
	resolutions []certstore.CertificateResolveRequest
}

func NewManagerWithCertificateVersionStore(
	stateRoot string,
	prechecker Prechecker,
	runtime Runtime,
	config Config,
	certificateVersions CertificateVersionStore,
	certificateStateRoot string,
) (*Manager, error) {
	manager, err := newManagerWithConfig(stateRoot, prechecker, runtime, config)
	if err != nil {
		return nil, err
	}
	if err := manager.ConfigureCertificateVersionStore(certificateVersions, certificateStateRoot); err != nil {
		return nil, err
	}
	return manager, nil
}

func (m *Manager) ConfigureCertificateVersionStore(certificateVersions CertificateVersionStore, certificateStateRoot string) error {
	if m == nil || certificateVersions == nil || certificateStateRoot == "" || !filepath.IsAbs(certificateStateRoot) {
		return fmt.Errorf("%w: certificate version store and absolute state root are required", ErrInvalidCommand)
	}
	resolvedRoot, err := filepath.EvalSymlinks(certificateStateRoot)
	if err != nil {
		return fmt.Errorf("%w: resolve certificate state root: %v", ErrInvalidPath, err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.certificateVersions != nil {
		return fmt.Errorf("%w: certificate version store is already configured", ErrInvalidCommand)
	}
	m.certificateVersions = certificateVersions
	m.certificateStateRoot = resolvedRoot
	return nil
}

func (m *Manager) RecoverCertificateVersionReferences(ctx context.Context) error {
	if m == nil || m.certificateVersions == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	unlock, err := m.store.lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	pointers, err := m.store.loadPointers()
	if err != nil {
		return err
	}
	activeDigest, err := m.store.currentDigest()
	if err != nil {
		return err
	}
	if activeDigest != pointers.CurrentDigest {
		return fmt.Errorf("%w: active release differs from saved pointers", ErrCorruptState)
	}
	_, _, err = m.prepareCertificateReferences(ctx, pointers.Current, pointers.CurrentDigest, pointers.Previous, pointers.PreviousDigest)
	return err
}

func (m *Manager) prepareCertificateReferences(ctx context.Context, currentConfigVersionID, currentDigest, previousConfigVersionID, previousDigest string) (certstore.CertificateVersionReferences, bool, error) {
	return m.prepareCertificateReferencesForRecovery(ctx, currentConfigVersionID, currentDigest, previousConfigVersionID, previousDigest, false)
}

func (m *Manager) prepareCertificateReferencesForRecovery(ctx context.Context, currentConfigVersionID, currentDigest, previousConfigVersionID, previousDigest string, preservePrevious bool) (certstore.CertificateVersionReferences, bool, error) {
	if m.certificateVersions == nil {
		return certstore.CertificateVersionReferences{}, false, nil
	}
	current, err := m.loadCertificateReleaseReferences(currentDigest, currentConfigVersionID)
	if err != nil {
		return certstore.CertificateVersionReferences{}, false, err
	}
	previous, err := m.loadCertificateReleaseReferences(previousDigest, previousConfigVersionID)
	if err != nil {
		return certstore.CertificateVersionReferences{}, false, err
	}
	before, err := m.certificateVersions.CertificateVersionReferences(ctx)
	if err != nil {
		return certstore.CertificateVersionReferences{}, false, err
	}
	desired := certstore.CertificateVersionReferences{
		Current: append([]string(nil), current.versions...), Previous: append([]string(nil), previous.versions...),
	}
	if preservePrevious {
		// A failed or interrupted recovery may leave either runtime generation
		// serving. Protect both until the selected target passes health checks.
		versions := make(map[string]struct{})
		for _, values := range [][]string{desired.Previous, before.Current, before.Previous} {
			for _, version := range values {
				versions[version] = struct{}{}
			}
		}
		desired.Previous = make([]string, 0, len(versions))
		for version := range versions {
			desired.Previous = append(desired.Previous, version)
		}
		sort.Strings(desired.Previous)
	}
	if err := m.certificateVersions.SetCertificateVersionReferences(ctx, desired); err != nil {
		return before, false, err
	}
	restore := func(cause error) error {
		if restoreErr := m.certificateVersions.SetCertificateVersionReferences(context.WithoutCancel(ctx), before); restoreErr != nil {
			return errors.Join(cause, errCertificateReferenceRecovery, fmt.Errorf("restore certificate references: %w", restoreErr))
		}
		return cause
	}
	// Every domain of a site resolves to the same files: check each path once.
	trusted := make(map[string]bool)
	for _, request := range current.resolutions {
		resolved, resolveErr := m.certificateVersions.ResolveCertificateVersion(ctx, request)
		if resolveErr != nil {
			return before, true, restore(resolveErr)
		}
		if !sameResolvedCertificateIdentity(resolved, request) {
			return before, true, restore(certstore.ErrCertificateUnavailable)
		}
		for _, path := range []string{resolved.CertificatePath, resolved.PrivateKeyPath} {
			if !trusted[path] {
				if !m.trustedCertificatePath(path) {
					return before, true, restore(certstore.ErrCertificateUnavailable)
				}
				trusted[path] = true
			}
		}
	}
	return before, true, nil
}

func (m *Manager) restoreCertificateReferences(ctx context.Context, references certstore.CertificateVersionReferences, changed bool) error {
	if !changed || m.certificateVersions == nil {
		return nil
	}
	return m.certificateVersions.SetCertificateVersionReferences(context.WithoutCancel(ctx), references)
}

func (m *Manager) loadCertificateReleaseReferences(digest, configVersionID string) (certificateReleaseReferences, error) {
	if digest == "" {
		return certificateReleaseReferences{}, nil
	}
	release, err := m.store.releasePath(digest)
	if err != nil {
		return certificateReleaseReferences{}, err
	}
	if err := m.store.verifyExistingRelease(release); err != nil {
		return certificateReleaseReferences{}, err
	}
	raw, err := readRegularFile(filepath.Join(release, siteRuntimeV2File))
	if errors.Is(err, os.ErrNotExist) {
		return certificateReleaseReferences{}, nil
	}
	if err != nil {
		return certificateReleaseReferences{}, err
	}
	// The release passed the node's gates at precheck; here it is only
	// re-read for its certificate references (scope, version, sites).
	var document struct {
		ConfigurationScopeID string `json:"configuration_scope_id"`
		ConfigVersionID      string `json:"config_version_id"`
		Sites                []struct {
			ID        string   `json:"id"`
			Domains   []string `json:"domains"`
			Listeners []struct {
				TLS *struct {
					CertificateVersionID string `json:"certificate_version_id"`
				} `json:"tls"`
			} `json:"listeners"`
		} `json:"sites"`
	}
	if json.Unmarshal(raw, &document) != nil || !canonicalUUID(document.ConfigurationScopeID) ||
		!canonicalUUID(document.ConfigVersionID) || (configVersionID != "" && document.ConfigVersionID != configVersionID) {
		return certificateReleaseReferences{}, fmt.Errorf("%w: site runtime certificate references are invalid", ErrCorruptState)
	}
	requests := make([]certstore.CertificateResolveRequest, 0)
	versions := make(map[string]struct{})
	for _, site := range document.Sites {
		for _, listener := range site.Listeners {
			if listener.TLS == nil {
				continue
			}
			version := listener.TLS.CertificateVersionID
			if !canonicalUUID(site.ID) || !canonicalUUID(version) || len(site.Domains) == 0 {
				return certificateReleaseReferences{}, fmt.Errorf("%w: site runtime certificate references are invalid", ErrCorruptState)
			}
			versions[version] = struct{}{}
			for _, domain := range site.Domains {
				requests = append(requests, certstore.CertificateResolveRequest{
					TenantScopeID: document.ConfigurationScopeID, SiteID: site.ID,
					CertificateVersionID: version, Domain: domain,
				})
			}
		}
	}
	result := certificateReleaseReferences{resolutions: requests}
	for version := range versions {
		result.versions = append(result.versions, version)
	}
	sort.Strings(result.versions)
	sort.Slice(result.resolutions, func(left, right int) bool {
		first, second := result.resolutions[left], result.resolutions[right]
		if first.CertificateVersionID != second.CertificateVersionID {
			return first.CertificateVersionID < second.CertificateVersionID
		}
		if first.TenantScopeID != second.TenantScopeID {
			return first.TenantScopeID < second.TenantScopeID
		}
		if first.SiteID != second.SiteID {
			return first.SiteID < second.SiteID
		}
		return first.Domain < second.Domain
	})
	result.resolutions = compactCertificateRequests(result.resolutions)
	return result, nil
}

func compactCertificateRequests(values []certstore.CertificateResolveRequest) []certstore.CertificateResolveRequest {
	result := values[:0]
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}

func sameResolvedCertificateIdentity(resolved certstore.ResolvedCertificateVersion, request certstore.CertificateResolveRequest) bool {
	if resolved.TenantScopeID != request.TenantScopeID || resolved.SiteID != request.SiteID ||
		resolved.CertificateVersionID != request.CertificateVersionID {
		return false
	}
	for _, domain := range resolved.Domains {
		if domain == request.Domain {
			return true
		}
	}
	return false
}

func (m *Manager) trustedCertificatePath(path string) bool {
	if path == "" || !filepath.IsAbs(path) {
		return false
	}
	pathInfo, err := os.Lstat(path)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.Mode().IsRegular() {
		return false
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return false
	}
	relative, err := filepath.Rel(m.certificateStateRoot, resolved)
	if err != nil || relative == ".." || filepath.IsAbs(relative) || len(relative) >= 3 && relative[:3] == ".."+string(filepath.Separator) {
		return false
	}
	info, err := os.Stat(resolved)
	return err == nil && info.Mode().IsRegular()
}

// canonicalUUID: the lower-case hyphenated form the documents carry.
func canonicalUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed.String() == value
}
