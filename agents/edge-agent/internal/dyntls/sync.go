package dyntls

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/certstore"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"golang.org/x/crypto/ocsp"
)

// Resolver is the certificate store's lookup (certstore.Manager): the
// version's files, checked against the site, scope, version and domain.
type Resolver interface {
	ResolveCertificateVersion(context.Context, certstore.CertificateResolveRequest) (certstore.ResolvedCertificateVersion, error)
}

// Version is one certificate version a generation serves.
type Version struct {
	ID    string
	Sites []string // site IDs, sorted
	// OCSP: some listener of it staples.
	OCSP bool
}

// Unavailable is a version the store cannot give (missing, or outside its
// validity window): the node refuses that site's handshakes (cdnca_tls) —
// the same outcome as v7's ssl_reject_handshake for it; other sites are not
// affected, so it is reported, not an activation failure.
type Unavailable struct {
	SiteID, VersionID string
	Err               error
}

// SyncResult is what Sync did.
type SyncResult struct {
	Versions    []Version
	Copied      int
	Unavailable []Unavailable
}

// Sync copies the certificate versions the sites' TLS listeners name from
// the certificate store into the pool, before the site index activation that
// makes them reachable (contract: objects first, then the generation). The
// files are copied, digest-checked against the store's record and parsed
// (ParseChain) once per version; a version already in the pool is not copied
// again (versions are immutable).
func (pool Pool) Sync(ctx context.Context, store Resolver, sites []edgesite.Site) (SyncResult, error) {
	versions := map[string]*Version{}
	var result SyncResult
	for _, site := range sites {
		for _, listener := range site.Listeners {
			if listener.TLS == nil {
				continue
			}
			id := listener.TLS.CertificateVersionID
			version := versions[id]
			if version == nil {
				version = &Version{ID: id}
				versions[id] = version
			}
			if !slices.Contains(version.Sites, site.SiteID) {
				version.Sites = append(version.Sites, site.SiteID)
			}
			version.OCSP = version.OCSP || listener.TLS.OCSPStapling
		}
	}
	ids := make([]string, 0, len(versions))
	for id := range versions {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	bySite := map[string]edgesite.Site{}
	for _, site := range sites {
		bySite[site.SiteID] = site
	}
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		version := versions[id]
		sort.Strings(version.Sites)
		result.Versions = append(result.Versions, *version)
		if pool.has(id) {
			continue
		}
		site := bySite[version.Sites[0]]
		chain, key, err := readVersion(ctx, store, site, id)
		if err != nil {
			result.Unavailable = append(result.Unavailable, Unavailable{SiteID: site.SiteID, VersionID: id, Err: err})
			continue
		}
		if err := pool.PutCertificate(id, chain, key); err != nil {
			return result, fmt.Errorf("certificate version %s: %w", id, err)
		}
		result.Copied++
	}
	return result, nil
}

func (pool Pool) has(version string) bool {
	for _, suffix := range []string{".crt", ".key"} {
		if info, err := os.Lstat(pool.path(version, suffix)); err != nil || !info.Mode().IsRegular() {
			return false
		}
	}
	return true
}

// readVersion resolves the version for every name of the site (the store
// checks the binding covers each) and reads its files, checking the digests
// the store recorded when it validated them.
func readVersion(ctx context.Context, store Resolver, site edgesite.Site, version string) ([]byte, []byte, error) {
	var resolved certstore.ResolvedCertificateVersion
	names := append([]string{site.Hosts.Primary}, site.Hosts.Aliases...)
	for index, name := range names {
		value, err := store.ResolveCertificateVersion(ctx, certstore.CertificateResolveRequest{
			TenantScopeID: site.ConfigurationScopeID, SiteID: site.SiteID, CertificateVersionID: version, Domain: name})
		if err != nil {
			return nil, nil, err
		}
		if index > 0 && (value.CertificatePath != resolved.CertificatePath || value.PrivateKeyPath != resolved.PrivateKeyPath) {
			return nil, nil, fmt.Errorf("%w: version %s files differ across names", ErrInvalid, version)
		}
		resolved = value
	}
	chain, err := readChecked(resolved.CertificatePath, resolved.CertificateSHA256, MaxChainBytes)
	if err != nil {
		return nil, nil, err
	}
	key, err := readChecked(resolved.PrivateKeyPath, resolved.PrivateKeySHA256, MaxKeyBytes)
	if err != nil {
		return nil, nil, err
	}
	return chain, key, nil
}

func readChecked(path string, digest [sha256.Size]byte, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(content)) > limit || sha256.Sum256(content) != digest {
		return nil, fmt.Errorf("%w: %s does not match the certificate store's record", ErrInvalid, path)
	}
	return content, nil
}

// Keep is the versions to keep in the pool after an activation: those of the
// generation now active and of the one before it (a rollback target). The
// same list goes to the certificate store's references
// (certstore.Manager.SetCertificateVersionReferences), so neither side drops
// a version the other still serves.
func Keep(current, previous []Version) certstore.CertificateVersionReferences {
	references := certstore.CertificateVersionReferences{Current: []string{}, Previous: []string{}}
	for _, version := range current {
		references.Current = append(references.Current, version.ID)
	}
	for _, version := range previous {
		if !slices.Contains(references.Current, version.ID) {
			references.Previous = append(references.Previous, version.ID)
		}
	}
	return references
}

// ---------------------------------------------------------------- OCSP

// Fetcher obtains the current OCSP response for a leaf certificate.
//
// The dynamic path has no nginx ssl_stapling (it only staples static
// certificates), so the agent fetches. The site TLS profile
// keeps nginx's own stapling on the v7 path and defines no control-plane
// prefetch; when one is added (the control plane fetching once per
// certificate version and shipping the DER with it), it is another Fetcher
// and RefreshOCSP stays as is.
type Fetcher interface {
	Fetch(ctx context.Context, leaf, issuer *x509.Certificate) ([]byte, error)
}

// ErrNoResponder: the leaf names no OCSP responder (Let's Encrypt
// certificates since 2025): nothing to staple, not an error to retry.
var ErrNoResponder = errors.New("certificate names no OCSP responder")

// ErrRevoked: the responder signed "revoked" for the certificate.
var ErrRevoked = errors.New("OCSP responder reports the certificate revoked")

// HTTPFetcher asks the leaf's own responders (Authority Information Access)
// over HTTP POST (RFC 6960 appendix A.1).
type HTTPFetcher struct {
	Client *http.Client
}

func (fetcher HTTPFetcher) Fetch(ctx context.Context, leaf, issuer *x509.Certificate) ([]byte, error) {
	if len(leaf.OCSPServer) == 0 {
		return nil, ErrNoResponder
	}
	request, err := ocsp.CreateRequest(leaf, issuer, &ocsp.RequestOptions{Hash: crypto.SHA256})
	if err != nil {
		return nil, err
	}
	client := fetcher.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	var failures []error
	for _, responder := range leaf.OCSPServer {
		if !strings.HasPrefix(responder, "http://") && !strings.HasPrefix(responder, "https://") {
			continue
		}
		httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, responder, bytes.NewReader(request))
		if err != nil {
			failures = append(failures, err)
			continue
		}
		httpRequest.Header.Set("Content-Type", "application/ocsp-request")
		httpRequest.Header.Set("Accept", "application/ocsp-response")
		response, err := client.Do(httpRequest)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, MaxOCSPBytes+1))
		response.Body.Close()
		if err == nil && response.StatusCode != http.StatusOK {
			err = fmt.Errorf("OCSP responder %s: HTTP %d", responder, response.StatusCode)
		} else if err == nil && len(body) > MaxOCSPBytes {
			err = fmt.Errorf("OCSP responder %s: response too large", responder)
		}
		if err != nil {
			failures = append(failures, err)
			continue
		}
		return body, nil
	}
	if len(failures) == 0 {
		return nil, ErrNoResponder
	}
	return nil, errors.Join(failures...)
}

// OCSPStatus is one version's refresh outcome.
type OCSPStatus struct {
	VersionID  string
	Stapled    bool      // a valid response is in the pool
	NextUpdate time.Time // of the stored response
	Err        error     // this round's failure (the previous response stays while valid)
}

// RefreshMaximum: a stored response is replaced once half of its validity
// has passed, and at least this often.
const RefreshMaximum = 12 * time.Hour

// RefreshOCSP fetches a fresh response for every stapling version whose
// stored one is missing, invalid or past half of its validity, and stores it
// with PutOCSP (which verifies signature, status good and freshness). A
// fetch failure keeps the stored response while it is valid (stapling a
// still valid response beats none); a signed "revoked" removes it at once;
// an expired one is removed so the node stops
// stapling it (Lua also refuses an expired one). Versions that no longer
// staple lose their response.
func (pool Pool) RefreshOCSP(ctx context.Context, fetcher Fetcher, versions []Version, now time.Time) []OCSPStatus {
	var statuses []OCSPStatus
	for _, version := range versions {
		if !version.OCSP {
			_ = pool.RemoveOCSP(version.ID)
			continue
		}
		status := OCSPStatus{VersionID: version.ID}
		leaf, issuer, err := pool.leafAndIssuer(version.ID)
		if err != nil {
			status.Err = err
			statuses = append(statuses, status)
			continue
		}
		current := pool.storedOCSP(version.ID, leaf, issuer, now)
		if current != nil {
			status.Stapled, status.NextUpdate = true, current.NextUpdate
			if !due(current, now) {
				statuses = append(statuses, status)
				continue
			}
		}
		response, err := fetcher.Fetch(ctx, leaf, issuer)
		if err == nil {
			if parsed, parseErr := ocsp.ParseResponseForCert(response, leaf, issuer); parseErr == nil && parsed.Status == ocsp.Revoked {
				// A signed "revoked" ends stapling at once: an older "good"
				// must not keep vouching for the certificate.
				_ = pool.RemoveOCSP(version.ID)
				status.Stapled, status.NextUpdate, status.Err = false, time.Time{}, ErrRevoked
				statuses = append(statuses, status)
				continue
			}
			err = pool.PutOCSP(version.ID, response, issuer, now)
		}
		if err == nil {
			parsed, _ := ocsp.ParseResponseForCert(response, leaf, issuer)
			status.Stapled, status.NextUpdate = true, parsed.NextUpdate
		} else {
			status.Err = err
			if current == nil {
				_ = pool.RemoveOCSP(version.ID)
				status.Stapled = false
			}
		}
		statuses = append(statuses, status)
	}
	return statuses
}

func due(response *ocsp.Response, now time.Time) bool {
	if response.NextUpdate.IsZero() {
		return now.Sub(response.ThisUpdate) >= RefreshMaximum
	}
	half := response.ThisUpdate.Add(response.NextUpdate.Sub(response.ThisUpdate) / 2)
	return !now.Before(half) || now.Sub(response.ThisUpdate) >= RefreshMaximum
}

func (pool Pool) leafAndIssuer(version string) (*x509.Certificate, *x509.Certificate, error) {
	chain, err := os.ReadFile(pool.path(version, ".crt"))
	if err != nil {
		return nil, nil, err
	}
	key, err := os.ReadFile(pool.path(version, ".key"))
	if err != nil {
		return nil, nil, err
	}
	leaf, issuer, err := ParseChain(chain, key)
	if err != nil {
		return nil, nil, err
	}
	if issuer == nil {
		return nil, nil, fmt.Errorf("%w: certificate version %s has no issuer in its chain", ErrInvalid, version)
	}
	return leaf, issuer, nil
}

// storedOCSP is the stored response when it is still good and current.
func (pool Pool) storedOCSP(version string, leaf, issuer *x509.Certificate, now time.Time) *ocsp.Response {
	raw, err := os.ReadFile(pool.path(version, ".ocsp"))
	if err != nil {
		return nil
	}
	parsed, err := ocsp.ParseResponseForCert(raw, leaf, issuer)
	if err != nil || parsed.Status != ocsp.Good || !parsed.NextUpdate.IsZero() && !now.Before(parsed.NextUpdate) {
		_ = pool.RemoveOCSP(version)
		return nil
	}
	return parsed
}
