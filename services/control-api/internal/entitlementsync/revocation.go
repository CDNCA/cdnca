package entitlementsync

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

const revocationPollInterval = time.Minute

type RevocationFetchRequest struct {
	InstallationID uuid.UUID
	PrivateKey     ed25519.PrivateKey
	Now            time.Time
	Known          *entitlementguard.RevocationSnapshot
}

type RevocationFetchResponse struct {
	Artifact    []byte
	NotModified bool
	// LeaseRefreshGeneration is entitlement.RevocationLeaseRefreshGenerationHeader;
	// HasLeaseRefreshGeneration is false when the header is absent or malformed.
	LeaseRefreshGeneration    uint64
	HasLeaseRefreshGeneration bool
}

// LeaseRefresher renews the entitlement lease now (Syncer.SyncOnce).
type LeaseRefresher interface {
	SyncOnce(context.Context) (entitlementguard.Snapshot, error)
}

type RevocationFetcher interface {
	Fetch(context.Context, RevocationFetchRequest) (RevocationFetchResponse, error)
}

type RevocationStore interface {
	Current(context.Context, time.Time) (entitlementguard.RevocationSnapshot, error)
	Install(context.Context, []byte, time.Time) (entitlementguard.RevocationSnapshot, error)
}

type RevocationClient struct {
	base *Client
}

func NewRevocationClient(base *Client) (*RevocationClient, error) {
	if base == nil || base.baseURL == nil || base.http == nil {
		return nil, ErrInvalidConfiguration
	}
	return &RevocationClient{base: base}, nil
}

func (client *RevocationClient) Fetch(ctx context.Context, input RevocationFetchRequest) (RevocationFetchResponse, error) {
	if client == nil || client.base == nil || client.base.baseURL == nil || client.base.http == nil ||
		input.InstallationID == uuid.Nil || len(input.PrivateKey) != ed25519.PrivateKeySize || input.Now.IsZero() {
		return RevocationFetchResponse{}, ErrInvalidConfiguration
	}
	requestedAt := input.Now.UTC().Unix()
	proof := entitlement.RevocationFetchProof{
		InstallationID: input.InstallationID.String(),
		RequestedAt:    requestedAt,
	}
	if input.Known != nil {
		if input.Known.Revision == 0 || input.Known.ArtifactSHA256 == ([32]byte{}) || input.Known.ETag == "" ||
			input.Known.ExpiresAt.IsZero() {
			return RevocationFetchResponse{}, ErrInvalidConfiguration
		}
		proof.KnownRevision = input.Known.Revision
		proof.KnownDigest = base64.RawURLEncoding.EncodeToString(input.Known.ArtifactSHA256[:])
		proof.IfNoneMatch = input.Known.ETag
		if proof.IfNoneMatch != `"sha256-`+proof.KnownDigest+`"` ||
			(input.Known.InstallationID != "" && input.Known.InstallationID != input.InstallationID.String()) {
			return RevocationFetchResponse{}, ErrInvalidConfiguration
		}
	}
	proof.RequestID = fmt.Sprintf("control-revocation-%s-%d-%d", input.InstallationID, requestedAt,
		proof.KnownRevision)
	message, err := entitlement.RevocationFetchProofMessage(proof)
	if err != nil {
		return RevocationFetchResponse{}, ErrInvalidConfiguration
	}
	proof.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(input.PrivateKey, message))

	target := *client.base.baseURL
	target.Path += entitlement.RevocationSetPath
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return RevocationFetchResponse{}, fmt.Errorf("create entitlement revocation request: %w", err)
	}
	request.Header.Set("Accept", entitlement.RevocationSetMediaTypeV2)
	request.Header.Set("X-Request-ID", proof.RequestID)
	request.Header.Set("X-CDNCA-Installation-ID", proof.InstallationID)
	request.Header.Set("X-CDNCA-Requested-At", strconv.FormatInt(proof.RequestedAt, 10))
	request.Header.Set("X-CDNCA-Known-Revocation-Revision", strconv.FormatUint(proof.KnownRevision, 10))
	request.Header.Set("X-CDNCA-Known-Revocation-SHA256", proof.KnownDigest)
	request.Header.Set("X-CDNCA-Proof", proof.Signature)
	if proof.IfNoneMatch != "" {
		request.Header.Set("If-None-Match", proof.IfNoneMatch)
	}
	response, err := client.base.http.Do(request)
	if err != nil {
		return RevocationFetchResponse{}, fmt.Errorf("fetch entitlement revocation state: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotModified {
		if input.Known == nil || !validRevocationResponseMetadata(response.Header, input.Known.ETag,
			input.Known.Revision, input.Known.ArtifactSHA256, input.Known.ExpiresAt.UTC().Unix()) {
			return RevocationFetchResponse{}, ErrInvalidResponse
		}
		generation, ok := leaseRefreshGeneration(response.Header)
		return RevocationFetchResponse{NotModified: true, LeaseRefreshGeneration: generation,
			HasLeaseRefreshGeneration: ok}, nil
	}
	if response.StatusCode != http.StatusOK {
		return RevocationFetchResponse{}, decodeRevocationHTTPError(response)
	}
	if response.Header.Get("Content-Type") != entitlement.RevocationSetMediaTypeV2 {
		return RevocationFetchResponse{}, ErrInvalidResponse
	}
	artifact, err := io.ReadAll(io.LimitReader(response.Body, entitlement.RevocationSetMaxBytes+1))
	if err != nil || len(artifact) == 0 || len(artifact) > entitlement.RevocationSetMaxBytes {
		return RevocationFetchResponse{}, ErrInvalidResponse
	}
	signed, err := entitlement.DecodeRevocationSet(artifact)
	if err != nil || signed.Body.InstallationID != input.InstallationID.String() {
		return RevocationFetchResponse{}, ErrInvalidResponse
	}
	digest := entitlement.RevocationSetDigest(artifact)
	if !validRevocationResponseMetadata(response.Header, entitlement.RevocationSetETag(artifact),
		signed.Body.Revision, digest, signed.Body.ExpiresAt) {
		return RevocationFetchResponse{}, ErrInvalidResponse
	}
	generation, ok := leaseRefreshGeneration(response.Header)
	return RevocationFetchResponse{Artifact: append([]byte(nil), artifact...), LeaseRefreshGeneration: generation,
		HasLeaseRefreshGeneration: ok}, nil
}

func leaseRefreshGeneration(header http.Header) (uint64, bool) {
	values := header.Values(entitlement.RevocationLeaseRefreshGenerationHeader)
	if len(values) != 1 {
		return 0, false
	}
	generation, err := strconv.ParseUint(values[0], 10, 64)
	if err != nil || strconv.FormatUint(generation, 10) != values[0] {
		return 0, false
	}
	return generation, true
}

func validRevocationResponseMetadata(header http.Header, etag string, revision uint64, digest [32]byte,
	expiresAt int64,
) bool {
	return exactRevocationResponseHeader(header, "ETag", etag) &&
		exactRevocationResponseHeader(header, "X-Cdnca-Revocation-Revision", strconv.FormatUint(revision, 10)) &&
		exactRevocationResponseHeader(header, "X-Cdnca-Revocation-Digest",
			base64.RawURLEncoding.EncodeToString(digest[:])) &&
		exactRevocationResponseHeader(header, "X-Cdnca-Revocation-Expires-At", strconv.FormatInt(expiresAt, 10))
}

func exactRevocationResponseHeader(header http.Header, name, expected string) bool {
	values := header.Values(name)
	return len(values) == 1 && values[0] == expected
}

func decodeRevocationHTTPError(response *http.Response) error {
	limited := io.LimitReader(response.Body, 16*1024)
	var payload struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.NewDecoder(limited).Decode(&payload)
	return &HTTPError{StatusCode: response.StatusCode, Code: payload.Error.Code,
		RetryAfter: parseRetryAfter(response.Header.Get("Retry-After"), time.Now())}
}

type PostgresRevocationStore struct {
	service *entitlementguard.RevocationService
}

func NewPostgresRevocationStore(pool *pgxpool.Pool, trust *entitlementguard.TrustStore) *PostgresRevocationStore {
	return &PostgresRevocationStore{service: entitlementguard.NewRevocationService(pool, trust)}
}

func (store *PostgresRevocationStore) Current(ctx context.Context, now time.Time) (entitlementguard.RevocationSnapshot, error) {
	if store == nil || store.service == nil {
		return entitlementguard.RevocationSnapshot{}, ErrInvalidConfiguration
	}
	return store.service.Restore(ctx, now)
}

// LastKnownGood returns the last verified revocation list even past its window;
// used for startup and readiness during an outage.
func (store *PostgresRevocationStore) LastKnownGood(ctx context.Context, now time.Time) (entitlementguard.RevocationSnapshot, error) {
	if store == nil || store.service == nil {
		return entitlementguard.RevocationSnapshot{}, ErrInvalidConfiguration
	}
	return store.service.RestoreLKG(ctx, now)
}

func (store *PostgresRevocationStore) Install(ctx context.Context, artifact []byte,
	now time.Time,
) (entitlementguard.RevocationSnapshot, error) {
	if store == nil || store.service == nil {
		return entitlementguard.RevocationSnapshot{}, ErrInvalidConfiguration
	}
	return store.service.Accept(ctx, artifact, now)
}

type RevocationSyncConfig struct {
	Client         RevocationFetcher
	Store          RevocationStore
	InstallationID uuid.UUID
	PrivateKey     ed25519.PrivateKey
	Now            func() time.Time
	Wait           func(context.Context, time.Duration) error
	Logger         *slog.Logger
	// Lease, when set, is renewed by RefreshLease once the license service's lease
	// refresh generation differs from the last one renewed for (binding or official
	// entry changes, license migration 081).
	Lease LeaseRefresher
}

type RevocationSyncer struct {
	client         RevocationFetcher
	store          RevocationStore
	installationID uuid.UUID
	privateKey     ed25519.PrivateKey
	now            func() time.Time
	wait           func(context.Context, time.Duration) error
	logger         *slog.Logger
	lease          LeaseRefresher

	generationMu sync.Mutex
	observed     uint64 // last generation the license service reported
	renewed      uint64 // generation the lease was last renewed for; 0 = none since start
}

func NewRevocationSyncer(config RevocationSyncConfig) (*RevocationSyncer, error) {
	if config.Client == nil || config.Store == nil || config.InstallationID == uuid.Nil ||
		len(config.PrivateKey) != ed25519.PrivateKeySize {
		return nil, ErrInvalidConfiguration
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Wait == nil {
		config.Wait = waitContext
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	return &RevocationSyncer{client: config.Client, store: config.Store,
		installationID: config.InstallationID, privateKey: append(ed25519.PrivateKey(nil), config.PrivateKey...),
		now: config.Now, wait: config.Wait, logger: config.Logger, lease: config.Lease}, nil
}

func (syncer *RevocationSyncer) SyncOnce(ctx context.Context) (entitlementguard.RevocationSnapshot, error) {
	if syncer == nil || syncer.client == nil || syncer.store == nil || syncer.now == nil {
		return entitlementguard.RevocationSnapshot{}, ErrInvalidConfiguration
	}
	now := syncer.now().UTC()
	current, currentErr := syncer.store.Current(ctx, now)
	var known *entitlementguard.RevocationSnapshot
	if currentErr == nil {
		copy := current
		known = &copy
	} else if !errors.Is(currentErr, entitlementguard.ErrRevocationUnavailable) &&
		!errors.Is(currentErr, entitlementguard.ErrRevocationExpired) &&
		!errors.Is(currentErr, entitlementguard.ErrRevocationInvalid) {
		return entitlementguard.RevocationSnapshot{}, currentErr
	}
	response, err := syncer.client.Fetch(ctx, RevocationFetchRequest{InstallationID: syncer.installationID,
		PrivateKey: syncer.privateKey, Now: now, Known: known})
	if err != nil {
		return entitlementguard.RevocationSnapshot{}, err
	}
	if response.HasLeaseRefreshGeneration {
		syncer.generationMu.Lock()
		syncer.observed = response.LeaseRefreshGeneration
		syncer.generationMu.Unlock()
	}
	if response.NotModified {
		if known == nil {
			return entitlementguard.RevocationSnapshot{}, ErrInvalidResponse
		}
		return current, nil
	}
	if len(response.Artifact) == 0 {
		return entitlementguard.RevocationSnapshot{}, ErrInvalidResponse
	}
	return syncer.store.Install(ctx, response.Artifact, now)
}

// RefreshLease renews the lease when the observed lease refresh generation differs from
// the one last renewed for. Generation 0 means nothing changed yet; after a restart a
// non-zero generation is renewed for once, since a change may have happened while down.
// It is called from the polling loop, never during startup: the first lease is installed
// only after the revocation state (installEntitlementLeaseAfterRevocations).
func (syncer *RevocationSyncer) RefreshLease(ctx context.Context) error {
	if syncer == nil || syncer.lease == nil {
		return nil
	}
	syncer.generationMu.Lock()
	target, renewed := syncer.observed, syncer.renewed
	syncer.generationMu.Unlock()
	if target == renewed {
		return nil
	}
	if _, err := syncer.lease.SyncOnce(ctx); err != nil {
		return fmt.Errorf("refresh entitlement lease for generation %d: %w", target, err)
	}
	syncer.generationMu.Lock()
	syncer.renewed = target
	syncer.generationMu.Unlock()
	return nil
}

func (syncer *RevocationSyncer) Run(ctx context.Context) error {
	if syncer == nil || syncer.wait == nil || syncer.logger == nil {
		return ErrInvalidConfiguration
	}
	for {
		if _, err := syncer.SyncOnce(ctx); err != nil && !errors.Is(err, context.Canceled) {
			syncer.logger.Warn("entitlement revocation synchronization deferred", "error", err)
		}
		if err := syncer.RefreshLease(ctx); err != nil && !errors.Is(err, context.Canceled) {
			syncer.logger.Warn("entitlement lease refresh deferred", "error", err)
		}
		if err := syncer.wait(ctx, revocationPollInterval); err != nil {
			return err
		}
	}
}

var _ RevocationFetcher = (*RevocationClient)(nil)
var _ RevocationStore = (*PostgresRevocationStore)(nil)
