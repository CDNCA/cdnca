package challenge

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/netip"
	"sync"
	"time"
)

const (
	MaxExternalProofBytes = 4096
	MaxReplayKeyBytes     = 256
	maxExternalRateScopes = 10000
)

var ErrExternalVerification = errors.New("external challenge verification failed")

type ExternalProvider string

const (
	ProviderTencent   ExternalProvider = "tencent"
	ProviderGeetestV4 ExternalProvider = "geetest-v4"
)

type ExternalRequest struct {
	Provider ExternalProvider
	AppID    string
	Proof    string
	ClientIP string
	SiteID   string
}

type ExternalResult struct {
	Valid     bool
	AppID     string
	ReplayKey string
}

type ExternalVerifier interface {
	Verify(context.Context, ExternalRequest) (ExternalResult, error)
}

type ExternalReplayStore interface {
	Consume(scope, key string, now, expiresAt time.Time) bool
}

type ExternalVerificationService struct {
	verifier ExternalVerifier
	replays  ExternalReplayStore
	limit    int
	window   time.Duration
	now      func() time.Time
	mu       sync.Mutex
	usage    map[string]externalUsage
}

type externalUsage struct {
	started time.Time
	count   int
}

func NewExternalVerificationService(verifier ExternalVerifier, replays ExternalReplayStore, limit int,
	window time.Duration, now func() time.Time) (*ExternalVerificationService, error) {
	if verifier == nil || replays == nil || limit < 1 || window < time.Second || now == nil {
		return nil, ErrExternalVerification
	}
	return &ExternalVerificationService{verifier: verifier, replays: replays, limit: limit,
		window: window, now: now, usage: make(map[string]externalUsage)}, nil
}

func (service *ExternalVerificationService) Verify(ctx context.Context, request ExternalRequest) (ExternalResult, error) {
	return service.verifyWith(ctx, request, service.verifier)
}

func (service *ExternalVerificationService) verifyWith(ctx context.Context, request ExternalRequest,
	verifier ExternalVerifier) (ExternalResult, error) {
	if service == nil || !service.allow(request.SiteID) {
		return ExternalResult{}, ErrExternalVerification
	}
	result, err := VerifyExternal(ctx, request, verifier)
	if err != nil {
		return ExternalResult{}, err
	}
	now := service.now().UTC()
	if now.IsZero() || !service.replays.Consume(string(request.Provider)+"\x00"+request.AppID,
		result.ReplayKey, now, now.Add(service.window)) {
		return ExternalResult{}, ErrExternalVerification
	}
	return result, nil
}

func (service *ExternalVerificationService) allow(siteID string) bool {
	if service == nil || validateIdentifier(siteID, MaxIdentifierBytes) != nil {
		return false
	}
	now := service.now().UTC()
	if now.IsZero() {
		return false
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	for scope, candidate := range service.usage {
		if !now.Before(candidate.started.Add(service.window)) {
			delete(service.usage, scope)
		}
	}
	usage := service.usage[siteID]
	if usage.started.IsZero() || !now.Before(usage.started.Add(service.window)) {
		usage = externalUsage{started: now}
	}
	if usage.count >= service.limit {
		return false
	}
	if _, exists := service.usage[siteID]; !exists && len(service.usage) >= maxExternalRateScopes {
		return false
	}
	usage.count++
	service.usage[siteID] = usage
	return true
}

type MemoryExternalReplayStore struct {
	mu       sync.Mutex
	capacity int
	entries  map[string]time.Time
}

func NewMemoryExternalReplayStore(capacity int) *MemoryExternalReplayStore {
	return &MemoryExternalReplayStore{capacity: capacity, entries: make(map[string]time.Time)}
}

func (store *MemoryExternalReplayStore) Consume(scope, key string, now, expiresAt time.Time) bool {
	if store == nil || store.capacity < 1 || scope == "" || !boundedExternalValue(key, MaxReplayKeyBytes) ||
		now.IsZero() || !expiresAt.After(now) {
		return false
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	for identity, expiry := range store.entries {
		if !expiry.After(now) {
			delete(store.entries, identity)
		}
	}
	identity := scope + "\x00" + key
	if _, exists := store.entries[identity]; exists || len(store.entries) >= store.capacity {
		return false
	}
	store.entries[identity] = expiresAt
	return true
}

func VerifyExternal(ctx context.Context, request ExternalRequest, verifier ExternalVerifier) (ExternalResult, error) {
	if ctx == nil || verifier == nil || (request.Provider != ProviderTencent && request.Provider != ProviderGeetestV4) ||
		validateIdentifier(request.AppID, MaxIdentifierBytes) != nil ||
		validateIdentifier(request.SiteID, MaxIdentifierBytes) != nil ||
		!boundedExternalValue(request.Proof, MaxExternalProofBytes) {
		return ExternalResult{}, ErrExternalVerification
	}
	address, err := netip.ParseAddr(request.ClientIP)
	if err != nil || address.Zone() != "" {
		return ExternalResult{}, ErrExternalVerification
	}
	if err := ctx.Err(); err != nil {
		return ExternalResult{}, ErrExternalVerification
	}
	result, err := verifier.Verify(ctx, request)
	if err != nil || ctx.Err() != nil || !result.Valid || !boundedExternalValue(result.ReplayKey, MaxReplayKeyBytes) ||
		len(result.AppID) != len(request.AppID) || subtle.ConstantTimeCompare([]byte(result.AppID), []byte(request.AppID)) != 1 {
		return ExternalResult{}, ErrExternalVerification
	}
	return result, nil
}

func boundedExternalValue(value string, maximum int) bool {
	return len(value) > 0 && len(value) <= maximum && isASCII(value) && !hasControl(value)
}
