package pluginruntimeprovider

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/pluginruntimeauth"
	"github.com/google/uuid"
)

const (
	runtimeAuthorizationPath   = "/installation/v1/plugin-runtime-authorizations:resolve"
	requestSchema              = "cdnca.plugin-runtime-authorization-request/v2"
	requestProofDomain         = "cdnca-plugin-runtime-authorization-request/v2"
	maximumBodyBytes           = 64 << 10
	maximumResponseHeaderBytes = 64 << 10
	maximumTimeout             = 30 * time.Second
	maximumCacheCapacity       = 4096
)

var (
	ErrInvalidConfiguration = errors.New("invalid plugin runtime provider configuration")
	ErrInvalidInput         = errors.New("invalid plugin runtime authorization input")
	ErrDenied               = errors.New("plugin runtime authorization denied")
	ErrRateLimited          = errors.New("plugin runtime authorization rate limited")
	ErrInvalid              = errors.New("plugin runtime authorization response invalid")
	ErrUnavailable          = errors.New("plugin runtime authorization unavailable")

	errRedirect = errors.New("plugin runtime authorization redirect rejected")

	hexDigestPattern  = regexp.MustCompile(`^[a-f0-9]{64}$`)
	permissionPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*){1,7}$`)
	eventPattern      = regexp.MustCompile(`^io\.cdnca\.[a-z][a-z0-9_]*\.v[1-9][0-9]*\.[a-z][a-z0-9_]*$`)
)

type Config struct {
	BaseURL                string
	TLSConfig              *tls.Config
	InstallationID         uuid.UUID
	InstallationPrivateKey ed25519.PrivateKey
	Verifier               pluginruntimeauth.Verifier
	Now                    func() time.Time
	Timeout                time.Duration
	MaxBodyBytes           int64
	CacheCapacity          int
	// DialContext opens the TCP (or mTLS tunnel, libs/mtlstunnel) connection the
	// inner TLS runs over; nil dials directly.
	DialContext func(ctx context.Context, network, address string) (net.Conn, error)
}

type Request struct {
	RequestID             string
	CustomerID            uuid.UUID
	InstallationID        uuid.UUID
	ServiceIdentityJSON   []byte
	ManifestSHA256        string
	VerificationID        uuid.UUID
	AttestationID         uuid.UUID
	AttestationRevision   uint64
	KnownApprovalRevision uint64
	CapabilityKind        string
	CapabilityCode        string
	Action                string
	RequestedAt           time.Time
}

type Facts struct {
	IdentityJSON []byte
	DecisionJSON []byte
}

type Provider struct {
	endpoint       string
	http           *http.Client
	installationID uuid.UUID
	privateKey     ed25519.PrivateKey
	verifier       pluginruntimeauth.Verifier
	now            func() time.Time
	bodyLimit      int64
	cache          *allowCache
}

type requestPayload struct {
	Schema                string          `json:"schema"`
	RequestID             string          `json:"request_id"`
	InstallationID        uuid.UUID       `json:"installation_id"`
	ServiceIdentity       json.RawMessage `json:"service_identity"`
	ManifestSHA256        string          `json:"manifest_sha256"`
	VerificationID        uuid.UUID       `json:"verification_id"`
	AttestationID         uuid.UUID       `json:"attestation_id"`
	AttestationRevision   uint64          `json:"attestation_revision"`
	KnownApprovalRevision uint64          `json:"known_approval_revision"`
	CapabilityKind        string          `json:"capability_kind"`
	CapabilityCode        string          `json:"capability_code"`
	Action                string          `json:"action"`
	RequestedAt           time.Time       `json:"requested_at"`
}

type requestBody struct {
	Schema                string          `json:"schema"`
	RequestID             string          `json:"request_id"`
	InstallationID        uuid.UUID       `json:"installation_id"`
	ServiceIdentity       json.RawMessage `json:"service_identity"`
	ManifestSHA256        string          `json:"manifest_sha256"`
	VerificationID        uuid.UUID       `json:"verification_id"`
	AttestationID         uuid.UUID       `json:"attestation_id"`
	AttestationRevision   uint64          `json:"attestation_revision"`
	KnownApprovalRevision uint64          `json:"known_approval_revision"`
	CapabilityKind        string          `json:"capability_kind"`
	CapabilityCode        string          `json:"capability_code"`
	Action                string          `json:"action"`
	RequestedAt           time.Time       `json:"requested_at"`
	Proof                 string          `json:"proof"`
}

type serviceIdentity struct {
	Schema             string    `json:"schema"`
	Algorithm          string    `json:"algorithm"`
	KeyID              string    `json:"key_id"`
	TokenID            uuid.UUID `json:"token_id"`
	AuthorizationID    uuid.UUID `json:"authorization_id"`
	InstallationID     uuid.UUID `json:"installation_id"`
	PluginID           string    `json:"plugin_id"`
	PluginVersion      string    `json:"plugin_version"`
	IdentityGeneration uint64    `json:"identity_generation"`
	Scopes             []string  `json:"scopes"`
	IssuedAt           time.Time `json:"issued_at"`
	ExpiresAt          time.Time `json:"expires_at"`
	Signature          string    `json:"signature"`
}

type preparedRequest struct {
	body     []byte
	cacheKey [sha256.Size]byte
	expected pluginruntimeauth.ExpectedAction
	request  Request
}

func New(config Config) (*Provider, error) {
	baseURL, err := url.Parse(config.BaseURL)
	if err != nil || config.BaseURL == "" || strings.TrimSpace(config.BaseURL) != config.BaseURL ||
		baseURL.Scheme != "https" || baseURL.Host == "" || baseURL.User != nil || baseURL.Path != "" ||
		baseURL.RawPath != "" || baseURL.RawQuery != "" || baseURL.ForceQuery || baseURL.Fragment != "" ||
		baseURL.RawFragment != "" || baseURL.Opaque != "" || baseURL.String() != config.BaseURL ||
		config.TLSConfig == nil || config.TLSConfig.InsecureSkipVerify ||
		config.TLSConfig.MinVersion != tls.VersionTLS13 ||
		config.TLSConfig.MaxVersion != 0 && config.TLSConfig.MaxVersion < tls.VersionTLS13 ||
		config.TLSConfig.RootCAs == nil || len(config.TLSConfig.Certificates) != 1 ||
		len(config.TLSConfig.Certificates[0].Certificate) == 0 || config.TLSConfig.Certificates[0].PrivateKey == nil ||
		config.InstallationID == uuid.Nil || len(config.InstallationPrivateKey) != ed25519.PrivateKeySize ||
		config.Verifier.Trust == nil || config.Now == nil || config.Now().IsZero() ||
		config.Timeout <= 0 || config.Timeout > maximumTimeout ||
		config.MaxBodyBytes <= 0 || config.MaxBodyBytes > maximumBodyBytes ||
		config.CacheCapacity <= 0 || config.CacheCapacity > maximumCacheCapacity {
		return nil, ErrInvalidConfiguration
	}
	tlsConfig := config.TLSConfig.Clone()
	tlsConfig.MinVersion = tls.VersionTLS13
	transport := &http.Transport{
		Proxy: nil, DialContext: config.DialContext, TLSClientConfig: tlsConfig, ForceAttemptHTTP2: true, DisableCompression: true,
		TLSHandshakeTimeout: config.Timeout, ResponseHeaderTimeout: config.Timeout,
		MaxIdleConns: 2, MaxIdleConnsPerHost: 2, IdleConnTimeout: config.Timeout,
		MaxResponseHeaderBytes: maximumResponseHeaderBytes,
	}
	client := &http.Client{Transport: transport, Timeout: config.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errRedirect }}
	verifier := config.Verifier
	verifier.Now = config.Now
	return &Provider{
		endpoint: config.BaseURL + runtimeAuthorizationPath, http: client,
		installationID: config.InstallationID,
		privateKey:     append(ed25519.PrivateKey(nil), config.InstallationPrivateKey...),
		verifier:       verifier, now: config.Now, bodyLimit: config.MaxBodyBytes,
		cache: newAllowCache(config.CacheCapacity),
	}, nil
}

func (provider *Provider) Resolve(ctx context.Context, request Request) (Facts, error) {
	if provider == nil || ctx == nil || provider.http == nil || provider.cache == nil ||
		provider.now == nil || provider.now().IsZero() {
		return Facts{}, ErrInvalidInput
	}
	prepared, err := provider.prepare(request)
	if err != nil {
		return Facts{}, err
	}
	facts, authorization, offlineEligible, err := provider.exchange(ctx, prepared)
	if err == nil {
		provider.cache.put(prepared.cacheKey, facts.DecisionJSON, authorization.ExpiresAt, provider.now())
		return cloneFacts(facts), nil
	}
	if !offlineEligible {
		provider.cache.remove(prepared.cacheKey)
		return Facts{}, err
	}
	if ctx.Err() != nil {
		return Facts{}, ErrUnavailable
	}
	cachedDecision, ok := provider.cache.get(prepared.cacheKey, provider.now())
	if !ok {
		return Facts{}, ErrUnavailable
	}
	cached := Facts{
		IdentityJSON: append([]byte(nil), prepared.request.ServiceIdentityJSON...),
		DecisionJSON: cachedDecision,
	}
	if _, verifyErr := provider.verify(cached, prepared); verifyErr != nil {
		clearFacts(&cached)
		provider.cache.remove(prepared.cacheKey)
		return Facts{}, ErrUnavailable
	}
	return cloneFacts(cached), nil
}

func (provider *Provider) prepare(request Request) (preparedRequest, error) {
	now := provider.now().UTC()
	if request.InstallationID == uuid.Nil || request.InstallationID != provider.installationID ||
		!validVisibleASCII(request.RequestID) || !hexDigestPattern.MatchString(request.ManifestSHA256) ||
		request.VerificationID == uuid.Nil || request.AttestationID == uuid.Nil || request.AttestationRevision == 0 ||
		request.KnownApprovalRevision == 0 || !validCapability(request.CapabilityKind, request.CapabilityCode) ||
		!validRuntimeAction(request.CapabilityKind, request.CapabilityCode, request.Action) ||
		request.RequestedAt.IsZero() || request.RequestedAt.Location() != time.UTC ||
		!request.RequestedAt.Equal(request.RequestedAt.Truncate(time.Second)) ||
		request.RequestedAt.Before(now.Add(-5*time.Minute)) || request.RequestedAt.After(now.Add(time.Minute)) {
		return preparedRequest{}, ErrInvalidInput
	}
	identity, ok := decodeCanonicalIdentity(request.ServiceIdentityJSON)
	if !ok || identity.InstallationID != request.InstallationID {
		return preparedRequest{}, ErrInvalidInput
	}
	payload := requestPayload{
		Schema: requestSchema, RequestID: request.RequestID, InstallationID: request.InstallationID,
		ServiceIdentity: append(json.RawMessage(nil), request.ServiceIdentityJSON...),
		ManifestSHA256:  request.ManifestSHA256, VerificationID: request.VerificationID,
		AttestationID: request.AttestationID, AttestationRevision: request.AttestationRevision,
		KnownApprovalRevision: request.KnownApprovalRevision, CapabilityKind: request.CapabilityKind,
		CapabilityCode: request.CapabilityCode, Action: request.Action, RequestedAt: request.RequestedAt,
	}
	unsigned, err := json.Marshal(payload)
	if err != nil || int64(len(unsigned)) > provider.bodyLimit {
		return preparedRequest{}, ErrInvalidInput
	}
	proof := ed25519.Sign(provider.privateKey, lengthPrefixed(requestProofDomain, unsigned))
	body, err := json.Marshal(requestBody{
		Schema: payload.Schema, RequestID: payload.RequestID, InstallationID: payload.InstallationID,
		ServiceIdentity: payload.ServiceIdentity, ManifestSHA256: payload.ManifestSHA256,
		VerificationID: payload.VerificationID, AttestationID: payload.AttestationID,
		AttestationRevision: payload.AttestationRevision, KnownApprovalRevision: payload.KnownApprovalRevision,
		CapabilityKind: payload.CapabilityKind, CapabilityCode: payload.CapabilityCode,
		Action: payload.Action, RequestedAt: payload.RequestedAt,
		Proof: base64.RawURLEncoding.EncodeToString(proof),
	})
	if err != nil || int64(len(body)) > provider.bodyLimit {
		return preparedRequest{}, ErrInvalidInput
	}
	return preparedRequest{
		body: body, cacheKey: sha256.Sum256(unsigned), request: request,
		expected: pluginruntimeauth.ExpectedAction{
			CustomerID: request.CustomerID, InstallationID: request.InstallationID, RequestID: request.RequestID,
			CapabilityKind: request.CapabilityKind, CapabilityCode: request.CapabilityCode, Action: request.Action,
		},
	}, nil
}

func (provider *Provider) exchange(ctx context.Context,
	prepared preparedRequest) (Facts, pluginruntimeauth.Authorization, bool, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, provider.endpoint, bytes.NewReader(prepared.body))
	if err != nil {
		return Facts{}, pluginruntimeauth.Authorization{}, false, ErrInvalidInput
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := provider.http.Do(request)
	if err != nil {
		if errors.Is(err, errRedirect) {
			return Facts{}, pluginruntimeauth.Authorization{}, false, ErrInvalid
		}
		return Facts{}, pluginruntimeauth.Authorization{}, true, ErrUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		switch {
		case response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= 500:
			return Facts{}, pluginruntimeauth.Authorization{}, true, ErrUnavailable
		case response.StatusCode == http.StatusForbidden || response.StatusCode == http.StatusNotFound ||
			response.StatusCode == http.StatusConflict:
			return Facts{}, pluginruntimeauth.Authorization{}, false, ErrDenied
		default:
			return Facts{}, pluginruntimeauth.Authorization{}, false, ErrInvalid
		}
	}
	contentTypes := response.Header.Values("Content-Type")
	if len(contentTypes) != 1 || contentTypes[0] != "application/json" || response.Header.Get("Content-Encoding") != "" {
		return Facts{}, pluginruntimeauth.Authorization{}, false, ErrInvalid
	}
	encoded, readErr := io.ReadAll(io.LimitReader(response.Body, provider.bodyLimit+2))
	if readErr != nil {
		return Facts{}, pluginruntimeauth.Authorization{}, true, ErrUnavailable
	}
	if len(encoded) < 2 || int64(len(encoded)) > provider.bodyLimit+1 || encoded[len(encoded)-1] != '\n' {
		return Facts{}, pluginruntimeauth.Authorization{}, false, ErrInvalid
	}
	decision := append([]byte(nil), encoded[:len(encoded)-1]...)
	facts := Facts{IdentityJSON: append([]byte(nil), prepared.request.ServiceIdentityJSON...), DecisionJSON: decision}
	authorization, verifyErr := provider.verify(facts, prepared)
	if verifyErr != nil {
		clearFacts(&facts)
		return Facts{}, pluginruntimeauth.Authorization{}, false, verifyErr
	}
	return facts, authorization, false, nil
}

func (provider *Provider) verify(facts Facts,
	prepared preparedRequest) (pluginruntimeauth.Authorization, error) {
	authorization, err := provider.verifier.Authorize(facts.IdentityJSON, facts.DecisionJSON, prepared.expected)
	if err != nil {
		switch {
		case errors.Is(err, pluginruntimeauth.ErrDenied):
			return pluginruntimeauth.Authorization{}, ErrDenied
		case errors.Is(err, pluginruntimeauth.ErrRateLimited):
			return pluginruntimeauth.Authorization{}, ErrRateLimited
		case errors.Is(err, pluginruntimeauth.ErrTrustUnavailable):
			return pluginruntimeauth.Authorization{}, ErrUnavailable
		default:
			return pluginruntimeauth.Authorization{}, ErrInvalid
		}
	}
	request := prepared.request
	if authorization.ManifestSHA256 != request.ManifestSHA256 || authorization.VerificationID != request.VerificationID ||
		authorization.AttestationID != request.AttestationID ||
		authorization.AttestationRevision != request.AttestationRevision ||
		authorization.ApprovalRevision != request.KnownApprovalRevision ||
		authorization.ExpiresAt.After(authorization.EvaluatedAt.Add(time.Minute)) ||
		!provider.now().Before(authorization.ExpiresAt) {
		return pluginruntimeauth.Authorization{}, ErrInvalid
	}
	return authorization, nil
}

func validRuntimeAction(kind, code, action string) bool {
	if !permissionPattern.MatchString(action) {
		return false
	}
	switch kind {
	case "scope":
		return action == code
	case "event":
		return action == "plugin.event.consume"
	case "webhook":
		return action == "plugin.webhook.deliver"
	default:
		return false
	}
}

func decodeCanonicalIdentity(encoded []byte) (serviceIdentity, bool) {
	if len(encoded) == 0 || len(encoded) > maximumBodyBytes {
		return serviceIdentity{}, false
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var identity serviceIdentity
	if decoder.Decode(&identity) != nil {
		return serviceIdentity{}, false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return serviceIdentity{}, false
	}
	canonical, err := json.Marshal(identity)
	return identity, err == nil && bytes.Equal(canonical, encoded)
}

func validVisibleASCII(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for index := range value {
		if value[index] < 0x21 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func validCapability(kind, code string) bool {
	switch kind {
	case "scope", "webhook":
		return permissionPattern.MatchString(code)
	case "event":
		return eventPattern.MatchString(code)
	default:
		return false
	}
}

func lengthPrefixed(domain string, payload []byte) []byte {
	result := make([]byte, 0, len(domain)+len(payload)+8)
	for _, field := range [][]byte{[]byte(domain), payload} {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(field)))
		result = append(result, size[:]...)
		result = append(result, field...)
	}
	return result
}

type allowCache struct {
	mu       sync.Mutex
	capacity int
	entries  map[[sha256.Size]byte]cacheEntry
}

type cacheEntry struct {
	decision  []byte
	expiresAt time.Time
}

func newAllowCache(capacity int) *allowCache {
	return &allowCache{capacity: capacity, entries: make(map[[sha256.Size]byte]cacheEntry, capacity)}
}

func (cache *allowCache) put(key [sha256.Size]byte, decision []byte, expiresAt, now time.Time) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	cache.purgeExpired(now)
	if previous, found := cache.entries[key]; found {
		clear(previous.decision)
		delete(cache.entries, key)
	}
	if len(cache.entries) >= cache.capacity {
		var earliestKey [sha256.Size]byte
		var earliest time.Time
		for candidateKey, candidate := range cache.entries {
			if earliest.IsZero() || candidate.expiresAt.Before(earliest) {
				earliestKey, earliest = candidateKey, candidate.expiresAt
			}
		}
		earliestEntry := cache.entries[earliestKey]
		clear(earliestEntry.decision)
		delete(cache.entries, earliestKey)
	}
	cache.entries[key] = cacheEntry{decision: append([]byte(nil), decision...), expiresAt: expiresAt}
}

func (cache *allowCache) get(key [sha256.Size]byte, now time.Time) ([]byte, bool) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	cache.purgeExpired(now)
	entry, found := cache.entries[key]
	if !found {
		return nil, false
	}
	return append([]byte(nil), entry.decision...), true
}

func (cache *allowCache) remove(key [sha256.Size]byte) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if entry, found := cache.entries[key]; found {
		clear(entry.decision)
		delete(cache.entries, key)
	}
}

func (cache *allowCache) purgeExpired(now time.Time) {
	for key, entry := range cache.entries {
		if !now.Before(entry.expiresAt) {
			clear(entry.decision)
			delete(cache.entries, key)
		}
	}
}

func cloneFacts(facts Facts) Facts {
	return Facts{IdentityJSON: append([]byte(nil), facts.IdentityJSON...),
		DecisionJSON: append([]byte(nil), facts.DecisionJSON...)}
}

func clearFacts(facts *Facts) {
	clear(facts.IdentityJSON)
	clear(facts.DecisionJSON)
}
