package dnsacme

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscustomhttp"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
	"github.com/google/uuid"
	"golang.org/x/net/publicsuffix"
)

const providerCursorVersion = 1
const maxProviderListPages = 100

var strictProviderCursorEncoding = base64.RawURLEncoding.Strict()

type providerCursorPayload struct {
	Version   int       `json:"v"`
	Kind      string    `json:"kind"`
	ScopeKind string    `json:"scope_kind"`
	ScopeID   uuid.UUID `json:"scope_id"`
	Limit     int       `json:"limit"`
	CreatedAt time.Time `json:"created_at"`
	ID        uuid.UUID `json:"id"`
}

var (
	hostLabelPattern   = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	recordLabelPattern = regexp.MustCompile(`^(?:\*|[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)$`)
	secretFieldPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
)

type Service struct {
	store    *Store
	cipher   CredentialCipher
	verifier ProviderVerifier
	apex     dnsproviderremote.ZoneApexResolver
}

// UseZoneApexResolver sets how a saved CNAME zone finds the domain its DNS
// account hosts (migration 473). Without one the zone is stored without an
// apex and the first provider call looks it up.
func (s *Service) UseZoneApexResolver(resolver dnsproviderremote.ZoneApexResolver) { s.apex = resolver }

// zoneApex returns the longest domain of the account equal to name or a
// parent of it. "" (no error): no resolver, or a provider type without a
// domain list API (dnsdun), left for the first use.
func (s *Service) zoneApex(ctx context.Context, providerType string, credentials map[string]string, name string) (string, error) {
	if s.apex == nil || credentials == nil {
		return "", nil
	}
	apex, err := s.apex.ResolveZoneApex(ctx, providerType, credentials, name)
	switch dnsproviderremote.ErrorCodeOf(err) {
	case "":
		if err != nil {
			return "", ErrProviderVerificationUnavailable
		}
		return apex, nil
	case dnsproviderremote.CodeZoneNotHosted:
		return "", ErrZoneNotHosted
	case dnsproviderremote.CodeUnsupported:
		return "", nil
	case dnsproviderremote.CodeCredentialsRejected:
		return "", ErrProviderCredentialsRejected
	case dnsproviderremote.CodeInvalidInput:
		return "", ErrProviderCredentialsInvalid
	default:
		return "", ErrProviderVerificationUnavailable
	}
}

func NewService(store *Store, cipher CredentialCipher) *Service {
	return NewServiceWithClockAndVerifier(store, cipher, nil, time.Now)
}

func NewServiceWithClock(store *Store, cipher CredentialCipher, now func() time.Time) *Service {
	return NewServiceWithClockAndVerifier(store, cipher, nil, now)
}

func NewServiceWithClockAndVerifier(store *Store, cipher CredentialCipher, verifier ProviderVerifier, _ func() time.Time) *Service {
	return &Service{store: store, cipher: cipher, verifier: verifier}
}

func (s *Service) CreateProvider(ctx context.Context, actor Actor, request CreateProviderRequest) (Provider, error) {
	if err := normalizeTarget(actor, &request.TargetScopeID); err != nil {
		return Provider{}, err
	}
	request.Name = strings.TrimSpace(request.Name)
	request.Remark = strings.TrimSpace(request.Remark)
	request.ProviderType = strings.ToLower(strings.TrimSpace(request.ProviderType))
	if !validMetadata(request.IdempotencyKey, request.RequestID) {
		return Provider{}, ErrInvalidInput
	}
	if err := nameRemarkField(request.Name, &request.Remark); err != nil {
		return Provider{}, err
	}
	if !supportedProvider(request.ProviderType) {
		return Provider{}, invalidField("provider_type", fielderr.Invalid)
	}
	credentialJSON, err := normalizeProviderCredentials(request.ProviderType, request.Credentials)
	if err != nil {
		return Provider{}, invalidField("credentials", fielderr.Invalid)
	}
	defer clear(credentialJSON)
	if s.store == nil {
		return Provider{}, ErrCredentialUnavailable
	}
	binding, err := s.store.prepareProviderCredentialCreate(ctx, actor, request.TargetScopeID)
	if err != nil {
		return Provider{}, err
	}
	boundCipher, ok := s.cipher.(BoundCredentialCipher)
	if !ok {
		return Provider{}, ErrCredentialUnavailable
	}
	keyID, ciphertext, err := boundCipher.EncryptCredential(binding, credentialJSON)
	if err != nil {
		return Provider{}, ErrCredentialUnavailable
	}
	defer clear(ciphertext)
	credentialDigest := s.cipher.IdempotencyDigest(credentialJSON)
	digest, err := digestRequest(struct {
		ScopeID          uuid.UUID `json:"scope_id"`
		Name             string    `json:"name"`
		Remark           string    `json:"remark,omitempty"`
		ProviderType     string    `json:"provider_type"`
		CredentialDigest [32]byte  `json:"credential_digest"`
	}{request.TargetScopeID, request.Name, request.Remark, request.ProviderType, credentialDigest})
	if err != nil {
		return Provider{}, err
	}
	return s.store.CreateProvider(ctx, actor, request, binding, keyID, ciphertext, digest)
}

func (s *Service) UpdateProvider(ctx context.Context, actor Actor, request UpdateProviderRequest) (Provider, error) {
	request.Name = strings.TrimSpace(request.Name)
	request.Status = strings.ToLower(strings.TrimSpace(request.Status))
	if request.Remark != nil {
		remark := strings.TrimSpace(*request.Remark)
		request.Remark = &remark
	}
	if !validActor(actor) || request.ID == uuid.Nil || !validMetadata(request.IdempotencyKey, request.RequestID) {
		return Provider{}, ErrInvalidInput
	}
	if request.ExpectedRevision < 1 {
		return Provider{}, invalidField("expected_version", fielderr.Required)
	}
	if err := nameRemarkField(request.Name, request.Remark); err != nil {
		return Provider{}, err
	}
	if request.Status != ProviderStatusUnverified && request.Status != ProviderStatusDisabled {
		return Provider{}, invalidField("status", fielderr.Invalid)
	}
	if request.Credentials != nil && !matchesSupportedProviderCredentialSchema(request.Credentials) {
		return Provider{}, invalidField("credentials", fielderr.Invalid)
	}
	if s.store == nil {
		return Provider{}, ErrCredentialUnavailable
	}
	target, err := s.store.providerForUpdate(ctx, actor, request.ID)
	if err != nil {
		return Provider{}, err
	}
	// The platform DNS copy is kept by the platform sync (节点管理 > DNS配置).
	if IsPlatformManagedProvider(target.ManagedBy, target.ScopeID, target.ID) {
		return Provider{}, ErrPlatformManagedProvider
	}
	if target.ProviderType == "dnsdun" &&
		(request.Status != ProviderStatusDisabled || request.Credentials != nil) {
		return Provider{}, ErrProviderVerificationUnsupported
	}
	var keyID string
	var ciphertext []byte
	var credentialDigest *[32]byte
	if request.Credentials != nil {
		credentialJSON, err := normalizeProviderCredentials(target.ProviderType, request.Credentials)
		if err != nil {
			return Provider{}, err
		}
		defer clear(credentialJSON)
		boundCipher, ok := s.cipher.(BoundCredentialCipher)
		if !ok {
			return Provider{}, ErrCredentialUnavailable
		}
		keyID, ciphertext, err = boundCipher.EncryptCredential(target.binding(), credentialJSON)
		if err != nil {
			return Provider{}, ErrCredentialUnavailable
		}
		defer clear(ciphertext)
		value := s.cipher.IdempotencyDigest(credentialJSON)
		credentialDigest = &value
	}
	digest, err := digestRequest(struct {
		ID               uuid.UUID `json:"id"`
		ExpectedRevision int64     `json:"expected_revision"`
		Name             string    `json:"name"`
		Status           string    `json:"status"`
		Remark           *string   `json:"remark,omitempty"`
		CredentialDigest *[32]byte `json:"credential_digest"`
	}{request.ID, request.ExpectedRevision, request.Name, request.Status, request.Remark, credentialDigest})
	if err != nil {
		return Provider{}, err
	}
	return s.store.UpdateProvider(ctx, actor, request, target.binding(), keyID, ciphertext, digest)
}

func (s *Service) ListProviders(ctx context.Context, actor Actor) ([]Provider, error) {
	if !validActor(actor) || s.store == nil {
		return nil, ErrInvalidInput
	}
	items := make([]Provider, 0)
	seen := make(map[uuid.UUID]struct{})
	var after *providerPageCursor
	for page := 0; page < maxProviderListPages; page++ {
		batch, err := s.store.ListProviders(ctx, actor, MaxProviderPageLimit+1, after)
		if err != nil {
			return nil, err
		}
		hasMore := len(batch) > MaxProviderPageLimit
		if hasMore {
			batch = batch[:MaxProviderPageLimit]
		}
		for _, item := range batch {
			if item.ID == uuid.Nil || actor.ScopeKind == "tenant" && item.ScopeID != actor.ScopeID {
				return nil, ErrInvalidInput
			}
			if _, duplicate := seen[item.ID]; duplicate {
				return nil, ErrInvalidInput
			}
			seen[item.ID] = struct{}{}
			items = append(items, item)
		}
		if !hasMore {
			return items, nil
		}
		last := batch[len(batch)-1]
		after = &providerPageCursor{CreatedAt: last.CreatedAt, ID: last.ID}
	}
	return nil, ErrInvalidInput
}

func (s *Service) ListProviderPage(ctx context.Context, actor Actor, request ProviderPageRequest) (ProviderPage, error) {
	if !validActor(actor) || validateProviderPageRequest(request) != nil || s.store == nil {
		return ProviderPage{}, ErrInvalidInput
	}
	if request.Limit == 0 {
		request.Limit = DefaultProviderPageLimit
	}
	var after *providerPageCursor
	if request.Cursor != "" {
		var err error
		after, err = s.decodeProviderCursor(actor, request)
		if err != nil {
			return ProviderPage{}, err
		}
	}
	items, err := s.store.ListProviders(ctx, actor, request.Limit+1, after)
	if err != nil {
		return ProviderPage{}, err
	}
	page := ProviderPage{Items: items}
	if len(page.Items) > request.Limit {
		page.Items = page.Items[:request.Limit]
		page.NextCursor, err = s.encodeProviderCursor(actor, request.Limit, page.Items[len(page.Items)-1])
		if err != nil {
			return ProviderPage{}, err
		}
	}
	return page, nil
}

func validateProviderPageRequest(request ProviderPageRequest) error {
	if request.Limit < 0 || request.Limit > MaxProviderPageLimit ||
		len(request.Cursor) > MaxProviderCursorLength || strings.ContainsAny(request.Cursor, "\x00\r\n") {
		return ErrInvalidInput
	}
	return nil
}

func (s *Service) encodeProviderCursor(actor Actor, limit int, last Provider) (string, error) {
	if s.cipher == nil || !validActor(actor) || limit < 1 || limit > MaxProviderPageLimit ||
		last.ID == uuid.Nil || last.CreatedAt.IsZero() {
		return "", ErrInvalidInput
	}
	payload, err := json.Marshal(providerCursorPayload{
		Version: providerCursorVersion, Kind: "dns-providers", ScopeKind: actor.ScopeKind,
		ScopeID: actor.ScopeID, Limit: limit, CreatedAt: last.CreatedAt.UTC().Truncate(time.Microsecond), ID: last.ID,
	})
	if err != nil {
		return "", ErrInvalidInput
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	signature := s.providerCursorDigest(encoded)
	result := encoded + "." + base64.RawURLEncoding.EncodeToString(signature[:])
	if len(result) > MaxProviderCursorLength {
		return "", ErrInvalidInput
	}
	return result, nil
}

func (s *Service) decodeProviderCursor(actor Actor, request ProviderPageRequest) (*providerPageCursor, error) {
	if s.cipher == nil || !validActor(actor) || validateProviderPageRequest(request) != nil ||
		request.Limit < 1 || request.Cursor == "" {
		return nil, ErrInvalidInput
	}
	payloadPart, signaturePart, ok := strings.Cut(request.Cursor, ".")
	if !ok || payloadPart == "" || signaturePart == "" || strings.Contains(signaturePart, ".") {
		return nil, ErrInvalidInput
	}
	signature, err := strictProviderCursorEncoding.DecodeString(signaturePart)
	expected := s.providerCursorDigest(payloadPart)
	if err != nil || !hmac.Equal(signature, expected[:]) ||
		base64.RawURLEncoding.EncodeToString(signature) != signaturePart {
		return nil, ErrInvalidInput
	}
	payload, err := strictProviderCursorEncoding.DecodeString(payloadPart)
	if err != nil || len(payload) > 2048 || base64.RawURLEncoding.EncodeToString(payload) != payloadPart {
		return nil, ErrInvalidInput
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var decoded providerCursorPayload
	if decoder.Decode(&decoded) != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		decoded.Version != providerCursorVersion || decoded.Kind != "dns-providers" ||
		decoded.ScopeKind != actor.ScopeKind || decoded.ScopeID != actor.ScopeID || decoded.Limit != request.Limit ||
		decoded.ID == uuid.Nil || decoded.CreatedAt.IsZero() || decoded.CreatedAt.Location() != time.UTC ||
		!decoded.CreatedAt.Equal(decoded.CreatedAt.UTC().Truncate(time.Microsecond)) {
		return nil, ErrInvalidInput
	}
	return &providerPageCursor{CreatedAt: decoded.CreatedAt, ID: decoded.ID}, nil
}

func (s *Service) providerCursorDigest(payload string) [32]byte {
	return s.cipher.IdempotencyDigest([]byte("cdnca-dns-provider-cursor/v1\x00" + payload))
}

func (s *Service) VerifyProvider(ctx context.Context, actor Actor, request VerifyProviderRequest) (Provider, error) {
	if !validActor(actor) || request.ID == uuid.Nil || request.ExpectedRevision < 1 ||
		!validMetadata(request.IdempotencyKey, request.RequestID) {
		return Provider{}, ErrInvalidInput
	}
	digest, err := digestRequest(struct {
		ID       uuid.UUID `json:"id"`
		Revision int64     `json:"revision"`
	}{request.ID, request.ExpectedRevision})
	if err != nil {
		return Provider{}, err
	}
	target, replay, err := s.store.PrepareProviderVerification(ctx, actor, request, digest)
	if err != nil {
		return Provider{}, err
	}
	if replay != nil {
		return replay.result()
	}

	if target.Provider.ProviderType == "dnsdun" {
		return s.store.CompleteProviderVerification(ctx, actor, request, digest, ErrProviderVerificationUnsupported)
	}
	if target.Provider.Status == ProviderStatusDisabled {
		return s.store.CompleteProviderVerification(ctx, actor, request, digest, ErrProviderDisabled)
	}
	if s.verifier == nil {
		return Provider{}, ErrProviderVerificationUnavailable
	}
	boundCipher, ok := s.cipher.(BoundCredentialCipher)
	if !ok {
		return Provider{}, ErrCredentialUnavailable
	}
	plaintext, decryptErr := boundCipher.DecryptCredential(CredentialBinding{
		TenantID: target.TenantID, ScopeID: target.ScopeID, ProviderID: target.ID,
	}, target.CredentialKeyID, target.CredentialCiphertext)
	if decryptErr != nil {
		return Provider{}, ErrCredentialUnavailable
	}
	defer clear(plaintext)
	credentials, parseErr := parseProviderCredentials(plaintext)
	var verificationErr error
	if parseErr != nil {
		verificationErr = ErrProviderCredentialsInvalid
	} else if verifier, ok := s.verifier.(CredentialProviderVerifier); ok {
		verificationErr = verifier.VerifyCredentials(ctx, target.Provider.ProviderType, credentials)
	} else if target.Provider.ProviderType != "cloudflare" {
		verificationErr = ErrProviderVerificationUnsupported
	} else {
		apiToken, credentialErr := exactCredential(credentials, "api_token")
		if credentialErr != nil {
			verificationErr = credentialErr
		} else {
			verificationErr = s.verifier.Verify(ctx, target.Provider.ProviderType, apiToken)
		}
	}
	if verificationErr != nil && !deterministicVerificationError(verificationErr) {
		return Provider{}, verificationErr
	}
	return s.store.CompleteProviderVerification(ctx, actor, request, digest, verificationErr)
}

func deterministicVerificationError(err error) bool {
	return errors.Is(err, ErrProviderVerificationUnsupported) ||
		errors.Is(err, ErrProviderDisabled) ||
		errors.Is(err, ErrProviderCredentialsInvalid) ||
		errors.Is(err, ErrProviderTokenInactive) ||
		errors.Is(err, ErrProviderCredentialsRejected)
}

func (s *Service) DeleteProvider(ctx context.Context, actor Actor, request DeleteRequest) error {
	if err := validateDelete(actor, request); err != nil {
		return err
	}
	if target, err := s.store.providerForUpdate(ctx, actor, request.ID); err == nil &&
		IsPlatformManagedProvider(target.ManagedBy, target.ScopeID, target.ID) {
		return ErrPlatformManagedProvider
	} else if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	digest, _ := digestRequest(struct {
		ID       uuid.UUID `json:"id"`
		Revision int64     `json:"revision"`
	}{request.ID, request.ExpectedRevision})
	return s.store.DeleteProvider(ctx, actor, request, digest)
}

func (s *Service) CreateZone(ctx context.Context, actor Actor, request CreateZoneRequest) (Zone, error) {
	if err := normalizeTarget(actor, &request.TargetScopeID); err != nil {
		return Zone{}, err
	}
	if !validMetadata(request.IdempotencyKey, request.RequestID) {
		return Zone{}, ErrInvalidInput
	}
	if request.ProviderID == uuid.Nil {
		return Zone{}, invalidField("provider_id", fielderr.Required)
	}
	name, err := normalizeHostname(request.Name, false)
	if err != nil {
		return Zone{}, hostnameField("name", request.Name)
	}
	request.Name = name
	// Before the hosted-domain lookup: that already uses the credentials.
	if err := refusePlatformManagedUse(ctx, s.store.pool, actor, request.TargetScopeID, request.ProviderID); err != nil {
		return Zone{}, err
	}
	if s.apex != nil {
		providerType, credentials, err := s.store.zoneProviderCredentials(ctx, s.cipher, request.TargetScopeID, request.ProviderID)
		if err != nil {
			return Zone{}, err
		}
		request.ProviderZoneApex, err = s.zoneApex(ctx, providerType, credentials, request.Name)
		clear(credentials)
		if err != nil {
			return Zone{}, err
		}
	}
	digest, _ := digestRequest(struct {
		ScopeID    uuid.UUID `json:"scope_id"`
		ProviderID uuid.UUID `json:"provider_id"`
		Name       string    `json:"name"`
	}{request.TargetScopeID, request.ProviderID, request.Name})
	return s.store.CreateZone(ctx, actor, request, digest)
}

func (s *Service) ListZones(ctx context.Context, actor Actor) ([]Zone, error) {
	if !validActor(actor) {
		return nil, ErrInvalidInput
	}
	return s.store.ListZones(ctx, actor)
}

func (s *Service) DeleteZone(ctx context.Context, actor Actor, request DeleteRequest) error {
	if err := validateDelete(actor, request); err != nil {
		return err
	}
	digest, _ := digestRequest(struct {
		ID       uuid.UUID `json:"id"`
		Revision int64     `json:"revision"`
	}{request.ID, request.ExpectedRevision})
	return s.store.DeleteZone(ctx, actor, request, digest)
}

func (s *Service) CreateRecord(ctx context.Context, actor Actor, request CreateRecordRequest) (Record, error) {
	if err := normalizeTarget(actor, &request.TargetScopeID); err != nil {
		return Record{}, err
	}
	if !validMetadata(request.IdempotencyKey, request.RequestID) {
		return Record{}, ErrInvalidInput
	}
	if request.ZoneID == uuid.Nil {
		return Record{}, invalidField("zone_id", fielderr.Required)
	}
	if err := normalizeRecord(&request.Name, &request.Type, &request.Content, request.TTL); err != nil {
		return Record{}, err
	}
	digest, _ := digestRequest(struct {
		ScopeID uuid.UUID `json:"scope_id"`
		ZoneID  uuid.UUID `json:"zone_id"`
		Name    string    `json:"name"`
		Type    string    `json:"type"`
		Content string    `json:"content"`
		TTL     int       `json:"ttl"`
	}{request.TargetScopeID, request.ZoneID, request.Name, request.Type, request.Content, request.TTL})
	return s.store.CreateRecord(ctx, actor, request, digest)
}

func (s *Service) UpdateRecord(ctx context.Context, actor Actor, request UpdateRecordRequest) (Record, error) {
	if !validActor(actor) || request.ID == uuid.Nil || request.ExpectedRevision < 1 ||
		!validMetadata(request.IdempotencyKey, request.RequestID) {
		return Record{}, ErrInvalidInput
	}
	if err := normalizeRecord(&request.Name, &request.Type, &request.Content, request.TTL); err != nil {
		return Record{}, err
	}
	digest, _ := digestRequest(struct {
		ID       uuid.UUID `json:"id"`
		Revision int64     `json:"revision"`
		Name     string    `json:"name"`
		Type     string    `json:"type"`
		Content  string    `json:"content"`
		TTL      int       `json:"ttl"`
	}{request.ID, request.ExpectedRevision, request.Name, request.Type, request.Content, request.TTL})
	return s.store.UpdateRecord(ctx, actor, request, digest)
}

func (s *Service) ListRecords(ctx context.Context, actor Actor, zoneID uuid.UUID) ([]Record, error) {
	if !validActor(actor) || zoneID == uuid.Nil {
		return nil, ErrInvalidInput
	}
	return s.store.ListRecords(ctx, actor, zoneID)
}

func (s *Service) DeleteRecord(ctx context.Context, actor Actor, request DeleteRequest) error {
	if err := validateDelete(actor, request); err != nil {
		return err
	}
	digest, _ := digestRequest(struct {
		ID       uuid.UUID `json:"id"`
		Revision int64     `json:"revision"`
	}{request.ID, request.ExpectedRevision})
	return s.store.DeleteRecord(ctx, actor, request, digest)
}

func (s *Service) CreateOrder(ctx context.Context, actor Actor, request CreateOrderRequest) (CertificateOrder, error) {
	if err := normalizeTarget(actor, &request.TargetScopeID); err != nil {
		return CertificateOrder{}, err
	}
	request.ChallengeType = strings.ToLower(strings.TrimSpace(request.ChallengeType))
	if !validMetadata(request.IdempotencyKey, request.RequestID) {
		return CertificateOrder{}, ErrInvalidInput
	}
	if request.ChallengeType != "http-01" && request.ChallengeType != "dns-01" {
		return CertificateOrder{}, invalidField("challenge_type", fielderr.Invalid)
	}
	domains, hasWildcard, err := normalizeDomains(request.Domains)
	switch {
	case err != nil:
		return CertificateOrder{}, err
	case request.ChallengeType == "dns-01" && request.DNSProviderID == nil:
		return CertificateOrder{}, invalidField("dns_provider_id", fielderr.Required)
	case request.ChallengeType == "http-01" && request.DNSProviderID != nil:
		return CertificateOrder{}, invalidField("dns_provider_id", fielderr.Invalid)
	case hasWildcard && request.ChallengeType != "dns-01":
		// A wildcard needs DNS validation: the page points at the challenge choice.
		return CertificateOrder{}, invalidField("challenge_type", fielderr.Invalid)
	}
	request.Domains = domains
	request.Name, request.Remark = strings.TrimSpace(request.Name), strings.TrimSpace(request.Remark)
	switch {
	case request.Issuer != "" && !slices.Contains(CertificateIssuers, request.Issuer):
		return CertificateOrder{}, invalidField("issuer", fielderr.Invalid)
	case len(request.Name) > 128:
		return CertificateOrder{}, invalidField("name", fielderr.TooLong)
	case !validRemark(request.Name):
		return CertificateOrder{}, remarkField("name", request.Name)
	case !validRemark(request.Remark):
		return CertificateOrder{}, remarkField("remark", request.Remark)
	}
	digest, _ := digestRequest(struct {
		ScopeID       uuid.UUID  `json:"scope_id"`
		DNSProviderID *uuid.UUID `json:"dns_provider_id"`
		Domains       []string   `json:"domains"`
		ChallengeType string     `json:"challenge_type"`
		AutoRenew     bool       `json:"auto_renew"`
		Issuer        string     `json:"issuer,omitempty"`
		Name          string     `json:"name,omitempty"`
		Remark        string     `json:"remark,omitempty"`
	}{request.TargetScopeID, request.DNSProviderID, request.Domains, request.ChallengeType, request.AutoRenew,
		request.Issuer, request.Name, request.Remark})
	return s.store.CreateOrder(ctx, actor, request, nil, digest)
}

func (s *Service) ListOrders(ctx context.Context, actor Actor) ([]CertificateOrder, error) {
	if !validActor(actor) {
		return nil, ErrInvalidInput
	}
	return s.store.ListOrders(ctx, actor)
}

// TransitionOrder is retained only to fail closed for legacy direct callers.
func (s *Service) TransitionOrder(context.Context, Actor, TransitionOrderRequest) (CertificateOrder, error) {
	return CertificateOrder{}, ErrPermissionDenied
}

// CreateRenewal is retained only to fail closed for legacy direct callers.
func (s *Service) CreateRenewal(context.Context, Actor, CreateRenewalRequest) (CertificateOrder, error) {
	return CertificateOrder{}, ErrPermissionDenied
}

func normalizeTarget(actor Actor, target *uuid.UUID) error {
	if !validActor(actor) {
		return ErrInvalidInput
	}
	if actor.ScopeKind == "platform" {
		if *target == uuid.Nil {
			return ErrInvalidInput
		}
		return nil
	}
	if *target != uuid.Nil && *target != actor.ScopeID {
		return ErrPermissionDenied
	}
	*target = actor.ScopeID
	return nil
}

func validActor(actor Actor) bool {
	return actor.UserID != uuid.Nil && actor.ScopeID != uuid.Nil &&
		(actor.ScopeKind == "platform" || actor.ScopeKind == "tenant")
}

func validateDelete(actor Actor, request DeleteRequest) error {
	if !validActor(actor) || request.ID == uuid.Nil || request.ExpectedRevision < 1 ||
		!validMetadata(request.IdempotencyKey, request.RequestID) {
		return ErrInvalidInput
	}
	return nil
}

// invalidField is ErrInvalidInput naming the refused DNS / certificate request
// field (fix-fielderr-be; domains[n] in request order).
func invalidField(field, reason string) error { return fielderr.New(ErrInvalidInput, field, reason) }

func hostnameField(field, value string) error {
	if strings.TrimSpace(value) == "" {
		return invalidField(field, fielderr.Required)
	}
	return invalidField(field, fielderr.InvalidFormat)
}

func contentField(value string) error { return hostnameField("content", value) }

func remarkField(field, value string) error {
	if utf8.ValidString(value) && utf8.RuneCountInString(value) > 256 {
		return invalidField(field, fielderr.TooLong)
	}
	return invalidField(field, fielderr.InvalidFormat)
}

// nameRemarkField checks a DNS account name (required, ≤128 bytes) and remark.
func nameRemarkField(name string, remark *string) error {
	switch {
	case name == "":
		return invalidField("name", fielderr.Required)
	case !validName(name):
		if len(name) > 128 {
			return invalidField("name", fielderr.TooLong)
		}
		return invalidField("name", fielderr.InvalidFormat)
	case remark != nil && !validRemark(*remark):
		return remarkField("remark", *remark)
	}
	return nil
}

func validMetadata(key, requestID string) bool {
	return len(key) >= 1 && len(key) <= 128 && len(requestID) >= 1 && len(requestID) <= 128
}

func validName(value string) bool {
	return utf8.ValidString(value) && len(value) >= 1 && len(value) <= 128
}

// validRemark: the DNS API 备注 (migration 490), up to 256 characters with no control characters.
func validRemark(value string) bool {
	return utf8.ValidString(value) && utf8.RuneCountInString(value) <= 256 &&
		!strings.ContainsFunc(value, unicode.IsControl)
}

func supportedProvider(value string) bool {
	switch value {
	case "aliyun", "cloudflare", "huawei", "dnspod_cn", "dns_com", "dns_la", "namecom", dnscustomhttp.ProviderType, ProviderTypePlugin:
		return true
	default:
		return false
	}
}

func normalizeProviderCredentials(providerType string, input map[string]string) ([]byte, error) {
	if !validProviderCredentialSchema(providerType, input) {
		return nil, ErrInvalidInput
	}
	return normalizeCredentials(input)
}

func matchesSupportedProviderCredentialSchema(input map[string]string) bool {
	for _, providerType := range []string{"aliyun", "cloudflare", "huawei", "dnspod_cn", "dns_com", "dns_la", "namecom", dnscustomhttp.ProviderType,
		ProviderTypePlugin} {
		if validProviderCredentialSchema(providerType, input) {
			return true
		}
	}
	return false
}

func validProviderCredentialSchema(providerType string, input map[string]string) bool {
	switch providerType {
	case "aliyun":
		_, _, err := exactAliyunCredentials(input)
		return err == nil
	case "cloudflare":
		_, err := exactCredential(input, "api_token")
		return err == nil
	case "huawei":
		_, err := exactHuaweiCredentials(input)
		return err == nil
	case "dnspod_cn":
		_, _, err := exactDNSPodCredentials(input)
		return err == nil
	case "dns_com":
		_, _, err := exactDNSComCredentials(input)
		return err == nil
	case "dns_la":
		_, _, err := exactDNSLACredentials(input)
		return err == nil
	case "namecom":
		_, _, err := exactNameComCredentials(input)
		return err == nil
	case dnscustomhttp.ProviderType:
		// A literal internal address is refused when saved; resolved
		// addresses are checked on every connection.
		_, _, err := dnscustomhttp.Credentials(input)
		return err == nil
	case ProviderTypePlugin:
		return len(input) == 1 && validPluginProviderID(input[PluginCredentialField])
	default:
		return false
	}
}

func normalizeCredentials(input map[string]string) ([]byte, error) {
	if len(input) < 1 || len(input) > 32 {
		return nil, ErrInvalidInput
	}
	for key, value := range input {
		if !secretFieldPattern.MatchString(key) || value == "" || len(value) > 4096 || !utf8.ValidString(value) {
			return nil, ErrInvalidInput
		}
	}
	encoded, err := json.Marshal(input)
	if err != nil {
		return nil, ErrInvalidInput
	}
	return encoded, nil
}

func normalizeHostname(input string, wildcard bool) (string, error) {
	value := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(input), "."))
	if wildcard && strings.HasPrefix(value, "*.") {
		value = strings.TrimPrefix(value, "*.")
		wildcard = true
	} else {
		wildcard = false
	}
	if value == "" || len(value) > 253 || !isASCII(value) {
		return "", ErrInvalidInput
	}
	for _, label := range strings.Split(value, ".") {
		if !hostLabelPattern.MatchString(label) {
			return "", ErrInvalidInput
		}
	}
	if _, err := publicsuffix.EffectiveTLDPlusOne(value); err != nil {
		return "", ErrInvalidInput
	}
	if wildcard {
		return "*." + value, nil
	}
	return value, nil
}

func normalizeDomains(input []string) ([]string, bool, error) {
	if len(input) < 1 {
		return nil, false, invalidField("domains", fielderr.Required)
	}
	if len(input) > 100 {
		return nil, false, invalidField("domains", fielderr.TooLong)
	}
	seen := make(map[string]struct{}, len(input))
	result := make([]string, 0, len(input))
	hasWildcard := false
	for index, raw := range input {
		field := "domains[" + strconv.Itoa(index) + "]"
		domain, err := normalizeHostname(raw, true)
		if err != nil {
			return nil, false, hostnameField(field, raw)
		}
		if _, exists := seen[domain]; exists {
			return nil, false, invalidField(field, fielderr.Duplicate)
		}
		seen[domain] = struct{}{}
		result = append(result, domain)
		hasWildcard = hasWildcard || strings.HasPrefix(domain, "*.")
	}
	sort.Strings(result)
	return result, hasWildcard, nil
}

func normalizeRecord(name, recordType, content *string, ttl int) error {
	*name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(*name), "."))
	*recordType = strings.ToUpper(strings.TrimSpace(*recordType))
	*content = strings.TrimSpace(*content)
	if !validRecordName(*name) {
		return invalidField("name", fielderr.InvalidFormat)
	}
	if ttl < 60 || ttl > 86400 {
		return invalidField("ttl", fielderr.OutOfRange)
	}
	switch *recordType {
	case "A":
		address, err := netip.ParseAddr(*content)
		if err != nil || !address.Is4() {
			return contentField(*content)
		}
		*content = address.String()
	case "AAAA":
		address, err := netip.ParseAddr(*content)
		if err != nil || !address.Is6() {
			return contentField(*content)
		}
		*content = address.String()
	case "CNAME":
		hostname, err := normalizeHostname(*content, false)
		if err != nil {
			return hostnameField("content", *content)
		}
		*content = hostname
	case "TXT":
		switch {
		case *content == "":
			return invalidField("content", fielderr.Required)
		case len(*content) > 1024:
			return invalidField("content", fielderr.TooLong)
		case !utf8.ValidString(*content) || strings.ContainsAny(*content, "\x00\r\n"):
			return invalidField("content", fielderr.InvalidFormat)
		}
	default:
		return invalidField("type", fielderr.Invalid)
	}
	return nil
}

func validRecordName(value string) bool {
	if value == "@" {
		return true
	}
	if value == "" || len(value) > 253 || !isASCII(value) {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if !recordLabelPattern.MatchString(label) {
			return false
		}
	}
	return true
}

func isASCII(value string) bool {
	for _, character := range value {
		if character > 127 {
			return false
		}
	}
	return true
}

func digestRequest(value any) ([32]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}
