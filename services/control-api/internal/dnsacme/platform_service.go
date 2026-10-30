package dnsacme

import (
	"context"
	"errors"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscustomhttp"
	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
	"github.com/google/uuid"
)

func platformActor(actor Actor) bool {
	return validActor(actor) && actor.ScopeKind == "platform"
}

func (s *Service) PlatformConfig(ctx context.Context, actor Actor) (PlatformConfig, error) {
	if !platformActor(actor) {
		return PlatformConfig{}, ErrPlatformOnly
	}
	return s.store.PlatformConfig(ctx)
}

// SavePlatformConfig stores the installation DNS configuration. New
// credentials are verified against the provider first and are not saved when
// the provider rejects them. The tenant copies are synchronised afterwards;
// a synchronisation failure is reported in the returned config, not as an
// error, because the platform configuration itself was saved.
func (s *Service) SavePlatformConfig(ctx context.Context, actor Actor, request SavePlatformConfigRequest) (PlatformConfig, error) {
	if !platformActor(actor) {
		return PlatformConfig{}, ErrPlatformOnly
	}
	request.ProviderType = strings.ToLower(strings.TrimSpace(request.ProviderType))
	if request.ExpectedRevision < 1 || !validMetadata(request.IdempotencyKey, request.RequestID) {
		return PlatformConfig{}, ErrInvalidInput
	}
	if !supportedProvider(request.ProviderType) {
		return PlatformConfig{}, invalidField("provider_type", fielderr.Invalid)
	}
	if request.TTL < PlatformMinTTLFor(request.ProviderType) || request.TTL > PlatformMaxTTL {
		return PlatformConfig{}, invalidField("ttl", fielderr.OutOfRange)
	}
	var write *platformCredentialWrite
	var credentialDigest [32]byte
	if request.Credentials != nil {
		credentialJSON, err := normalizeProviderCredentials(request.ProviderType, request.Credentials)
		if err != nil {
			return PlatformConfig{}, invalidField("credentials", fielderr.Invalid)
		}
		defer clear(credentialJSON)
		if err := s.verifyPlatformCredentials(ctx, request.ProviderType, request.Credentials); err != nil {
			return PlatformConfig{}, err
		}
		boundCipher, ok := s.cipher.(BoundCredentialCipher)
		if !ok {
			return PlatformConfig{}, ErrCredentialUnavailable
		}
		bindingID, err := uuid.NewV7()
		if err != nil {
			return PlatformConfig{}, err
		}
		keyID, ciphertext, err := boundCipher.EncryptCredential(platformBinding(bindingID), credentialJSON)
		if err != nil {
			return PlatformConfig{}, ErrCredentialUnavailable
		}
		defer clear(ciphertext)
		identifiers := map[string]string{}
		for _, field := range identifierFields[request.ProviderType] {
			identifiers[field] = request.Credentials[field]
		}
		write = &platformCredentialWrite{bindingID: bindingID, keyID: keyID, ciphertext: ciphertext, identifiers: identifiers}
		credentialDigest = s.cipher.IdempotencyDigest(credentialJSON)
	}
	digest, err := digestRequest(struct {
		ProviderType     string   `json:"provider_type"`
		CredentialDigest [32]byte `json:"credential_digest"`
		TTL              int      `json:"ttl"`
		IPWeight         bool     `json:"ip_weight"`
		Revision         int64    `json:"revision"`
	}{request.ProviderType, credentialDigest, request.TTL, request.IPWeight, request.ExpectedRevision})
	if err != nil {
		return PlatformConfig{}, err
	}
	if err := s.store.SavePlatformConfig(ctx, actor, request, write, digest); err != nil {
		return PlatformConfig{}, err
	}
	_, _ = s.SyncPlatformTenants(ctx)
	return s.store.PlatformConfig(ctx)
}

// TestPlatformConnection (连接测试) checks credentials against the provider
// without saving anything or writing any record: the same verification as a
// save, then for each CNAME domain whether the account hosts it (the domain
// list read of ResolveZoneApex). Nil credentials test the saved ones, which
// must be of providerType. A verification failure is returned as the error.
func (s *Service) TestPlatformConnection(ctx context.Context, actor Actor, providerType string,
	credentials map[string]string) (PlatformConnection, error) {
	if !platformActor(actor) {
		return PlatformConnection{}, ErrPlatformOnly
	}
	providerType = strings.ToLower(strings.TrimSpace(providerType))
	if !supportedProvider(providerType) {
		return PlatformConnection{}, ErrInvalidInput
	}
	if credentials == nil {
		savedType, saved, err := s.PlatformCredentials(ctx)
		if err != nil {
			return PlatformConnection{}, err
		}
		defer clear(saved)
		if savedType != providerType {
			return PlatformConnection{}, ErrInvalidInput
		}
		credentials = saved
	} else if normalized, err := normalizeProviderCredentials(providerType, credentials); err != nil {
		return PlatformConnection{}, err
	} else {
		clear(normalized)
	}
	if err := s.verifyPlatformCredentials(ctx, providerType, credentials); err != nil {
		return PlatformConnection{}, err
	}
	zones, err := s.store.PlatformZoneNames(ctx)
	if err != nil {
		return PlatformConnection{}, err
	}
	result := PlatformConnection{ProviderType: providerType, Zones: make([]PlatformConnectionZone, 0, len(zones))}
	for _, name := range zones {
		zone := PlatformConnectionZone{Name: name, Status: PlatformZoneUnchecked}
		if providerType == dnscustomhttp.ProviderType || providerType == ProviderTypePlugin {
			result.Zones = append(result.Zones, zone) // no domain list to check against
			continue
		}
		apex, err := s.zoneApex(ctx, providerType, credentials, name)
		switch {
		case errors.Is(err, ErrZoneNotHosted):
			zone.Status = PlatformZoneNotHosted
		case err != nil:
			return PlatformConnection{}, err
		case apex != "":
			zone.Status, zone.Apex = PlatformZoneHosted, apex
		}
		result.Zones = append(result.Zones, zone)
	}
	sort.Slice(result.Zones, func(i, j int) bool { return result.Zones[i].Name < result.Zones[j].Name })
	return result, nil
}

func (s *Service) verifyPlatformCredentials(ctx context.Context, providerType string, credentials map[string]string) error {
	verifier, ok := s.verifier.(CredentialProviderVerifier)
	if !ok {
		return ErrProviderVerificationUnavailable
	}
	return verifier.VerifyCredentials(ctx, providerType, credentials)
}

func (s *Service) ListPlatformZones(ctx context.Context, actor Actor, query PlatformZoneQuery) (PlatformZonePage, error) {
	query.Search = strings.ToLower(strings.TrimSpace(query.Search))
	if !platformActor(actor) {
		return PlatformZonePage{}, ErrPlatformOnly
	}
	if query.Page < 1 || query.Limit < 1 || query.Limit > 100 || utf8.RuneCountInString(query.Search) > 253 {
		return PlatformZonePage{}, ErrInvalidInput
	}
	return s.store.ListPlatformZones(ctx, query)
}

func (s *Service) CreatePlatformZone(ctx context.Context, actor Actor, request PlatformZoneRequest) (PlatformZone, error) {
	if err := s.normalizePlatformZone(actor, &request, false); err != nil {
		return PlatformZone{}, err
	}
	if err := s.platformZoneApex(ctx, &request); err != nil {
		return PlatformZone{}, err
	}
	digest, _ := digestRequest(struct {
		Name             string `json:"name"`
		Remark           string `json:"remark"`
		RandomAllocation *bool  `json:"random_allocation"`
	}{request.Name, request.Remark, request.RandomAllocation})
	result, err := s.store.CreatePlatformZone(ctx, actor, request, digest)
	if err == nil {
		_, _ = s.SyncPlatformTenants(ctx)
	}
	return result, err
}

func (s *Service) UpdatePlatformZone(ctx context.Context, actor Actor, request PlatformZoneRequest) (PlatformZone, error) {
	if err := s.normalizePlatformZone(actor, &request, true); err != nil {
		return PlatformZone{}, err
	}
	if err := s.platformZoneApex(ctx, &request); err != nil {
		return PlatformZone{}, err
	}
	digest, _ := digestRequest(struct {
		ID               uuid.UUID `json:"id"`
		Revision         int64     `json:"revision"`
		Name             string    `json:"name"`
		Remark           string    `json:"remark"`
		RandomAllocation *bool     `json:"random_allocation"`
	}{request.ID, request.ExpectedRevision, request.Name, request.Remark, request.RandomAllocation})
	result, err := s.store.UpdatePlatformZone(ctx, actor, request, digest)
	if err == nil {
		_, _ = s.SyncPlatformTenants(ctx)
	}
	return result, err
}

func (s *Service) DeletePlatformZone(ctx context.Context, actor Actor, request PlatformZoneRequest) error {
	if !platformActor(actor) {
		return ErrPlatformOnly
	}
	if request.ID == uuid.Nil || request.ExpectedRevision < 1 || !validMetadata(request.IdempotencyKey, request.RequestID) {
		return ErrInvalidInput
	}
	digest, _ := digestRequest(struct {
		ID       uuid.UUID `json:"id"`
		Revision int64     `json:"revision"`
	}{request.ID, request.ExpectedRevision})
	return s.store.DeletePlatformZone(ctx, actor, request, digest)
}

func (s *Service) PlatformTenants(ctx context.Context, actor Actor) ([]PlatformTenant, error) {
	if !platformActor(actor) {
		return nil, ErrPlatformOnly
	}
	return s.store.PlatformTenants(ctx)
}

func (s *Service) normalizePlatformZone(actor Actor, request *PlatformZoneRequest, update bool) error {
	if !platformActor(actor) {
		return ErrPlatformOnly
	}
	name, err := normalizeHostname(request.Name, false)
	if err != nil || !validPlatformRemark(request.Remark) || !validMetadata(request.IdempotencyKey, request.RequestID) ||
		update && (request.ID == uuid.Nil || request.ExpectedRevision < 1) {
		return ErrInvalidInput
	}
	request.Name = name
	return nil
}

// platformZoneApex finds the domain the platform DNS account hosts for the
// CNAME domain (migration 473): saving fails with ErrZoneNotHosted when the
// account hosts neither the name nor a parent of it. A platform without DNS
// credentials yet stores no apex; the first use looks it up.
func (s *Service) platformZoneApex(ctx context.Context, request *PlatformZoneRequest) error {
	if s.apex == nil {
		return nil
	}
	providerType, credentials, err := s.PlatformCredentials(ctx)
	if errors.Is(err, ErrPlatformNotConfigured) {
		return nil
	}
	if err != nil {
		return err
	}
	defer clear(credentials)
	request.ProviderZoneApex, err = s.zoneApex(ctx, providerType, credentials, request.Name)
	return err
}

func validPlatformRemark(value string) bool {
	if value != strings.TrimSpace(value) || utf8.RuneCountInString(value) > 255 {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}
