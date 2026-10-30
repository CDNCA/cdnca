package urlauthpolicy

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
	"github.com/google/uuid"
)

var (
	idempotencyPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
	parameterPattern   = regexp.MustCompile(`^[A-Za-z0-9_.~-]{1,64}$`)
	keyIDPattern       = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,64}$`)
)

type SecretCipher interface {
	Encrypt([]byte) (string, []byte, error)
	IdempotencyDigest([]byte) [32]byte
}

type Service struct {
	store  *Store
	cipher SecretCipher
}

func NewService(store *Store, cipher SecretCipher) *Service {
	return &Service{store: store, cipher: cipher}
}

func (s *Service) Create(ctx context.Context, actor Actor, request CreateRequest) (SecretWriteResult, error) {
	if err := normalizeActorAndTarget(actor, &request.TargetScopeID, &request.OwnerUserID); err != nil {
		return SecretWriteResult{}, err
	}
	if err := normalizeFields(&request.Fields); err != nil || !validWriteMetadata(request.IdempotencyKey, request.RequestID) {
		if err != nil {
			return SecretWriteResult{}, err
		}
		return SecretWriteResult{}, ErrInvalidInput
	}
	digest, err := requestDigest(struct {
		TargetScopeID uuid.UUID    `json:"target_scope_id"`
		OwnerUserID   uuid.UUID    `json:"owner_user_id"`
		Fields        PolicyFields `json:"fields"`
	}{request.TargetScopeID, request.OwnerUserID, request.Fields})
	if err != nil {
		return SecretWriteResult{}, err
	}
	result, err := s.store.Create(ctx, actor, request, digest, s.newKey)
	redact(&result.Policy, actor)
	return result, err
}

func (s *Service) Update(ctx context.Context, actor Actor, request UpdateRequest) (WriteResult, error) {
	if !validActor(actor) || request.ID == uuid.Nil || request.ExpectedRevision < 1 || !validWriteMetadata(request.IdempotencyKey, request.RequestID) {
		return WriteResult{}, ErrInvalidInput
	}
	if err := normalizeFields(&request.Fields); err != nil {
		return WriteResult{}, err
	}
	digest, err := requestDigest(struct {
		ID       uuid.UUID    `json:"id"`
		Revision int64        `json:"revision"`
		Fields   PolicyFields `json:"fields"`
	}{request.ID, request.ExpectedRevision, request.Fields})
	if err != nil {
		return WriteResult{}, err
	}
	result, err := s.store.Update(ctx, actor, request, digest)
	redact(&result.Policy, actor)
	return result, err
}

func (s *Service) SetEnabled(ctx context.Context, actor Actor, request StateRequest) (WriteResult, error) {
	if !validActor(actor) || request.ID == uuid.Nil || request.ExpectedRevision < 1 || !validWriteMetadata(request.IdempotencyKey, request.RequestID) {
		return WriteResult{}, ErrInvalidInput
	}
	digest, err := requestDigest(struct {
		ID       uuid.UUID `json:"id"`
		Revision int64     `json:"revision"`
		Enabled  bool      `json:"enabled"`
	}{request.ID, request.ExpectedRevision, request.Enabled})
	if err != nil {
		return WriteResult{}, err
	}
	result, err := s.store.SetEnabled(ctx, actor, request, digest)
	redact(&result.Policy, actor)
	return result, err
}

func (s *Service) Rotate(ctx context.Context, actor Actor, request RotateRequest) (SecretWriteResult, error) {
	if !validActor(actor) || request.ID == uuid.Nil || request.ExpectedRevision < 1 || !validWriteMetadata(request.IdempotencyKey, request.RequestID) {
		return SecretWriteResult{}, ErrInvalidInput
	}
	digest, err := requestDigest(struct {
		ID       uuid.UUID `json:"id"`
		Revision int64     `json:"revision"`
	}{request.ID, request.ExpectedRevision})
	if err != nil {
		return SecretWriteResult{}, err
	}
	result, err := s.store.Rotate(ctx, actor, request, digest, s.newKey)
	redact(&result.Policy, actor)
	return result, err
}

func (s *Service) Revoke(ctx context.Context, actor Actor, request RevokeRequest) (WriteResult, error) {
	request.KeyID = strings.TrimSpace(request.KeyID)
	if !validActor(actor) || request.ID == uuid.Nil || request.ExpectedRevision < 1 || !keyIDPattern.MatchString(request.KeyID) || !validWriteMetadata(request.IdempotencyKey, request.RequestID) {
		return WriteResult{}, ErrInvalidInput
	}
	digest, err := requestDigest(struct {
		ID       uuid.UUID `json:"id"`
		KeyID    string    `json:"key_id"`
		Revision int64     `json:"revision"`
	}{request.ID, request.KeyID, request.ExpectedRevision})
	if err != nil {
		return WriteResult{}, err
	}
	result, err := s.store.Revoke(ctx, actor, request, digest)
	redact(&result.Policy, actor)
	return result, err
}

func (s *Service) Get(ctx context.Context, actor Actor, id uuid.UUID) (Policy, error) {
	if !validActor(actor) || id == uuid.Nil {
		return Policy{}, ErrInvalidInput
	}
	item, err := s.store.Get(ctx, actor, id)
	if err != nil {
		return Policy{}, err
	}
	redact(&item, actor)
	return item, nil
}

func (s *Service) List(ctx context.Context, actor Actor, filter ListFilter) (ListResult, error) {
	filter.Name = strings.TrimSpace(filter.Name)
	filter.Status = strings.TrimSpace(filter.Status)
	if !validActor(actor) || filter.Page < 1 || filter.Page > 1_000_000 || filter.Limit < 1 || filter.Limit > 100 ||
		(filter.Status != "" && filter.Status != "enabled" && filter.Status != "disabled") || utf8.RuneCountInString(filter.Name) > 128 {
		return ListResult{}, ErrInvalidInput
	}
	result, err := s.store.List(ctx, actor, filter)
	if err != nil {
		return ListResult{}, err
	}
	for index := range result.Items {
		redact(&result.Items[index], actor)
	}
	return result, nil
}

func (s *Service) Snapshot(ctx context.Context, actor Actor, id uuid.UUID) (SnapshotResult, error) {
	if !validActor(actor) || id == uuid.Nil {
		return SnapshotResult{}, ErrInvalidInput
	}
	return s.store.Snapshot(ctx, actor, id)
}

type encryptedKey struct {
	ID         string
	KEKKeyID   string
	Ciphertext []byte
	Digest     [32]byte
	Plaintext  string
}

func (s *Service) newKey(policyID uuid.UUID) (encryptedKey, error) {
	if s.cipher == nil {
		return encryptedKey{}, ErrEncryptionUnavailable
	}
	secretBytes := make([]byte, 32)
	if _, err := rand.Read(secretBytes); err != nil {
		return encryptedKey{}, err
	}
	secret := base64.RawURLEncoding.EncodeToString(secretBytes)
	keyUUID, err := uuid.NewV7()
	if err != nil {
		return encryptedKey{}, err
	}
	keyID := "k-" + keyUUID.String()
	associatedData := []byte("cdnca-control-url-auth/key-envelope/v1\x00" + policyID.String() + "\x00" + keyID + "\x00current")
	bound, isBound := s.cipher.(BoundSecretCipher)
	var kekID string
	var ciphertext []byte
	if isBound {
		kekID, ciphertext, err = bound.EncryptBound([]byte(secret), associatedData)
	} else {
		kekID, ciphertext, err = s.cipher.Encrypt([]byte(secret))
	}
	if err != nil {
		return encryptedKey{}, ErrEncryptionUnavailable
	}
	digest := s.cipher.IdempotencyDigest([]byte(secret))
	if isBound {
		digest = bound.SecretDigest([]byte(secret))
	}
	return encryptedKey{ID: keyID, KEKKeyID: kekID, Ciphertext: ciphertext, Digest: digest, Plaintext: secret}, nil
}

func normalizeActorAndTarget(actor Actor, scopeID, ownerID *uuid.UUID) error {
	if !validActor(actor) {
		return ErrInvalidInput
	}
	if actor.ScopeKind == "platform" {
		if *scopeID == uuid.Nil || *ownerID == uuid.Nil {
			return ErrInvalidInput
		}
		return nil
	}
	if (*scopeID != uuid.Nil && *scopeID != actor.ScopeID) || (*ownerID != uuid.Nil && *ownerID != actor.UserID) {
		return ErrPermissionDenied
	}
	*scopeID, *ownerID = actor.ScopeID, actor.UserID
	return nil
}

func validActor(actor Actor) bool {
	return actor.UserID != uuid.Nil && actor.ScopeID != uuid.Nil && (actor.ScopeKind == "platform" || actor.ScopeKind == "tenant")
}

func normalizeFields(fields *PolicyFields) error {
	fields.Name = strings.TrimSpace(fields.Name)
	fields.Algorithm = strings.TrimSpace(fields.Algorithm)
	fields.SignatureParameter = strings.TrimSpace(fields.SignatureParameter)
	fields.ExpirationParameter = strings.TrimSpace(fields.ExpirationParameter)
	fields.KeyIDParameter = strings.TrimSpace(fields.KeyIDParameter)
	// fix-fielderr-be4: each refusal names its field as sent in the (flat)
	// policy body; list entries keep their submitted index (sorted below).
	refuse := func(field, reason string) error { return fielderr.New(ErrInvalidInput, field, reason) }
	switch count := utf8.RuneCountInString(fields.Name); {
	case fields.SiteID == uuid.Nil:
		return refuse("site_id", fielderr.Required)
	case count < 1:
		return refuse("name", fielderr.Required)
	case count > 128:
		return refuse("name", fielderr.TooLong)
	case fields.Algorithm != AlgorithmHMACSHA256:
		return refuse("algorithm", fielderr.Invalid)
	case !parameterPattern.MatchString(fields.SignatureParameter):
		return refuse("signature_parameter", fielderr.InvalidFormat)
	case !parameterPattern.MatchString(fields.ExpirationParameter):
		return refuse("expiration_parameter", fielderr.InvalidFormat)
	case !parameterPattern.MatchString(fields.KeyIDParameter):
		return refuse("key_id_parameter", fielderr.InvalidFormat)
	case fields.SignatureParameter == fields.ExpirationParameter:
		return refuse("expiration_parameter", fielderr.Duplicate)
	case fields.SignatureParameter == fields.KeyIDParameter || fields.ExpirationParameter == fields.KeyIDParameter:
		return refuse("key_id_parameter", fielderr.Duplicate)
	case fields.MaxClockSkewSeconds > 300:
		return refuse("max_clock_skew_seconds", fielderr.OutOfRange)
	case fields.MaxValiditySeconds < 1 || fields.MaxValiditySeconds > 86400:
		return refuse("max_validity_seconds", fielderr.OutOfRange)
	case fields.MaxSignatureUses > 1_000_000:
		return refuse("max_signature_uses", fielderr.OutOfRange)
	case len(fields.ExcludedQueryParameters) > 32:
		return refuse("excluded_query_parameters", fielderr.OutOfRange)
	case len(fields.TrustedProxyCIDRs) > 64:
		return refuse("trusted_proxy_cidrs", fielderr.OutOfRange)
	}
	authParams := map[string]struct{}{fields.SignatureParameter: {}, fields.ExpirationParameter: {}, fields.KeyIDParameter: {}}
	seen := make(map[string]struct{}, len(fields.ExcludedQueryParameters))
	for i, raw := range fields.ExcludedQueryParameters {
		field := fmt.Sprintf("excluded_query_parameters[%d]", i)
		value := strings.TrimSpace(raw)
		if !parameterPattern.MatchString(value) {
			return refuse(field, fielderr.InvalidFormat)
		}
		if _, exists := authParams[value]; exists {
			return refuse(field, fielderr.Invalid)
		}
		if _, exists := seen[value]; exists {
			return refuse(field, fielderr.Duplicate)
		}
		seen[value] = struct{}{}
		fields.ExcludedQueryParameters[i] = value
	}
	sort.Strings(fields.ExcludedQueryParameters)
	seen = make(map[string]struct{}, len(fields.TrustedProxyCIDRs))
	for i, raw := range fields.TrustedProxyCIDRs {
		field := fmt.Sprintf("trusted_proxy_cidrs[%d]", i)
		if hasControl(raw) || strings.Contains(raw, "%") {
			return refuse(field, fielderr.InvalidFormat)
		}
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			return refuse(field, fielderr.InvalidFormat)
		}
		if prefix.Addr().Is4In6() {
			return refuse(field, fielderr.Invalid)
		}
		value := prefix.Masked().String()
		if len(value) > 64 {
			return refuse(field, fielderr.TooLong)
		}
		if _, exists := seen[value]; exists {
			return refuse(field, fielderr.Duplicate)
		}
		seen[value] = struct{}{}
		fields.TrustedProxyCIDRs[i] = value
	}
	sort.Strings(fields.TrustedProxyCIDRs)
	return nil
}

func validWriteMetadata(key, requestID string) bool {
	return idempotencyPattern.MatchString(key) && idempotencyPattern.MatchString(requestID)
}

func requestDigest(value any) ([32]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

func redact(item *Policy, actor Actor) {
	if actor.ScopeKind == "tenant" {
		item.Owner = nil
	}
}

func hasControl(value string) bool {
	for _, character := range value {
		if unicode.IsControl(character) {
			return true
		}
	}
	return false
}
