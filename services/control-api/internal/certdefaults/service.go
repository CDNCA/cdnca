package certdefaults

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"regexp"
	"slices"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/acmecacredentials"
	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
	"github.com/google/uuid"
)

var metadataPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// Issuers are the CAs a default may name (systemconfig CertificateIssuers).
var Issuers = []string{"lets_encrypt", "zerossl", "google_trust"}

type Store struct {
	*store
}

type serviceStore interface {
	Get(context.Context, Actor, Request) (Defaults, error)
	Update(context.Context, Actor, UpdateRequest, [32]byte) (Defaults, error)
	// IssuerConfigured is acmecacredentials.Configured: lets_encrypt always,
	// an EAB CA only with platform credentials.
	IssuerConfigured(context.Context, string) (bool, error)
}

func (s *store) IssuerConfigured(ctx context.Context, issuer string) (bool, error) {
	return acmecacredentials.Configured(ctx, s.pool, issuer)
}

type Service struct{ store serviceStore }

func NewService(store *Store) *Service { return &Service{store: store} }

func (s *Service) Get(ctx context.Context, actor Actor, request Request) (Defaults, error) {
	if err := normalizeActor(actor, &request.TargetScopeID, &request.TargetUserID); err != nil {
		return Defaults{}, err
	}
	return s.store.Get(ctx, actor, request)
}

func (s *Service) Update(ctx context.Context, actor Actor, request UpdateRequest) (Defaults, error) {
	if err := normalizeActor(actor, &request.TargetScopeID, &request.TargetUserID); err != nil {
		return Defaults{}, err
	}
	request.CertificateType = strings.TrimSpace(strings.ToLower(request.CertificateType))
	if request.CertificateType != CertificateTypeACME && request.CertificateType != CertificateTypeUploaded {
		return Defaults{}, fielderr.New(ErrInvalidInput, "certificate_type", fielderr.Invalid)
	}
	if request.CertificateType == CertificateTypeUploaded {
		request.DNSProviderID = nil
		request.Issuer = nil
	}
	if request.Issuer != nil && !slices.Contains(Issuers, *request.Issuer) {
		return Defaults{}, fielderr.New(ErrInvalidInput, "issuer", fielderr.Invalid)
	}
	if request.ExpectedRevision < 0 || !metadataPattern.MatchString(request.IdempotencyKey) || !metadataPattern.MatchString(request.RequestID) {
		return Defaults{}, ErrInvalidInput
	}
	if request.DNSProviderID != nil && *request.DNSProviderID == uuid.Nil {
		return Defaults{}, fielderr.New(ErrInvalidInput, "dns_provider_id", fielderr.Invalid)
	}
	// The CA must be usable now, as an order create checks it (409
	// certificate_issuer_unavailable); no issuer is the platform default.
	if request.Issuer != nil {
		configured, err := s.store.IssuerConfigured(ctx, *request.Issuer)
		if err != nil {
			return Defaults{}, err
		}
		if !configured {
			return Defaults{}, ErrIssuerUnavailable
		}
	}
	digest, err := digestRequest(struct {
		ScopeID         uuid.UUID  `json:"scope_id"`
		UserID          uuid.UUID  `json:"user_id"`
		CertificateType string     `json:"certificate_type"`
		DNSProviderID   *uuid.UUID `json:"dns_provider_id"`
		Issuer          *string    `json:"issuer,omitempty"`
		Revision        int64      `json:"revision"`
	}{request.TargetScopeID, request.TargetUserID, request.CertificateType, request.DNSProviderID, request.Issuer, request.ExpectedRevision})
	if err != nil {
		return Defaults{}, err
	}
	return s.store.Update(ctx, actor, request, digest)
}

func normalizeActor(actor Actor, scopeID, userID *uuid.UUID) error {
	if actor.UserID == uuid.Nil || actor.ScopeID == uuid.Nil || (actor.ScopeKind != "tenant" && actor.ScopeKind != "platform") {
		return ErrInvalidInput
	}
	if actor.ScopeKind == "tenant" {
		if *scopeID == uuid.Nil {
			*scopeID = actor.ScopeID
		}
		if *userID == uuid.Nil {
			*userID = actor.UserID
		}
		if *scopeID != actor.ScopeID || *userID != actor.UserID {
			return ErrPermissionDenied
		}
		return nil
	}
	if *scopeID == uuid.Nil || *userID == uuid.Nil {
		return ErrInvalidInput
	}
	return nil
}

func digestRequest(value any) ([32]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}
