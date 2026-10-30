package packagesubscription

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"math"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cdnca/cdnca/services/control-api/internal/packageperiod"
	"github.com/google/uuid"
)

var writeMetadataPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
var ianaTimeZonePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._+-]*/[A-Za-z0-9][A-Za-z0-9._+/-]*$`)

type Service struct {
	store *Store
}

func NewService(store *Store) *Service {
	return &Service{store: store}
}

func (s *Service) Open(ctx context.Context, actor Actor, request OpenRequest) (MutationResult, error) {
	normalizeTerms(&request.Terms)
	if !validActorEnvelope(actor) {
		return MutationResult{}, ErrUnauthenticated
	}
	if request.TenantScopeID == uuid.Nil || request.OwnerUserID == uuid.Nil || request.ProductID == uuid.Nil ||
		request.ProductRevision < 1 || !validLimit(request.SiteLimit) || !validLimit(request.NodeLimit) ||
		request.CyclePolicy.Validate() != nil || !validFactor(request.TrafficFactor) ||
		!validTermsShape(request.Terms) || !validMetadata(request.IdempotencyKey, request.RequestID) {
		return MutationResult{}, ErrInvalidInput
	}
	if _, err := loadIANAZone(request.TimeZone); err != nil {
		return MutationResult{}, ErrInvalidInput
	}
	digest, err := openDigest(request)
	if err != nil {
		return MutationResult{}, err
	}
	return s.store.Open(ctx, actor, request, digest)
}

func (s *Service) Renew(ctx context.Context, actor Actor, request RenewRequest) (MutationResult, error) {
	normalizeTerms(&request.Terms)
	if !validActorEnvelope(actor) {
		return MutationResult{}, ErrUnauthenticated
	}
	if request.TenantScopeID == uuid.Nil || request.SubscriptionID == uuid.Nil ||
		request.ExpectedRevision < 1 || !validTermsShape(request.Terms) ||
		!validMetadata(request.IdempotencyKey, request.RequestID) {
		return MutationResult{}, ErrInvalidInput
	}
	digest, err := renewDigest(request)
	if err != nil {
		return MutationResult{}, err
	}
	return s.store.Renew(ctx, actor, request, digest)
}

func (s *Service) Cancel(ctx context.Context, actor Actor, request CancelRequest) (MutationResult, error) {
	if !validActorEnvelope(actor) {
		return MutationResult{}, ErrUnauthenticated
	}
	if request.TenantScopeID == uuid.Nil || request.SubscriptionID == uuid.Nil ||
		request.ExpectedRevision < 1 || !validMetadata(request.IdempotencyKey, request.RequestID) {
		return MutationResult{}, ErrInvalidInput
	}
	digest, err := requestDigest(struct {
		TenantScopeID  string `json:"tenant_scope_id"`
		SubscriptionID string `json:"subscription_id"`
		Revision       int64  `json:"expected_revision"`
	}{request.TenantScopeID.String(), request.SubscriptionID.String(), request.ExpectedRevision})
	if err != nil {
		return MutationResult{}, err
	}
	return s.store.Cancel(ctx, actor, request, digest)
}

func (s *Service) Get(ctx context.Context, actor Actor, tenantScopeID, subscriptionID uuid.UUID) (Subscription, error) {
	if !validActorEnvelope(actor) {
		return Subscription{}, ErrUnauthenticated
	}
	if tenantScopeID == uuid.Nil || subscriptionID == uuid.Nil {
		return Subscription{}, ErrInvalidInput
	}
	return s.store.Get(ctx, actor, tenantScopeID, subscriptionID)
}

func validActorEnvelope(actor Actor) bool {
	return actor.UserID != uuid.Nil && actor.ScopeID != uuid.Nil &&
		(actor.SessionID != uuid.Nil) != actor.bridge.Valid() &&
		(actor.ScopeKind == ScopePlatform || actor.ScopeKind == ScopeTenant)
}

func validLimit(value int64) bool {
	return value == -1 || (value >= 0 && value <= maxCountLimit)
}

func validFactor(factor packageperiod.TrafficFactor) bool {
	canonical, err := packageperiod.NewTrafficFactor(factor.Numerator(), factor.Denominator())
	return err == nil && canonical == factor && factor.Numerator() <= math.MaxInt64 && factor.Denominator() <= math.MaxInt64
}

func validTermsShape(terms packageperiod.Terms) bool {
	if (terms.Duration == nil) == (terms.EndAt == nil) {
		return false
	}
	if terms.Duration != nil {
		switch *terms.Duration {
		case packageperiod.DurationMonth, packageperiod.DurationQuarter, packageperiod.DurationYear:
			return true
		default:
			return false
		}
	}
	return terms.EndAt != nil && !terms.EndAt.IsZero()
}

func validMetadata(key, requestID string) bool {
	return writeMetadataPattern.MatchString(key) && writeMetadataPattern.MatchString(requestID)
}

func normalizeTerms(terms *packageperiod.Terms) {
	if terms.EndAt != nil {
		value := terms.EndAt.UTC().Truncate(time.Microsecond)
		terms.EndAt = &value
	}
}

func loadIANAZone(name string) (*time.Location, error) {
	if name == "UTC" {
		return time.UTC, nil
	}
	if name == "" || len(name) > 128 || strings.TrimSpace(name) != name || name == "Local" ||
		strings.Contains(name, "..") || !ianaTimeZonePattern.MatchString(name) {
		return nil, ErrInvalidInput
	}
	location, err := time.LoadLocation(name)
	if err != nil || location.String() != name {
		return nil, ErrInvalidInput
	}
	return location, nil
}

func openDigest(request OpenRequest) ([32]byte, error) {
	return requestDigest(struct {
		TenantScopeID     string                    `json:"tenant_scope_id"`
		OwnerUserID       string                    `json:"owner_user_id"`
		ProductID         string                    `json:"product_id"`
		ProductRevision   int64                     `json:"product_revision"`
		SiteLimit         int64                     `json:"site_limit"`
		NodeLimit         int64                     `json:"node_limit"`
		Terms             packageperiod.Terms       `json:"terms"`
		TimeZone          string                    `json:"timezone"`
		CyclePolicy       packageperiod.CyclePolicy `json:"cycle_policy"`
		FactorNumerator   uint64                    `json:"factor_numerator"`
		FactorDenominator uint64                    `json:"factor_denominator"`
	}{request.TenantScopeID.String(), request.OwnerUserID.String(), request.ProductID.String(), request.ProductRevision,
		request.SiteLimit, request.NodeLimit, request.Terms, request.TimeZone, request.CyclePolicy,
		request.TrafficFactor.Numerator(), request.TrafficFactor.Denominator()})
}

func renewDigest(request RenewRequest) ([32]byte, error) {
	return requestDigest(struct {
		TenantScopeID  string              `json:"tenant_scope_id"`
		SubscriptionID string              `json:"subscription_id"`
		Revision       int64               `json:"expected_revision"`
		Terms          packageperiod.Terms `json:"terms"`
	}{request.TenantScopeID.String(), request.SubscriptionID.String(), request.ExpectedRevision, request.Terms})
}

func requestDigest(value any) ([32]byte, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(payload), nil
}

// Suspend suspends (request.Suspend) or unsuspends one subscription; the
// platform (package_subscriptions.manage) or the customer's reseller
// (reseller.customers.manage) may do it.
func (s *Service) Suspend(ctx context.Context, actor Actor, request SuspendRequest) (MutationResult, error) {
	if !validActorEnvelope(actor) {
		return MutationResult{}, ErrUnauthenticated
	}
	request.Reason = strings.TrimSpace(request.Reason)
	if request.TenantScopeID == uuid.Nil || request.SubscriptionID == uuid.Nil ||
		!validMetadata(request.IdempotencyKey, request.RequestID) ||
		(request.Suspend && (request.Reason == "" || utf8.RuneCountInString(request.Reason) > 256)) ||
		(!request.Suspend && request.Reason != "") {
		return MutationResult{}, ErrInvalidInput
	}
	digest, err := requestDigest(struct {
		TenantScopeID  string `json:"tenant_scope_id"`
		SubscriptionID string `json:"subscription_id"`
		Suspend        bool   `json:"suspend"`
		Reason         string `json:"reason"`
	}{request.TenantScopeID.String(), request.SubscriptionID.String(), request.Suspend, request.Reason})
	if err != nil {
		return MutationResult{}, err
	}
	return s.store.Suspend(ctx, actor, request, digest)
}
