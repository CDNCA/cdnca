package pluginruntimewebhook

import (
	"context"
	"errors"
	"reflect"
	"regexp"

	"github.com/cdnca/cdnca/services/control-api/internal/pluginruntimeauth"
	"github.com/cdnca/cdnca/services/control-api/internal/pluginwebhook"
	"github.com/google/uuid"
)

var ErrInvalidConfig = errors.New("invalid authorized plugin webhook deliverer configuration")

var versionedWebhookEventType = regexp.MustCompile(`^io\.cdnca\.[a-z][a-z0-9_]*\.v[1-9][0-9]*\.[a-z][a-z0-9_]*$`)

var supportedWebhookEventTypes = map[string]struct{}{
	"io.cdnca.webhook.v1.test":               {},
	"io.cdnca.certificate.v1.expiry_reached": {},
	"io.cdnca.certificate.v1.status_changed": {},
	"io.cdnca.deployment.v1.status_changed":  {},
	"io.cdnca.dns.v1.changed":                {},
	"io.cdnca.dns.v1.deleted":                {},
	"io.cdnca.node.v1.status_changed":        {},
	"io.cdnca.security.v1.incident_detected": {},
	"io.cdnca.site.v1.updated":               {},
	"io.cdnca.usage.v1.threshold_reached":    {},
}

type RuntimeAuthorizationRequest struct {
	InstallationID uuid.UUID
	TargetScopeID  uuid.UUID
	TenantID       uuid.UUID
	SubscriptionID uuid.UUID
	DeliveryID     uuid.UUID
	EventID        uuid.UUID
	RequestID      string
	CapabilityKind string
	CapabilityCode string
}

type RuntimeAuthorizationFacts struct {
	IdentityJSON []byte
	DecisionJSON []byte
}

type RuntimeAuthorizationProvider interface {
	RuntimeAuthorization(context.Context, RuntimeAuthorizationRequest) (RuntimeAuthorizationFacts, error)
}

type RuntimeAuthorizationVerifier interface {
	Authorize([]byte, []byte, pluginruntimeauth.ExpectedAction) (pluginruntimeauth.Authorization, error)
}

type V2Deliverer interface {
	DeliverV2(context.Context, pluginwebhook.QueueItem, uint64, []byte) pluginwebhook.SendResult
}

type AuthorizedDeliverer struct {
	installationID uuid.UUID
	provider       RuntimeAuthorizationProvider
	verifier       RuntimeAuthorizationVerifier
	delegate       V2Deliverer
}

func NewAuthorizedDeliverer(installationID uuid.UUID, provider RuntimeAuthorizationProvider,
	verifier RuntimeAuthorizationVerifier, delegate V2Deliverer) (*AuthorizedDeliverer, error) {
	if installationID == uuid.Nil || nilInterface(provider) || nilInterface(verifier) || nilInterface(delegate) {
		return nil, ErrInvalidConfig
	}
	return &AuthorizedDeliverer{
		installationID: installationID,
		provider:       provider,
		verifier:       verifier,
		delegate:       delegate,
	}, nil
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func (deliverer *AuthorizedDeliverer) DeliverV2(ctx context.Context, item pluginwebhook.QueueItem,
	attempt uint64, secret []byte) pluginwebhook.SendResult {
	if !deliverer.validAction(ctx, item, attempt, secret) {
		return authorizationDenied()
	}
	expected := pluginruntimeauth.ExpectedAction{
		InstallationID: deliverer.installationID,
		RequestID:      item.DeliveryID.String(),
		CapabilityKind: "webhook",
		CapabilityCode: item.Event.Type,
	}
	request := RuntimeAuthorizationRequest{
		InstallationID: expected.InstallationID,
		TargetScopeID:  item.TargetScopeID,
		TenantID:       item.TenantID,
		SubscriptionID: item.SubscriptionID,
		DeliveryID:     item.DeliveryID,
		EventID:        item.EventID,
		RequestID:      expected.RequestID,
		CapabilityKind: expected.CapabilityKind,
		CapabilityCode: expected.CapabilityCode,
	}
	facts, err := deliverer.provider.RuntimeAuthorization(ctx, request)
	defer clear(facts.IdentityJSON)
	defer clear(facts.DecisionJSON)
	if err != nil {
		return authorizationUnavailable()
	}
	if len(facts.IdentityJSON) == 0 || len(facts.DecisionJSON) == 0 {
		return authorizationDenied()
	}
	authorization, err := deliverer.verifier.Authorize(facts.IdentityJSON, facts.DecisionJSON, expected)
	if errors.Is(err, pluginruntimeauth.ErrTrustUnavailable) {
		return authorizationUnavailable()
	}
	if err != nil || authorization.InstallationID != expected.InstallationID ||
		authorization.RequestID != expected.RequestID || authorization.CapabilityKind != expected.CapabilityKind ||
		authorization.CapabilityCode != expected.CapabilityCode {
		return authorizationDenied()
	}
	return deliverer.delegate.DeliverV2(ctx, item, attempt, secret)
}

func (deliverer *AuthorizedDeliverer) validAction(ctx context.Context, item pluginwebhook.QueueItem,
	attempt uint64, secret []byte) bool {
	return deliverer != nil && ctx != nil && attempt > 0 && len(secret) > 0 &&
		deliverer.installationID != uuid.Nil && deliverer.provider != nil && deliverer.verifier != nil && deliverer.delegate != nil &&
		item.Schema == pluginwebhook.QueueSchemaV2 && item.TargetScopeID != uuid.Nil && item.TenantID != uuid.Nil &&
		item.TargetScopeID != item.TenantID && item.SubscriptionID != uuid.Nil && item.SecretVersionID != uuid.Nil &&
		item.DeliveryID != uuid.Nil && item.EventID != uuid.Nil && item.Event.ID == item.EventID.String() &&
		isSupportedWebhookEventType(item.Event.Type)
}

func isSupportedWebhookEventType(eventType string) bool {
	if !versionedWebhookEventType.MatchString(eventType) {
		return false
	}
	_, ok := supportedWebhookEventTypes[eventType]
	return ok
}

func authorizationDenied() pluginwebhook.SendResult {
	return pluginwebhook.SendResult{Code: "runtime_authorization_denied"}
}

func authorizationUnavailable() pluginwebhook.SendResult {
	return pluginwebhook.SendResult{Code: "runtime_authorization_unavailable", Retryable: true}
}
