package pluginwebhookcontrol

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

var (
	ErrInvalidInput          = errors.New("invalid plugin webhook input")
	ErrInvalidConfig         = errors.New("invalid plugin webhook configuration")
	ErrPermissionDenied      = errors.New("plugin webhook permission denied")
	ErrNotFound              = errors.New("plugin webhook not found")
	ErrIdempotencyConflict   = errors.New("plugin webhook idempotency conflict")
	ErrIdempotencyExpired    = errors.New("plugin webhook idempotency receipt expired")
	ErrStateConflict         = errors.New("plugin webhook state conflict")
	ErrDeliveryNotReplayable = errors.New("plugin webhook delivery is not replayable")
	ErrRotationPending       = errors.New("plugin webhook rotation already pending")
	ErrRevisionConflict      = errors.New("plugin webhook revision conflict")
	ErrTargetForbidden       = errors.New("plugin webhook target forbidden")
	ErrEntitlementDenied     = errors.New("plugin webhook entitlement denied")
	ErrQuotaExceeded         = errors.New("plugin webhook quota exceeded")
	ErrRateLimited           = errors.New("plugin webhook rate limited")
	ErrStoreUnavailable      = errors.New("plugin webhook store unavailable")
	ErrSecretUnavailable     = errors.New("plugin webhook secret unavailable")
	ErrResultUnknown         = errors.New("plugin webhook result unknown")
)

const (
	ScopeTenant   = "tenant"
	ScopePlatform = "platform"

	PermissionRead   = "plugin_webhooks.read"
	PermissionManage = "plugin_webhooks.manage"

	EventTypeTest = "io.cdnca.webhook.v1.test"
)

type Actor struct {
	ActorUserID   uuid.UUID
	ActorScopeID  uuid.UUID
	TargetScopeID uuid.UUID
	ScopeKind     string
	rawSession    string
}

const redactedActor = "pluginwebhookcontrol.Actor{session:redacted}"

func NewActor(userID, actorScopeID, targetScopeID uuid.UUID, scopeKind, rawSession string) (Actor, error) {
	actor := Actor{ActorUserID: userID, ActorScopeID: actorScopeID, TargetScopeID: targetScopeID, ScopeKind: scopeKind, rawSession: rawSession}
	if actor.validate() != nil || rawSession == "" {
		return Actor{}, ErrPermissionDenied
	}
	return actor, nil
}

func (Actor) String() string                 { return redactedActor }
func (Actor) GoString() string               { return redactedActor }
func (Actor) Format(state fmt.State, _ rune) { _, _ = state.Write([]byte(redactedActor)) }
func (Actor) MarshalJSON() ([]byte, error)   { return json.Marshal(redactedActor) }

func (actor Actor) validate() error {
	if actor.ActorUserID == uuid.Nil || actor.ActorScopeID == uuid.Nil || actor.TargetScopeID == uuid.Nil ||
		(actor.ScopeKind != ScopeTenant && actor.ScopeKind != ScopePlatform) ||
		actor.ScopeKind == ScopeTenant && actor.ActorScopeID != actor.TargetScopeID {
		return ErrPermissionDenied
	}
	return nil
}

func (actor Actor) Valid() bool { return actor.validate() == nil }

type CreateSubscriptionRequest struct {
	Name                        string
	TargetURL                   string
	EventTypes                  []string
	InstallationAuthorizationID *uuid.UUID
	// SiteIDs limits the subscription to site-bound events of these sites
	// (nil = all sites and all tenant-level events).
	SiteIDs        []uuid.UUID
	IdempotencyKey string
}

type WriteRequest struct {
	IdempotencyKey string
	Revision       uint64
}

type Subscription struct {
	ID                          uuid.UUID   `json:"id"`
	TenantScopeID               uuid.UUID   `json:"tenant_scope_id"`
	Name                        string      `json:"name"`
	TargetURL                   string      `json:"target_url"`
	EventTypes                  []string    `json:"event_types"`
	InstallationAuthorizationID *uuid.UUID  `json:"installation_authorization_id,omitempty"`
	InstallationID              *uuid.UUID  `json:"installation_id,omitempty"`
	PluginID                    *string     `json:"plugin_id,omitempty"`
	SiteIDs                     []uuid.UUID `json:"site_ids,omitempty"`
	Status                      string      `json:"status"`
	Revision                    uint64      `json:"revision"`
	ActiveSecretVersionID       uuid.UUID   `json:"active_secret_version_id"`
	CreatedAt                   time.Time   `json:"created_at"`
	UpdatedAt                   time.Time   `json:"updated_at"`
}

type Delivery struct {
	ID             uuid.UUID  `json:"id"`
	SubscriptionID uuid.UUID  `json:"subscription_id"`
	EventID        uuid.UUID  `json:"event_id"`
	ReplayOf       *uuid.UUID `json:"replay_of"`
	Status         string     `json:"status"`
	AttemptCount   uint64     `json:"attempt_count"`
	NextAttemptAt  *time.Time `json:"next_attempt_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	CompletedAt    *time.Time `json:"completed_at,omitempty"`
}

type SubscriptionReceipt struct {
	Subscription Subscription `json:"subscription"`
	Secret       string       `json:"secret"`
}

const redactedSubscriptionReceipt = "pluginwebhookcontrol.SubscriptionReceipt{secret:redacted}"

func (SubscriptionReceipt) String() string   { return redactedSubscriptionReceipt }
func (SubscriptionReceipt) GoString() string { return redactedSubscriptionReceipt }
func (SubscriptionReceipt) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte(redactedSubscriptionReceipt))
}

type DeliveryReceipt struct {
	Delivery Delivery `json:"delivery"`
}

type RotationReceipt struct {
	RotationID           uuid.UUID `json:"rotation_id"`
	KeyID                uuid.UUID `json:"key_id"`
	Status               string    `json:"status"`
	ExpiresAt            time.Time `json:"expires_at"`
	Secret               string    `json:"secret"`
	SubscriptionRevision uint64    `json:"subscription_revision"`
}

const redactedRotationReceipt = "pluginwebhookcontrol.RotationReceipt{secret:redacted}"

func (RotationReceipt) String() string   { return redactedRotationReceipt }
func (RotationReceipt) GoString() string { return redactedRotationReceipt }
func (RotationReceipt) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte(redactedRotationReceipt))
}

type SubscriptionResult struct {
	Subscription Subscription `json:"subscription"`
}

type ListQuery struct {
	Cursor string
	Limit  int
}

type SubscriptionPage struct {
	Items      []Subscription `json:"items"`
	NextCursor string         `json:"next_cursor,omitempty"`
}

type DeliveryPage struct {
	Items      []Delivery `json:"items"`
	NextCursor string     `json:"next_cursor,omitempty"`
}

type WriteResult[T any] struct {
	Value    T
	Replayed bool
}

type Domain interface {
	ListSubscriptions(context.Context, Actor, ListQuery) (SubscriptionPage, error)
	CreateSubscription(context.Context, Actor, CreateSubscriptionRequest) (WriteResult[SubscriptionReceipt], error)
	GetSubscription(context.Context, Actor, uuid.UUID) (Subscription, error)
	CreateTestDelivery(context.Context, Actor, uuid.UUID, WriteRequest) (WriteResult[DeliveryReceipt], error)
	ListDeliveries(context.Context, Actor, uuid.UUID, ListQuery) (DeliveryPage, error)
	GetDelivery(context.Context, Actor, uuid.UUID, uuid.UUID) (Delivery, error)
	ReplayDelivery(context.Context, Actor, uuid.UUID, uuid.UUID, WriteRequest) (WriteResult[DeliveryReceipt], error)
	RotateSecret(context.Context, Actor, uuid.UUID, WriteRequest) (WriteResult[RotationReceipt], error)
	ActivateSecret(context.Context, Actor, uuid.UUID, uuid.UUID, WriteRequest) (WriteResult[SubscriptionResult], error)
	RevokeSubscription(context.Context, Actor, uuid.UUID, WriteRequest) (WriteResult[SubscriptionResult], error)
	ReplayRange(context.Context, Actor, uuid.UUID, ReplayRangeRequest) (ReplayRangeResult, error)
}

// UnimplementedDomain lets narrow adapters implement only methods they exercise.
type UnimplementedDomain struct{}

func (UnimplementedDomain) ListSubscriptions(context.Context, Actor, ListQuery) (SubscriptionPage, error) {
	return SubscriptionPage{}, ErrStoreUnavailable
}
func (UnimplementedDomain) CreateSubscription(context.Context, Actor, CreateSubscriptionRequest) (WriteResult[SubscriptionReceipt], error) {
	return WriteResult[SubscriptionReceipt]{}, ErrStoreUnavailable
}
func (UnimplementedDomain) GetSubscription(context.Context, Actor, uuid.UUID) (Subscription, error) {
	return Subscription{}, ErrStoreUnavailable
}
func (UnimplementedDomain) CreateTestDelivery(context.Context, Actor, uuid.UUID, WriteRequest) (WriteResult[DeliveryReceipt], error) {
	return WriteResult[DeliveryReceipt]{}, ErrStoreUnavailable
}
func (UnimplementedDomain) ListDeliveries(context.Context, Actor, uuid.UUID, ListQuery) (DeliveryPage, error) {
	return DeliveryPage{}, ErrStoreUnavailable
}
func (UnimplementedDomain) GetDelivery(context.Context, Actor, uuid.UUID, uuid.UUID) (Delivery, error) {
	return Delivery{}, ErrStoreUnavailable
}
func (UnimplementedDomain) ReplayDelivery(context.Context, Actor, uuid.UUID, uuid.UUID, WriteRequest) (WriteResult[DeliveryReceipt], error) {
	return WriteResult[DeliveryReceipt]{}, ErrStoreUnavailable
}
func (UnimplementedDomain) RotateSecret(context.Context, Actor, uuid.UUID, WriteRequest) (WriteResult[RotationReceipt], error) {
	return WriteResult[RotationReceipt]{}, ErrStoreUnavailable
}
func (UnimplementedDomain) ActivateSecret(context.Context, Actor, uuid.UUID, uuid.UUID, WriteRequest) (WriteResult[SubscriptionResult], error) {
	return WriteResult[SubscriptionResult]{}, ErrStoreUnavailable
}
func (UnimplementedDomain) RevokeSubscription(context.Context, Actor, uuid.UUID, WriteRequest) (WriteResult[SubscriptionResult], error) {
	return WriteResult[SubscriptionResult]{}, ErrStoreUnavailable
}
func (UnimplementedDomain) ReplayRange(context.Context, Actor, uuid.UUID, ReplayRangeRequest) (ReplayRangeResult, error) {
	return ReplayRangeResult{}, ErrStoreUnavailable
}

type RateLimitError struct{ RetryAfter time.Duration }

func (err RateLimitError) Error() string { return ErrRateLimited.Error() }
func (err RateLimitError) Unwrap() error { return ErrRateLimited }
