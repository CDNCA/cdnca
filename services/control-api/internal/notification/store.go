package notification

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type AuditAppender interface {
	Append(context.Context, pgx.Tx, audit.Event) error
}

type Store struct {
	pool    *pgxpool.Pool
	auditor AuditAppender
	now     Clock

	guardsMu     sync.RWMutex
	replayGuards map[string]ReplayGuard
}

func NewStore(pool *pgxpool.Pool) (*Store, error) {
	if pool == nil {
		return nil, ErrInvalidStore
	}
	return NewStoreWithClock(pool, audit.New(pool), time.Now)
}

func NewStoreWithClock(pool *pgxpool.Pool, auditor AuditAppender, now Clock) (*Store, error) {
	if pool == nil || auditor == nil || now == nil {
		return nil, ErrInvalidStore
	}
	return &Store{pool: pool, auditor: auditor, now: now}, nil
}

func (s *Store) SaveTemplate(ctx context.Context, definition TemplateDefinition) error {
	if s == nil || s.pool == nil {
		return ErrInvalidStore
	}
	if _, err := compileTemplate(definition); err != nil {
		return err
	}
	result, err := s.pool.Exec(ctx, `
		INSERT INTO notification_templates (
			template_id, version, channel, subject, body, variables, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (template_id, version, channel) DO NOTHING`,
		definition.Ref.ID, definition.Ref.Version, definition.Ref.Channel,
		definition.Subject, definition.Body, definition.Variables, storeTime(s.now()))
	if err != nil {
		return fmt.Errorf("save notification template: %w", err)
	}
	if result.RowsAffected() != 1 {
		return ErrTemplateExists
	}
	return nil
}

func (s *Store) SetChannelSwitches(ctx context.Context, switches ChannelSwitches) error {
	if s == nil || s.pool == nil {
		return ErrInvalidStore
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE notification_channel_settings
		SET sms_enabled = $1, email_enabled = $2,
			revision = revision + 1, updated_at = $3
		WHERE singleton`, switches.SMS, switches.Email, storeTime(s.now()))
	if err != nil {
		return fmt.Errorf("update notification channel settings: %w", err)
	}
	return nil
}

func (s *Store) SetSubscription(
	ctx context.Context,
	scopeID, userID uuid.UUID,
	eventType string,
	subscription Subscription,
) error {
	if s == nil || s.pool == nil {
		return ErrInvalidStore
	}
	if scopeID == uuid.Nil || userID == uuid.Nil || !templateIDPattern.MatchString(eventType) {
		return ErrInvalidEnqueue
	}
	now := storeTime(s.now())
	result, err := s.pool.Exec(ctx, `
		INSERT INTO notification_subscriptions (
			scope_id, user_id, event_type, sms_enabled, email_enabled,
			revision, created_at, updated_at
		)
		SELECT scope.id, membership.user_id, $3, $4, $5, 1, $6, $6
		FROM access_scopes scope
		JOIN memberships membership
		  ON membership.scope_id = scope.id AND membership.user_id = $2
		WHERE scope.id = $1 AND scope.kind = 'tenant'
		ON CONFLICT (scope_id, user_id, event_type) DO UPDATE
		SET sms_enabled = EXCLUDED.sms_enabled,
			email_enabled = EXCLUDED.email_enabled,
			revision = notification_subscriptions.revision + 1,
			updated_at = EXCLUDED.updated_at`,
		scopeID, userID, eventType, subscription.SMS, subscription.Email, now)
	if err != nil {
		return fmt.Errorf("save notification subscription: %w", err)
	}
	if result.RowsAffected() != 1 {
		return ErrTenantScopeDenied
	}
	return nil
}

func (s *Store) Enqueue(ctx context.Context, request EnqueueRequest) (EnqueueResult, error) {
	if s == nil || s.pool == nil {
		return EnqueueResult{}, ErrInvalidStore
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return EnqueueResult{}, fmt.Errorf("begin notification enqueue: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	result, err := s.enqueueTx(ctx, tx, request)
	if err != nil {
		return EnqueueResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return EnqueueResult{}, fmt.Errorf("commit notification enqueue: %w", err)
	}
	return result, nil
}

func (s *Store) EnqueueTx(ctx context.Context, tx pgx.Tx, request EnqueueRequest) (EnqueueResult, error) {
	if s == nil || s.pool == nil || tx == nil {
		return EnqueueResult{}, ErrInvalidStore
	}
	savepoint, err := tx.Begin(ctx)
	if err != nil {
		return EnqueueResult{}, fmt.Errorf("begin notification enqueue savepoint: %w", err)
	}
	defer func() { _ = savepoint.Rollback(context.Background()) }()
	result, err := s.enqueueTx(ctx, savepoint, request)
	if err != nil {
		return EnqueueResult{}, err
	}
	if err := savepoint.Commit(ctx); err != nil {
		return EnqueueResult{}, fmt.Errorf("release notification enqueue savepoint: %w", err)
	}
	return result, nil
}

func (s *Store) EnqueueDispatchTx(
	ctx context.Context,
	tx pgx.Tx,
	request DispatchEnqueueRequest,
) (EnqueueResult, error) {
	if s == nil || s.pool == nil || tx == nil {
		return EnqueueResult{}, ErrInvalidStore
	}
	savepoint, err := tx.Begin(ctx)
	if err != nil {
		return EnqueueResult{}, fmt.Errorf("begin anonymous notification dispatch savepoint: %w", err)
	}
	defer func() { _ = savepoint.Rollback(context.Background()) }()
	if request.EventType == "" {
		request.EventType = EventTypeAccountRecovery
	}
	result, err := s.enqueueDispatchTx(ctx, savepoint, request)
	if err != nil {
		return EnqueueResult{}, err
	}
	if err := savepoint.Commit(ctx); err != nil {
		return EnqueueResult{}, fmt.Errorf("release anonymous notification dispatch savepoint: %w", err)
	}
	return result, nil
}

func (s *Store) enqueueTx(ctx context.Context, tx pgx.Tx, request EnqueueRequest) (EnqueueResult, error) {
	if err := validateEnqueueRequest(request); err != nil {
		return EnqueueResult{}, err
	}
	if err := requireRecipientMembership(ctx, tx, request.ScopeID, request.RecipientID, request.EventType); err != nil {
		return EnqueueResult{}, err
	}
	digest := enqueueRequestDigest(request)
	if replay, found, err := findReplay(ctx, tx, request, digest); err != nil {
		return EnqueueResult{}, err
	} else if found {
		return replay, nil
	}
	switches, subscription, runtimePolicy, err := readDeliverySettings(ctx, tx, request)
	if err != nil {
		return EnqueueResult{}, err
	}
	// The administrator's per-event switches apply to every member event;
	// events without a policy row keep the all-enabled default.
	if !runtimePolicy.Enabled {
		switches = ChannelSwitches{}
	} else {
		switches.SMS = switches.SMS && runtimePolicy.SMSEnabled
		switches.Email = switches.Email && runtimePolicy.EmailEnabled
	}
	channels, err := DecideChannels(request.Policy, switches, subscription)
	if err != nil {
		return EnqueueResult{}, err
	}

	catalog := NewCatalog()
	for _, channel := range channels {
		ref, exists := request.Templates[channel]
		if !exists || ref.Channel != channel {
			return EnqueueResult{}, ErrTemplateSelection
		}
		definition, err := loadTemplate(ctx, tx, ref)
		if err != nil {
			return EnqueueResult{}, err
		}
		if err := catalog.Register(definition); err != nil {
			return EnqueueResult{}, err
		}
	}
	now := storeTime(s.now())
	availableAt := now
	if request.Policy == DeliveryTenantSubscribed {
		availableAt = nextNotificationWindow(now, runtimePolicy)
	}
	engine, err := NewEngine(catalog, func() time.Time { return now })
	if err != nil {
		return EnqueueResult{}, err
	}
	plan, err := engine.Plan(PlanRequest{
		Identity: EventIdentity{
			TenantID: request.ScopeID.String(), RecipientID: request.RecipientID.String(),
			EventID: request.SourceEventID, EventType: request.EventType,
		},
		Policy: request.Policy, Switches: switches, Subscription: subscription,
		Templates: request.Templates, Contexts: request.Contexts,
		ContextValidationPolicies: request.ContextValidationPolicies,
	})
	if err != nil {
		return EnqueueResult{}, err
	}
	eventID, err := uuid.NewV7()
	if err != nil {
		return EnqueueResult{}, fmt.Errorf("generate notification event ID: %w", err)
	}
	insert, err := tx.Exec(ctx, `
		INSERT INTO notification_events (
			id, scope_id, recipient_user_id, source_event_id, event_type,
			delivery_policy, request_digest, created_at, subject_site_id, subject_package_id
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (scope_id, recipient_user_id, source_event_id, event_type) DO NOTHING`,
		eventID, request.ScopeID, request.RecipientID, request.SourceEventID,
		request.EventType, request.Policy, digest[:], now, request.SubjectSiteID, request.SubjectPackageID)
	if err != nil {
		return EnqueueResult{}, fmt.Errorf("insert notification event: %w", err)
	}
	if insert.RowsAffected() == 0 {
		replay, _, err := findReplay(ctx, tx, request, digest)
		return replay, err
	}

	if err := insertAdminInboxMessageTx(ctx, tx, request, subscription.Inbox, now); err != nil {
		return EnqueueResult{}, err
	}
	result := EnqueueResult{EventID: eventID, CreatedAt: now, Deliveries: make([]EnqueuedDelivery, 0, len(plan.Deliveries))}
	smsParams, err := encodeTemplateParams(templateParams(request.Contexts[ChannelSMS]))
	if err != nil {
		return EnqueueResult{}, err
	}
	for _, delivery := range plan.Deliveries {
		var params *string
		if delivery.Channel == ChannelSMS {
			params = smsParams
		}
		outboxID, err := uuid.NewV7()
		if err != nil {
			return EnqueueResult{}, fmt.Errorf("generate notification outbox ID: %w", err)
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO notification_outbox (
				id, scope_id, event_id, channel, template_id, template_version,
				subject, body, dedup_key, status, attempt_count, available_at,
				created_at, updated_at, generation, replay_of_outbox_id, template_params
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'pending', 0, $10, $10, $10, 1, NULL, $11::jsonb)`,
			outboxID, request.ScopeID, eventID, delivery.Channel,
			delivery.Template.ID, delivery.Template.Version, delivery.Subject,
			delivery.Body, delivery.DedupKey, availableAt, params)
		if err != nil {
			return EnqueueResult{}, fmt.Errorf("insert notification outbox: %w", err)
		}
		result.Deliveries = append(result.Deliveries, EnqueuedDelivery{
			OutboxID: outboxID, Channel: delivery.Channel, DedupKey: delivery.DedupKey, Status: "pending",
		})
		replayAt := availableAt
		for generation := 2; generation <= runtimePolicy.RepeatCount; generation++ {
			replayID, err := uuid.NewV7()
			if err != nil {
				return EnqueueResult{}, fmt.Errorf("generate notification replay outbox ID: %w", err)
			}
			replayAt = replayAt.Add(time.Duration(runtimePolicy.IntervalHours) * time.Hour)
			if request.Policy == DeliveryTenantSubscribed {
				replayAt = nextNotificationWindow(replayAt, runtimePolicy)
			}
			replayKey := replayDedupKey(delivery.DedupKey, digest, generation)
			_, err = tx.Exec(ctx, `INSERT INTO notification_outbox(
				id,scope_id,event_id,channel,template_id,template_version,subject,body,dedup_key,status,attempt_count,available_at,created_at,updated_at,generation,replay_of_outbox_id,template_params
			) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'pending',0,$10,$10,$10,$11,$12,$13::jsonb)`,
				replayID, request.ScopeID, eventID, delivery.Channel, delivery.Template.ID, delivery.Template.Version,
				delivery.Subject, delivery.Body, replayKey, replayAt, generation, outboxID, params)
			if err != nil {
				return EnqueueResult{}, fmt.Errorf("insert notification replay outbox: %w", err)
			}
			result.Deliveries = append(result.Deliveries, EnqueuedDelivery{OutboxID: replayID, Channel: delivery.Channel, DedupKey: replayKey, Status: "pending"})
		}
	}
	if err := s.auditor.Append(ctx, tx, audit.Event{
		ScopeID: request.ScopeID, ActorUserID: request.ActorUserID,
		Action: "notification.event.enqueue", ResourceType: "notification_event",
		ResourceID: eventID.String(), RequestID: request.AuditRequestID, Result: "success",
		Payload: map[string]any{
			"event_type": request.EventType, "delivery_policy": request.Policy,
			"outbox_count": len(result.Deliveries),
		},
	}); err != nil {
		return EnqueueResult{}, fmt.Errorf("audit notification enqueue: %w", err)
	}
	return result, nil
}

func (s *Store) enqueueDispatchTx(
	ctx context.Context,
	tx pgx.Tx,
	request DispatchEnqueueRequest,
) (EnqueueResult, error) {
	if err := validateDispatchEnqueueRequest(request); err != nil {
		return EnqueueResult{}, err
	}
	if err := requireAnonymousDispatchScope(ctx, tx, request.ScopeID, dispatchEventType(request)); err != nil {
		return EnqueueResult{}, err
	}
	eventType := dispatchEventType(request)
	digest := dispatchEnqueueRequestDigest(request)
	if replay, found, err := findDispatchReplay(ctx, tx, request, digest); err != nil {
		return EnqueueResult{}, err
	} else if found {
		return replay, nil
	}

	var switches ChannelSwitches
	if err := tx.QueryRow(ctx, `
		SELECT sms_enabled, email_enabled
		FROM notification_channel_settings WHERE singleton`).Scan(&switches.SMS, &switches.Email); err != nil {
		return EnqueueResult{}, fmt.Errorf("read anonymous notification channel settings: %w", err)
	}
	channels, err := DecideChannels(DeliverySystemRequired, switches, Subscription{})
	if err != nil {
		return EnqueueResult{}, err
	}
	if eventType == EventTypeAccountRegistrationVerification || eventType == EventTypeAccountLoginVerification {
		enabled := (request.SelectedChannel == ChannelEmail && switches.Email) ||
			(request.SelectedChannel == ChannelSMS && switches.SMS)
		if !enabled {
			return EnqueueResult{}, ErrInvalidPolicy
		}
		channels = []Channel{request.SelectedChannel}
	}
	deliveries := make([]Delivery, 0, len(channels))
	identity := EventIdentity{
		TenantID:    request.ScopeID.String(),
		RecipientID: "anonymous:" + request.AnonymousDispatchReference.String(),
		EventID:     request.SourceEventID,
		EventType:   eventType,
	}
	for _, channel := range channels {
		ref, exists := request.Templates[channel]
		if !exists || ref.Channel != channel {
			return EnqueueResult{}, ErrTemplateSelection
		}
		definition, err := loadTemplate(ctx, tx, ref)
		if err != nil {
			return EnqueueResult{}, err
		}
		if !validDispatchTemplateSource(definition) {
			return EnqueueResult{}, ErrRenderLimit
		}
		dedupKey, err := DedupKey(identity, ref)
		if err != nil {
			return EnqueueResult{}, err
		}
		deliveries = append(deliveries, Delivery{
			Channel: channel, Template: ref, Subject: definition.Subject,
			Body: definition.Body, DedupKey: dedupKey,
		})
	}

	now := storeTime(s.now())
	eventID, err := uuid.NewV7()
	if err != nil {
		return EnqueueResult{}, fmt.Errorf("generate anonymous notification event ID: %w", err)
	}
	insert, err := tx.Exec(ctx, `
		INSERT INTO notification_events (
			id, scope_id, recipient_user_id, source_event_id, event_type,
			delivery_policy, request_digest, created_at, recipient_kind,
			anonymous_dispatch_reference
		) VALUES ($1, $2, NULL, $3, $4, $5, $6, $7, 'anonymous', $8)
		ON CONFLICT DO NOTHING`,
		eventID, request.ScopeID, request.SourceEventID, eventType,
		DeliverySystemRequired, digest[:], now, request.AnonymousDispatchReference)
	if err != nil {
		return EnqueueResult{}, fmt.Errorf("insert anonymous notification event: %w", err)
	}
	if insert.RowsAffected() == 0 {
		replay, found, err := findDispatchReplay(ctx, tx, request, digest)
		if err != nil {
			return EnqueueResult{}, err
		}
		if found {
			return replay, nil
		}
		return EnqueueResult{}, ErrEventConflict
	}

	result := EnqueueResult{
		EventID: eventID, CreatedAt: now,
		Deliveries: make([]EnqueuedDelivery, 0, len(deliveries)),
	}
	for _, delivery := range deliveries {
		outboxID, err := uuid.NewV7()
		if err != nil {
			return EnqueueResult{}, fmt.Errorf("generate anonymous notification outbox ID: %w", err)
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO notification_outbox (
				id, scope_id, event_id, channel, template_id, template_version,
				subject, body, dedup_key, status, attempt_count, available_at,
				created_at, updated_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'pending', 0, $10, $10, $10)`,
			outboxID, request.ScopeID, eventID, delivery.Channel,
			delivery.Template.ID, delivery.Template.Version, delivery.Subject,
			delivery.Body, delivery.DedupKey, now)
		if err != nil {
			return EnqueueResult{}, fmt.Errorf("insert anonymous notification outbox: %w", err)
		}
		result.Deliveries = append(result.Deliveries, EnqueuedDelivery{
			OutboxID: outboxID, Channel: delivery.Channel,
			DedupKey: delivery.DedupKey, Status: OutboxPending,
		})
	}
	if err := s.auditor.Append(ctx, tx, audit.Event{
		ScopeID: request.ScopeID,
		Action:  "notification.event.enqueue", ResourceType: "notification_event",
		ResourceID: eventID.String(), RequestID: request.AuditRequestID, Result: "success",
		Payload: map[string]any{
			"recipient_kind": "anonymous", "event_type": eventType,
			"delivery_policy": DeliverySystemRequired, "outbox_count": len(result.Deliveries),
		},
	}); err != nil {
		return EnqueueResult{}, fmt.Errorf("audit anonymous notification enqueue: %w", err)
	}
	return result, nil
}

func validateEnqueueRequest(request EnqueueRequest) error {
	if request.ScopeID == uuid.Nil || request.RecipientID == uuid.Nil ||
		!validIdentityPart(request.SourceEventID) || !templateIDPattern.MatchString(request.EventType) ||
		!validIdentityPart(request.AuditRequestID) || len(request.AuditRequestID) > 128 {
		return ErrInvalidEnqueue
	}
	if validAnonymousEventType(request.EventType) {
		return ErrInvalidEnqueue
	}
	if request.ActorUserID != nil && *request.ActorUserID == uuid.Nil {
		return ErrInvalidEnqueue
	}
	if request.SubjectSiteID != nil && *request.SubjectSiteID == uuid.Nil ||
		request.SubjectPackageID != nil && *request.SubjectPackageID == uuid.Nil {
		return ErrInvalidEnqueue
	}
	if request.Policy != DeliveryTenantSubscribed && request.Policy != DeliverySystemRequired {
		return ErrInvalidPolicy
	}
	if err := validateContextValidationPolicies(
		request.EventType, request.Templates, request.Contexts, request.ContextValidationPolicies,
	); err != nil {
		return ErrInvalidEnqueue
	}
	for channel, context := range request.Contexts {
		if channel != ChannelSMS && channel != ChannelEmail {
			return ErrInvalidEnqueue
		}
		if err := validateContextResourcesWithPolicy(context, request.ContextValidationPolicies[channel]); err != nil {
			return err
		}
	}
	for channel := range request.Templates {
		if channel != ChannelSMS && channel != ChannelEmail {
			return ErrInvalidEnqueue
		}
	}
	return nil
}

func validateDispatchEnqueueRequest(request DispatchEnqueueRequest) error {
	if request.ScopeID == uuid.Nil || request.AnonymousDispatchReference == uuid.Nil ||
		!validIdentityPart(request.SourceEventID) ||
		!validIdentityPart(request.AuditRequestID) || len(request.AuditRequestID) > 128 {
		return ErrInvalidDispatch
	}
	eventType := dispatchEventType(request)
	if !validAnonymousEventType(eventType) {
		return ErrInvalidDispatch
	}
	if eventType == EventTypeAccountRegistrationVerification || eventType == EventTypeAccountLoginVerification {
		if (request.SelectedChannel != ChannelEmail && request.SelectedChannel != ChannelSMS) ||
			len(request.Templates) != 1 {
			return ErrInvalidDispatch
		}
		if _, exists := request.Templates[request.SelectedChannel]; !exists {
			return ErrInvalidDispatch
		}
	} else if request.SelectedChannel != "" {
		return ErrInvalidDispatch
	}
	for channel, ref := range request.Templates {
		if (channel != ChannelSMS && channel != ChannelEmail) ||
			ref.Channel != channel || !validTemplateRef(ref) {
			return ErrInvalidDispatch
		}
	}
	return nil
}

func dispatchEventType(request DispatchEnqueueRequest) string {
	if request.EventType == "" {
		return EventTypeAccountRecovery
	}
	return request.EventType
}

func validAnonymousEventType(eventType string) bool {
	return eventType == EventTypeAccountRecovery || eventType == EventTypeAccountRegistrationVerification ||
		eventType == EventTypeAccountLoginVerification
}

// requireRecipientMembership admits tenant members for every event and
// platform members only for the platform operations alerts.
func requireRecipientMembership(ctx context.Context, tx pgx.Tx, scopeID, userID uuid.UUID, eventType string) error {
	var allowed bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM access_scopes scope
			JOIN memberships membership ON membership.scope_id = scope.id
			WHERE scope.id = $1 AND membership.user_id = $2 AND (scope.kind = 'tenant' OR
			      (scope.kind = 'platform' AND scope.tenant_id IS NULL AND $3))
		)`, scopeID, userID, PlatformEventType(eventType)).Scan(&allowed); err != nil {
		return fmt.Errorf("authorize notification tenant: %w", err)
	}
	if !allowed {
		return ErrTenantScopeDenied
	}
	return nil
}

func requireTenantScope(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID) error {
	var allowed bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM access_scopes
			WHERE id = $1 AND kind = 'tenant'
		)`, scopeID).Scan(&allowed); err != nil {
		return fmt.Errorf("authorize anonymous notification tenant: %w", err)
	}
	if !allowed {
		return ErrTenantScopeDenied
	}
	return nil
}

func requireAnonymousDispatchScope(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, eventType string) error {
	if eventType != EventTypeAccountRecovery {
		return requireTenantScope(ctx, tx, scopeID)
	}
	var allowed bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM access_scopes
			WHERE id = $1 AND kind IN ('tenant', 'platform')
		)`, scopeID).Scan(&allowed); err != nil {
		return fmt.Errorf("authorize anonymous account recovery scope: %w", err)
	}
	if !allowed {
		return ErrTenantScopeDenied
	}
	return nil
}

// defaultSubscription reads the event's default channels (316; tenant
// events default on, see DefaultChannels). Older
// schemas have no such columns (or no policy table) and mean no channel; the
// row is read as JSON so a missing column is simply absent.
func defaultSubscription(ctx context.Context, tx pgx.Tx, eventType string) (Subscription, error) {
	var present bool
	if err := tx.QueryRow(ctx, `SELECT to_regclass('notification_event_policies') IS NOT NULL`).Scan(&present); err != nil || !present {
		return Subscription{}, err
	}
	var supported, defaultSMS, defaultEmail bool
	err := tx.QueryRow(ctx, `SELECT policy.supported, COALESCE((to_jsonb(policy)->>'default_sms')::boolean, false),
		COALESCE((to_jsonb(policy)->>'default_email')::boolean, false)
		FROM notification_event_policies policy WHERE policy.event_type=$1`, eventType).Scan(&supported, &defaultSMS, &defaultEmail)
	if err == pgx.ErrNoRows {
		return Subscription{}, nil
	}
	if err != nil {
		return Subscription{}, err
	}
	var subscription Subscription
	subscription.SMS, subscription.Email = DefaultChannels(eventType, supported, defaultSMS, defaultEmail)
	return subscription, nil
}

func readDeliverySettings(ctx context.Context, tx pgx.Tx, request EnqueueRequest) (ChannelSwitches, Subscription, DeliveryRuntimePolicy, error) {
	var switches ChannelSwitches
	if err := tx.QueryRow(ctx, `
		SELECT sms_enabled, email_enabled
		FROM notification_channel_settings WHERE singleton`).Scan(&switches.SMS, &switches.Email); err != nil {
		return ChannelSwitches{}, Subscription{}, DeliveryRuntimePolicy{}, fmt.Errorf("read notification channel settings: %w", err)
	}
	var subscription Subscription
	// inbox_enabled (546) is read as JSON so an older schema without the
	// column keeps the in-app copy on.
	err := tx.QueryRow(ctx, `
		SELECT sms_enabled, email_enabled, COALESCE((to_jsonb(subscription)->>'inbox_enabled')::boolean, true)
		FROM notification_subscriptions subscription
		WHERE scope_id = $1 AND user_id = $2 AND event_type = $3`,
		request.ScopeID, request.RecipientID, request.EventType).Scan(&subscription.SMS, &subscription.Email, &subscription.Inbox)
	if err == pgx.ErrNoRows {
		// A member who never chose for this event gets the event's default
		// channels (316: notification_event_policies.default_email/default_sms)
		// and keeps the in-app copy (546 default).
		subscription, err = defaultSubscription(ctx, tx, request.EventType)
		subscription.Inbox = true
	}
	if err != nil {
		return ChannelSwitches{}, Subscription{}, DeliveryRuntimePolicy{}, fmt.Errorf("read notification subscription: %w", err)
	}
	policy := DeliveryRuntimePolicy{Enabled: true, SMSEnabled: true, EmailEnabled: true, RepeatCount: 1, IntervalHours: 24, WindowMode: "all_day", WindowStart: 0, WindowEnd: 1439, Timezone: "Asia/Shanghai"}
	var start, end int
	err = tx.QueryRow(ctx, `SELECT window_mode,window_start_minute,window_end_minute,timezone FROM notification_delivery_policy WHERE singleton`).Scan(&policy.WindowMode, &start, &end, &policy.Timezone)
	if err == nil {
		policy.WindowStart, policy.WindowEnd = start, end
	}
	if err != nil && err != pgx.ErrNoRows {
		return ChannelSwitches{}, Subscription{}, DeliveryRuntimePolicy{}, fmt.Errorf("read notification delivery policy: %w", err)
	}
	err = tx.QueryRow(ctx, `SELECT enabled,sms_enabled,email_enabled,repeat_count,interval_hours FROM notification_event_policies WHERE event_type=$1`, request.EventType).Scan(&policy.Enabled, &policy.SMSEnabled, &policy.EmailEnabled, &policy.RepeatCount, &policy.IntervalHours)
	if err != nil && err != pgx.ErrNoRows {
		return ChannelSwitches{}, Subscription{}, DeliveryRuntimePolicy{}, fmt.Errorf("read notification event policy: %w", err)
	}
	return switches, subscription, policy, nil
}

func nextNotificationWindow(now time.Time, policy DeliveryRuntimePolicy) time.Time {
	if policy.WindowMode != "custom" {
		return now
	}
	location, err := time.LoadLocation(policy.Timezone)
	if err != nil {
		location = time.UTC
	}
	local := now.In(location)
	minute := local.Hour()*60 + local.Minute()
	start, end := policy.WindowStart, policy.WindowEnd
	if start == end || (start < end && minute >= start && minute <= end) || (start > end && (minute >= start || minute <= end)) {
		return now
	}
	day := local
	if start < end && minute > end {
		day = day.Add(24 * time.Hour)
	}
	if start > end && minute > end && minute < start { /* same day */
	}
	if start > end && minute <= end { /* next day not needed */
	}
	window := time.Date(day.Year(), day.Month(), day.Day(), start/60, start%60, 0, 0, location)
	if !window.After(local) {
		window = window.Add(24 * time.Hour)
	}
	return window.In(now.Location())
}

func loadTemplate(ctx context.Context, tx pgx.Tx, ref TemplateRef) (TemplateDefinition, error) {
	definition := TemplateDefinition{Ref: ref}
	err := tx.QueryRow(ctx, `
		SELECT subject, body, variables
		FROM notification_templates
		WHERE template_id = $1 AND version = $2 AND channel = $3`,
		ref.ID, ref.Version, ref.Channel).Scan(&definition.Subject, &definition.Body, &definition.Variables)
	if err == pgx.ErrNoRows {
		return TemplateDefinition{}, ErrTemplateNotFound
	}
	if err != nil {
		return TemplateDefinition{}, fmt.Errorf("read notification template: %w", err)
	}
	return definition, nil
}

func validDispatchTemplateSource(definition TemplateDefinition) bool {
	if definition.Ref.Channel == ChannelSMS {
		return len(definition.Body) <= MaxSMSBodyBytes
	}
	return utf8.RuneCountInString(definition.Subject) <= MaxEmailSubjectRunes &&
		len(definition.Body) <= MaxEmailBodyBytes
}

func findReplay(
	ctx context.Context,
	tx pgx.Tx,
	request EnqueueRequest,
	digest [sha256.Size]byte,
) (EnqueueResult, bool, error) {
	var result EnqueueResult
	var storedDigest []byte
	err := tx.QueryRow(ctx, `
		SELECT id, request_digest, created_at
		FROM notification_events
		WHERE scope_id = $1 AND recipient_user_id = $2 AND source_event_id = $3 AND event_type = $4`,
		request.ScopeID, request.RecipientID, request.SourceEventID, request.EventType,
	).Scan(&result.EventID, &storedDigest, &result.CreatedAt)
	if err == pgx.ErrNoRows {
		return EnqueueResult{}, false, nil
	}
	if err != nil {
		return EnqueueResult{}, false, fmt.Errorf("read replayed notification event: %w", err)
	}
	if !bytes.Equal(storedDigest, digest[:]) {
		return EnqueueResult{}, true, ErrEventConflict
	}
	rows, err := tx.Query(ctx, `
		SELECT id, channel, dedup_key, status
		FROM notification_outbox
		WHERE scope_id = $1 AND event_id = $2
		ORDER BY CASE channel WHEN 'sms' THEN 1 ELSE 2 END`, request.ScopeID, result.EventID)
	if err != nil {
		return EnqueueResult{}, true, fmt.Errorf("read replayed notification outbox: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var delivery EnqueuedDelivery
		if err := rows.Scan(&delivery.OutboxID, &delivery.Channel, &delivery.DedupKey, &delivery.Status); err != nil {
			return EnqueueResult{}, true, fmt.Errorf("scan replayed notification outbox: %w", err)
		}
		result.Deliveries = append(result.Deliveries, delivery)
	}
	if err := rows.Err(); err != nil {
		return EnqueueResult{}, true, fmt.Errorf("iterate replayed notification outbox: %w", err)
	}
	result.Replayed = true
	return result, true, nil
}

func findDispatchReplay(
	ctx context.Context,
	tx pgx.Tx,
	request DispatchEnqueueRequest,
	digest [sha256.Size]byte,
) (EnqueueResult, bool, error) {
	var result EnqueueResult
	var storedDigest []byte
	var storedReference uuid.UUID
	err := tx.QueryRow(ctx, `
		SELECT id, request_digest, created_at, anonymous_dispatch_reference
		FROM notification_events
		WHERE scope_id = $1 AND source_event_id = $2 AND event_type = $3
		  AND recipient_kind = 'anonymous'`,
		request.ScopeID, request.SourceEventID, dispatchEventType(request),
	).Scan(&result.EventID, &storedDigest, &result.CreatedAt, &storedReference)
	if err == pgx.ErrNoRows {
		return EnqueueResult{}, false, nil
	}
	if err != nil {
		return EnqueueResult{}, false, fmt.Errorf("read replayed anonymous notification event: %w", err)
	}
	if storedReference != request.AnonymousDispatchReference || !bytes.Equal(storedDigest, digest[:]) {
		return EnqueueResult{}, true, ErrEventConflict
	}
	rows, err := tx.Query(ctx, `
		SELECT id, channel, dedup_key, status
		FROM notification_outbox
		WHERE scope_id = $1 AND event_id = $2
		ORDER BY CASE channel WHEN 'sms' THEN 1 ELSE 2 END`, request.ScopeID, result.EventID)
	if err != nil {
		return EnqueueResult{}, true, fmt.Errorf("read replayed anonymous notification outbox: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var delivery EnqueuedDelivery
		if err := rows.Scan(&delivery.OutboxID, &delivery.Channel, &delivery.DedupKey, &delivery.Status); err != nil {
			return EnqueueResult{}, true, fmt.Errorf("scan replayed anonymous notification outbox: %w", err)
		}
		result.Deliveries = append(result.Deliveries, delivery)
	}
	if err := rows.Err(); err != nil {
		return EnqueueResult{}, true, fmt.Errorf("iterate replayed anonymous notification outbox: %w", err)
	}
	result.Replayed = true
	return result, true, nil
}

func enqueueRequestDigest(request EnqueueRequest) [sha256.Size]byte {
	hash := sha256.New()
	for _, value := range []string{
		"notification-enqueue-v1", request.ScopeID.String(), request.RecipientID.String(),
		request.SourceEventID, request.EventType, string(request.Policy),
	} {
		writeLengthPrefixed(hash, value)
	}
	templateChannels := make([]Channel, 0, len(request.Templates))
	for channel := range request.Templates {
		templateChannels = append(templateChannels, channel)
	}
	sort.Slice(templateChannels, func(i, j int) bool { return templateChannels[i] < templateChannels[j] })
	for _, channel := range templateChannels {
		ref := request.Templates[channel]
		for _, value := range []string{
			"template", string(channel), ref.ID, fmt.Sprint(ref.Version), string(ref.Channel),
		} {
			writeLengthPrefixed(hash, value)
		}
	}
	contextChannels := make([]Channel, 0, len(request.Contexts))
	for channel := range request.Contexts {
		contextChannels = append(contextChannels, channel)
	}
	sort.Slice(contextChannels, func(i, j int) bool { return contextChannels[i] < contextChannels[j] })
	for _, channel := range contextChannels {
		names := make([]string, 0, len(request.Contexts[channel]))
		for name := range request.Contexts[channel] {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			for _, value := range []string{"context", string(channel), name, request.Contexts[channel][name].value} {
				writeLengthPrefixed(hash, value)
			}
		}
	}
	// Only present subjects extend the digest, so replays of requests that
	// predate migration 502 keep their stored digest.
	if request.SubjectSiteID != nil {
		writeLengthPrefixed(hash, "subject_site")
		writeLengthPrefixed(hash, request.SubjectSiteID.String())
	}
	if request.SubjectPackageID != nil {
		writeLengthPrefixed(hash, "subject_package")
		writeLengthPrefixed(hash, request.SubjectPackageID.String())
	}
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return digest
}

func dispatchEnqueueRequestDigest(request DispatchEnqueueRequest) [sha256.Size]byte {
	hash := sha256.New()
	for _, value := range []string{
		"notification-anonymous-dispatch-v1", request.ScopeID.String(),
		request.SourceEventID, dispatchEventType(request), string(request.SelectedChannel),
		request.AnonymousDispatchReference.String(), string(DeliverySystemRequired),
	} {
		writeLengthPrefixed(hash, value)
	}
	channels := make([]Channel, 0, len(request.Templates))
	for channel := range request.Templates {
		channels = append(channels, channel)
	}
	sort.Slice(channels, func(i, j int) bool { return channels[i] < channels[j] })
	for _, channel := range channels {
		ref := request.Templates[channel]
		for _, value := range []string{
			"template", string(channel), ref.ID, fmt.Sprint(ref.Version), string(ref.Channel),
		} {
			writeLengthPrefixed(hash, value)
		}
	}
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return digest
}

// templateParams keeps the public template variables for template-based SMS
// providers. Sensitive values never reach here: enqueue validation rejects them.
func templateParams(context TemplateContext) map[string]string {
	if len(context) == 0 {
		return nil
	}
	params := make(map[string]string, len(context))
	for name, value := range context {
		if value.sensitive {
			return nil
		}
		params[name] = value.value
	}
	return params
}

// encodeTemplateParams returns SQL NULL for an empty set (pgx would store a
// nil map as the JSON literal null).
func encodeTemplateParams(params map[string]string) (*string, error) {
	if len(params) == 0 {
		return nil, nil
	}
	encoded, err := json.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("encode notification template params: %w", err)
	}
	value := string(encoded)
	return &value, nil
}

func storeTime(value time.Time) time.Time {
	return value.UTC().Truncate(time.Microsecond)
}

// insertAdminInboxMessageTx copies a platform operations event for a
// platform member into the administrator message center,
// and a tenant in-app event (InboxEventType) into the member's message
// center (/v1/account/inbox, N23), whatever the email/SMS switches decided;
// ticket events only while the member keeps the in-app choice (inbox, 546).
// Only public template values are kept; the console renders the text per
// language.
func insertAdminInboxMessageTx(ctx context.Context, tx pgx.Tx, request EnqueueRequest, inbox bool, now time.Time) error {
	if !PlatformEventType(request.EventType) && !InboxEventType(request.EventType) {
		return nil
	}
	var platform bool
	if err := tx.QueryRow(ctx, `SELECT kind='platform' AND tenant_id IS NULL FROM access_scopes WHERE id=$1`, request.ScopeID).Scan(&platform); err != nil {
		return fmt.Errorf("read notification scope kind: %w", err)
	}
	if !inboxCopy(platform, request.EventType, inbox) {
		return nil
	}
	params := map[string]string{}
	for _, context := range request.Contexts {
		for name, value := range context {
			if !value.sensitive {
				params[name] = value.value
			}
		}
	}
	encoded, err := json.Marshal(params)
	if err != nil || len(encoded) > 16384 {
		return fmt.Errorf("encode admin inbox params: %w", ErrContextLimit)
	}
	id, err := uuid.NewV7()
	if err != nil {
		return fmt.Errorf("generate admin inbox message ID: %w", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO admin_inbox_messages(id,scope_id,recipient_user_id,event_type,source_event_id,params,created_at)
		VALUES($1,$2,$3,$4,$5,$6::jsonb,$7) ON CONFLICT (recipient_user_id,event_type,source_event_id) DO NOTHING`,
		id, request.ScopeID, request.RecipientID, request.EventType, request.SourceEventID, string(encoded), now); err != nil {
		return fmt.Errorf("insert admin inbox message: %w", err)
	}
	return nil
}
