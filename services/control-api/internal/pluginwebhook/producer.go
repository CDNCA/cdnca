package pluginwebhook

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const DomainEventOperation = "plugin_webhook.domain_event.publish"

type DomainEventProducer struct {
	pool *pgxpool.Pool
}

// DomainEventRequest publishes one domain event to one subscription. RequestID
// is the source fact id (shared by every subscription's copy of the event);
// Subject names the resource, e.g. "site/<uuid>".
type DomainEventRequest struct {
	SubscriptionID uuid.UUID
	EventType      string
	Subject        string
	RequestID      string
	Traceparent    *string
	OccurredAt     time.Time
	Data           json.RawMessage
}

type DomainEventResult struct {
	EventID        uuid.UUID
	DeliveryID     uuid.UUID
	Sequence       uint64
	IdempotencyKey string
	Replayed       bool
}

type domainEventQueryRower interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

type domainSubscription struct {
	tenantScopeID uuid.UUID
	actorScopeID  uuid.UUID
	actorUserID   uuid.UUID
	targetURL     string
	targetHost    string
	targetPath    string
	status        string
	revision      string
	eventSequence string
}

func NewDomainEventProducer(pool *pgxpool.Pool) (*DomainEventProducer, error) {
	if pool == nil {
		return nil, ErrInvalidConfig
	}
	return &DomainEventProducer{pool: pool}, nil
}

func (producer *DomainEventProducer) PublishDomainEvent(
	ctx context.Context,
	request DomainEventRequest,
) (DomainEventResult, error) {
	if producer == nil || producer.pool == nil || ctx == nil {
		return DomainEventResult{}, ErrInvalidConfig
	}
	if err := validateDomainEventRequest(request); err != nil {
		return DomainEventResult{}, err
	}

	tx, err := producer.pool.Begin(ctx)
	if err != nil {
		return DomainEventResult{}, ErrProducerUnavailable
	}
	defer tx.Rollback(ctx)

	subscription, err := loadDomainSubscription(ctx, tx, request.SubscriptionID)
	if err != nil {
		return DomainEventResult{}, err
	}
	if err := authorizeDomainActor(ctx, tx, subscription); err != nil {
		return DomainEventResult{}, err
	}
	canonicalData, err := canonicalDomainEventData(request.Data)
	if err != nil {
		return DomainEventResult{}, ErrInvalidInput
	}
	idempotencyKey := domainIdempotencyKey(request, subscription)
	requestDigest := domainRequestDigest(request, subscription, canonicalData)
	if replay, found, err := loadDomainEventReplay(ctx, tx, request, subscription, idempotencyKey, requestDigest); err != nil {
		return DomainEventResult{}, err
	} else {
		if err := validateDomainEventSubscriptionStatus(subscription.status, found); err != nil {
			return DomainEventResult{}, err
		}
		if found {
			return replay, nil
		}
	}

	sequence, err := strconv.ParseUint(subscription.eventSequence, 10, 64)
	if err != nil || sequence == ^uint64(0) {
		return DomainEventResult{}, ErrProducerState
	}
	sequence++
	eventID, err := uuid.NewV7()
	if err != nil {
		return DomainEventResult{}, ErrProducerUnavailable
	}
	deliveryID, err := uuid.NewV7()
	if err != nil {
		return DomainEventResult{}, ErrProducerUnavailable
	}
	now, err := transactionTime(ctx, tx)
	if err != nil {
		return DomainEventResult{}, ErrProducerUnavailable
	}
	canonicalBody, bodyDigest, err := insertDomainEvent(ctx, tx, request, subscription, eventID, sequence, now)
	if err != nil {
		return DomainEventResult{}, mapProducerError(err)
	}
	deliveryKey := sha256.Sum256([]byte(deliveryID.String()))
	deliveryIdempotencyKey := "plugin-webhook-v2-" + hex.EncodeToString(deliveryKey[:])
	if _, err = tx.Exec(ctx, `INSERT INTO plugin_webhook_deliveries(
		id,tenant_scope_id,subscription_id,event_id,actor_scope_id,actor_user_id,
		delivery_idempotency_key,target_url,target_host,target_path,status,
		subscription_revision,attempt_count,created_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'pending',$11,0,$12)`,
		deliveryID, subscription.tenantScopeID, request.SubscriptionID,
		eventID, subscription.actorScopeID, subscription.actorUserID,
		deliveryIdempotencyKey, subscription.targetURL, subscription.targetHost,
		subscription.targetPath, subscription.revision, now); err != nil {
		return DomainEventResult{}, mapProducerError(err)
	}
	messageDigest := sha256.Sum256([]byte("msg-" + deliveryID.String()))
	messageID := "plugin-webhook-v2-" + hex.EncodeToString(messageDigest[:])
	if _, err = tx.Exec(ctx, `INSERT INTO plugin_webhook_outbox(
		id,tenant_scope_id,subscription_id,event_id,delivery_id,actor_scope_id,actor_user_id,
		queue_schema,queue_body,queue_body_sha256,message_id,status,publish_attempt,
		available_at,created_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,'cdnca.plugin-webhook.queue/v2',$8,$9,$10,'pending',0,$11,$11)`,
		uuid.New(), subscription.tenantScopeID, request.SubscriptionID, eventID,
		deliveryID, subscription.actorScopeID, subscription.actorUserID,
		canonicalBody, bodyDigest, messageID, now); err != nil {
		return DomainEventResult{}, mapProducerError(err)
	}
	commandID, err := uuid.NewV7()
	if err != nil {
		return DomainEventResult{}, ErrProducerUnavailable
	}
	if _, err = tx.Exec(ctx, `INSERT INTO plugin_webhook_write_requests(
		id,tenant_scope_id,actor_scope_id,actor_user_id,operation,idempotency_key,
		request_digest,subscription_id,delivery_id,created_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		commandID, subscription.tenantScopeID, subscription.actorScopeID,
		subscription.actorUserID, DomainEventOperation, idempotencyKey,
		requestDigest[:], request.SubscriptionID, deliveryID, now); err != nil {
		return DomainEventResult{}, mapProducerError(err)
	}
	auditID, err := appendDomainAudit(ctx, tx, subscription, deliveryID,
		domainIdempotencyKey(request, subscription), now)
	if err != nil {
		return DomainEventResult{}, mapProducerError(err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO plugin_webhook_rate_events(
		id,tenant_scope_id,subscription_id,actor_scope_id,actor_user_id,operation,
		outcome,reason_code,audit_event_id,occurred_at
	) VALUES($1,$2,$3,$4,$5,$6,'allowed','accepted',$7,$8)`,
		uuid.New(), subscription.tenantScopeID, request.SubscriptionID,
		subscription.actorScopeID, subscription.actorUserID, DomainEventOperation,
		auditID, now); err != nil {
		return DomainEventResult{}, mapProducerError(err)
	}
	if _, err = tx.Exec(ctx, `UPDATE plugin_webhook_write_requests
		SET response_status=202,
		    response_body=jsonb_build_object('subscription_id',subscription_id::text,'delivery_id',delivery_id::text),
		    audit_event_id=$2,completed_at=$3
		WHERE id=$1`, commandID, auditID, now); err != nil {
		return DomainEventResult{}, mapProducerError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return DomainEventResult{}, ErrProducerUnavailable
	}
	return DomainEventResult{EventID: eventID, DeliveryID: deliveryID,
		Sequence: sequence, IdempotencyKey: deliveryIdempotencyKey}, nil
}

func validateDomainEventRequest(request DomainEventRequest) error {
	contract, ok := eventContractsV2[request.EventType]
	if !ok || contract.Test || !validEventSubject(request.EventType, request.Subject, request.SubscriptionID) ||
		request.SubscriptionID == uuid.Nil || !eventIDPattern.MatchString(request.RequestID) ||
		request.OccurredAt.IsZero() || request.OccurredAt.Nanosecond()%1000 != 0 ||
		len(request.Data) == 0 || len(request.Data) > 65536 || !json.Valid(request.Data) ||
		!validCanonicalEventData(json.RawMessage(request.Data), request.SubscriptionID, request.EventType) ||
		!validTraceparent(request.Traceparent) {
		return ErrInvalidInput
	}
	return nil
}

func validateDomainEventSubscriptionStatus(status string, replayed bool) error {
	if !replayed && status != "active" {
		return ErrProducerState
	}
	return nil
}

func loadDomainSubscription(ctx context.Context, tx pgx.Tx, subscriptionID uuid.UUID) (domainSubscription, error) {
	var result domainSubscription
	err := tx.QueryRow(ctx, `SELECT tenant_scope_id,actor_scope_id,actor_user_id,target_url,
		target_host,target_path,status,revision::text,event_sequence::text
		FROM plugin_webhook_subscriptions
		WHERE id=$1 AND (SELECT count(*) FROM plugin_webhook_subscriptions WHERE id=$1)=1
		FOR UPDATE`, subscriptionID).Scan(&result.tenantScopeID, &result.actorScopeID,
		&result.actorUserID, &result.targetURL, &result.targetHost, &result.targetPath,
		&result.status, &result.revision, &result.eventSequence)
	if errors.Is(err, pgx.ErrNoRows) {
		return domainSubscription{}, ErrProducerNotFound
	}
	if err != nil {
		return domainSubscription{}, ErrProducerUnavailable
	}
	return result, nil
}

func authorizeDomainActor(ctx context.Context, tx pgx.Tx, subscription domainSubscription) error {
	var allowed bool
	err := tx.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1
		FROM access_scopes target
		JOIN tenants tenant ON tenant.id=target.tenant_id AND tenant.status='active'
		JOIN access_scopes actor_scope ON actor_scope.id=$1
		JOIN memberships membership
		  ON membership.scope_id=actor_scope.id AND membership.user_id=$2 AND membership.status='active'
		JOIN users account ON account.id=membership.user_id AND account.status='active'
		WHERE target.id=$3 AND target.kind='tenant' AND (
			(actor_scope.kind='tenant' AND actor_scope.id=target.id AND EXISTS (
				SELECT 1
				FROM custom_rbac_effective_permissions(actor_scope.id, membership.user_id) permission
				WHERE permission.permission_name='plugin_webhooks.manage'
			)) OR
			(actor_scope.kind='platform' AND EXISTS (
				SELECT 1
				FROM role_assignments assignment
				JOIN roles assigned_role
				  ON assigned_role.id=assignment.role_id AND assigned_role.scope_id=assignment.scope_id
				JOIN role_permissions permission ON permission.role_id=assigned_role.id
				WHERE assignment.scope_id=actor_scope.id AND assignment.user_id=membership.user_id
				  AND assigned_role.system_role AND permission.permission_name='plugin_webhooks.manage'
			))
		)
	)`, subscription.actorScopeID, subscription.actorUserID, subscription.tenantScopeID).Scan(&allowed)
	if err != nil {
		return ErrProducerUnavailable
	}
	if !allowed {
		return ErrProducerPermissionDenied
	}
	return nil
}

func transactionTime(ctx context.Context, tx pgx.Tx) (time.Time, error) {
	var value time.Time
	err := tx.QueryRow(ctx, `SELECT transaction_timestamp()`).Scan(&value)
	return value.UTC(), err
}

func insertDomainEvent(ctx context.Context, tx domainEventQueryRower, request DomainEventRequest,
	subscription domainSubscription, eventID uuid.UUID, sequence uint64, now time.Time) ([]byte, []byte, error) {
	var body, digest []byte
	err := tx.QueryRow(ctx, `WITH canonical AS (
		SELECT plugin_webhook_canonical_body_084(
			$1,(SELECT tenant_id FROM access_scopes WHERE id=$2),$3,$4,$5,$6,$7,$8::numeric,$9::jsonb
		) AS value
	)
	INSERT INTO plugin_webhook_events(
		id,tenant_scope_id,subscription_id,actor_scope_id,actor_user_id,sequence,event_type,
		subject,request_id,traceparent,event_time,data,canonical_body,body_sha256,created_at
	)
	SELECT $1,$2,$10,$11,$12,$8::numeric,$3,$4,$6,$7,$5,$9::jsonb,value,sha256(value),$13
	FROM canonical
	RETURNING canonical_body,body_sha256`, eventID, subscription.tenantScopeID,
		request.EventType, request.Subject,
		request.OccurredAt.UTC(), request.RequestID, request.Traceparent, sequence,
		request.Data, request.SubscriptionID, subscription.actorScopeID, subscription.actorUserID, now).
		Scan(&body, &digest)
	return body, digest, err
}

func domainIdempotencyKey(request DomainEventRequest, subscription domainSubscription) string {
	input := []byte("cdnca.plugin-webhook.domain-event/v2")
	for _, part := range []string{subscription.tenantScopeID.String(), request.SubscriptionID.String(), request.EventType, request.RequestID} {
		input = appendDigestPart(input, []byte(part))
	}
	digest := sha256.Sum256(input)
	return "domain-event-" + hex.EncodeToString(digest[:])
}

func domainRequestDigest(request DomainEventRequest, subscription domainSubscription, canonicalData []byte) [32]byte {
	input := []byte("cdnca.plugin-webhook.domain-event-request/v2")
	for _, part := range []string{subscription.tenantScopeID.String(), subscription.actorScopeID.String(),
		subscription.actorUserID.String(), request.SubscriptionID.String(), request.EventType,
		request.Subject, request.RequestID, request.OccurredAt.UTC().Format(time.RFC3339Nano)} {
		input = appendDigestPart(input, []byte(part))
	}
	if request.Traceparent == nil {
		input = appendDigestPart(input, nil)
	} else {
		input = appendDigestPart(input, []byte(*request.Traceparent))
	}
	input = appendDigestPart(input, canonicalData)
	return sha256.Sum256(input)
}

func appendDigestPart(input, value []byte) []byte {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	input = append(input, size[:]...)
	return append(input, value...)
}

func canonicalDomainEventData(raw json.RawMessage) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if number, ok := value.(json.Number); ok {
		canonical, err := normalizeCanonicalJSONNumber(number.String())
		if err != nil {
			return nil, err
		}
		return canonical, nil
	}
	if err := normalizeCanonicalDomainNumbers(value); err != nil {
		return nil, err
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	if len(canonical) > maxCanonicalEventDataSize {
		return nil, errCanonicalEventDataTooLarge
	}
	return canonical, nil
}

const maxCanonicalEventDataSize = 65536

var errCanonicalEventDataTooLarge = errors.New("canonical domain event data exceeds size limit")

func normalizeCanonicalDomainNumbers(value any) error {
	switch current := value.(type) {
	case json.Number:
		return nil
	case []any:
		for index, item := range current {
			if number, ok := item.(json.Number); ok {
				normalized, err := normalizeCanonicalJSONNumber(number.String())
				if err != nil {
					return err
				}
				current[index] = json.RawMessage(normalized)
				continue
			}
			if err := normalizeCanonicalDomainNumbers(item); err != nil {
				return err
			}
		}
	case map[string]any:
		for key, item := range current {
			if number, ok := item.(json.Number); ok {
				normalized, err := normalizeCanonicalJSONNumber(number.String())
				if err != nil {
					return err
				}
				current[key] = json.RawMessage(normalized)
				continue
			}
			if err := normalizeCanonicalDomainNumbers(item); err != nil {
				return err
			}
		}
	}
	return nil
}

func normalizeCanonicalJSONNumber(raw string) ([]byte, error) {
	if raw == "" {
		return nil, ErrInvalidInput
	}
	negative := raw[0] == '-'
	if negative {
		raw = raw[1:]
	}
	exponent := 0
	mantissa := raw
	if index := strings.IndexAny(raw, "eE"); index >= 0 {
		mantissa = raw[:index]
		parsed, err := parseCanonicalExponent(raw[index+1:], len(mantissa))
		if err != nil {
			return nil, err
		}
		exponent = parsed
	}
	integer, fraction := mantissa, ""
	if index := strings.IndexByte(mantissa, '.'); index >= 0 {
		integer, fraction = mantissa[:index], mantissa[index+1:]
	}
	if integer == "" || (fraction == "" && strings.Contains(mantissa, ".")) {
		return nil, ErrInvalidInput
	}
	fraction = strings.TrimRight(fraction, "0")
	digits := integer + fraction
	leading := len(digits) - len(strings.TrimLeft(digits, "0"))
	if leading == len(digits) {
		return []byte("0"), nil
	}
	digits = digits[leading:]
	decimalPosition := len(integer) + exponent - leading
	digits = strings.TrimRight(digits, "0")
	outputLength := len(digits) + 1
	switch {
	case decimalPosition <= 0:
		outputLength = 2 - decimalPosition + len(digits)
	case decimalPosition >= len(digits):
		outputLength = decimalPosition
	}
	if negative {
		outputLength++
	}
	if outputLength > maxCanonicalEventDataSize {
		return nil, errCanonicalEventDataTooLarge
	}
	result := make([]byte, 0, outputLength)
	if negative {
		result = append(result, '-')
	}
	switch {
	case decimalPosition <= 0:
		result = append(result, '0', '.')
		result = append(result, strings.Repeat("0", -decimalPosition)...)
		result = append(result, digits...)
	case decimalPosition >= len(digits):
		result = append(result, digits...)
		result = append(result, strings.Repeat("0", decimalPosition-len(digits))...)
	default:
		result = append(result, digits[:decimalPosition]...)
		result = append(result, '.')
		result = append(result, digits[decimalPosition:]...)
	}
	return result, nil
}

func parseCanonicalExponent(raw string, mantissaLength int) (int, error) {
	if raw == "" {
		return 0, ErrInvalidInput
	}
	negative := raw[0] == '-'
	if raw[0] == '-' || raw[0] == '+' {
		raw = raw[1:]
	}
	if raw == "" {
		return 0, ErrInvalidInput
	}
	limit := maxCanonicalEventDataSize + mantissaLength + 2
	value := 0
	for _, digit := range raw {
		if digit < '0' || digit > '9' {
			return 0, ErrInvalidInput
		}
		if value > limit/10 || value*10 > limit-int(digit-'0') {
			value = limit
			continue
		}
		value = value*10 + int(digit-'0')
	}
	if negative {
		return -value, nil
	}
	return value, nil
}

type domainEventReplayFact struct {
	RequestDigest     []byte
	ResponseStatus    *int
	ResponseBody      []byte
	CompletedAt       *time.Time
	RequestDeliveryID *uuid.UUID
	DeliveryID        *uuid.UUID
	EventID           *uuid.UUID
	Sequence          *string
	DeliveryKey       *string
}

func loadDomainEventReplay(ctx context.Context, tx domainEventQueryRower, request DomainEventRequest,
	subscription domainSubscription, idempotencyKey string, requestDigest [32]byte) (DomainEventResult, bool, error) {
	var fact domainEventReplayFact
	err := tx.QueryRow(ctx, `SELECT request.request_digest,request.response_status,request.response_body,
		request.completed_at,request.delivery_id,delivery.id,delivery.event_id,event.sequence::text,
		delivery.delivery_idempotency_key
		FROM plugin_webhook_write_requests request
		LEFT JOIN plugin_webhook_deliveries delivery
		  ON delivery.tenant_scope_id=request.tenant_scope_id
		 AND delivery.subscription_id=request.subscription_id
		 AND delivery.id=request.delivery_id
		LEFT JOIN plugin_webhook_events event
		  ON event.tenant_scope_id=delivery.tenant_scope_id
		 AND event.subscription_id=delivery.subscription_id
		 AND event.id=delivery.event_id
		WHERE request.tenant_scope_id=$1 AND request.actor_scope_id=$2 AND request.actor_user_id=$3
		  AND request.operation=$4 AND request.idempotency_key=$5 AND request.subscription_id=$6
		FOR UPDATE OF request`, subscription.tenantScopeID, subscription.actorScopeID,
		subscription.actorUserID, DomainEventOperation, idempotencyKey, request.SubscriptionID).
		Scan(&fact.RequestDigest, &fact.ResponseStatus, &fact.ResponseBody, &fact.CompletedAt,
			&fact.RequestDeliveryID, &fact.DeliveryID, &fact.EventID, &fact.Sequence, &fact.DeliveryKey)
	if errors.Is(err, pgx.ErrNoRows) {
		return DomainEventResult{}, false, nil
	}
	if err != nil {
		return DomainEventResult{}, false, ErrProducerUnavailable
	}
	result, err := validateDomainEventReplay(fact, requestDigest, request.SubscriptionID)
	if err != nil {
		return DomainEventResult{}, false, err
	}
	return result, true, nil
}

func validateDomainEventReplay(fact domainEventReplayFact, requestDigest [32]byte,
	subscriptionID uuid.UUID) (DomainEventResult, error) {
	if !bytes.Equal(fact.RequestDigest, requestDigest[:]) || fact.ResponseStatus == nil ||
		*fact.ResponseStatus != 202 || fact.CompletedAt == nil || fact.RequestDeliveryID == nil ||
		fact.DeliveryID == nil || fact.EventID == nil || fact.Sequence == nil || *fact.Sequence == "" ||
		fact.DeliveryKey == nil || *fact.DeliveryKey == "" || *fact.RequestDeliveryID != *fact.DeliveryID ||
		*fact.DeliveryID == uuid.Nil || *fact.EventID == uuid.Nil {
		return DomainEventResult{}, ErrProducerState
	}
	sequence, err := strconv.ParseUint(*fact.Sequence, 10, 64)
	if err != nil || sequence == 0 {
		return DomainEventResult{}, ErrProducerState
	}
	var response struct {
		SubscriptionID string `json:"subscription_id"`
		DeliveryID     string `json:"delivery_id"`
	}
	if err := json.Unmarshal(fact.ResponseBody, &response); err != nil ||
		response.SubscriptionID != subscriptionID.String() || response.DeliveryID != fact.DeliveryID.String() ||
		!json.Valid(fact.ResponseBody) {
		return DomainEventResult{}, ErrProducerState
	}
	var responseFields map[string]json.RawMessage
	if json.Unmarshal(fact.ResponseBody, &responseFields) != nil || len(responseFields) != 2 {
		return DomainEventResult{}, ErrProducerState
	}
	deliveryKey := sha256.Sum256([]byte(fact.DeliveryID.String()))
	expectedDeliveryKey := "plugin-webhook-v2-" + hex.EncodeToString(deliveryKey[:])
	if *fact.DeliveryKey != expectedDeliveryKey {
		return DomainEventResult{}, ErrProducerState
	}
	return DomainEventResult{EventID: *fact.EventID, DeliveryID: *fact.DeliveryID,
		Sequence: sequence, IdempotencyKey: expectedDeliveryKey, Replayed: true}, nil
}

func appendDomainAudit(ctx context.Context, tx pgx.Tx, subscription domainSubscription,
	deliveryID uuid.UUID, requestID string, occurredAt time.Time) (uuid.UUID, error) {
	actorID := subscription.actorUserID
	return audit.AppendTx(ctx, tx, audit.Event{
		ScopeID: subscription.tenantScopeID, ActorUserID: &actorID, Action: DomainEventOperation,
		ResourceType: "plugin_webhook_delivery", ResourceID: deliveryID.String(), RequestID: requestID,
		Result: "success", OccurredAt: occurredAt,
		Payload: map[string]any{"actor_scope_id": subscription.actorScopeID.String(),
			"target_scope_id": subscription.tenantScopeID.String(), "operation": DomainEventOperation, "reason": "accepted"},
	})
}

func mapProducerError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	// P3687: the bound installation is disabled or lacks the event permission.
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "P3687" {
		return ErrProducerPermissionDenied
	}
	return ErrProducerState
}
