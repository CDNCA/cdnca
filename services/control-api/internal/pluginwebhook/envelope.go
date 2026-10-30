package pluginwebhook

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/domaineventsource"
	"github.com/google/uuid"
)

const (
	QueueSchemaV1     = "cdnca.plugin-webhook.queue/v1"
	QueueSchemaV2     = "cdnca.plugin-webhook.queue/v2"
	CloudEventsV1     = "1.0"
	MaxEventDataBytes = 256 * 1024
)

var (
	eventIDPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	eventTypePattern   = regexp.MustCompile(`^io\.cdnca\.[a-z][a-z0-9_]*\.v[1-9][0-9]*\.[a-z][a-z0-9_]*$`)
	traceparentPattern = regexp.MustCompile(`^00-[0-9a-f]{32}-[0-9a-f]{16}-(00|01)$`)
	deliveryNamespace  = uuid.MustParse("c35245fa-e2ce-5eb1-a212-675865af5c12")
)

const (
	domainEventSchemaV2 = "https://schemas.cdnca.example/marketplace/v1/domain-event.schema.json"
	testEventSchemaV2   = "https://schemas.cdnca.example/marketplace/v1/webhook-test-event.schema.json"
)

type eventContractV2 struct {
	SchemaURI     string
	MaxDataFields int
	Test          bool
}

var eventContractsV2 = map[string]eventContractV2{
	"io.cdnca.certificate.v1.expiry_reached": {SchemaURI: domainEventSchemaV2, MaxDataFields: 16},
	"io.cdnca.certificate.v1.status_changed": {SchemaURI: domainEventSchemaV2, MaxDataFields: 16},
	"io.cdnca.deployment.v1.status_changed":  {SchemaURI: domainEventSchemaV2, MaxDataFields: 16},
	"io.cdnca.node.v1.status_changed":        {SchemaURI: domainEventSchemaV2, MaxDataFields: 16},
	"io.cdnca.security.v1.incident_detected": {SchemaURI: domainEventSchemaV2, MaxDataFields: 16},
	"io.cdnca.site.v1.updated":               {SchemaURI: domainEventSchemaV2, MaxDataFields: 16},
	"io.cdnca.usage.v1.threshold_reached":    {SchemaURI: domainEventSchemaV2, MaxDataFields: 16},
	"io.cdnca.webhook.v1.test":               {SchemaURI: testEventSchemaV2, MaxDataFields: 10, Test: true},
}

type CloudEvent struct {
	SpecVersion     string          `json:"specversion"`
	ID              string          `json:"id"`
	Source          string          `json:"source"`
	Type            string          `json:"type"`
	Subject         string          `json:"subject"`
	Time            time.Time       `json:"time"`
	DataContentType string          `json:"datacontenttype"`
	TenantID        string          `json:"tenantid"`
	InstallationID  string          `json:"installationid"`
	Data            json.RawMessage `json:"data"`
}

type PublishRequest struct {
	TenantID       uuid.UUID
	InstallationID uuid.UUID
	EventID        string
	EventType      string
	TargetURL      string
	OccurredAt     time.Time
	Data           json.RawMessage
}

type QueueItem struct {
	Schema          string     `json:"schema"`
	DeliveryID      uuid.UUID  `json:"delivery_id"`
	IdempotencyKey  string     `json:"idempotency_key"`
	TargetURL       string     `json:"target_url"`
	ReplayOf        *uuid.UUID `json:"replay_of,omitempty"`
	ReplayRequestID string     `json:"replay_request_id,omitempty"`
	Event           CloudEvent `json:"event"`
	// RawEvent is populated only for the database-backed v2 runtime. It keeps
	// the exact canonical bytes produced by migration 084 for signing and HTTP
	// delivery; v1 queue messages continue to marshal Event as before.
	RawEvent json.RawMessage `json:"-"`

	TargetScopeID   uuid.UUID `json:"-"`
	TenantID        uuid.UUID `json:"-"`
	SubscriptionID  uuid.UUID `json:"-"`
	SecretVersionID uuid.UUID `json:"-"`
	EventID         uuid.UUID `json:"-"`
}

type V2QueueIdentity struct {
	TargetScopeID   uuid.UUID
	TenantID        uuid.UUID
	SubscriptionID  uuid.UUID
	SecretVersionID uuid.UUID
	EventID         uuid.UUID
	DeliveryID      uuid.UUID
}

type canonicalEventV2 struct {
	SpecVersion     string    `json:"specversion"`
	ID              uuid.UUID `json:"id"`
	Source          string    `json:"source"`
	Type            string    `json:"type"`
	Subject         string    `json:"subject"`
	Time            time.Time `json:"time"`
	DataContentType string    `json:"datacontenttype"`
	DataSchema      string    `json:"dataschema"`
	TenantID        uuid.UUID `json:"tenant_id"`
	RequestID       string    `json:"request_id"`
	Traceparent     *string   `json:"traceparent,omitempty"`
	Sequence        uint64    `json:"sequence"`
	Data            any       `json:"data"`
}

// NewV2QueueItem validates and wraps the canonical migration-084 event body.
// The runtime supplies identity and target fields from the corresponding
// delivery row; the canonical event bytes are retained unchanged.
func NewV2QueueItem(raw []byte, identity V2QueueIdentity, idempotencyKey, targetURL string) (QueueItem, error) {
	if identity.TargetScopeID == uuid.Nil || identity.TenantID == uuid.Nil ||
		identity.TargetScopeID == identity.TenantID || identity.SubscriptionID == uuid.Nil ||
		identity.SecretVersionID == uuid.Nil || identity.EventID == uuid.Nil || identity.DeliveryID == uuid.Nil ||
		len(raw) < 2 || len(raw) > MaxQueueMessageBytes || !json.Valid(raw) ||
		!strings.HasPrefix(idempotencyKey, "plugin-webhook-v2-") ||
		!lowerHex64(idempotencyKey[len("plugin-webhook-v2-"):]) {
		return QueueItem{}, ErrInvalidInput
	}
	var event canonicalEventV2
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&event); err != nil {
		return QueueItem{}, ErrInvalidInput
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return QueueItem{}, ErrInvalidInput
	}
	contract, contractFound := eventContractsV2[event.Type]
	if event.SpecVersion != CloudEventsV1 || event.ID != identity.EventID || event.ID.Version() != 7 ||
		event.Source != "/control-plane/plugin-webhooks" || !contractFound ||
		!validEventSubject(event.Type, event.Subject, identity.SubscriptionID) || event.Time.IsZero() ||
		event.Time.Nanosecond()%1000 != 0 ||
		event.DataContentType != "application/json" ||
		event.DataSchema != contract.SchemaURI || event.TenantID != identity.TenantID ||
		!eventIDPattern.MatchString(event.RequestID) || event.Sequence == 0 ||
		!validCanonicalEventData(event.Data, identity.SubscriptionID, event.Type) || !validTraceparent(event.Traceparent) {
		return QueueItem{}, ErrInvalidInput
	}
	canonical, err := json.Marshal(event)
	if err != nil || !bytes.Equal(canonical, raw) {
		return QueueItem{}, ErrInvalidInput
	}
	parsedTarget, err := parseTargetURL(targetURL)
	if err != nil || parsedTarget.String() != targetURL {
		return QueueItem{}, ErrInvalidInput
	}
	var data json.RawMessage
	var rawObject map[string]json.RawMessage
	if err := json.Unmarshal(raw, &rawObject); err != nil || json.Unmarshal(rawObject["data"], &data) != nil || len(data) == 0 {
		return QueueItem{}, ErrInvalidInput
	}
	return QueueItem{
		Schema: QueueSchemaV2, DeliveryID: identity.DeliveryID, IdempotencyKey: idempotencyKey, TargetURL: targetURL,
		Event: CloudEvent{
			SpecVersion: event.SpecVersion, ID: event.ID.String(), Source: event.Source, Type: event.Type,
			Subject: event.Subject, Time: event.Time.UTC(), DataContentType: event.DataContentType,
			Data: data,
		},
		RawEvent:      append(json.RawMessage(nil), raw...),
		TargetScopeID: identity.TargetScopeID, TenantID: identity.TenantID,
		SubscriptionID: identity.SubscriptionID, SecretVersionID: identity.SecretVersionID,
		EventID: identity.EventID,
	}, nil
}

// validCanonicalEventData checks the delivered data object: the test event is
// exactly {subscription_id,test:true}; a domain event must satisfy its
// domaineventsource contract plus the webhook fields fanout adds.
func validCanonicalEventData(value any, subscriptionID uuid.UUID, eventType string) bool {
	contract, ok := eventContractsV2[eventType]
	if !ok || subscriptionID == uuid.Nil {
		return false
	}
	encodedValue, err := json.Marshal(value)
	if err != nil || len(encodedValue) > 65536 {
		return false
	}
	data := make(map[string]json.RawMessage)
	if json.Unmarshal(encodedValue, &data) != nil || len(data) < 1 || len(data) > contract.MaxDataFields {
		return false
	}
	for _, field := range data {
		if len(field) == 0 || bytes.Equal(bytes.TrimSpace(field), []byte("null")) {
			return false
		}
	}
	if !contract.Test {
		return domaineventsource.ValidWebhookData(eventType, subscriptionID.String(), data)
	}
	var encodedSubscriptionID string
	var test bool
	return len(data) == 2 && json.Unmarshal(data["subscription_id"], &encodedSubscriptionID) == nil &&
		encodedSubscriptionID == subscriptionID.String() && json.Unmarshal(data["test"], &test) == nil && test
}

// validEventSubject: the test event names its subscription; a domain event
// names the resource it is about (site/<uuid>, deployment/<uuid>, ...).
func validEventSubject(eventType, subject string, subscriptionID uuid.UUID) bool {
	if eventType == "io.cdnca.webhook.v1.test" {
		return subject == "webhook_subscription/"+subscriptionID.String()
	}
	return domaineventsource.ValidSubject(eventType, subject)
}

func validTraceparent(value *string) bool {
	if value == nil {
		return true
	}
	if !traceparentPattern.MatchString(*value) {
		return false
	}
	parts := strings.Split(*value, "-")
	return len(parts) == 4 && strings.Trim(parts[1], "0") != "" && strings.Trim(parts[2], "0") != ""
}

func lowerHex64(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if !(character >= '0' && character <= '9') && !(character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

func newQueueItem(request PublishRequest) (QueueItem, error) {
	if request.TenantID == uuid.Nil || request.InstallationID == uuid.Nil ||
		!eventIDPattern.MatchString(request.EventID) || !eventTypePattern.MatchString(request.EventType) ||
		request.OccurredAt.IsZero() || len(request.Data) == 0 || len(request.Data) > MaxEventDataBytes ||
		!json.Valid(request.Data) {
		return QueueItem{}, ErrInvalidInput
	}
	parsed, err := parseTargetURL(request.TargetURL)
	if err != nil {
		return QueueItem{}, err
	}
	scope := request.TenantID.String() + "\x00" + request.InstallationID.String() + "\x00" + request.EventID
	deliveryID := uuid.NewHash(sha256.New(), deliveryNamespace, []byte(scope), 5)
	digest := sha256.Sum256([]byte(scope))
	data := append(json.RawMessage(nil), request.Data...)
	return QueueItem{
		Schema: QueueSchemaV1, DeliveryID: deliveryID,
		IdempotencyKey: "plugin-webhook-v1-" + hex.EncodeToString(digest[:]),
		TargetURL:      parsed.String(),
		Event: CloudEvent{
			SpecVersion: CloudEventsV1, ID: request.EventID,
			Source: fmt.Sprintf("urn:cdnca:tenant:%s", request.TenantID),
			Type:   request.EventType, Subject: request.InstallationID.String(),
			Time: request.OccurredAt.UTC(), DataContentType: "application/json",
			TenantID: request.TenantID.String(), InstallationID: request.InstallationID.String(), Data: data,
		},
	}, nil
}

func validateQueueItem(item QueueItem) error {
	if item.Schema == QueueSchemaV2 {
		if item.RawEvent == nil || item.DeliveryID == uuid.Nil {
			return ErrInvalidInput
		}
		rebuilt, err := NewV2QueueItem(item.RawEvent, V2QueueIdentity{
			TargetScopeID: item.TargetScopeID, TenantID: item.TenantID,
			SubscriptionID: item.SubscriptionID, SecretVersionID: item.SecretVersionID,
			EventID: item.EventID, DeliveryID: item.DeliveryID,
		}, item.IdempotencyKey, item.TargetURL)
		if err != nil {
			return err
		}
		if item.Event.SpecVersion != rebuilt.Event.SpecVersion || item.Event.ID != rebuilt.Event.ID ||
			item.Event.Source != rebuilt.Event.Source || item.Event.Type != rebuilt.Event.Type ||
			item.Event.Subject != rebuilt.Event.Subject || !item.Event.Time.Equal(rebuilt.Event.Time) ||
			item.Event.DataContentType != rebuilt.Event.DataContentType ||
			item.Event.TenantID != rebuilt.Event.TenantID || item.Event.InstallationID != rebuilt.Event.InstallationID ||
			!bytes.Equal(item.Event.Data, rebuilt.Event.Data) {
			return ErrInvalidInput
		}
		return nil
	}
	if item.Schema != QueueSchemaV1 || item.DeliveryID == uuid.Nil || item.IdempotencyKey == "" ||
		item.Event.SpecVersion != CloudEventsV1 || item.Event.DataContentType != "application/json" {
		return ErrInvalidInput
	}
	tenantID, tenantErr := uuid.Parse(item.Event.TenantID)
	installationID, installationErr := uuid.Parse(item.Event.InstallationID)
	if tenantErr != nil || installationErr != nil || item.Event.Subject != item.Event.InstallationID {
		return ErrInvalidInput
	}
	rebuilt, err := newQueueItem(PublishRequest{
		TenantID: tenantID, InstallationID: installationID, EventID: item.Event.ID,
		EventType: item.Event.Type, TargetURL: item.TargetURL, OccurredAt: item.Event.Time, Data: item.Event.Data,
	})
	if err != nil {
		return ErrInvalidInput
	}
	if item.TargetURL != rebuilt.TargetURL || item.Event.Source != rebuilt.Event.Source ||
		item.Event.Subject != rebuilt.Event.Subject || !item.Event.Time.Equal(rebuilt.Event.Time) {
		return ErrInvalidInput
	}
	if item.ReplayOf == nil {
		if item.ReplayRequestID != "" || rebuilt.DeliveryID != item.DeliveryID || rebuilt.IdempotencyKey != item.IdempotencyKey {
			return ErrInvalidInput
		}
		return nil
	}
	if *item.ReplayOf == uuid.Nil || !eventIDPattern.MatchString(item.ReplayRequestID) {
		return ErrInvalidInput
	}
	expectedID := uuid.NewHash(sha256.New(), deliveryNamespace, []byte("replay\x00"+item.ReplayOf.String()+"\x00"+item.ReplayRequestID), 5)
	digest := sha256.Sum256([]byte("replay\x00" + item.ReplayOf.String() + "\x00" + item.ReplayRequestID))
	if item.DeliveryID != expectedID || item.IdempotencyKey != "plugin-webhook-replay-v1-"+hex.EncodeToString(digest[:]) {
		return ErrInvalidInput
	}
	return nil
}
