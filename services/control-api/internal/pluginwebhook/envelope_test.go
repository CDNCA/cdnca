package pluginwebhook

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

var (
	testTenantID        = uuid.MustParse("018cc251-f400-7def-8000-000000000001")
	testInstallationID  = uuid.MustParse("018cc251-f400-7def-8000-000000000002")
	testTargetScopeID   = uuid.MustParse("018cc251-f400-7def-8000-000000000003")
	testSecretVersionID = uuid.MustParse("018cc251-f400-7def-8000-000000000004")
)

func TestNewQueueItemBuildsVersionedCloudEventAndStableIdentity(t *testing.T) {
	t.Parallel()
	request := PublishRequest{
		TenantID: testTenantID, InstallationID: testInstallationID,
		EventID: "evt_01HV7G4M6PX", EventType: "io.cdnca.site.v1.updated",
		TargetURL:  "https://hooks.example.com/events",
		OccurredAt: time.Date(2026, 7, 22, 1, 2, 3, 456000000, time.UTC),
		Data:       json.RawMessage(`{"site_id":"site-1","enabled":true}`),
	}
	first, err := newQueueItem(request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := newQueueItem(request)
	if err != nil {
		t.Fatal(err)
	}
	if first.Schema != QueueSchemaV1 || first.Event.SpecVersion != "1.0" ||
		first.Event.DataContentType != "application/json" || first.Event.ID != request.EventID ||
		first.Event.Type != request.EventType || first.Event.TenantID != testTenantID.String() ||
		first.Event.InstallationID != testInstallationID.String() {
		t.Fatalf("queue item = %#v", first)
	}
	if first.DeliveryID == uuid.Nil || first.DeliveryID != second.DeliveryID ||
		first.IdempotencyKey != second.IdempotencyKey {
		t.Fatalf("identity is not stable: %#v / %#v", first, second)
	}
	body, err := json.Marshal(first.Event)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(body, []byte(`"data":{"site_id":"site-1","enabled":true}`)) {
		t.Fatalf("CloudEvent body = %s", body)
	}

	request.InstallationID = uuid.MustParse("018cc251-f400-7def-8000-000000000003")
	other, err := newQueueItem(request)
	if err != nil {
		t.Fatal(err)
	}
	if other.DeliveryID == first.DeliveryID || other.IdempotencyKey == first.IdempotencyKey {
		t.Fatal("installation scope did not change delivery identity")
	}
}

func TestNewQueueItemRejectsUnsafeOrOversizedInput(t *testing.T) {
	t.Parallel()
	valid := PublishRequest{
		TenantID: testTenantID, InstallationID: testInstallationID,
		EventID: "event-1", EventType: "io.cdnca.site.v1.updated",
		TargetURL: "https://hooks.example.com/events", OccurredAt: time.Now().UTC(),
		Data: json.RawMessage(`{"ok":true}`),
	}
	tests := []struct {
		name   string
		mutate func(*PublishRequest)
	}{
		{"nil tenant", func(r *PublishRequest) { r.TenantID = uuid.Nil }},
		{"unversioned event type", func(r *PublishRequest) { r.EventType = "site.updated" }},
		{"invalid JSON", func(r *PublishRequest) { r.Data = json.RawMessage(`{"bad"`) }},
		{"oversized JSON", func(r *PublishRequest) {
			r.Data = json.RawMessage(`"` + string(bytes.Repeat([]byte("x"), MaxEventDataBytes)) + `"`)
		}},
		{"URL query secret", func(r *PublishRequest) { r.TargetURL += "?token=secret" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := valid
			test.mutate(&request)
			if _, err := newQueueItem(request); err == nil {
				t.Fatal("invalid request accepted")
			}
		})
	}
}

func TestValidateQueueItemRejectsTamperedCloudEventSourceAndTarget(t *testing.T) {
	t.Parallel()
	item, err := newQueueItem(PublishRequest{
		TenantID: testTenantID, InstallationID: testInstallationID,
		EventID: "event-tamper", EventType: "io.cdnca.site.v1.updated",
		TargetURL: "https://hooks.example.com/events", OccurredAt: time.Now().UTC(),
		Data: json.RawMessage(`{"ok":true}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	tamperedSource := item
	tamperedSource.Event.Source = "urn:cdnca:tenant:" + uuid.NewString()
	if err := validateQueueItem(tamperedSource); err == nil {
		t.Fatal("tampered source accepted")
	}
	tamperedTarget := item
	tamperedTarget.TargetURL = "https://hooks.example.com:443/events"
	if err := validateQueueItem(tamperedTarget); err == nil {
		t.Fatal("non-canonical target accepted")
	}
}

func TestNewV2QueueItemPreservesCanonicalBodyAndRejectsUnknownFields(t *testing.T) {
	t.Parallel()
	subscriptionID := uuid.MustParse("018cc251-f400-7def-8000-000000000010")
	eventID := uuid.Must(uuid.NewV7())
	now := time.Date(2026, 7, 29, 8, 0, 0, 0, time.UTC)
	raw, err := json.Marshal(struct {
		SpecVersion string    `json:"specversion"`
		ID          uuid.UUID `json:"id"`
		Source      string    `json:"source"`
		Type        string    `json:"type"`
		Subject     string    `json:"subject"`
		Time        time.Time `json:"time"`
		ContentType string    `json:"datacontenttype"`
		Schema      string    `json:"dataschema"`
		TenantID    uuid.UUID `json:"tenant_id"`
		RequestID   string    `json:"request_id"`
		Sequence    uint64    `json:"sequence"`
		Data        struct {
			SubscriptionID uuid.UUID `json:"subscription_id"`
			Test           bool      `json:"test"`
		} `json:"data"`
	}{
		SpecVersion: "1.0", ID: eventID, Source: "/control-plane/plugin-webhooks",
		Type: "io.cdnca.webhook.v1.test", Subject: "webhook_subscription/" + subscriptionID.String(),
		Time: now, ContentType: "application/json",
		Schema:   "https://schemas.cdnca.example/marketplace/v1/webhook-test-event.schema.json",
		TenantID: testTenantID, RequestID: "request-084", Sequence: 1,
		Data: struct {
			SubscriptionID uuid.UUID `json:"subscription_id"`
			Test           bool      `json:"test"`
		}{SubscriptionID: subscriptionID, Test: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	key := "plugin-webhook-v2-" + strings.Repeat("a", 64)
	deliveryID := uuid.Must(uuid.NewV7())
	identity := V2QueueIdentity{TargetScopeID: testTargetScopeID, TenantID: testTenantID,
		SubscriptionID: subscriptionID, SecretVersionID: testSecretVersionID,
		EventID: eventID, DeliveryID: deliveryID}
	item, err := NewV2QueueItem(raw, identity, key,
		"https://hooks.example.com/v1/events")
	if err != nil {
		t.Fatal(err)
	}
	if item.Schema != QueueSchemaV2 || !bytes.Equal(item.RawEvent, raw) || item.Event.ID != eventID.String() ||
		item.TargetScopeID != testTargetScopeID || item.TenantID != testTenantID ||
		item.SubscriptionID != subscriptionID || item.SecretVersionID != testSecretVersionID ||
		item.EventID != eventID || item.DeliveryID != deliveryID || item.Event.TenantID != "" ||
		item.Event.InstallationID != "" || validateQueueItem(item) != nil {
		t.Fatalf("v2 item = %#v", item)
	}
	unknown := append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"unknown":true}`)...)
	if _, err := NewV2QueueItem(unknown, identity, key,
		"https://hooks.example.com/v1/events"); err == nil {
		t.Fatal("unknown canonical event field accepted")
	}
}

func TestValidateQueueItemRejectsTamperedV2EventProjection(t *testing.T) {
	t.Parallel()
	subscriptionID := uuid.MustParse("018cc251-f400-7def-8000-000000000040")
	eventID := uuid.Must(uuid.NewV7())
	raw, err := json.Marshal(canonicalEventV2{
		SpecVersion: CloudEventsV1, ID: eventID, Source: "/control-plane/plugin-webhooks",
		Type: "io.cdnca.site.v1.updated", Subject: "site/" + testSiteID.String(),
		Time: time.Date(2026, 7, 29, 8, 0, 0, 0, time.UTC), DataContentType: "application/json",
		DataSchema: domainEventSchemaV2, TenantID: testTenantID, RequestID: "request-projection-084", Sequence: 3,
		Data: siteEventData(subscriptionID),
	})
	if err != nil {
		t.Fatal(err)
	}
	item, err := NewV2QueueItem(raw, V2QueueIdentity{
		TargetScopeID: testTargetScopeID, TenantID: testTenantID, SubscriptionID: subscriptionID,
		SecretVersionID: testSecretVersionID, EventID: eventID, DeliveryID: uuid.Must(uuid.NewV7()),
	}, "plugin-webhook-v2-"+strings.Repeat("a", 64), "https://hooks.example.com/v1/events")
	if err != nil {
		t.Fatal(err)
	}
	item.Event.Type = "io.cdnca.security.v1.incident_detected"
	if err := validateQueueItem(item); err == nil {
		t.Fatal("tampered event projection accepted")
	}
}

func TestNewV2QueueItemRequiresLowercaseHexIdempotencyKey(t *testing.T) {
	t.Parallel()
	subscriptionID := uuid.MustParse("018cc251-f400-7def-8000-000000000010")
	eventID := uuid.Must(uuid.NewV7())
	now := time.Date(2026, 7, 29, 8, 0, 0, 0, time.UTC)
	raw, err := json.Marshal(struct {
		SpecVersion string    `json:"specversion"`
		ID          uuid.UUID `json:"id"`
		Source      string    `json:"source"`
		Type        string    `json:"type"`
		Subject     string    `json:"subject"`
		Time        time.Time `json:"time"`
		ContentType string    `json:"datacontenttype"`
		Schema      string    `json:"dataschema"`
		TenantID    uuid.UUID `json:"tenant_id"`
		RequestID   string    `json:"request_id"`
		Sequence    uint64    `json:"sequence"`
		Data        struct {
			SubscriptionID uuid.UUID `json:"subscription_id"`
			Test           bool      `json:"test"`
		} `json:"data"`
	}{
		SpecVersion: "1.0", ID: eventID, Source: "/control-plane/plugin-webhooks",
		Type: "io.cdnca.webhook.v1.test", Subject: "webhook_subscription/" + subscriptionID.String(),
		Time: now, ContentType: "application/json",
		Schema:   "https://schemas.cdnca.example/marketplace/v1/webhook-test-event.schema.json",
		TenantID: testTenantID, RequestID: "request-084", Sequence: 1,
		Data: struct {
			SubscriptionID uuid.UUID `json:"subscription_id"`
			Test           bool      `json:"test"`
		}{SubscriptionID: subscriptionID, Test: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	valid := "plugin-webhook-v2-" + strings.Repeat("a", 64)
	identity := V2QueueIdentity{TargetScopeID: testTargetScopeID, TenantID: testTenantID,
		SubscriptionID: subscriptionID, SecretVersionID: testSecretVersionID,
		EventID: eventID, DeliveryID: uuid.Must(uuid.NewV7())}
	for _, key := range []string{
		"plugin-webhook-v2-" + strings.Repeat("A", 64),
		"plugin-webhook-v2-" + strings.Repeat("g", 64),
		"plugin-webhook-v2-" + strings.Repeat("a", 63),
		"plugin-webhook-v2-" + strings.Repeat("a", 65),
		"plugin-webhook-v1-" + strings.Repeat("a", 64),
	} {
		if _, err := NewV2QueueItem(raw, identity, key,
			"https://hooks.example.com/v1/events"); err == nil {
			t.Fatalf("invalid v2 idempotency key accepted: %q", key)
		}
	}
	if _, err := NewV2QueueItem(raw, identity, valid,
		"https://hooks.example.com/v1/events"); err != nil {
		t.Fatalf("valid v2 idempotency key rejected: %v", err)
	}
}

func TestNewV2QueueItemAcceptsDistinctTargetScopeAndPublicTenant(t *testing.T) {
	t.Parallel()
	targetScopeID := uuid.MustParse("018cc251-f400-7def-8000-000000000020")
	publicTenantID := uuid.MustParse("018cc251-f400-7def-8000-000000000021")
	subscriptionID := uuid.MustParse("018cc251-f400-7def-8000-000000000022")
	eventID := uuid.Must(uuid.NewV7())
	deliveryID := uuid.Must(uuid.NewV7())
	raw, err := json.Marshal(struct {
		SpecVersion string    `json:"specversion"`
		ID          uuid.UUID `json:"id"`
		Source      string    `json:"source"`
		Type        string    `json:"type"`
		Subject     string    `json:"subject"`
		Time        time.Time `json:"time"`
		ContentType string    `json:"datacontenttype"`
		Schema      string    `json:"dataschema"`
		TenantID    uuid.UUID `json:"tenant_id"`
		RequestID   string    `json:"request_id"`
		Sequence    uint64    `json:"sequence"`
		Data        struct {
			SubscriptionID uuid.UUID `json:"subscription_id"`
			Test           bool      `json:"test"`
		} `json:"data"`
	}{
		SpecVersion: "1.0", ID: eventID, Source: "/control-plane/plugin-webhooks",
		Type: "io.cdnca.webhook.v1.test", Subject: "webhook_subscription/" + subscriptionID.String(),
		Time: time.Date(2026, 7, 29, 8, 0, 0, 0, time.UTC), ContentType: "application/json",
		Schema:   "https://schemas.cdnca.example/marketplace/v1/webhook-test-event.schema.json",
		TenantID: publicTenantID, RequestID: "request-distinct-identity", Sequence: 1,
		Data: struct {
			SubscriptionID uuid.UUID `json:"subscription_id"`
			Test           bool      `json:"test"`
		}{SubscriptionID: subscriptionID, Test: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	secretVersionID := uuid.Must(uuid.NewV7())
	item, err := NewV2QueueItem(raw, V2QueueIdentity{
		TargetScopeID: targetScopeID, TenantID: publicTenantID, SubscriptionID: subscriptionID,
		SecretVersionID: secretVersionID, EventID: eventID, DeliveryID: deliveryID,
	}, "plugin-webhook-v2-"+strings.Repeat("a", 64), "https://hooks.example.com/v1/events")
	if err != nil {
		t.Fatalf("distinct target scope and public tenant rejected: %v", err)
	}
	if item.TargetScopeID != targetScopeID || item.TenantID != publicTenantID ||
		item.SubscriptionID != subscriptionID || item.SecretVersionID != secretVersionID ||
		item.EventID != eventID || item.DeliveryID != deliveryID {
		t.Fatalf("v2 identity collapsed: %#v", item)
	}
}

func TestNewV2QueueItemAcceptsContractDomainEvent(t *testing.T) {
	t.Parallel()
	subscriptionID := uuid.MustParse("018cc251-f400-7def-8000-000000000030")
	eventID := uuid.Must(uuid.NewV7())
	deliveryID := uuid.Must(uuid.NewV7())
	raw, err := json.Marshal(canonicalEventV2{
		SpecVersion: CloudEventsV1, ID: eventID, Source: "/control-plane/plugin-webhooks",
		Type: "io.cdnca.site.v1.updated", Subject: "site/" + testSiteID.String(),
		Time: time.Date(2026, 7, 29, 8, 0, 0, 0, time.UTC), DataContentType: "application/json",
		DataSchema: domainEventSchemaV2, TenantID: testTenantID, RequestID: "request-domain-084", Sequence: 2,
		Data: siteEventData(subscriptionID),
	})
	if err != nil {
		t.Fatal(err)
	}
	identity := V2QueueIdentity{TargetScopeID: testTargetScopeID, TenantID: testTenantID,
		SubscriptionID: subscriptionID, SecretVersionID: testSecretVersionID,
		EventID: eventID, DeliveryID: deliveryID}
	item, err := NewV2QueueItem(raw, identity, "plugin-webhook-v2-"+strings.Repeat("a", 64),
		"https://hooks.example.com/v1/events")
	if err != nil {
		t.Fatalf("contract domain event rejected: %v", err)
	}
	if item.Schema != QueueSchemaV2 || item.Event.Type != "io.cdnca.site.v1.updated" ||
		!bytes.Equal(item.RawEvent, raw) || validateQueueItem(item) != nil {
		t.Fatalf("domain queue item = %#v", item)
	}
	var unknown canonicalEventV2
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&unknown); err != nil {
		t.Fatal(err)
	}
	unknown.Type = "io.cdnca.site.v1.unknown"
	unknownRaw, err := json.Marshal(unknown)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewV2QueueItem(unknownRaw, identity, "plugin-webhook-v2-"+strings.Repeat("a", 64),
		"https://hooks.example.com/v1/events"); err == nil {
		t.Fatal("unregistered domain event accepted")
	}
}

func TestNewV2QueueItemRejectsDomainEventWithoutSubscriptionIdentity(t *testing.T) {
	t.Parallel()
	subscriptionID := uuid.MustParse("018cc251-f400-7def-8000-000000000031")
	eventID := uuid.Must(uuid.NewV7())
	raw, err := json.Marshal(canonicalEventV2{
		SpecVersion: CloudEventsV1, ID: eventID, Source: "/control-plane/plugin-webhooks",
		Type: "io.cdnca.site.v1.updated", Subject: "site/" + testSiteID.String(),
		Time: time.Date(2026, 7, 29, 8, 0, 0, 0, time.UTC), DataContentType: "application/json",
		DataSchema: domainEventSchemaV2, TenantID: testTenantID, RequestID: "request-domain-085", Sequence: 2,
		Data: func() map[string]any {
			data := siteEventData(subscriptionID)
			delete(data, "subscription_id")
			return data
		}(),
	})
	if err != nil {
		t.Fatal(err)
	}
	identity := V2QueueIdentity{TargetScopeID: testTargetScopeID, TenantID: testTenantID,
		SubscriptionID: subscriptionID, SecretVersionID: testSecretVersionID,
		EventID: eventID, DeliveryID: uuid.Must(uuid.NewV7())}
	if _, err := NewV2QueueItem(raw, identity, "plugin-webhook-v2-"+strings.Repeat("a", 64),
		"https://hooks.example.com/v1/events"); err == nil {
		t.Fatal("domain event without subscription_id accepted")
	}
}

func TestNewV2QueueItemRequiresCanonicalSubscriptionIdentityInBody(t *testing.T) {
	t.Parallel()
	subscriptionID := uuid.MustParse("018cc251-f400-7def-8000-000000000031")
	eventID := uuid.MustParse("018cc251-f400-7def-8000-000000000032")
	identity := V2QueueIdentity{TargetScopeID: testTargetScopeID, TenantID: testTenantID,
		SubscriptionID: subscriptionID, SecretVersionID: testSecretVersionID,
		EventID: eventID, DeliveryID: uuid.MustParse("018cc251-f400-7def-8000-000000000033")}
	for name, encodedSubscription := range map[string]string{
		"compact":   strings.ReplaceAll(subscriptionID.String(), "-", ""),
		"uppercase": strings.ToUpper(subscriptionID.String()),
	} {
		t.Run(name, func(t *testing.T) {
			raw, err := json.Marshal(canonicalEventV2{
				SpecVersion: CloudEventsV1, ID: eventID, Source: "/control-plane/plugin-webhooks",
				Type: "io.cdnca.site.v1.updated", Subject: "site/" + testSiteID.String(),
				Time: time.Date(2026, 7, 29, 8, 0, 0, 0, time.UTC), DataContentType: "application/json",
				DataSchema: domainEventSchemaV2, TenantID: testTenantID, RequestID: "request-domain-identity", Sequence: 2,
				Data: func() map[string]any {
					data := siteEventData(subscriptionID)
					data["subscription_id"] = encodedSubscription
					return data
				}(),
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err = NewV2QueueItem(raw, identity, "plugin-webhook-v2-"+strings.Repeat("a", 64),
				"https://hooks.example.com/v1/events"); err == nil {
				t.Fatal("noncanonical subscription identity was accepted in signed body")
			}
		})
	}
}

var testSiteID = uuid.MustParse("018cc251-f400-7def-8000-0000000000a1")

// siteEventData is a delivered io.cdnca.site.v1.updated data object.
func siteEventData(subscription any) map[string]any {
	return map[string]any{"subscription_id": subscription, "subject_sequence": json.Number("9007199254740993"),
		"site_id": testSiteID.String(), "change": "updated", "changed_fields": []string{"origins", "https"}}
}

func TestNewV2QueueItemRejectsDomainEventOutsideItsContract(t *testing.T) {
	t.Parallel()
	subscriptionID := uuid.MustParse("018cc251-f400-7def-8000-000000000034")
	identity := V2QueueIdentity{TargetScopeID: testTargetScopeID, TenantID: testTenantID,
		SubscriptionID: subscriptionID, SecretVersionID: testSecretVersionID,
		EventID: uuid.Must(uuid.NewV7()), DeliveryID: uuid.Must(uuid.NewV7())}
	for name, mutate := range map[string]func(*canonicalEventV2){
		"subscription subject": func(event *canonicalEventV2) { event.Subject = "webhook_subscription/" + subscriptionID.String() },
		"other kind subject":   func(event *canonicalEventV2) { event.Subject = "node/" + testSiteID.String() },
		"extension field": func(event *canonicalEventV2) {
			data := siteEventData(subscriptionID)
			data["x_counter"] = json.Number("1")
			event.Data = data
		},
		"undeclared field": func(event *canonicalEventV2) {
			data := siteEventData(subscriptionID)
			data["origin_password"] = "secret"
			event.Data = data
		},
		"no subject sequence": func(event *canonicalEventV2) {
			data := siteEventData(subscriptionID)
			delete(data, "subject_sequence")
			event.Data = data
		},
		"unavailable type": func(event *canonicalEventV2) { event.Type = "io.cdnca.dns.v1.changed" },
	} {
		t.Run(name, func(t *testing.T) {
			event := canonicalEventV2{
				SpecVersion: CloudEventsV1, ID: identity.EventID, Source: "/control-plane/plugin-webhooks",
				Type: "io.cdnca.site.v1.updated", Subject: "site/" + testSiteID.String(),
				Time: time.Date(2026, 7, 29, 8, 0, 0, 0, time.UTC), DataContentType: "application/json",
				DataSchema: domainEventSchemaV2, TenantID: testTenantID, RequestID: uuid.NewString(), Sequence: 2,
				Data: siteEventData(subscriptionID),
			}
			mutate(&event)
			raw, err := json.Marshal(event)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := NewV2QueueItem(raw, identity, "plugin-webhook-v2-"+strings.Repeat("a", 64),
				"https://hooks.example.com/v1/events"); err == nil {
				t.Fatal("event outside its contract accepted")
			}
		})
	}
}
