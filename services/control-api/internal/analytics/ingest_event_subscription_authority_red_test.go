package analytics

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

const eventAuthoritySubscriptionID = "4aaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1"

func TestIngestDecoderEnforcesCanonicalEventSubscriptionAuthority(t *testing.T) {
	now := time.Date(2099, 1, 1, 1, 0, 0, 0, time.UTC)
	decoder, err := NewIngestDecoder(IngestDecoderConfig{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	subject, err := IngestSubject(testNodeID)
	if err != nil {
		t.Fatal(err)
	}
	otherSubscription := "4aaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2"
	uppercaseSubscription := strings.ToUpper(eventAuthoritySubscriptionID)
	tests := []struct {
		name              string
		rootSubscription  string
		eventSubscription any
		omitEventClaim    bool
		wantCode          string
	}{
		{name: "canonical", rootSubscription: eventAuthoritySubscriptionID, eventSubscription: eventAuthoritySubscriptionID},
		{name: "legacy explicit empty", rootSubscription: "", eventSubscription: ""},
		{name: "missing event claim", rootSubscription: eventAuthoritySubscriptionID, omitEventClaim: true, wantCode: RejectInvalidEvent},
		{name: "null event claim", rootSubscription: eventAuthoritySubscriptionID, eventSubscription: nil, wantCode: RejectInvalidEvent},
		{name: "uppercase event claim", rootSubscription: eventAuthoritySubscriptionID, eventSubscription: uppercaseSubscription, wantCode: RejectInvalidEvent},
		{name: "mismatched event claim", rootSubscription: eventAuthoritySubscriptionID, eventSubscription: otherSubscription, wantCode: RejectInvalidEvent},
		{name: "uppercase root and event", rootSubscription: uppercaseSubscription, eventSubscription: uppercaseSubscription, wantCode: RejectIdentityMismatch},
	}
	for _, kind := range []string{AccessEnvelopeType, SecurityEnvelopeType} {
		t.Run(kind, func(t *testing.T) {
			for index, test := range tests {
				t.Run(test.name, func(t *testing.T) {
					messageID := fmt.Sprintf("subscription-%d", index)
					payload := eventSubscriptionEnvelope(t, kind, messageID, now, test.rootSubscription, test.eventSubscription, test.omitEventClaim)
					_, err := decoder.Decode(subject, messageID, payload)
					if test.wantCode == "" {
						if err != nil {
							t.Fatalf("Decode() error = %v", err)
						}
						return
					}
					if code := RejectionCode(err); code != test.wantCode {
						t.Fatalf("Decode() error = %v, code = %q, want %q", err, code, test.wantCode)
					}
				})
			}
		})
	}
}

func eventSubscriptionEnvelope(
	t *testing.T,
	kind string,
	messageID string,
	producedAt time.Time,
	rootSubscription string,
	eventSubscription any,
	omitEventClaim bool,
) []byte {
	t.Helper()
	var event any
	switch kind {
	case AccessEnvelopeType:
		event = validAccessEvent("subscription-event")
	case SecurityEnvelopeType:
		event = validSecurityEvent("subscription-event")
	default:
		t.Fatalf("unsupported test kind %q", kind)
	}
	encodedEvent, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	var eventFields map[string]any
	if err := json.Unmarshal(encodedEvent, &eventFields); err != nil {
		t.Fatal(err)
	}
	if omitEventClaim {
		delete(eventFields, "package_subscription_id")
	} else {
		eventFields["package_subscription_id"] = eventSubscription
	}
	envelope := map[string]any{
		"schema_version":          IngestSchemaVersion,
		"type":                    kind,
		"message_id":              messageID,
		"produced_at":             producedAt,
		"tenant_id":               testTenantID,
		"node_id":                 testNodeID,
		"package_subscription_id": rootSubscription,
		"events":                  []any{eventFields},
	}
	payload, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}
