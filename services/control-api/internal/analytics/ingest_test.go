package analytics

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestIngestDecoderAcceptsVersionedAccessAndSecurityEnvelopes(t *testing.T) {
	t.Parallel()
	now := time.Date(2099, 1, 1, 1, 0, 0, 0, time.UTC)
	decoder := mustIngestDecoder(t, now, IngestDecoderConfig{})
	subject, err := IngestSubject(testNodeID)
	if err != nil {
		t.Fatal(err)
	}

	accessPayload := marshalAccessEnvelope(t, "access-message", now, []AccessEvent{validAccessEvent("access-event")})
	access, err := decoder.Decode(subject, "access-message", accessPayload)
	if err != nil {
		t.Fatal(err)
	}
	if access.Kind != AccessEnvelopeType || access.MessageID != "access-message" || len(access.AccessEvents) != 1 ||
		access.PayloadDigest != sha256Sum(accessPayload) {
		t.Fatalf("access envelope = %#v", access)
	}
	unicodeEvent := validAccessEvent("unicode-event")
	unicodeEvent.Host = "例子.example"
	unicodePayload := marshalAccessEnvelope(t, "unicode-message", now, []AccessEvent{unicodeEvent})
	unicodeDecoded, err := decoder.Decode(subject, "unicode-message", unicodePayload)
	if err != nil || len(unicodeDecoded.AccessEvents) != 1 || unicodeDecoded.AccessEvents[0].Host != unicodeEvent.Host {
		t.Fatalf("Unicode access envelope = %#v, error = %v", unicodeDecoded, err)
	}

	securityPayload := marshalSecurityEnvelope(t, "security-message", now, []SecurityEvent{validSecurityEvent("security-event")})
	security, err := decoder.Decode(subject, "security-message", securityPayload)
	if err != nil {
		t.Fatal(err)
	}
	if security.Kind != SecurityEnvelopeType || len(security.SecurityEvents) != 1 ||
		security.PayloadDigest != sha256Sum(securityPayload) {
		t.Fatalf("security envelope = %#v", security)
	}
}

func TestIngestDecoderRejectsMalformedAndAmbiguousJSON(t *testing.T) {
	t.Parallel()
	now := time.Date(2099, 1, 1, 1, 0, 0, 0, time.UTC)
	decoder := mustIngestDecoder(t, now, IngestDecoderConfig{MaxMessageBytes: 4096})
	subject, _ := IngestSubject(testNodeID)
	valid := marshalAccessEnvelope(t, "message", now, []AccessEvent{validAccessEvent("event")})

	unknownTop := append([]byte(nil), valid...)
	unknownTop[len(unknownTop)-1] = ','
	unknownTop = append(unknownTop, []byte(`"unknown":true}`)...)
	unknownEvent := bytes.Replace(valid, []byte(`"duration_us":1000`), []byte(`"duration_us":1000,"unknown":true`), 1)
	duplicateTop := bytes.Replace(valid, []byte(`"schema_version":1`), []byte(`"schema_version":1,"schema_version":1`), 1)
	duplicateNested := bytes.Replace(valid, []byte(`"event_id":"event"`), []byte(`"event_id":"event","event_id":"event"`), 1)
	invalidUTF8 := bytes.Replace(valid, []byte("example.test"), []byte{'e', 'x', 0xff, 'a', 'm', 'p', 'l', 'e'}, 1)
	tests := []struct {
		name    string
		payload []byte
		code    string
	}{
		{"empty", nil, RejectInvalidJSON},
		{"syntax", []byte(`{"schema_version":`), RejectInvalidJSON},
		{"trailing", append(valid, []byte(` {}`)...), RejectInvalidJSON},
		{"unknown top", unknownTop, RejectInvalidJSON},
		{"unknown event", unknownEvent, RejectInvalidJSON},
		{"duplicate top", duplicateTop, RejectInvalidJSON},
		{"duplicate nested", duplicateNested, RejectInvalidJSON},
		{"raw invalid UTF-8", invalidUTF8, RejectInvalidJSON},
		{"oversize", bytes.Repeat([]byte{'x'}, 4097), RejectMessageTooLarge},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := decoder.Decode(subject, "message", test.payload)
			if RejectionCode(err) != test.code {
				t.Fatalf("error = %v, code = %q", err, RejectionCode(err))
			}
		})
	}
}

func TestIngestDecoderRejectsForgedJSONStructureBeforeEventValidation(t *testing.T) {
	t.Parallel()
	now := time.Date(2099, 1, 1, 1, 0, 0, 0, time.UTC)
	decoder := mustIngestDecoder(t, now, IngestDecoderConfig{})
	subject, _ := IngestSubject(testNodeID)

	deepEvent := validAccessEvent("budget-deep")
	var nested any = map[string]any{"leaf": "value"}
	for depth := 0; depth < 40; depth++ {
		nested = map[string]any{"nested": nested}
	}
	deepEvent.RequestBody = nested.(map[string]any)

	wideEvent := validAccessEvent("budget-wide")
	wideBody := make(map[string]any, 300)
	for index := 0; index < 300; index++ {
		wideBody[fmt.Sprintf("key-%03d", index)] = index
	}
	wideEvent.RequestBody = wideBody

	for _, test := range []struct {
		name  string
		event AccessEvent
	}{
		{name: "deep", event: deepEvent},
		{name: "wide", event: wideEvent},
	} {
		t.Run(test.name, func(t *testing.T) {
			payload := marshalAccessEnvelope(t, "budget-"+test.name, now, []AccessEvent{test.event})
			if len(payload) >= 1<<20 {
				t.Fatalf("forged payload unexpectedly exceeds decoder limit: %d", len(payload))
			}
			if _, err := decoder.Decode(subject, "budget-"+test.name, payload); RejectionCode(err) != RejectInvalidJSON {
				t.Fatalf("structure budget error = %v, code = %q, want %s", err, RejectionCode(err), RejectInvalidJSON)
			}
		})
	}
}

func TestValidateUniqueJSONKeysEnforcesExactStructureBoundaries(t *testing.T) {
	for _, test := range []struct {
		name    string
		payload []byte
		wantErr bool
	}{
		{name: "object depth 32", payload: nestedJSONObject(32, false)},
		{name: "object depth 33", payload: nestedJSONObject(33, false), wantErr: true},
		{name: "object leaf depth 32", payload: nestedJSONObject(32, true)},
		{name: "object leaf depth 33", payload: nestedJSONObject(33, true), wantErr: true},
		{name: "array depth 32", payload: nestedJSONArray(32, false)},
		{name: "array depth 33", payload: nestedJSONArray(33, false), wantErr: true},
		{name: "array leaf depth 32", payload: nestedJSONArray(32, true)},
		{name: "array leaf depth 33", payload: nestedJSONArray(33, true), wantErr: true},
		{name: "object keys 256", payload: jsonObjectWithKeys(maxJSONStructureObjectKeys)},
		{name: "object keys 257", payload: jsonObjectWithKeys(maxJSONStructureObjectKeys + 1), wantErr: true},
		{name: "tokens exact max", payload: jsonArrayWithValues(maxJSONStructureTokens - 2)},
		{name: "tokens max plus one", payload: jsonArrayWithValues(maxJSONStructureTokens - 1), wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateUniqueJSONKeys(test.payload)
			if (err != nil) != test.wantErr {
				t.Fatalf("validateUniqueJSONKeys() error = %v, wantErr = %v", err, test.wantErr)
			}
		})
	}
}

func TestIngestDecoderRejectsVersionIdentityTimeAndBatchViolations(t *testing.T) {
	t.Parallel()
	now := time.Date(2099, 1, 1, 1, 0, 0, 0, time.UTC)
	decoder := mustIngestDecoder(t, now, IngestDecoderConfig{MaxEvents: 2, MaxFutureSkew: time.Minute})
	subject, _ := IngestSubject(testNodeID)
	otherTenant := "10000000-0000-0000-0000-000000000002"
	otherNode := "30000000-0000-0000-0000-000000000002"

	validEvent := validAccessEvent("event")
	validEvent.OccurredAt = now.Add(-time.Minute)
	overlongPath := validEvent
	overlongPath.Path = "/" + strings.Repeat("x", 4096)
	tests := []struct {
		name     string
		envelope AccessIngestEnvelope
		brokerID string
		subject  string
		wantCode string
	}{
		{"version", accessEnvelope("message", now, []AccessEvent{validEvent}), "message", subject, RejectUnsupportedVersion},
		{"broker ID", accessEnvelope("message", now, []AccessEvent{validEvent}), "other-message", subject, RejectIdentityMismatch},
		{"subject node", accessEnvelope("message", now, []AccessEvent{validEvent}), "message", IngestSubjectPrefix + "." + otherNode, RejectIdentityMismatch},
		{"tenant claim", accessEnvelope("message", now, []AccessEvent{validEvent}), "message", subject, RejectInvalidEvent},
		{"node claim", accessEnvelope("message", now, []AccessEvent{validEvent}), "message", subject, RejectIdentityMismatch},
		{"future produced", accessEnvelope("message", now.Add(2*time.Minute), []AccessEvent{validEvent}), "message", subject, RejectInvalidTime},
		{"empty batch", accessEnvelope("message", now, nil), "message", subject, RejectBatchLimit},
		{"batch limit", accessEnvelope("message", now, []AccessEvent{validEvent, eventWithID(validEvent, "two"), eventWithID(validEvent, "three")}), "message", subject, RejectBatchLimit},
		{"duplicate event", accessEnvelope("message", now, []AccessEvent{validEvent, validEvent}), "message", subject, RejectInvalidEvent},
		{"string limit", accessEnvelope("message", now, []AccessEvent{overlongPath}), "message", subject, RejectInvalidEvent},
		{"future event", accessEnvelope("message", now, []AccessEvent{eventAt(validEvent, now.Add(2*time.Minute))}), "message", subject, RejectInvalidEvent},
		{"expired event", accessEnvelope("message", now, []AccessEvent{eventAt(validEvent, now.Add(-31*24*time.Hour))}), "message", subject, RejectInvalidEvent},
		{"stale envelope and event", accessEnvelope("message", now.Add(-31*24*time.Hour), []AccessEvent{eventAt(validEvent, now.Add(-31*24*time.Hour))}), "message", subject, RejectInvalidEvent},
		{"event beyond current skew", accessEnvelope("message", now.Add(time.Minute), []AccessEvent{eventAt(validEvent, now.Add(2*time.Minute))}), "message", subject, RejectInvalidEvent},
	}
	tests[0].envelope.SchemaVersion = 2
	tests[3].envelope.TenantID = otherTenant
	tests[4].envelope.NodeID = otherNode
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload, err := json.Marshal(test.envelope)
			if err != nil {
				t.Fatal(err)
			}
			_, err = decoder.Decode(test.subject, test.brokerID, payload)
			if RejectionCode(err) != test.wantCode {
				t.Fatalf("error = %v, code = %q, want %q", err, RejectionCode(err), test.wantCode)
			}
		})
	}
}

func TestIngestSubjectIsFixedAndValidated(t *testing.T) {
	t.Parallel()
	subject, err := IngestSubject(testNodeID)
	if err != nil {
		t.Fatal(err)
	}
	if subject != IngestSubjectPrefix+"."+testNodeID {
		t.Fatalf("subject = %q", subject)
	}
	if _, err := ParseIngestSubject(subject + ".extra"); RejectionCode(err) != RejectIdentityMismatch {
		t.Fatalf("extra token error = %v", err)
	}
	if _, err := IngestSubject(strings.ToUpper("30000000-0000-4000-8a00-000000000001")); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("uppercase node error = %v", err)
	}
	if _, err := IngestSubject("*"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("wildcard node error = %v", err)
	}
}

func mustIngestDecoder(t *testing.T, now time.Time, config IngestDecoderConfig) *IngestDecoder {
	t.Helper()
	config.Now = func() time.Time { return now }
	decoder, err := NewIngestDecoder(config)
	if err != nil {
		t.Fatal(err)
	}
	return decoder
}

func accessEnvelope(messageID string, producedAt time.Time, events []AccessEvent) AccessIngestEnvelope {
	return AccessIngestEnvelope{
		SchemaVersion: IngestSchemaVersion, Type: AccessEnvelopeType, MessageID: messageID,
		ProducedAt: producedAt, TenantID: testTenantID, NodeID: testNodeID, Events: events,
	}
}

func marshalAccessEnvelope(t *testing.T, messageID string, producedAt time.Time, events []AccessEvent) []byte {
	t.Helper()
	payload, err := json.Marshal(accessEnvelope(messageID, producedAt, events))
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func marshalSecurityEnvelope(t *testing.T, messageID string, producedAt time.Time, events []SecurityEvent) []byte {
	t.Helper()
	payload, err := json.Marshal(SecurityIngestEnvelope{
		SchemaVersion: IngestSchemaVersion, Type: SecurityEnvelopeType, MessageID: messageID,
		ProducedAt: producedAt, TenantID: testTenantID, NodeID: testNodeID, Events: events,
	})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func eventWithID(event AccessEvent, eventID string) AccessEvent {
	event.EventID = eventID
	return event
}

func eventAt(event AccessEvent, occurredAt time.Time) AccessEvent {
	event.OccurredAt = occurredAt
	return event
}

func nestedJSONObject(depth int, leaf bool) []byte {
	var payload strings.Builder
	payload.Grow(depth*6 + 2)
	wrappers := depth
	if !leaf {
		wrappers--
	}
	for level := 0; level < wrappers; level++ {
		payload.WriteString(`{"k":`)
	}
	if leaf {
		payload.WriteByte('0')
	} else {
		payload.WriteString(`{}`)
	}
	for level := 0; level < wrappers; level++ {
		payload.WriteByte('}')
	}
	return []byte(payload.String())
}

func nestedJSONArray(depth int, leaf bool) []byte {
	var payload strings.Builder
	payload.Grow(depth*2 + 2)
	wrappers := depth
	if !leaf {
		wrappers--
	}
	for level := 0; level < wrappers; level++ {
		payload.WriteByte('[')
	}
	if leaf {
		payload.WriteByte('0')
	} else {
		payload.WriteString(`[]`)
	}
	for level := 0; level < wrappers; level++ {
		payload.WriteByte(']')
	}
	return []byte(payload.String())
}

func jsonObjectWithKeys(count int) []byte {
	var payload strings.Builder
	payload.Grow(count*12 + 2)
	payload.WriteByte('{')
	for index := 0; index < count; index++ {
		if index != 0 {
			payload.WriteByte(',')
		}
		fmt.Fprintf(&payload, `"key-%03d":0`, index)
	}
	payload.WriteByte('}')
	return []byte(payload.String())
}

func jsonArrayWithValues(count int) []byte {
	var payload strings.Builder
	payload.Grow(count*2 + 2)
	payload.WriteByte('[')
	for index := 0; index < count; index++ {
		if index != 0 {
			payload.WriteByte(',')
		}
		payload.WriteByte('0')
	}
	payload.WriteByte(']')
	return []byte(payload.String())
}
