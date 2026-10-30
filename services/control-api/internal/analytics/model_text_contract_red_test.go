package analytics

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestIngestTextContractRejectsControlsAndMalformedUTF8(t *testing.T) {
	now := time.Date(2099, 1, 1, 1, 0, 0, 0, time.UTC)
	decoder := mustIngestDecoder(t, now, IngestDecoderConfig{})
	subject, err := IngestSubject(testNodeID)
	if err != nil {
		t.Fatal(err)
	}

	controls := []struct {
		name  string
		value string
	}{
		{name: "C0", value: "value\u0001text"},
		{name: "C1 low", value: "value\u0080text"},
		{name: "C1 high", value: "value\u009ftext"},
		{name: "DEL", value: "value\u007ftext"},
	}
	for index, test := range controls {
		t.Run("access carrier "+test.name, func(t *testing.T) {
			event := validAccessEvent("access-control")
			event.Carrier = test.value
			messageID := "access-control-" + string(rune('a'+index))
			decoded, err := decoder.Decode(subject, messageID, marshalAccessEnvelope(t, messageID, now, []AccessEvent{event}))
			if RejectionCode(err) != RejectInvalidEvent {
				t.Fatalf("Decode() error = %v, code = %q, want %s", err, RejectionCode(err), RejectInvalidEvent)
			}
			if !reflect.DeepEqual(decoded, DecodedIngest{}) {
				t.Fatalf("Decode() result = %#v, want zero result", decoded)
			}
		})

		t.Run("security severity "+test.name, func(t *testing.T) {
			event := validSecurityEvent("security-control")
			event.Severity = test.value
			messageID := "security-control-" + string(rune('a'+index))
			decoded, err := decoder.Decode(subject, messageID, marshalSecurityEnvelope(t, messageID, now, []SecurityEvent{event}))
			if RejectionCode(err) != RejectInvalidEvent {
				t.Fatalf("Decode() error = %v, code = %q, want %s", err, RejectionCode(err), RejectInvalidEvent)
			}
			if !reflect.DeepEqual(decoded, DecodedIngest{}) {
				t.Fatalf("Decode() result = %#v, want zero result", decoded)
			}
		})
	}

	malformed := string([]byte{'v', 0xff, 'x'})
	access := validAccessEvent("access-malformed")
	access.Carrier = malformed
	if err := validateAccessEvent(access); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("validateAccessEvent() error = %v, want %v", err, ErrInvalidInput)
	}
	security := validSecurityEvent("security-malformed")
	security.Severity = malformed
	if err := validateSecurityEvent(security); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("validateSecurityEvent() error = %v, want %v", err, ErrInvalidInput)
	}

	access = validAccessEvent("access-unicode")
	access.Carrier = "中国移动"
	if err := validateAccessEvent(access); err != nil {
		t.Fatalf("validateAccessEvent() Unicode error = %v", err)
	}
	accessDecoded, err := decoder.Decode(subject, "access-unicode", marshalAccessEnvelope(t, "access-unicode", now, []AccessEvent{access}))
	if err != nil || len(accessDecoded.AccessEvents) != 1 || accessDecoded.AccessEvents[0].Carrier != access.Carrier {
		t.Fatalf("Unicode access Decode() = %#v, error = %v", accessDecoded, err)
	}

	security = validSecurityEvent("security-unicode")
	security.Severity = "高危"
	if err := validateSecurityEvent(security); err != nil {
		t.Fatalf("validateSecurityEvent() Unicode error = %v", err)
	}
	securityDecoded, err := decoder.Decode(subject, "security-unicode", marshalSecurityEnvelope(t, "security-unicode", now, []SecurityEvent{security}))
	if err != nil || len(securityDecoded.SecurityEvents) != 1 || securityDecoded.SecurityEvents[0].Severity != security.Severity {
		t.Fatalf("Unicode security Decode() = %#v, error = %v", securityDecoded, err)
	}
}
