package analytics

import (
	"bytes"
	"testing"
	"time"
)

func TestIngestDecoderRejectsUnauthoritativeTaskAndJA4Claims(t *testing.T) {
	t.Parallel()
	now := time.Date(2099, 1, 1, 1, 0, 0, 0, time.UTC)
	decoder := mustIngestDecoder(t, now, IngestDecoderConfig{})
	subject, err := IngestSubject(testNodeID)
	if err != nil {
		t.Fatal(err)
	}

	taskID := "wire-task-claim"
	// Not a JA4 (two sections): the node only ever reports $cdnca_ja4.
	ja4 := "t13d1516h2_8daaf6152773"
	accessTask := validAccessEvent("access-task-claim")
	accessTask.TaskID = &taskID
	accessJA4 := validAccessEvent("access-ja4-claim")
	accessJA4.JA4 = &ja4
	securityTask := validSecurityEvent("security-task-claim")
	securityTask.TaskID = &taskID
	securityJA4 := validSecurityEvent("security-ja4-claim")
	securityJA4.JA4 = &ja4

	for _, test := range []struct {
		name      string
		messageID string
		payload   []byte
	}{
		{name: "access task_id", messageID: "access-task-message", payload: marshalAccessEnvelope(t, "access-task-message", now, []AccessEvent{accessTask})},
		{name: "access ja4", messageID: "access-ja4-message", payload: marshalAccessEnvelope(t, "access-ja4-message", now, []AccessEvent{accessJA4})},
		{name: "security task_id", messageID: "security-task-message", payload: marshalSecurityEnvelope(t, "security-task-message", now, []SecurityEvent{securityTask})},
		{name: "security ja4", messageID: "security-ja4-message", payload: marshalSecurityEnvelope(t, "security-ja4-message", now, []SecurityEvent{securityJA4})},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := decoder.Decode(subject, test.messageID, test.payload); RejectionCode(err) != RejectInvalidEvent {
				t.Fatalf("Decode() error = %v, code = %q, want %s", err, RejectionCode(err), RejectInvalidEvent)
			}
		})
	}

	for _, test := range []struct {
		name      string
		messageID string
		payload   []byte
	}{
		{name: "access explicit null", messageID: "access-null-message", payload: marshalAccessEnvelope(t, "access-null-message", now, []AccessEvent{validAccessEvent("access-null")})},
		{name: "security explicit null", messageID: "security-null-message", payload: marshalSecurityEnvelope(t, "security-null-message", now, []SecurityEvent{validSecurityEvent("security-null")})},
	} {
		t.Run(test.name, func(t *testing.T) {
			if !bytes.Contains(test.payload, []byte(`"task_id":null`)) || !bytes.Contains(test.payload, []byte(`"ja4":null`)) {
				t.Fatalf("payload does not preserve explicit null authority fields: %s", test.payload)
			}
			if _, err := decoder.Decode(subject, test.messageID, test.payload); err != nil {
				t.Fatalf("Decode() error = %v", err)
			}
		})
	}

	fingerprint := "t13d1516h2_8daaf6152771_e5627efa2ab1"
	accessFingerprint := validAccessEvent("access-ja4-real")
	accessFingerprint.JA4 = &fingerprint
	securityFingerprint := validSecurityEvent("security-ja4-real")
	securityFingerprint.JA4 = &fingerprint
	for _, payload := range [][]byte{
		marshalAccessEnvelope(t, "access-ja4-real-message", now, []AccessEvent{accessFingerprint}),
		marshalSecurityEnvelope(t, "security-ja4-real-message", now, []SecurityEvent{securityFingerprint}),
	} {
		messageID := "access-ja4-real-message"
		if bytes.Contains(payload, []byte(`security.v1`)) {
			messageID = "security-ja4-real-message"
		}
		if _, err := decoder.Decode(subject, messageID, payload); err != nil {
			t.Fatalf("Decode(%s) with a node JA4 error = %v", messageID, err)
		}
	}
}
