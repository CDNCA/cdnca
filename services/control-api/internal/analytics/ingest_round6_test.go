package analytics

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

func TestOBSUsageARound7LiteralEdgeWirePreservesNullableAuthorityFields(t *testing.T) {
	t.Parallel()
	now := time.Date(2099, 1, 1, 1, 0, 0, 0, time.UTC)
	fixtures := []struct {
		name      string
		messageID string
		payload   []byte
		assert    func(*testing.T, *fakeIngestWriter)
	}{
		{
			name:      "access",
			messageID: "edge-wire-access-r7",
			payload:   []byte(`{"schema_version":1,"type":"access.v1","message_id":"edge-wire-access-r7","produced_at":"2099-01-01T01:00:00Z","tenant_id":"10000000-0000-0000-0000-000000000001","node_id":"30000000-0000-0000-0000-000000000001","events":[{"metric_version":1,"event_id":"edge-access-r7","occurred_at":"2099-01-01T00:59:00Z","tenant_id":"10000000-0000-0000-0000-000000000001","site_id":"20000000-0000-0000-0000-000000000001","node_id":"30000000-0000-0000-0000-000000000001","task_id":null,"host":"edge.example.test","path":"/literal-access","client_ip":"203.0.113.10","method":"GET","protocol":"HTTP/2","cache_status":"HIT","status_code":200,"request_bytes":10,"response_bytes":20,"duration_us":30,"ja4":null,"origin_connect_us":1200,"origin_first_byte_us":2400,"origin_total_us":3600,"request_headers":null,"response_headers":null,"request_body":null,"response_body":null}]}`),
			assert: func(t *testing.T, writer *fakeIngestWriter) {
				t.Helper()
				if writer.accessCalls != 1 || len(writer.accessEvents) != 1 || len(writer.accessEvents[0]) != 1 {
					t.Fatalf("access writer calls=%d events=%v", writer.accessCalls, writer.accessEvents)
				}
				event := writer.accessEvents[0][0]
				if event.TaskID != nil || event.JA4 != nil || event.OriginConnectUS == nil || *event.OriginConnectUS != 1200 ||
					event.OriginFirstByteUS == nil || *event.OriginFirstByteUS != 2400 ||
					event.OriginTotalUS == nil || *event.OriginTotalUS != 3600 {
					t.Fatalf("access nullable authority fields=%+v", event)
				}
				if event.RequestHeaders != nil || event.ResponseHeaders != nil || event.RequestBody != nil || event.ResponseBody != nil {
					t.Fatalf("disabled capture leaked into access writer=%+v", event)
				}
				insert, err := accessInsertFrom(event)
				if err != nil {
					t.Fatal(err)
				}
				encoded, err := json.Marshal(insert)
				if err != nil {
					t.Fatal(err)
				}
				var row map[string]any
				decoder := json.NewDecoder(bytes.NewReader(encoded))
				decoder.UseNumber()
				if err := decoder.Decode(&row); err != nil {
					t.Fatal(err)
				}
				for field, want := range map[string]string{
					"origin_connect_us": "1200", "origin_first_byte_us": "2400", "origin_total_us": "3600",
				} {
					got, ok := row[field].(json.Number)
					if !ok || got.String() != want {
						t.Fatalf("stored %s=%#v, want %s", field, row[field], want)
					}
				}
				if row["task_id"] != nil || row["ja4"] != nil {
					t.Fatalf("stored nullable authority fields=%#v", row)
				}
			},
		},
		{
			name:      "security",
			messageID: "edge-wire-security-r7",
			payload:   []byte(`{"schema_version":1,"type":"security.v1","message_id":"edge-wire-security-r7","produced_at":"2099-01-01T01:00:00Z","tenant_id":"10000000-0000-0000-0000-000000000001","node_id":"30000000-0000-0000-0000-000000000001","events":[{"metric_version":1,"event_id":"edge-security-r7","occurred_at":"2099-01-01T00:59:00Z","tenant_id":"10000000-0000-0000-0000-000000000001","site_id":"20000000-0000-0000-0000-000000000001","node_id":"30000000-0000-0000-0000-000000000001","task_id":null,"host":"edge.example.test","path":"/literal-security","client_ip":"203.0.113.11","event_type":"waf","action":"block","severity":"high","status_code":403,"request_bytes":11,"response_bytes":21,"ja4":null,"origin_connect_us":null,"origin_first_byte_us":null,"origin_total_us":null,"request_headers":null,"response_headers":null,"request_body":null,"response_body":null}]}`),
			assert: func(t *testing.T, writer *fakeIngestWriter) {
				t.Helper()
				if writer.securityCalls != 1 || len(writer.securityEvents) != 1 || len(writer.securityEvents[0]) != 1 {
					t.Fatalf("security writer calls=%d events=%v", writer.securityCalls, writer.securityEvents)
				}
				event := writer.securityEvents[0][0]
				if event.TaskID != nil || event.JA4 != nil || event.OriginConnectUS != nil ||
					event.OriginFirstByteUS != nil || event.OriginTotalUS != nil {
					t.Fatalf("security nullable authority fields=%+v", event)
				}
			},
		},
	}
	for _, fixture := range fixtures {
		fixture := fixture
		t.Run(fixture.name, func(t *testing.T) {
			decoder, err := NewIngestDecoder(IngestDecoderConfig{Now: func() time.Time { return now }})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decoder.Decode(IngestSubjectPrefix+"."+testNodeID, fixture.messageID, fixture.payload); err != nil {
				t.Fatalf("literal Edge %s decode=%s err=%v", fixture.name, RejectionCode(err), err)
			}
			writer := &fakeIngestWriter{}
			processor := mustProcessor(t, now, writer, &memoryIsolationSink{}, IngestProcessorConfig{})
			delivery := &fakeIngestDelivery{
				subject: IngestSubjectPrefix + "." + testNodeID, payload: fixture.payload,
				messageID: fixture.messageID, installationID: "test-installation", streamSequence: 1,
			}
			result, err := processor.Process(context.Background(), []IngestDelivery{delivery})
			if err != nil || result.Acknowledged != 1 || result.Terminated != 0 || result.Naked != 0 {
				t.Fatalf("literal Edge %s result=%+v err=%v", fixture.name, result, err)
			}
			fixture.assert(t, writer)
		})
	}

	decoder, err := NewIngestDecoder(IngestDecoderConfig{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	access := fixtures[0]
	unknown := bytes.Replace(access.payload, []byte(`"events":[`), []byte(`"unknown_edge_field":true,"events":[`), 1)
	if _, err := decoder.Decode(IngestSubjectPrefix+"."+testNodeID, access.messageID, unknown); RejectionCode(err) != RejectInvalidJSON {
		t.Fatalf("unknown Edge field rejection=%v", err)
	}
	wrongType := []byte(strings.Replace(string(access.payload), `"origin_connect_us":1200`, `"origin_connect_us":"1200"`, 1))
	if _, err := decoder.Decode(IngestSubjectPrefix+"."+testNodeID, access.messageID, wrongType); RejectionCode(err) != RejectInvalidJSON {
		t.Fatalf("wrong origin timing type rejection=%v", err)
	}
}

func TestIsolationStoredMessageMustMatchPreparedIntentExactly(t *testing.T) {
	t.Parallel()
	payload := []byte(`{"schema_version":1,"wire_ciphertext":"ciphertext"}`)
	digest := sha256Sum(payload)
	intent := isolationPublishIntent{
		Subject: IsolationSubject, MessageID: "analytics-isolation-v1-exact",
		Payload: payload, PayloadSHA256: digest,
	}
	exact := &nats.RawStreamMsg{
		Subject: intent.Subject, Sequence: 42, Data: append([]byte(nil), payload...),
		Header: nats.Header{nats.MsgIdHdr: []string{intent.MessageID}},
	}
	if err := validateStoredIsolationEvidence(intent, exact); err != nil {
		t.Fatalf("exact evidence rejected: %v", err)
	}
	for name, mutate := range map[string]func(*nats.RawStreamMsg){
		"subject": func(message *nats.RawStreamMsg) { message.Subject += ".wrong" },
		"wire":    func(message *nats.RawStreamMsg) { message.Data = append(message.Data, 'x') },
		"msg id":  func(message *nats.RawStreamMsg) { message.Header.Set(nats.MsgIdHdr, intent.MessageID+"-wrong") },
		"extra header": func(message *nats.RawStreamMsg) {
			message.Header.Set("X-Extra", "wrong")
		},
		"duplicate msg id header": func(message *nats.RawStreamMsg) {
			message.Header.Add(nats.MsgIdHdr, intent.MessageID)
		},
	} {
		t.Run(name, func(t *testing.T) {
			headers := make(nats.Header, len(exact.Header))
			for key, values := range exact.Header {
				headers[key] = append([]string(nil), values...)
			}
			candidate := &nats.RawStreamMsg{
				Subject: exact.Subject, Sequence: exact.Sequence, Data: append([]byte(nil), exact.Data...),
				Header: headers,
			}
			mutate(candidate)
			if err := validateStoredIsolationEvidence(intent, candidate); err == nil {
				t.Fatal("mismatched stored evidence was accepted")
			}
		})
	}
	if !bytes.Equal(intent.Payload, payload) {
		t.Fatal("validation mutated prepared evidence bytes")
	}
}

// 去重窗口吞掉补发（PubAck duplicate 指向已删序号）时恢复必须指数退避，不能按扫描暂停 1ms 空转。
func TestIsolationEvidenceDedupeHiddenHoleBacksOff(t *testing.T) {
	t.Parallel()
	hidden := errors.Join(errIsolationEvidenceScanPending, errors.Join(errIsolationEvidenceDedupeHidden, nats.ErrMsgNotFound))
	wrapped := fmt.Errorf("publish terminal evidence: %w", hidden)
	if !retryableIsolationRecoveryError(wrapped) {
		t.Fatal("dedupe-hidden evidence hole must stay retryable")
	}
	if got := isolationEvidenceRecoveryDelay(wrapped, 1); got != isolationEvidenceRecoveryMinBackoff {
		t.Fatalf("first dedupe-hidden delay=%s want=%s", got, isolationEvidenceRecoveryMinBackoff)
	}
	if got := isolationEvidenceRecoveryDelay(wrapped, 20); got != isolationEvidenceRecoveryMaxBackoff {
		t.Fatalf("repeated dedupe-hidden delay=%s want=%s", got, isolationEvidenceRecoveryMaxBackoff)
	}
	if got := isolationEvidenceRecoveryDelay(errIsolationEvidenceScanPending, 20); got != isolationEvidenceRecoveryPause {
		t.Fatalf("bounded scan continuation delay=%s want=%s", got, isolationEvidenceRecoveryPause)
	}
}
