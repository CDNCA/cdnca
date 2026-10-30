package audit

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestComputeHashCoversEveryPersistentField(t *testing.T) {
	base := testRecord()
	want, err := computeHash(base)
	if err != nil {
		t.Fatalf("computeHash() error = %v", err)
	}
	otherActor := uuid.New()
	tests := map[string]func(*record){
		"id":              func(event *record) { event.ID = uuid.New() },
		"scope_id":        func(event *record) { event.ScopeID = uuid.New() },
		"stream_position": func(event *record) { event.StreamPosition++ },
		"actor_user_id":   func(event *record) { event.ActorUserID = &otherActor },
		"action":          func(event *record) { event.Action = "changed" },
		"resource_type":   func(event *record) { event.ResourceType = "changed" },
		"resource_id":     func(event *record) { event.ResourceID = "changed" },
		"request_id":      func(event *record) { event.RequestID = "changed" },
		"result":          func(event *record) { event.Result = "denied" },
		"payload":         func(event *record) { event.Payload = []byte(`{"count":2}`) },
		"previous_hash":   func(event *record) { event.PreviousHash = bytes.Repeat([]byte{2}, 32) },
		"occurred_at":     func(event *record) { event.OccurredAt = event.OccurredAt.Add(time.Second) },
		"category":        func(event *record) { event.Category = "finance" },
		"actor_kind":      func(event *record) { event.ActorKind = ActorPlugin },
		"actor_ref":       func(event *record) { event.ActorRef = "plugin:other" },
		"source_ip":       func(event *record) { event.SourceIP = "198.51.100.9" },
		"reason_code":     func(event *record) { event.ReasonCode = "changed" },
		"changes":         func(event *record) { event.Changes = []byte(`[{"field":"x","before":1,"after":2}]`) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			changed := base
			mutate(&changed)
			got, err := computeHash(changed)
			if err != nil {
				t.Fatalf("computeHash() error = %v", err)
			}
			if bytes.Equal(got, want) {
				t.Fatalf("hash did not change when %s changed", name)
			}
		})
	}
}

func TestVerifyRecordDetectsActorTampering(t *testing.T) {
	event := testRecord()
	event.EventHash, _ = computeHash(event)
	if err := verifyRecord(event, event.StreamPosition, event.PreviousHash); err != nil {
		t.Fatalf("verifyRecord(valid) error = %v", err)
	}
	tamperedActor := uuid.New()
	event.ActorUserID = &tamperedActor
	if err := verifyRecord(event, event.StreamPosition, event.PreviousHash); !errors.Is(err, ErrInvalidChain) {
		t.Fatalf("verifyRecord(tampered actor) error = %v, want ErrInvalidChain", err)
	}
}

func TestComputeHashNormalizesJSONPayload(t *testing.T) {
	first := testRecord()
	first.Payload = []byte(`{"b":2,"a":1}`)
	second := first
	second.Payload = []byte("{ \"a\": 1, \"b\": 2 }")
	firstHash, err := computeHash(first)
	if err != nil {
		t.Fatalf("computeHash(first) error = %v", err)
	}
	secondHash, err := computeHash(second)
	if err != nil {
		t.Fatalf("computeHash(second) error = %v", err)
	}
	if !bytes.Equal(firstHash, secondHash) {
		t.Fatal("semantically equal JSON payloads produced different hashes")
	}
}

func testRecord() record {
	actor := uuid.New()
	return record{
		ID:             uuid.New(),
		ScopeID:        uuid.New(),
		StreamPosition: 2,
		ActorUserID:    &actor,
		Action:         "node.create",
		ResourceType:   "node",
		ResourceID:     uuid.NewString(),
		RequestID:      "request-1",
		Result:         "success",
		Payload:        []byte(`{"count":1}`),
		PreviousHash:   bytes.Repeat([]byte{1}, 32),
		OccurredAt:     time.Date(2026, 7, 21, 12, 0, 0, 123000, time.UTC),
		Category:       "node",
		ActorKind:      ActorUser,
		SourceIP:       "192.0.2.1",
		Changes:        []byte("[]"),
	}
}
