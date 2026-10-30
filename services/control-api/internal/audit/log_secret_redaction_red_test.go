package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestNormalizePayloadRedactsNestedSecretVariants(t *testing.T) {
	raw := []byte(`{"Password":"one","pass_phrase":"two","client-secret":"three","refresh_token":"four","Authorization":"five","set-cookie":"six","api_key":"seven","private-key":"eight","safe":{"count":3,"enabled":true,"empty":null,"message":"keep"},"items":[{"TOKEN":"nine"},{"value":false}]}`)
	want := []byte(`{"Authorization":"[REDACTED]","Password":"[REDACTED]","api_key":"[REDACTED]","client-secret":"[REDACTED]","items":[{"TOKEN":"[REDACTED]"},{"value":false}],"pass_phrase":"[REDACTED]","private-key":"[REDACTED]","refresh_token":"[REDACTED]","safe":{"count":3,"empty":null,"enabled":true,"message":"keep"},"set-cookie":"[REDACTED]"}`)
	got, err := normalizePayload(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("normalized payload = %s, want %s", got, want)
	}
	again, err := normalizePayload(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again, got) {
		t.Fatalf("redaction is not idempotent: first=%s again=%s", got, again)
	}
}

func TestNormalizePayloadRedactsAccessAndSecretKeyVariants(t *testing.T) {
	raw := []byte(`{"access_key":"one","access_key_id":"two","ACCESS-KEY-ID":"three","nested":{"secret_key":"four","secret key":"five","safe_key":"keep"},"items":[{"tenant_access key":"six"}]}`)
	want := []byte(`{"ACCESS-KEY-ID":"[REDACTED]","access_key":"[REDACTED]","access_key_id":"[REDACTED]","items":[{"tenant_access key":"[REDACTED]"}],"nested":{"safe_key":"keep","secret key":"[REDACTED]","secret_key":"[REDACTED]"}}`)
	got, err := normalizePayload(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("normalized payload = %s, want %s", got, want)
	}
	again, err := normalizePayload(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again, got) {
		t.Fatalf("redaction is not idempotent: first=%s again=%s", got, again)
	}
}

func TestAppendStoresAndHashesRedactedPayload(t *testing.T) {
	tx := &auditCaptureTx{}
	fixedTime := time.Date(2026, 8, 7, 12, 0, 0, 123456000, time.UTC)
	log := NewWithClock(nil, func() time.Time { return fixedTime })
	input := Event{
		ScopeID: uuid.New(), Action: "secret.test", ResourceType: "audit", ResourceID: "resource-1",
		RequestID: "request-1", Result: "success", Payload: map[string]any{
			"nested": map[string]any{"database_password": "db-secret", "count": 4},
			"values": []any{map[string]any{"access-token": "token-secret"}, "safe"},
		},
	}
	if err := log.Append(context.Background(), tx, input); err != nil {
		t.Fatal(err)
	}
	if len(tx.insertArgs) != 20 { // tp-b6b: + user_agent
		t.Fatalf("insert args = %d, want 20", len(tx.insertArgs))
	}
	payload, ok := tx.insertArgs[9].([]byte)
	if !ok {
		t.Fatalf("stored payload type = %T", tx.insertArgs[9])
	}
	if strings.Contains(string(payload), "db-secret") || strings.Contains(string(payload), "token-secret") {
		t.Fatalf("stored payload leaked a secret: %s", payload)
	}
	var stored map[string]any
	if err := json.Unmarshal(payload, &stored); err != nil {
		t.Fatal(err)
	}
	if stored["nested"].(map[string]any)["database_password"] != "[REDACTED]" {
		t.Fatalf("stored nested password = %#v", stored["nested"])
	}

	event := record{
		ID: tx.insertArgs[0].(uuid.UUID), ScopeID: input.ScopeID, StreamPosition: 1,
		Action: input.Action, ResourceType: input.ResourceType, ResourceID: input.ResourceID,
		RequestID: input.RequestID, Result: input.Result, Payload: payload,
		PreviousHash: tx.insertArgs[10].([]byte), OccurredAt: fixedTime,
		Category: string(CategoryOther), ActorKind: ActorSystem, Changes: []byte("[]"),
	}
	wantHash, err := computeHash(event)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(tx.insertArgs[11].([]byte), wantHash) {
		t.Fatal("stored event hash does not cover the redacted canonical payload")
	}
}

type auditCaptureTx struct {
	pgx.Tx
	insertArgs []any
}

func (tx *auditCaptureTx) Exec(_ context.Context, query string, args ...any) (pgconn.CommandTag, error) {
	if strings.Contains(query, "INSERT INTO audit_events") {
		tx.insertArgs = append([]any(nil), args...)
	}
	return pgconn.NewCommandTag("OK"), nil
}

func (tx *auditCaptureTx) QueryRow(context.Context, string, ...any) pgx.Row {
	return auditNoRows{}
}

type auditNoRows struct{}

func (auditNoRows) Scan(...any) error { return pgx.ErrNoRows }
