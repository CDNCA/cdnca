package analyticsconnections

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClickHouseWriterRecordsReceivedBeforePreparedOnRetry(t *testing.T) {
	var insertBodies [][]byte
	var insertTokens []string
	insertAttempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read insert body: %v", err)
		}
		if strings.HasPrefix(strings.TrimSpace(string(body)), "SELECT ") {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		insertBodies = append(insertBodies, body)
		insertTokens = append(insertTokens, r.URL.Query().Get("insert_deduplication_token"))
		insertAttempts++
		if insertAttempts == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	writer, err := NewClickHouseWriter(ClickHouseConfig{Endpoint: server.URL, Database: "analytics"}, server.Client())
	if err != nil {
		t.Fatalf("writer: %v", err)
	}
	receipt, err := ValidateDelivery(validConnectionsDelivery())
	if err != nil {
		t.Fatalf("receipt: %v", err)
	}
	if err := writer.Prepare(context.Background(), receipt); !errors.Is(err, ErrClickHouseUnavailable) {
		t.Fatalf("first prepare error = %v, want ClickHouse unavailable", err)
	}
	if err := writer.Prepare(context.Background(), receipt); err != nil {
		t.Fatalf("replay prepare: %v", err)
	}

	if len(insertBodies) != 2 {
		t.Fatalf("insert attempts = %d, want 2", len(insertBodies))
	}
	if insertTokens[0] == "" || insertTokens[0] != insertTokens[1] {
		t.Fatalf("insert token drift: %q", insertTokens)
	}
	for attempt, body := range insertBodies {
		encoded := strings.TrimSpace(string(body))
		separator := strings.IndexByte(encoded, '\n')
		if separator < 0 {
			t.Fatalf("attempt %d missing insert payload", attempt+1)
		}
		lines := strings.Split(strings.TrimSpace(encoded[separator+1:]), "\n")
		if len(lines) != 2 {
			t.Fatalf("attempt %d rows = %d, want received and prepared", attempt+1, len(lines))
		}
		var received, prepared struct {
			State ReceiptState `json:"state"`
		}
		if err := json.Unmarshal([]byte(lines[0]), &received); err != nil {
			t.Fatalf("attempt %d received row: %v", attempt+1, err)
		}
		if err := json.Unmarshal([]byte(lines[1]), &prepared); err != nil {
			t.Fatalf("attempt %d prepared row: %v", attempt+1, err)
		}
		if received.State != StateReceived || prepared.State != StateClickHousePrepared {
			t.Fatalf("attempt %d states = %q, %q; want received then ch_prepared", attempt+1, received.State, prepared.State)
		}
	}
}

func TestClickHouseWriterRanksStatesAndScopesTransitionTokens(t *testing.T) {
	type insertedRow struct {
		State                 ReceiptState `json:"state"`
		StateRank             uint8        `json:"state_rank"`
		ClickHouseInsertToken string       `json:"clickhouse_insert_token"`
	}
	var insertRows [][]insertedRow
	var requestTokens []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		encoded := strings.TrimSpace(string(body))
		if strings.HasPrefix(encoded, "SELECT ") {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		separator := strings.IndexByte(encoded, '\n')
		if separator < 0 {
			t.Fatalf("missing insert payload")
		}
		var rows []insertedRow
		for _, line := range strings.Split(strings.TrimSpace(encoded[separator+1:]), "\n") {
			var row insertedRow
			if err := json.Unmarshal([]byte(line), &row); err != nil {
				t.Fatalf("decode row: %v", err)
			}
			rows = append(rows, row)
		}
		insertRows = append(insertRows, rows)
		requestTokens = append(requestTokens, r.URL.Query().Get("insert_deduplication_token"))
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	writer, err := NewClickHouseWriter(ClickHouseConfig{Endpoint: server.URL, Database: "analytics"}, server.Client())
	if err != nil {
		t.Fatalf("writer: %v", err)
	}
	receipt, err := ValidateDelivery(validConnectionsDelivery())
	if err != nil {
		t.Fatalf("receipt: %v", err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if err := writer.Prepare(context.Background(), receipt); err != nil {
			t.Fatalf("prepare attempt %d: %v", attempt+1, err)
		}
	}
	for attempt := 0; attempt < 2; attempt++ {
		if err := writer.MarkBrokerAckObserved(context.Background(), receipt, receipt.PubAck); err != nil {
			t.Fatalf("ack transition attempt %d: %v", attempt+1, err)
		}
	}

	wantStates := [][]insertedRow{
		{{State: StateReceived, StateRank: 1}, {State: StateClickHousePrepared, StateRank: 2}},
		{{State: StateReceived, StateRank: 1}, {State: StateClickHousePrepared, StateRank: 2}},
		{{State: StateBrokerAckObserved, StateRank: 3}},
		{{State: StateBrokerAckObserved, StateRank: 3}},
	}
	if len(insertRows) != len(wantStates) {
		t.Fatalf("insert requests = %d, want %d", len(insertRows), len(wantStates))
	}
	for requestIndex, wantRows := range wantStates {
		if len(insertRows[requestIndex]) != len(wantRows) {
			t.Fatalf("request %d rows = %d, want %d", requestIndex+1, len(insertRows[requestIndex]), len(wantRows))
		}
		for rowIndex, want := range wantRows {
			got := insertRows[requestIndex][rowIndex]
			if got.State != want.State || got.StateRank != want.StateRank {
				t.Fatalf("request %d row %d state/rank = %q/%d, want %q/%d", requestIndex+1, rowIndex+1, got.State, got.StateRank, want.State, want.StateRank)
			}
			if got.ClickHouseInsertToken != receipt.ClickHouseToken {
				t.Fatalf("request %d row %d stored token = %q, want authority token", requestIndex+1, rowIndex+1, got.ClickHouseInsertToken)
			}
		}
	}
	if requestTokens[0] == "" || requestTokens[0] != requestTokens[1] {
		t.Fatalf("prepare request token is not replay-stable: %q", requestTokens)
	}
	if requestTokens[2] == "" || requestTokens[2] != requestTokens[3] {
		t.Fatalf("ack request token is not replay-stable: %q", requestTokens)
	}
	if requestTokens[0] == requestTokens[2] {
		t.Fatalf("prepare and ack transitions share request token: %q", requestTokens[0])
	}
}
