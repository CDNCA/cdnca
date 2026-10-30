package l4analytics

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestClickHouseFactWriterUsesDateTime64Milliseconds(t *testing.T) {
	body := make(chan []byte, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		defer request.Body.Close()
		payload, err := io.ReadAll(request.Body)
		if err != nil {
			t.Error(err)
			return
		}
		body <- payload
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	source, err := NewClickHouseSource(ClickHouseConfig{
		Endpoint: server.URL, Database: "facts", QueryTimeout: time.Second, HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	factWriter, err := NewClickHouseFactWriter(source)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Date(2026, 8, 9, 12, 34, 56, 123456789, time.UTC)
	finalized := started.Add(time.Second)
	event := &agentv1.L4SessionEventV1{
		Event:       &commonv1.EventMetadata{EventId: "event-1"},
		StartedAt:   timestamppb.New(started),
		FinalizedAt: timestamppb.New(finalized),
	}
	if err := factWriter.Write(t.Context(), []*agentv1.L4SessionEventV1{event}, 1); err != nil {
		t.Fatal(err)
	}

	var row struct {
		StartedAt   string `json:"started_at"`
		FinalizedAt string `json:"finalized_at"`
	}
	if err := json.Unmarshal(<-body, &row); err != nil {
		t.Fatal(err)
	}
	if row.StartedAt != "2026-08-09 12:34:56.123" || row.FinalizedAt != "2026-08-09 12:34:57.123" {
		t.Fatalf("ClickHouse DateTime64 values = %q, %q", row.StartedAt, row.FinalizedAt)
	}
}
