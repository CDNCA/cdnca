package analyticsconnections

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestConnectionsReceiptMigrationCarriesFinalizedDimensions(t *testing.T) {
	root := filepath.Join("..", "..", "..", "..", "infra", "clickhouse", "migrations")
	up, err := os.ReadFile(filepath.Join(root, "013_connections_finalized_dimensions.up.sql"))
	if err != nil {
		t.Fatalf("read migration 013: %v", err)
	}
	down, err := os.ReadFile(filepath.Join(root, "013_connections_finalized_dimensions.down.sql"))
	if err != nil {
		t.Fatalf("read migration 013 down: %v", err)
	}
	upText, downText := string(up), string(down)
	for _, required := range []string{
		"connections_ingest_receipts_v1", "ADD COLUMN IF NOT EXISTS node_id UUID",
		"ADD COLUMN IF NOT EXISTS domain", "ADD COLUMN IF NOT EXISTS listen_port UInt16",
		"node_id != toUUID", "length(domain) > 0", "listen_port BETWEEN 1 AND 65535",
		"finalized_connection_dimensions_v1",
	} {
		if !strings.Contains(upText, required) {
			t.Fatalf("migration 013 missing %q", required)
		}
	}
	if strings.Contains(strings.ToUpper(downText), "TRUNCATE") ||
		!strings.Contains(downText, "DROP COLUMN IF EXISTS node_id") ||
		!strings.Contains(downText, "DROP COLUMN IF EXISTS domain") ||
		!strings.Contains(downText, "DROP COLUMN IF EXISTS listen_port") {
		t.Fatalf("migration 013 down is not bounded: %s", downText)
	}
}

func TestClickHouseInsertCarriesFinalizedDimensions(t *testing.T) {
	receipt, err := ValidateDelivery(validConnectionsDelivery())
	if err != nil {
		t.Fatalf("receipt: %v", err)
	}
	row, ok := newReceiptInsertRow(receipt)
	if !ok {
		t.Fatal("valid receipt was rejected")
	}
	encoded, err := json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"node_id", "domain", "listen_port"} {
		if _, ok := fields[field]; !ok {
			t.Fatalf("insert row missing finalized dimension %q: %s", field, encoded)
		}
	}
}

func TestClickHouseLookupBindsFinalizedDimensionsAndTenant(t *testing.T) {
	receipt, err := ValidateDelivery(validConnectionsDelivery())
	if err != nil {
		t.Fatalf("receipt: %v", err)
	}
	var query string
	var bindingError string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			bindingError = readErr.Error()
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if !strings.HasPrefix(strings.TrimSpace(string(body)), "SELECT ") {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		query = string(body)
		for _, key := range []string{"param_tenant", "param_node", "param_domain", "param_listen_port"} {
			if r.URL.Query().Get(key) == "" {
				bindingError = "missing " + key
			}
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	writer, err := NewClickHouseWriter(ClickHouseConfig{Endpoint: server.URL, Database: "analytics"}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Prepare(context.Background(), receipt); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if bindingError != "" {
		t.Fatal(bindingError)
	}
	for _, token := range []string{"node_id={node:UUID}", "domain={domain:String}", "listen_port={listen_port:UInt16}", "tenant_id={tenant:UUID}"} {
		if !strings.Contains(query, token) {
			t.Fatalf("lookup query missing %q: %s", token, query)
		}
	}
}

func TestValidateDeliveryRejectsMissingFinalizedDimensions(t *testing.T) {
	delivery := validConnectionsDelivery()
	value := reflect.ValueOf(delivery.Envelope).Elem()
	for _, name := range []string{"NodeId", "Domain", "ListenPort"} {
		field := value.FieldByName(name)
		if field.IsValid() && field.CanSet() {
			field.Set(reflect.Zero(field.Type()))
		}
	}
	if _, err := ValidateDelivery(delivery); err == nil {
		t.Fatal("delivery without finalized connection dimensions was accepted")
	}
}
