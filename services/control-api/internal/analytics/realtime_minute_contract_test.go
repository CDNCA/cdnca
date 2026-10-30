package analytics

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestRealtimeMinuteSQLSingleScanAndSnapshotBinding(t *testing.T) {
	from := time.Date(2026, 9, 24, 10, 17, 0, 0, time.UTC)
	filter := RealtimeFilter{From: from, To: from.Add(745 * time.Minute), Host: "cdn.example.test", ListenPort: 443}
	coverage := realtimeCoverageFilter(filter)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		query := string(body)
		if strings.Count(query, "FROM access_events FINAL") != 1 || strings.Count(query, "FROM connections_ingest_receipts_v1 FINAL") != 1 ||
			strings.Count(query, "GROUP BY GROUPING SETS") != 2 || strings.Contains(query, "expected AS") {
			t.Errorf("bounding evidence and projections must not rescan raw access facts or invent expected counts")
		}
		parameters := request.URL.Query()
		for key, expected := range map[string]string{
			"param_from_ms":          strconv.FormatInt(from.UnixMilli(), 10),
			"param_to_ms":            strconv.FormatInt(filter.To.UnixMilli(), 10),
			"param_coverage_from_ms": strconv.FormatInt(coverage.From.UnixMilli(), 10),
			"param_coverage_to_ms":   strconv.FormatInt(coverage.To.UnixMilli(), 10),
			"param_bucket_seconds":   "120", "param_host": filter.Host, "param_listen_port": "443",
		} {
			if parameters.Get(key) != expected {
				t.Errorf("%s=%q expected=%q", key, parameters.Get(key), expected)
			}
		}
		if snapshot, err := strconv.ParseInt(parameters.Get("param_snapshot_ms"), 10, 64); err != nil || snapshot <= 0 ||
			strings.Count(query, "{snapshot_ms:UInt64}") != 2 {
			t.Errorf("access and connection ingestion cutoff not shared")
		}
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	client := mustClient(t, Config{Endpoint: server.URL, Database: "analytics_test"}, server.Client())
	_, _ = client.Realtime(t.Context(), AdminScope(), filter)
}

func TestRealtimeMinuteOpenAPIAndUnavailableOriginBytes(t *testing.T) {
	data, err := os.ReadFile("../../../../api/control-analytics.openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Components struct {
			Schemas map[string]struct {
				Required []string `yaml:"required"`
			} `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(data, &document); err != nil {
		t.Fatalf("OpenAPI YAML: %v", err)
	}
	if len(document.Components.Schemas["RealtimePoint"].Required) != 13 || len(document.Components.Schemas["RealtimeEvidence"].Required) != 10 {
		t.Fatal("minute OpenAPI required fields drifted")
	}
	point, err := json.Marshal(RealtimePoint{})
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(point, &fields); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"origin_total_us", "origin_traffic_bytes", "origin_bandwidth_bps"} {
		if string(fields[key]) != "null" {
			t.Fatalf("unknown %s must be explicit null, got %s", key, fields[key])
		}
	}
}
