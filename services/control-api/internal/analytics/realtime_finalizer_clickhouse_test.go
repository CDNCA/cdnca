package analytics

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClickHouseRealtimeConnectionEvidenceReadsExactFinalizedNodes(t *testing.T) {
	candidate, _, _, _ := realtimeCoverageFixture(t)
	var query string
	var parameters map[string]string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Error(err)
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		query = string(body)
		parameters = map[string]string{}
		for _, name := range []string{
			"tenant_id", "site_id", "domain", "listen_port", "window_start_ms", "window_end_ms",
		} {
			parameters[name] = request.URL.Query().Get("param_" + name)
		}
		_, _ = io.WriteString(writer,
			`{"result_node_id":"018f0000-0000-7000-8000-000000000004","max_source_watermark":11,"finalized_through_ms":1787828400000,"aggregate_evidence_sha256":"`+strings.Repeat("1", 64)+`","watermark_count":1,"watermark_evidence_count":1,"installation_count":1,"subscription_count":1}`+"\n"+
				`{"result_node_id":"018f0000-0000-7000-8000-000000000005","max_source_watermark":12,"finalized_through_ms":1787828400000,"aggregate_evidence_sha256":"`+strings.Repeat("2", 64)+`","watermark_count":2,"watermark_evidence_count":2,"installation_count":1,"subscription_count":1}`+"\n")
	}))
	defer server.Close()
	client, err := NewClient(Config{Endpoint: server.URL, Database: "analytics"}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	reader, err := NewClickHouseRealtimeConnectionEvidenceReader(client)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := reader.RealtimeConnectionEvidence(t.Context(), candidate)
	if err != nil || len(evidence) != 2 || evidence[0].SourceWatermark != 11 ||
		!evidence[0].FinalizedThrough.Equal(candidate.WindowEnd) ||
		!evidence[0].RecordedAt.Equal(candidate.WindowEnd) {
		t.Fatalf("evidence = %#v, error=%v", evidence, err)
	}
	for _, token := range []string{
		"connections_ingest_receipts_v1 FINAL", "schema_version IN (1,2)", "state_rank>=2", "config_version_count",
		"tenant_id={tenant_id:UUID}", "site_id={site_id:UUID}", "domain={domain:String}",
		"listen_port={listen_port:UInt16}", "finalized_through=", "GROUP BY node_id", "ORDER BY node_id",
		"uniqExact(installation_id)", "uniqExact(package_subscription_id)",
	} {
		if !strings.Contains(query, token) {
			t.Errorf("connection evidence query missing %q", token)
		}
	}
	if parameters["tenant_id"] != candidate.TenantID || parameters["site_id"] != candidate.SiteID ||
		parameters["domain"] != candidate.Host || parameters["listen_port"] != "443" ||
		parameters["window_start_ms"] == "" || parameters["window_end_ms"] == "" {
		t.Fatalf("query parameters = %#v", parameters)
	}
}

func TestClickHouseRealtimeConnectionEvidenceRejectsConflicts(t *testing.T) {
	candidate, _, _, _ := realtimeCoverageFixture(t)
	base := `{"result_node_id":"018f0000-0000-7000-8000-000000000004","max_source_watermark":11,"finalized_through_ms":1787828400000,"aggregate_evidence_sha256":"` +
		strings.Repeat("1", 64) + `","watermark_count":1,"watermark_evidence_count":1,"installation_count":1,"subscription_count":1}`
	for _, test := range []struct {
		name string
		body string
	}{
		{name: "same watermark different evidence", body: strings.Replace(base, `"watermark_evidence_count":1`, `"watermark_evidence_count":2`, 1)},
		{name: "multiple installations", body: strings.Replace(base, `"installation_count":1`, `"installation_count":2`, 1)},
		{name: "noncanonical digest", body: strings.Replace(base, strings.Repeat("1", 64), strings.Repeat("A", 64), 1)},
		{name: "duplicate node row", body: base + "\n" + base},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(writer, test.body+"\n")
			}))
			defer server.Close()
			client, err := NewClient(Config{Endpoint: server.URL, Database: "analytics"}, server.Client())
			if err != nil {
				t.Fatal(err)
			}
			reader, err := NewClickHouseRealtimeConnectionEvidenceReader(client)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := reader.RealtimeConnectionEvidence(t.Context(), candidate); err != ErrRealtimeCoverageConflict {
				t.Fatalf("conflict error = %v", err)
			}
		})
	}
}
