//go:build integration

package analytics

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// TestSubscriptionMinuteControlLeg (ML-07 S3 e2e, tests/subscription-minutes):
// the publications the gateway leg bound (CDNCA_MINUTE_BOUND) go through
// the real ingest processor (decoder, receipt, writer) into ClickHouse
// subscription_minutes_v1 (migrations up to 024), each one twice: a
// redelivery leaves one row per (subscription, minute, node).
// CDNCA_MINUTE_EXPECT: JSON {subscription_id: {max_connections, max_new_cps,
// max_qps}} the node side measured (maxima across the minutes).
func TestSubscriptionMinuteControlLeg(t *testing.T) {
	in := os.Getenv("CDNCA_MINUTE_BOUND")
	if in == "" {
		t.Skip("set CDNCA_MINUTE_BOUND (tests/subscription-minutes/run.sh)")
	}
	database := newRankTestDatabase(t)
	database.reset(t)
	applyAllClickHouseMigrations(t, database)
	client, err := NewClient(Config{Endpoint: database.endpoint, Database: database.name, Username: database.username,
		Password: database.password, QueryTimeout: 5 * time.Second}, &http.Client{Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(in)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1<<20), 1<<20)
	var deliveries []IngestDelivery
	const sequence = uint64(41) // each message has its own history (below)
	now := time.Now().UTC()
	var installation string
	for scanner.Scan() {
		var bound map[string]string
		if err := json.Unmarshal(scanner.Bytes(), &bound); err != nil {
			t.Fatal(err)
		}
		payload, err := base64.StdEncoding.DecodeString(bound["payload"])
		if err != nil {
			t.Fatal(err)
		}
		installation = bound["installation_id"]
		// each message delivered twice (a NATS redelivery after a lost ack)
		for range 2 {
			deliveries = append(deliveries, &fakeIngestDelivery{subject: bound["subject"], messageID: bound["message_id"], attempts: 1,
				streamSequence: sequence, installationID: installation, payload: payload})
		}
	}
	if len(deliveries) == 0 {
		t.Fatal("no bound publications")
	}
	generation := authorityGenerationV1()
	generation.InstallationID = installation
	// The recording history fixture tracks one message's receipt state, so
	// each message gets its own; its redelivery replays against the same one
	// (receipt already prepared: acknowledged without a second write).
	var history *recordingIngestHistoryAuthorityV1
	var processor *IngestProcessor
	for index, delivery := range deliveries {
		if index%2 == 0 {
			history = newRecordingIngestHistoryAuthorityV1(t, generation)
			processor = authorityProcessorV1(t, now, client, history, generation, &memoryIsolationSink{})
		}
		result, err := processor.Process(context.Background(), []IngestDelivery{delivery})
		if err != nil || result.Acknowledged != 1 || result.WriteBatches != 1-index%2 {
			t.Fatalf("process %d: %+v %v", index, result, err)
		}
	}
	// A write the history lost (ack lost after the insert): ClickHouse keeps
	// one row for the same token / (subscription, minute, node).
	first := deliveries[0].(*fakeIngestDelivery)
	decoded, err := mustIngestDecoder(t, now, IngestDecoderConfig{}).Decode(first.subject, first.messageID, first.payload)
	if err != nil {
		t.Fatal(err)
	}
	decoded.InstallationID = installation
	receipt, err := NewIngestReceiptV1(generation, 41, decoded)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.WriteSubscriptionMinutes(context.Background(), receipt.ClickHouseToken, decoded.SubscriptionMinutes); err != nil {
		t.Fatal(err)
	}
	rows := queryMinuteRows(t, database, "SELECT toString(package_subscription_id) AS sub, count() AS rows, max(max_connections) AS conns, "+
		"max(max_new_cps) AS new, max(max_qps) AS qps, sum(bytes_out) AS bytes FROM subscription_minutes_v1 FINAL GROUP BY sub ORDER BY sub FORMAT JSONEachRow")
	total := 0
	got := map[string]map[string]float64{}
	for _, row := range rows {
		total += int(number(row["rows"]))
		got[row["sub"].(string)] = map[string]float64{"max_connections": number(row["conns"]), "max_new_cps": number(row["new"]),
			"max_qps": number(row["qps"]), "bytes_out": number(row["bytes"])}
	}
	if total != len(deliveries)/2 {
		t.Fatalf("rows %d, want one per record (%d): %v", total, len(deliveries)/2, rows)
	}
	var expect map[string]map[string]float64
	if raw := os.Getenv("CDNCA_MINUTE_EXPECT"); raw != "" {
		if err := json.Unmarshal([]byte(raw), &expect); err != nil {
			t.Fatal(err)
		}
	}
	for sub, want := range expect {
		for key, value := range want {
			if got[sub][key] != value {
				t.Errorf("%s %s = %v, want %v (node side)", sub, key, got[sub][key], value)
			}
		}
	}
	t.Logf("%d records -> %d rows in subscription_minutes_v1: %v", len(deliveries)/2, total, got)
}

func queryMinuteRows(t *testing.T, database *rankTestDatabase, query string) []map[string]any {
	t.Helper()
	target, _ := url.Parse(database.endpoint)
	values := target.Query()
	values.Set("database", database.name)
	values.Set("output_format_json_quote_64bit_integers", "0")
	target.RawQuery = values.Encode()
	request, _ := http.NewRequest(http.MethodPost, target.String(), strings.NewReader(query))
	if database.username != "" {
		request.SetBasicAuth(database.username, database.password)
	}
	response, err := database.http.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("query: %d %s", response.StatusCode, body)
	}
	var rows []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
		if line == "" {
			continue
		}
		var row map[string]any
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			t.Fatal(err)
		}
		rows = append(rows, row)
	}
	return rows
}

func number(value any) float64 {
	n, _ := value.(float64)
	return n
}
