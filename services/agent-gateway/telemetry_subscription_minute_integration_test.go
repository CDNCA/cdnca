//go:build integration

package gateway

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

// TestSubscriptionMinuteGatewayLeg (ML-07 S3 e2e, tests/subscription-minutes):
// the wire records the agent leg wrote (CDNCA_MINUTE_RECORDS, real
// OpenResty -> dyntelemetry -> event spool -> telemetry publisher) are
// validated and bound the way the gateway does and written for the
// control-api leg (CDNCA_MINUTE_BOUND: JSON lines of bound publications).
func TestSubscriptionMinuteGatewayLeg(t *testing.T) {
	in, out := os.Getenv("CDNCA_MINUTE_RECORDS"), os.Getenv("CDNCA_MINUTE_BOUND")
	if in == "" || out == "" {
		t.Skip("set CDNCA_MINUTE_RECORDS and CDNCA_MINUTE_BOUND (tests/subscription-minutes/run.sh)")
	}
	const (
		node         = "0d9a0000-0000-4000-8000-0000000000a1"
		tenant       = "0d9a0000-0000-4000-8000-000000000002"
		config       = "0d9a0000-0000-4000-8000-0000000000a2"
		installation = "0d9a-d9-filters-installation"
	)
	file, err := os.Open(in)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	type wire struct {
		Kind, MessageID, LastEventID, Payload string
	}
	var records []wire
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1<<20), 1<<20)
	for scanner.Scan() {
		var record struct {
			Kind        string `json:"kind"`
			MessageID   string `json:"message_id"`
			LastEventID string `json:"last_event_id"`
			Payload     string `json:"payload"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			t.Fatal(err)
		}
		records = append(records, wire(record))
	}
	if len(records) == 0 {
		t.Fatal("no wire records")
	}
	// The authorization the control plane gives this node: every site of the
	// fixture under its subscription (the agent bound each minute to one).
	authority := telemetryAuthorization{tenantID: tenant, installationID: installation,
		configBySite: map[telemetryScopeKey]string{}, subscriptionBySite: map[telemetryScopeKey]string{}}
	var probe struct {
		Events []struct {
			SiteID         string `json:"site_id"`
			SubscriptionID string `json:"subscription_id"`
		} `json:"events"`
	}
	output, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	encoder := json.NewEncoder(output)
	for index, record := range records {
		payload, err := base64.StdEncoding.DecodeString(record.Payload)
		if err != nil || record.Kind != "subscription_minute.v1" {
			t.Fatalf("record %d: kind %q %v", index, record.Kind, err)
		}
		if err := json.Unmarshal(payload, &probe); err != nil || len(probe.Events) != 1 {
			t.Fatalf("record %d: %v", index, err)
		}
		key := telemetryScopeKey{siteID: probe.Events[0].SiteID, configVersionID: config}
		authority.configBySite[key] = tenant
		authority.subscriptionBySite[key] = probe.Events[0].SubscriptionID
		message := &agentv1.TelemetryRecord{Kind: agentv1.TelemetryKind_TELEMETRY_KIND_SUBSCRIPTION_MINUTE_V1, MessageId: record.MessageID,
			FirstSequence: uint64(index + 1), LastSequence: uint64(index + 1), EventCount: 1, LastEventId: record.LastEventID, Payload: payload}
		ids, siteID, configVersionID, err := validateTelemetryPayload(message, node, authority, time.Now())
		if err != nil || len(ids) != 1 || siteID != key.siteID || configVersionID != config {
			t.Fatalf("record %d rejected: %v", index, err)
		}
		if err := bindTelemetryPackageSubscription(message, authority.subscriptionBySite[key], installation); err != nil {
			t.Fatalf("record %d bind: %v", index, err)
		}
		// what NATSTelemetryPublisher.Publish sends (subject + headers)
		if err := encoder.Encode(map[string]string{"subject": TelemetryIngestSubjectPrefix + "." + node, "message_id": record.MessageID,
			"node_id": node, "tenant_id": tenant, "site_id": siteID, "config_version_id": configVersionID, "installation_id": installation,
			"payload": base64.StdEncoding.EncodeToString(message.Payload)}); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("bound %d records", len(records))
}
