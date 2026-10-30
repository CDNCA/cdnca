package analytics

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestOBSUsageAIsolationRecordCarriesBoundedExactWire(t *testing.T) {
	t.Parallel()
	payload := []byte(`{"schema_version":1,"secret":"must-remain-encrypted"`)
	delivery := &fakeIngestDelivery{
		subject: IngestSubjectPrefix + "." + testNodeID,
		payload: payload, messageID: "reviewer-poison", attempts: 2, streamSequence: 17,
		installationID: "installation-reviewer",
	}
	record := isolationRecord(delivery, RejectInvalidJSON, time.Unix(1_700_000_000, 0).UTC())
	wire := reflect.ValueOf(record).FieldByName("Wire")
	if !wire.IsValid() || wire.IsNil() {
		t.Fatal("isolation record has no exact replayable wire fact")
	}
	wirePayload := wire.Elem().FieldByName("Payload")
	if !wirePayload.IsValid() || !bytes.Equal(wirePayload.Bytes(), payload) {
		t.Fatal("isolation wire did not preserve the exact bounded payload bytes")
	}
}

func TestOBSUsageAHourlyRebuildUsesAtomicShadowAndPreservesUnreconstructibleHistory(t *testing.T) {
	t.Parallel()
	repoRoot := filepath.Clean(filepath.Join("..", "..", "..", ".."))
	path := filepath.Join(repoRoot, "infra", "clickhouse", "rebuild-hourly-v1.sql")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	upper := strings.ToUpper(string(content))
	for _, destructive := range []string{
		"TRUNCATE TABLE ACCESS_HOURLY_FACTS_V1;",
		"TRUNCATE TABLE SECURITY_HOURLY_FACTS_V1;",
	} {
		if strings.Contains(upper, destructive) {
			t.Fatalf("rebuild destroys production facts before replacement: %s", destructive)
		}
	}
	for _, required := range []string{
		"{ACCESS_SHADOW:IDENTIFIER}",
		"{SECURITY_SHADOW:IDENTIFIER}",
		"EXCHANGE TABLES ACCESS_HOURLY_FACTS_V1 AND {ACCESS_SHADOW:IDENTIFIER}",
		"EXCHANGE TABLES SECURITY_HOURLY_FACTS_V1 AND {SECURITY_SHADOW:IDENTIFIER}",
		"FROM ACCESS_HOURLY_FACTS_V1 FINAL",
		"FROM SECURITY_HOURLY_FACTS_V1 FINAL",
	} {
		if !strings.Contains(upper, required) {
			t.Fatalf("atomic retained-history rebuild is missing %q", required)
		}
	}
}
