package analytics

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestOBSUsageARecoveryIsPersistedResumableAndLeaseFenced(t *testing.T) {
	t.Parallel()
	contents, err := os.ReadFile("ingest_nats.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(contents)
	for _, required := range []string{
		"consumer_recovery.v1",
		"type consumerRecoveryState struct",
		"recoveryDeletePending",
		"recoveryRecreatePending",
		"recoveryEpochPending",
		"recoveryCleanupPending",
		"withLeaseFence",
		"resumeConsumerRecovery",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("resumable recovery contract is missing %q", required)
		}
	}
	start := strings.Index(source, "func (consumer *NATSIngestConsumer) Fetch")
	end := strings.Index(source[start:], "func (consumer *NATSIngestConsumer) Close")
	if start < 0 || end < 0 {
		t.Fatal("cannot locate Fetch recovery boundary")
	}
	fetch := source[start : start+end]
	if strings.Index(fetch, "consumer.mu.Unlock()") > strings.Index(fetch, "consumer.recoverParked") {
		t.Fatal("Fetch still holds consumer.mu across parked recovery")
	}
}

func TestOBSUsageAIsolationUsesExternalWrappedDEKProvider(t *testing.T) {
	t.Parallel()
	contents, err := os.ReadFile("ingest_nats.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(contents)
	for _, required := range []string{
		"type IsolationKeyProvider interface",
		"wrapped_dek",
		"WireKeyID",
		"clear(dek)",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("envelope-encryption contract is missing %q", required)
		}
	}
	field, ok := reflect.TypeOf(JetStreamConfig{}).FieldByName("IsolationKeyProvider")
	providerType := reflect.TypeOf((*IsolationKeyProvider)(nil)).Elem()
	if !ok || field.Type != providerType {
		t.Fatal("JetStreamConfig has no caller-injected IsolationKeyProvider")
	}
	for _, forbidden := range []string{
		"isolationCipherKeyName = \"isolation_cipher_key.v1\"",
		"cipherKey        []byte",
	} {
		if strings.Contains(source, forbidden) {
			t.Errorf("same-store plaintext key contract remains: %q", forbidden)
		}
	}
}

func TestOBSUsageAHourlyDDLKeepsOldReadersUntilBackfillCompletes(t *testing.T) {
	t.Parallel()
	repoRoot := filepath.Clean(filepath.Join("..", "..", "..", ".."))
	checks := []struct {
		path         string
		accessView   string
		securityView string
	}{
		{
			path:         filepath.Join(repoRoot, "infra", "clickhouse", "migrations", "003_analytics_hourly_rollup.up.sql"),
			accessView:   "CREATE OR REPLACE VIEW access_hourly_v1",
			securityView: "CREATE OR REPLACE VIEW security_hourly_v1",
		},
		{
			// the cluster mirror of 003 (infra/clickhouse/replicated, one file per migration)
			path:         filepath.Join(repoRoot, "infra", "clickhouse", "replicated", "003_analytics_hourly_rollup.up.sql"),
			accessView:   "CREATE OR REPLACE VIEW access_hourly_v1 ON CLUSTER",
			securityView: "CREATE OR REPLACE VIEW security_hourly_v1 ON CLUSTER",
		},
	}
	for _, check := range checks {
		contents, err := os.ReadFile(check.path)
		if err != nil {
			t.Fatal(err)
		}
		source := string(contents)
		accessBackfill := strings.Index(source, "INSERT INTO access_hourly_facts_v1")
		securityBackfill := strings.Index(source, "INSERT INTO security_hourly_facts_v1")
		accessSwitch := strings.LastIndex(source, check.accessView)
		securitySwitch := strings.LastIndex(source, check.securityView)
		if accessBackfill < 0 || securityBackfill < 0 || accessSwitch < securityBackfill || securitySwitch < securityBackfill {
			t.Errorf("%s switches readers before both backfills complete", check.path)
		}
		cutover := minPositive(accessSwitch, securitySwitch)
		if cutover >= 0 {
			prefix := source[:cutover]
			if strings.Contains(prefix, "DROP VIEW IF EXISTS access_hourly_v1") || strings.Contains(prefix, "DROP VIEW IF EXISTS security_hourly_v1") {
				t.Errorf("%s drops old readers before final cutover", check.path)
			}
		}
	}
}

func TestOBSUsageARebuildObjectsAreRunScopedAndOwnerChecked(t *testing.T) {
	t.Parallel()
	repoRoot := filepath.Clean(filepath.Join("..", "..", "..", ".."))
	path := filepath.Join(repoRoot, "infra", "clickhouse", "rebuild-hourly-v1.sql")
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	source := string(contents)
	for _, required := range []string{
		"{run_marker:Identifier}",
		"{access_shadow:Identifier}",
		"{security_shadow:Identifier}",
		"{access_catchup:Identifier}",
		"{security_catchup:Identifier}",
		"{owner:String}",
		"throwIf",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("concurrent rebuild contract is missing %q", required)
		}
	}
	for _, fixed := range []string{
		"access_hourly_facts_v1_rebuild",
		"security_hourly_facts_v1_rebuild",
		"access_hourly_rebuild_catchup_v1",
		"security_hourly_rebuild_catchup_v1",
	} {
		if strings.Contains(source, fixed) {
			t.Errorf("rebuild still uses shared object %q", fixed)
		}
	}
	cleanupPath := filepath.Join(repoRoot, "infra", "clickhouse", "rebuild-hourly-cleanup-v1.sql")
	if _, err := os.Stat(cleanupPath); err != nil {
		t.Errorf("owned stale-run cleanup contract is missing: %v", err)
	}
}

func TestOBSUsageARebuildCanResumeBetweenHourlyFactExchanges(t *testing.T) {
	t.Parallel()
	repoRoot := filepath.Clean(filepath.Join("..", "..", "..", ".."))
	sqlPath := filepath.Join(repoRoot, "infra", "clickhouse", "rebuild-hourly-v1.sql")
	contents, err := os.ReadFile(sqlPath)
	if err != nil {
		t.Fatal(err)
	}
	source := string(contents)
	accessExchange := strings.Index(source, "EXCHANGE TABLES access_hourly_facts_v1")
	fault := strings.Index(source, "{fail_after_access_exchange:UInt8}")
	securityExchange := strings.Index(source, "EXCHANGE TABLES security_hourly_facts_v1")
	if accessExchange < 0 || fault <= accessExchange || securityExchange <= fault {
		t.Fatal("rebuild has no deterministic crash boundary between access and security exchanges")
	}

	wrapperPath := filepath.Join(repoRoot, "infra", "clickhouse", "analytics-rebuild-hourly-v1.sh")
	wrapper, err := os.ReadFile(wrapperPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"ANALYTICS_REBUILD_FAIL_AFTER_ACCESS_EXCHANGE",
		"--param_fail_after_access_exchange",
	} {
		if !strings.Contains(string(wrapper), required) {
			t.Errorf("rebuild wrapper is missing split-exchange recovery contract %q", required)
		}
	}
}

func minPositive(left, right int) int {
	if left < 0 {
		return right
	}
	if right < 0 || left < right {
		return left
	}
	return right
}
