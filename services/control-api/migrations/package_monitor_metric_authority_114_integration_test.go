package migrations_test

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

const (
	migration113UpSHA114   = "ac4716d79decdb1076dbc19a5bf9ac9400d997f198cd56a8639b3d1924c12ccb"
	migration113DownSHA114 = "0928a9f3a9d93df1917fe32b2a4c0b5c406cbb7fdb0f66fe84523404522fe5a5"
	migration113TestSHA114 = "2d4243ed2fe303502f84f136e89cb7bdc7734c0dc3068a61f90664f8bee0ba3d"
)

func TestPackageMonitorMetricAuthority114Contract(t *testing.T) {
	up := readMigration114(t, "114_package_monitor_metric_authority.up.sql")
	down := readMigration114(t, "114_package_monitor_metric_authority.down.sql")
	upSHA := fmt.Sprintf("%x", sha256.Sum256([]byte(up)))
	assertMigrationSHA114(t, "113_cname_authority.up.sql", migration113UpSHA114)
	migration113Test := readRepositoryFile114(t, "cname_authority_113_integration_test.go")
	if got := fmt.Sprintf("%x", sha256.Sum256([]byte(migration113Test))); got != migration113TestSHA114 {
		t.Fatalf("113 CNAME authority integration test SHA-256 = %s, want %s", got, migration113TestSHA114)
	}
	for _, required := range []string{
		"migration 114 requires the exact verified 113 release head",
		"migration_id='113_cname_authority'",
		"checksum_sha256='" + migration113UpSHA114 + "'",
		"down_checksum_sha256='" + migration113DownSHA114 + "'",
		"REQUIRED_MIGRATION_113_INTEGRATION_SHA256=" + migration113TestSHA114,
		"CREATE TABLE package_monitor_site_subscription_bindings_114",
		"config_version_id", "valid_from", "valid_to", "binding_revision", "binding_digest",
		"CREATE TABLE package_monitor_metric_observations_114",
		"source_watermark", "source_evidence_digest", "finalized_through",
		"CREATE SEQUENCE package_monitor_metric_watermark_114_seq",
		"CREATE FUNCTION package_monitor_commit_metric_observation_114",
		"CREATE FUNCTION package_monitor_resolve_period_114",
		"prevent_package_monitor_metric_truncate_114",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("114 up missing %q", required)
		}
	}
	guard, mutation := strings.Index(up, "migration 114 requires the exact verified 113 release head"), strings.Index(up, "CREATE SEQUENCE")
	if guard < 0 || mutation < 0 || guard > mutation {
		t.Fatal("114 predecessor guard must precede the first mutation")
	}
	for _, required := range []string{
		"migration 114 rollback requires the exact verified 114 head",
		"checksum_sha256='" + upSHA + "'",
		"checksum_sha256='" + migration113UpSHA114 + "'",
		"rollback would discard package monitor metric authority facts",
		"DROP TABLE package_monitor_metric_observations_114",
		"DROP TABLE package_monitor_site_subscription_bindings_114",
	} {
		if !strings.Contains(down, required) {
			t.Errorf("114 down missing %q", required)
		}
	}
}

func TestPackageMonitorClickHouse005Contract(t *testing.T) {
	up := readRepositoryFile114(t, "../../../infra/clickhouse/migrations/005_package_monitor_metrics.up.sql")
	down := readRepositoryFile114(t, "../../../infra/clickhouse/migrations/005_package_monitor_metrics.down.sql")
	for _, required := range []string{
		"package_subscription_id UUID", "installation_id String", "period_start", "period_end",
		"CREATE TABLE IF NOT EXISTS package_metric_access_facts_v1", "CREATE TABLE IF NOT EXISTS package_metric_connection_facts_v1",
		"active_connections UInt64", "finalized_through", "source_evidence_digest",
		"package_metric_finalized_v1", "uniqExact(event_id)", "max(active_connections)",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("ClickHouse 005 up missing %q", required)
		}
	}
	if strings.Contains(up, "request_count AS active_connections") || strings.Contains(up, "count() AS active_connections") {
		t.Fatal("connections must not be inferred from request volume")
	}
	for _, required := range []string{"DROP VIEW IF EXISTS package_metric_finalized_v1", "DROP TABLE IF EXISTS package_metric_connection_facts_v1"} {
		if !strings.Contains(down, required) {
			t.Errorf("ClickHouse 005 down missing %q", required)
		}
	}
}

func TestPackageMonitorEventTimeAuthoritySources114(t *testing.T) {
	checks := map[string][]string{
		"../../../libs/edgeconfig/config.go":                       {"PackageSubscriptionID"},
		"../../../libs/edgeconfig/telemetry.go":                    {"PackageSubscriptionID"},
		"../../../proto/agent/v1/types.proto":                      {"package_subscription_id"},
		"../../../proto/controlinternal/v1/control_internal.proto": {"package_subscription_id"},
		"../../agent-gateway/telemetry_validation.go":              {"PackageSubscriptionId", "package_subscription_id"},
		"../internal/nodeidentity/model.go":                        {"PackageSubscriptionID"},
		"../internal/nodeidentity/store.go":                        {"PackageSubscriptionID"},
		"../internal/controlinternal/service.go":                   {"PackageSubscriptionId"},
		"../internal/edgepublish/service.go":                       {"PackageSubscriptionID"},
		"../internal/analytics/model.go":                           {"PackageSubscriptionID"},
		"../internal/analytics/ingest.go":                          {"PackageSubscriptionID"},
		"../internal/analytics/client.go":                          {"package_subscription_id"},
		"../internal/analytics/query.go":                           {"PackageMetric", "FinalizedThrough", "SourceEvidenceDigest"},
	}
	for file, required := range checks {
		content := readRepositoryFile114(t, file)
		for _, fragment := range required {
			if !strings.Contains(content, fragment) {
				t.Errorf("%s missing %q", file, fragment)
			}
		}
	}
	for _, file := range []string{
		"../../../edge/openresty/telemetry/access-json.conf",
		"../../../edge/openresty/telemetry/security-json.conf",
	} {
		if content := readRepositoryFile114(t, file); strings.Contains(content, "package_subscription_id") {
			t.Errorf("%s must not let the raw event self-assert package_subscription_id", file)
		}
	}
	edgeTelemetry := readRepositoryFile114(t, "../../../libs/edgeconfig/telemetry.go")
	for _, fragment := range []string{"\\\"package_subscription_id\\\"", "package_subscription_id=ngx.var.cdnca_package_subscription_id"} {
		if strings.Contains(edgeTelemetry, fragment) {
			t.Errorf("edge telemetry raw event must not contain %q", fragment)
		}
	}
}

func readMigration114(t *testing.T, name string) string {
	t.Helper()
	content, err := controlmigrations.FS.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}

func readRepositoryFile114(t *testing.T, name string) string {
	t.Helper()
	content, err := osReadFile114(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}

var osReadFile114 = os.ReadFile

func assertMigrationSHA114(t *testing.T, name, want string) {
	t.Helper()
	content, err := controlmigrations.FS.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(content)); got != want {
		t.Fatalf("%s SHA-256 = %s, want %s", name, got, want)
	}
}
