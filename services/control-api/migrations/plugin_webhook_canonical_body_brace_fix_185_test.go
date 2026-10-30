package migrations_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	controldatabase "github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPluginWebhookCanonicalBodyBraceFix185Contract(t *testing.T) {
	up := readCanonicalBodyBraceFix185(t, "185_plugin_webhook_canonical_body_brace_fix.up.sql")
	down := readCanonicalBodyBraceFix185(t, "185_plugin_webhook_canonical_body_brace_fix.down.sql")
	if !strings.Contains(up, "migration_id='184_analytics_realtime_source_window_authority'") ||
		!strings.Contains(down, "migration_id='185_plugin_webhook_canonical_body_brace_fix'") {
		t.Fatal("185 migration lineage guard is incomplete")
	}
	if !strings.Contains(up, "CREATE OR REPLACE FUNCTION plugin_webhook_canonical_body_084(") ||
		!strings.Contains(down, "CREATE OR REPLACE FUNCTION plugin_webhook_canonical_body_084(") {
		t.Fatal("185 must preserve the canonical body function signature")
	}
	if !strings.Contains(up, "plugin_webhook_json_canonical_122(data_value) || '}'") {
		t.Fatal("185 up must close the CloudEvent envelope")
	}
	if !strings.Contains(down, "plugin_webhook_json_canonical_122(data_value),") ||
		strings.Contains(down, "plugin_webhook_json_canonical_122(data_value) || '}'") {
		t.Fatal("185 down must restore the pre-185 canonical function")
	}
	for name, want := range map[string]string{
		"122_plugin_webhook_event_contract.up.sql":        "358b0e639ffa5290cd4146826beb29ac22d114abfb7ae7ce00675cbdc71236cb",
		"122_plugin_webhook_event_contract.down.sql":      "cbb00f190518cd10509dc9014e0f35431e02d7c88e5678e5c3182afff959ccea",
		"123_plugin_webhook_domain_event_producer.up.sql": "1571676e83b10966f0490b7f4ef8064e9e3e19593e8577a726c160dcaff64e0f",
		"124_plugin_webhook_event_clock.up.sql":           "d53d6c1fc04d4d09c227989e507b2b35de5855a4a524081290984921fce97afb",
	} {
		body := readCanonicalBodyBraceFix185(t, name)
		got := sha256.Sum256([]byte(body))
		if hex.EncodeToString(got[:]) != want {
			t.Fatalf("historical migration %s changed: %s", name, hex.EncodeToString(got[:]))
		}
	}
	if strings.Contains(strings.ToUpper(up+down), "CASCADE") {
		t.Fatal("185 migration must not use CASCADE")
	}
}

func TestPluginWebhookCanonicalBodyBraceFix185RuntimeUpDown(t *testing.T) {
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	admin, err := pgxpool.New(t.Context(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "plugin_webhook_brace_185_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	identifier := pgx.Identifier{schema}
	if _, err := admin.Exec(t.Context(), "CREATE SCHEMA "+identifier.Sanitize()); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		_, _ = admin.Exec(t.Context(), "DROP SCHEMA "+identifier.Sanitize()+" CASCADE")
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		// t.Context() is already cancelled when cleanup runs.
		cleanupCtx, cancel := databasetest.CleanupContext()
		defer cancel()
		_, _ = admin.Exec(cleanupCtx, "DROP SCHEMA "+identifier.Sanitize()+" CASCADE")
		admin.Close()
	})
	if err := controldatabase.Migrate(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	assertCanonicalBody185JSON(t, pool)
	if err := controldatabase.Migrate(t.Context(), pool, "down"); err != nil {
		t.Fatal(err)
	}
	if err := controldatabase.Migrate(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	assertCanonicalBody185JSON(t, pool)
}

func assertCanonicalBody185JSON(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	eventID := uuid.MustParse("019f8f00-0000-7000-8000-000000000058")
	tenantID := uuid.MustParse("019f8f00-0000-7000-8000-000000000059")
	subscriptionID := uuid.MustParse("019f8f00-0000-7000-8000-000000000060")
	var body []byte
	if err := pool.QueryRow(t.Context(), `SELECT plugin_webhook_canonical_body_084(
		$1,$2,'io.cdnca.webhook.v1.test',$3,TIMESTAMPTZ '2026-08-09 03:29:22.123456+00',
		'test-1',NULL,1,jsonb_build_object('subscription_id',$4::text,'test',true))`,
		eventID, tenantID, "webhook_subscription/"+subscriptionID.String(), subscriptionID).Scan(&body); err != nil {
		t.Fatal(err)
	}
	if !json.Valid(body) || len(body) == 0 || body[len(body)-1] != '}' {
		t.Fatalf("canonical body is not a closed JSON object: %q", body)
	}
}

func readCanonicalBodyBraceFix185(t *testing.T, name string) string {
	t.Helper()
	for _, root := range []string{".", "services/control-api/migrations"} {
		if body, err := os.ReadFile(filepath.Join(root, name)); err == nil {
			return string(body)
		}
	}
	t.Fatalf("migration file %s not found", name)
	return ""
}
