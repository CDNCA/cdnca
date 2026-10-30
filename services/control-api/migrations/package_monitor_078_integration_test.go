//go:build integration

package migrations_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed testdata/package_monitor_templates_v1.json
var packageMonitorTemplateManifest078 []byte

type packageMonitorTemplate078 struct {
	TemplateID string   `json:"template_id"`
	Version    int64    `json:"version"`
	Channel    string   `json:"channel"`
	Subject    string   `json:"subject"`
	Body       string   `json:"body"`
	Variables  []string `json:"variables"`
	SHA256     string   `json:"sha256"`
}

type packageMonitorTemplateCanonical078 struct {
	Body       string   `json:"body"`
	Channel    string   `json:"channel"`
	Subject    string   `json:"subject"`
	TemplateID string   `json:"template_id"`
	Variables  []string `json:"variables"`
	Version    int64    `json:"version"`
}

type packageMonitorAuditCanonicalV1078 struct {
	Version        int             `json:"version"`
	ID             string          `json:"id"`
	ScopeID        string          `json:"scope_id"`
	StreamPosition int64           `json:"stream_position"`
	ActorUserID    *string         `json:"actor_user_id"`
	Action         string          `json:"action"`
	ResourceType   string          `json:"resource_type"`
	ResourceID     string          `json:"resource_id"`
	RequestID      string          `json:"request_id"`
	Result         string          `json:"result"`
	Payload        json.RawMessage `json:"payload"`
	PreviousHash   string          `json:"previous_hash"`
	OccurredAt     string          `json:"occurred_at"`
}

func TestPackageMonitor078MigrationFilesAndManifest(t *testing.T) {
	up, err := controlmigrations.FS.ReadFile("078_package_monitor_runtime.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := controlmigrations.FS.ReadFile("078_package_monitor_runtime.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{
		"package_monitor_subscription_owners",
		"package_monitor_policy_versions",
		"package_monitor_policy_templates",
		"package_monitor_policy_heads",
		"package_monitor_evaluation_clocks",
		"package_monitor_alert_heads",
		"package_monitor_transition_facts",
		"package_monitor_evaluation_receipts",
		"notification_events_monitor_exact_078",
		"package_monitor_evaluation_receipts_immutable_078",
		"package_monitor_evaluation_receipts_current_head_078",
		"audit_events_package_monitor_clock_078",
		"package_monitor_transaction_clock_078",
		"migration_backfilled",
		"package_monitor_subscription_owners_provenance_078",
		"DEFERRABLE INITIALLY DEFERRED",
	} {
		if !strings.Contains(string(up), marker) {
			t.Errorf("078 up is missing %q", marker)
		}
	}
	for _, marker := range []string{
		"ACCESS EXCLUSIVE", "NOWAIT", "P7809", "package_monitor_runtime_facts_prevent_rollback",
		"WHERE NOT migration_backfilled",
	} {
		if !strings.Contains(string(down), marker) {
			t.Errorf("078 down is missing %q", marker)
		}
	}
	if strings.Contains(strings.ToUpper(string(down)), "CASCADE") {
		t.Fatal("078 down must not use CASCADE")
	}
	globalGate := "SELECT pg_advisory_xact_lock(1229016321, 1);"
	if gateAt, firstTableAt := strings.Index(string(down), globalGate),
		strings.Index(string(down), "LOCK TABLE"); gateAt < 0 || gateAt > firstTableAt {
		t.Fatalf("078 down must acquire %q before table locks", globalGate)
	}
	runbook, err := os.ReadFile("../../../docs/runbooks/package-monitor-runtime.md")
	if err != nil {
		t.Fatal(err)
	}
	downGuard := string(runbook)
	downGuard = downGuard[strings.Index(downGuard, "## Down guard"):]
	downGuard = downGuard[:strings.Index(downGuard, "取得完整锁集后")]
	if !strings.Contains(downGuard, "`pg_advisory_xact_lock(1229016321, 1)`") {
		t.Fatal("runbook down guard is missing the migration-safe IAM global gate")
	}
	lockPattern := regexp.MustCompile(`(?s)LOCK TABLE\s+(.+?)\s+IN ACCESS EXCLUSIVE MODE NOWAIT;`)
	quotedTablePattern := regexp.MustCompile("`([a-z0-9_]+)`")
	var migrationLocks, runbookLocks []string
	lockMatches := lockPattern.FindAllStringSubmatch(string(down), -1)
	if len(lockMatches) != 1 {
		t.Fatalf("078 down atomic NOWAIT lock statements = %d, want 1", len(lockMatches))
	}
	for _, table := range strings.Split(lockMatches[0][1], ",") {
		migrationLocks = append(migrationLocks, strings.TrimSpace(table))
	}
	for _, match := range quotedTablePattern.FindAllStringSubmatch(downGuard, -1) {
		runbookLocks = append(runbookLocks, match[1])
	}
	if strings.Join(runbookLocks, ",") != strings.Join(migrationLocks, ",") {
		t.Fatalf("runbook down locks = %v, migration locks = %v", runbookLocks, migrationLocks)
	}
	if !strings.Contains(downGuard, "`55P03`") {
		t.Fatal("runbook down guard is missing the retryable NOWAIT SQLSTATE")
	}

	manifest := readPackageMonitorManifest078(t)
	if len(manifest) != 16 {
		t.Fatalf("template manifest rows = %d, want 16", len(manifest))
	}
	seen := make(map[string]struct{}, len(manifest))
	placeholder := regexp.MustCompile(`\{\{\.([a-z][a-z0-9_]*)\}\}`)
	for _, row := range manifest {
		key := row.TemplateID + "/" + row.Channel
		if _, duplicate := seen[key]; duplicate {
			t.Fatalf("duplicate manifest key %s", key)
		}
		seen[key] = struct{}{}
		canonical, err := json.Marshal(packageMonitorTemplateCanonical078{
			Body: row.Body, Channel: row.Channel, Subject: row.Subject,
			TemplateID: row.TemplateID, Variables: row.Variables, Version: row.Version,
		})
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(canonical)
		if got := hex.EncodeToString(sum[:]); got != row.SHA256 {
			t.Errorf("%s sha256 = %s, want %s", key, got, row.SHA256)
		}
		used := make([]string, 0, len(row.Variables))
		for _, match := range placeholder.FindAllStringSubmatch(row.Subject+row.Body, -1) {
			used = append(used, match[1])
		}
		sort.Strings(used)
		declared := append([]string(nil), row.Variables...)
		sort.Strings(declared)
		if strings.Join(used, ",") != strings.Join(declared, ",") {
			t.Errorf("%s used variables %v differ from manifest %v", key, used, declared)
		}
		if row.Channel == "sms" && row.Subject != "" {
			t.Errorf("%s SMS subject is not empty", key)
		}
	}
}

func TestPackageMonitor078FullMigrationLedgerRoundTripAndExactContracts(t *testing.T) {
	pool := packageMonitor078Pool(t)
	assertPackageMonitor078Version(t, pool, 78)

	var count, minimum, maximum, invalid int
	if err := pool.QueryRow(t.Context(), `SELECT count(*),min(version),max(version),
		count(*) FILTER (WHERE migration_id IS NULL OR checksum_sha256 IS NULL
			OR down_checksum_sha256 IS NULL OR integrity_state <> 'verified')
		FROM schema_migrations`).Scan(&count, &minimum, &maximum, &invalid); err != nil {
		t.Fatal(err)
	}
	if count != 78 || minimum != 1 || maximum != 78 || invalid != 0 {
		t.Fatalf("migration ledger count/min/max/invalid = %d/%d/%d/%d", count, minimum, maximum, invalid)
	}
	up := mustReadPackageMonitorMigration078(t, "078_package_monitor_runtime.up.sql")
	down := mustReadPackageMonitorMigration078(t, "078_package_monitor_runtime.down.sql")
	upSum, downSum := sha256.Sum256(up), sha256.Sum256(down)
	var ledgerUp, ledgerDown string
	if err := pool.QueryRow(t.Context(), `SELECT checksum_sha256,down_checksum_sha256
		FROM schema_migrations WHERE version=78`).Scan(&ledgerUp, &ledgerDown); err != nil {
		t.Fatal(err)
	}
	if ledgerUp != hex.EncodeToString(upSum[:]) || ledgerDown != hex.EncodeToString(downSum[:]) {
		t.Fatal("migration 078 ledger checksums do not match embedded SQL")
	}

	for _, table := range []string{
		"package_monitor_subscription_owners",
		"package_monitor_policy_versions",
		"package_monitor_policy_templates",
		"package_monitor_policy_heads",
		"package_monitor_evaluation_clocks",
		"package_monitor_alert_heads",
		"package_monitor_transition_facts",
		"package_monitor_evaluation_receipts",
	} {
		var exists bool
		if err := pool.QueryRow(t.Context(), `SELECT to_regclass($1) IS NOT NULL`, table).Scan(&exists); err != nil || !exists {
			t.Fatalf("table %s exists=%t err=%v", table, exists, err)
		}
		for _, privilege := range []string{
			"SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER",
		} {
			var allowed bool
			if err := pool.QueryRow(t.Context(), `SELECT has_table_privilege('public',$1,$2)`,
				table, privilege).Scan(&allowed); err != nil {
				t.Fatalf("read PUBLIC %s privilege on %s: %v", privilege, table, err)
			}
			if allowed {
				t.Fatalf("PUBLIC has %s privilege on %s", privilege, table)
			}
		}
	}
	for _, signature := range []string{
		"package_monitor_template_sha256_078(text,text,text,text,text[],bigint)",
		"package_monitor_threshold_sha256_078(uuid,bigint,text,numeric,numeric,bigint)",
		"validate_package_monitor_owner_078()",
		"validate_package_monitor_owner_provenance_078()",
		"prevent_package_monitor_immutable_078()",
		"protect_package_monitor_policy_head_078()",
		"protect_package_monitor_alert_head_078()",
		"bind_package_monitor_evaluation_clock_078()",
		"package_monitor_transaction_clock_078()",
		"validate_package_monitor_evaluation_clock_078()",
		"validate_package_monitor_head_fact_078()",
		"validate_package_monitor_audit_078()",
		"validate_package_monitor_receipt_audit_078()",
		"validate_package_monitor_new_receipt_078()",
		"package_monitor_go_json_string_078(text)",
		"package_monitor_json_canonical_078(jsonb)",
		"package_monitor_rfc3339nano_078(timestamp with time zone)",
		"package_monitor_audit_hash_078(uuid,uuid,bigint,uuid,text,text,text,text,text,jsonb,bytea,timestamp with time zone)",
		"bind_package_monitor_audit_clock_078()",
	} {
		var allowed bool
		if err := pool.QueryRow(t.Context(), `SELECT has_function_privilege('public',$1,'EXECUTE')`,
			signature).Scan(&allowed); err != nil {
			t.Fatalf("read PUBLIC EXECUTE privilege on %s: %v", signature, err)
		}
		if allowed {
			t.Fatalf("PUBLIC can execute %s", signature)
		}
	}

	manifest := readPackageMonitorManifest078(t)
	for _, row := range manifest {
		var databaseSHA string
		if err := pool.QueryRow(t.Context(), `SELECT encode(package_monitor_template_sha256_078(
			body,channel,subject,template_id,variables,version),'hex')
			FROM notification_templates WHERE template_id=$1 AND version=$2 AND channel=$3`,
			row.TemplateID, row.Version, row.Channel).Scan(&databaseSHA); err != nil {
			t.Fatalf("read template %s/%s: %v", row.TemplateID, row.Channel, err)
		}
		if databaseSHA != row.SHA256 {
			t.Errorf("database template %s/%s sha = %s, want %s", row.TemplateID, row.Channel, databaseSHA, row.SHA256)
		}
	}

	var exactNotificationFK bool
	if err := pool.QueryRow(t.Context(), `SELECT EXISTS (
		SELECT 1 FROM pg_constraint
		WHERE conrelid='package_monitor_transition_facts'::regclass
		  AND confrelid='notification_events'::regclass
		  AND pg_get_constraintdef(oid) LIKE
		      'FOREIGN KEY (tenant_scope_id, notification_event_id, owner_user_id, source_event_id, notification_event_type)%'
	)`).Scan(&exactNotificationFK); err != nil || !exactNotificationFK {
		t.Fatalf("single exact notification FK exists=%t err=%v", exactNotificationFK, err)
	}
	var exactReceiptFK bool
	if err := pool.QueryRow(t.Context(), `SELECT EXISTS (
		SELECT 1 FROM pg_constraint
		WHERE conrelid='package_monitor_evaluation_receipts'::regclass
		  AND confrelid='package_monitor_alert_heads'::regclass
		  AND pg_get_constraintdef(oid) LIKE
		      'FOREIGN KEY (alert_id, tenant_scope_id, subscription_id, owner_user_id, policy_id, policy_revision, metric, period_key, threshold_identity)%'
	)`).Scan(&exactReceiptFK); err != nil || !exactReceiptFK {
		t.Fatalf("single exact receipt head FK exists=%t err=%v", exactReceiptFK, err)
	}
	var exactReceiptNotificationFK bool
	if err := pool.QueryRow(t.Context(), `SELECT EXISTS (
		SELECT 1 FROM pg_constraint
		WHERE conrelid='package_monitor_evaluation_receipts'::regclass
		  AND confrelid='package_monitor_transition_facts'::regclass
		  AND pg_get_constraintdef(oid) LIKE
		      'FOREIGN KEY (alert_id, transition_fact_revision, notification_event_id)%'
	)`).Scan(&exactReceiptNotificationFK); err != nil || !exactReceiptNotificationFK {
		t.Fatalf("exact receipt notification FK exists=%t err=%v", exactReceiptNotificationFK, err)
	}
	var exactReceiptObservedAtFK bool
	if err := pool.QueryRow(t.Context(), `SELECT EXISTS (
		SELECT 1 FROM pg_constraint
		WHERE conrelid='package_monitor_evaluation_receipts'::regclass
		  AND confrelid='package_monitor_transition_facts'::regclass
		  AND pg_get_constraintdef(oid) LIKE
		      'FOREIGN KEY (alert_id, transition_fact_revision, observed_at)%'
	)`).Scan(&exactReceiptObservedAtFK); err != nil || !exactReceiptObservedAtFK {
		t.Fatalf("exact receipt observed_at FK exists=%t err=%v", exactReceiptObservedAtFK, err)
	}

	if err := migrateVersionIsolated(t.Context(), pool, "down", 78); err != nil {
		t.Fatalf("078 down: %v", err)
	}
	assertPackageMonitor078Version(t, pool, 77)
	if err := migrateVersionIsolated(t.Context(), pool, "up", 78); err != nil {
		t.Fatalf("078 re-up: %v", err)
	}
	assertPackageMonitor078Version(t, pool, 78)
}

func TestPackageMonitor078ExpirationTriggerMustBePositive(t *testing.T) {
	pool := packageMonitor078Pool(t)
	for _, test := range []struct {
		name              string
		trigger, recovery int64
		stale             any
		wantError         bool
	}{
		{name: "zero_trigger", trigger: 0, recovery: 1, stale: int64(1), wantError: true},
		{name: "null_stale", trigger: 1, recovery: 2, stale: nil, wantError: true},
		{name: "positive_boundary", trigger: 1, recovery: 2, stale: int64(1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			subscriptionID, scopeID, userID, createdAt := seedPackageMonitor078LegacySubscription(t, pool)
			if _, err := pool.Exec(t.Context(), `INSERT INTO package_monitor_subscription_owners(
				subscription_id,state_revision,tenant_scope_id,owner_user_id,
				source_kind,source_fulfillment_id,created_at
			) VALUES($1,1,$2,$3,'subscription_state',NULL,$4)`,
				subscriptionID, scopeID, userID, createdAt); err != nil {
				t.Fatal(err)
			}
			policyID := uuid.New()
			_, err := pool.Exec(t.Context(), `INSERT INTO package_monitor_policy_versions(
				policy_id,revision,tenant_scope_id,subscription_id,owner_user_id,metric,
				trigger_value,recovery_value,stale_after_seconds,threshold_identity,
				enabled,created_by_user_id,created_at
			) VALUES($1,1,$2,$3,$4,'expiration',$5,$6,$7,
				package_monitor_threshold_sha256_078($1,1,'expiration',$5,$6,$7),true,$4,$8)`,
				policyID, scopeID, subscriptionID, userID, test.trigger, test.recovery,
				test.stale, createdAt)
			if test.wantError {
				assertPackageMonitor078Code(t, err, "23514")
			} else if err != nil {
				t.Fatalf("positive expiration boundary: %v", err)
			}
		})
	}
}

func TestPackageMonitor078AuditCanonicalV1Vectors(t *testing.T) {
	pool := packageMonitor078Pool(t)
	controlVector := "quote\" backslash\\ \b\f\n\r\t \u0001\u000b\u001f \u2028\u2029 <>& 中文"
	payload, err := json.Marshal(map[string]any{
		"array":  []any{controlVector, true, nil, uint64(math.MaxUint64)},
		"nested": map[string]any{"control": controlVector, "count": 7},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(payload, []byte(`18446744073709551615`)) ||
		bytes.Contains(payload, []byte(`18446744073709552000`)) {
		t.Fatalf("Go max uint64 canonical bytes = %s", payload)
	}
	var sqlPayload []byte
	if err := pool.QueryRow(t.Context(), `SELECT convert_to(
		package_monitor_json_canonical_078($1::jsonb),'UTF8')`, string(payload)).Scan(
		&sqlPayload,
	); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sqlPayload, payload) {
		t.Fatalf("SQL canonical payload = %q, want Go bytes %q", sqlPayload, payload)
	}

	for _, input := range []string{
		"2026-08-01T01:02:03Z",
		"2026-08-01T01:02:03.1Z",
		"2026-08-01T01:02:03.123Z",
		"2026-08-01T01:02:03.123456Z",
		"2026-08-01T01:02:03.123456000Z",
		"2026-08-01T01:02:03.123456789Z",
	} {
		t.Run("timestamp_"+strings.ReplaceAll(input, ":", "_"), func(t *testing.T) {
			var sqlFormatted string
			var databaseTime time.Time
			if err := pool.QueryRow(t.Context(), `SELECT
				package_monitor_rfc3339nano_078($1::timestamptz),$1::timestamptz`, input).Scan(
				&sqlFormatted, &databaseTime,
			); err != nil {
				t.Fatal(err)
			}
			if want := databaseTime.UTC().Format(time.RFC3339Nano); sqlFormatted != want {
				t.Fatalf("SQL RFC3339Nano = %q, want Go %q", sqlFormatted, want)
			}
		})
	}

	eventID := uuid.MustParse("018f0f5d-0c6a-7b8c-9d0e-112233445566")
	scopeID := uuid.MustParse("11111111-2222-4333-8444-555555555555")
	actorID := uuid.MustParse("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")
	actorText := actorID.String()
	occurredAt := time.Date(2026, 8, 1, 1, 2, 3, 123456000, time.UTC)
	previousHash := []byte(nil)
	for position := int64(1); position <= 2; position++ {
		canonical, err := json.Marshal(packageMonitorAuditCanonicalV1078{
			Version: 1, ID: eventID.String(), ScopeID: scopeID.String(),
			StreamPosition: position, ActorUserID: &actorText,
			Action: "package_monitor.evaluation.commit", ResourceType: "vector-<>&",
			ResourceID: controlVector, RequestID: "request-\"-\\-\n-中文", Result: "success",
			Payload: payload, PreviousHash: hex.EncodeToString(previousHash),
			OccurredAt: occurredAt.Format(time.RFC3339Nano),
		})
		if err != nil {
			t.Fatal(err)
		}
		wantHash := sha256.Sum256(canonical)
		var sqlHash []byte
		if err := pool.QueryRow(t.Context(), `SELECT package_monitor_audit_hash_078(
			$1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11,$12)`,
			eventID, scopeID, position, actorID, "package_monitor.evaluation.commit",
			"vector-<>&", controlVector, "request-\"-\\-\n-中文", "success",
			string(payload), previousHash, occurredAt,
		).Scan(&sqlHash); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(sqlHash, wantHash[:]) {
			t.Fatalf("SQL audit hash position %d = %x, want Go canonical %x\ncanonical=%s",
				position, sqlHash, wantHash, canonical)
		}
		previousHash = sqlHash
		eventID = uuid.MustParse("018f0f5d-0c6a-7b8c-9d0e-223344556677")
	}
}

func TestPackageMonitor078DownRejectsPostUpSubscriptionOwner(t *testing.T) {
	pool := packageMonitor078Pool(t)
	subscriptionID, scopeID, userID, createdAt := seedPackageMonitor078LegacySubscription(t, pool)
	if _, err := pool.Exec(t.Context(), `INSERT INTO package_monitor_subscription_owners(
		subscription_id,state_revision,tenant_scope_id,owner_user_id,
		source_kind,source_fulfillment_id,created_at
	) VALUES($1,1,$2,$3,'subscription_state',NULL,$4)`,
		subscriptionID, scopeID, userID, createdAt); err != nil {
		t.Fatal(err)
	}
	var migrationBackfilled bool
	if err := pool.QueryRow(t.Context(), `SELECT migration_backfilled
		FROM package_monitor_subscription_owners WHERE subscription_id=$1`,
		subscriptionID).Scan(&migrationBackfilled); err != nil || migrationBackfilled {
		t.Fatalf("post-up owner migration_backfilled=%t err=%v", migrationBackfilled, err)
	}
	forgedSubscription, forgedScope, forgedUser, forgedAt := seedPackageMonitor078LegacySubscription(t, pool)
	_, err := pool.Exec(t.Context(), `INSERT INTO package_monitor_subscription_owners(
		subscription_id,state_revision,tenant_scope_id,owner_user_id,
		source_kind,source_fulfillment_id,migration_backfilled,created_at
	) VALUES($1,1,$2,$3,'subscription_state',NULL,true,$4)`,
		forgedSubscription, forgedScope, forgedUser, forgedAt)
	assertPackageMonitor078Code(t, err, "23514")

	assertPackageMonitor078Code(t, migrateVersionIsolated(t.Context(), pool, "down", 78), "P7809")
	assertPackageMonitor078Version(t, pool, 78)
	var owners int
	if err := pool.QueryRow(t.Context(), `SELECT count(*)
		FROM package_monitor_subscription_owners WHERE subscription_id=$1`, subscriptionID).Scan(&owners); err != nil || owners != 1 {
		t.Fatalf("post-up owners after rejected down = %d, want 1, err=%v", owners, err)
	}
}

func TestPackageMonitor078LegacyBackfillExactRoundTrip(t *testing.T) {
	pool := packageMonitor078Pool(t)
	if err := migrateVersionIsolated(t.Context(), pool, "down", 78); err != nil {
		t.Fatal(err)
	}
	assertPackageMonitor078Version(t, pool, 77)
	subscriptionID, _, _, _ := seedPackageMonitor078LegacySubscription(t, pool)
	if err := migrateVersionIsolated(t.Context(), pool, "up", 78); err != nil {
		t.Fatal(err)
	}
	assertPackageMonitor078Version(t, pool, 78)
	var owners int
	if err := pool.QueryRow(t.Context(), `SELECT count(*)
		FROM package_monitor_subscription_owners WHERE subscription_id=$1`, subscriptionID).Scan(&owners); err != nil || owners != 1 {
		t.Fatalf("legacy backfill owners = %d, want 1, err=%v", owners, err)
	}
	var migrationBackfilled bool
	if err := pool.QueryRow(t.Context(), `SELECT migration_backfilled
		FROM package_monitor_subscription_owners WHERE subscription_id=$1`,
		subscriptionID).Scan(&migrationBackfilled); err != nil || !migrationBackfilled {
		t.Fatalf("legacy owner migration_backfilled=%t err=%v", migrationBackfilled, err)
	}
	if err := migrateVersionIsolated(t.Context(), pool, "down", 78); err != nil {
		t.Fatalf("legacy exact down: %v", err)
	}
	assertPackageMonitor078Version(t, pool, 77)
}

func TestPackageMonitor078DownRejectsSeedDriftAtomically(t *testing.T) {
	pool := packageMonitor078Pool(t)
	if _, err := pool.Exec(t.Context(), `ALTER TABLE notification_templates
		DISABLE TRIGGER notification_templates_immutable`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE notification_templates SET body=body || '篡改'
		WHERE template_id='package.monitor.traffic.triggered.zh-cn' AND version=1 AND channel='sms'`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `ALTER TABLE notification_templates
		ENABLE TRIGGER notification_templates_immutable`); err != nil {
		t.Fatal(err)
	}
	assertPackageMonitor078Code(t, migrateVersionIsolated(t.Context(), pool, "down", 78), "P7809")
	assertPackageMonitor078Version(t, pool, 78)
	var tables int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM (VALUES
		(to_regclass('package_monitor_subscription_owners')),
		(to_regclass('package_monitor_policy_versions')),
		(to_regclass('package_monitor_policy_templates')),
		(to_regclass('package_monitor_policy_heads')),
		(to_regclass('package_monitor_evaluation_clocks')),
		(to_regclass('package_monitor_alert_heads')),
			(to_regclass('package_monitor_transition_facts')),
			(to_regclass('package_monitor_evaluation_receipts'))
		) AS required(name) WHERE name IS NOT NULL`).Scan(&tables); err != nil || tables != 8 {
		t.Fatalf("tables after rejected down = %d, want 8, err=%v", tables, err)
	}
}

func TestPackageMonitor078DownWaitsAtGlobalGateBeforeReverseTablePaths(t *testing.T) {
	for _, test := range []struct {
		name        string
		firstLock   string
		reverseLock string
	}{
		{
			name:        "policy_head_then_version",
			firstLock:   "LOCK TABLE package_monitor_policy_heads IN ROW EXCLUSIVE MODE",
			reverseLock: "LOCK TABLE package_monitor_policy_versions IN ROW EXCLUSIVE MODE NOWAIT",
		},
		{
			name:        "receipt_then_transition",
			firstLock:   "LOCK TABLE package_monitor_evaluation_receipts IN ROW EXCLUSIVE MODE",
			reverseLock: "LOCK TABLE package_monitor_transition_facts IN ROW EXCLUSIVE MODE NOWAIT",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			pool := packageMonitor078Pool(t)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			writer, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer writer.Rollback(context.Background())
			if _, err := writer.Exec(ctx, `SELECT iam_global_lock_shared_v1()`); err != nil {
				t.Fatal(err)
			}
			if _, err := writer.Exec(ctx, test.firstLock); err != nil {
				t.Fatal(err)
			}
			var writerPID int
			if err := writer.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&writerPID); err != nil {
				t.Fatal(err)
			}

			schema := currentPackageMonitor078Schema(t, pool)
			downPool, downPID := newPackageMonitor078SessionPool(t, pool, schema)
			unrelatedApplication := "pm078_unrelated_" + strings.ReplaceAll(uuid.NewString(), "-", "")
			unrelatedPool, unrelatedPID := newPackageMonitor078SessionPool(
				t, pool, unrelatedApplication,
			)
			unrelatedCtx, unrelatedCancel := context.WithCancel(ctx)
			unrelatedResult := make(chan error, 1)
			go func() {
				_, unrelatedErr := unrelatedPool.Exec(
					unrelatedCtx, `SELECT pg_advisory_xact_lock(1229016321, 1)`,
				)
				unrelatedResult <- unrelatedErr
			}()
			_, unrelatedBlocked := waitPackageMonitor078ResultOrBlocked(
				t, ctx, pool, unrelatedResult, unrelatedPID, unrelatedApplication, writerPID,
				"pg_advisory_xact_lock(1229016321, 1)",
			)
			if !unrelatedBlocked {
				t.Fatal("unrelated IAM waiter completed before reaching the global gate")
			}

			var broadPID int
			if err := pool.QueryRow(ctx, `SELECT activity.pid
				FROM pg_stat_activity AS activity
				WHERE $1=ANY(pg_blocking_pids(activity.pid))
				  AND activity.wait_event_type='Lock'
				ORDER BY activity.pid
				LIMIT 1`, writerPID).Scan(&broadPID); err != nil {
				t.Fatal(err)
			}
			if broadPID != unrelatedPID {
				t.Fatalf("broad blocked-state predicate selected backend %d, want unrelated backend %d",
					broadPID, unrelatedPID)
			}
			var downObserved bool
			if err := pool.QueryRow(ctx, `SELECT EXISTS (
				SELECT 1 FROM pg_stat_activity AS activity
				WHERE activity.pid=$1
				  AND activity.application_name=$2
				  AND current_schema()=$3
				  AND $4=ANY(pg_blocking_pids(activity.pid))
				  AND activity.wait_event_type='Lock'
				  AND activity.wait_event IN ('advisory','AdvisoryLock')
				  AND position('SELECT pg_advisory_xact_lock(1229016321, 1);' in activity.query)>0
			)`, downPID, schema, schema, writerPID).Scan(&downObserved); err != nil {
				t.Fatal(err)
			}
			if downObserved {
				t.Fatalf("target down backend %d was observed before its migration started", downPID)
			}
			unrelatedCancel()
			select {
			case <-unrelatedResult:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}

			downResult := make(chan error, 1)
			go func() { downResult <- migrateVersionIsolated(ctx, downPool, "down", 78) }()
			blockedQuery, waitEvent, waitErr := waitPackageMonitor078BlockedState(
				ctx, pool, downPID, schema, schema, writerPID,
			)
			_, reverseErr := writer.Exec(ctx, test.reverseLock)
			commitErr := writer.Commit(ctx)
			var downErr error
			select {
			case downErr = <-downResult:
			case <-ctx.Done():
				downErr = ctx.Err()
			}

			if waitErr != nil {
				t.Fatalf("observe blocked down: %v", waitErr)
			}
			if waitEvent != "advisory" && waitEvent != "AdvisoryLock" {
				t.Fatalf("down blocked query=%q wait_event=%q, want advisory global gate",
					blockedQuery, waitEvent)
			}
			if reverseErr != nil || commitErr != nil {
				t.Fatalf("reverse writer lock/commit errors = %v/%v", reverseErr, commitErr)
			}
			if downErr != nil {
				t.Fatalf("078 down after reverse writer = %v", downErr)
			}
			assertPackageMonitor078Version(t, pool, 77)
		})
	}
}

func waitPackageMonitor078BlockedState(
	ctx context.Context,
	pool *pgxpool.Pool,
	backendPID int,
	applicationName string,
	schema string,
	blockerPID int,
) (string, string, error) {
	for {
		var query, waitEvent string
		err := pool.QueryRow(ctx, `SELECT activity.query,activity.wait_event
			FROM pg_stat_activity AS activity
			WHERE activity.pid=$1
			  AND activity.application_name=$2
			  AND current_schema()=$3
			  AND $4=ANY(pg_blocking_pids(activity.pid))
			  AND activity.wait_event_type='Lock'
			  AND activity.wait_event IN ('advisory','AdvisoryLock')
			  AND position('SELECT pg_advisory_xact_lock(1229016321, 1);' in activity.query)>0`,
			backendPID, applicationName, schema, blockerPID).Scan(&query, &waitEvent)
		if err == nil {
			return query, waitEvent, nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return "", "", err
		}
		if err := ctx.Err(); err != nil {
			return "", "", err
		}
	}
}

func newPackageMonitor078SessionPool(
	t *testing.T,
	source *pgxpool.Pool,
	applicationName string,
) (*pgxpool.Pool, int) {
	t.Helper()
	config := source.Config().Copy()
	config.MaxConns = 1
	config.MinConns = 0
	config.ConnConfig.RuntimeParams["application_name"] = applicationName
	config.ConnConfig.RuntimeParams["deadlock_timeout"] = "100ms"
	config.ConnConfig.RuntimeParams["statement_timeout"] = "6s"
	sessionPool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sessionPool.Close)
	var backendPID int
	if err := sessionPool.QueryRow(t.Context(), `SELECT pg_backend_pid()`).Scan(&backendPID); err != nil {
		t.Fatal(err)
	}
	return sessionPool, backendPID
}

func currentPackageMonitor078Schema(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	var schema string
	if err := pool.QueryRow(t.Context(), `SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	return schema
}

func waitPackageMonitor078ResultOrBlocked(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	result <-chan error,
	backendPID int,
	applicationName string,
	blockerPID int,
	queryFragment string,
) (error, bool) {
	t.Helper()
	for {
		select {
		case err := <-result:
			return err, false
		default:
		}
		var blocked bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS (
			SELECT 1 FROM pg_stat_activity AS activity
			WHERE activity.pid=$1
			  AND activity.application_name=$2
			  AND $3=ANY(pg_blocking_pids(activity.pid))
			  AND activity.wait_event_type='Lock'
			  AND position($4 in activity.query)>0
		)`, backendPID, applicationName, blockerPID, queryFragment).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			return nil, true
		}
		if err := ctx.Err(); err != nil {
			return err, false
		}
	}
}

func TestPackageMonitor078CommerceOwnerRejectsAmbiguousProofSet(t *testing.T) {
	pool := packageMonitor078Pool(t)
	ctx := t.Context()
	tenantID, scopeID, userID := uuid.New(), uuid.New(), uuid.New()
	subscriptionID, selectedFulfillmentID := uuid.New(), uuid.New()
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")
	now := time.Date(2026, 7, 28, 3, 30, 0, 0, time.UTC)
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO tenants(id,display_name) VALUES($1,$2)`, []any{tenantID, "078 owner " + suffix}},
		{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, []any{scopeID, tenantID}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,$3,'hash')`, []any{userID, "o078" + suffix, "078 owner " + suffix}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{scopeID, userID}},
	} {
		if _, err := pool.Exec(ctx, statement.sql, statement.args...); err != nil {
			t.Fatal(err)
		}
	}

	seed, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer seed.Rollback(context.Background())
	if _, err := seed.Exec(ctx, `SET LOCAL session_replication_role='replica'`); err != nil {
		t.Fatal(err)
	}
	if _, err := seed.Exec(ctx, `INSERT INTO package_subscription_state_versions(
		subscription_id,revision,tenant_scope_id,owner_user_id,lifecycle_status,
		starts_at,ends_at,cancelled_at,created_at,updated_at,commit_sequence
	) VALUES($1,1,$2,$3,'active',$4,$5,NULL,$4,$4,0)`,
		subscriptionID, scopeID, userID, now, now.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	correctOrderID, ambiguousOrderID := uuid.New(), uuid.New()
	productID := uuid.New()
	for index, order := range []struct {
		id      uuid.UUID
		scopeID uuid.UUID
		userID  uuid.UUID
		request string
	}{
		{id: correctOrderID, scopeID: scopeID, userID: userID, request: "owner-proof-correct"},
		{id: ambiguousOrderID, scopeID: uuid.New(), userID: uuid.New(), request: "owner-proof-ambiguous"},
	} {
		if _, err := seed.Exec(ctx, `INSERT INTO package_orders(
			id,tenant_scope_id,user_id,operation,product_kind,product_id,product_revision,
			package_period,product_snapshot,entitlement_snapshot,pricing_snapshot,currency,
			original_amount_minor,discount_amount_minor,payable_amount_minor,
			settlement_direction,funding_source,effective_mode,effective_at,
			request_id,trace_id,created_by_scope_id,created_by_user_id,created_at
		) VALUES($1,$2,$3,'purchase','package_subscription',$4,1,'month',
			'{}'::jsonb,'{}'::jsonb,'{}'::jsonb,'CNY',0,0,0,
			'debit','provider','immediate',$5,$6,$6,$2,$3,$5)`,
			order.id, order.scopeID, order.userID, productID, now, order.request); err != nil {
			t.Fatalf("insert commerce order %d: %v", index, err)
		}
	}
	for index, fulfillment := range []struct {
		id      uuid.UUID
		orderID uuid.UUID
		scopeID uuid.UUID
	}{
		{id: selectedFulfillmentID, orderID: correctOrderID, scopeID: scopeID},
		{id: uuid.New(), orderID: ambiguousOrderID, scopeID: uuid.New()},
	} {
		if _, err := seed.Exec(ctx, `INSERT INTO package_order_fulfillments(
			id,order_id,tenant_scope_id,subscription_id,subscription_revision,
			entitlement_revision,fulfilled_at
		) VALUES($1,$2,$3,$4,1,1,$5)`, fulfillment.id, fulfillment.orderID,
			fulfillment.scopeID, subscriptionID, now); err != nil {
			t.Fatalf("insert commerce fulfillment %d: %v", index, err)
		}
	}
	if _, err := seed.Exec(ctx, `SET LOCAL session_replication_role='origin'`); err != nil {
		t.Fatal(err)
	}
	if err := seed.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	_, err = pool.Exec(ctx, `INSERT INTO package_monitor_subscription_owners(
		subscription_id,state_revision,tenant_scope_id,owner_user_id,
		source_kind,source_fulfillment_id,created_at
	) VALUES($1,1,$2,$3,'commerce_fulfillment',$4,$5)`,
		subscriptionID, scopeID, userID, selectedFulfillmentID, now)
	assertPackageMonitor078Code(t, err, "23514")
	var owners int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM package_monitor_subscription_owners
		WHERE subscription_id=$1`, subscriptionID).Scan(&owners); err != nil || owners != 0 {
		t.Fatalf("ambiguous commerce owners = %d, want 0, err=%v", owners, err)
	}
}

func TestPackageMonitor078BackfillRejectsPlatformCreator(t *testing.T) {
	pool := packageMonitor078Pool(t)
	ctx := t.Context()
	if err := migrateVersionIsolated(ctx, pool, "down", 78); err != nil {
		t.Fatal(err)
	}
	assertPackageMonitor078Version(t, pool, 77)

	tenantID, tenantScopeID, platformScopeID := uuid.New(), uuid.New(), uuid.New()
	userID, subscriptionID, productID := uuid.New(), uuid.New(), uuid.New()
	now := time.Date(2026, 7, 28, 3, 45, 0, 0, time.UTC)
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")
	seed, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer seed.Rollback(context.Background())
	if _, err := seed.Exec(ctx, `SET LOCAL session_replication_role='replica'`); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO tenants(id,display_name) VALUES($1,$2)`, []any{tenantID, "078 platform owner " + suffix}},
		{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2),($3,'platform',NULL)`, []any{tenantScopeID, tenantID, platformScopeID}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,$3,'hash')`, []any{userID, "p078" + suffix, "078 platform owner " + suffix}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$3),($2,$3)`, []any{tenantScopeID, platformScopeID, userID}},
		{`INSERT INTO package_subscriptions(
			id,tenant_scope_id,product_id,product_revision,product_snapshot,
			site_limit,domain_limit,node_limit,traffic_limit_bytes,starts_at,ends_at,
			timezone,cycle_kind,custom_cycle_days,tcp_factor_numerator,tcp_factor_denominator,
			lifecycle_status,revision,created_by_user_id,updated_by_user_id,created_at,updated_at
		) VALUES($1,$2,$3::uuid,1,jsonb_build_object(
			'id',$3::uuid::text,'revision',1,'name','platform product','spec','{}'::jsonb
		),1,1,1,1,$4,$5,'UTC','monthly',0,1,1,'active',1,$6,$6,$4,$4)`, []any{
			subscriptionID, tenantScopeID, productID, now, now.Add(24 * time.Hour), userID,
		}},
		{`INSERT INTO package_subscription_state_versions(
			subscription_id,revision,tenant_scope_id,owner_user_id,lifecycle_status,
			starts_at,ends_at,cancelled_at,created_at,updated_at,commit_sequence
		) VALUES($1,1,$2,$3,'active',$4,$5,NULL,$4,$4,0)`, []any{
			subscriptionID, tenantScopeID, userID, now, now.Add(24 * time.Hour),
		}},
	} {
		if _, err := seed.Exec(ctx, statement.sql, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	if err := seed.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	if err := migrateVersionIsolated(ctx, pool, "up", 78); err != nil {
		t.Fatal(err)
	}
	assertPackageMonitor078Version(t, pool, 78)
	var owners int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM package_monitor_subscription_owners
		WHERE subscription_id=$1`, subscriptionID).Scan(&owners); err != nil || owners != 0 {
		t.Fatalf("platform creator owners = %d, want 0, err=%v", owners, err)
	}
	_, err = pool.Exec(ctx, `INSERT INTO package_monitor_subscription_owners(
		subscription_id,state_revision,tenant_scope_id,owner_user_id,
		source_kind,source_fulfillment_id,created_at
	) VALUES($1,1,$2,$3,'subscription_state',NULL,$4)`,
		subscriptionID, tenantScopeID, userID, now)
	assertPackageMonitor078Code(t, err, "23514")
}

func TestPackageMonitor078DeferredHeadAuditAndExactNotificationRollback(t *testing.T) {
	pool := packageMonitor078Pool(t)
	ctx := t.Context()
	tenantID, scopeID, userID := uuid.New(), uuid.New(), uuid.New()
	subscriptionID, policyID, alertID := uuid.New(), uuid.New(), uuid.New()
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")
	now := time.Date(2026, 7, 28, 4, 0, 0, 0, time.UTC)
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO tenants(id,display_name) VALUES($1,$2)`, []any{tenantID, "078 kernel " + suffix}},
		{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, []any{scopeID, tenantID}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,$3,'hash')`, []any{userID, "k078" + suffix, "078 kernel " + suffix}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{scopeID, userID}},
	} {
		if _, err := pool.Exec(ctx, statement.sql, statement.args...); err != nil {
			t.Fatal(err)
		}
	}

	seed, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := seed.Exec(ctx, `SET LOCAL session_replication_role='replica'`); err != nil {
		_ = seed.Rollback(ctx)
		t.Fatal(err)
	}
	if _, err := seed.Exec(ctx, `INSERT INTO package_monitor_subscription_owners(
		subscription_id,state_revision,tenant_scope_id,owner_user_id,source_kind,created_at
	) VALUES($1,1,$2,$3,'subscription_state',$4)`, subscriptionID, scopeID, userID, now); err != nil {
		_ = seed.Rollback(ctx)
		t.Fatal(err)
	}
	if _, err := seed.Exec(ctx, `SET LOCAL session_replication_role='origin'`); err != nil {
		_ = seed.Rollback(ctx)
		t.Fatal(err)
	}
	if _, err := seed.Exec(ctx, `INSERT INTO package_monitor_policy_versions(
		policy_id,revision,tenant_scope_id,subscription_id,owner_user_id,metric,
		trigger_value,recovery_value,stale_after_seconds,threshold_identity,
		enabled,created_by_user_id,created_at
	) VALUES($1,1,$2,$3,$4,'traffic_bytes',100,80,NULL,
		package_monitor_threshold_sha256_078($1,1,'traffic_bytes',100,80,NULL),true,$4,$5)`,
		policyID, scopeID, subscriptionID, userID, now); err != nil {
		_ = seed.Rollback(ctx)
		t.Fatal(err)
	}
	if _, err := seed.Exec(ctx, `INSERT INTO package_monitor_policy_heads(
		policy_id,tenant_scope_id,subscription_id,owner_user_id,metric,current_revision,
		current_threshold_identity,next_evaluation_at,revision,updated_at
	) SELECT policy_id,tenant_scope_id,subscription_id,owner_user_id,metric,revision,
		threshold_identity,NULL,1,$2 FROM package_monitor_policy_versions
		WHERE policy_id=$1 AND revision=1`, policyID, now); err != nil {
		_ = seed.Rollback(ctx)
		t.Fatal(err)
	}
	if err := seed.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	var thresholdHex string
	if err := pool.QueryRow(ctx, `SELECT encode(threshold_identity,'hex')
		FROM package_monitor_policy_versions WHERE policy_id=$1 AND revision=1`, policyID).Scan(&thresholdHex); err != nil {
		t.Fatal(err)
	}

	missingAudit, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := insertPackageMonitorBefore078(ctx, missingAudit, alertID, scopeID, subscriptionID, userID, policyID, now); err != nil {
		_ = missingAudit.Rollback(ctx)
		t.Fatal(err)
	}
	assertPackageMonitor078Code(t, missingAudit.Commit(ctx), "23514")
	assertPackageMonitor078KernelCounts(t, pool, 0, 0, 0, 0)

	contradictory, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	contradictoryReceiptID, err := insertPackageMonitorBefore078(
		ctx, contradictory, alertID, scopeID, subscriptionID, userID, policyID, now,
	)
	if err != nil {
		_ = contradictory.Rollback(ctx)
		t.Fatal(err)
	}
	contradictoryPayload := packageMonitorAuditPayload078(
		scopeID, subscriptionID, userID, policyID, thresholdHex, "2026-07",
		1, "before.reason", nil, now,
	)
	var contradictoryFields map[string]any
	if err := json.Unmarshal(contradictoryPayload, &contradictoryFields); err != nil {
		_ = contradictory.Rollback(ctx)
		t.Fatal(err)
	}
	contradictoryFields["job_id"] = uuid.NewString()
	contradictoryFields["job_attempt"] = 2
	contradictoryFields["job_item_id"] = "contradictory-item"
	contradictoryFields["request_id"] = "contradictory-request"
	contradictoryPayload, err = json.Marshal(contradictoryFields)
	if err != nil {
		_ = contradictory.Rollback(ctx)
		t.Fatal(err)
	}
	if err := insertPackageMonitorAudit078(
		ctx, contradictory, scopeID, 1, "package_monitor.alert.observe_before",
		alertID, 1, contradictoryPayload, "contradictory-audit-item", nil, nil, now,
	); err != nil {
		_ = contradictory.Rollback(ctx)
		t.Fatal(err)
	}
	if err := insertPackageMonitorReceiptAudit078(
		ctx, contradictory, contradictoryReceiptID, 2, nil, now,
	); err != nil {
		_ = contradictory.Rollback(ctx)
		t.Fatal(err)
	}
	contradictoryErr := contradictory.Commit(ctx)
	assertPackageMonitor078Code(t, contradictoryErr, "23514")
	if !strings.Contains(contradictoryErr.Error(), "transition requires one exact success audit event") {
		t.Fatalf("contradictory audit commit error = %v", contradictoryErr)
	}
	assertPackageMonitor078KernelCounts(t, pool, 0, 0, 0, 0)

	for _, spelling := range []string{"offset", "fixed_nine_fraction", "space_separator"} {
		t.Run("audit_evaluated_at_rejects_"+spelling, func(t *testing.T) {
			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			testReceiptID, err := insertPackageMonitorBefore078(
				ctx, tx, alertID, scopeID, subscriptionID, userID, policyID, now,
			)
			if err != nil {
				t.Fatal(err)
			}
			var evaluatedAt time.Time
			if err := tx.QueryRow(ctx, `SELECT evaluated_at
				FROM package_monitor_evaluation_receipts WHERE receipt_id=$1`,
				testReceiptID).Scan(&evaluatedAt); err != nil {
				t.Fatal(err)
			}
			noncanonical := ""
			switch spelling {
			case "offset":
				noncanonical = evaluatedAt.UTC().Add(time.Hour).
					Format("2006-01-02T15:04:05.999999999") + "+01:00"
			case "fixed_nine_fraction":
				noncanonical = evaluatedAt.UTC().Format("2006-01-02T15:04:05.000000000Z")
			case "space_separator":
				noncanonical = evaluatedAt.UTC().Format("2006-01-02 15:04:05.999999999") + "+00:00"
			}
			payload := packageMonitorAuditPayload078(
				scopeID, subscriptionID, userID, policyID, thresholdHex, "2026-07",
				1, "before.reason", nil, now,
			)
			auditErr := insertPackageMonitorAudit078(
				ctx, tx, scopeID, 1, "package_monitor.alert.observe_before",
				alertID, 1, payload, "job-item", &noncanonical, nil, now,
			)
			assertPackageMonitor078Code(t, auditErr, "23514")
			if !strings.Contains(auditErr.Error(), "evaluation clock mismatch") {
				t.Fatalf("noncanonical evaluated_at %q error = %v", noncanonical, auditErr)
			}
		})
	}

	validBefore, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	receiptID, err := insertPackageMonitorBefore078(
		ctx, validBefore, alertID, scopeID, subscriptionID, userID, policyID, now,
	)
	if err != nil {
		_ = validBefore.Rollback(ctx)
		t.Fatal(err)
	}
	beforePayload := packageMonitorAuditPayload078(
		scopeID, subscriptionID, userID, policyID, thresholdHex, "2026-07",
		1, "before.reason", nil, now,
	)
	if err := insertPackageMonitorAudit078(
		ctx, validBefore, scopeID, 1, "package_monitor.alert.observe_before",
		alertID, 1, beforePayload, "job-item", nil, nil, now,
	); err != nil {
		_ = validBefore.Rollback(ctx)
		t.Fatal(err)
	}
	if err := insertPackageMonitorReceiptAudit078(
		ctx, validBefore, receiptID, 2, nil, now,
	); err != nil {
		_ = validBefore.Rollback(ctx)
		t.Fatal(err)
	}
	if err := validBefore.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	assertPackageMonitor078KernelCounts(t, pool, 1, 1, 0, 1)
	var canonicalAuditTimes int
	if err := pool.QueryRow(ctx, `SELECT count(*)
		FROM audit_events AS event
		JOIN package_monitor_transition_facts AS fact
		  ON event.resource_id=fact.alert_id::text || ':' || fact.revision::text
		WHERE event.action='package_monitor.alert.observe_before'
		  AND event.payload->>'evaluated_at'=package_monitor_rfc3339nano_078(fact.evaluated_at)
		  AND event.payload->>'observed_at'=package_monitor_rfc3339nano_078(fact.observed_at)`).Scan(
		&canonicalAuditTimes,
	); err != nil || canonicalAuditTimes != 1 {
		t.Fatalf("canonical audit evaluated/observed times = %d, err=%v", canonicalAuditTimes, err)
	}

	for _, test := range []struct {
		name   string
		offset time.Duration
		valid  bool
	}{
		{name: "exact", valid: true},
		{name: "minus_one_microsecond", offset: -time.Microsecond},
		{name: "plus_one_microsecond", offset: time.Microsecond},
		{name: "far_future", offset: 365 * 24 * time.Hour},
	} {
		t.Run("head_updated_at_clock/"+test.name, func(t *testing.T) {
			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			clockID, evaluatedAt, err := packageMonitorEvaluationClock078(ctx, tx)
			if err != nil {
				t.Fatal(err)
			}
			digest := make([]byte, 32)
			digest[0] = 1
			_, updateErr := tx.Exec(ctx, `UPDATE package_monitor_alert_heads
				SET last_source_watermark=2,last_evidence_digest=$2,last_finalized_through=$3,
					last_evaluation_clock_id=$4,last_evaluated_at=$5,updated_at=$6
				WHERE id=$1`, alertID, digest, now.Add(time.Minute), clockID, evaluatedAt,
				evaluatedAt.Add(test.offset))
			if test.valid {
				if updateErr != nil {
					t.Fatalf("exact head updated_at: %v", updateErr)
				}
				return
			}
			assertPackageMonitor078Code(t, updateErr, "23514")
			if !strings.Contains(updateErr.Error(), "evaluation clock mismatch") {
				t.Fatalf("head updated_at clock error = %v", updateErr)
			}
		})
	}

	for _, test := range []struct {
		name   string
		offset time.Duration
		valid  bool
	}{
		{name: "exact", valid: true},
		{name: "minus_one_microsecond", offset: -time.Microsecond},
		{name: "plus_one_microsecond", offset: time.Microsecond},
	} {
		t.Run("receipt_created_at_clock/"+test.name, func(t *testing.T) {
			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			clockID, evaluatedAt, err := packageMonitorEvaluationClock078(ctx, tx)
			if err != nil {
				t.Fatal(err)
			}
			digest := make([]byte, 32)
			digest[0] = 2
			if _, err := tx.Exec(ctx, `UPDATE package_monitor_alert_heads
				SET last_source_watermark=2,last_evidence_digest=$2,last_finalized_through=$3,
					last_evaluation_clock_id=$4,last_evaluated_at=$5,updated_at=$5
				WHERE id=$1`, alertID, digest, now.Add(time.Minute), clockID, evaluatedAt); err != nil {
				t.Fatal(err)
			}
			_, insertErr := tx.Exec(ctx, `INSERT INTO package_monitor_evaluation_receipts(
				receipt_id,alert_id,tenant_scope_id,subscription_id,owner_user_id,policy_id,
				policy_revision,metric,period_key,threshold_identity,result_revision,result_state,
				result_transition,transition_fact_revision,metric_schema_version,source_watermark,
				observed_at,finalized_through,evidence_digest,evaluation_clock_id,evaluated_at,
				notification_event_id,job_id,job_attempt,job_item_id,request_id,created_at
			) SELECT $1,$2,$3,$4,$5,$6,1,'traffic_bytes','2026-07',threshold_identity,
				1,'before','',NULL,'package-monitor-metric/v1',2,$7,$7,$8,$9,$10,NULL,
				$11,1,$12,$13,$14
				FROM package_monitor_policy_versions WHERE policy_id=$6 AND revision=1`,
				uuid.New(), alertID, scopeID, subscriptionID, userID, policyID, now.Add(time.Minute),
				digest, clockID, evaluatedAt, uuid.New(), "created-at-item-"+test.name,
				"created-at-request-"+test.name, evaluatedAt.Add(test.offset))
			if test.valid {
				if insertErr != nil {
					t.Fatalf("exact receipt created_at: %v", insertErr)
				}
				return
			}
			assertPackageMonitor078Code(t, insertErr, "23514")
			if !strings.Contains(insertErr.Error(), "evaluation clock mismatch") {
				t.Fatalf("receipt created_at clock error = %v", insertErr)
			}
		})
	}

	for _, test := range []struct {
		name                 string
		forgeNotification    bool
		receiptObservedShift time.Duration
	}{
		{name: "notification", forgeNotification: true},
		{name: "observed_at", receiptObservedShift: time.Microsecond},
	} {
		t.Run("receipt_matches_transition_"+test.name, func(t *testing.T) {
			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			clockID, evaluatedAt, err := packageMonitorEvaluationClock078(ctx, tx)
			if err != nil {
				t.Fatal(err)
			}
			realEventID := uuid.New()
			sourceEventID := "receipt-identity-source-" + test.name
			if _, err := tx.Exec(ctx, `INSERT INTO notification_events(
				id,scope_id,recipient_user_id,source_event_id,event_type,delivery_policy,
				request_digest,created_at
			) VALUES($1,$2,$3,$4,'package.monitor.traffic.triggered',
				'tenant_subscribed',$5,$6)`, realEventID, scopeID, userID, sourceEventID,
				make([]byte, 32), now); err != nil {
				t.Fatal(err)
			}
			digest := make([]byte, 32)
			digest[0] = 3
			observedAt := now.Add(time.Minute)
			finalizedAt := observedAt.Add(time.Second)
			if _, err := tx.Exec(ctx, `UPDATE package_monitor_alert_heads
				SET state='triggered',revision=2,last_source_watermark=2,last_evidence_digest=$2,
					last_finalized_through=$3,last_evaluation_clock_id=$4,last_evaluated_at=$5,updated_at=$5
				WHERE id=$1`, alertID, digest, finalizedAt, clockID, evaluatedAt); err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, `INSERT INTO package_monitor_transition_facts(
				alert_id,revision,tenant_scope_id,subscription_id,owner_user_id,policy_id,policy_revision,
				metric,period_key,threshold_identity,phase,observed_value,metric_schema_version,
				source_watermark,observed_at,finalized_through,evidence_digest,evaluation_clock_id,
				evaluated_at,reason_code,source_event_id,notification_event_id,notification_event_type
			) SELECT $1,2,$2,$3,$4,$5,1,'traffic_bytes','2026-07',threshold_identity,
				'triggered',100,'package-monitor-metric/v1',2,$6,$7,$8,$9,$10,'trigger.reason',
				$11,$12,'package.monitor.traffic.triggered'
				FROM package_monitor_policy_versions WHERE policy_id=$5 AND revision=1`,
				alertID, scopeID, subscriptionID, userID, policyID, observedAt, finalizedAt,
				digest, clockID, evaluatedAt, sourceEventID, realEventID); err != nil {
				t.Fatal(err)
			}
			receiptEventID := realEventID
			if test.forgeNotification {
				receiptEventID = uuid.New()
			}
			_, receiptErr := tx.Exec(ctx, `INSERT INTO package_monitor_evaluation_receipts(
				receipt_id,alert_id,tenant_scope_id,subscription_id,owner_user_id,policy_id,
				policy_revision,metric,period_key,threshold_identity,result_revision,result_state,
				result_transition,transition_fact_revision,metric_schema_version,source_watermark,
				observed_at,finalized_through,evidence_digest,evaluation_clock_id,evaluated_at,
				notification_event_id,job_id,job_attempt,job_item_id,request_id,created_at
			) SELECT $1,$2,$3,$4,$5,$6,1,'traffic_bytes','2026-07',threshold_identity,
				2,'triggered','triggered',2,'package-monitor-metric/v1',2,$7,$8,$9,$10,$11,
				$12,$13,1,'receipt-identity-item','receipt-identity-request',$11
				FROM package_monitor_policy_versions WHERE policy_id=$6 AND revision=1`,
				uuid.New(), alertID, scopeID, subscriptionID, userID, policyID,
				observedAt.Add(test.receiptObservedShift), finalizedAt, digest, clockID, evaluatedAt,
				receiptEventID, uuid.New())
			assertPackageMonitor078Code(t, receiptErr, "23514")
			if !strings.Contains(receiptErr.Error(), "new evaluation receipt does not equal current alert head") {
				t.Fatalf("receipt %s identity error = %v", test.name, receiptErr)
			}
		})
	}

	gap, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	gapClockID, gapEvaluatedAt, err := packageMonitorEvaluationClock078(ctx, gap)
	if err != nil {
		_ = gap.Rollback(ctx)
		t.Fatal(err)
	}
	gapEventID := uuid.New()
	if _, err := gap.Exec(ctx, `INSERT INTO notification_events(
		id,scope_id,recipient_user_id,source_event_id,event_type,delivery_policy,request_digest,created_at
	) VALUES($1,$2,$3,'gap-recovery-source','package.monitor.traffic.recovered',
		'tenant_subscribed',$4,$5)`, gapEventID, scopeID, userID, make([]byte, 32), now.Add(2*time.Minute)); err != nil {
		_ = gap.Rollback(ctx)
		t.Fatal(err)
	}
	if _, err := gap.Exec(ctx, `UPDATE package_monitor_alert_heads
		SET state='triggered',revision=2,last_source_watermark=2,
			last_finalized_through=$2,last_evaluation_clock_id=$3,
			last_evaluated_at=$4,updated_at=$4
		WHERE id=$1`, alertID, now.Add(time.Minute), gapClockID, gapEvaluatedAt); err != nil {
		_ = gap.Rollback(ctx)
		t.Fatal(err)
	}
	if _, err := gap.Exec(ctx, `UPDATE package_monitor_alert_heads
		SET state='recovered',revision=3,last_source_watermark=3,
			last_finalized_through=$2,last_evaluation_clock_id=$3,
			last_evaluated_at=$4,updated_at=$4
		WHERE id=$1`, alertID, now.Add(2*time.Minute), gapClockID, gapEvaluatedAt); err != nil {
		_ = gap.Rollback(ctx)
		t.Fatal(err)
	}
	if _, err := gap.Exec(ctx, `INSERT INTO package_monitor_transition_facts(
		alert_id,revision,tenant_scope_id,subscription_id,owner_user_id,policy_id,policy_revision,
		metric,period_key,threshold_identity,phase,observed_value,metric_schema_version,
		source_watermark,observed_at,finalized_through,evidence_digest,evaluation_clock_id,
		evaluated_at,reason_code,
		source_event_id,notification_event_id,notification_event_type
	) SELECT $1,3,$2,$3,$4,$5,1,'traffic_bytes','2026-07',threshold_identity,
		'recovered',70,'package-monitor-metric/v1',3,$6,$6,$7,$8,$9,'gap.recovered',
		'gap-recovery-source',$10,'package.monitor.traffic.recovered'
		FROM package_monitor_policy_versions WHERE policy_id=$5 AND revision=1`,
		alertID, scopeID, subscriptionID, userID, policyID, now.Add(2*time.Minute),
		make([]byte, 32), gapClockID, gapEvaluatedAt, gapEventID); err != nil {
		_ = gap.Rollback(ctx)
		t.Fatal(err)
	}
	gapPayload := packageMonitorAuditPayload078(
		scopeID, subscriptionID, userID, policyID, thresholdHex, "2026-07",
		3, "gap.recovered", &gapEventID, now.Add(2*time.Minute),
	)
	if err := insertPackageMonitorAudit078(
		ctx, gap, scopeID, 3, "package_monitor.alert.recover",
		alertID, 3, gapPayload, "job-item", nil, nil, now.Add(2*time.Minute),
	); err != nil {
		_ = gap.Rollback(ctx)
		t.Fatal(err)
	}
	gapErr := gap.Commit(ctx)
	assertPackageMonitor078Code(t, gapErr, "23514")
	if !strings.Contains(gapErr.Error(), "alert head transition has no exact fact") {
		t.Fatalf("gap commit error = %v, want exact intermediate head fact rejection", gapErr)
	}
	assertPackageMonitor078KernelCounts(t, pool, 1, 1, 0, 1)

	rogueAudit, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	rogueClockID, rogueEvaluatedAt, err := packageMonitorEvaluationClock078(ctx, rogueAudit)
	if err != nil {
		_ = rogueAudit.Rollback(ctx)
		t.Fatal(err)
	}
	if _, err := rogueAudit.Exec(ctx, `INSERT INTO audit_events(
		id,scope_id,stream_position,action,resource_type,resource_id,request_id,result,
		payload,previous_hash,event_hash,occurred_at
	) VALUES($1,$2,3,'package_monitor.alert.observe_before',
		'package_monitor_alert_transition_rogue',$3,'job-item','success',
		$4::jsonb || jsonb_build_object(
			'evaluation_clock_id',$5::uuid::text,
			'evaluated_at',package_monitor_rfc3339nano_078($6)
		),$7,$7,$6)`, uuid.New(), scopeID, alertID.String()+":1", beforePayload,
		rogueClockID, rogueEvaluatedAt, make([]byte, 32)); err != nil {
		_ = rogueAudit.Rollback(ctx)
		t.Fatal(err)
	}
	rogueAuditErr := rogueAudit.Commit(ctx)
	assertPackageMonitor078Code(t, rogueAuditErr, "23514")
	if !strings.Contains(rogueAuditErr.Error(), "requires one exact success audit event") {
		t.Fatalf("rogue audit commit error = %v, want triggering audit row rejection", rogueAuditErr)
	}
	assertPackageMonitor078KernelCounts(t, pool, 1, 1, 0, 1)

	mismatched, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	mismatchClockID, mismatchEvaluatedAt, err := packageMonitorEvaluationClock078(ctx, mismatched)
	if err != nil {
		_ = mismatched.Rollback(ctx)
		t.Fatal(err)
	}
	eventID := uuid.New()
	if _, err := mismatched.Exec(ctx, `INSERT INTO notification_events(
		id,scope_id,recipient_user_id,source_event_id,event_type,delivery_policy,request_digest,created_at
	) VALUES($1,$2,$3,'exact-source','package.monitor.traffic.triggered','tenant_subscribed',$4,$5)`,
		eventID, scopeID, userID, make([]byte, 32), now.Add(time.Minute)); err != nil {
		_ = mismatched.Rollback(ctx)
		t.Fatal(err)
	}
	_, mismatchErr := mismatched.Exec(ctx, `INSERT INTO package_monitor_transition_facts(
		alert_id,revision,tenant_scope_id,subscription_id,owner_user_id,policy_id,policy_revision,
		metric,period_key,threshold_identity,phase,observed_value,metric_schema_version,
		source_watermark,observed_at,finalized_through,evidence_digest,evaluation_clock_id,
		evaluated_at,reason_code,
		source_event_id,notification_event_id,notification_event_type
	) SELECT $1,2,$2,$3,$4,$5,1,'traffic_bytes','2026-07',threshold_identity,
		'triggered',120,'package-monitor-metric/v1',2,$6,$6,$7,$8,$9,'trigger.reason',
		'wrong-source',$10,'package.monitor.traffic.triggered'
		FROM package_monitor_policy_versions WHERE policy_id=$5 AND revision=1`,
		alertID, scopeID, subscriptionID, userID, policyID, now.Add(time.Minute),
		make([]byte, 32), mismatchClockID, mismatchEvaluatedAt, eventID)
	assertPackageMonitor078Code(t, mismatchErr, "23503")
	_ = mismatched.Rollback(ctx)
	assertPackageMonitor078KernelCounts(t, pool, 1, 1, 0, 1)

	for _, operation := range []string{"insert", "state-changing-update"} {
		for _, field := range []string{
			"source-watermark", "finalized-through", "evidence-digest",
		} {
			if !t.Run(operation+"/"+field, func(t *testing.T) {
				tx, err := pool.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback(context.Background())
				clockID, evaluatedAt, err := packageMonitorEvaluationClock078(ctx, tx)
				if err != nil {
					t.Fatal(err)
				}

				testAlertID := alertID
				revision := 2
				phase := "triggered"
				action := "package_monitor.alert.trigger"
				reason := "provenance.update." + strings.ReplaceAll(field, "-", "_")
				periodKey := "2026-07"
				transitionAt := now.Add(time.Minute)
				headWatermark := uint64(2)
				headFinalized := transitionAt
				headDigest := make([]byte, 32)
				switch field {
				case "source-watermark":
					headWatermark = 3
				case "finalized-through":
					headFinalized = transitionAt.Add(time.Second)
				case "evidence-digest":
					headDigest[0] = 1
				}

				if operation == "insert" {
					testAlertID = uuid.New()
					revision = 1
					phase = "before"
					action = "package_monitor.alert.observe_before"
					reason = "provenance.insert." + strings.ReplaceAll(field, "-", "_")
					periodKey = "2026-07-insert-" + field
					if _, err := tx.Exec(ctx, `INSERT INTO package_monitor_alert_heads(
						id,tenant_scope_id,subscription_id,owner_user_id,policy_id,policy_revision,metric,
						period_key,threshold_identity,state,revision,last_source_watermark,last_evidence_digest,
						last_finalized_through,last_evaluation_clock_id,last_evaluated_at,updated_at
					) SELECT $1,$2,$3,$4,$5,1,'traffic_bytes',$6,threshold_identity,
						'before',1,$7,$8,$9,$10,$11,$11 FROM package_monitor_policy_versions
						WHERE policy_id=$5 AND revision=1`,
						testAlertID, scopeID, subscriptionID, userID, policyID, periodKey, headWatermark,
						headDigest, headFinalized, clockID, evaluatedAt); err != nil {
						t.Fatal(err)
					}
				} else {
					if _, err := tx.Exec(ctx, `UPDATE package_monitor_alert_heads
						SET state='triggered',revision=2,last_source_watermark=$2,
							last_evidence_digest=$3,last_finalized_through=$4,
							last_evaluation_clock_id=$5,last_evaluated_at=$6,updated_at=$6
						WHERE id=$1`, testAlertID, headWatermark, headDigest,
						headFinalized, clockID, evaluatedAt); err != nil {
						t.Fatal(err)
					}
				}

				var notificationEventID *uuid.UUID
				var sourceEventID, notificationEventType any
				if operation == "state-changing-update" {
					eventID := uuid.New()
					source := "provenance-" + strings.ReplaceAll(field, "-", "_")
					eventType := "package.monitor.traffic.triggered"
					if _, err := tx.Exec(ctx, `INSERT INTO notification_events(
						id,scope_id,recipient_user_id,source_event_id,event_type,delivery_policy,
						request_digest,created_at
					) VALUES($1,$2,$3,$4,$5,'tenant_subscribed',$6,$7)`,
						eventID, scopeID, userID, source, eventType, make([]byte, 32), transitionAt); err != nil {
						t.Fatal(err)
					}
					notificationEventID = &eventID
					sourceEventID = source
					notificationEventType = eventType
				}
				if _, err := tx.Exec(ctx, `INSERT INTO package_monitor_transition_facts(
					alert_id,revision,tenant_scope_id,subscription_id,owner_user_id,policy_id,policy_revision,
					metric,period_key,threshold_identity,phase,observed_value,metric_schema_version,
					source_watermark,observed_at,finalized_through,evidence_digest,evaluation_clock_id,
					evaluated_at,reason_code,
					source_event_id,notification_event_id,notification_event_type
				) SELECT $1,$2,$3,$4,$5,$6,1,'traffic_bytes',$7,threshold_identity,
					$8,120,'package-monitor-metric/v1',2,$9,$9,$10,$11,$12,$13,$14,$15,$16
					FROM package_monitor_policy_versions WHERE policy_id=$6 AND revision=1`,
					testAlertID, revision, scopeID, subscriptionID, userID, policyID, periodKey, phase,
					transitionAt, make([]byte, 32), clockID, evaluatedAt, reason,
					sourceEventID, notificationEventID,
					notificationEventType); err != nil {
					t.Fatal(err)
				}
				payload := packageMonitorAuditPayload078(
					scopeID, subscriptionID, userID, policyID, thresholdHex, periodKey,
					2, reason, notificationEventID, transitionAt,
				)
				if err := insertPackageMonitorAudit078(
					ctx, tx, scopeID, 3, action, testAlertID, revision,
					payload, "job-item", nil, nil, transitionAt,
				); err != nil {
					t.Fatal(err)
				}
				commitErr := tx.Commit(ctx)
				assertPackageMonitor078Code(t, commitErr, "23514")
				if !strings.Contains(commitErr.Error(), "alert head transition has no exact fact") {
					t.Fatalf("commit error = %v, want exact head/fact provenance rejection", commitErr)
				}
				assertPackageMonitor078KernelCounts(t, pool, 1, 1, 0, 1)
			}) {
				return
			}
		}
	}

	progressAt := now.Add(3 * time.Minute)
	progressDigest := make([]byte, 32)
	progressDigest[0] = 1
	progress, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer progress.Rollback(context.Background())
	progressClockID, progressEvaluatedAt, err := packageMonitorEvaluationClock078(ctx, progress)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := progress.Exec(ctx, `UPDATE package_monitor_alert_heads
		SET last_source_watermark=2,last_evidence_digest=$2,last_finalized_through=$3,
			last_evaluation_clock_id=$4,last_evaluated_at=$5,updated_at=$5
		WHERE id=$1`, alertID, progressDigest, progressAt,
		progressClockID, progressEvaluatedAt); err != nil {
		t.Fatalf("same-state progress: %v", err)
	}
	progressReceiptID := uuid.New()
	if _, err := progress.Exec(ctx, `INSERT INTO package_monitor_evaluation_receipts(
		receipt_id,alert_id,tenant_scope_id,subscription_id,owner_user_id,policy_id,
		policy_revision,metric,period_key,threshold_identity,result_revision,result_state,
		result_transition,transition_fact_revision,metric_schema_version,source_watermark,
		observed_at,finalized_through,evidence_digest,evaluation_clock_id,evaluated_at,
		notification_event_id,
		job_id,job_attempt,job_item_id,request_id,created_at
	) SELECT $1,$2,$3,$4,$5,$6,1,'traffic_bytes','2026-07',threshold_identity,
		1,'before','',NULL,'package-monitor-metric/v1',2,$7,$7,$8,$9,$10,NULL,
		$11,1,'job-item-progress','request-progress',$10
		FROM package_monitor_policy_versions WHERE policy_id=$6 AND revision=1`,
		progressReceiptID, alertID, scopeID, subscriptionID, userID, policyID,
		progressAt, progressDigest, progressClockID, progressEvaluatedAt,
		uuid.MustParse("00000000-0000-0000-0000-000000000079")); err != nil {
		t.Fatal(err)
	}
	if err := insertPackageMonitorReceiptAudit078(
		ctx, progress, progressReceiptID, 3, make([]byte, 32), progressAt,
	); err != nil {
		t.Fatal(err)
	}
	if err := progress.Commit(ctx); err != nil {
		t.Fatalf("same-state progress commit: %v", err)
	}
	var progressRevision int
	var progressState string
	var progressWatermark uint64
	var progressFinalized time.Time
	if err := pool.QueryRow(ctx, `SELECT revision,state,last_source_watermark,last_finalized_through
		FROM package_monitor_alert_heads WHERE id=$1`, alertID).Scan(
		&progressRevision, &progressState, &progressWatermark, &progressFinalized,
	); err != nil {
		t.Fatal(err)
	}
	if progressRevision != 1 || progressState != "before" || progressWatermark != 2 ||
		!progressFinalized.Equal(progressAt) {
		t.Fatalf("same-state progress = revision %d state %s watermark %d finalized %s",
			progressRevision, progressState, progressWatermark, progressFinalized)
	}
	assertPackageMonitor078KernelCounts(t, pool, 1, 1, 0, 1)
}

func insertPackageMonitorBefore078(
	ctx context.Context,
	tx pgx.Tx,
	alertID, scopeID, subscriptionID, userID, policyID uuid.UUID,
	now time.Time,
) (uuid.UUID, error) {
	clockID, evaluatedAt, err := packageMonitorEvaluationClock078(ctx, tx)
	if err != nil {
		return uuid.Nil, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO package_monitor_alert_heads(
		id,tenant_scope_id,subscription_id,owner_user_id,policy_id,policy_revision,metric,
		period_key,threshold_identity,state,revision,last_source_watermark,last_evidence_digest,
		last_finalized_through,last_evaluation_clock_id,last_evaluated_at,updated_at
	) SELECT $1,$2,$3,$4,$5,1,'traffic_bytes','2026-07',threshold_identity,
		'before',1,1,$6,$7,$8,$9,$9 FROM package_monitor_policy_versions
		WHERE policy_id=$5 AND revision=1`,
		alertID, scopeID, subscriptionID, userID, policyID, make([]byte, 32), now,
		clockID, evaluatedAt); err != nil {
		return uuid.Nil, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO package_monitor_transition_facts(
		alert_id,revision,tenant_scope_id,subscription_id,owner_user_id,policy_id,policy_revision,
		metric,period_key,threshold_identity,phase,observed_value,metric_schema_version,
		source_watermark,observed_at,finalized_through,evidence_digest,evaluation_clock_id,
		evaluated_at,reason_code
	) SELECT $1,1,$2,$3,$4,$5,1,'traffic_bytes','2026-07',threshold_identity,
		'before',50,'package-monitor-metric/v1',1,$6,$6,$7,$8,$9,'before.reason'
		FROM package_monitor_policy_versions WHERE policy_id=$5 AND revision=1`,
		alertID, scopeID, subscriptionID, userID, policyID, now, make([]byte, 32),
		clockID, evaluatedAt); err != nil {
		return uuid.Nil, err
	}
	receiptID := uuid.New()
	_, err = tx.Exec(ctx, `INSERT INTO package_monitor_evaluation_receipts(
		receipt_id,alert_id,tenant_scope_id,subscription_id,owner_user_id,policy_id,
		policy_revision,metric,period_key,threshold_identity,result_revision,result_state,
		result_transition,transition_fact_revision,metric_schema_version,source_watermark,
		observed_at,finalized_through,evidence_digest,evaluation_clock_id,evaluated_at,
		notification_event_id,
		job_id,job_attempt,job_item_id,request_id,created_at
	) SELECT $1,$2,$3,$4,$5,$6,1,'traffic_bytes','2026-07',threshold_identity,
		1,'before','',1,'package-monitor-metric/v1',1,$7,$7,$8,$9,$10,NULL,
		$11,1,'job-item','request-078',$10
		FROM package_monitor_policy_versions WHERE policy_id=$6 AND revision=1`,
		receiptID, alertID, scopeID, subscriptionID, userID, policyID, now,
		make([]byte, 32), clockID, evaluatedAt,
		uuid.MustParse("00000000-0000-0000-0000-000000000078"))
	return receiptID, err
}

func packageMonitorEvaluationClock078(
	ctx context.Context,
	tx pgx.Tx,
) (uuid.UUID, time.Time, error) {
	var clockID uuid.UUID
	var evaluatedAt time.Time
	err := tx.QueryRow(ctx, `SELECT evaluation_clock_id,evaluated_at
		FROM package_monitor_transaction_clock_078()`).Scan(&clockID, &evaluatedAt)
	return clockID, evaluatedAt, err
}

func insertPackageMonitorReceiptAudit078(
	ctx context.Context,
	tx pgx.Tx,
	receiptID uuid.UUID,
	streamPosition int,
	previousHash []byte,
	now time.Time,
) error {
	if streamPosition > 1 && previousHash == nil {
		previousHash = make([]byte, 32)
	}
	_, err := tx.Exec(ctx, `INSERT INTO audit_events(
		id,scope_id,stream_position,actor_user_id,action,resource_type,resource_id,
		request_id,result,payload,previous_hash,event_hash,occurred_at
	) SELECT $1,receipt.tenant_scope_id,$2,receipt.owner_user_id,
		'package_monitor.evaluation.commit','package_monitor_evaluation_receipt',
		receipt.receipt_id::text,receipt.job_item_id,'success',jsonb_build_object(
			'receipt_id',receipt.receipt_id::text,
			'alert_id',receipt.alert_id::text,
			'tenant_scope_id',receipt.tenant_scope_id::text,
			'subscription_id',receipt.subscription_id::text,
			'owner_user_id',receipt.owner_user_id::text,
			'policy_id',receipt.policy_id::text,
			'policy_revision',receipt.policy_revision,
			'metric',receipt.metric,
			'period_key',receipt.period_key,
			'threshold_identity',encode(receipt.threshold_identity,'hex'),
			'result_revision',receipt.result_revision,
			'result_state',receipt.result_state,
			'result_transition',receipt.result_transition,
			'source_watermark',receipt.source_watermark,
			'observed_at',package_monitor_rfc3339nano_078(receipt.observed_at),
			'evidence_digest',encode(receipt.evidence_digest,'hex'),
			'evaluation_clock_id',receipt.evaluation_clock_id::text,
			'evaluated_at',package_monitor_rfc3339nano_078(receipt.evaluated_at),
			'notification_event_id',receipt.notification_event_id,
			'job_id',receipt.job_id::text,
			'job_attempt',receipt.job_attempt,
			'job_item_id',receipt.job_item_id,
			'request_id',receipt.request_id
		),$3,$4,$5
		FROM package_monitor_evaluation_receipts AS receipt
		WHERE receipt.receipt_id=$6`, uuid.New(), streamPosition, previousHash,
		make([]byte, 32), now, receiptID)
	return err
}

func packageMonitorAuditPayload078(
	scopeID, subscriptionID, userID, policyID uuid.UUID,
	thresholdIdentity, periodKey string,
	watermark uint64,
	reason string,
	notificationEventID *uuid.UUID,
	evaluatedAt time.Time,
) []byte {
	var eventID any
	if notificationEventID != nil {
		eventID = notificationEventID.String()
	}
	payload, _ := json.Marshal(map[string]any{
		"tenant_scope_id": scopeID.String(), "subscription_id": subscriptionID.String(),
		"owner_user_id": userID.String(), "policy_id": policyID.String(),
		"policy_revision": 1, "metric": "traffic_bytes", "period_key": periodKey,
		"threshold_identity": thresholdIdentity, "source_watermark": watermark,
		"evidence_digest": strings.Repeat("0", 64), "reason_code": reason,
		"observed_at":           evaluatedAt.UTC().Format(time.RFC3339Nano),
		"evaluated_at":          evaluatedAt.UTC().Format(time.RFC3339Nano),
		"notification_event_id": eventID,
		"job_id":                uuid.MustParse("00000000-0000-0000-0000-000000000078").String(),
		"job_attempt":           1, "job_item_id": "job-item", "request_id": "request-078",
	})
	return payload
}

func insertPackageMonitorAudit078(
	ctx context.Context,
	tx pgx.Tx,
	scopeID uuid.UUID,
	streamPosition int,
	action string,
	alertID uuid.UUID,
	revision int,
	payload []byte,
	requestID string,
	payloadEvaluatedAt *string,
	previousHash []byte,
	now time.Time,
) error {
	if streamPosition > 1 && previousHash == nil {
		previousHash = make([]byte, 32)
	}
	_, err := tx.Exec(ctx, `INSERT INTO audit_events(
		id,scope_id,stream_position,action,resource_type,resource_id,request_id,result,
		payload,previous_hash,event_hash,occurred_at
	) SELECT $1,$2,$3,$4,'package_monitor_alert_transition',$5,$6,'success',
		$7::jsonb || jsonb_build_object(
			'evaluation_clock_id',fact.evaluation_clock_id::text,
			'evaluated_at',COALESCE($8::text,package_monitor_rfc3339nano_078(fact.evaluated_at))
		),$9,$10,$11
		FROM package_monitor_transition_facts AS fact
		WHERE fact.alert_id=$12 AND fact.revision=$13`, uuid.New(), scopeID, streamPosition, action,
		alertID.String()+":"+strconv.Itoa(revision), requestID, payload, payloadEvaluatedAt,
		previousHash, make([]byte, 32), now, alertID, revision)
	return err
}

func assertPackageMonitor078KernelCounts(
	t *testing.T,
	pool *pgxpool.Pool,
	heads, facts, notifications, audits int,
) {
	t.Helper()
	var gotHeads, gotFacts, gotNotifications, gotAudits int
	if err := pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM package_monitor_alert_heads),
		(SELECT count(*) FROM package_monitor_transition_facts),
		(SELECT count(*) FROM notification_events WHERE event_type LIKE 'package.monitor.%'),
		(SELECT count(*) FROM audit_events WHERE action LIKE 'package_monitor.alert.%')`).Scan(
		&gotHeads, &gotFacts, &gotNotifications, &gotAudits,
	); err != nil || gotHeads != heads || gotFacts != facts ||
		gotNotifications != notifications || gotAudits != audits {
		t.Fatalf("kernel counts heads=%d/%d facts=%d/%d notifications=%d/%d audits=%d/%d err=%v",
			gotHeads, heads, gotFacts, facts, gotNotifications, notifications, gotAudits, audits, err)
	}
}

func readPackageMonitorManifest078(t *testing.T) []packageMonitorTemplate078 {
	t.Helper()
	var manifest []packageMonitorTemplate078
	if err := json.Unmarshal(packageMonitorTemplateManifest078, &manifest); err != nil {
		t.Fatal(err)
	}
	return manifest
}

func mustReadPackageMonitorMigration078(t *testing.T, name string) []byte {
	t.Helper()
	content, err := controlmigrations.FS.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func seedPackageMonitor078LegacySubscription(
	t *testing.T,
	pool *pgxpool.Pool,
) (uuid.UUID, uuid.UUID, uuid.UUID, time.Time) {
	t.Helper()
	tenantID, scopeID, userID := uuid.New(), uuid.New(), uuid.New()
	subscriptionID, productID := uuid.New(), uuid.New()
	createdAt := time.Date(2026, 7, 28, 3, 15, 0, 0, time.UTC)
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO tenants(id,display_name) VALUES($1,$2)`, []any{tenantID, "078 legacy " + suffix}},
		{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, []any{scopeID, tenantID}},
		{`INSERT INTO users(id,username,display_name,password_hash)
		  VALUES($1,$2,$3,'hash')`, []any{userID, "l078" + suffix, "078 legacy " + suffix}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{scopeID, userID}},
	} {
		if _, err := pool.Exec(t.Context(), statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role='replica'`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO package_subscriptions(
		id,tenant_scope_id,product_id,product_revision,product_snapshot,
		site_limit,domain_limit,node_limit,traffic_limit_bytes,starts_at,ends_at,
		timezone,cycle_kind,custom_cycle_days,tcp_factor_numerator,tcp_factor_denominator,
		lifecycle_status,revision,created_by_user_id,updated_by_user_id,created_at,updated_at
	) VALUES($1,$2,$3::uuid,1,jsonb_build_object(
		'id',$3::uuid::text,'revision',1,'name','legacy product','spec','{}'::jsonb
	),1,1,1,1,$4,$5,'UTC','monthly',0,1,1,'active',1,$6,$6,$4,$4)`,
		subscriptionID, scopeID, productID, createdAt, createdAt.Add(24*time.Hour), userID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO package_subscription_state_versions(
		subscription_id,revision,tenant_scope_id,owner_user_id,lifecycle_status,
		starts_at,ends_at,cancelled_at,created_at,updated_at,commit_sequence
	) VALUES($1,1,$2,$3,'active',$4,$5,NULL,$4,$4,0)`,
		subscriptionID, scopeID, userID, createdAt, createdAt.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role='origin'`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	return subscriptionID, scopeID, userID, createdAt
}

func packageMonitor078Pool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "package_monitor_078_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^package_monitor_078_test_[a-f0-9]{32}$`).MatchString(schema) {
		admin.Close()
		t.Fatalf("unsafe schema %q", schema)
	}
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		_, _ = admin.Exec(ctx, "DROP SCHEMA "+identifier+" CASCADE")
		admin.Close()
		t.Fatal(err)
	}
	if err := migrateVersionIsolated(ctx, pool, "up", 78); err != nil {
		pool.Close()
		_, _ = admin.Exec(ctx, "DROP SCHEMA "+identifier+" CASCADE")
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		cleanupCtx, cleanupCancel := databasetest.CleanupContext()
		defer cleanupCancel()
		if _, err := admin.Exec(cleanupCtx, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop schema: %v", err)
		}
		admin.Close()
	})
	return pool
}

func assertPackageMonitor078Version(t *testing.T, pool *pgxpool.Pool, want int) {
	t.Helper()
	var got int
	if err := pool.QueryRow(t.Context(), `SELECT COALESCE(max(version),0) FROM schema_migrations`).Scan(&got); err != nil || got != want {
		t.Fatalf("migration version = %d, want %d, err=%v", got, want, err)
	}
}

func assertPackageMonitor078Code(t *testing.T, err error, want string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != want {
		t.Fatalf("PostgreSQL error = %v, want code %s", err, want)
	}
}
