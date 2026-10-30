//go:build integration

package migrations_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestUpgradeLicenseReceiptDelivery097Contract(t *testing.T) {
	up := mustReadUpgradeLicenseReceipt097(t, "097_upgrade_license_receipt_delivery.up.sql")
	down := mustReadUpgradeLicenseReceipt097(t, "097_upgrade_license_receipt_delivery.down.sql")
	for _, fragment := range []string{
		"migration 097 requires the exact verified 096 release head",
		"5f6cbeaec3ea9d0e0b59861516575147a6b897022c5f25d911c115976d72214f",
		"3f1302b42bbe9a841da0892a989422d661407a381a1052522634ed0335f3eac4",
		"ERRCODE = 'P9700'",
		"CREATE TABLE control_upgrade_license_receipt_outbox_097",
		"CREATE TABLE control_upgrade_license_receipt_deliveries_097",
		"upgrade-grant.receipt-request/v2",
		"request_digest_schema",
		"cdnca-upgrade-grant-receipt-idempotency/v2",
		"UNIQUE (plan_id,status)",
		"UNIQUE (plan_id,receipt_sequence)",
		"UNIQUE (installation_id,request_id)",
		"UNIQUE (installation_id,grant_id,status)",
		"FOREIGN KEY (plan_id,installation_id,grant_id)",
		"FOREIGN KEY (predecessor_id)",
		"control_upgrade_license_receipt_id_097",
		"control_upgrade_license_receipt_reason_097",
		"control_upgrade_license_receipt_fact_097",
		"FOR SHARE",
		"INSUFFICIENT_DISK",
		"ARTIFACT_TOO_LARGE",
		"INSTALLER_ROLLED_BACK",
		"state IN ('pending','claimed','delivered','failed')",
		"DEFERRABLE INITIALLY DEFERRED",
		"control upgrade License receipt delivery is immutable",
		"ERRCODE = 'P9702'",
		"BEFORE TRUNCATE",
	} {
		if !strings.Contains(up, fragment) {
			t.Errorf("097 up missing %q", fragment)
		}
	}
	upDigest := sha256.Sum256([]byte(up))
	for _, fragment := range []string{
		"migration 097 rollback requires the exact verified 097 head",
		hex.EncodeToString(upDigest[:]),
		"migration 097 rollback would discard License receipt delivery facts",
		"ERRCODE = 'P9701'",
		"DROP TABLE control_upgrade_license_receipt_deliveries_097",
		"DROP TABLE control_upgrade_license_receipt_outbox_097",
	} {
		if !strings.Contains(down, fragment) {
			t.Errorf("097 down missing %q", fragment)
		}
	}
}

func TestUpgradeLicenseReceiptDelivery097DigestAndStateStaticContract(t *testing.T) {
	up := strings.Join(strings.Fields(mustReadUpgradeLicenseReceipt097(t,
		"097_upgrade_license_receipt_delivery.up.sql")), " ")
	for _, fragment := range []string{
		"int4send(octet_length(convert_to(value,'UTF8'))) || convert_to(value,'UTF8')",
		"NEW.request_id IS DISTINCT FROM NEW.id",
		"NEW.receipt_sequence=1 AND NEW.status='fetched'",
		"NEW.receipt_sequence=2 AND NEW.status='verified'",
		"NEW.receipt_sequence=3 AND NEW.status IN ('applied','rejected')",
		"NEW.receipt_sequence=4 AND NEW.status='rolled_back'",
		"previous.state<>'delivered'",
		"OLD.state='pending' AND NEW.state='claimed'",
		"OLD.state='claimed' AND NEW.state IN ('pending','delivered','failed')",
		"CREATE CONSTRAINT TRIGGER control_upgrade_license_receipt_delivered_097",
		"JOIN control_upgrade_grant_intents_096 intent ON intent.plan_id=plan.id AND",
		"intent.candidate_plan_id=plan.id",
		"control_upgrade_rollout_events",
		"Completion'='upgraded'",
		"Completion'='rolled_back'",
		"transaction_timestamp()",
		"NEW.receipt_id='00000000-0000-0000-0000-000000000000'::uuid",
		"NEW.received_at<=to_timestamp(0)",
		"NEW.response_schema IS DISTINCT FROM 'upgrade-grant.receipt-response/v1'",
	} {
		if !strings.Contains(up, fragment) {
			t.Errorf("097 state contract missing %q", fragment)
		}
	}
}

func TestUpgradeLicenseReceiptDelivery097FreshRoundTripAndHeadGuards(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 96)
	if err := migrateVersionIsolated(t.Context(), pool, "up", 97); err != nil {
		t.Fatalf("fresh 1..97: %v", err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, 97)
	if err := migrateVersionIsolated(t.Context(), pool, "down", 97); err != nil {
		t.Fatalf("97 down: %v", err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, 96)
	if err := migrateVersionIsolated(t.Context(), pool, "up", 97); err != nil {
		t.Fatalf("96 -> 97 reapply: %v", err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, 97)

	t.Run("missing 096", func(t *testing.T) {
		candidate := packageCommerceRBAC079Pool(t, 95)
		_, err := candidate.Exec(t.Context(), mustReadUpgradeLicenseReceipt097(t,
			"097_upgrade_license_receipt_delivery.up.sql"))
		assertUpgradeLicenseReceipt097Code(t, err, "P9700")
	})
	t.Run("tampered 096", func(t *testing.T) {
		candidate := packageCommerceRBAC079Pool(t, 96)
		if _, err := candidate.Exec(t.Context(), `UPDATE schema_migrations
			SET checksum_sha256=repeat('a',64) WHERE version=96`); err != nil {
			t.Fatal(err)
		}
		_, err := candidate.Exec(t.Context(), mustReadUpgradeLicenseReceipt097(t,
			"097_upgrade_license_receipt_delivery.up.sql"))
		assertUpgradeLicenseReceipt097Code(t, err, "P9700")
	})
}

func TestUpgradeLicenseReceiptDelivery097DownRejectsDurableFacts(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 97)
	identity := seedUpgradeLicenseReceiptIdentity097(t, pool)
	planID := insertUpgradeRuntimePlan096(t, pool, identity, true)
	if _, err := pool.Exec(t.Context(), `ALTER TABLE control_upgrade_license_receipt_outbox_097
		DISABLE TRIGGER ALL`); err != nil {
		t.Fatal(err)
	}
	receiptID := uuid.New()
	observed := time.Now().UTC().Truncate(time.Second)
	if _, err := pool.Exec(t.Context(), `INSERT INTO control_upgrade_license_receipt_outbox_097(
		id,request_id,plan_id,installation_id,grant_id,request_schema,request_digest_schema,
		logical_digest,receipt_sequence,status,installed_version,error_code,observed_at,predecessor_id,
		state,available_at,attempt_count,created_at,updated_at)
		SELECT $1,$1,id,installation_id,parent_grant_id,'upgrade-grant.receipt-request/v2',2,
		control_upgrade_license_receipt_digest_097($1,installation_id,parent_grant_id,
		'fetched','1.0.0','',$2),1,'fetched','1.0.0',NULL,$2,NULL,'pending',$2,0,$2,$2
		FROM control_upgrade_rollout_plans WHERE id=$3`, receiptID, observed, planID); err != nil {
		t.Fatal(err)
	}
	assertUpgradeLicenseReceipt097Code(t,
		migrateVersionIsolated(t.Context(), pool, "down", 97), "P9701")
}

func TestUpgradeLicenseReceiptDelivery097BackfillsOnlyAuthoritativeHistoricalTerminals(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 96)
	identity := seedUpgradeLicenseReceiptIdentity097(t, pool)
	if _, err := pool.Exec(t.Context(), `ALTER TABLE control_upgrade_rollout_plans DISABLE TRIGGER ALL;
		ALTER TABLE control_upgrade_rollout_events DISABLE TRIGGER ALL;
		ALTER TABLE control_upgrade_grant_intents_096 DISABLE TRIGGER ALL`); err != nil {
		t.Fatal(err)
	}
	upgraded := seedUpgradeLicenseReceiptHistorical097(t, pool, identity, "upgraded")
	rejected := seedUpgradeLicenseReceiptHistorical097(t, pool, identity, "rejected")
	rolledBack := seedUpgradeLicenseReceiptHistorical097(t, pool, identity, "rolled_back")
	unresolved := seedUpgradeLicenseReceiptHistorical097(t, pool, identity, "unresolved")
	if _, err := pool.Exec(t.Context(), `ALTER TABLE control_upgrade_grant_intents_096 ENABLE TRIGGER ALL;
		ALTER TABLE control_upgrade_rollout_events ENABLE TRIGGER ALL;
		ALTER TABLE control_upgrade_rollout_plans ENABLE TRIGGER ALL`); err != nil {
		t.Fatal(err)
	}
	if err := migrateVersionIsolated(t.Context(), pool, "up", 97); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		plan uuid.UUID
		want []string
	}{
		{name: "upgraded", plan: upgraded, want: []string{"fetched", "verified", "applied"}},
		{name: "rejected", plan: rejected, want: []string{"fetched", "verified", "rejected"}},
		{name: "rolled back", plan: rolledBack, want: []string{"fetched", "verified", "applied", "rolled_back"}},
		{name: "unresolved", plan: unresolved, want: []string{"fetched", "verified"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			rows, err := pool.Query(t.Context(), `SELECT status,id,
				control_upgrade_license_receipt_id_097(plan_id,status)
				FROM control_upgrade_license_receipt_outbox_097 WHERE plan_id=$1
				ORDER BY receipt_sequence`, test.plan)
			if err != nil {
				t.Fatal(err)
			}
			defer rows.Close()
			got := make([]string, 0, len(test.want))
			for rows.Next() {
				var status string
				var actualID, deterministicID uuid.UUID
				if err := rows.Scan(&status, &actualID, &deterministicID); err != nil {
					t.Fatal(err)
				}
				if actualID != deterministicID {
					t.Errorf("%s id=%s, deterministic=%s", status, actualID, deterministicID)
				}
				got = append(got, status)
			}
			if err := rows.Err(); err != nil {
				t.Fatal(err)
			}
			if strings.Join(got, ",") != strings.Join(test.want, ",") {
				t.Fatalf("statuses = %v, want %v", got, test.want)
			}
		})
	}
	var rejectedCode string
	if err := pool.QueryRow(t.Context(), `SELECT error_code
		FROM control_upgrade_license_receipt_outbox_097 WHERE plan_id=$1 AND status='rejected'`,
		rejected).Scan(&rejectedCode); err != nil || rejectedCode != "preflight_failed" {
		t.Fatalf("rejected code = (%q,%v)", rejectedCode, err)
	}
}

func seedUpgradeLicenseReceiptIdentity097(t *testing.T, pool *pgxpool.Pool) upgradeRolloutIdentity093 {
	t.Helper()
	identity := upgradeRolloutIdentity093{scopeID: uuid.New(), userID: uuid.New(), installationID: uuid.New()}
	tenantID := uuid.New()
	if _, err := pool.Exec(t.Context(), `
		INSERT INTO tenants(id,display_name) VALUES($1,'Upgrade rollout tenant');
		INSERT INTO access_scopes(id,kind,tenant_id) VALUES($2,'tenant',$1);
		INSERT INTO users(id,username,display_name,password_hash) VALUES($3,$4,'Upgrade operator','test-only');
		INSERT INTO memberships(scope_id,user_id) VALUES($2,$3)`, pgx.QueryExecModeSimpleProtocol,
		tenantID, identity.scopeID, identity.userID,
		"upgrade-"+strings.ReplaceAll(identity.userID.String(), "-", "")); err != nil {
		t.Fatal(err)
	}
	return identity
}

func seedUpgradeLicenseReceiptHistorical097(t *testing.T, pool *pgxpool.Pool,
	identity upgradeRolloutIdentity093, outcome string) uuid.UUID {
	t.Helper()
	planID := insertUpgradeRuntimePlan096(t, pool, identity, true)
	var snapshot []byte
	if err := pool.QueryRow(t.Context(), `SELECT canonical_snapshot_bytes
		FROM control_upgrade_rollout_plans WHERE id=$1`, planID).Scan(&snapshot); err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(snapshot, &document); err != nil {
		t.Fatal(err)
	}
	baseTime := time.Now().UTC().Truncate(time.Second).Add(-10 * time.Second)
	if _, err := pool.Exec(t.Context(), `INSERT INTO control_upgrade_grant_intents_096(
		id,actor_scope_id,actor_user_id,installation_id,candidate_plan_id,plan_id,
		idempotency_key,request_digest,request_id,state,parent_grant_bytes,parent_grant_sha256,
		parent_grant_expires_at,artifact_bundle_id,artifact_bundle_bytes,artifact_bundle_sha256,
		command_issuance_not_after,forward_profile_bytes,forward_profile_sha256,
		rollback_profile_bytes,rollback_profile_sha256,created_at,updated_at)
		SELECT $1,actor_scope_id,actor_user_id,installation_id,id,id,$2,sha256(convert_to($2,'UTF8')),
		$3,'consumed',parent_grant_bytes,parent_grant_sha256,parent_grant_expires_at,
		artifact_bundle_id,artifact_bundle_bytes,artifact_bundle_sha256,command_issuance_not_after,
		forward_profile_bytes,forward_profile_sha256,rollback_profile_bytes,rollback_profile_sha256,$4,$4
		FROM control_upgrade_rollout_plans WHERE id=$5`, uuid.New(), "backfill-"+planID.String(),
		"request-"+planID.String(), baseTime, planID); err != nil {
		t.Fatal(err)
	}
	insertEvent := func(revision int, completion string, createdAt time.Time, errorCodes ...string) {
		document["State"], document["Completion"], document["Revision"] = "completed", completion, revision
		receipts := make([]any, 0, len(errorCodes))
		for _, errorCode := range errorCodes {
			receipts = append(receipts, map[string]any{
				"Health": map[string]any{"Code": errorCode, "Success": false},
			})
		}
		document["HealthReceipts"] = receipts
		encoded, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		eventID, causationID := uuid.New(), uuid.New()
		eventBytes, causeBytes := []byte(`{"ID":"`+eventID.String()+`"}`), []byte(`{"ID":"`+causationID.String()+`"}`)
		if _, err := pool.Exec(t.Context(), `INSERT INTO control_upgrade_rollout_events(
			plan_id,revision,event_id,actor_scope_id,actor_user_id,installation_id,causation_id,
			causation_bytes,causation_sha256,event_bytes,event_sha256,result_snapshot_bytes,
			result_snapshot_sha256,created_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,sha256($8),$9,sha256($9),$10,sha256($10),$11)`,
			planID, revision, eventID, identity.scopeID, identity.userID, identity.installationID,
			causationID, causeBytes, eventBytes, encoded, createdAt); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(t.Context(), `UPDATE control_upgrade_rollout_plans SET revision=$2,
			state='completed',completion=$3,canonical_snapshot_bytes=$4,
			canonical_snapshot_sha256=sha256($4),updated_at=$5 WHERE id=$1`, planID, revision,
			completion, encoded, createdAt); err != nil {
			t.Fatal(err)
		}
	}
	switch outcome {
	case "upgraded":
		insertEvent(2, "upgraded", baseTime.Add(time.Second))
	case "rejected":
		insertEvent(2, "rolled_back", baseTime.Add(time.Second), "INSUFFICIENT_DISK")
	case "rolled_back":
		insertEvent(2, "upgraded", baseTime.Add(time.Second))
		insertEvent(3, "rolled_back", baseTime.Add(2*time.Second))
	case "unresolved":
		insertEvent(2, "rolled_back", baseTime.Add(time.Second), "INSUFFICIENT_DISK", "INSTALLER_UNCERTAIN")
	default:
		t.Fatalf("unknown historical outcome %q", outcome)
	}
	return planID
}

func assertUpgradeLicenseReceipt097Code(t *testing.T, err error, code string) {
	t.Helper()
	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) || postgresError.Code != code {
		t.Fatalf("PostgreSQL error = %v, want SQLSTATE %s", err, code)
	}
}

func mustReadUpgradeLicenseReceipt097(t *testing.T, name string) string {
	t.Helper()
	encoded, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}
