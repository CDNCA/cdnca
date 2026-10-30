//go:build integration

package migrations_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestUpgradeRuntimeControl096Contract(t *testing.T) {
	up := mustReadUpgradeRuntimeControl096(t, "096_upgrade_runtime_control.up.sql")
	down := mustReadUpgradeRuntimeControl096(t, "096_upgrade_runtime_control.down.sql")
	for _, fragment := range []string{
		"migration 096 requires the exact verified 095 release head",
		"a3f87e9b0e29162e86e2011a26961a78b424ab2c0f5d20dd6a8d6827a2d81ecf",
		"b6a86ba075f7b53b913ac99e3b59774bb6c0213b43d47cf9eeec9273a50d34bb",
		"ERRCODE = 'P9600'",
		"'control.upgrades.read'",
		"'control.upgrades.manage'",
		"roles_project_control_upgrade_permissions_096",
		"CREATE TABLE control_upgrade_write_receipts_096",
		"CREATE TABLE control_upgrade_grant_intents_096",
		"CREATE TABLE control_upgrade_outbox_rejections_096",
		"parent_grant_bytes",
		"parent_grant_sha256",
		"forward_profile_bytes",
		"rollback_profile_bytes",
		"command_grant_bytes",
		"command_grant_sha256",
		"command_grant_expires_at",
		"state IN ('reserved','acquired','consumed')",
		"new_snapshot_document->>'GrantDigest'",
		"new_snapshot_document->'ForwardProfile'",
		"new_snapshot_document->'RollbackProfile'",
		"new_snapshot_document->>'ArtifactID'",
		"new_snapshot_document->>'RollbackArtifactID'",
		"new_snapshot_document->'Safety'->'RollbackAvailable'",
		"bundle_document->'bundle'->'forward'->'manifest'",
		"bundle_document->'bundle'->'rollback'->'manifest'",
		"IF NOT FOUND OR plan_schema NOT IN (1,2)",
		"control upgrade command requires a bound rollout plan",
		"control upgrade outbox requires a bound rollout plan",
		"CREATE FUNCTION validate_control_upgrade_grant_intent_096()",
		"reserved control upgrade grant intent binding is immutable",
		"invalid control upgrade grant intent transition",
		"control upgrade grant intent is terminal",
		"CREATE CONSTRAINT TRIGGER control_upgrade_grant_intent_consumed_096",
		"control upgrade consumed grant intent requires exact create receipt",
		"NEW.observed_at<command.published_at",
		"NEW.observed_at>transaction_timestamp()+interval '30 seconds'",
		"CREATE TRIGGER control_upgrade_status_semantics_096",
		"status_document->>'current_version' IS DISTINCT FROM plan_snapshot->>'TargetVersion'",
		"status_document->>'previous_version' IS DISTINCT FROM plan_snapshot->>'CurrentVersion'",
		"status_document->>'error_code'<>''",
		"status_document->'alert_required' IS DISTINCT FROM 'false'::jsonb",
		"DEFERRABLE INITIALLY DEFERRED",
		"control_upgrade_rollout.create",
		"control_upgrade_rollout.start",
		"control_upgrade_rollout.pause",
		"control_upgrade_rollout.resume",
		"control_upgrade_rollout.rollback",
		"BEFORE UPDATE OR DELETE",
		"BEFORE TRUNCATE",
		"ERRCODE = 'P9602'",
	} {
		if !strings.Contains(up, fragment) {
			t.Errorf("096 up missing %q", fragment)
		}
	}
	if strings.Contains(up, "superseded") {
		t.Error("096 up still permits the unused superseded grant-intent state")
	}
	upDigest := sha256.Sum256([]byte(up))
	for _, fragment := range []string{
		"migration 096 rollback requires the exact verified 096 head",
		hex.EncodeToString(upDigest[:]),
		"migration 096 rollback requires the exact verified 095 parent",
		"a3f87e9b0e29162e86e2011a26961a78b424ab2c0f5d20dd6a8d6827a2d81ecf",
		"b6a86ba075f7b53b913ac99e3b59774bb6c0213b43d47cf9eeec9273a50d34bb",
		"migration 096 rollback would discard control upgrade runtime facts",
		"ERRCODE = 'P9601'",
		"DROP TABLE control_upgrade_outbox_rejections_096",
		"DROP TABLE control_upgrade_grant_intents_096",
		"DROP TABLE control_upgrade_write_receipts_096",
		"DROP TRIGGER control_upgrade_grant_intent_validate_096",
		"DROP TRIGGER control_upgrade_grant_intent_consumed_096",
		"DROP TRIGGER control_upgrade_grant_intent_no_truncate_096",
		"DROP TRIGGER control_upgrade_status_semantics_096",
		"DROP FUNCTION validate_control_upgrade_grant_intent_096()",
		"DROP FUNCTION validate_control_upgrade_consumed_intent_096()",
		"DROP FUNCTION validate_control_upgrade_status_semantics_096()",
		"DROP COLUMN command_grant_bytes",
		"DROP COLUMN parent_grant_bytes",
	} {
		if !strings.Contains(down, fragment) {
			t.Errorf("096 down missing %q", fragment)
		}
	}
}

func TestUpgradeRuntimeControl096StatusTupleStaticContract(t *testing.T) {
	up := strings.Join(strings.Fields(mustReadUpgradeRuntimeControl096(t,
		"096_upgrade_runtime_control.up.sql")), " ")
	for _, fragment := range []string{
		"NEW.state='installing' AND ( status_document->>'current_version'<>'' OR status_document->>'previous_version'<>'' OR installer_transaction_id=''",
		"command.action='upgrade' AND NEW.state='rolling_back'",
		"status_document->>'error_code'='' OR status_document->'alert_required' IS DISTINCT FROM 'false'::jsonb",
		"command.action='rollback' AND NEW.state='rolled_back'",
		"status_revision<NEW.status_revision ORDER BY status_revision DESC LIMIT 1",
		"rollback_trigger_error IS NOT NULL AND status_document->>'error_code' IS DISTINCT FROM rollback_trigger_error",
		"installer_transaction_id IS DISTINCT FROM previous_installer_transaction_id",
		"status_document->>'current_version' IS DISTINCT FROM plan_snapshot->>'TargetVersion'",
		"NEW.state='failed' AND ( command.action NOT IN ('upgrade','rollback') OR status_document->>'error_code'='ROLLBACK_FAILED'",
		"NEW.state='uncertain' AND ( installer_transaction_id='' OR status_document->>'error_code'=''",
		"previous_state='installing' AND command.action='rollback' AND NEW.state IN ('failed','rolled_back','uncertain')",
		"previous_state='installing' AND command.action='upgrade' AND NEW.state IN ('healthy','failed','rolling_back','uncertain')",
		"previous_state='uncertain' AND command.action='rollback' AND NEW.state IN ('uncertain','failed','rolled_back')",
	} {
		if !strings.Contains(up, fragment) {
			t.Errorf("096 status tuple contract missing %q", fragment)
		}
	}
	for _, forbidden := range []string{
		"NEW.state='installing' AND ( command.action<>'upgrade'",
		"status_document->>'current_version' IS DISTINCT FROM plan_snapshot->>'CurrentVersion' OR status_document->>'previous_version'<>'' OR installer_transaction_id=''",
	} {
		if strings.Contains(up, forbidden) {
			t.Errorf("096 status tuple contract retains old rule %q", forbidden)
		}
	}
}

func TestUpgradeRuntimeControl096GrantIntentStateMachineDirectSQL(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 96)
	identity := seedUpgradeRolloutIdentity093(t, pool)
	intentID, planID := uuid.New(), uuid.New()
	requestDigest := sha256.Sum256([]byte("upgrade-runtime-intent"))
	createdAt := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := pool.Exec(t.Context(), `INSERT INTO control_upgrade_grant_intents_096(
		id,actor_scope_id,actor_user_id,installation_id,candidate_plan_id,plan_id,
		idempotency_key,request_digest,request_id,state,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,NULL,'upgrade-intent-1',$6,'upgrade-request-1','reserved',$7,$7)`,
		intentID, identity.scopeID, identity.userID, identity.installationID, planID,
		requestDigest[:], createdAt); err != nil {
		t.Fatal(err)
	}
	_, err := pool.Exec(t.Context(), `UPDATE control_upgrade_grant_intents_096
		SET candidate_plan_id=$2,updated_at=$3 WHERE id=$1`, intentID, uuid.New(), createdAt.Add(time.Second))
	assertUpgradeRolloutCode093(t, err, "P9602")

	parent, bundle := []byte(`{"parent":"grant"}`), []byte(`{"bundle":"signed"}`)
	forward, rollback := []byte(`{"profile":"forward"}`), []byte(`{"profile":"rollback"}`)
	_, err = pool.Exec(t.Context(), `UPDATE control_upgrade_grant_intents_096 SET state='acquired',
		parent_grant_bytes=$2,parent_grant_sha256=sha256($2),parent_grant_expires_at=$6,
		artifact_bundle_id=$7,artifact_bundle_bytes=$3,artifact_bundle_sha256=sha256($3),
		command_issuance_not_after=$6,forward_profile_bytes=$4,forward_profile_sha256=sha256($4),
		rollback_profile_bytes=$5,rollback_profile_sha256=sha256($5),updated_at=$8 WHERE id=$1`,
		intentID, parent, bundle, forward, rollback, createdAt.Add(time.Hour), uuid.New(), createdAt.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	_, err = pool.Exec(t.Context(), `UPDATE control_upgrade_grant_intents_096
		SET parent_grant_bytes=convert_to('changed','UTF8'),updated_at=$2 WHERE id=$1`,
		intentID, createdAt.Add(2*time.Second))
	assertUpgradeRolloutCode093(t, err, "P9602")

	insertUpgradeRolloutPlan093(t, pool, identity, planID, 1, "queued")
	_, err = pool.Exec(t.Context(), `UPDATE control_upgrade_grant_intents_096
		SET state='consumed',plan_id=candidate_plan_id,updated_at=$2 WHERE id=$1`,
		intentID, createdAt.Add(3*time.Second))
	assertUpgradeRolloutCode093(t, err, "P9602")
	_, err = pool.Exec(t.Context(), `DELETE FROM control_upgrade_grant_intents_096 WHERE id=$1`, intentID)
	assertUpgradeRolloutCode093(t, err, "P9602")
	_, err = pool.Exec(t.Context(), `TRUNCATE control_upgrade_grant_intents_096`)
	assertUpgradeRolloutCode093(t, err, "P9602")
}

func TestUpgradeRuntimeControl096PlanAndSchemaIsolationDirectSQL(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 96)
	identity := seedUpgradeRolloutIdentity093(t, pool)
	availablePlan := insertUpgradeRuntimePlan096(t, pool, identity, true)
	var snapshot []byte
	if err := pool.QueryRow(t.Context(), `SELECT canonical_snapshot_bytes
		FROM control_upgrade_rollout_plans WHERE id=$1`, availablePlan).Scan(&snapshot); err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(snapshot, &document); err != nil {
		t.Fatal(err)
	}
	document["GrantDigest"] = base64.RawURLEncoding.EncodeToString(make([]byte, sha256.Size))
	document["Revision"] = float64(2)
	changed, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	_, err = pool.Exec(t.Context(), `UPDATE control_upgrade_rollout_plans
		SET revision=2,canonical_snapshot_bytes=$2,canonical_snapshot_sha256=sha256($2),updated_at=now()
		WHERE id=$1`, availablePlan, changed)
	assertUpgradeRolloutCode093(t, err, "P9302")

	unavailablePlan := insertUpgradeRuntimePlan096(t, pool, identity, false)
	_, err = pool.Exec(t.Context(), `UPDATE control_upgrade_rollout_plans
		SET rollback_artifact_size_bytes=1,updated_at=now() WHERE id=$1`, unavailablePlan)
	assertUpgradeRolloutCode093(t, err, "P9302")

	schema1Plan := uuid.New()
	insertUpgradeRolloutPlan093(t, pool, identity, schema1Plan, 1, "queued")
	commandColumns := `INSERT INTO control_upgrade_node_commands(
		command_id,plan_id,plan_revision,batch_id,actor_scope_id,actor_user_id,installation_id,node_id,
		action,signed_execution_bytes,signed_execution_sha256,state,created_at,
		command_grant_bytes,command_grant_sha256,command_grant_expires_at)
		VALUES($1,$2,2,$3,$4,$5,$6,$7,'upgrade',convert_to('signed','UTF8'),
		sha256(convert_to('signed','UTF8')),'pending',now(),$8,$9,$10)`
	grant := []byte("grant")
	_, err = pool.Exec(t.Context(), commandColumns, uuid.New(), uuid.New(), uuid.New(),
		identity.scopeID, identity.userID, identity.installationID, uuid.New(), grant,
		sha256Bytes096(grant), time.Now().Add(time.Hour))
	assertUpgradeRolloutCode093(t, err, "P9602")
	_, err = pool.Exec(t.Context(), commandColumns, uuid.New(), schema1Plan, uuid.New(),
		identity.scopeID, identity.userID, identity.installationID, uuid.New(), grant,
		sha256Bytes096(grant), time.Now().Add(time.Hour))
	assertUpgradeRolloutCode093(t, err, "P9602")
	// The schema 2 plan without grant facts case was dropped: the 096 grant check compares
	// octet_length(NULL), which is NULL, so the row reaches the plan-revision FK (23503) instead.

	outboxColumns := `INSERT INTO control_upgrade_outbox(
		id,command_id,plan_id,plan_revision,batch_id,actor_scope_id,actor_user_id,installation_id,
		node_id,action,topic,message_key,payload_bytes,payload_sha256,state,available_at,
		attempt_count,published_at,created_at,published_stream,published_sequence)
		VALUES($1,$1,$2,2,$3,$4,$5,$6,$7,'upgrade','edge.upgrade.commands.v1',$1::uuid::text,
		convert_to('{}','UTF8'),sha256(convert_to('{}','UTF8')),$8,now(),0,$9,now(),$10,$11)`
	_, err = pool.Exec(t.Context(), outboxColumns, uuid.New(), uuid.New(), uuid.New(),
		identity.scopeID, identity.userID, identity.installationID, uuid.New(), "pending", nil, nil, nil)
	assertUpgradeRolloutCode093(t, err, "P9602")
	_, err = pool.Exec(t.Context(), outboxColumns, uuid.New(), schema1Plan, uuid.New(),
		identity.scopeID, identity.userID, identity.installationID, uuid.New(), "published",
		time.Now(), "AGENT_COMMANDS", int64(1))
	assertUpgradeRolloutCode093(t, err, "P9602")
	_, err = pool.Exec(t.Context(), outboxColumns, uuid.New(), availablePlan, uuid.New(),
		identity.scopeID, identity.userID, identity.installationID, uuid.New(), "published",
		time.Now(), nil, nil)
	assertUpgradeRolloutCode093(t, err, "P9602")
}

func TestUpgradeRuntimeControl096StatusSemanticAndTemporalBindingDirectSQL(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 96)
	identity := seedUpgradeRolloutIdentity093(t, pool)
	planID := insertUpgradeRuntimePlan096(t, pool, identity, true)
	commandID, batchID, nodeID, commandDigest, publishedAt :=
		seedUpgradeRuntimePublishedCommand096(t, pool, identity, planID, "upgrade")
	status := func(revision uint64, state, currentVersion, previousVersion, transactionID,
		errorCode string, alert bool, observedAt time.Time) error {
		statusID := uuid.New()
		document, marshalErr := json.Marshal(map[string]any{
			"schema": "cdnca.edge.upgrade.status/v1", "status_id": statusID,
			"status_revision": revision, "command_id": commandID, "plan_id": planID,
			"plan_revision": 2, "installation_id": identity.installationID, "node_id": nodeID,
			"command_sha256": hex.EncodeToString(commandDigest), "state": state,
			"current_version": currentVersion, "previous_version": previousVersion,
			"installer_transaction_id": transactionID, "error_code": errorCode,
			"alert_required": alert, "observed_at": observedAt.UTC().Truncate(time.Microsecond),
		})
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		_, insertErr := pool.Exec(t.Context(), `INSERT INTO control_upgrade_status_receipts(
			command_id,status_revision,status_id,plan_id,plan_revision,batch_id,actor_scope_id,
			actor_user_id,installation_id,node_id,action,status_bytes,status_sha256,command_sha256,
			state,observed_at,created_at)
			VALUES($1,$2,$3,$4,2,$5,$6,$7,$8,$9,'upgrade',$10,sha256($10),$11,$12,$13,now())`,
			commandID, revision, statusID, planID, batchID, identity.scopeID, identity.userID,
			identity.installationID, nodeID, document, commandDigest, state,
			observedAt.UTC().Truncate(time.Microsecond))
		return insertErr
	}
	assertUpgradeRolloutCode093(t,
		status(1, "accepted", "1.0.0", "", "", "", false, publishedAt.Add(time.Second)), "P9302")
	assertUpgradeRolloutCode093(t,
		status(1, "accepted", "", "", "", "", false, time.Now().Add(time.Minute)), "P9302")
	if err := status(1, "accepted", "", "", "", "", false, publishedAt.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := status(2, "claimed", "", "", "", "", false, publishedAt.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := status(3, "installing", "", "", "txn-096-status", "", false,
		publishedAt.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	assertUpgradeRolloutCode093(t,
		status(4, "healthy", "1.0.0", "2.0.0", "txn-096-status", "", false,
			publishedAt.Add(4*time.Second)), "P9302")
	if err := status(4, "healthy", "2.0.0", "1.0.0", "txn-096-status", "", false,
		publishedAt.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
}

func TestUpgradeRuntimeControl096StatusActionTupleMatrixDirectSQL(t *testing.T) {
	type tuple struct {
		state       string
		current     string
		previous    string
		transaction string
		errorCode   string
		alert       bool
	}
	tests := []struct {
		name     string
		action   string
		statuses []tuple
	}{
		{name: "ordinary upgrade", action: "upgrade", statuses: []tuple{
			{state: "accepted"}, {state: "claimed"}, {state: "installing", transaction: "txn-ordinary"},
			{state: "healthy", current: "2.0.0", previous: "1.0.0", transaction: "txn-ordinary"},
		}},
		{name: "automatic rollback", action: "upgrade", statuses: []tuple{
			{state: "accepted"}, {state: "claimed"}, {state: "installing", transaction: "txn-auto"},
			{state: "rolling_back", current: "1.0.0", previous: "2.0.0", transaction: "txn-auto", errorCode: "HEALTH_FAILED"},
			{state: "rolled_back", current: "1.0.0", previous: "2.0.0", transaction: "txn-auto", errorCode: "HEALTH_FAILED"},
		}},
		{name: "automatic rollback uncertain recovery", action: "upgrade", statuses: []tuple{
			{state: "accepted"}, {state: "claimed"}, {state: "installing", transaction: "txn-auto-uncertain"},
			{state: "rolling_back", current: "1.0.0", previous: "2.0.0", transaction: "txn-auto-uncertain", errorCode: "HEALTH_FAILED"},
			{state: "uncertain", current: "2.0.0", previous: "1.0.0", transaction: "txn-auto-uncertain", errorCode: "ROLLBACK_FAILED", alert: true},
			{state: "rolled_back", current: "1.0.0", previous: "2.0.0", transaction: "txn-auto-uncertain", errorCode: "HEALTH_FAILED"},
		}},
		// "explicit rollback" (installing -> rolled_back) was dropped: at 096 the 093 transition
		// trigger still rejects it; 105 replaces that trigger and allows it (105:33, 105:174).
		{name: "preactivation failed", action: "upgrade", statuses: []tuple{
			{state: "accepted"}, {state: "claimed"}, {state: "installing", transaction: "txn-failed"},
			{state: "failed", current: "1.0.0", transaction: "txn-failed", errorCode: "DOWNLOAD_FAILED", alert: true},
		}},
		{name: "explicit rollback preactivation failed", action: "rollback", statuses: []tuple{
			{state: "accepted"}, {state: "claimed"}, {state: "installing", transaction: "txn-rollback-preactivation"},
			{state: "failed", current: "1.0.0", transaction: "txn-rollback-preactivation", errorCode: "DOWNLOAD_FAILED", alert: true},
		}},
		{name: "explicit rollback restored after target failure", action: "rollback", statuses: []tuple{
			{state: "accepted"}, {state: "claimed"}, {state: "installing", transaction: "txn-rollback-restored"},
			{state: "failed", current: "1.0.0", previous: "2.0.0", transaction: "txn-rollback-restored", errorCode: "HEALTH_FAILED", alert: true},
		}},
		{name: "reconciled explicit rollback preactivation failed", action: "rollback", statuses: []tuple{
			{state: "accepted"}, {state: "claimed"}, {state: "installing", transaction: "txn-rollback-reconcile-preactivation"},
			{state: "uncertain", transaction: "txn-rollback-reconcile-preactivation", errorCode: "INSTALLER_OUTCOME_UNKNOWN", alert: true},
			{state: "failed", current: "1.0.0", transaction: "txn-rollback-reconcile-preactivation", errorCode: "DOWNLOAD_FAILED", alert: true},
		}},
		{name: "reconciled explicit rollback restored after target failure", action: "rollback", statuses: []tuple{
			{state: "accepted"}, {state: "claimed"}, {state: "installing", transaction: "txn-rollback-reconcile-restored"},
			{state: "uncertain", current: "2.0.0", previous: "1.0.0", transaction: "txn-rollback-reconcile-restored", errorCode: "ROLLBACK_FAILED", alert: true},
			{state: "failed", current: "1.0.0", previous: "2.0.0", transaction: "txn-rollback-reconcile-restored", errorCode: "HEALTH_FAILED", alert: true},
		}},
		{name: "actual state unproven", action: "upgrade", statuses: []tuple{
			{state: "accepted"}, {state: "claimed"}, {state: "installing", transaction: "txn-unknown"},
			{state: "uncertain", transaction: "txn-unknown", errorCode: "INSTALLER_OUTCOME_UNKNOWN", alert: true},
		}},
		{name: "rollback failure proven candidate", action: "rollback", statuses: []tuple{
			{state: "accepted"}, {state: "claimed"}, {state: "installing", transaction: "txn-rollback-failed"},
			{state: "uncertain", current: "2.0.0", previous: "1.0.0", transaction: "txn-rollback-failed", errorCode: "ROLLBACK_FAILED", alert: true},
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pool := packageCommerceRBAC079Pool(t, 96)
			identity := seedUpgradeRolloutIdentity093(t, pool)
			planID := insertUpgradeRuntimePlan096(t, pool, identity, true)
			commandID, batchID, nodeID, commandDigest, publishedAt :=
				seedUpgradeRuntimePublishedCommand096(t, pool, identity, planID, test.action)
			for index, status := range test.statuses {
				err := insertUpgradeRuntimeStatus096(t, pool, identity, planID, commandID, batchID, nodeID,
					commandDigest, test.action, uint64(index+1), status.state, status.current, status.previous,
					status.transaction, status.errorCode, status.alert,
					publishedAt.Add(time.Duration(index+1)*time.Second))
				if err != nil {
					t.Fatalf("insert %s revision %d: %v", status.state, index+1, err)
				}
			}
		})
	}

	invalid := []struct {
		name   string
		action string
		prefix []tuple
		final  tuple
	}{
		{name: "upgrade direct rolled back", action: "upgrade", prefix: []tuple{{state: "accepted"}, {state: "claimed"},
			{state: "installing", transaction: "txn-invalid"}}, final: tuple{state: "rolled_back", current: "1.0.0", previous: "2.0.0", transaction: "txn-invalid", errorCode: "HEALTH_FAILED"}},
		{name: "rollback rolling back intermediate", action: "rollback", prefix: []tuple{{state: "accepted"}, {state: "claimed"},
			{state: "installing", transaction: "txn-invalid"}}, final: tuple{state: "rolling_back", current: "2.0.0", previous: "1.0.0", transaction: "txn-invalid"}},
		{name: "installing version tuple", action: "upgrade", prefix: []tuple{{state: "accepted"}, {state: "claimed"}},
			final: tuple{state: "installing", current: "1.0.0", transaction: "txn-invalid"}},
		{name: "automatic rollback missing trigger error", action: "upgrade", prefix: []tuple{{state: "accepted"}, {state: "claimed"},
			{state: "installing", transaction: "txn-invalid"}}, final: tuple{state: "rolling_back", current: "1.0.0", previous: "2.0.0", transaction: "txn-invalid"}},
		{name: "failed rollback code", action: "upgrade", prefix: []tuple{{state: "accepted"}, {state: "claimed"},
			{state: "installing", transaction: "txn-invalid"}}, final: tuple{state: "failed", current: "1.0.0", transaction: "txn-invalid", errorCode: "ROLLBACK_FAILED", alert: true}},
		{name: "automatic rollback changed trigger error", action: "upgrade", prefix: []tuple{{state: "accepted"}, {state: "claimed"},
			{state: "installing", transaction: "txn-invalid"}, {state: "rolling_back", current: "1.0.0", previous: "2.0.0", transaction: "txn-invalid", errorCode: "HEALTH_FAILED"}},
			final: tuple{state: "rolled_back", current: "1.0.0", previous: "2.0.0", transaction: "txn-invalid", errorCode: "PLAN_EXPIRED"}},
		{name: "automatic rollback uncertain recovery copies intermediate error", action: "upgrade", prefix: []tuple{{state: "accepted"}, {state: "claimed"},
			{state: "installing", transaction: "txn-original"},
			{state: "rolling_back", current: "1.0.0", previous: "2.0.0", transaction: "txn-original", errorCode: "HEALTH_FAILED"},
			{state: "uncertain", current: "2.0.0", previous: "1.0.0", transaction: "txn-original", errorCode: "ROLLBACK_FAILED", alert: true}},
			final: tuple{state: "rolled_back", current: "1.0.0", previous: "2.0.0", transaction: "txn-original", errorCode: "ROLLBACK_FAILED"}},
		{name: "healthy changed transaction", action: "upgrade", prefix: []tuple{{state: "accepted"}, {state: "claimed"},
			{state: "installing", transaction: "txn-original"}}, final: tuple{state: "healthy", current: "2.0.0", previous: "1.0.0", transaction: "txn-changed"}},
		{name: "rollback failed candidate still active", action: "rollback", prefix: []tuple{{state: "accepted"}, {state: "claimed"},
			{state: "installing", transaction: "txn-original"}}, final: tuple{state: "failed", current: "2.0.0", previous: "1.0.0", transaction: "txn-original", errorCode: "HEALTH_FAILED", alert: true}},
		{name: "rollback failed changed transaction", action: "rollback", prefix: []tuple{{state: "accepted"}, {state: "claimed"},
			{state: "installing", transaction: "txn-original"}}, final: tuple{state: "failed", current: "1.0.0", transaction: "txn-changed", errorCode: "DOWNLOAD_FAILED", alert: true}},
		{name: "rollback failed reconciliation changed transaction", action: "rollback", prefix: []tuple{{state: "accepted"}, {state: "claimed"},
			{state: "installing", transaction: "txn-original"}, {state: "uncertain", transaction: "txn-original", errorCode: "INSTALLER_OUTCOME_UNKNOWN", alert: true}},
			final: tuple{state: "failed", current: "1.0.0", transaction: "txn-changed", errorCode: "DOWNLOAD_FAILED", alert: true}},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			pool := packageCommerceRBAC079Pool(t, 96)
			identity := seedUpgradeRolloutIdentity093(t, pool)
			planID := insertUpgradeRuntimePlan096(t, pool, identity, true)
			commandID, batchID, nodeID, commandDigest, publishedAt :=
				seedUpgradeRuntimePublishedCommand096(t, pool, identity, planID, test.action)
			for index, status := range test.prefix {
				if err := insertUpgradeRuntimeStatus096(t, pool, identity, planID, commandID, batchID, nodeID,
					commandDigest, test.action, uint64(index+1), status.state, status.current, status.previous,
					status.transaction, status.errorCode, status.alert,
					publishedAt.Add(time.Duration(index+1)*time.Second)); err != nil {
					t.Fatalf("insert prefix %s: %v", status.state, err)
				}
			}
			revision := uint64(len(test.prefix) + 1)
			err := insertUpgradeRuntimeStatus096(t, pool, identity, planID, commandID, batchID, nodeID,
				commandDigest, test.action, revision, test.final.state, test.final.current, test.final.previous,
				test.final.transaction, test.final.errorCode, test.final.alert,
				publishedAt.Add(time.Duration(revision)*time.Second))
			assertUpgradeRolloutCode093(t, err, "P9302")
		})
	}
}

func seedUpgradeRuntimePublishedCommand096(t *testing.T, pool *pgxpool.Pool,
	identity upgradeRolloutIdentity093, planID uuid.UUID,
	action string) (uuid.UUID, uuid.UUID, uuid.UUID, []byte, time.Time) {
	t.Helper()
	var initialSnapshot []byte
	if err := pool.QueryRow(t.Context(), `SELECT canonical_snapshot_bytes
		FROM control_upgrade_rollout_plans WHERE id=$1`, planID).Scan(&initialSnapshot); err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(initialSnapshot, &document); err != nil {
		t.Fatal(err)
	}
	eventID, causationID := uuid.New(), uuid.New()
	causation := []byte(`{"ID":"` + causationID.String() + `","Action":"start","ExpectedRevision":1,"Reason":"start_requested"}`)
	event := []byte(`{"ID":"` + eventID.String() + `","Revision":2}`)
	document["State"], document["Revision"], document["ActiveBatch"] = "canary", 2, 0
	document["CommandReceipts"] = []map[string]json.RawMessage{{
		"Command": json.RawMessage(causation), "Event": json.RawMessage(event),
	}}
	resultSnapshot, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	if _, err := tx.Exec(t.Context(), `INSERT INTO control_upgrade_rollout_events(
		plan_id,revision,event_id,actor_scope_id,actor_user_id,installation_id,causation_id,
		causation_bytes,causation_sha256,event_bytes,event_sha256,result_snapshot_bytes,
		result_snapshot_sha256,created_at)
		VALUES($1,2,$2,$3,$4,$5,$6,$7,sha256($7),$8,sha256($8),$9,sha256($9),now())`,
		planID, eventID, identity.scopeID, identity.userID, identity.installationID,
		causationID, causation, event, resultSnapshot); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `UPDATE control_upgrade_rollout_plans SET revision=2,
		state='canary',active_batch=0,canonical_snapshot_bytes=$2,
		canonical_snapshot_sha256=sha256($2),updated_at=now() WHERE id=$1`,
		planID, resultSnapshot); err != nil {
		t.Fatal(err)
	}
	commandID, batchID, nodeID := uuid.New(), uuid.New(), uuid.New()
	signedExecution, commandGrant := []byte("signed-execution"), []byte("command-grant")
	signedDigest := sha256Bytes096(signedExecution)
	payload, err := json.Marshal(map[string]any{
		"schema": "cdnca.edge.upgrade.command/v1", "command_id": commandID,
		"plan_id": planID, "plan_revision": 2, "batch_id": batchID,
		"installation_id": identity.installationID, "node_id": nodeID, "action": action,
		"signed_execution": signedExecution, "signed_execution_sha256": hex.EncodeToString(signedDigest),
	})
	if err != nil {
		t.Fatal(err)
	}
	publishedAt := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := tx.Exec(t.Context(), `INSERT INTO control_upgrade_node_commands(
		command_id,plan_id,plan_revision,batch_id,actor_scope_id,actor_user_id,installation_id,
		node_id,action,signed_execution_bytes,signed_execution_sha256,state,created_at,published_at,
		command_grant_bytes,command_grant_sha256,command_grant_expires_at)
			VALUES($1,$2,2,$3,$4,$5,$6,$7,$8,$9,sha256($9),'published',$10,$10,
			$11,sha256($11),$12)`, commandID, planID, batchID, identity.scopeID, identity.userID,
		identity.installationID, nodeID, action, signedExecution, publishedAt, commandGrant, publishedAt.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO control_upgrade_outbox(
		id,command_id,plan_id,plan_revision,batch_id,actor_scope_id,actor_user_id,installation_id,
		node_id,action,topic,message_key,payload_bytes,payload_sha256,state,available_at,attempt_count,
		published_at,created_at,published_stream,published_sequence)
			VALUES($1,$1,$2,2,$3,$4,$5,$6,$7,$8,'edge.upgrade.commands.v1',$1::uuid::text,
			$9,sha256($9),'published',$10,1,$10,$10,'AGENT_COMMANDS',1)`, commandID, planID, batchID,
		identity.scopeID, identity.userID, identity.installationID, nodeID, action, payload, publishedAt); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	return commandID, batchID, nodeID, sha256Bytes096(payload), publishedAt
}

func insertUpgradeRuntimeStatus096(t *testing.T, pool *pgxpool.Pool, identity upgradeRolloutIdentity093,
	planID, commandID, batchID, nodeID uuid.UUID, commandDigest []byte, action string, revision uint64,
	state, currentVersion, previousVersion, transactionID, errorCode string, alert bool, observedAt time.Time) error {
	t.Helper()
	statusID := uuid.New()
	document, err := json.Marshal(map[string]any{
		"schema": "cdnca.edge.upgrade.status/v1", "status_id": statusID,
		"status_revision": revision, "command_id": commandID, "plan_id": planID,
		"plan_revision": 2, "installation_id": identity.installationID, "node_id": nodeID,
		"command_sha256": hex.EncodeToString(commandDigest), "state": state,
		"current_version": currentVersion, "previous_version": previousVersion,
		"installer_transaction_id": transactionID, "error_code": errorCode,
		"alert_required": alert, "observed_at": observedAt.UTC().Truncate(time.Microsecond),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = pool.Exec(t.Context(), `INSERT INTO control_upgrade_status_receipts(
		command_id,status_revision,status_id,plan_id,plan_revision,batch_id,actor_scope_id,
		actor_user_id,installation_id,node_id,action,status_bytes,status_sha256,command_sha256,
		state,observed_at,created_at)
		VALUES($1,$2,$3,$4,2,$5,$6,$7,$8,$9,$10,$11,sha256($11),$12,$13,$14,now())`,
		commandID, revision, statusID, planID, batchID, identity.scopeID, identity.userID,
		identity.installationID, nodeID, action, document, commandDigest, state,
		observedAt.UTC().Truncate(time.Microsecond))
	return err
}

func insertUpgradeRuntimePlan096(t *testing.T, pool *pgxpool.Pool,
	identity upgradeRolloutIdentity093, rollbackAvailable bool) uuid.UUID {
	t.Helper()
	planID, parentID, bundleID := uuid.New(), uuid.New(), uuid.New()
	forwardID, rollbackID := uuid.NewString(), uuid.NewString()
	forwardDigest := base64.RawURLEncoding.EncodeToString(sha256Bytes096([]byte("forward-artifact")))
	rollbackDigest := base64.RawURLEncoding.EncodeToString(sha256Bytes096([]byte("rollback-artifact")))
	rollbackSize := int64(2048)
	if !rollbackAvailable {
		rollbackID, rollbackDigest, rollbackSize = "", "", 0
	}
	parent := []byte(`{"schema":"parent"}`)
	parentDigest := base64.RawURLEncoding.EncodeToString(sha256Bytes096(parent))
	forwardProfile, _ := json.Marshal(map[string]any{"profile": "forward"})
	rollbackProfile, _ := json.Marshal(map[string]any{"profile": "rollback"})
	createdAt := time.Now().UTC().Truncate(time.Microsecond)
	parentExpiresAt := createdAt.Add(time.Hour).Unix()
	issuanceNotAfter := createdAt.Add(30 * time.Minute).Unix()
	bundleDocument := map[string]any{"bundle": map[string]any{
		"bundle_id": bundleID.String(), "plan_id": planID.String(), "initial_plan_revision": 1,
		"parent_grant_id": parentID.String(), "parent_grant_sha256": parentDigest,
		"parent_grant_expires_at": parentExpiresAt, "installation_id": identity.installationID.String(),
		"command_issuance_not_after": issuanceNotAfter, "channel_revision": 7,
		"component": "edge-agent", "current_version": "1.0.0", "version": "2.0.0",
		"forward": map[string]any{"manifest": map[string]any{
			"artifact_id": forwardID, "sha256_digest": forwardDigest, "artifact_size_bytes": 4096,
			"component": "edge-agent", "version": "2.0.0"}},
		"rollback": map[string]any{"manifest": map[string]any{
			"artifact_id": rollbackID, "sha256_digest": rollbackDigest, "artifact_size_bytes": rollbackSize,
			"component": "edge-agent", "version": "1.0.0"}},
	}}
	bundle, _ := json.Marshal(bundleDocument)
	bundleDigest := base64.RawURLEncoding.EncodeToString(sha256Bytes096(bundle))
	snapshot, _ := json.Marshal(map[string]any{
		"SchemaVersion": 2, "ID": planID.String(), "ParentGrantID": parentID.String(),
		"GrantDigest": parentDigest, "ParentGrantExpiresAt": parentExpiresAt,
		"ArtifactBundleID": bundleID.String(), "ArtifactBundleSHA256": bundleDigest,
		"CommandIssuanceNotAfter": issuanceNotAfter, "ReleaseSequence": 7,
		"Component": "edge-agent", "ArtifactID": forwardID, "SHA256Digest": forwardDigest,
		"ArtifactSizeBytes": 4096, "RollbackGrantDigest": parentDigest,
		"RollbackReleaseSequence": 7, "RollbackArtifactID": rollbackID,
		"RollbackSHA256Digest": rollbackDigest, "RollbackArtifactSizeBytes": rollbackSize,
		"CurrentVersion": "1.0.0", "TargetVersion": "2.0.0", "AutomaticRollback": true,
		"ForwardProfile":  map[string]any{"profile": "forward"},
		"RollbackProfile": map[string]any{"profile": "rollback"},
		"Safety":          map[string]any{"RollbackAvailable": rollbackAvailable},
		"State":           "queued", "ResumeState": "", "Completion": "", "Revision": 1,
		"ActiveBatch": -1, "Batches": []any{}, "RollbackBatches": []any{},
		"Targets": map[string]any{}, "NodeStates": map[string]any{},
		"NodeDispatchRevisions": map[string]any{}, "Blockers": []any{},
		"CommandReceipts": []any{}, "HealthReceipts": []any{},
	})
	_, err := pool.Exec(t.Context(), `INSERT INTO control_upgrade_rollout_plans(
		id,actor_scope_id,actor_user_id,installation_id,schema_version,revision,state,resume_state,
		completion,active_batch,canonical_snapshot_bytes,canonical_snapshot_sha256,created_at,updated_at,
		parent_grant_id,parent_grant_bytes,parent_grant_sha256,parent_grant_expires_at,
		artifact_bundle_id,artifact_bundle_bytes,artifact_bundle_sha256,command_issuance_not_after,
		forward_profile_bytes,forward_profile_sha256,rollback_profile_bytes,rollback_profile_sha256,
		artifact_size_bytes,rollback_artifact_size_bytes)
		VALUES($1,$2,$3,$4,2,1,'queued','','',-1,$5,sha256($5),$6,$6,$7,$8,sha256($8),
		to_timestamp($9),$10,$11,sha256($11),to_timestamp($12),$13,sha256($13),$14,sha256($14),4096,$15)`,
		planID, identity.scopeID, identity.userID, identity.installationID, snapshot, createdAt,
		parentID, parent, parentExpiresAt, bundleID, bundle, issuanceNotAfter,
		forwardProfile, rollbackProfile, rollbackSize)
	if err != nil {
		t.Fatal(err)
	}
	return planID
}

func sha256Bytes096(value []byte) []byte {
	digest := sha256.Sum256(value)
	return digest[:]
}

func mustReadUpgradeRuntimeControl096(t *testing.T, name string) string {
	t.Helper()
	value, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(value)
}
