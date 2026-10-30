//go:build integration

package migrations_test

import (
	"crypto/sha256"
	"encoding/base64"
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

func TestUpgradeRolloutPersistence093MigrationContract(t *testing.T) {
	up := mustReadUpgradeRollout093(t, "093_upgrade_rollout_persistence.up.sql")
	down := mustReadUpgradeRollout093(t, "093_upgrade_rollout_persistence.down.sql")
	for _, fragment := range []string{
		"migration 093 requires the exact verified 092 release head",
		"5b9d6ced167be563e6dfdbe022681b7ed6842728a831597389a3a4e9280d8c6d",
		"8cd70b1cf78f3ea668934b6db898a2c0d1a487bc4a85f05dd9585d4a66058bbc",
		"ERRCODE = 'P9300'",
		"CREATE TABLE control_upgrade_rollout_plans",
		"CREATE TABLE control_upgrade_rollout_events",
		"CREATE TABLE control_upgrade_node_commands",
		"CREATE TABLE control_upgrade_status_receipts",
		"CREATE TABLE control_upgrade_outbox",
		"causation_bytes bytea NOT NULL",
		"sha256(NEW.causation_bytes)",
		"CommandReceipts",
		"HealthReceipts",
		"signed_execution_bytes bytea NOT NULL",
		"signed_execution_sha256 bytea NOT NULL",
		"command_sha256 bytea NOT NULL",
		"payload_bytes bytea NOT NULL",
		"payload_sha256 bytea NOT NULL",
		"sha256(NEW.payload_bytes)",
		"new_snapshot_document - ARRAY",
		"encode(command.signed_execution_sha256,'hex')",
		"encode(command_payload_sha,'hex')",
		"CHECK (id = command_id)",
		"previous_state = 'accepted' AND NEW.state = 'claimed'",
		"previous_state = 'installing' AND NEW.state IN ('healthy','failed','rolling_back','uncertain')",
		"previous_state = 'uncertain'",
		"previous_installer_transaction_id",
		"FOR UPDATE",
		"ERRCODE = 'P9302'",
	} {
		if !strings.Contains(up, fragment) {
			t.Errorf("093 up missing %q", fragment)
		}
	}
	upDigest := sha256.Sum256([]byte(up))
	for _, fragment := range []string{
		"migration 093 rollback requires the verified 093 head",
		hex.EncodeToString(upDigest[:]),
		"migration 093 rollback would discard upgrade rollout facts",
		"ERRCODE = 'P9301'",
	} {
		if !strings.Contains(down, fragment) {
			t.Errorf("093 down missing %q", fragment)
		}
	}
}

func TestUpgradeRolloutPersistence093FreshRoundTrip(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 92)
	if err := migrateVersionIsolated(t.Context(), pool, "up", 93); err != nil {
		t.Fatalf("fresh 1..93: %v", err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, 93)
	if err := migrateVersionIsolated(t.Context(), pool, "down", 93); err != nil {
		t.Fatalf("93 down: %v", err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, 92)
	if err := migrateVersionIsolated(t.Context(), pool, "up", 93); err != nil {
		t.Fatalf("93 reapply: %v", err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, 93)
}

func TestUpgradeRolloutPersistence093RejectsWrongHead(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 92)
	if _, err := pool.Exec(t.Context(), `UPDATE schema_migrations
		SET down_checksum_sha256=repeat('a',64) WHERE version=92`); err != nil {
		t.Fatal(err)
	}
	up := mustReadUpgradeRollout093(t, "093_upgrade_rollout_persistence.up.sql")
	_, err := pool.Exec(t.Context(), up)
	assertUpgradeRolloutCode093(t, err, "P9300")
}

func TestUpgradeRolloutPersistence093DownRejectsFacts(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 93)
	identity := seedUpgradeRolloutIdentity093(t, pool)
	insertUpgradeRolloutPlan093(t, pool, identity, uuid.New(), 1, "queued")
	err := migrateVersionIsolated(t.Context(), pool, "down", 93)
	assertUpgradeRolloutCode093(t, err, "P9301")
}

func TestUpgradeRolloutPersistence093RejectsInvalidTupleStateAndBinding(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 93)
	identity := seedUpgradeRolloutIdentity093(t, pool)
	planID := uuid.New()
	_, err := pool.Exec(t.Context(), `INSERT INTO control_upgrade_rollout_plans(
		id,actor_scope_id,actor_user_id,installation_id,schema_version,revision,state,resume_state,
		completion,active_batch,canonical_snapshot_bytes,canonical_snapshot_sha256,created_at,updated_at)
		VALUES($1,$2,$3,$4,1,1,'not-a-state','', '',-1,convert_to('{}','UTF8'),
		sha256(convert_to('{}','UTF8')),now(),now())`,
		planID, identity.scopeID, identity.userID, identity.installationID)
	assertUpgradeRolloutCode093(t, err, "P9302")
	_, err = pool.Exec(t.Context(), `INSERT INTO control_upgrade_rollout_plans(
		id,actor_scope_id,actor_user_id,installation_id,schema_version,revision,state,resume_state,
		completion,active_batch,canonical_snapshot_bytes,canonical_snapshot_sha256,created_at,updated_at)
		VALUES($1,$2,$3,$4,1,1,'queued','','',-1,convert_to('{}','UTF8'),
		decode(repeat('11',32),'hex'),now(),now())`, uuid.New(), identity.scopeID, identity.userID,
		identity.installationID)
	assertUpgradeRolloutCode093(t, err, "P9302")

	insertUpgradeRolloutPlan093(t, pool, identity, planID, 1, "queued")
	_, err = pool.Exec(t.Context(), `INSERT INTO control_upgrade_rollout_events(
		plan_id,revision,event_id,actor_scope_id,actor_user_id,installation_id,
		causation_id,causation_bytes,causation_sha256,event_bytes,event_sha256,
		result_snapshot_bytes,result_snapshot_sha256,created_at)
		VALUES($1,3,$2,$3,$4,$5,$6,convert_to('{}','UTF8'),decode(repeat('12',32),'hex'),convert_to('{}','UTF8'),
		sha256(convert_to('{}','UTF8')),convert_to('{}','UTF8'),sha256(convert_to('{}','UTF8')),now())`,
		planID, uuid.New(), identity.scopeID, identity.userID, identity.installationID, uuid.New())
	assertUpgradeRolloutCode093(t, err, "P9302")

	commandPlanID := uuid.New()
	insertUpgradeRolloutPlan093(t, pool, identity, commandPlanID, 1, "queued")
	commandID, batchID, nodeID := seedUpgradeRolloutCommand093(t, pool, identity, commandPlanID)
	_, err = pool.Exec(t.Context(), `UPDATE control_upgrade_node_commands
		SET signed_execution_bytes=convert_to('tampered','UTF8') WHERE command_id=$1`, commandID)
	assertUpgradeRolloutCode093(t, err, "P9302")
	_, err = pool.Exec(t.Context(), `INSERT INTO control_upgrade_outbox(
		id,command_id,plan_id,plan_revision,batch_id,actor_scope_id,actor_user_id,installation_id,node_id,action,
		topic,message_key,payload_bytes,payload_sha256,state,available_at,attempt_count,created_at)
		VALUES($1,$2,$3,2,$4,$5,$6,$7,$8,'upgrade','edge.upgrade.commands.v1',$2::uuid::text,
		convert_to('{}','UTF8'),sha256(convert_to('{}','UTF8')),'pending',now(),0,now())`,
		uuid.New(), commandID, commandPlanID, batchID, identity.scopeID, identity.userID, identity.installationID, nodeID)
	assertUpgradeRolloutCode093(t, err, "P9302")
	_, err = pool.Exec(t.Context(), `INSERT INTO control_upgrade_status_receipts(
		command_id,status_revision,status_id,plan_id,plan_revision,batch_id,actor_scope_id,actor_user_id,
		installation_id,node_id,action,status_bytes,status_sha256,command_sha256,state,observed_at,created_at)
		VALUES($1,1,$2,$3,2,$4,$5,$6,$7,$8,'upgrade',convert_to('{}','UTF8'),
		sha256(convert_to('{}','UTF8')),sha256(convert_to('payload','UTF8')),'healthy',now(),now())`,
		commandID, uuid.New(), commandPlanID, batchID, identity.scopeID, identity.userID, identity.installationID, nodeID)
	assertUpgradeRolloutCode093(t, err, "P9302")
}

func TestUpgradeRolloutPersistence093RejectsStaticSnapshotRewriteBeforeHistoryCheck(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 93)
	identity := seedUpgradeRolloutIdentity093(t, pool)
	planID := uuid.New()
	insertUpgradeRolloutPlan093(t, pool, identity, planID, 1, "queued")
	snapshot := upgradeRolloutSnapshot093(t, planID, 2, "canary", 0, nil)
	var document map[string]any
	if err := json.Unmarshal(snapshot, &document); err != nil {
		t.Fatal(err)
	}
	document["Component"] = "edge-agent-rewritten"
	snapshot, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	_, err = tx.Exec(t.Context(), `UPDATE control_upgrade_rollout_plans
		SET revision=2,state='canary',active_batch=0,canonical_snapshot_bytes=$2,
			canonical_snapshot_sha256=sha256($2),updated_at=now() WHERE id=$1`, planID, snapshot)
	assertUpgradeRolloutCode093(t, err, "P9302")
}

func TestUpgradeRolloutPersistence093RejectsForgedReceiptCausation(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 93)
	identity := seedUpgradeRolloutIdentity093(t, pool)
	planID := uuid.New()
	insertUpgradeRolloutPlan093(t, pool, identity, planID, 1, "queued")
	causeID, forgedID := uuid.New(), uuid.New()
	cause := []byte(`{"ID":"` + causeID.String() + `","Action":"start","ExpectedRevision":1,"Reason":"start_requested"}`)
	forged := []byte(`{"ID":"` + forgedID.String() + `","Action":"start","ExpectedRevision":1,"Reason":"forged"}`)
	snapshot := []byte(`{"CommandReceipts":[{"Command":` + string(forged) + `,"Event":{"Revision":2}}],"HealthReceipts":[],"Revision":2}`)
	_, err := pool.Exec(t.Context(), `INSERT INTO control_upgrade_rollout_events(
		plan_id,revision,event_id,actor_scope_id,actor_user_id,installation_id,
		causation_id,causation_bytes,causation_sha256,event_bytes,event_sha256,
		result_snapshot_bytes,result_snapshot_sha256,created_at)
		VALUES($1,2,$2,$3,$4,$5,$6,$7,sha256($7),convert_to('{}','UTF8'),
		sha256(convert_to('{}','UTF8')),$8,sha256($8),now())`,
		planID, uuid.New(), identity.scopeID, identity.userID, identity.installationID, causeID, cause, snapshot)
	assertUpgradeRolloutCode093(t, err, "P9302")
}

func TestUpgradeRolloutPersistence093RejectsForgedReceiptEvent(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 93)
	identity := seedUpgradeRolloutIdentity093(t, pool)
	planID, eventID, causeID := uuid.New(), uuid.New(), uuid.New()
	insertUpgradeRolloutPlan093(t, pool, identity, planID, 1, "queued")
	cause := []byte(`{"ID":"` + causeID.String() + `","Action":"start","ExpectedRevision":1,"Reason":"start_requested"}`)
	expectedEvent := []byte(`{"ID":"` + eventID.String() + `","Revision":2,"From":"queued","To":"canary","Action":"start","Reason":"start_requested","BatchID":"","NodeID":""}`)
	forgedEvent := []byte(`{"ID":"` + eventID.String() + `","Revision":2,"From":"queued","To":"canary","Action":"forged","Reason":"forged","BatchID":"","NodeID":""}`)
	snapshot := []byte(`{"CommandReceipts":[{"Command":` + string(cause) + `,"Event":` + string(expectedEvent) +
		`}],"HealthReceipts":[],"Revision":2}`)
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	_, err = tx.Exec(t.Context(), `INSERT INTO control_upgrade_rollout_events(
		plan_id,revision,event_id,actor_scope_id,actor_user_id,installation_id,
		causation_id,causation_bytes,causation_sha256,event_bytes,event_sha256,
		result_snapshot_bytes,result_snapshot_sha256,created_at)
		VALUES($1,2,$2,$3,$4,$5,$6,$7,sha256($7),$8,sha256($8),$9,sha256($9),now())`,
		planID, eventID, identity.scopeID, identity.userID, identity.installationID,
		causeID, cause, forgedEvent, snapshot)
	if err == nil {
		_, err = tx.Exec(t.Context(), `UPDATE control_upgrade_rollout_plans
			SET revision=2,state='canary',active_batch=0,
				canonical_snapshot_bytes=$2,canonical_snapshot_sha256=sha256($2),updated_at=now()
			WHERE id=$1`, planID, snapshot)
	}
	if err == nil {
		err = tx.Commit(t.Context())
	}
	assertUpgradeRolloutCode093(t, err, "P9302")
}

func TestUpgradeRolloutPersistence093AcceptsAgentStatusGraphAndBindsReconciliation(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 93)
	identity := seedUpgradeRolloutIdentity093(t, pool)
	planID := uuid.New()
	insertUpgradeRolloutPlan093(t, pool, identity, planID, 1, "queued")
	commandID, batchID, nodeID := seedUpgradeRolloutCommand093(t, pool, identity, planID)
	publishedAt := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := pool.Exec(t.Context(), `UPDATE control_upgrade_outbox SET state='published',published_at=$2
		WHERE command_id=$1; UPDATE control_upgrade_node_commands SET state='published',published_at=$2
		WHERE command_id=$1`, pgx.QueryExecModeSimpleProtocol, commandID, publishedAt); err != nil {
		t.Fatal(err)
	}
	var commandDigest []byte
	if err := pool.QueryRow(t.Context(), `SELECT payload_sha256 FROM control_upgrade_outbox WHERE command_id=$1`,
		commandID).Scan(&commandDigest); err != nil {
		t.Fatal(err)
	}
	transactionID := "txn-migration-reconcile-1"
	legacy := upgradeRolloutStatusValue093(commandID, planID, identity.installationID, nodeID, commandDigest,
		1, "accepted", "", publishedAt.Add(time.Second))
	legacy.CommandSHA256 = base64.RawURLEncoding.EncodeToString(commandDigest)
	assertUpgradeRolloutCode093(t,
		insertUpgradeRolloutStatus093(t, pool, identity, planID, batchID, nodeID, legacy, commandDigest), "P9302")
	statuses := []upgradeRolloutStatus093{
		upgradeRolloutStatusValue093(commandID, planID, identity.installationID, nodeID, commandDigest,
			1, "accepted", "", publishedAt.Add(time.Second)),
		upgradeRolloutStatusValue093(commandID, planID, identity.installationID, nodeID, commandDigest,
			2, "claimed", "", publishedAt.Add(2*time.Second)),
		upgradeRolloutStatusValue093(commandID, planID, identity.installationID, nodeID, commandDigest,
			3, "installing", transactionID, publishedAt.Add(3*time.Second)),
		upgradeRolloutStatusValue093(commandID, planID, identity.installationID, nodeID, commandDigest,
			4, "uncertain", transactionID, publishedAt.Add(4*time.Second)),
	}
	for _, status := range statuses {
		if err := insertUpgradeRolloutStatus093(t, pool, identity, planID, batchID, nodeID, status, commandDigest); err != nil {
			t.Fatalf("insert status %s: %v", status.State, err)
		}
	}
	mismatched := upgradeRolloutStatusValue093(commandID, planID, identity.installationID, nodeID, commandDigest,
		5, "healthy", "txn-migration-reconcile-2", publishedAt.Add(5*time.Second))
	assertUpgradeRolloutCode093(t,
		insertUpgradeRolloutStatus093(t, pool, identity, planID, batchID, nodeID, mismatched, commandDigest), "P9302")
	reconciled := upgradeRolloutStatusValue093(commandID, planID, identity.installationID, nodeID, commandDigest,
		5, "rolled_back", transactionID, publishedAt.Add(5*time.Second))
	if err := insertUpgradeRolloutStatus093(t, pool, identity, planID, batchID, nodeID, reconciled, commandDigest); err != nil {
		t.Fatalf("insert reconciled status: %v", err)
	}
}

type upgradeRolloutStatus093 struct {
	Schema                 string    `json:"schema"`
	StatusID               uuid.UUID `json:"status_id"`
	StatusRevision         uint64    `json:"status_revision"`
	CommandID              uuid.UUID `json:"command_id"`
	PlanID                 uuid.UUID `json:"plan_id"`
	PlanRevision           uint64    `json:"plan_revision"`
	InstallationID         uuid.UUID `json:"installation_id"`
	NodeID                 uuid.UUID `json:"node_id"`
	CommandSHA256          string    `json:"command_sha256"`
	State                  string    `json:"state"`
	CurrentVersion         string    `json:"current_version"`
	PreviousVersion        string    `json:"previous_version"`
	InstallerTransactionID string    `json:"installer_transaction_id"`
	ErrorCode              string    `json:"error_code"`
	AlertRequired          bool      `json:"alert_required"`
	ObservedAt             time.Time `json:"observed_at"`
}

type upgradeRolloutIdentity093 struct {
	scopeID        uuid.UUID
	userID         uuid.UUID
	installationID uuid.UUID
}

func seedUpgradeRolloutIdentity093(t *testing.T, pool *pgxpool.Pool) upgradeRolloutIdentity093 {
	t.Helper()
	identity := upgradeRolloutIdentity093{scopeID: uuid.New(), userID: uuid.New(), installationID: uuid.New()}
	tenantID := uuid.New()
	// Several statements with arguments: only the simple protocol accepts them
	// (a parameterized extended-protocol Exec is one prepared statement, SQLSTATE 42601).
	if _, err := pool.Exec(t.Context(), `
		INSERT INTO tenants(id,display_name) VALUES($1,'Upgrade rollout tenant');
		INSERT INTO access_scopes(id,kind,tenant_id) VALUES($2,'tenant',$1);
		INSERT INTO users(id,username,display_name,password_hash) VALUES($3,$4,'Upgrade operator','test-only');
		INSERT INTO memberships(scope_id,user_id) VALUES($2,$3)`, pgx.QueryExecModeSimpleProtocol,
		tenantID, identity.scopeID, identity.userID, "upgrade-"+strings.ReplaceAll(identity.userID.String(), "-", "")); err != nil {
		t.Fatal(err)
	}
	return identity
}

func insertUpgradeRolloutPlan093(t *testing.T, pool *pgxpool.Pool, identity upgradeRolloutIdentity093,
	planID uuid.UUID, revision int64, state string) {
	t.Helper()
	snapshot := upgradeRolloutSnapshot093(t, planID, revision, state, -1, nil)
	if _, err := pool.Exec(t.Context(), `INSERT INTO control_upgrade_rollout_plans(
		id,actor_scope_id,actor_user_id,installation_id,schema_version,revision,state,resume_state,
		completion,active_batch,canonical_snapshot_bytes,canonical_snapshot_sha256,created_at,updated_at)
		VALUES($1,$2,$3,$4,1,$5,$6,'','',-1,$7,sha256($7),now(),now())`,
		planID, identity.scopeID, identity.userID, identity.installationID, revision, state, snapshot); err != nil {
		t.Fatal(err)
	}
}

func seedUpgradeRolloutCommand093(t *testing.T, pool *pgxpool.Pool, identity upgradeRolloutIdentity093,
	planID uuid.UUID) (uuid.UUID, uuid.UUID, uuid.UUID) {
	t.Helper()
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	eventID, causationID := uuid.New(), uuid.New()
	causationBytes := []byte(`{"ID":"` + causationID.String() + `","Action":"start","ExpectedRevision":1,"Reason":"start_requested"}`)
	eventBytes := []byte(`{"ID":"` + eventID.String() + `","Revision":2}`)
	commandReceipts := json.RawMessage(`[{"Command":` + string(causationBytes) +
		`,"Event":` + string(eventBytes) + `}]`)
	resultSnapshot := upgradeRolloutSnapshot093(t, planID, 2, "canary", 0, commandReceipts)
	if _, err := tx.Exec(t.Context(), `INSERT INTO control_upgrade_rollout_events(
			plan_id,revision,event_id,actor_scope_id,actor_user_id,installation_id,
			causation_id,causation_bytes,causation_sha256,event_bytes,event_sha256,
			result_snapshot_bytes,result_snapshot_sha256,created_at)
		VALUES($1,2,$2,$3,$4,$5,$6,$7,sha256($7),$8,
			sha256($8),$9,sha256($9),now())`,
		planID, eventID, identity.scopeID, identity.userID, identity.installationID,
		causationID, causationBytes, eventBytes, resultSnapshot); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `UPDATE control_upgrade_rollout_plans
		SET revision=2,state='canary',active_batch=0,
			canonical_snapshot_bytes=$2,canonical_snapshot_sha256=sha256($2),updated_at=now()
		WHERE id=$1`, planID, resultSnapshot); err != nil {
		t.Fatal(err)
	}
	commandID, batchID, nodeID := uuid.New(), uuid.New(), uuid.New()
	signedExecution := []byte("signed")
	signedExecutionDigest := sha256.Sum256(signedExecution)
	payload, err := json.Marshal(map[string]any{
		"schema": "cdnca.edge.upgrade.command/v1", "command_id": commandID,
		"plan_id": planID, "plan_revision": 2, "batch_id": batchID,
		"installation_id": identity.installationID, "node_id": nodeID, "action": "upgrade",
		"signed_execution": signedExecution, "signed_execution_sha256": hex.EncodeToString(signedExecutionDigest[:]),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO control_upgrade_node_commands(
		command_id,plan_id,plan_revision,batch_id,actor_scope_id,actor_user_id,installation_id,node_id,action,
		signed_execution_bytes,signed_execution_sha256,state,created_at)
		VALUES($1,$2,2,$3,$4,$5,$6,$7,'upgrade',$8,sha256($8),'pending',now())`, commandID, planID, batchID,
		identity.scopeID, identity.userID, identity.installationID, nodeID, signedExecution); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO control_upgrade_outbox(
		id,command_id,plan_id,plan_revision,batch_id,actor_scope_id,actor_user_id,installation_id,node_id,action,
		topic,message_key,payload_bytes,payload_sha256,state,available_at,attempt_count,created_at)
		VALUES($1,$1,$2,2,$3,$4,$5,$6,$7,'upgrade','edge.upgrade.commands.v1',$1::uuid::text,
		$8,sha256($8),'pending',now(),0,now())`,
		commandID, planID, batchID, identity.scopeID, identity.userID, identity.installationID, nodeID, payload); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	return commandID, batchID, nodeID
}

func upgradeRolloutStatusValue093(commandID, planID, installationID, nodeID uuid.UUID,
	commandDigest []byte, revision uint64, state, installerTransactionID string,
	observedAt time.Time) upgradeRolloutStatus093 {
	status := upgradeRolloutStatus093{
		Schema: "cdnca.edge.upgrade.status/v1", StatusID: uuid.New(), StatusRevision: revision,
		CommandID: commandID, PlanID: planID, PlanRevision: 2, InstallationID: installationID,
		NodeID: nodeID, CommandSHA256: hex.EncodeToString(commandDigest), State: state,
		CurrentVersion: "2.0.0", PreviousVersion: "1.0.0",
		InstallerTransactionID: installerTransactionID, ObservedAt: observedAt.UTC().Truncate(time.Microsecond),
	}
	if state == "uncertain" {
		status.ErrorCode = "INSTALLER_OUTCOME_UNKNOWN"
		status.AlertRequired = true
	}
	return status
}

func upgradeRolloutSnapshot093(t *testing.T, planID uuid.UUID, revision int64, state string,
	activeBatch int, commandReceipts json.RawMessage) []byte {
	t.Helper()
	if commandReceipts == nil {
		commandReceipts = json.RawMessage(`[]`)
	}
	document := map[string]any{
		"SchemaVersion": 1, "ID": planID.String(),
		"GrantDigest": "grant-v1", "ReleaseSequence": 7,
		"Component": "edge-agent", "ArtifactID": "artifact-v1", "SHA256Digest": "artifact-sha-v1",
		"RollbackGrantDigest": "rollback-grant-v1", "RollbackReleaseSequence": 8,
		"RollbackArtifactID": "rollback-artifact-v1", "RollbackSHA256Digest": "rollback-sha-v1",
		"CurrentVersion": "1.0.0", "TargetVersion": "2.0.0", "AutomaticRollback": true,
		"Safety": map[string]any{"RollbackAvailable": true},
		"State":  state, "ResumeState": "", "Completion": "", "Revision": revision,
		"ActiveBatch": activeBatch, "Batches": []any{}, "RollbackBatches": []any{},
		"Targets": map[string]any{}, "NodeStates": map[string]any{}, "NodeDispatchRevisions": map[string]any{},
		"Blockers": []any{}, "CommandReceipts": commandReceipts, "HealthReceipts": []any{},
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func insertUpgradeRolloutStatus093(t *testing.T, pool *pgxpool.Pool, identity upgradeRolloutIdentity093,
	planID, batchID, nodeID uuid.UUID, status upgradeRolloutStatus093, commandDigest []byte) error {
	t.Helper()
	encoded, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	_, err = pool.Exec(t.Context(), `INSERT INTO control_upgrade_status_receipts(
		command_id,status_revision,status_id,plan_id,plan_revision,batch_id,actor_scope_id,actor_user_id,
		installation_id,node_id,action,status_bytes,status_sha256,command_sha256,state,observed_at,created_at)
		VALUES($1,$2,$3,$4,2,$5,$6,$7,$8,$9,'upgrade',$10,sha256($10),$11,$12,$13,now())`,
		status.CommandID, status.StatusRevision, status.StatusID, planID, batchID,
		identity.scopeID, identity.userID, identity.installationID, nodeID, encoded, commandDigest,
		status.State, status.ObservedAt)
	return err
}

func mustReadUpgradeRollout093(t *testing.T, name string) string {
	t.Helper()
	value, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(value)
}

func assertUpgradeRolloutCode093(t *testing.T, err error, code string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != code {
		t.Fatalf("error = %v, want SQLSTATE %s", err, code)
	}
}
