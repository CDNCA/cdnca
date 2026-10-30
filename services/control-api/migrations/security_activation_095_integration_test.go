//go:build integration

package migrations_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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

func TestSecurityActivation095MigrationContract(t *testing.T) {
	up := mustReadSecurityActivation095(t, "095_security_activation.up.sql")
	down := mustReadSecurityActivation095(t, "095_security_activation.down.sql")
	for _, fragment := range []string{
		"migration 095 requires the exact verified 094 release head",
		"68da50b82c6597f264d66a3ca366f8738652ae608ddf04edccc6b4a191bfebc8",
		"45539ad704fd82aaea1eaa9cb6d540a6f3c875f28a0ae3b158bc8a9c9c52de80",
		"ERRCODE = 'P9500'",
		"CREATE TABLE security_policy_activation_recovery_pending_095",
		"CREATE TABLE security_policy_activation_recovery_proofs_095",
		"LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE",
		"security_policy_activation_candidates",
		"security_policy_activation_recovery_rollouts",
		"edge_command_outbox",
		"deployment_status_events",
		"node_config_state",
		"UNIQUE (candidate_id, node_id, generation)",
		"UNIQUE (rollout_id, node_id, deployment_attempt)",
		"UNIQUE (deployment_id, deployment_attempt)",
		"candidate_target_snapshot_sha256",
		"recovery_target_snapshot_sha256",
		"BEFORE UPDATE OR DELETE",
		"BEFORE TRUNCATE",
		"security_policy_activation_recovered_095",
		"cdnca.security-activation-recovery-targets/v1",
		"record_security_policy_activation_recovery_pending_095",
		"record_security_policy_activation_recovery_proofs_095",
		"CREATE OR REPLACE FUNCTION validate_security_policy_activation_recovery_rollout_088()",
		"pending.generation=(",
		"deployment.attempt=(",
		"CREATE OR REPLACE FUNCTION enforce_edge_outbox_state_046()",
		"OLD.status IN ('pending', 'failed') AND NEW.status = 'cancelled'",
		"candidate.recovered_at IS NOT NULL",
		"IS DISTINCT FROM NEW.recovery_config_version_id",
		") IS NOT TRUE",
		"CREATE OR REPLACE FUNCTION assert_rollout_contract_046()",
		"DEFERRABLE INITIALLY DEFERRED",
		"REVOKE ALL ON TABLE security_policy_activation_recovery_pending_095 FROM PUBLIC",
		"REVOKE ALL ON TABLE security_policy_activation_recovery_proofs_095 FROM PUBLIC",
		"ERRCODE = 'P9502'",
	} {
		if !strings.Contains(up, fragment) {
			t.Errorf("095 up missing %q", fragment)
		}
	}
	upDigest := sha256.Sum256([]byte(up))
	for _, fragment := range []string{
		"migration 095 rollback requires the exact verified 095 head",
		hex.EncodeToString(upDigest[:]),
		"migration 095 rollback requires the exact verified 094 parent",
		"68da50b82c6597f264d66a3ca366f8738652ae608ddf04edccc6b4a191bfebc8",
		"45539ad704fd82aaea1eaa9cb6d540a6f3c875f28a0ae3b158bc8a9c9c52de80",
		"migration 095 rollback would discard security activation recovery facts",
		"ERRCODE = 'P9501'",
		"DROP TABLE security_policy_activation_recovery_proofs_095",
		"DROP TABLE security_policy_activation_recovery_pending_095",
		"CREATE OR REPLACE FUNCTION assert_rollout_contract_046()",
		"security_policy_activation_recovered_088",
		"CREATE OR REPLACE FUNCTION validate_security_policy_activation_recovery_rollout_088()",
	} {
		if !strings.Contains(down, fragment) {
			t.Errorf("095 down missing %q", fragment)
		}
	}
	originalValidator := securityActivation095SQLFunction(t,
		mustReadSecurityActivation095(t, "088_security_policy_activation.up.sql"),
		"CREATE FUNCTION validate_security_policy_activation_recovery_rollout_088()")
	restoredValidator := securityActivation095SQLFunction(t, down,
		"CREATE OR REPLACE FUNCTION validate_security_policy_activation_recovery_rollout_088()")
	restoredValidator = strings.Replace(restoredValidator, "CREATE OR REPLACE FUNCTION", "CREATE FUNCTION", 1)
	if restoredValidator != originalValidator {
		t.Error("095 down does not restore the exact 088 recovery-rollout validator")
	}
	originalOutboxValidator := securityActivation095SQLFunction(t,
		mustReadSecurityActivation095(t, "046_edge_publication_contract.up.sql"),
		"CREATE FUNCTION enforce_edge_outbox_state_046()")
	restoredOutboxValidator := securityActivation095SQLFunction(t, down,
		"CREATE OR REPLACE FUNCTION enforce_edge_outbox_state_046()")
	restoredOutboxValidator = strings.Replace(restoredOutboxValidator,
		"CREATE OR REPLACE FUNCTION", "CREATE FUNCTION", 1)
	if restoredOutboxValidator != originalOutboxValidator {
		t.Error("095 down does not restore the exact 046 outbox-state validator")
	}
}

func TestSecurityActivation095AttemptTwoAndDeliverability(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 94)
	scenario := seedSecurityRecoveryScenario088(t, pool)
	seedSecurityActivation095Outboxes(t, pool, scenario.fixture.candidateID)
	if err := migrateVersionIsolated(t.Context(), pool, "up", 95); err != nil {
		t.Fatal(err)
	}

	var recovered bool
	if err := pool.QueryRow(t.Context(), `SELECT security_policy_activation_recovered_095($1)`,
		scenario.fixture.candidateID).Scan(&recovered); err != nil {
		t.Fatal(err)
	}
	if recovered {
		t.Fatal("pending apply outbox was treated as recovered")
	}

	if _, err := pool.Exec(t.Context(), `UPDATE edge_command_outbox outbox SET status='publishing'
		FROM node_deployments deployment WHERE deployment.id=outbox.deployment_id
		 AND deployment.attempt=outbox.deployment_attempt AND deployment.rollout_id=$1`,
		scenario.activationRolloutID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(t.Context(), `SELECT security_policy_activation_recovered_095($1)`,
		scenario.fixture.candidateID).Scan(&recovered); err != nil || recovered {
		t.Fatalf("publishing apply outbox recovered=%t err=%v", recovered, err)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE edge_command_outbox outbox SET status='failed'
		FROM node_deployments deployment WHERE deployment.id=outbox.deployment_id
		 AND deployment.attempt=outbox.deployment_attempt AND deployment.rollout_id=$1`,
		scenario.activationRolloutID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(t.Context(), `SELECT security_policy_activation_recovered_095($1)`,
		scenario.fixture.candidateID).Scan(&recovered); err != nil || recovered {
		t.Fatalf("failed apply outbox recovered=%t err=%v", recovered, err)
	}

	if _, err := pool.Exec(t.Context(), `UPDATE edge_command_outbox outbox SET status='publishing'
		FROM node_deployments deployment WHERE deployment.id=outbox.deployment_id
		 AND deployment.attempt=outbox.deployment_attempt AND deployment.rollout_id=$1`,
		scenario.activationRolloutID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE edge_command_outbox outbox
		SET status='published',published_at=clock_timestamp()
		FROM node_deployments deployment WHERE deployment.id=outbox.deployment_id
		 AND deployment.attempt=outbox.deployment_attempt AND deployment.rollout_id=$1`,
		scenario.activationRolloutID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(t.Context(), `SELECT security_policy_activation_recovered_095($1)`,
		scenario.fixture.candidateID).Scan(&recovered); err != nil || !recovered {
		t.Fatalf("terminal published apply recovered=%t err=%v", recovered, err)
	}

	if _, err := pool.Exec(t.Context(), `ALTER TABLE node_deployments DISABLE TRIGGER node_deployments_state_046;
		ALTER TABLE node_deployments DISABLE TRIGGER node_deployments_fact_046`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `ALTER TABLE node_deployments ENABLE TRIGGER node_deployments_fact_046;
			ALTER TABLE node_deployments ENABLE TRIGGER node_deployments_state_046`)
	})
	if _, err := pool.Exec(t.Context(), `UPDATE node_deployments SET state='queued' WHERE rollout_id=$1`,
		scenario.activationRolloutID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `ALTER TABLE node_deployments ENABLE TRIGGER node_deployments_fact_046;
		ALTER TABLE node_deployments ENABLE TRIGGER node_deployments_state_046`); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(t.Context(), `SELECT security_policy_activation_recovered_095($1)`,
		scenario.fixture.candidateID).Scan(&recovered); err != nil || recovered {
		t.Fatalf("active apply deployment recovered=%t err=%v", recovered, err)
	}

	if _, err := pool.Exec(t.Context(), `ALTER TABLE node_deployments DISABLE TRIGGER node_deployments_state_046;
		ALTER TABLE node_deployments DISABLE TRIGGER node_deployments_fact_046`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `ALTER TABLE node_deployments ENABLE TRIGGER node_deployments_fact_046;
			ALTER TABLE node_deployments ENABLE TRIGGER node_deployments_state_046`)
	})
	if _, err := pool.Exec(t.Context(), `UPDATE node_deployments SET state='failed' WHERE rollout_id=$1`,
		scenario.activationRolloutID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `ALTER TABLE node_deployments ENABLE TRIGGER node_deployments_state_046`); err != nil {
		t.Fatal(err)
	}
	var deploymentID uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT id FROM node_deployments WHERE rollout_id=$1 AND attempt=1`,
		scenario.activationRolloutID).Scan(&deploymentID); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	command := []byte("095 activation retry " + deploymentID.String())
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `INSERT INTO node_deployments(id,rollout_id,node_id,attempt,
			config_version_id,previous_config_version_id,action,state,command_event_id,command_bytes,
			command_sha256,deadline_at,created_at,updated_at)
			SELECT id,rollout_id,node_id,2,config_version_id,previous_config_version_id,action,'queued',$2,$3,$4,
			deadline_at,$5,$5 FROM node_deployments WHERE id=$1 AND attempt=1`, deploymentID, uuid.New(),
			command, sha256Bytes087(command), now); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO node_deployment_artifacts(deployment_id,
			deployment_attempt,config_version_id,artifact_id,ordinal)
			SELECT deployment_id,2,config_version_id,artifact_id,ordinal FROM node_deployment_artifacts
			WHERE deployment_id=$1 AND deployment_attempt=1`, deploymentID); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO edge_command_outbox(id,deployment_id,deployment_attempt,
			node_id,subject,payload,payload_sha256,status,available_at,created_at,updated_at)
			SELECT gen_random_uuid(),id,attempt,node_id,'cdnca.agent.commands.'||node_id::text,
			command_bytes,command_sha256,'pending',$2,$2,$2 FROM node_deployments WHERE id=$1 AND attempt=2`,
			deploymentID, now)
		return err
	})
	if err != nil {
		t.Fatalf("append legitimate activation attempt 2: %v", err)
	}
	var pending, latestAttempt, latestGeneration int
	if err := pool.QueryRow(t.Context(), `SELECT count(*),max(deployment_attempt),max(generation)
		FROM security_policy_activation_recovery_pending_095 WHERE candidate_id=$1 AND action='apply'`,
		scenario.fixture.candidateID).Scan(&pending, &latestAttempt, &latestGeneration); err != nil {
		t.Fatal(err)
	}
	if pending != 2 || latestAttempt != 2 || latestGeneration != 2 {
		t.Fatalf("attempt pending/count/latest/generation=%d/%d/%d, want 2/2/2",
			pending, latestAttempt, latestGeneration)
	}
	if err := pool.QueryRow(t.Context(), `SELECT security_policy_activation_recovered_095($1)`,
		scenario.fixture.candidateID).Scan(&recovered); err != nil || recovered {
		t.Fatalf("latest queued retry recovered=%t err=%v", recovered, err)
	}
}

func TestSecurityActivation095RejectsNullRecoveryProofIdentity(t *testing.T) {
	pool, scenario := seedQueuedSecurityRecovery095(t, true)
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		return insertQueuedSecurityRecovery095(t, tx, scenario, queuedSecurityRecovery095Options{})
	}); err != nil {
		t.Fatal(err)
	}
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `ALTER TABLE deployment_status_events
			DISABLE TRIGGER deployment_status_security_activation_proof_095;
			ALTER TABLE node_config_state DISABLE TRIGGER node_config_state_security_activation_proof_095`); err != nil {
			return err
		}
		var pending struct {
			rolloutID, deploymentID, nodeID, outboxID uuid.UUID
			attempt, generation                       int
		}
		if err := tx.QueryRow(t.Context(), `SELECT rollout_id,deployment_id,node_id,outbox_id,
			deployment_attempt,generation FROM security_policy_activation_recovery_pending_095
			WHERE candidate_id=$1 AND action='rollback'`, scenario.fixture.candidateID).Scan(
			&pending.rolloutID, &pending.deploymentID, &pending.nodeID, &pending.outboxID,
			&pending.attempt, &pending.generation); err != nil {
			return err
		}
		var eventID uuid.UUID
		var receivedAt time.Time
		for index, state := range []string{"delivered", "staged", "prechecked", "reverting", "reverted"} {
			eventID = uuid.New()
			receivedAt = time.Now().UTC().Truncate(time.Microsecond).Add(time.Duration(index) * time.Microsecond)
			payload := []byte("095 null recovery proof " + state)
			if _, err := tx.Exec(t.Context(), `INSERT INTO deployment_status_events(id,deployment_id,event_id,
				attempt,transition_sequence,state,payload,payload_sha256,occurred_at,received_at)
				VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$9)`, eventID, pending.deploymentID, uuid.New(),
				pending.attempt, index+1, state, payload, sha256Bytes087(payload), receivedAt); err != nil {
				return err
			}
			if _, err := tx.Exec(t.Context(), `UPDATE node_deployments SET state=$2,updated_at=$3
				WHERE id=$1 AND attempt=$4`, pending.deploymentID, state, receivedAt, pending.attempt); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(t.Context(), `UPDATE node_config_state SET
			current_config_version_id=NULL,current_config_identity_schema=NULL,
			current_config_artifact_sha256=NULL,updated_at=$2 WHERE node_id=$1`,
			pending.nodeID, receivedAt); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO security_policy_activation_recovery_proofs_095(
			candidate_id,tenant_scope_id,rollout_id,deployment_id,deployment_attempt,node_id,generation,
			action,candidate_config_version_id,candidate_artifact_sha256,recovery_config_version_id,
			recovery_artifact_sha256,candidate_target_snapshot_sha256,recovery_target_snapshot_sha256,
			outbox_id,status_event_id,transition_sequence,proved_at)
			SELECT candidate_id,tenant_scope_id,rollout_id,deployment_id,deployment_attempt,node_id,generation,
			action,candidate_config_version_id,candidate_artifact_sha256,recovery_config_version_id,
			recovery_artifact_sha256,candidate_target_snapshot_sha256,recovery_target_snapshot_sha256,
			outbox_id,$2,5,$3 FROM security_policy_activation_recovery_pending_095
			WHERE candidate_id=$1 AND action='rollback'`, scenario.fixture.candidateID, eventID, receivedAt)
		return err
	}); err == nil {
		t.Fatal("NULL recovery proof identity was accepted")
	} else {
		assertSecurityActivation095Code(t, err, "P9502")
	}
}

func TestSecurityActivation095RejectsRetryAfterRecovery(t *testing.T) {
	t.Run("apply retry", func(t *testing.T) {
		pool, scenario := seedQueuedSecurityRecovery095(t, false)
		publishSecurityActivation095Outbox(t, pool, scenario.activationRolloutID)
		var deploymentID uuid.UUID
		if err := pool.QueryRow(t.Context(), `SELECT id FROM node_deployments
			WHERE rollout_id=$1 AND attempt=1`, scenario.activationRolloutID).Scan(&deploymentID); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(t.Context(), `ALTER TABLE node_deployments
			DISABLE TRIGGER node_deployments_state_046`); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(t.Context(), `UPDATE node_deployments SET state='failed',updated_at=clock_timestamp()
			WHERE id=$1 AND attempt=1`, deploymentID); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(t.Context(), `ALTER TABLE node_deployments
			ENABLE TRIGGER node_deployments_state_046`); err != nil {
			t.Fatal(err)
		}
		markSecurityActivation095Recovered(t, pool, scenario.fixture.candidateID)
		assertSecurityActivation095RecoveredRetryRejected(t, pool, scenario.fixture.candidateID,
			scenario.activationRolloutID, deploymentID, "apply")
	})

	t.Run("older rollback retry", func(t *testing.T) {
		pool, scenario := seedQueuedSecurityRecovery095(t, true)
		if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
			return insertQueuedSecurityRecovery095(t, tx, scenario, queuedSecurityRecovery095Options{})
		}); err != nil {
			t.Fatal(err)
		}
		var rolloutID, deploymentID uuid.UUID
		if err := pool.QueryRow(t.Context(), `SELECT rollout_id,deployment_id
			FROM security_policy_activation_recovery_pending_095
			WHERE candidate_id=$1 AND action='rollback'`, scenario.fixture.candidateID).
			Scan(&rolloutID, &deploymentID); err != nil {
			t.Fatal(err)
		}
		publishSecurityActivation095Outbox(t, pool, scenario.activationRolloutID)
		publishSecurityActivation095Outbox(t, pool, rolloutID)
		if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
			for index, state := range []string{"delivered", "failed"} {
				at := time.Now().UTC().Truncate(time.Microsecond).Add(time.Duration(index) * time.Microsecond)
				payload := []byte("095 recovered rollback " + state)
				if _, err := tx.Exec(t.Context(), `INSERT INTO deployment_status_events(id,deployment_id,
					event_id,attempt,transition_sequence,state,payload,payload_sha256,occurred_at,received_at)
					VALUES($1,$2,$3,1,$4,$5,$6,$7,$8,$8)`, uuid.New(), deploymentID, uuid.New(),
					index+1, state, payload, sha256Bytes087(payload), at); err != nil {
					return err
				}
				if _, err := tx.Exec(t.Context(), `UPDATE node_deployments SET state=$2,updated_at=$3
					WHERE id=$1 AND attempt=1`, deploymentID, state, at); err != nil {
					return err
				}
			}
			_, err := tx.Exec(t.Context(), `UPDATE node_config_state SET
				previous_config_version_id=NULL,previous_config_identity_schema=NULL,
				previous_config_artifact_sha256=NULL,current_config_version_id=$2,
				current_config_identity_schema=1,current_config_artifact_sha256=$3,
				updated_at=clock_timestamp() WHERE node_id=$1`, scenario.fixture.nodeID,
				scenario.previous.configID, scenario.previous.digest)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		markSecurityActivation095Recovered(t, pool, scenario.fixture.candidateID)
		assertSecurityActivation095RecoveredRetryRejected(t, pool, scenario.fixture.candidateID,
			rolloutID, deploymentID, "rollback")
	})
}

func TestSecurityActivation095SerializesRetryAndRecovery(t *testing.T) {
	t.Run("immediate retry blocks recovery", func(t *testing.T) {
		pool, scenario, deploymentID := seedSecurityActivation095ConcurrentRetry(t)
		retry, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer retry.Rollback(t.Context())
		if err := insertSecurityActivation095ApplyRetry(t, retry, scenario.activationRolloutID,
			deploymentID); err != nil {
			t.Fatal(err)
		}
		if _, err := retry.Exec(t.Context(), `SET CONSTRAINTS
			edge_command_outbox_security_activation_pending_095 IMMEDIATE`); err != nil {
			t.Fatal(err)
		}
		var pendingCount int
		var candidateTableLocked bool
		if err := retry.QueryRow(t.Context(), `SELECT
			(SELECT count(*) FROM security_policy_activation_recovery_pending_095
			 WHERE candidate_id=$1 AND deployment_id=$2 AND deployment_attempt=2),
			EXISTS(SELECT 1 FROM pg_locks WHERE pid=pg_backend_pid()
			 AND relation='security_policy_activation_candidates'::regclass
			 AND mode='RowShareLock' AND granted)`, scenario.fixture.candidateID, deploymentID).
			Scan(&pendingCount, &candidateTableLocked); err != nil {
			t.Fatal(err)
		}
		if pendingCount != 1 || !candidateTableLocked {
			t.Fatalf("validated attempt-2 pending/table-lock=%d/%t, want 1/true",
				pendingCount, candidateTableLocked)
		}
		var retryPID int32
		if err := retry.QueryRow(t.Context(), `SELECT pg_backend_pid()`).Scan(&retryPID); err != nil {
			t.Fatal(err)
		}

		recoveryPID := make(chan int32, 1)
		recoveryResult := make(chan error, 1)
		go func() {
			recoveryResult <- pgx.BeginFunc(context.Background(), pool, func(tx pgx.Tx) error {
				var pid int32
				if err := tx.QueryRow(context.Background(), `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
					return err
				}
				recoveryPID <- pid
				command, err := tx.Exec(context.Background(), `UPDATE security_policy_activation_candidates
					SET recovered_at=clock_timestamp(),updated_at=clock_timestamp() WHERE id=$1`,
					scenario.fixture.candidateID)
				if err == nil && command.RowsAffected() != 1 {
					return errors.New("concurrent recovery did not update exactly one candidate")
				}
				return err
			})
		}()
		waitSecurityActivation095Blocked(t, <-recoveryPID, retryPID, recoveryResult)
		if err := retry.Commit(t.Context()); err != nil {
			t.Fatal(err)
		}
		assertSecurityActivation095Code(t, <-recoveryResult, "P8802")

		var recoveredAt *time.Time
		var attempts, outboxes, pending, generation int
		if err := pool.QueryRow(t.Context(), `SELECT candidate.recovered_at,
			(SELECT count(*) FROM node_deployments WHERE id=$2),
			(SELECT count(*) FROM edge_command_outbox WHERE deployment_id=$2),
			count(pending.*),COALESCE(max(pending.generation),0)
			FROM security_policy_activation_candidates candidate
			LEFT JOIN security_policy_activation_recovery_pending_095 pending
			  ON pending.candidate_id=candidate.id
			WHERE candidate.id=$1 GROUP BY candidate.id`, scenario.fixture.candidateID, deploymentID).
			Scan(&recoveredAt, &attempts, &outboxes, &pending, &generation); err != nil {
			t.Fatal(err)
		}
		if recoveredAt != nil || attempts != 2 || outboxes != 2 || pending != 2 || generation != 2 {
			t.Fatalf("retry-first recovery/attempts/outboxes/pending/generation=%v/%d/%d/%d/%d, want nil/2/2/2/2",
				recoveredAt, attempts, outboxes, pending, generation)
		}
	})

	t.Run("recovery blocks deferred retry commit", func(t *testing.T) {
		pool, scenario, deploymentID := seedSecurityActivation095ConcurrentRetry(t)
		before := loadSecurityActivation095RetryCounts(t, pool, scenario.fixture.candidateID, deploymentID)

		recovery, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer recovery.Rollback(t.Context())
		var recoveryPID int32
		if err := recovery.QueryRow(t.Context(), `SELECT pg_backend_pid()`).Scan(&recoveryPID); err != nil {
			t.Fatal(err)
		}
		if _, err := recovery.Exec(t.Context(), `UPDATE security_policy_activation_candidates
			SET recovered_at=clock_timestamp(),updated_at=clock_timestamp() WHERE id=$1`,
			scenario.fixture.candidateID); err != nil {
			t.Fatal(err)
		}

		retry, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer retry.Rollback(t.Context())
		if err := insertSecurityActivation095ApplyRetry(t, retry, scenario.activationRolloutID,
			deploymentID); err != nil {
			t.Fatal(err)
		}
		if _, err := retry.Exec(t.Context(), `SET CONSTRAINTS
			edge_command_outbox_security_activation_pending_095 DEFERRED`); err != nil {
			t.Fatal(err)
		}
		var retryPID int32
		if err := retry.QueryRow(t.Context(), `SELECT pg_backend_pid()`).Scan(&retryPID); err != nil {
			t.Fatal(err)
		}
		retryResult := make(chan error, 1)
		go func() {
			retryResult <- retry.Commit(context.Background())
		}()
		waitSecurityActivation095Blocked(t, retryPID, recoveryPID, retryResult)
		if err := recovery.Commit(t.Context()); err != nil {
			t.Fatal(err)
		}
		assertSecurityActivation095Code(t, <-retryResult, "P9502")

		after := loadSecurityActivation095RetryCounts(t, pool, scenario.fixture.candidateID, deploymentID)
		if after != before {
			t.Fatalf("recovery-first retry changed facts from %+v to %+v", before, after)
		}
		var recovered bool
		if err := pool.QueryRow(t.Context(), `SELECT recovered_at IS NOT NULL
			FROM security_policy_activation_candidates WHERE id=$1`, scenario.fixture.candidateID).
			Scan(&recovered); err != nil {
			t.Fatal(err)
		}
		if !recovered {
			t.Fatal("recovery-first candidate was not marked recovered")
		}
	})
}

type securityActivation095RetryCounts struct {
	attempts, outboxes, pending, generation int
}

func loadSecurityActivation095RetryCounts(t *testing.T, pool *pgxpool.Pool,
	candidateID, deploymentID uuid.UUID,
) securityActivation095RetryCounts {
	t.Helper()
	var value securityActivation095RetryCounts
	if err := pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM node_deployments WHERE id=$1),
		(SELECT count(*) FROM edge_command_outbox WHERE deployment_id=$1),
		count(*),COALESCE(max(generation),0)
		FROM security_policy_activation_recovery_pending_095 WHERE candidate_id=$2`, deploymentID,
		candidateID).Scan(&value.attempts, &value.outboxes, &value.pending, &value.generation); err != nil {
		t.Fatal(err)
	}
	return value
}

func seedSecurityActivation095ConcurrentRetry(t *testing.T) (*pgxpool.Pool,
	securityRecoveryScenario088, uuid.UUID,
) {
	t.Helper()
	pool, scenario := seedQueuedSecurityRecovery095(t, false)
	publishSecurityActivation095Outbox(t, pool, scenario.activationRolloutID)
	var deploymentID uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT id FROM node_deployments
		WHERE rollout_id=$1 AND attempt=1`, scenario.activationRolloutID).Scan(&deploymentID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `ALTER TABLE node_deployments
		DISABLE TRIGGER node_deployments_state_046`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `ALTER TABLE node_deployments
			ENABLE TRIGGER node_deployments_state_046`)
	})
	if _, err := pool.Exec(t.Context(), `UPDATE node_deployments SET state='failed',updated_at=clock_timestamp()
		WHERE id=$1 AND attempt=1`, deploymentID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `ALTER TABLE node_deployments
		ENABLE TRIGGER node_deployments_state_046`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `ALTER TABLE node_deployments
		DISABLE TRIGGER node_deployments_fact_046`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `ALTER TABLE node_deployments
			ENABLE TRIGGER node_deployments_fact_046`)
	})
	var recoverable bool
	if err := pool.QueryRow(t.Context(), `SELECT security_policy_activation_recovered_095($1)`,
		scenario.fixture.candidateID).Scan(&recoverable); err != nil {
		t.Fatal(err)
	}
	if !recoverable {
		t.Fatal("concurrent recovery fixture is not recoverable")
	}
	return pool, scenario, deploymentID
}

func insertSecurityActivation095ApplyRetry(t *testing.T, tx pgx.Tx, rolloutID, deploymentID uuid.UUID) error {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	commandBytes := []byte("095 concurrent apply retry")
	if _, err := tx.Exec(t.Context(), `INSERT INTO node_deployments(id,rollout_id,node_id,attempt,
		config_version_id,previous_config_version_id,action,state,command_event_id,command_bytes,
		command_sha256,deadline_at,created_at,updated_at)
		SELECT id,rollout_id,node_id,2,config_version_id,previous_config_version_id,action,'queued',
		$2,$3,$4,deadline_at,$5,$5 FROM node_deployments WHERE id=$1 AND attempt=1`, deploymentID,
		uuid.New(), commandBytes, sha256Bytes087(commandBytes), now); err != nil {
		return err
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO node_deployment_artifacts(deployment_id,
		deployment_attempt,config_version_id,artifact_id,ordinal)
		SELECT deployment_id,2,config_version_id,artifact_id,ordinal
		FROM node_deployment_artifacts WHERE deployment_id=$1 AND deployment_attempt=1`, deploymentID); err != nil {
		return err
	}
	_, err := tx.Exec(t.Context(), `INSERT INTO edge_command_outbox(id,deployment_id,deployment_attempt,
		node_id,subject,payload,payload_sha256,status,available_at,created_at,updated_at)
		SELECT gen_random_uuid(),id,attempt,node_id,'cdnca.agent.commands.'||node_id::text,
		command_bytes,command_sha256,'pending',$2,$2,$2 FROM node_deployments
		WHERE id=$1 AND rollout_id=$3 AND attempt=2`, deploymentID, now, rolloutID)
	return err
}

func waitSecurityActivation095Blocked(t *testing.T, blockedPID, blockerPID int32, result <-chan error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	monitor, err := pgx.Connect(ctx, strings.TrimSpace(os.Getenv("TEST_DATABASE_URL")))
	if err != nil {
		t.Fatal(err)
	}
	defer monitor.Close(context.Background())
	for ctx.Err() == nil {
		select {
		case err := <-result:
			t.Fatalf("backend %d completed before blocking behind %d: %v", blockedPID, blockerPID, err)
		default:
		}
		var blocked bool
		if err := monitor.QueryRow(ctx, `SELECT $2::integer=ANY(pg_blocking_pids($1::integer))`,
			blockedPID, blockerPID).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			return
		}
	}
	t.Fatalf("backend %d was not blocked by %d", blockedPID, blockerPID)
}

func publishSecurityActivation095Outbox(t *testing.T, pool *pgxpool.Pool, rolloutID uuid.UUID) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), `UPDATE edge_command_outbox outbox
		SET status='publishing',updated_at=clock_timestamp()
		FROM node_deployments deployment WHERE deployment.id=outbox.deployment_id
		 AND deployment.attempt=outbox.deployment_attempt AND deployment.rollout_id=$1
		 AND outbox.status='pending'`, rolloutID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE edge_command_outbox outbox
		SET status='published',published_at=clock_timestamp(),updated_at=clock_timestamp()
		FROM node_deployments deployment WHERE deployment.id=outbox.deployment_id
		 AND deployment.attempt=outbox.deployment_attempt AND deployment.rollout_id=$1
		 AND outbox.status='publishing'`, rolloutID); err != nil {
		t.Fatal(err)
	}
}

func markSecurityActivation095Recovered(t *testing.T, pool *pgxpool.Pool, candidateID uuid.UUID) {
	t.Helper()
	var recovered bool
	if err := pool.QueryRow(t.Context(), `SELECT security_policy_activation_recovered_095($1)`, candidateID).
		Scan(&recovered); err != nil {
		t.Fatal(err)
	}
	if !recovered {
		t.Fatal("candidate fixture is not recoverable")
	}
	command, err := pool.Exec(t.Context(), `UPDATE security_policy_activation_candidates
		SET recovered_at=clock_timestamp(),updated_at=clock_timestamp() WHERE id=$1`, candidateID)
	if err != nil {
		t.Fatal(err)
	}
	if command.RowsAffected() != 1 {
		t.Fatalf("recovered candidates = %d, want 1", command.RowsAffected())
	}
}

func assertSecurityActivation095RecoveredRetryRejected(t *testing.T, pool *pgxpool.Pool,
	candidateID, rolloutID, deploymentID uuid.UUID, action string,
) {
	t.Helper()
	type counts struct {
		deployments, outboxes, pending, maxGeneration int
	}
	loadCounts := func() counts {
		var value counts
		if err := pool.QueryRow(t.Context(), `SELECT
			(SELECT count(*) FROM node_deployments WHERE id=$1),
			(SELECT count(*) FROM edge_command_outbox WHERE deployment_id=$1),
			count(*),COALESCE(max(generation),0)
			FROM security_policy_activation_recovery_pending_095 WHERE candidate_id=$2`,
			deploymentID, candidateID).Scan(&value.deployments, &value.outboxes,
			&value.pending, &value.maxGeneration); err != nil {
			t.Fatal(err)
		}
		return value
	}
	before := loadCounts()
	if _, err := pool.Exec(t.Context(), `ALTER TABLE node_deployments
		DISABLE TRIGGER node_deployments_fact_046`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `ALTER TABLE node_deployments
			ENABLE TRIGGER node_deployments_fact_046`)
	})
	now := time.Now().UTC().Truncate(time.Microsecond)
	commandBytes := []byte("095 rejected recovered retry " + action)
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `INSERT INTO node_deployments(id,rollout_id,node_id,attempt,
			config_version_id,previous_config_version_id,action,state,command_event_id,command_bytes,
			command_sha256,deadline_at,created_at,updated_at)
			SELECT id,rollout_id,node_id,2,config_version_id,previous_config_version_id,action,'queued',
			$2,$3,$4,deadline_at,$5,$5 FROM node_deployments WHERE id=$1 AND attempt=1`, deploymentID,
			uuid.New(), commandBytes, sha256Bytes087(commandBytes), now); err != nil {
			return err
		}
		if action == "apply" {
			if _, err := tx.Exec(t.Context(), `INSERT INTO node_deployment_artifacts(deployment_id,
				deployment_attempt,config_version_id,artifact_id,ordinal)
				SELECT deployment_id,2,config_version_id,artifact_id,ordinal
				FROM node_deployment_artifacts WHERE deployment_id=$1 AND deployment_attempt=1`,
				deploymentID); err != nil {
				return err
			}
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO edge_command_outbox(id,deployment_id,deployment_attempt,
			node_id,subject,payload,payload_sha256,status,available_at,created_at,updated_at)
			SELECT gen_random_uuid(),id,attempt,node_id,'cdnca.agent.commands.'||node_id::text,
			command_bytes,command_sha256,'pending',$2,$2,$2 FROM node_deployments
			WHERE id=$1 AND rollout_id=$3 AND attempt=2`, deploymentID, now, rolloutID)
		return err
	})
	assertSecurityActivation095Code(t, err, "P9502")
	after := loadCounts()
	if after != before {
		t.Fatalf("recovered retry changed deployments/outboxes/pending/generation from %+v to %+v", before, after)
	}
}

func TestSecurityActivation095QueuedRecoveryRegistrationIsStrict(t *testing.T) {
	t.Run("exact queued registration", func(t *testing.T) {
		pool, scenario := seedQueuedSecurityRecovery095(t, true)
		if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
			return insertQueuedSecurityRecovery095(t, tx, scenario, queuedSecurityRecovery095Options{})
		}); err != nil {
			t.Fatalf("exact queued recovery registration: %v", err)
		}
		var pending int
		if err := pool.QueryRow(t.Context(), `SELECT count(*)
			FROM security_policy_activation_recovery_pending_095
			WHERE candidate_id=$1 AND action='rollback'`, scenario.fixture.candidateID).Scan(&pending); err != nil {
			t.Fatal(err)
		}
		if pending != 1 {
			t.Fatalf("rollback pending facts = %d, want 1", pending)
		}
	})
	t.Run("existing proven registration", func(t *testing.T) {
		pool, scenario := seedQueuedSecurityRecovery095(t, true)
		if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
			return insertQueuedSecurityRecovery095(t, tx, scenario,
				queuedSecurityRecovery095Options{provenTerminal: true})
		}); err != nil {
			t.Fatalf("existing proven recovery registration: %v", err)
		}
	})

	tests := []struct {
		name            string
		candidateLoaded bool
		corruptPending  string
		options         queuedSecurityRecovery095Options
	}{
		{name: "missing latest apply pending", candidateLoaded: true,
			corruptPending: `DELETE FROM security_policy_activation_recovery_pending_095
				WHERE candidate_id=$1 AND node_id=$2`},
		{name: "mismatched pending identity", candidateLoaded: true,
			corruptPending: `UPDATE security_policy_activation_recovery_pending_095
				SET candidate_config_version_id=gen_random_uuid() WHERE candidate_id=$1 AND node_id=$2`},
		{name: "mismatched pending digest", candidateLoaded: true,
			corruptPending: `UPDATE security_policy_activation_recovery_pending_095
				SET recovery_artifact_sha256=sha256(convert_to('wrong recovery digest','UTF8'))
				WHERE candidate_id=$1 AND node_id=$2`},
		{name: "wrong pending action", candidateLoaded: true,
			corruptPending: `UPDATE security_policy_activation_recovery_pending_095
				SET action='rollback' WHERE candidate_id=$1 AND node_id=$2`},
		{name: "candidate identity not loaded"},
		{name: "node subset mismatch", candidateLoaded: true,
			options: queuedSecurityRecovery095Options{factNodeID: uuid.New()}},
		{name: "deployment previous identity mismatch", candidateLoaded: true,
			options: queuedSecurityRecovery095Options{wrongPrevious: true}},
		{name: "deployment attempt is not one", candidateLoaded: true,
			options: queuedSecurityRecovery095Options{attempt: 2}},
		{name: "forged terminal proof", candidateLoaded: true,
			options: queuedSecurityRecovery095Options{forgedTerminal: true}},
		{name: "missing pending outbox", candidateLoaded: true,
			options: queuedSecurityRecovery095Options{outboxMode: "missing"}},
		{name: "mismatched pending outbox subject", candidateLoaded: true,
			options: queuedSecurityRecovery095Options{outboxMode: "subject"}},
		{name: "mismatched pending outbox data", candidateLoaded: true,
			options: queuedSecurityRecovery095Options{outboxMode: "data"}},
		{name: "mismatched pending outbox digest", candidateLoaded: true,
			options: queuedSecurityRecovery095Options{outboxMode: "digest"}},
		{name: "nonpending outbox status", candidateLoaded: true,
			options: queuedSecurityRecovery095Options{outboxMode: "status"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pool, scenario := seedQueuedSecurityRecovery095(t, test.candidateLoaded)
			err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
				if test.corruptPending != "" {
					if _, err := tx.Exec(t.Context(), `ALTER TABLE security_policy_activation_recovery_pending_095
						DISABLE TRIGGER security_policy_activation_recovery_pending_immutable_095`); err != nil {
						return err
					}
					if _, err := tx.Exec(t.Context(), test.corruptPending,
						scenario.fixture.candidateID, scenario.fixture.nodeID); err != nil {
						return err
					}
					if _, err := tx.Exec(t.Context(), `ALTER TABLE security_policy_activation_recovery_pending_095
						ENABLE TRIGGER security_policy_activation_recovery_pending_immutable_095`); err != nil {
						return err
					}
				}
				return insertQueuedSecurityRecovery095(t, tx, scenario, test.options)
			})
			assertSecurityActivation095Code(t, err, "P8802")
		})
	}
}

type queuedSecurityRecovery095Options struct {
	factNodeID     uuid.UUID
	attempt        int
	wrongPrevious  bool
	forgedTerminal bool
	provenTerminal bool
	outboxMode     string
}

func seedQueuedSecurityRecovery095(t *testing.T, candidateLoaded bool) (*pgxpool.Pool, securityRecoveryScenario088) {
	t.Helper()
	pool := packageCommerceRBAC079Pool(t, 94)
	scenario := seedSecurityRecoveryScenario088(t, pool)
	seedSecurityActivation095Outboxes(t, pool, scenario.fixture.candidateID)
	if err := migrateVersionIsolated(t.Context(), pool, "up", 95); err != nil {
		t.Fatalf("apply 095 queued recovery fixture: %v", err)
	}
	if candidateLoaded {
		if _, err := pool.Exec(t.Context(), `UPDATE node_config_state SET
			previous_config_version_id=$2,previous_config_identity_schema=1,
			previous_config_artifact_sha256=$3,current_config_version_id=$4,
			current_config_identity_schema=1,current_config_artifact_sha256=$5,
			updated_at=clock_timestamp() WHERE node_id=$1`, scenario.fixture.nodeID,
			scenario.previous.configID, scenario.previous.digest, scenario.fixture.configID,
			scenario.fixture.digest); err != nil {
			t.Fatalf("mark queued recovery candidate loaded: %v", err)
		}
	}
	return pool, scenario
}

func insertQueuedSecurityRecovery095(t *testing.T, tx pgx.Tx, scenario securityRecoveryScenario088,
	options queuedSecurityRecovery095Options,
) error {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	rolloutID, deploymentID, outboxID, requestID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	attempt := options.attempt
	if attempt == 0 {
		attempt = 1
	}
	factNodeID := options.factNodeID
	if factNodeID == uuid.Nil {
		factNodeID = scenario.fixture.nodeID
	}
	previousConfigID := scenario.fixture.configID
	if options.wrongPrevious {
		previousConfigID = scenario.previous.configID
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO rollouts(id,configuration_scope_id,config_version_id,
		action,status,idempotency_key,request_digest,request_id,correlation_id,activation_timeout_ms,
		observation_window_ms,required_consecutive_successes,deadline_at,created_at,queued_at,updated_at,
		revision,max_attempts,contract_version) VALUES($1,$2,$3,'rollback','queued',$4,$5,$6,$7,1000,
		1000,1,$8,$9,$9,$9,1,2,1)`, rolloutID, scenario.fixture.scopeID, scenario.previous.configID,
		"recovery."+rolloutID.String(), make([]byte, sha256.Size), requestID, uuid.New(), now.Add(time.Hour), now); err != nil {
		return err
	}
	command := []byte("095 queued recovery " + deploymentID.String())
	if attempt != 1 {
		priorCommand := []byte("095 prior failed recovery " + deploymentID.String())
		if _, err := tx.Exec(t.Context(), `INSERT INTO node_deployments(id,rollout_id,node_id,attempt,
			config_version_id,previous_config_version_id,action,state,command_event_id,command_bytes,
			command_sha256,deadline_at,created_at,updated_at) VALUES($1,$2,$3,1,$4,$5,'rollback','failed',
			$6,$7,$8,$9,$10,$10)`, deploymentID, rolloutID, scenario.fixture.nodeID,
			scenario.previous.configID, previousConfigID, uuid.New(), priorCommand,
			sha256Bytes087(priorCommand), now.Add(time.Hour), now); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO node_deployments(id,rollout_id,node_id,attempt,
		config_version_id,previous_config_version_id,action,state,command_event_id,command_bytes,
		command_sha256,deadline_at,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,'rollback',$7,
		$8,$9,$10,$11,$12,$12)`, deploymentID, rolloutID, scenario.fixture.nodeID, attempt,
		scenario.previous.configID, previousConfigID, func() string {
			if options.forgedTerminal || options.provenTerminal {
				return "reverted"
			}
			return "queued"
		}(), uuid.New(), command, sha256Bytes087(command), now.Add(time.Hour), now); err != nil {
		return err
	}
	if options.outboxMode != "missing" {
		subject := "cdnca.agent.commands." + scenario.fixture.nodeID.String()
		payload, payloadDigest, status := command, sha256Bytes087(command), "pending"
		switch options.outboxMode {
		case "subject":
			subject = "cdnca.agent.commands.wrong"
		case "data":
			payload = []byte("wrong queued recovery payload")
			payloadDigest = sha256Bytes087(payload)
		case "digest":
			payloadDigest = sha256Bytes087([]byte("wrong queued recovery digest"))
		case "status":
			status = "failed"
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO edge_command_outbox(id,deployment_id,
			deployment_attempt,node_id,subject,payload,payload_sha256,status,available_at,created_at,updated_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$9,$9)`, outboxID, deploymentID, attempt,
			scenario.fixture.nodeID, subject, payload, payloadDigest, status, now); err != nil {
			return err
		}
	}
	if options.forgedTerminal || options.provenTerminal {
		payload := []byte("095 forged recovery terminal")
		var identityAPIVersion, identitySchema, identityConfigID, identityDigest any
		if options.provenTerminal {
			identityAPIVersion, identitySchema = 1, 1
			identityConfigID, identityDigest = scenario.previous.configID, scenario.previous.digest
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO deployment_status_events(id,deployment_id,event_id,
			attempt,transition_sequence,state,payload,payload_sha256,occurred_at,received_at,
			active_config_identity_api_version,active_config_identity_schema,active_config_version_id,
			active_config_artifact_sha256) VALUES($1,$2,$3,$4,1,'reverted',$5,$6,$7,$7,$8,$9,$10,$11)`,
			uuid.New(), deploymentID, uuid.New(), attempt, payload, sha256Bytes087(payload), now,
			identityAPIVersion, identitySchema, identityConfigID, identityDigest); err != nil {
			return err
		}
		if options.provenTerminal {
			if _, err := tx.Exec(t.Context(), `UPDATE node_config_state SET
				previous_config_version_id=$2,previous_config_identity_schema=1,
				previous_config_artifact_sha256=$3,current_config_version_id=$4,
				current_config_identity_schema=1,current_config_artifact_sha256=$5,
				updated_at=$6 WHERE node_id=$1`, scenario.fixture.nodeID, scenario.fixture.configID,
				scenario.fixture.digest, scenario.previous.configID, scenario.previous.digest, now); err != nil {
				return err
			}
		}
	}
	_, err := tx.Exec(t.Context(), `INSERT INTO security_policy_activation_recovery_rollouts(candidate_id,
		tenant_scope_id,rollout_id,recovery_config_version_id,recovery_artifact_sha256,target_snapshot_sha256,
		node_ids,request_id,created_at) VALUES($1,$2,$3,$4,$5,$6,ARRAY[$7]::uuid[],$8,$9)`,
		scenario.fixture.candidateID, scenario.fixture.scopeID, rolloutID, scenario.previous.configID,
		scenario.previous.digest, securityActivationTargetDigest088(scenario.fixture), factNodeID, requestID, now)
	return err
}

func TestSecurityActivation095FreshRoundTrip(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 94)
	if err := migrateVersionIsolated(t.Context(), pool, "up", 95); err != nil {
		t.Fatalf("fresh 1..95: %v", err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, 95)
	assertSecurityActivation095Relations(t, pool, true)
	if err := migrateVersionIsolated(t.Context(), pool, "down", 95); err != nil {
		t.Fatalf("95 down: %v", err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, 94)
	assertSecurityActivation095Relations(t, pool, false)
	if err := migrateVersionIsolated(t.Context(), pool, "up", 95); err != nil {
		t.Fatalf("94 -> 95 reapply: %v", err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, 95)
}

func TestSecurityActivation095RejectsWrongHeadAndFactsOnDown(t *testing.T) {
	t.Run("missing 094 head", func(t *testing.T) {
		pool := packageCommerceRBAC079Pool(t, 93)
		_, err := pool.Exec(t.Context(), mustReadSecurityActivation095(t, "095_security_activation.up.sql"))
		assertSecurityActivation095Code(t, err, "P9500")
	})
	t.Run("tampered 094 head", func(t *testing.T) {
		pool := packageCommerceRBAC079Pool(t, 94)
		if _, err := pool.Exec(t.Context(), `UPDATE schema_migrations SET checksum_sha256=repeat('a',64)
			WHERE version=94`); err != nil {
			t.Fatal(err)
		}
		_, err := pool.Exec(t.Context(), mustReadSecurityActivation095(t, "095_security_activation.up.sql"))
		assertSecurityActivation095Code(t, err, "P9500")
	})
	for _, test := range []struct {
		name   string
		mutate string
	}{
		{name: "raw down rejects tampered 094 parent",
			mutate: `UPDATE schema_migrations SET checksum_sha256=repeat('a',64) WHERE version=94`},
		{name: "raw down rejects missing 094 parent",
			mutate: `DELETE FROM schema_migrations WHERE version=94`},
	} {
		t.Run(test.name, func(t *testing.T) {
			pool := packageCommerceRBAC079Pool(t, 95)
			if _, err := pool.Exec(t.Context(), test.mutate); err != nil {
				t.Fatal(err)
			}
			_, err := pool.Exec(t.Context(), mustReadSecurityActivation095(t, "095_security_activation.down.sql"))
			assertSecurityActivation095Code(t, err, "P9500")
			assertSecurityActivation095Relations(t, pool, true)
		})
	}
	t.Run("pending facts", func(t *testing.T) {
		pool := packageCommerceRBAC079Pool(t, 95)
		candidate := seedSecurityActivationCandidate088(t, pool)
		if _, err := pool.Exec(t.Context(), `ALTER TABLE security_policy_activation_recovery_pending_095
			DISABLE TRIGGER ALL`); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(t.Context(), `INSERT INTO security_policy_activation_recovery_pending_095(
			candidate_id,tenant_scope_id,rollout_id,deployment_id,deployment_attempt,node_id,generation,
			action,candidate_config_version_id,candidate_artifact_sha256,recovery_config_version_id,
			recovery_artifact_sha256,candidate_target_snapshot_sha256,recovery_target_snapshot_sha256,
			outbox_id,request_id,created_at)
			VALUES($1,$2,$3,$4,1,$5,1,'apply',$6,$7,NULL,NULL,$8,$8,$9,$10,clock_timestamp())`,
			candidate.candidateID, candidate.scopeID, uuid.New(), uuid.New(), candidate.nodeID,
			candidate.configID, candidate.digest, securityActivationTargetDigest088(candidate), uuid.New(), uuid.New()); err != nil {
			t.Fatal(err)
		}
		assertSecurityActivation095Code(t, migrateVersionIsolated(t.Context(), pool, "down", 95), "P9501")
	})
}

func TestSecurityActivation095ForwardBackfillsOnlyProvable088Facts(t *testing.T) {
	t.Run("provable recovery", func(t *testing.T) {
		pool := packageCommerceRBAC079Pool(t, 94)
		scenario := seedSecurityRecoveryScenario088(t, pool)
		insertSecurityRecoveryProof088(t, pool, scenario, securityRecoveryProofOptions088{
			config: scenario.previous, artifactDigest: scenario.previous.digest,
			deploymentAction: "rollback", eventState: "reverted", eventMode: "exact",
		})
		seedSecurityActivation095Outboxes(t, pool, scenario.fixture.candidateID)
		if _, err := pool.Exec(t.Context(), `UPDATE edge_command_outbox SET status='publishing';
			UPDATE edge_command_outbox SET status='published',
			published_at=created_at+interval '1 second',updated_at=created_at+interval '1 second'`); err != nil {
			t.Fatal(err)
		}
		if err := migrateVersionIsolated(t.Context(), pool, "up", 95); err != nil {
			t.Fatalf("provable 088 recovery forward migration: %v", err)
		}
		var pending, proofs int
		var recovered bool
		if err := pool.QueryRow(t.Context(), `SELECT
			(SELECT count(*) FROM security_policy_activation_recovery_pending_095 WHERE candidate_id=$1),
			(SELECT count(*) FROM security_policy_activation_recovery_proofs_095 WHERE candidate_id=$1),
			security_policy_activation_recovered_095($1)`, scenario.fixture.candidateID).
			Scan(&pending, &proofs, &recovered); err != nil {
			t.Fatal(err)
		}
		if pending < 2 || proofs != 1 || !recovered {
			t.Fatalf("forward pending/proofs/recovered=%d/%d/%t, want >=2/1/true", pending, proofs, recovered)
		}
	})
	t.Run("unprovable recovery", func(t *testing.T) {
		pool := packageCommerceRBAC079Pool(t, 94)
		disableSecurityRecoveryProofGuards088(t, pool)
		scenario := seedSecurityRecoveryScenario088(t, pool)
		insertSecurityRecoveryProof088(t, pool, scenario, securityRecoveryProofOptions088{
			config: scenario.previous, artifactDigest: scenario.previous.digest,
			deploymentAction: "rollback", eventMode: "missing",
		})
		assertSecurityActivation095Code(t,
			migrateVersionIsolated(t.Context(), pool, "up", 95), "P9502")
		assertPackageCommerceRBAC079Ledger(t, pool, 94)
		assertSecurityActivation095Relations(t, pool, false)
	})
}

func seedSecurityActivation095Outboxes(t *testing.T, pool *pgxpool.Pool, candidateID uuid.UUID) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), `INSERT INTO edge_command_outbox(
		id,deployment_id,deployment_attempt,node_id,subject,payload,payload_sha256,status,
		available_at,created_at,updated_at)
		SELECT gen_random_uuid(),deployment.id,deployment.attempt,deployment.node_id,
			'cdnca.agent.commands.'||deployment.node_id::text,deployment.command_bytes,
			deployment.command_sha256,'pending',deployment.created_at,deployment.created_at,
			deployment.created_at
		FROM node_deployments deployment
		WHERE deployment.rollout_id IN (
			SELECT rollout_id FROM security_policy_activation_rollouts WHERE candidate_id=$1
			UNION
			SELECT rollout_id FROM security_policy_activation_recovery_rollouts WHERE candidate_id=$1
		)
		ON CONFLICT (deployment_id,deployment_attempt) DO NOTHING`, candidateID); err != nil {
		t.Fatal(err)
	}
}

func TestSecurityActivation095FactsAreAppendOnlyAndValidated(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 95)
	candidate := seedSecurityActivationCandidate088(t, pool)
	_, err := pool.Exec(t.Context(), `INSERT INTO security_policy_activation_recovery_pending_095(
		candidate_id,tenant_scope_id,rollout_id,deployment_id,deployment_attempt,node_id,generation,
		action,candidate_config_version_id,candidate_artifact_sha256,recovery_config_version_id,
		recovery_artifact_sha256,candidate_target_snapshot_sha256,recovery_target_snapshot_sha256,
		request_id,created_at)
		VALUES($1,$2,$3,$4,1,$5,1,'apply',$6,$7,NULL,NULL,$8,$8,$9,clock_timestamp())`,
		candidate.candidateID, candidate.scopeID, uuid.New(), uuid.New(), candidate.nodeID,
		candidate.configID, candidate.digest, securityActivationTargetDigest088(candidate), uuid.New())
	assertSecurityActivation095Code(t, err, "P9502")
	if _, err := pool.Exec(t.Context(), `ALTER TABLE security_policy_activation_recovery_pending_095
		DISABLE TRIGGER ALL`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO security_policy_activation_recovery_pending_095(
		candidate_id,tenant_scope_id,rollout_id,deployment_id,deployment_attempt,node_id,generation,
		action,candidate_config_version_id,candidate_artifact_sha256,recovery_config_version_id,
		recovery_artifact_sha256,candidate_target_snapshot_sha256,recovery_target_snapshot_sha256,
		outbox_id,request_id,created_at)
		VALUES($1,$2,$3,$4,1,$5,1,'apply',$6,$7,NULL,NULL,$8,$8,$9,$10,clock_timestamp())`,
		candidate.candidateID, candidate.scopeID, uuid.New(), uuid.New(), candidate.nodeID,
		candidate.configID, candidate.digest, securityActivationTargetDigest088(candidate), uuid.New(), uuid.New()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `ALTER TABLE security_policy_activation_recovery_pending_095
		ENABLE TRIGGER ALL`); err != nil {
		t.Fatal(err)
	}

	for _, query := range []string{
		`UPDATE security_policy_activation_recovery_pending_095 SET generation=generation+1`,
		`DELETE FROM security_policy_activation_recovery_pending_095`,
		`TRUNCATE security_policy_activation_recovery_pending_095,
			security_policy_activation_recovery_proofs_095`,
		`TRUNCATE security_policy_activation_recovery_proofs_095`,
	} {
		_, err := pool.Exec(t.Context(), query)
		assertSecurityActivation095Code(t, err, "P9502")
	}
	_, err = pool.Exec(t.Context(), `INSERT INTO security_policy_activation_recovery_proofs_095(
		candidate_id,tenant_scope_id,rollout_id,deployment_id,deployment_attempt,node_id,generation,
		action,candidate_config_version_id,candidate_artifact_sha256,recovery_config_version_id,
		recovery_artifact_sha256,candidate_target_snapshot_sha256,recovery_target_snapshot_sha256,
		outbox_id,status_event_id,transition_sequence,proved_at)
		VALUES($1,$2,$3,$4,1,$5,1,'rollback',$6,$7,$6,$7,$8,$8,$9,$10,1,clock_timestamp())`,
		candidate.candidateID, candidate.scopeID, uuid.New(), uuid.New(), candidate.nodeID,
		candidate.configID, candidate.digest, securityActivationTargetDigest088(candidate), uuid.New(), uuid.New())
	assertSecurityActivation095Code(t, err, "P9502")
}

func TestSecurityActivation095DownSerializesConcurrentFact(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 95)
	candidate := seedSecurityActivationCandidate088(t, pool)
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(t.Context(), `ALTER TABLE security_policy_activation_recovery_pending_095
		DISABLE TRIGGER ALL`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO security_policy_activation_recovery_pending_095(
		candidate_id,tenant_scope_id,rollout_id,deployment_id,deployment_attempt,node_id,generation,
		action,candidate_config_version_id,candidate_artifact_sha256,recovery_config_version_id,
		recovery_artifact_sha256,candidate_target_snapshot_sha256,recovery_target_snapshot_sha256,
		outbox_id,request_id,created_at)
		VALUES($1,$2,$3,$4,1,$5,1,'apply',$6,$7,NULL,NULL,$8,$8,$9,$10,clock_timestamp())`,
		candidate.candidateID, candidate.scopeID, uuid.New(), uuid.New(), candidate.nodeID,
		candidate.configID, candidate.digest, securityActivationTargetDigest088(candidate), uuid.New(), uuid.New()); err != nil {
		t.Fatal(err)
	}
	downResult := make(chan error, 1)
	go func() {
		downResult <- migrateVersionIsolated(context.Background(), pool, "down", 95)
	}()
	select {
	case err := <-downResult:
		t.Fatalf("095 down did not wait for concurrent recovery fact: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	assertSecurityActivation095Code(t, <-downResult, "P9501")
	assertPackageCommerceRBAC079Ledger(t, pool, 95)
}

func assertSecurityActivation095Relations(t *testing.T, pool *pgxpool.Pool, want bool) {
	t.Helper()
	for _, relation := range []string{
		"security_policy_activation_recovery_pending_095",
		"security_policy_activation_recovery_proofs_095",
	} {
		var exists bool
		if err := pool.QueryRow(t.Context(), `SELECT to_regclass($1) IS NOT NULL`, relation).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if exists != want {
			t.Fatalf("relation %s exists=%t, want %t", relation, exists, want)
		}
	}
}

func mustReadSecurityActivation095(t *testing.T, name string) string {
	t.Helper()
	value, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(value)
}

func securityActivation095SQLFunction(t *testing.T, script, declaration string) string {
	t.Helper()
	start := strings.Index(script, declaration)
	if start < 0 {
		t.Fatalf("SQL function declaration %q not found", declaration)
	}
	end := strings.Index(script[start:], "\n$$;")
	if end < 0 {
		t.Fatalf("SQL function %q terminator not found", declaration)
	}
	return strings.TrimSpace(script[start : start+end+len("\n$$;")])
}

func assertSecurityActivation095Code(t *testing.T, err error, code string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != code {
		t.Fatalf("error = %v, want SQLSTATE %s", err, code)
	}
}
