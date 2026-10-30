//go:build integration

package migrations_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"testing"
	"time"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestSecurityPolicyActivation088PinsApproved087(t *testing.T) {
	tests := []struct {
		name string
		read func() ([]byte, error)
		want string
	}{
		{name: "up", read: func() ([]byte, error) {
			return fs.ReadFile(controlmigrations.FS, "087_active_config_identity_control.up.sql")
		}, want: "bf9388d78ed42d1d4faba324863b4efd47fa0e7aefff5e37c48bc0e8da66383b"},
		{name: "down", read: func() ([]byte, error) {
			return fs.ReadFile(controlmigrations.FS, "087_active_config_identity_control.down.sql")
		}, want: "d6e9ddd6e856b228733c3615422acfe8567d65246d941ffc338ec76e6eb7997b"},
		{name: "integration", read: func() ([]byte, error) { return os.ReadFile("active_config_identity_control_087_integration_test.go") }, want: "22f910de18a93771def34c3785637d9d45657e73ed8f479698f651b30b43f0bb"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value, err := test.read()
			if err != nil {
				t.Fatal(err)
			}
			if got := fmt.Sprintf("%x", sha256.Sum256(value)); got != test.want {
				t.Fatalf("087 %s sha256 = %s, want %s", test.name, got, test.want)
			}
		})
	}
}

func TestSecurityPolicyActivation088MigrationContract(t *testing.T) {
	up, err := fs.ReadFile(controlmigrations.FS, "088_security_policy_activation.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := fs.ReadFile(controlmigrations.FS, "088_security_policy_activation.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	upText, downText := string(up), string(down)
	for _, required := range []string{
		"security_policy_activation_candidates", "candidate_source_revision", "candidate_config_version_id",
		"candidate_artifact_sha256", "target_snapshot_sha256", "candidate_status",
		"claimed", "canary", "expanding", "healthy", "failed", "cancelled", "expired", "promoted",
		"security_policy_activation_events", "security_policy_activation_rollouts",
		"security_policy_activation_recovery_rollouts", "required_capabilities",
		"expected_active_policy_version", "last_claimed_policy_version", "last_bundle_id",
		"edge_configuration_scopes", "source_revision",
		"CREATE OR REPLACE FUNCTION assert_rollout_contract_046()",
	} {
		if !strings.Contains(upText, required) {
			t.Errorf("088 up missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"UPDATE edge_configuration_scopes SET source_revision = candidate_source_revision",
		"SET active_policy_version = EXCLUDED",
	} {
		if strings.Contains(upText, forbidden) {
			t.Errorf("088 up contains desired-state-first pattern %q", forbidden)
		}
	}
	for _, required := range []string{
		"CREATE OR REPLACE FUNCTION assert_rollout_contract_046()",
		"migration 088 rollback requires the verified 088 head",
		"migration 088 rollback would discard security activation facts",
		"DROP TABLE security_policy_activation_recovery_rollouts",
		"DROP TABLE security_policy_activation_rollouts", "DROP TABLE security_policy_activation_events",
		"DROP TABLE security_policy_activation_candidates",
	} {
		if !strings.Contains(downText, required) {
			t.Errorf("088 down missing %q", required)
		}
	}
}

func TestSecurityPolicyActivation088RoundTrip(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 87)
	if err := migrateVersionIsolated(t.Context(), pool, "up", 88); err != nil {
		t.Fatal(err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, 88)
	if err := migrateVersionIsolated(t.Context(), pool, "down", 88); err != nil {
		t.Fatal(err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, 87)
	if err := migrateVersionIsolated(t.Context(), pool, "up", 88); err != nil {
		t.Fatal(err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, 88)
}

func TestSecurityPolicyActivation088RequiresExactVerified087Head(t *testing.T) {
	script, err := fs.ReadFile(controlmigrations.FS, "088_security_policy_activation.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		maximum int64
		tamper  bool
	}{
		{name: "missing 087", maximum: 86},
		{name: "tampered 087", maximum: 87, tamper: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			pool := packageCommerceRBAC079Pool(t, test.maximum)
			if test.tamper {
				if _, err := pool.Exec(t.Context(), `UPDATE schema_migrations SET checksum_sha256=repeat('a',64)
					WHERE version=87`); err != nil {
					t.Fatal(err)
				}
			}
			_, err := pool.Exec(t.Context(), string(script))
			assertActiveIdentityCode087(t, err, "P8800")
			assertSecurityActivation088Tables(t, pool, false)
		})
	}
}

func TestSecurityPolicyActivation088DownSerializesConcurrentFact(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 88)
	fixture := seedActiveIdentity087(t, pool)
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(t.Context(), `INSERT INTO security_policy_activation_config_facts(
		tenant_scope_id,config_version_id,artifact_sha256,policy_kind,required_capabilities,created_at)
		SELECT scope_id,$2,$3,'waf','["waf.v1"]'::jsonb,clock_timestamp()
		FROM nodes WHERE id=$1`, fixture.nodeID, fixture.configID, fixture.digest); err != nil {
		t.Fatal(err)
	}
	downResult := make(chan error, 1)
	go func() {
		downResult <- migrateVersionIsolated(context.Background(), pool, "down", 88)
	}()
	select {
	case err := <-downResult:
		t.Fatalf("088 down did not wait for concurrent activation fact: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	assertActiveIdentityCode087(t, <-downResult, "P8801")
	assertPackageCommerceRBAC079Ledger(t, pool, 88)
	assertSecurityActivation088Tables(t, pool, true)
}

func TestSecurityPolicyActivation088RolloutIdentityStateBinding(t *testing.T) {
	pool := securityActivationBody088Pool(t)
	fixture := seedSecurityActivationCandidate088(t, pool)
	tests := []struct {
		name       string
		action     string
		attempt    int
		eventState string
		eventMode  string
		wantError  bool
	}{
		{name: "missing state", action: "apply", attempt: 1, eventMode: "missing", wantError: true},
		{name: "wrong state", action: "apply", attempt: 1, eventState: "failed", eventMode: "exact", wantError: true},
		{name: "wrong action", action: "rollback", attempt: 1, eventState: "reverted", eventMode: "exact", wantError: true},
		{name: "wrong attempt", action: "apply", attempt: 2, eventState: "healthy", eventMode: "exact", wantError: true},
		{name: "mismatched deployment", action: "apply", attempt: 1, eventState: "healthy", eventMode: "mismatched", wantError: true},
		{name: "healthy", action: "apply", attempt: 1, eventState: "healthy", eventMode: "exact"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := insertSecurityActivationRollout088(t, pool, fixture, "apply", test.action,
				test.attempt, test.eventState, test.eventMode, false)
			assertSecurityActivationCall088(t, err, test.wantError,
				"invalid security policy activation rollout identity")
		})
	}
}

func TestSecurityPolicyActivation088RecoveryIdentityStateBinding(t *testing.T) {
	pool := securityActivationBody088Pool(t)
	fixture := seedSecurityActivationCandidate088(t, pool)
	tests := []struct {
		name       string
		action     string
		attempt    int
		eventState string
		eventMode  string
		wantError  bool
	}{
		{name: "missing state", action: "rollback", attempt: 1, eventMode: "missing", wantError: true},
		{name: "wrong state", action: "rollback", attempt: 1, eventState: "failed", eventMode: "exact", wantError: true},
		{name: "wrong action", action: "apply", attempt: 1, eventState: "healthy", eventMode: "exact", wantError: true},
		{name: "wrong attempt", action: "rollback", attempt: 2, eventState: "reverted", eventMode: "exact", wantError: true},
		{name: "mismatched deployment", action: "rollback", attempt: 1, eventState: "reverted", eventMode: "mismatched", wantError: true},
		{name: "reverted", action: "rollback", attempt: 1, eventState: "reverted", eventMode: "exact"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := insertSecurityActivationRollout088(t, pool, fixture, "rollback", test.action,
				test.attempt, test.eventState, test.eventMode, false)
			assertSecurityActivationCall088(t, err, test.wantError,
				"invalid security policy activation recovery rollout identity")
		})
	}
}

func TestSecurityPolicyActivation088PhaseHealthyStateBinding(t *testing.T) {
	pool := securityActivationBody088Pool(t)
	for _, statement := range []string{
		`ALTER TABLE security_policy_activation_rollouts DISABLE TRIGGER security_policy_activation_rollouts_validate`,
		`ALTER TABLE node_deployments DISABLE TRIGGER node_deployments_attempt_046`,
		`ALTER TABLE node_deployments DISABLE TRIGGER node_deployments_fact_046`,
	} {
		if _, err := pool.Exec(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, statement := range []string{
			`ALTER TABLE node_deployments ENABLE TRIGGER node_deployments_fact_046`,
			`ALTER TABLE node_deployments ENABLE TRIGGER node_deployments_attempt_046`,
			`ALTER TABLE security_policy_activation_rollouts ENABLE TRIGGER security_policy_activation_rollouts_validate`,
		} {
			if _, err := pool.Exec(ctx, statement); err != nil {
				t.Errorf("restore phase identity test trigger: %v", err)
			}
		}
	})
	tests := []struct {
		name       string
		action     string
		attempt    int
		eventState string
		eventMode  string
		want       bool
	}{
		{name: "missing state", action: "apply", attempt: 1, eventMode: "missing"},
		{name: "wrong state", action: "apply", attempt: 1, eventState: "failed", eventMode: "exact"},
		{name: "wrong action", action: "rollback", attempt: 1, eventState: "reverted", eventMode: "exact"},
		{name: "wrong attempt", action: "apply", attempt: 2, eventState: "healthy", eventMode: "exact"},
		{name: "mismatched deployment", action: "apply", attempt: 1, eventState: "healthy", eventMode: "mismatched"},
		{name: "healthy", action: "apply", attempt: 1, eventState: "healthy", eventMode: "exact", want: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := seedSecurityActivationCandidate088(t, pool)
			if err := insertSecurityActivationRollout088(t, pool, fixture, "apply", test.action,
				test.attempt, test.eventState, test.eventMode, true); err != nil {
				t.Fatal(err)
			}
			var got bool
			if err := pool.QueryRow(t.Context(), `SELECT security_policy_activation_phase_healthy_088($1,'canary')`,
				fixture.candidateID).Scan(&got); err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("phase healthy = %t, want %t", got, test.want)
			}
		})
	}
}

func TestSecurityPolicyActivation088RecoveryRequiresExactRevertedReceipt(t *testing.T) {
	// Each scenario seeds the fixed 087 UUIDv7 config identity (activeIdentityObservedUUID087),
	// so every subtest needs its own schema.
	recoveryPool := func(t *testing.T) *pgxpool.Pool {
		pool := securityActivationBody088Pool(t)
		disableSecurityRecoveryProofGuards088(t, pool)
		return pool
	}
	tests := []struct {
		name string
		seed func(*testing.T, *pgxpool.Pool, securityRecoveryScenario088)
	}{
		{name: "missing receipt"},
		{name: "failed receipt", seed: func(t *testing.T, pool *pgxpool.Pool, scenario securityRecoveryScenario088) {
			insertSecurityRecoveryProof088(t, pool, scenario, securityRecoveryProofOptions088{
				config: scenario.previous, artifactDigest: scenario.previous.digest,
				deploymentAction: "rollback", eventState: "failed", eventMode: "exact",
			})
		}},
		{name: "wrong action", seed: func(t *testing.T, pool *pgxpool.Pool, scenario securityRecoveryScenario088) {
			insertSecurityRecoveryProof088(t, pool, scenario, securityRecoveryProofOptions088{
				config: scenario.previous, artifactDigest: scenario.previous.digest,
				deploymentAction: "apply", eventState: "healthy", eventMode: "exact",
			})
		}},
		{name: "wrong config", seed: func(t *testing.T, pool *pgxpool.Pool, scenario securityRecoveryScenario088) {
			insertSecurityRecoveryProof088(t, pool, scenario, securityRecoveryProofOptions088{
				config: scenario.fixture.activeIdentityFixture087, artifactDigest: scenario.fixture.digest,
				deploymentAction: "rollback", eventState: "reverted", eventMode: "exact",
			})
		}},
		{name: "wrong artifact", seed: func(t *testing.T, pool *pgxpool.Pool, scenario securityRecoveryScenario088) {
			insertSecurityRecoveryProof088(t, pool, scenario, securityRecoveryProofOptions088{
				config: scenario.previous, artifactDigest: scenario.fixture.digest,
				deploymentAction: "rollback", eventState: "reverted", eventMode: "exact",
			})
		}},
		{name: "wrong deployment", seed: func(t *testing.T, pool *pgxpool.Pool, scenario securityRecoveryScenario088) {
			insertSecurityRecoveryProof088(t, pool, scenario, securityRecoveryProofOptions088{
				config: scenario.previous, artifactDigest: scenario.previous.digest,
				deploymentAction: "rollback", eventState: "reverted", eventMode: "mismatched",
			})
		}},
		{name: "stale receipt", seed: func(t *testing.T, pool *pgxpool.Pool, scenario securityRecoveryScenario088) {
			proof := insertSecurityRecoveryProof088(t, pool, scenario, securityRecoveryProofOptions088{
				config: scenario.previous, artifactDigest: scenario.previous.digest,
				deploymentAction: "rollback", eventState: "reverted", eventMode: "exact",
			})
			appendSecurityRecoveryStatus088(t, pool, scenario, proof, 1, 2, "failed")
		}},
		{name: "competing deployment attempt", seed: func(t *testing.T, pool *pgxpool.Pool, scenario securityRecoveryScenario088) {
			proof := insertSecurityRecoveryProof088(t, pool, scenario, securityRecoveryProofOptions088{
				config: scenario.previous, artifactDigest: scenario.previous.digest,
				deploymentAction: "rollback", eventState: "reverted", eventMode: "exact",
			})
			appendSecurityRecoveryAttempt088(t, pool, scenario, proof, 2, "failed")
		}},
		{name: "stale recovery rollout", seed: func(t *testing.T, pool *pgxpool.Pool, scenario securityRecoveryScenario088) {
			now := time.Now().UTC().Truncate(time.Microsecond)
			insertSecurityRecoveryProof088(t, pool, scenario, securityRecoveryProofOptions088{
				config: scenario.previous, artifactDigest: scenario.previous.digest,
				deploymentAction: "rollback", eventState: "reverted", eventMode: "exact", createdAt: now,
			})
			insertSecurityRecoveryProof088(t, pool, scenario, securityRecoveryProofOptions088{
				config: scenario.previous, artifactDigest: scenario.previous.digest,
				deploymentAction: "rollback", eventMode: "missing", createdAt: now.Add(time.Second),
			})
		}},
		{name: "tied recovery rollouts", seed: func(t *testing.T, pool *pgxpool.Pool, scenario securityRecoveryScenario088) {
			now := time.Now().UTC().Truncate(time.Microsecond)
			for range 2 {
				insertSecurityRecoveryProof088(t, pool, scenario, securityRecoveryProofOptions088{
					config: scenario.previous, artifactDigest: scenario.previous.digest,
					deploymentAction: "rollback", eventState: "reverted", eventMode: "exact", createdAt: now,
				})
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pool := recoveryPool(t)
			scenario := seedSecurityRecoveryScenario088(t, pool)
			if test.seed != nil {
				test.seed(t, pool, scenario)
			}
			assertSecurityRecoveryOutcome088(t, pool, scenario.fixture.candidateID, false)
		})
	}

	t.Run("exact rollback reverted", func(t *testing.T) {
		pool := recoveryPool(t)
		scenario := seedSecurityRecoveryScenario088(t, pool)
		insertSecurityRecoveryProof088(t, pool, scenario, securityRecoveryProofOptions088{
			config: scenario.previous, artifactDigest: scenario.previous.digest,
			deploymentAction: "rollback", eventState: "reverted", eventMode: "exact",
		})
		assertSecurityRecoveryOutcome088(t, pool, scenario.fixture.candidateID, true)
	})
}

func TestSecurityPolicyActivation088ConcurrentReceiptMustCommitBeforeRecovery(t *testing.T) {
	pool := securityActivationBody088Pool(t)
	disableSecurityRecoveryProofGuards088(t, pool)
	scenario := seedSecurityRecoveryScenario088(t, pool)
	proof := insertSecurityRecoveryProof088(t, pool, scenario, securityRecoveryProofOptions088{
		config: scenario.previous, artifactDigest: scenario.previous.digest,
		deploymentAction: "rollback", eventMode: "missing",
	})
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := insertSecurityRecoveryStatusTx088(t, tx, scenario.previous, proof.deploymentID, 1, 1, "reverted"); err != nil {
		t.Fatal(err)
	}
	assertSecurityRecoveryOutcome088(t, pool, scenario.fixture.candidateID, false)
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	assertSecurityRecoveryOutcome088(t, pool, scenario.fixture.candidateID, true)
}

func TestSecurityPolicyActivation088TriggerErrorsUseStableSQLState(t *testing.T) {
	t.Run("candidate transition", func(t *testing.T) {
		pool := securityActivationBody088Pool(t)
		fixture := seedSecurityActivationCandidate088(t, pool)
		_, err := pool.Exec(t.Context(), `UPDATE security_policy_activation_candidates
			SET candidate_status='healthy',updated_at=clock_timestamp() WHERE id=$1`, fixture.candidateID)
		assertSecurityActivationCode088(t, err, "P8802")
	})
	t.Run("append only fact", func(t *testing.T) {
		pool := securityActivationBody088Pool(t)
		fixture := seedSecurityActivationCandidate088(t, pool)
		_, err := pool.Exec(t.Context(), `UPDATE security_policy_activation_config_facts
			SET created_at=created_at WHERE tenant_scope_id=$1 AND config_version_id=$2`,
			fixture.scopeID, fixture.configID)
		assertSecurityActivationCode088(t, err, "P8802")
	})
}

type securityRecoveryScenario088 struct {
	fixture             securityActivationFixture088
	previous            activeIdentityFixture087
	activationRolloutID uuid.UUID
}

type securityRecoveryProofOptions088 struct {
	config           activeIdentityFixture087
	artifactDigest   []byte
	deploymentAction string
	eventState       string
	eventMode        string
	createdAt        time.Time
}

type securityRecoveryProof088 struct {
	rolloutID, deploymentID uuid.UUID
	config                  activeIdentityFixture087
}

func seedSecurityRecoveryScenario088(t *testing.T, pool *pgxpool.Pool) securityRecoveryScenario088 {
	t.Helper()
	fixture := seedSecurityActivationCandidate088(t, pool)
	previous := seedActiveIdentityV7Observed087(t, pool, fixture.activeIdentityFixture087)
	scenario := securityRecoveryScenario088{
		fixture: fixture, previous: previous, activationRolloutID: uuid.New(),
	}
	deploymentID := uuid.New()
	now := time.Now().UTC().Truncate(time.Microsecond)
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `INSERT INTO rollouts(id,configuration_scope_id,config_version_id,
			action,status,idempotency_key,request_digest,request_id,correlation_id,activation_timeout_ms,
			observation_window_ms,required_consecutive_successes,deadline_at,created_at,queued_at,updated_at,
			contract_version) VALUES($1,$2,$3,'apply','queued',$4,$5,$6,$7,1000,1000,1,$8,$9,$9,$9,1)`,
			scenario.activationRolloutID, fixture.scopeID, fixture.configID, scenario.activationRolloutID.String(),
			make([]byte, sha256.Size), uuid.New(), uuid.New(), now.Add(time.Hour), now); err != nil {
			return err
		}
		command := []byte("088 recovery activation " + deploymentID.String())
		if _, err := tx.Exec(t.Context(), `INSERT INTO node_deployments(id,rollout_id,node_id,attempt,
			config_version_id,previous_config_version_id,action,state,command_event_id,command_bytes,
			command_sha256,deadline_at,created_at,updated_at) VALUES($1,$2,$3,1,$4,$5,'apply','healthy',
			$6,$7,$8,$9,$10,$10)`, deploymentID, scenario.activationRolloutID, fixture.nodeID,
			fixture.configID, previous.configID, uuid.New(), command, sha256Bytes087(command), now.Add(time.Hour), now); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO node_deployment_artifacts(deployment_id,
			deployment_attempt,config_version_id,artifact_id,ordinal) VALUES($1,1,$2,$3,1)`,
			deploymentID, fixture.configID, fixture.artifactID); err != nil {
			return err
		}
		if err := insertSecurityActivationStatus088(t, tx, fixture, deploymentID, 1, "healthy", now); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO security_policy_activation_rollouts(candidate_id,
			tenant_scope_id,phase,rollout_id,candidate_config_version_id,candidate_artifact_sha256,
			target_snapshot_sha256,node_ids,created_at) VALUES($1,$2,'canary',$3,$4,$5,$6,ARRAY[$7]::uuid[],$8)`,
			fixture.candidateID, fixture.scopeID, scenario.activationRolloutID, fixture.configID, fixture.digest,
			securityActivationTargetDigest088(fixture), fixture.nodeID, now)
		return err
	})
	if err != nil {
		t.Fatalf("seed recovery activation: %v", err)
	}
	payload := []byte("088 activation failed " + deploymentID.String())
	failureAt := now.Add(time.Millisecond)
	err = pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `INSERT INTO deployment_status_events(id,deployment_id,event_id,
			attempt,transition_sequence,state,payload,payload_sha256,occurred_at,received_at)
			VALUES($1,$2,$3,1,2,'failed',$4,$5,$6,$6)`, uuid.New(), deploymentID, uuid.New(), payload,
			sha256Bytes087(payload), failureAt); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `UPDATE node_config_state SET current_config_version_id=$2,
			current_config_identity_schema=1,current_config_artifact_sha256=$3,previous_config_version_id=NULL,
			previous_config_identity_schema=NULL,previous_config_artifact_sha256=NULL,updated_at=$4 WHERE node_id=$1`,
			fixture.nodeID, previous.configID, previous.digest, failureAt); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `UPDATE security_policy_activation_candidates
			SET candidate_status='canary',updated_at=$2 WHERE id=$1`, fixture.candidateID, failureAt); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `UPDATE security_policy_activation_candidates
			SET candidate_status='failed',updated_at=$2 WHERE id=$1`, fixture.candidateID, failureAt.Add(time.Microsecond))
		return err
	})
	if err != nil {
		t.Fatalf("fail recovery activation: %v", err)
	}
	return scenario
}

func insertSecurityRecoveryProof088(t *testing.T, pool *pgxpool.Pool, scenario securityRecoveryScenario088,
	options securityRecoveryProofOptions088,
) securityRecoveryProof088 {
	t.Helper()
	proof := securityRecoveryProof088{rolloutID: uuid.New(), deploymentID: uuid.New(), config: options.config}
	now := options.createdAt
	if now.IsZero() {
		now = time.Now().UTC().Truncate(time.Microsecond)
	}
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		requestID := uuid.New()
		if _, err := tx.Exec(t.Context(), `INSERT INTO rollouts(id,configuration_scope_id,config_version_id,
			action,status,idempotency_key,request_digest,request_id,correlation_id,activation_timeout_ms,
			observation_window_ms,required_consecutive_successes,deadline_at,created_at,queued_at,updated_at,
			contract_version) VALUES($1,$2,$3,'rollback','queued',$4,$5,$6,$7,1000,1000,1,$8,$9,$9,$9,1)`,
			proof.rolloutID, scenario.fixture.scopeID, options.config.configID, proof.rolloutID.String(),
			make([]byte, sha256.Size), requestID, uuid.New(), now.Add(time.Hour), now); err != nil {
			return err
		}
		previousConfigID := any(nil)
		deploymentState := "healthy"
		if options.deploymentAction == "rollback" {
			previousConfigID = scenario.fixture.configID
			deploymentState = "reverted"
		}
		if options.eventState == "failed" {
			deploymentState = "failed"
		}
		command := []byte("088 recovery proof " + proof.deploymentID.String())
		if _, err := tx.Exec(t.Context(), `INSERT INTO node_deployments(id,rollout_id,node_id,attempt,
			config_version_id,previous_config_version_id,action,state,command_event_id,command_bytes,
			command_sha256,deadline_at,created_at,updated_at) VALUES($1,$2,$3,1,$4,$5,$6,$7,$8,$9,$10,$11,$12,$12)`,
			proof.deploymentID, proof.rolloutID, scenario.fixture.nodeID, options.config.configID, previousConfigID,
			options.deploymentAction, deploymentState, uuid.New(), command, sha256Bytes087(command), now.Add(time.Hour), now); err != nil {
			return err
		}
		if options.deploymentAction == "apply" {
			if _, err := tx.Exec(t.Context(), `INSERT INTO node_deployment_artifacts(deployment_id,
				deployment_attempt,config_version_id,artifact_id,ordinal) VALUES($1,1,$2,$3,1)`,
				proof.deploymentID, options.config.configID, options.config.artifactID); err != nil {
				return err
			}
		}
		if options.eventMode == "exact" {
			if err := insertSecurityRecoveryStatusTx088(t, tx, options.config, proof.deploymentID, 1, 1,
				options.eventState); err != nil {
				return err
			}
		} else if options.eventMode == "mismatched" {
			if err := seedSecurityRecoveryDecoy088(t, tx, scenario, options.config, now); err != nil {
				return err
			}
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO security_policy_activation_recovery_rollouts(candidate_id,
			tenant_scope_id,rollout_id,recovery_config_version_id,recovery_artifact_sha256,target_snapshot_sha256,
			node_ids,request_id,created_at) VALUES($1,$2,$3,$4,$5,$6,ARRAY[$7]::uuid[],$8,$9)`,
			scenario.fixture.candidateID, scenario.fixture.scopeID, proof.rolloutID, options.config.configID,
			options.artifactDigest, securityActivationTargetDigest088(scenario.fixture), scenario.fixture.nodeID,
			requestID, now)
		return err
	})
	if err != nil {
		t.Fatalf("insert recovery proof: %v", err)
	}
	return proof
}

func appendSecurityRecoveryStatus088(t *testing.T, pool *pgxpool.Pool, scenario securityRecoveryScenario088,
	proof securityRecoveryProof088, attempt int, sequence int64, state string,
) {
	t.Helper()
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		return insertSecurityRecoveryStatusTx088(t, tx, proof.config, proof.deploymentID, attempt, sequence, state)
	})
	if err != nil {
		t.Fatalf("append recovery status: %v", err)
	}
}

func appendSecurityRecoveryAttempt088(t *testing.T, pool *pgxpool.Pool, scenario securityRecoveryScenario088,
	proof securityRecoveryProof088, attempt int, state string,
) {
	t.Helper()
	deploymentID := uuid.New()
	now := time.Now().UTC().Truncate(time.Microsecond)
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		command := []byte("088 competing recovery " + deploymentID.String())
		if _, err := tx.Exec(t.Context(), `INSERT INTO node_deployments(id,rollout_id,node_id,attempt,
			config_version_id,previous_config_version_id,action,state,command_event_id,command_bytes,
			command_sha256,deadline_at,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,'rollback',$7,
			$8,$9,$10,$11,$12,$12)`, deploymentID, proof.rolloutID, scenario.fixture.nodeID, attempt,
			proof.config.configID, scenario.fixture.configID, state, uuid.New(), command, sha256Bytes087(command),
			now.Add(time.Hour), now); err != nil {
			return err
		}
		return insertSecurityRecoveryStatusTx088(t, tx, proof.config, deploymentID, attempt, 1, state)
	})
	if err != nil {
		t.Fatalf("append competing recovery attempt: %v", err)
	}
}

func seedSecurityRecoveryDecoy088(t *testing.T, tx pgx.Tx, scenario securityRecoveryScenario088,
	config activeIdentityFixture087, now time.Time,
) error {
	t.Helper()
	rolloutID, deploymentID := uuid.New(), uuid.New()
	if _, err := tx.Exec(t.Context(), `INSERT INTO rollouts(id,configuration_scope_id,config_version_id,
		action,status,idempotency_key,request_digest,request_id,correlation_id,activation_timeout_ms,
		observation_window_ms,required_consecutive_successes,deadline_at,created_at,queued_at,updated_at,
		contract_version) VALUES($1,$2,$3,'rollback','queued',$4,$5,$6,$7,1000,1000,1,$8,$9,$9,$9,0)`,
		rolloutID, scenario.fixture.scopeID, config.configID, rolloutID.String(), make([]byte, sha256.Size),
		uuid.New(), uuid.New(), now.Add(time.Hour), now); err != nil {
		return err
	}
	command := []byte("088 recovery decoy " + deploymentID.String())
	if _, err := tx.Exec(t.Context(), `INSERT INTO node_deployments(id,rollout_id,node_id,attempt,
		config_version_id,previous_config_version_id,action,state,command_event_id,command_bytes,
		command_sha256,deadline_at,created_at,updated_at) VALUES($1,$2,$3,1,$4,$5,'rollback','reverted',
		$6,$7,$8,$9,$10,$10)`, deploymentID, rolloutID, scenario.fixture.nodeID, config.configID,
		scenario.fixture.configID, uuid.New(), command, sha256Bytes087(command), now.Add(time.Hour), now); err != nil {
		return err
	}
	return insertSecurityRecoveryStatusTx088(t, tx, config, deploymentID, 1, 1, "reverted")
}

func insertSecurityRecoveryStatusTx088(t *testing.T, tx pgx.Tx, config activeIdentityFixture087,
	deploymentID uuid.UUID, attempt int, sequence int64, state string,
) error {
	t.Helper()
	payload := []byte(fmt.Sprintf("088 recovery status %s/%d/%d/%s", deploymentID, attempt, sequence, state))
	now := time.Now().UTC().Truncate(time.Microsecond)
	if state == "reverted" {
		_, err := tx.Exec(t.Context(), `INSERT INTO deployment_status_events(id,deployment_id,event_id,attempt,
			transition_sequence,state,payload,payload_sha256,occurred_at,received_at,
			active_config_identity_api_version,active_config_identity_schema,active_config_version_id,
			active_config_artifact_sha256) VALUES($1,$2,$3,$4,$5,'reverted',$6,$7,$8,$8,1,1,$9,$10)`,
			uuid.New(), deploymentID, uuid.New(), attempt, sequence, payload, sha256Bytes087(payload), now,
			config.configID, config.digest)
		return err
	}
	_, err := tx.Exec(t.Context(), `INSERT INTO deployment_status_events(id,deployment_id,event_id,attempt,
		transition_sequence,state,payload,payload_sha256,occurred_at,received_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$9)`, uuid.New(), deploymentID, uuid.New(), attempt,
		sequence, state, payload, sha256Bytes087(payload), now)
	return err
}

func disableSecurityRecoveryProofGuards088(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	for _, statement := range []string{
		`ALTER TABLE security_policy_activation_recovery_rollouts DISABLE TRIGGER security_policy_activation_recovery_rollouts_validate`,
		`ALTER TABLE node_deployments DISABLE TRIGGER node_deployments_attempt_046`,
		`ALTER TABLE node_deployments DISABLE TRIGGER node_deployments_fact_046`,
	} {
		if _, err := pool.Exec(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, statement := range []string{
			`ALTER TABLE node_deployments ENABLE TRIGGER node_deployments_fact_046`,
			`ALTER TABLE node_deployments ENABLE TRIGGER node_deployments_attempt_046`,
			`ALTER TABLE security_policy_activation_recovery_rollouts ENABLE TRIGGER security_policy_activation_recovery_rollouts_validate`,
		} {
			if _, err := pool.Exec(ctx, statement); err != nil {
				t.Errorf("restore recovery proof trigger: %v", err)
			}
		}
	})
}

func assertSecurityRecoveryOutcome088(t *testing.T, pool *pgxpool.Pool, candidateID uuid.UUID, want bool) {
	t.Helper()
	var got bool
	if err := pool.QueryRow(t.Context(), `SELECT security_policy_activation_recovered_088($1)`, candidateID).
		Scan(&got); err != nil {
		t.Fatal(err)
	}
	recoveredAt := time.Now().UTC().Add(time.Second)
	_, err := pool.Exec(t.Context(), `UPDATE security_policy_activation_candidates
		SET recovered_at=$2,updated_at=$2 WHERE id=$1`, candidateID, recoveredAt)
	if want {
		if !got || err != nil {
			t.Fatalf("exact recovery result/update = %t/%v, want true/nil", got, err)
		}
		return
	}
	if got {
		t.Errorf("unproven recovery returned true")
	}
	assertSecurityActivationCode088(t, err, "P8802")
}

func securityActivationTargetDigest088(fixture securityActivationFixture088) []byte {
	return sha256Bytes087([]byte("088 target " + fixture.targetSnapshotID.String()))
}

type securityActivationFixture088 struct {
	activeIdentityFixture087
	scopeID, userID, candidateID, targetSnapshotID uuid.UUID
}

func securityActivationBody088Pool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool := packageCommerceRBAC079Pool(t, 87)
	script, err := fs.ReadFile(controlmigrations.FS, "088_security_policy_activation.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	marker := "CREATE FUNCTION valid_security_activation_nodes_088"
	start := strings.Index(string(script), marker)
	if start < 0 {
		t.Fatalf("088 body marker %q not found", marker)
	}
	if _, err := pool.Exec(t.Context(), string(script[start:])); err != nil {
		t.Fatalf("apply isolated 088 body: %v", err)
	}
	return pool
}

func seedSecurityActivationCandidate088(t *testing.T, pool *pgxpool.Pool) securityActivationFixture088 {
	t.Helper()
	identity := seedActiveIdentity087(t, pool)
	fixture := securityActivationFixture088{
		activeIdentityFixture087: identity,
		candidateID:              uuid.New(),
		targetSnapshotID:         uuid.New(),
	}
	var tenantID uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT node.scope_id,node.created_by_user_id,scope.tenant_id
		FROM nodes node JOIN access_scopes scope ON scope.id=node.scope_id WHERE node.id=$1`, identity.nodeID).
		Scan(&fixture.scopeID, &fixture.userID, &tenantID); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	siteID, policyID, bindingID, publicationID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	requestDigest := sha256Bytes087([]byte("088 activation request " + fixture.candidateID.String()))
	targetDigest := sha256Bytes087([]byte("088 target " + fixture.targetSnapshotID.String()))
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		statements := []struct {
			query string
			args  []any
		}{
			{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{fixture.scopeID, fixture.userID}},
			{`INSERT INTO sites(id,scope_id,owner_user_id,domain,origins,origin_hosts,created_by_user_id,
				updated_by_user_id,created_at,updated_at) VALUES($1,$2,$3,$4,ARRAY['127.0.0.1'],ARRAY['origin'],
				$3,$3,$5,$5)`, []any{siteID, fixture.scopeID, fixture.userID, "activation-" + siteID.String() + ".example", now}},
			{`INSERT INTO site_origin_pools(site_id,updated_at) VALUES($1,$2)`, []any{siteID, now}},
			{`INSERT INTO site_origins(site_id,position,host,port) VALUES($1,1,'origin',80)`, []any{siteID}},
			{`INSERT INTO security_policies(id,scope_id,tenant_id,owner_user_id,kind,name,default_action,rules,
				created_by_user_id,updated_by_user_id,created_at,updated_at)
				VALUES($1,$2,$3,$4,'waf',$5,'allow','[{}]'::jsonb,$4,$4,$6,$6)`, []any{policyID, fixture.scopeID, tenantID, fixture.userID, "activation-" + policyID.String(), now}},
			{`INSERT INTO security_policy_versions(policy_id,revision,document,created_by_user_id,created_at)
				VALUES($1,1,'{}'::jsonb,$2,$3)`, []any{policyID, fixture.userID, now}},
			{`INSERT INTO security_policy_site_bindings(id,tenant_scope_id,site_id,policy_id,policy_kind,
				revision,created_at,updated_at) VALUES($1,$2,$3,$4,'waf',0,$5,$5)`, []any{bindingID, fixture.scopeID, siteID, policyID, now}},
			{`INSERT INTO security_policy_publications(id,binding_id,tenant_scope_id,site_id,policy_id,policy_kind,
				policy_version,expected_binding_revision,binding_revision,expected_active_version,rollout_id,
				idempotency_key,request_digest,plan_request_digest,canonical_payload,canonical_payload_sha256,
				runtime_snapshot_sha256,bundle_bytes,bundle_sha256,signing_key_id,issued_at,expires_at,
				actor_scope_id,actor_user_id,request_id,created_at)
				VALUES($1,$2,$3,$4,$5,'waf',1,0,1,0,$6,$7,$8,$8,$9,$10,$11,$9,$10,$12,$13,$14,$3,$15,$16,$13)`,
				[]any{publicationID, bindingID, fixture.scopeID, siteID, policyID, uuid.New(), "activation-" + publicationID.String(), requestDigest,
					[]byte("088 publication"), sha256Bytes087([]byte("088 publication")), targetDigest, "088-signing-key", now, now.Add(time.Hour), fixture.userID,
					"activation-" + publicationID.String()}},
			{`UPDATE security_policy_site_bindings SET revision=1,last_claimed_policy_version=1,
				last_bundle_id=$2,updated_at=$3 WHERE id=$1`, []any{bindingID, publicationID, now}},
			{`INSERT INTO security_policy_activation_config_facts(tenant_scope_id,config_version_id,
				artifact_sha256,policy_kind,required_capabilities,created_at)
				VALUES($1,$2,$3,'waf','["waf.v1"]'::jsonb,$4)`, []any{fixture.scopeID, identity.configID, identity.digest, now}},
			{`INSERT INTO security_policy_activation_candidates(id,tenant_scope_id,site_id,binding_id,
				binding_revision,last_bundle_id,last_claimed_policy_version,expected_active_policy_version,
				candidate_source_revision,candidate_config_version_id,candidate_artifact_sha256,
				target_snapshot_sha256,required_capabilities,candidate_status,canary_node_ids,expand_node_ids,
				idempotency_key,request_digest,request_id,actor_scope_id,actor_user_id,expires_at,created_at,updated_at)
				VALUES($1,$2,$3,$4,1,$5,1,0,2,$6,$7,$8,'["waf.v1"]'::jsonb,'claimed',ARRAY[$9]::uuid[],
				'{}'::uuid[],$10,$11,$12,$2,$13,$14,$15,$15)`, []any{fixture.candidateID, fixture.scopeID, siteID, bindingID,
				publicationID, identity.configID, identity.digest, targetDigest, identity.nodeID,
				"activation-" + fixture.candidateID.String(), requestDigest, "activation-" + fixture.candidateID.String(),
				fixture.userID, now.Add(time.Hour), now}},
		}
		for _, statement := range statements {
			if _, err := tx.Exec(t.Context(), statement.query, statement.args...); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("seed 088 activation candidate: %v", err)
	}
	return fixture
}

func insertSecurityActivationRollout088(t *testing.T, pool *pgxpool.Pool,
	fixture securityActivationFixture088, rolloutAction, deploymentAction string, attempt int,
	eventState, eventMode string, activation bool,
) error {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	rolloutID, deploymentID, requestID := uuid.New(), uuid.New(), uuid.New()
	return pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `INSERT INTO rollouts(id,configuration_scope_id,config_version_id,
			action,status,idempotency_key,request_digest,request_id,correlation_id,activation_timeout_ms,
			observation_window_ms,required_consecutive_successes,deadline_at,created_at,queued_at,updated_at,
			contract_version) VALUES($1,$2,$3,$4,'queued',$5,$6,$7,$8,1000,1000,1,$9,$10,$10,$10,1)`,
			rolloutID, fixture.scopeID, fixture.configID, rolloutAction, rolloutID.String(), make([]byte, sha256.Size),
			requestID, uuid.New(), now.Add(time.Hour), now); err != nil {
			return err
		}
		previousConfigID := any(nil)
		deploymentState := "healthy"
		if deploymentAction == "rollback" {
			previousConfigID = fixture.configID
			deploymentState = "reverted"
		}
		command := []byte("088 deployment " + deploymentID.String())
		if _, err := tx.Exec(t.Context(), `INSERT INTO node_deployments(id,rollout_id,node_id,attempt,
			config_version_id,previous_config_version_id,action,state,command_event_id,command_bytes,
			command_sha256,deadline_at,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$13)`,
			deploymentID, rolloutID, fixture.nodeID, attempt, fixture.configID, previousConfigID, deploymentAction,
			deploymentState, uuid.New(), command, sha256Bytes087(command), now.Add(time.Hour), now); err != nil {
			return err
		}
		if deploymentAction == "apply" {
			if _, err := tx.Exec(t.Context(), `INSERT INTO node_deployment_artifacts(deployment_id,
				deployment_attempt,config_version_id,artifact_id,ordinal) VALUES($1,$2,$3,$4,1)`,
				deploymentID, attempt, fixture.configID, fixture.artifactID); err != nil {
				return err
			}
		}
		if eventMode == "mismatched" {
			decoyAction, decoyState := "apply", "healthy"
			if rolloutAction == "rollback" {
				decoyAction, decoyState = "rollback", "reverted"
			}
			if _, err := seedSecurityActivationEventDeployment088(t, tx, fixture, decoyAction, decoyState, now); err != nil {
				return err
			}
		} else if eventMode == "exact" {
			if err := insertSecurityActivationStatus088(t, tx, fixture, deploymentID, attempt, eventState, now); err != nil {
				return err
			}
		}
		if activation || rolloutAction == "apply" {
			_, err := tx.Exec(t.Context(), `INSERT INTO security_policy_activation_rollouts(candidate_id,
				tenant_scope_id,phase,rollout_id,candidate_config_version_id,candidate_artifact_sha256,
				target_snapshot_sha256,node_ids,created_at) VALUES($1,$2,'canary',$3,$4,$5,$6,ARRAY[$7]::uuid[],$8)`,
				fixture.candidateID, fixture.scopeID, rolloutID, fixture.configID, fixture.digest,
				sha256Bytes087([]byte("088 target "+fixture.targetSnapshotID.String())), fixture.nodeID, now)
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO security_policy_activation_recovery_rollouts(candidate_id,
			tenant_scope_id,rollout_id,recovery_config_version_id,recovery_artifact_sha256,target_snapshot_sha256,
			node_ids,request_id,created_at) VALUES($1,$2,$3,$4,$5,$6,ARRAY[$7]::uuid[],$8,$9)`,
			fixture.candidateID, fixture.scopeID, rolloutID, fixture.configID, fixture.digest,
			sha256Bytes087([]byte("088 target "+fixture.targetSnapshotID.String())), fixture.nodeID, requestID, now)
		return err
	})
}

func seedSecurityActivationEventDeployment088(t *testing.T, tx pgx.Tx, fixture securityActivationFixture088,
	action, state string, now time.Time,
) (uuid.UUID, error) {
	t.Helper()
	rolloutID, deploymentID := uuid.New(), uuid.New()
	if _, err := tx.Exec(t.Context(), `INSERT INTO rollouts(id,configuration_scope_id,config_version_id,action,
		status,idempotency_key,request_digest,request_id,correlation_id,activation_timeout_ms,observation_window_ms,
		required_consecutive_successes,deadline_at,created_at,queued_at,updated_at,contract_version)
		VALUES($1,$2,$3,$4,'queued',$5,$6,$7,$8,1000,1000,1,$9,$10,$10,$10,0)`, rolloutID, fixture.scopeID,
		fixture.configID, action, rolloutID.String(), make([]byte, sha256.Size), uuid.New(), uuid.New(), now.Add(time.Hour), now); err != nil {
		return uuid.Nil, err
	}
	previousConfigID := any(nil)
	if action == "rollback" {
		previousConfigID = fixture.configID
	}
	command := []byte("088 decoy deployment " + deploymentID.String())
	if _, err := tx.Exec(t.Context(), `INSERT INTO node_deployments(id,rollout_id,node_id,attempt,config_version_id,
		previous_config_version_id,action,state,command_event_id,command_bytes,command_sha256,deadline_at,created_at,updated_at)
		VALUES($1,$2,$3,1,$4,$5,$6,$7,$8,$9,$10,$11,$12,$12)`, deploymentID, rolloutID, fixture.nodeID,
		fixture.configID, previousConfigID, action, state, uuid.New(), command, sha256Bytes087(command), now.Add(time.Hour), now); err != nil {
		return uuid.Nil, err
	}
	if action == "apply" {
		if _, err := tx.Exec(t.Context(), `INSERT INTO node_deployment_artifacts(deployment_id,deployment_attempt,
			config_version_id,artifact_id,ordinal) VALUES($1,1,$2,$3,1)`, deploymentID, fixture.configID,
			fixture.artifactID); err != nil {
			return uuid.Nil, err
		}
	}
	return deploymentID, insertSecurityActivationStatus088(t, tx, fixture, deploymentID, 1, state, now)
}

func insertSecurityActivationStatus088(t *testing.T, tx pgx.Tx, fixture securityActivationFixture088,
	deploymentID uuid.UUID, attempt int, state string, now time.Time,
) error {
	t.Helper()
	payload := []byte("088 status " + deploymentID.String() + state)
	if state == "healthy" || state == "reverted" {
		_, err := tx.Exec(t.Context(), `INSERT INTO deployment_status_events(id,deployment_id,event_id,attempt,
			transition_sequence,state,payload,payload_sha256,occurred_at,received_at,
			active_config_identity_api_version,active_config_identity_schema,active_config_version_id,
			active_config_artifact_sha256) VALUES($1,$2,$3,$4,1,$5,$6,$7,$8,$8,1,1,$9,$10)`, uuid.New(),
			deploymentID, uuid.New(), attempt, state, payload, sha256Bytes087(payload), now, fixture.configID, fixture.digest)
		return err
	}
	_, err := tx.Exec(t.Context(), `INSERT INTO deployment_status_events(id,deployment_id,event_id,attempt,
		transition_sequence,state,payload,payload_sha256,occurred_at,received_at)
		VALUES($1,$2,$3,$4,1,$5,$6,$7,$8,$8)`, uuid.New(), deploymentID, uuid.New(), attempt, state,
		payload, sha256Bytes087(payload), now)
	return err
}

func assertSecurityActivationCall088(t *testing.T, err error, wantError bool, message string) {
	t.Helper()
	if wantError {
		if err == nil || !strings.Contains(err.Error(), message) {
			t.Fatalf("error = %v, want %q", err, message)
		}
		assertSecurityActivationCode088(t, err, "P8802")
		return
	}
	if err != nil {
		t.Fatalf("valid state-bound identity rejected: %v", err)
	}
}

func assertSecurityActivationCode088(t *testing.T, err error, want string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != want {
		t.Fatalf("SQLSTATE = %v, want %s (error=%v)", func() string {
			if pgErr == nil {
				return ""
			}
			return pgErr.Code
		}(), want, err)
	}
}

func assertSecurityActivation088Tables(t *testing.T, pool *pgxpool.Pool, want bool) {
	t.Helper()
	var exists bool
	if err := pool.QueryRow(t.Context(), `SELECT to_regclass('security_policy_activation_candidates') IS NOT NULL`).
		Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if exists != want {
		t.Fatalf("088 activation tables exist = %t, want %t", exists, want)
	}
}
