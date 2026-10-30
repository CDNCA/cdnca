//go:build integration

package securityactivation

import (
	"testing"
	"time"

	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/edgestatus"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// End to end through the deployment state machine: every node report goes
// through the gateway's status path (edgestatus Validator.Decode and
// Store.Project, which advance node_deployments and node_config_state and
// fire the activation's recovery triggers), as a 1.0.35 agent sends it.

type v2NodeReporter struct {
	t         *testing.T
	fixture   v2ActivationFixture
	store     *edgestatus.Store
	validator *edgestatus.Validator
}

func newV2NodeReporter(t *testing.T, fixture v2ActivationFixture) *v2NodeReporter {
	t.Helper()
	store, err := edgestatus.NewStore(fixture.pool)
	if err != nil {
		t.Fatal(err)
	}
	validator, err := edgestatus.NewValidator(edgestatus.DefaultValidatorConfig())
	if err != nil {
		t.Fatal(err)
	}
	return &v2NodeReporter{t: t, fixture: fixture, store: store, validator: validator}
}

// dispatch marks the deployment's command published, as the outbox relay does.
func (reporter *v2NodeReporter) dispatch(deploymentID uuid.UUID) {
	reporter.t.Helper()
	for _, statement := range []string{
		`UPDATE edge_command_outbox SET status='publishing',updated_at=now() WHERE deployment_id=$1 AND deployment_attempt=1 AND status='pending'`,
		`UPDATE edge_command_outbox SET status='published',published_at=now(),updated_at=now() WHERE deployment_id=$1 AND deployment_attempt=1 AND status='publishing'`,
	} {
		if _, err := reporter.fixture.pool.Exec(reporter.t.Context(), statement, deploymentID); err != nil {
			reporter.t.Fatal(err)
		}
	}
}

// report sends the node's transitions for its deployment in rollout; the
// last carries the active config identity (configID, digest) when set.
func (reporter *v2NodeReporter) report(rolloutID, nodeID uuid.UUID, identityConfigID uuid.UUID, digest []byte,
	states ...agentv1.NodeDeploymentState) {
	reporter.t.Helper()
	var deploymentID, configID uuid.UUID
	var commandBytes []byte
	if err := reporter.fixture.pool.QueryRow(reporter.t.Context(), `SELECT id,config_version_id,command_bytes
		FROM node_deployments WHERE rollout_id=$1 AND node_id=$2 AND attempt=1`, rolloutID, nodeID).
		Scan(&deploymentID, &configID, &commandBytes); err != nil {
		reporter.t.Fatalf("node %s has no deployment in rollout %s: %v", nodeID, rolloutID, err)
	}
	command := new(agentv1.DeploymentCommand)
	if err := proto.Unmarshal(commandBytes, command); err != nil {
		reporter.t.Fatal(err)
	}
	reporter.dispatch(deploymentID)
	var sequence uint64
	if err := reporter.fixture.pool.QueryRow(reporter.t.Context(), `SELECT COALESCE(max(transition_sequence),0)
		FROM deployment_status_events WHERE deployment_id=$1 AND attempt=1`, deploymentID).Scan(&sequence); err != nil {
		reporter.t.Fatal(err)
	}
	for index, state := range states {
		causationID := command.Event.EventId
		status := &agentv1.DeploymentStatus{
			Event: &commonv1.EventMetadata{
				EventId: uuid.NewString(), RequestId: command.Event.RequestId, OccurredTime: timestamppb.Now(),
				CausationId: &causationID, CorrelationId: command.Event.CorrelationId,
				Traceparent: command.Event.Traceparent, TaskId: command.Event.TaskId,
			},
			DeploymentId: deploymentID.String(), Attempt: 1, ConfigVersionId: configID.String(),
			State: state, TransitionSequence: sequence + uint64(index) + 1,
			ActiveConfigIdentityCapability: &agentv1.Capability{
				Name: agentv1.CapabilityName_CAPABILITY_NAME_ACTIVE_CONFIG_IDENTITY, ApiVersion: 1,
			},
			// A failed apply leaves the node on its running config.
			RunningConfigUnchanged: state == agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED,
		}
		if state == agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED {
			status.Error = &commonv1.ProtocolError{Code: commonv1.ErrorCode_ERROR_CODE_UNAVAILABLE, Message: "precheck failed"}
		}
		if index == len(states)-1 && identityConfigID != uuid.Nil {
			status.ActiveConfigIdentity = &agentv1.ActiveConfigIdentity{
				Schema:          agentv1.ActiveConfigIdentitySchema_ACTIVE_CONFIG_IDENTITY_SCHEMA_V1,
				ConfigVersionId: identityConfigID.String(), ArtifactSha256: append([]byte(nil), digest...),
			}
			// The agent's runtime probe accompanies a terminal identity
			// (edgestatus requireTerminalConfigConvergence).
			status.Checks = []*agentv1.CheckResult{{Name: "edge_active_config_probe", Succeeded: true,
				Summary: "active config runtime probe passed", LatencyDuration: durationpb.New(time.Millisecond)}}
		}
		payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(status)
		if err != nil {
			reporter.t.Fatal(err)
		}
		envelope, err := reporter.validator.Decode(edgestatus.DefaultSubjectPrefix+"."+nodeID.String(), payload)
		if err != nil {
			reporter.t.Fatalf("decode %s: %v", state, err)
		}
		result, err := reporter.store.Project(reporter.t.Context(), envelope)
		if err != nil || result.Outcome != edgestatus.OutcomeAdvanced {
			reporter.t.Fatalf("project node %s %s = (%+v, %v)", nodeID, state, result, err)
		}
	}
}

var (
	v2ApplyHealthy = []agentv1.NodeDeploymentState{
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STAGED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_PRECHECKED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ACTIVATED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY,
	}
	v2ApplyFailedPrecheck = []agentv1.NodeDeploymentState{
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STAGED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED,
	}
	v2RollbackReverted = []agentv1.NodeDeploymentState{
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STAGED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_PRECHECKED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_REVERTING,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_REVERTED,
	}
)

func nodeRunning(t *testing.T, fixture v2ActivationFixture, nodeID uuid.UUID) (uuid.UUID, []byte) {
	t.Helper()
	var configID uuid.UUID
	var digest []byte
	if err := fixture.pool.QueryRow(t.Context(), `SELECT current_config_version_id,current_config_artifact_sha256
		FROM node_config_state WHERE node_id=$1`, nodeID).Scan(&configID, &digest); err != nil {
		t.Fatal(err)
	}
	return configID, digest
}

// Success: canary and expand nodes each report healthy running their own
// artifact; the candidate promotes and both nodes run it.
//
// Each phase rollout reaching terminal runs edgedeployment
// projectSiteIPv6RolloutTerminalTx (UPDATE sites ipv6_runtime_*); before
// migration 335 that advanced the scope's source_revision and Promote's CAS
// (source_revision = candidate - 1) failed. This runs the real projection.
func TestSiteRuntimeV2ActivationStateMachinePromotes(t *testing.T) {
	fixture := newV2ActivationFixture(t)
	store := newProductionActivationStore(t, fixture.activationFixture)
	reporter := newV2NodeReporter(t, fixture)
	input, candidate := startV2Activation(t, fixture, store, "v2-state-machine-promote", 1)
	artifacts := loadV2NodeArtifacts(t, fixture, candidate)
	canary, expand := candidate.CanaryNodeIDs[0], candidate.ExpandNodeIDs[0]

	reporter.report(productionPhaseRolloutID(t, fixture.pool, candidate.ID, "canary"), canary,
		candidate.CandidateConfigVersionID, digestBytes(artifacts[canary].digest), v2ApplyHealthy...)
	expanded, err := store.Reconcile(t.Context(), fixture.actor, productionReconcileInput(candidate, "sm-canary"))
	if err != nil || expanded.Action != string(actionExpand) {
		t.Fatalf("canary Reconcile = (%+v, %v)", expanded, err)
	}
	reporter.report(productionPhaseRolloutID(t, fixture.pool, candidate.ID, "expand"), expand,
		candidate.CandidateConfigVersionID, digestBytes(artifacts[expand].digest), v2ApplyHealthy...)
	promoted, err := store.Reconcile(t.Context(), fixture.actor, productionReconcileInput(candidate, "sm-expand"))
	if err != nil || promoted.Action != string(actionPromote) || promoted.Candidate.Status != StatusPromoted {
		t.Fatalf("expand Reconcile = (%+v, %v)", promoted, err)
	}
	for _, nodeID := range []uuid.UUID{canary, expand} {
		configID, digest := nodeRunning(t, fixture, nodeID)
		if configID != candidate.CandidateConfigVersionID || [32]byte(digest) != artifacts[nodeID].digest {
			t.Fatalf("node %s runs %s/%x, want its candidate artifact", nodeID, configID, digest)
		}
	}
	assertBindingActiveAndSource(t, fixture.activationFixture, input.PolicyVersion, fixture.sourceRevision+1)
}

// Failure recovery: the canary runs the candidate healthy, the expand node's
// precheck fails. The candidate fails; the canary, now running the candidate,
// is rolled back to the previous config and reports reverted; the candidate
// is recovered and the binding keeps the previous policy. The expand node,
// which never loaded the candidate, gets no rollback.
func TestSiteRuntimeV2ActivationStateMachineRecoversAfterExpandFailure(t *testing.T) {
	fixture := newV2ActivationFixture(t)
	store := newProductionActivationStore(t, fixture.activationFixture)
	reporter := newV2NodeReporter(t, fixture)
	_, candidate := startV2Activation(t, fixture, store, "v2-state-machine-recover", 1)
	artifacts := loadV2NodeArtifacts(t, fixture, candidate)
	canary, expand := candidate.CanaryNodeIDs[0], candidate.ExpandNodeIDs[0]

	reporter.report(productionPhaseRolloutID(t, fixture.pool, candidate.ID, "canary"), canary,
		candidate.CandidateConfigVersionID, digestBytes(artifacts[canary].digest), v2ApplyHealthy...)
	if result, err := store.Reconcile(t.Context(), fixture.actor, productionReconcileInput(candidate, "sm-r-canary")); err != nil ||
		result.Action != string(actionExpand) {
		t.Fatalf("canary Reconcile = (%+v, %v)", result, err)
	}
	reporter.report(productionPhaseRolloutID(t, fixture.pool, candidate.ID, "expand"), expand, uuid.Nil, nil,
		v2ApplyFailedPrecheck...)
	failed, err := store.Reconcile(t.Context(), fixture.actor, productionReconcileInput(candidate, "sm-r-expand-failed"))
	if err != nil || failed.Action != string(actionFail) || failed.Candidate.Status != StatusFailed {
		t.Fatalf("expand failure Reconcile = (%+v, %v)", failed, err)
	}
	if configID, _ := nodeRunning(t, fixture, expand); configID != fixture.previousConfigID {
		t.Fatalf("failed expand node runs %s, want the previous config", configID)
	}
	var recoveryRollout uuid.UUID
	var nodes []uuid.UUID
	if err := fixture.pool.QueryRow(t.Context(), `SELECT rollout_id,node_ids FROM security_policy_activation_recovery_rollouts
		WHERE candidate_id=$1`, candidate.ID).Scan(&recoveryRollout, &nodes); err != nil {
		t.Fatalf("no recovery rollout: %v", err)
	}
	if len(nodes) != 1 || nodes[0] != canary {
		t.Fatalf("recovery rollout nodes = %v, want only the canary %s", nodes, canary)
	}
	reporter.report(recoveryRollout, canary, fixture.previousConfigID, fixture.previousArtifactDigest[:], v2RollbackReverted...)
	recovered, err := store.Reconcile(t.Context(), fixture.actor, productionReconcileInput(candidate, "sm-r-recovered"))
	if err != nil || recovered.Action != string(actionRecover) || recovered.Candidate.RecoveredAt == nil {
		t.Fatalf("recovery Reconcile = (%+v, %v)", recovered, err)
	}
	if configID, digest := nodeRunning(t, fixture, canary); configID != fixture.previousConfigID ||
		[32]byte(digest) != fixture.previousArtifactDigest {
		t.Fatalf("recovered canary runs %s/%x, want the previous config", configID, digest)
	}
	// The binding keeps the previous policy and the IPv6 projection of the
	// phase and recovery rollouts left the scope's source_revision alone.
	assertBindingActiveAndSource(t, fixture.activationFixture, 1, fixture.sourceRevision)
}

func digestBytes(digest [32]byte) []byte { return digest[:] }
