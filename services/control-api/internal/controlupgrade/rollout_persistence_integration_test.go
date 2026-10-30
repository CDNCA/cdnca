//go:build integration

package controlupgrade

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestStoreImplementsRolloutPersistence(t *testing.T) {
	store := NewStore(nil, nil, nil, time.Now)
	if _, ok := any(store).(RolloutPersistence); !ok {
		t.Fatal("production Store does not implement RolloutPersistence")
	}
	if _, ok := reflect.TypeOf((*RolloutPersistence)(nil)).Elem().MethodByName("CreatePlan"); ok {
		t.Fatal("RolloutPersistence still exposes the unbound direct create path")
	}
	if _, ok := reflect.TypeOf(store).MethodByName("CreatePlan"); ok {
		t.Fatal("production Store still exposes the unbound direct create path")
	}
}

type agentRolloutStatusV1 struct {
	Schema                 string    `json:"schema"`
	StatusID               string    `json:"status_id"`
	StatusRevision         uint64    `json:"status_revision"`
	CommandID              string    `json:"command_id"`
	PlanID                 string    `json:"plan_id"`
	PlanRevision           uint64    `json:"plan_revision"`
	InstallationID         string    `json:"installation_id"`
	NodeID                 string    `json:"node_id"`
	CommandSHA256          string    `json:"command_sha256"`
	State                  string    `json:"state"`
	CurrentVersion         string    `json:"current_version"`
	PreviousVersion        string    `json:"previous_version"`
	InstallerTransactionID string    `json:"installer_transaction_id"`
	ErrorCode              string    `json:"error_code"`
	AlertRequired          bool      `json:"alert_required"`
	ObservedAt             time.Time `json:"observed_at"`
}

func TestRollbackCommandBindsDedicatedSignedAuthorization(t *testing.T) {
	identity := RolloutIdentity{ActorScopeID: nodeID(701), ActorUserID: nodeID(702), InstallationID: nodeID(703)}
	plan := mustRolloutPlan(t)
	plan = mustPlanCommand(t, plan, planCommand(PlanStart, plan.Revision, "start_requested")).Plan
	failure := currentPlanHealth(plan, nodeID(1), false)
	failure.Code = "health_probe_failed"
	plan = mustPlanHealth(t, plan, failure).Plan
	commands, _ := rollbackCommandOutbox(t, identity, plan, plan.Revision)
	if len(commands) != 1 || commands[0].Action != entitlement.RollbackOperation {
		t.Fatalf("rollback commands = %#v", commands)
	}
	signed, err := entitlement.DecodeUpgradeExecution(commands[0].SignedExecutionBytes)
	if err != nil {
		t.Fatal(err)
	}
	signedGrant, err := entitlement.DecodeUpgradeCommandGrant(commands[0].CommandGrantBytes)
	if err != nil {
		t.Fatal(err)
	}
	rollbackGrant := rolloutPlanStringField(t, plan, "RollbackGrantDigest")
	rollbackSequence := rolloutPlanUintField(t, plan, "RollbackReleaseSequence")
	rollbackArtifact := rolloutPlanStringField(t, plan, "RollbackArtifactID")
	rollbackDigest := rolloutPlanStringField(t, plan, "RollbackSHA256Digest")
	if t.Failed() {
		return
	}
	execution := signed.Execution
	grant := signedGrant.Grant
	batch := plan.RollbackBatches[plan.ActiveBatch]
	if grant.Schema != entitlement.UpgradeCommandGrantV2Schema || grant.PlanID != plan.ID ||
		grant.PlanRevision != commands[0].PlanRevision || grant.BatchID != batch.ID ||
		grant.ParentGrantSHA256 != rollbackGrant ||
		grant.ArtifactBundleID != plan.ArtifactBundleID ||
		grant.ArtifactBundleSHA256 != plan.ArtifactBundleSHA256 ||
		grant.CommandIssuanceNotAfter != plan.CommandIssuanceNotAfter ||
		execution.Schema != entitlement.UpgradeExecutionV2Schema || execution.PlanID != plan.ID ||
		execution.PlanRevision != commands[0].PlanRevision || execution.BatchID != batch.ID ||
		execution.ArtifactBundleID != plan.ArtifactBundleID ||
		execution.ArtifactBundleSHA256 != plan.ArtifactBundleSHA256 ||
		execution.CommandIssuanceNotAfter != plan.CommandIssuanceNotAfter ||
		execution.Operation != entitlement.RollbackOperation || execution.Operation != commands[0].Action ||
		execution.GrantDigest != commands[0].CommandGrantSHA256 || execution.ReleaseSequence != rollbackSequence ||
		execution.CurrentVersion != plan.TargetVersion || execution.TargetVersion != plan.CurrentVersion ||
		execution.ArtifactID != rollbackArtifact || execution.SHA256Digest != rollbackDigest ||
		!validRolloutCommand(identity, plan, commands[0]) {
		t.Fatalf("rollback execution = %#v command=%#v", execution, commands[0])
	}
}

func TestRolloutStatusPayloadAndGraphMatchAgentContract(t *testing.T) {
	identity := RolloutIdentity{ActorScopeID: nodeID(711), ActorUserID: nodeID(712), InstallationID: nodeID(713)}
	command := RolloutNodeCommand{
		ID: nodeID(714), PlanID: nodeID(715), PlanRevision: 2, BatchID: nodeID(716),
		InstallationID: identity.InstallationID, NodeID: nodeID(717), Action: entitlement.UpgradeOperation,
	}
	receipt := agentRolloutStatus(t, command, 1, "accepted", nodeID(718), "", time.Now())
	if !validRolloutStatus(identity, receipt) {
		t.Fatalf("Agent-compatible accepted status rejected: %s", receipt.StatusBytes)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(receipt.StatusBytes, &fields); err != nil {
		t.Fatal(err)
	}
	wantFields := []string{
		"schema", "status_id", "status_revision", "command_id", "plan_id", "plan_revision",
		"installation_id", "node_id", "command_sha256", "state", "current_version", "previous_version",
		"installer_transaction_id", "error_code", "alert_required", "observed_at",
	}
	if len(fields) != len(wantFields) {
		t.Fatalf("status fields = %v", fields)
	}
	for _, field := range wantFields {
		if _, ok := fields[field]; !ok {
			t.Errorf("status missing field %q", field)
		}
	}
	if _, found := fields["batch_id"]; found {
		t.Error("Agent status bytes include derived batch_id")
	}
	if _, found := fields["action"]; found {
		t.Error("Agent status bytes include derived action")
	}

	transitions := []struct {
		action string
		from   string
		to     string
		want   bool
	}{
		{action: "upgrade", from: "accepted", to: "claimed", want: true},
		{action: "rollback", from: "accepted", to: "claimed", want: true},
		{action: "upgrade", from: "claimed", to: "installing", want: true},
		{action: "rollback", from: "claimed", to: "installing", want: true},
		{action: "upgrade", from: "installing", to: "healthy", want: true},
		{action: "upgrade", from: "installing", to: "failed", want: true},
		{action: "upgrade", from: "installing", to: "rolling_back", want: true},
		{action: "upgrade", from: "installing", to: "uncertain", want: true},
		{action: "upgrade", from: "installing", to: "rolled_back", want: false},
		{action: "rollback", from: "installing", to: "rolled_back", want: true},
		{action: "rollback", from: "installing", to: "uncertain", want: true},
		{action: "rollback", from: "installing", to: "healthy", want: false},
		{action: "rollback", from: "installing", to: "failed", want: true},
		{action: "rollback", from: "installing", to: "rolling_back", want: false},
		{action: "upgrade", from: "rolling_back", to: "rolled_back", want: true},
		{action: "upgrade", from: "rolling_back", to: "uncertain", want: true},
		{action: "upgrade", from: "rolling_back", to: "failed", want: false},
		{action: "rollback", from: "rolling_back", to: "rolled_back", want: false},
		{action: "upgrade", from: "uncertain", to: "uncertain", want: true},
		{action: "upgrade", from: "uncertain", to: "healthy", want: true},
		{action: "upgrade", from: "uncertain", to: "failed", want: true},
		{action: "upgrade", from: "uncertain", to: "rolled_back", want: true},
		{action: "rollback", from: "uncertain", to: "uncertain", want: true},
		{action: "rollback", from: "uncertain", to: "rolled_back", want: true},
		{action: "rollback", from: "uncertain", to: "healthy", want: false},
		{action: "rollback", from: "uncertain", to: "failed", want: true},
		{action: "rollback", from: "uncertain", to: "rolling_back", want: false},
		{action: "upgrade", from: "uncertain", to: "installing", want: false},
	}
	for _, transition := range transitions {
		if got := validRolloutStatusTransition(transition.action, transition.from, transition.to); got != transition.want {
			t.Errorf("status transition %s %s->%s=%v want=%v",
				transition.action, transition.from, transition.to, got, transition.want)
		}
	}
}

func TestRolloutStatusTupleSemanticsMatchAgentContract(t *testing.T) {
	plan := mustRolloutPlan(t)
	tests := []struct {
		name          string
		action        string
		previousState string
		state         string
		current       string
		previous      string
		transaction   string
		errorCode     string
		alert         bool
		previousTx    string
		previousError string
		triggerError  string
		want          bool
	}{
		{name: "accepted empty", action: "upgrade", state: "accepted", want: true},
		{name: "claimed empty", action: "rollback", state: "claimed", want: true},
		{name: "accepted rejects transaction", action: "upgrade", state: "accepted", transaction: "txn-status", want: false},
		{name: "upgrade installing transaction only", action: "upgrade", state: "installing", transaction: "txn-status", want: true},
		{name: "rollback installing transaction only", action: "rollback", state: "installing", transaction: "txn-status", want: true},
		{name: "installing rejects current", action: "upgrade", state: "installing", current: plan.CurrentVersion, transaction: "txn-status", want: false},
		{name: "installing requires transaction", action: "rollback", state: "installing", want: false},
		{name: "upgrade healthy", action: "upgrade", state: "healthy", current: plan.TargetVersion,
			previous: plan.CurrentVersion, transaction: "txn-status", want: true},
		{name: "rollback cannot report healthy", action: "rollback", state: "healthy", current: plan.TargetVersion,
			previous: plan.CurrentVersion, transaction: "txn-status", want: false},
		{name: "automatic rollback started", action: "upgrade", previousState: "installing", state: "rolling_back",
			current: plan.CurrentVersion, previous: plan.TargetVersion, transaction: "txn-status",
			errorCode: "HEALTH_FAILED", previousTx: "txn-status", want: true},
		{name: "automatic rollback completed", action: "upgrade", previousState: "rolling_back", state: "rolled_back",
			current: plan.CurrentVersion, previous: plan.TargetVersion, transaction: "txn-status",
			errorCode: "HEALTH_FAILED", previousTx: "txn-status", previousError: "HEALTH_FAILED",
			triggerError: "HEALTH_FAILED", want: true},
		{name: "automatic rollback rejects changed triggering error", action: "upgrade", previousState: "rolling_back", state: "rolled_back",
			current: plan.CurrentVersion, previous: plan.TargetVersion, transaction: "txn-status",
			errorCode: "PLAN_EXPIRED", previousTx: "txn-status", previousError: "HEALTH_FAILED",
			triggerError: "HEALTH_FAILED", want: false},
		{name: "automatic rollback uncertain recovery preserves original trigger", action: "upgrade", previousState: "uncertain", state: "rolled_back",
			current: plan.CurrentVersion, previous: plan.TargetVersion, transaction: "txn-status",
			errorCode: "HEALTH_FAILED", previousTx: "txn-status", previousError: "ROLLBACK_FAILED",
			triggerError: "HEALTH_FAILED", want: true},
		{name: "automatic rollback uncertain recovery rejects intermediate error", action: "upgrade", previousState: "uncertain", state: "rolled_back",
			current: plan.CurrentVersion, previous: plan.TargetVersion, transaction: "txn-status",
			errorCode: "ROLLBACK_FAILED", previousTx: "txn-status", previousError: "ROLLBACK_FAILED",
			triggerError: "HEALTH_FAILED", want: false},
		{name: "uncertain recovery without rolling back history accepts nonempty final cause", action: "upgrade", previousState: "uncertain", state: "rolled_back",
			current: plan.CurrentVersion, previous: plan.TargetVersion, transaction: "txn-status",
			errorCode: "PLAN_EXPIRED", previousTx: "txn-status", previousError: "INSTALLER_OUTCOME_UNKNOWN", want: true},
		{name: "automatic rollback requires triggering error", action: "upgrade", previousState: "installing", state: "rolling_back",
			current: plan.CurrentVersion, previous: plan.TargetVersion, transaction: "txn-status", previousTx: "txn-status", want: false},
		{name: "automatic rollback never alerts", action: "upgrade", previousState: "rolling_back", state: "rolled_back",
			current: plan.CurrentVersion, previous: plan.TargetVersion, transaction: "txn-status",
			errorCode: "HEALTH_FAILED", alert: true, previousTx: "txn-status", previousError: "HEALTH_FAILED",
			triggerError: "HEALTH_FAILED", want: false},
		{name: "explicit rollback completed", action: "rollback", previousState: "installing", state: "rolled_back",
			current: plan.TargetVersion, previous: plan.CurrentVersion, transaction: "txn-status", previousTx: "txn-status", want: true},
		{name: "explicit rollback success rejects error", action: "rollback", previousState: "installing", state: "rolled_back",
			current: plan.TargetVersion, previous: plan.CurrentVersion, transaction: "txn-status",
			errorCode: "ROLLBACK_FAILED", previousTx: "txn-status", want: false},
		{name: "preactivation failed unchanged", action: "upgrade", previousState: "installing", state: "failed",
			current: plan.CurrentVersion, transaction: "txn-status", errorCode: "DOWNLOAD_FAILED", alert: true,
			previousTx: "txn-status", want: true},
		{name: "explicit rollback preactivation failed", action: "rollback", previousState: "installing", state: "failed",
			current: plan.CurrentVersion, transaction: "txn-status", errorCode: "DOWNLOAD_FAILED", alert: true,
			previousTx: "txn-status", want: true},
		{name: "explicit rollback restored after target failure", action: "rollback", previousState: "installing", state: "failed",
			current: plan.CurrentVersion, previous: plan.TargetVersion, transaction: "txn-status",
			errorCode: "HEALTH_FAILED", alert: true, previousTx: "txn-status", want: true},
		{name: "explicit rollback failed cannot leave candidate active", action: "rollback", previousState: "installing", state: "failed",
			current: plan.TargetVersion, previous: plan.CurrentVersion, transaction: "txn-status",
			errorCode: "HEALTH_FAILED", alert: true, previousTx: "txn-status", want: false},
		{name: "rollback failure is uncertain not failed", action: "rollback", previousState: "installing", state: "failed",
			current: plan.CurrentVersion, transaction: "txn-status", errorCode: "ROLLBACK_FAILED", alert: true,
			previousTx: "txn-status", want: false},
		{name: "reconciled explicit rollback preactivation failed", action: "rollback", previousState: "uncertain", state: "failed",
			current: plan.CurrentVersion, transaction: "txn-status", errorCode: "DOWNLOAD_FAILED", alert: true,
			previousTx: "txn-status", want: true},
		{name: "reconciled explicit rollback restored after target failure", action: "rollback", previousState: "uncertain", state: "failed",
			current: plan.CurrentVersion, previous: plan.TargetVersion, transaction: "txn-status",
			errorCode: "HEALTH_FAILED", alert: true, previousTx: "txn-status", want: true},
		{name: "failed requires alert", action: "upgrade", previousState: "installing", state: "failed",
			current: plan.CurrentVersion, transaction: "txn-status", errorCode: "DOWNLOAD_FAILED", previousTx: "txn-status", want: false},
		{name: "uncertain unproven upgrade", action: "upgrade", previousState: "installing", state: "uncertain",
			transaction: "txn-status", errorCode: "INSTALLER_OUTCOME_UNKNOWN", alert: true, previousTx: "txn-status", want: true},
		{name: "uncertain unproven rollback", action: "rollback", previousState: "installing", state: "uncertain",
			transaction: "txn-status", errorCode: "INSTALLER_OUTCOME_UNKNOWN", alert: true, previousTx: "txn-status", want: true},
		{name: "uncertain proven active candidate", action: "upgrade", previousState: "rolling_back", state: "uncertain",
			current: plan.TargetVersion, previous: plan.CurrentVersion, transaction: "txn-status",
			errorCode: "ROLLBACK_FAILED", alert: true, previousTx: "txn-status", previousError: "HEALTH_FAILED", want: true},
		{name: "uncertain rejects unbound tuple", action: "upgrade", previousState: "rolling_back", state: "uncertain",
			current: plan.CurrentVersion, transaction: "txn-status", errorCode: "ROLLBACK_FAILED", alert: true,
			previousTx: "txn-status", previousError: "HEALTH_FAILED", want: false},
		{name: "uncertain requires transaction", action: "upgrade", previousState: "installing", state: "uncertain",
			errorCode: "INSTALLER_OUTCOME_UNKNOWN", alert: true, previousTx: "txn-status", want: false},
		{name: "healthy rejects changed transaction", action: "upgrade", previousState: "installing", state: "healthy",
			current: plan.TargetVersion, previous: plan.CurrentVersion, transaction: "txn-changed",
			previousTx: "txn-status", want: false},
		{name: "rolling back rejects changed transaction", action: "upgrade", previousState: "installing", state: "rolling_back",
			current: plan.CurrentVersion, previous: plan.TargetVersion, transaction: "txn-changed",
			errorCode: "HEALTH_FAILED", previousTx: "txn-status", want: false},
		{name: "failed rejects changed transaction", action: "rollback", previousState: "installing", state: "failed",
			current: plan.CurrentVersion, transaction: "txn-changed", errorCode: "DOWNLOAD_FAILED", alert: true,
			previousTx: "txn-status", want: false},
		{name: "uncertain rejects changed transaction", action: "upgrade", previousState: "installing", state: "uncertain",
			transaction: "txn-changed", errorCode: "INSTALLER_OUTCOME_UNKNOWN", alert: true,
			previousTx: "txn-status", want: false},
		{name: "rolled back rejects changed transaction", action: "rollback", previousState: "installing", state: "rolled_back",
			current: plan.TargetVersion, previous: plan.CurrentVersion, transaction: "txn-changed",
			previousTx: "txn-status", want: false},
		{name: "uncertain reconciliation rejects changed transaction", action: "upgrade", previousState: "uncertain", state: "healthy",
			current: plan.TargetVersion, previous: plan.CurrentVersion, transaction: "txn-changed",
			previousTx: "txn-status", want: false},
		{name: "rollback failed reconciliation rejects changed transaction", action: "rollback", previousState: "uncertain", state: "failed",
			current: plan.CurrentVersion, transaction: "txn-changed", errorCode: "DOWNLOAD_FAILED", alert: true,
			previousTx: "txn-status", want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			command := RolloutNodeCommand{Action: test.action}
			payload := rolloutStatusPayload{State: test.state, CurrentVersion: test.current,
				PreviousVersion: test.previous, InstallerTransactionID: test.transaction,
				ErrorCode: test.errorCode, AlertRequired: test.alert}
			previousPayload := rolloutStatusPayload{InstallerTransactionID: test.previousTx,
				ErrorCode: test.previousError}
			if got := validRolloutStatusSemantics(plan, command, payload,
				test.previousState, previousPayload, test.triggerError); got != test.want {
				t.Fatalf("validRolloutStatusSemantics(%s,%s,%#v) = %v, want %v",
					test.action, test.previousState, payload, got, test.want)
			}
		})
	}
}

func TestRolloutMutationBindsEveryReceiptCausation(t *testing.T) {
	if _, found := reflect.TypeOf(RolloutEventMutation{}).FieldByName("CausationBytes"); !found {
		t.Fatal("RolloutEventMutation missing CausationBytes")
	}
	identity := RolloutIdentity{ActorScopeID: nodeID(721), ActorUserID: nodeID(722), InstallationID: nodeID(723)}
	plan := mustRolloutPlan(t)
	start := planCommand(PlanStart, plan.Revision, "start_requested")
	startCause, startBytes := rolloutCause(t, start)
	locked := LockedRolloutPlan{Identity: identity, Plan: plan}
	mutation := rolloutStartMutation(t, locked, startCause, time.Now())
	setRolloutCausationBytes(t, &mutation.Events[0], startBytes)
	if err := validateRolloutMutation(locked, startCause, mutation); err != nil {
		t.Fatalf("valid start causation = %v", err)
	}
	forged := start
	forged.Reason = "forged_reason"
	forgedCause, forgedBytes := rolloutCause(t, forged)
	mutation.Events[0].Causation = forgedCause
	setRolloutCausationBytes(t, &mutation.Events[0], forgedBytes)
	if err := validateRolloutMutation(locked, forgedCause, mutation); !errors.Is(err, ErrInvalidPlanEvent) {
		t.Fatalf("forged start causation = %v", err)
	}

	plan = mustRolloutPlan(t)
	plan = mustPlanCommand(t, plan, planCommand(PlanStart, plan.Revision, "start_requested")).Plan
	plan = mustPlanHealth(t, plan, currentPlanHealth(plan, nodeID(1), true)).Plan
	failure := currentPlanHealth(plan, nodeID(2), false)
	failure.Code = "health_probe_failed"
	plan = mustPlanHealth(t, plan, failure).Plan
	locked = LockedRolloutPlan{Identity: identity, Plan: plan}
	health := currentPlanHealth(plan, nodeID(3), true)
	healthCause, healthBytes := rolloutCause(t, health)
	result := mustPlanHealth(t, plan, health)
	healthReceipt := result.Plan.HealthReceipts[len(result.Plan.HealthReceipts)-1]
	commandReceipt := result.Plan.CommandReceipts[len(result.Plan.CommandReceipts)-1]
	commandCause, commandBytes := rolloutCause(t, commandReceipt.Command)
	events := []RolloutEventMutation{
		rolloutEventMutation(t, healthCause, healthBytes, healthReceipt.Event),
		rolloutEventMutation(t, commandCause, commandBytes, commandReceipt.Event),
	}
	setRolloutCausationBytes(t, &events[0], healthBytes)
	setRolloutCausationBytes(t, &events[1], commandBytes)
	commands, outbox := rollbackCommandOutbox(t, identity, result.Plan, commandReceipt.Event.Revision)
	mutation = rolloutMutation(t, locked.Plan.Revision, result.Plan, events, commands, outbox)
	if err := validateRolloutMutation(locked, healthCause, mutation); err != nil {
		t.Fatalf("valid multi-event causation = %v", err)
	}
	mutation.Events[1].Causation = healthCause
	setRolloutCausationBytes(t, &mutation.Events[1], healthBytes)
	if err := validateRolloutMutation(locked, healthCause, mutation); !errors.Is(err, ErrInvalidPlanEvent) {
		t.Fatalf("forged later-event causation = %v", err)
	}
}

func TestRolloutWireDigestsMatchAgentLowercaseHexContract(t *testing.T) {
	identity := RolloutIdentity{ActorScopeID: nodeID(731), ActorUserID: nodeID(732), InstallationID: nodeID(733)}
	plan := mustRolloutPlan(t)
	start := planCommand(PlanStart, plan.Revision, "start_requested")
	cause, _ := rolloutCause(t, start)
	locked := LockedRolloutPlan{Identity: identity, Plan: plan}
	mutation := rolloutStartMutation(t, locked, cause, time.Now())
	command, message := mutation.NodeCommands[0], mutation.Outbox[0]
	status := agentRolloutStatus(t, command, 1, "accepted", nodeID(734), "", time.Now())
	for name, digest := range map[string]string{
		"signed execution": command.SignedExecutionSHA256,
		"outbox payload":   message.PayloadSHA256,
		"status command":   status.CommandSHA256,
		"status outer":     status.StatusSHA256,
	} {
		decoded, err := hex.DecodeString(digest)
		if err != nil || len(decoded) != sha256.Size || len(digest) != sha256.Size*2 || strings.ToLower(digest) != digest {
			t.Errorf("%s digest %q is not exact lowercase hex", name, digest)
		}
	}
	if err := validateRolloutMutation(locked, cause, mutation); err != nil {
		t.Errorf("Agent-shaped lowercase-hex command = %v", err)
	}
	if !validRolloutStatus(identity, status) {
		t.Error("Agent-shaped lowercase-hex status rejected")
	}

	legacy := rolloutStartMutation(t, locked, cause, time.Now())
	legacyCommand := &legacy.NodeCommands[0]
	legacyCommand.SignedExecutionSHA256 = base64URLFromWireDigest(t, legacyCommand.SignedExecutionSHA256)
	legacy.Outbox[0].PayloadBytes = mustJSONRollout(t, rolloutCommandEnvelope(*legacyCommand))
	legacy.Outbox[0].PayloadSHA256 = base64.RawURLEncoding.EncodeToString(rolloutSHA256(legacy.Outbox[0].PayloadBytes))
	if err := validateRolloutMutation(locked, cause, legacy); !errors.Is(err, ErrInvalidPlanCommand) {
		t.Errorf("base64url command/outbox digests = %v", err)
	}

	legacyStatus := status
	legacyStatus.CommandSHA256 = base64URLFromWireDigest(t, status.CommandSHA256)
	var payload agentRolloutStatusV1
	if err := json.Unmarshal(legacyStatus.StatusBytes, &payload); err != nil {
		t.Fatal(err)
	}
	payload.CommandSHA256 = legacyStatus.CommandSHA256
	legacyStatus.StatusBytes = mustJSONRollout(t, payload)
	legacyStatus.StatusSHA256 = base64.RawURLEncoding.EncodeToString(rolloutSHA256(legacyStatus.StatusBytes))
	if validRolloutStatus(identity, legacyStatus) {
		t.Error("base64url status command/outer digests were accepted")
	}
}

func TestRolloutMutationRejectsEveryStaticExecutionIdentityRewrite(t *testing.T) {
	identity := RolloutIdentity{ActorScopeID: nodeID(741), ActorUserID: nodeID(742), InstallationID: nodeID(743)}
	plan := mustRolloutPlan(t)
	start := planCommand(PlanStart, plan.Revision, "start_requested")
	cause, _ := rolloutCause(t, start)
	locked := LockedRolloutPlan{Identity: identity, Plan: plan}
	tests := []struct {
		name string
		edit func(*RolloutPlan)
	}{
		{"schema version", func(plan *RolloutPlan) { plan.SchemaVersion++ }},
		{"plan id", func(plan *RolloutPlan) { plan.ID = nodeID(744) }},
		{"forward grant", func(plan *RolloutPlan) { plan.GrantDigest = planDigest(0x51) }},
		{"forward sequence", func(plan *RolloutPlan) { plan.ReleaseSequence-- }},
		{"forward artifact", func(plan *RolloutPlan) { plan.ArtifactID = nodeID(745) }},
		{"forward sha", func(plan *RolloutPlan) { plan.SHA256Digest = planDigest(0x52) }},
		{"rollback grant", func(plan *RolloutPlan) { plan.RollbackGrantDigest = planDigest(0x53) }},
		{"rollback sequence", func(plan *RolloutPlan) { plan.RollbackReleaseSequence++ }},
		{"rollback artifact", func(plan *RolloutPlan) { plan.RollbackArtifactID = nodeID(746) }},
		{"rollback sha", func(plan *RolloutPlan) { plan.RollbackSHA256Digest = planDigest(0x54) }},
		{"component", func(plan *RolloutPlan) { plan.Component = "edge-agent-v2" }},
		{"current version", func(plan *RolloutPlan) { plan.CurrentVersion = "0.9.0" }},
		{"target version", func(plan *RolloutPlan) { plan.TargetVersion = "2.1.0" }},
		{"automatic rollback", func(plan *RolloutPlan) { plan.AutomaticRollback = false }},
		{"safety", func(plan *RolloutPlan) { plan.Safety.ProtocolMax++ }},
		{"batches", func(plan *RolloutPlan) {
			plan.Batches[0].GroupID = "canary-v2"
			plan.Batches[0].ID = derivedPlanID(plan.ID, "batch", "canary-v2:0001")
		}},
		{"targets", func(plan *RolloutPlan) {
			target := plan.Targets[nodeID(1)]
			target.AgentVersion = "1.6.0"
			plan.Targets[nodeID(1)] = target
		}},
		{"blockers", func(plan *RolloutPlan) {
			plan.Blockers = append(plan.Blockers, PlanBlocker{Code: BlockerRollbackUnavailable})
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mutation := rolloutStartMutation(t, locked, cause, time.Now())
			test.edit(&mutation.Plan)
			mutation.CanonicalSnapshotBytes = mustJSONRollout(t, mutation.Plan)
			mutation.CanonicalSnapshotSHA256 = digestRolloutBytes(mutation.CanonicalSnapshotBytes)
			if err := validateRolloutMutation(locked, cause, mutation); !errors.Is(err, ErrInvalidPlan) {
				t.Errorf("static rewrite error = %v, want %v", err, ErrInvalidPlan)
			}
		})
	}
}

func planGrantBindingForTest(t *testing.T, identity RolloutIdentity, plan *RolloutPlan) PlanGrantBinding {
	t.Helper()
	parent := []byte(`{"schema":"test-parent-grant"}`)
	parentDigest := sha256.Sum256(parent)
	plan.GrantDigest = base64.RawURLEncoding.EncodeToString(parentDigest[:])
	plan.RollbackGrantDigest = plan.GrantDigest
	forward, err := json.Marshal(plan.ForwardProfile)
	if err != nil {
		t.Fatal(err)
	}
	rollback, err := json.Marshal(plan.RollbackProfile)
	if err != nil {
		t.Fatal(err)
	}
	forwardDigest, rollbackDigest := sha256.Sum256(forward), sha256.Sum256(rollback)
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x58}, ed25519.SeedSize))
	signer := grantTestSigner{privateKey: privateKey}
	manifest := func(artifactID, version, digest string, size int64) entitlement.ArtifactManifestV2 {
		return entitlement.ArtifactManifestV2{Schema: entitlement.ArtifactManifestV2Schema,
			Audience: entitlement.ArtifactManifestAudience, Purpose: entitlement.ArtifactManifestPurpose,
			ArtifactID: artifactID, Component: plan.Component, Version: version,
			ProtocolMin: int(plan.Safety.ProtocolMin), ProtocolMax: int(plan.Safety.ProtocolMax),
			ArtifactSizeBytes: size, DigestAlgorithm: "sha256", SHA256Digest: digest,
			DownloadURL: "https://downloads.example.test/" + artifactID}
	}
	forwardManifest := manifest(plan.ArtifactID, plan.TargetVersion, plan.SHA256Digest, plan.ArtifactSizeBytes)
	rollbackManifest := manifest(plan.RollbackArtifactID, plan.CurrentVersion,
		plan.RollbackSHA256Digest, plan.RollbackArtifactSizeBytes)
	forwardSignature, err := entitlement.SignArtifactManifestV2(t.Context(), forwardManifest, signer)
	if err != nil {
		t.Fatal(err)
	}
	rollbackSignature, err := entitlement.SignArtifactManifestV2(t.Context(), rollbackManifest, signer)
	if err != nil {
		t.Fatal(err)
	}
	plan.ArtifactBundleID = nodeID(178)
	plan.CommandIssuanceNotAfter = plan.ParentGrantExpiresAt + int64(time.Hour/time.Second)
	bundle := entitlement.UpgradePlanArtifactBundle{Schema: entitlement.UpgradePlanArtifactBundleSchema,
		Audience: entitlement.UpgradePlanArtifactBundleAudience, Purpose: entitlement.UpgradePlanArtifactBundlePurpose,
		BundleID: plan.ArtifactBundleID, PlanID: plan.ID, InitialPlanRevision: 1,
		ParentGrantID: plan.ParentGrantID, ParentGrantSHA256: plan.GrantDigest,
		ParentGrantIssuedAt:  plan.ParentGrantExpiresAt - int64(15*time.Minute/time.Second),
		ParentGrantExpiresAt: plan.ParentGrantExpiresAt, CustomerID: nodeID(179),
		InstallationID: identity.InstallationID, LicenseID: nodeID(180), Channel: "stable",
		ChannelRevision: plan.ReleaseSequence, Component: plan.Component, CurrentVersion: plan.CurrentVersion,
		Version: plan.TargetVersion, ProtocolVersion: int(plan.Safety.ProtocolMin),
		Forward: entitlement.UpgradePlanArtifact{Manifest: forwardManifest, SignatureAlgorithm: entitlement.Algorithm,
			SignatureKeyID: signer.KeyID(), ManifestSignature: base64.RawURLEncoding.EncodeToString(forwardSignature)},
		Rollback: entitlement.UpgradePlanArtifact{Manifest: rollbackManifest, SignatureAlgorithm: entitlement.Algorithm,
			SignatureKeyID: signer.KeyID(), ManifestSignature: base64.RawURLEncoding.EncodeToString(rollbackSignature)},
		IssuedAt:                plan.ParentGrantExpiresAt - int64(14*time.Minute/time.Second),
		CommandIssuanceNotAfter: plan.CommandIssuanceNotAfter}
	signedBundle, err := entitlement.SignUpgradePlanArtifactBundle(t.Context(), bundle, signer)
	if err != nil {
		t.Fatal(err)
	}
	bundleBytes, err := signedBundle.Encode()
	if err != nil {
		t.Fatal(err)
	}
	bundleDigest := sha256.Sum256(bundleBytes)
	plan.ArtifactBundleSHA256 = base64.RawURLEncoding.EncodeToString(bundleDigest[:])
	return PlanGrantBinding{ParentGrantBytes: parent, ParentGrantSHA256: plan.GrantDigest,
		ArtifactBundleBytes: bundleBytes, ArtifactBundleSHA256: plan.ArtifactBundleSHA256,
		ForwardProfileBytes: forward, ForwardProfileSHA256: base64.RawURLEncoding.EncodeToString(forwardDigest[:]),
		RollbackProfileBytes: rollback, RollbackProfileSHA256: base64.RawURLEncoding.EncodeToString(rollbackDigest[:])}
}

func TestRolloutPersistenceSchemaAndCASPrerequisites(t *testing.T) {
	pool := openRolloutPersistenceIntegrationPool(t)
	requiredColumns := map[string][]string{
		"control_upgrade_rollout_plans": {
			"id", "actor_scope_id", "actor_user_id", "installation_id", "schema_version", "revision", "state",
			"resume_state", "completion", "active_batch", "canonical_snapshot_bytes", "canonical_snapshot_sha256",
			"created_at", "updated_at",
		},
		"control_upgrade_rollout_events": {
			"plan_id", "revision", "event_id", "actor_scope_id", "actor_user_id", "installation_id",
			"causation_id", "causation_bytes", "causation_sha256", "event_bytes", "event_sha256",
			"result_snapshot_bytes", "result_snapshot_sha256", "created_at",
		},
		"control_upgrade_node_commands": {
			"command_id", "plan_id", "plan_revision", "batch_id", "actor_scope_id", "actor_user_id",
			"installation_id", "node_id", "action", "signed_execution_bytes", "signed_execution_sha256",
			"state", "created_at", "published_at", "acknowledged_at",
		},
		"control_upgrade_status_receipts": {
			"command_id", "status_revision", "status_id", "plan_id", "plan_revision", "batch_id",
			"actor_scope_id", "actor_user_id", "installation_id", "node_id", "action", "status_bytes",
			"status_sha256", "command_sha256", "state", "observed_at", "created_at",
		},
		"control_upgrade_outbox": {
			"id", "command_id", "plan_id", "plan_revision", "batch_id", "actor_scope_id", "actor_user_id",
			"installation_id", "node_id", "action", "topic", "message_key", "payload_bytes", "payload_sha256",
			"state", "available_at", "claimed_by", "claim_token", "claimed_at", "claim_expires_at",
			"attempt_count", "published_at", "last_error_code", "created_at",
		},
	}
	for table, columns := range requiredColumns {
		rows, err := pool.Query(t.Context(), `SELECT column_name FROM information_schema.columns
			WHERE table_schema=current_schema() AND table_name=$1`, table)
		if err != nil {
			t.Fatal(err)
		}
		found, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			t.Fatal(err)
		}
		for _, column := range columns {
			if !slices.Contains(found, column) {
				t.Errorf("%s missing column %s", table, column)
			}
		}
	}
}

func TestRolloutPersistenceRowLockCASReplayConflictAndAtomicCommit(t *testing.T) {
	pool := openRolloutPersistenceIntegrationPool(t)
	identity := seedRolloutPersistenceIdentity(t, pool)
	plan := mustRolloutPlan(t)
	insertRolloutPersistencePlan(t, pool, identity, &plan)
	store := requireRolloutPersistence(t, NewStore(pool, nil, nil, time.Now))
	cause, _ := rolloutCause(t, planCommand(PlanStart, plan.Revision, "start_requested"))
	entered := make(chan struct{})
	release := make(chan struct{})
	firstResult := make(chan error, 1)
	go func() {
		_, err := store.TransactLocked(context.Background(), identity, plan.ID, cause,
			func(locked LockedRolloutPlan) (RolloutAtomicMutation, error) {
				close(entered)
				<-release
				return rolloutStartMutation(t, locked, cause, time.Now()), nil
			})
		firstResult <- err
	}()
	<-entered

	secondEntered := make(chan struct{})
	secondResult := make(chan error, 1)
	go func() {
		_, err := store.TransactLocked(context.Background(), identity, plan.ID,
			RolloutCausation{ID: nodeID(802), SHA256: planDigest(0x82)},
			func(locked LockedRolloutPlan) (RolloutAtomicMutation, error) {
				close(secondEntered)
				return RolloutAtomicMutation{ExpectedRevision: plan.Revision}, nil
			})
		secondResult <- err
	}()
	select {
	case <-secondEntered:
		t.Fatal("second mutation entered while the first transaction held the plan row lock")
	case <-time.After(150 * time.Millisecond):
	}
	close(release)
	if err := <-firstResult; err != nil {
		t.Fatalf("first mutation: %v", err)
	}
	if err := <-secondResult; !errors.Is(err, ErrStalePlanRevision) {
		t.Fatalf("second CAS error = %v", err)
	}

	replay, err := store.TransactLocked(t.Context(), identity, plan.ID, cause,
		func(LockedRolloutPlan) (RolloutAtomicMutation, error) {
			t.Fatal("exact replay invoked mutation builder")
			return RolloutAtomicMutation{}, nil
		})
	if err != nil || !replay.Replayed || len(replay.Events) != 1 || len(replay.NodeCommands) != 1 || len(replay.Outbox) != 1 {
		t.Fatalf("replay = (%#v, %v)", replay, err)
	}
	conflict := cause
	conflict.SHA256 = planDigest(0x83)
	if _, err := store.TransactLocked(t.Context(), identity, plan.ID, conflict,
		func(LockedRolloutPlan) (RolloutAtomicMutation, error) { return RolloutAtomicMutation{}, nil }); !errors.Is(err, ErrPlanIdempotencyConflict) {
		t.Fatalf("causation conflict error = %v", err)
	}
	assertRolloutAtomicCounts(t, pool, plan.ID, 1, 1, 1)
}

func TestRolloutPersistenceAutomaticRollbackEventCommandsAndOutboxAtomic(t *testing.T) {
	pool := openRolloutPersistenceIntegrationPool(t)
	identity := seedRolloutPersistenceIdentity(t, pool)
	plan := mustRolloutPlan(t)
	plan = mustPlanCommand(t, plan, planCommand(PlanStart, plan.Revision, "start_requested")).Plan
	plan = mustPlanHealth(t, plan, currentPlanHealth(plan, nodeID(1), true)).Plan
	failure := currentPlanHealth(plan, nodeID(2), false)
	failure.Code = "health_probe_failed"
	plan = mustPlanHealth(t, plan, failure).Plan
	if plan.State != PlanPaused || plan.NodeStates[nodeID(3)] != NodeDispatched {
		t.Fatalf("automatic rollback fixture = %#v", plan)
	}
	insertRolloutPersistencePlan(t, pool, identity, &plan)
	store := requireRolloutPersistence(t, NewStore(pool, nil, nil, time.Now))
	health := currentPlanHealth(plan, nodeID(3), true)
	cause, causeBytes := rolloutCause(t, health)
	commit, err := store.TransactLocked(t.Context(), identity, plan.ID, cause,
		func(locked LockedRolloutPlan) (RolloutAtomicMutation, error) {
			beforeHealth := len(locked.Plan.HealthReceipts)
			beforeCommands := len(locked.Plan.CommandReceipts)
			result := mustPlanHealth(t, locked.Plan, health)
			if result.Plan.State != PlanRollingBack || len(result.Plan.CommandReceipts) != beforeCommands+1 {
				t.Fatalf("settled automatic rollback = %#v", result.Plan)
			}
			healthReceipt := result.Plan.HealthReceipts[beforeHealth]
			commandReceipt := result.Plan.CommandReceipts[beforeCommands]
			commandCause, commandBytes := rolloutCause(t, commandReceipt.Command)
			events := []RolloutEventMutation{
				rolloutEventMutation(t, cause, causeBytes, healthReceipt.Event),
				rolloutEventMutation(t, commandCause, commandBytes, commandReceipt.Event),
			}
			commands, outbox := rollbackCommandOutbox(t, identity, result.Plan, commandReceipt.Event.Revision)
			return rolloutMutation(t, locked.Plan.Revision, result.Plan, events, commands, outbox), nil
		})
	if err != nil || commit.Plan.State != PlanRollingBack || len(commit.Events) != 2 || len(commit.NodeCommands) == 0 {
		t.Fatalf("automatic rollback commit = (%#v, %v)", commit, err)
	}
	assertRolloutAtomicCounts(t, pool, plan.ID, int(plan.Revision-1)+2, len(commit.NodeCommands), len(commit.Outbox))
}

func TestRolloutPersistenceRejectsIncompleteDispatchAndMismatchedPayload(t *testing.T) {
	pool := openRolloutPersistenceIntegrationPool(t)
	identity := seedRolloutPersistenceIdentity(t, pool)
	plan := mustRolloutPlan(t)
	insertRolloutPersistencePlan(t, pool, identity, &plan)
	store := requireRolloutPersistence(t, NewStore(pool, nil, nil, time.Now))

	apply := func(cause RolloutCausation, mutate func(*RolloutAtomicMutation)) error {
		_, err := store.TransactLocked(t.Context(), identity, plan.ID, cause,
			func(locked LockedRolloutPlan) (RolloutAtomicMutation, error) {
				mutation := rolloutStartMutation(t, locked, cause, time.Now())
				mutate(&mutation)
				return mutation, nil
			})
		return err
	}
	startCause, _ := rolloutCause(t, planCommand(PlanStart, plan.Revision, "start_requested"))
	if err := apply(startCause,
		func(mutation *RolloutAtomicMutation) {
			mutation.NodeCommands = nil
			mutation.Outbox = nil
		}); !errors.Is(err, ErrInvalidPlanCommand) {
		t.Fatalf("missing dispatch command = %v", err)
	}
	if err := apply(startCause,
		func(mutation *RolloutAtomicMutation) {
			command := mutation.NodeCommands[0]
			payload := rolloutCommandEnvelope(command)
			payload.NodeID = nodeID(99)
			mutation.Outbox[0].PayloadBytes = mustJSONRollout(t, payload)
			mutation.Outbox[0].PayloadSHA256 = digestRolloutWireBytes(mutation.Outbox[0].PayloadBytes)
		}); !errors.Is(err, ErrInvalidPlanCommand) {
		t.Fatalf("mismatched payload identity = %v", err)
	}
	if err := apply(startCause,
		func(mutation *RolloutAtomicMutation) {
			command := mutation.NodeCommands[0]
			command.ID = nodeID(874)
			commandGrant, commandGrantExpiresAt, signedExecution := rolloutSignedExecution(t, identity,
				mutation.Plan, command.ID, command.PlanRevision, command.BatchID, command.NodeID)
			command.CommandGrantBytes = commandGrant
			command.CommandGrantSHA256 = digestRolloutBytes(commandGrant)
			command.CommandGrantExpiresAt = commandGrantExpiresAt
			command.SignedExecutionBytes = signedExecution
			command.SignedExecutionSHA256 = digestRolloutWireBytes(command.SignedExecutionBytes)
			message := mutation.Outbox[0]
			message.ID = command.ID
			message.MessageKey = command.ID
			message.PayloadBytes = mustJSONRollout(t, rolloutCommandEnvelope(command))
			message.PayloadSHA256 = digestRolloutWireBytes(message.PayloadBytes)
			mutation.NodeCommands = append(mutation.NodeCommands, command)
			mutation.Outbox = append(mutation.Outbox, message)
		}); !errors.Is(err, ErrInvalidPlanCommand) {
		t.Fatalf("duplicate dispatch command = %v", err)
	}
}

func TestRolloutPersistenceOutboxLeaseUnknownCrashAndExactReplay(t *testing.T) {
	pool := openRolloutPersistenceIntegrationPool(t)
	identity := seedRolloutPersistenceIdentity(t, pool)
	plan := mustRolloutPlan(t)
	insertRolloutPersistencePlan(t, pool, identity, &plan)
	now := time.Date(2026, 8, 4, 3, 0, 0, 0, time.UTC)
	store := requireRolloutPersistence(t, NewStore(pool, nil, nil, func() time.Time { return now }))
	cause, _ := rolloutCause(t, planCommand(PlanStart, plan.Revision, "start_requested"))
	commit, err := store.TransactLocked(t.Context(), identity, plan.ID, cause,
		func(locked LockedRolloutPlan) (RolloutAtomicMutation, error) {
			return rolloutStartMutation(t, locked, cause, now), nil
		})
	if err != nil {
		t.Fatal(err)
	}
	want := commit.Outbox[0]
	first, err := store.ClaimOutbox(t.Context(), "worker-a", now, time.Minute, 1)
	if err != nil || len(first) != 1 || !bytes.Equal(first[0].Message.PayloadBytes, want.PayloadBytes) {
		t.Fatalf("first claim = (%#v, %v)", first, err)
	}
	if err := store.SettleOutbox(t.Context(), RolloutOutboxSettlement{
		OutboxID: want.ID, ClaimToken: first[0].ClaimToken, PayloadSHA256: want.PayloadSHA256,
		Disposition: RolloutOutboxUnknownOutcome, ErrorCode: "publish_result_unknown", SettledAt: now.Add(time.Second),
	}); err != nil {
		t.Fatal(err)
	}
	var state string
	var availableAt time.Time
	if err := pool.QueryRow(t.Context(), `SELECT state,available_at FROM control_upgrade_outbox WHERE id=$1`, want.ID).
		Scan(&state, &availableAt); err != nil {
		t.Fatal(err)
	}
	availableAt = availableAt.UTC().Truncate(time.Microsecond)
	if state != "unknown" {
		t.Fatalf("unknown settlement state = %q", state)
	}
	status := rolloutStatus(t, commit.NodeCommands[0], 1, "accepted", nodeID(879), availableAt)
	if _, err := store.RecordStatus(t.Context(), identity, status); !errors.Is(err, ErrResourceUnavailable) {
		t.Fatalf("status before durable publish = %v", err)
	}
	second, err := store.ClaimOutbox(t.Context(), "worker-b", availableAt.Add(-time.Microsecond), time.Minute, 1)
	if err != nil || len(second) != 0 {
		t.Fatalf("unknown outcome reclaimed before available_at = (%#v, %v)", second, err)
	}
	restarted := requireRolloutPersistence(t, NewStore(pool, nil, nil, func() time.Time { return availableAt }))
	second, err = restarted.ClaimOutbox(t.Context(), "worker-b", availableAt, time.Minute, 1)
	if err != nil || len(second) != 1 || !bytes.Equal(second[0].Message.PayloadBytes, want.PayloadBytes) ||
		second[0].Message.PayloadSHA256 != want.PayloadSHA256 {
		t.Fatalf("durable unknown reclaim after restart = (%#v, %v)", second, err)
	}
	if firstMessageID, secondMessageID := commandMessageID(first[0].Message.PayloadBytes),
		commandMessageID(second[0].Message.PayloadBytes); firstMessageID == "" || firstMessageID != secondMessageID {
		t.Fatalf("reclaimed Msg-Id changed: %q != %q", firstMessageID, secondMessageID)
	}
	if claimed, err := store.ClaimOutbox(t.Context(), "worker-c", availableAt.Add(30*time.Second), time.Minute, 1); err != nil || len(claimed) != 0 {
		t.Fatalf("unexpired crash claim = (%#v, %v)", claimed, err)
	}
	if _, pending, err := store.ReconcileOutbox(t.Context(), want.ID, want.PayloadSHA256,
		availableAt.Add(30*time.Second)); err != nil || pending {
		t.Fatalf("live claim reconcile = (%v, %v)", pending, err)
	}
	third, err := store.ClaimOutbox(t.Context(), "worker-c", availableAt.Add(64*time.Second), time.Minute, 1)
	if err != nil || len(third) != 1 || !bytes.Equal(third[0].Message.PayloadBytes, want.PayloadBytes) {
		t.Fatalf("crash-after-publish reclaim = (%#v, %v)", third, err)
	}
	if err := store.SettleOutbox(t.Context(), RolloutOutboxSettlement{
		OutboxID: want.ID, ClaimToken: third[0].ClaimToken, PayloadSHA256: want.PayloadSHA256,
		Disposition: RolloutOutboxPublished, PublishedStream: upgradeCommandStream, PublishedSequence: 41,
		SettledAt: now.Add(66 * time.Second),
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.SettleOutbox(t.Context(), RolloutOutboxSettlement{
		OutboxID: want.ID, ClaimToken: third[0].ClaimToken, PayloadSHA256: want.PayloadSHA256,
		Disposition: RolloutOutboxPublished, PublishedStream: upgradeCommandStream, PublishedSequence: 41,
		SettledAt: now.Add(67 * time.Second),
	}); err != nil {
		t.Fatalf("exact published replay = %v", err)
	}
	var publishedAt time.Time
	if err := pool.QueryRow(t.Context(), `SELECT published_at FROM control_upgrade_node_commands WHERE command_id=$1`, want.ID).
		Scan(&publishedAt); err != nil {
		t.Fatal(err)
	}
	status = rolloutStatus(t, commit.NodeCommands[0], 1, "accepted", nodeID(879),
		publishedAt.UTC().Add(time.Microsecond))
	if replayed, err := store.RecordStatus(t.Context(), identity, status); err != nil || replayed {
		t.Fatalf("status after durable publish = (%v, %v)", replayed, err)
	}
	if claimed, err := store.ClaimOutbox(t.Context(), "worker-e", availableAt.Add(2*time.Minute), time.Minute, 1); err != nil || len(claimed) != 0 {
		t.Fatalf("published claim = (%#v, %v)", claimed, err)
	}
}

func TestRolloutPersistenceRejectedUnknownNeverReclaims(t *testing.T) {
	_, store, command, now := rolloutPersistenceLockOrderFixture(t)
	claims, err := store.ClaimOutbox(t.Context(), "reject-worker", now, time.Minute, 1)
	if err != nil || len(claims) != 1 {
		t.Fatalf("rejection claim = (%#v, %v)", claims, err)
	}
	settlement := RolloutOutboxSettlement{OutboxID: command.ID, ClaimToken: claims[0].ClaimToken,
		PayloadSHA256: claims[0].Message.PayloadSHA256, Disposition: RolloutOutboxRejected,
		Stream: upgradeCommandStream, MessageID: commandMessageID(claims[0].Message.PayloadBytes),
		ErrorCode: "publish_rejected", SettledAt: now.Add(time.Second)}
	if err := store.SettleOutbox(t.Context(), settlement); err != nil {
		t.Fatal(err)
	}
	if err := store.SettleOutbox(t.Context(), settlement); err != nil {
		t.Fatalf("exact rejection replay = %v", err)
	}
	farFuture := now.Add(365 * 24 * time.Hour)
	if reclaimed, err := store.ClaimOutbox(t.Context(), "reject-reclaimer", farFuture, time.Minute, 1); err != nil || len(reclaimed) != 0 {
		t.Fatalf("rejected unknown reclaimed = (%#v, %v)", reclaimed, err)
	}
	if _, pending, err := store.ReconcileOutbox(t.Context(), command.ID,
		claims[0].Message.PayloadSHA256, farFuture); err != nil || pending {
		t.Fatalf("rejected unknown reconciled = (%v, %v)", pending, err)
	}
}

func TestRolloutPersistencePublishedSettlementIsAtomicAndIdempotent(t *testing.T) {
	t.Run("forged command state rolls back outbox", func(t *testing.T) {
		pool, store, command, now := rolloutPersistenceLockOrderFixture(t)
		claims, err := store.ClaimOutbox(t.Context(), "forged-state-worker", now, time.Minute, 1)
		if err != nil || len(claims) != 1 {
			t.Fatalf("forged state claim = (%#v, %v)", claims, err)
		}
		if _, err := pool.Exec(t.Context(), `UPDATE control_upgrade_node_commands
			SET state='published',published_at=transaction_timestamp() WHERE command_id=$1`, command.ID); err != nil {
			t.Fatal(err)
		}
		err = store.SettleOutbox(t.Context(), RolloutOutboxSettlement{OutboxID: command.ID,
			ClaimToken: claims[0].ClaimToken, PayloadSHA256: claims[0].Message.PayloadSHA256,
			Disposition: RolloutOutboxPublished, PublishedStream: upgradeCommandStream, PublishedSequence: 51})
		if !errors.Is(err, ErrStalePlanRevision) {
			t.Fatalf("forged command state settlement = %v", err)
		}
		var outboxState string
		var stream *string
		var sequence *uint64
		if err := pool.QueryRow(t.Context(), `SELECT state,published_stream,published_sequence
			FROM control_upgrade_outbox WHERE id=$1`, command.ID).Scan(&outboxState, &stream, &sequence); err != nil {
			t.Fatal(err)
		}
		if outboxState != "claimed" || stream != nil || sequence != nil {
			t.Fatalf("partial settlement escaped rollback: %q %v %v", outboxState, stream, sequence)
		}
	})

	t.Run("concurrent settlement has one immutable winner", func(t *testing.T) {
		pool, store, command, now := rolloutPersistenceLockOrderFixture(t)
		claims, err := store.ClaimOutbox(t.Context(), "concurrent-settle-worker", now, time.Minute, 1)
		if err != nil || len(claims) != 1 {
			t.Fatalf("concurrent settlement claim = (%#v, %v)", claims, err)
		}
		type result struct {
			sequence uint64
			err      error
		}
		start := make(chan struct{})
		results := make(chan result, 2)
		for _, sequence := range []uint64{61, 62} {
			sequence := sequence
			go func() {
				<-start
				results <- result{sequence: sequence, err: store.SettleOutbox(context.Background(),
					RolloutOutboxSettlement{OutboxID: command.ID, ClaimToken: claims[0].ClaimToken,
						PayloadSHA256: claims[0].Message.PayloadSHA256, Disposition: RolloutOutboxPublished,
						PublishedStream: upgradeCommandStream, PublishedSequence: sequence})}
			}()
		}
		close(start)
		var winner uint64
		for range 2 {
			result := <-results
			switch {
			case result.err == nil:
				if winner != 0 {
					t.Fatal("both concurrent settlements succeeded")
				}
				winner = result.sequence
			case !errors.Is(result.err, ErrPlanIdempotencyConflict):
				t.Fatalf("losing settlement error = %v", result.err)
			}
		}
		var outboxState, commandState, stream string
		var sequence uint64
		var outboxPublishedAt, commandPublishedAt time.Time
		if err := pool.QueryRow(t.Context(), `SELECT outbox.state,command.state,outbox.published_stream,
			outbox.published_sequence,outbox.published_at,command.published_at
			FROM control_upgrade_outbox outbox JOIN control_upgrade_node_commands command
			ON command.command_id=outbox.command_id WHERE outbox.id=$1`, command.ID).
			Scan(&outboxState, &commandState, &stream, &sequence, &outboxPublishedAt, &commandPublishedAt); err != nil {
			t.Fatal(err)
		}
		if winner == 0 || sequence != winner || outboxState != "published" || commandState != "published" ||
			stream != upgradeCommandStream || !outboxPublishedAt.Equal(commandPublishedAt) {
			t.Fatalf("atomic published state = winner=%d outbox=%q command=%q stream=%q sequence=%d at=%v/%v",
				winner, outboxState, commandState, stream, sequence, outboxPublishedAt, commandPublishedAt)
		}
		if err := store.SettleOutbox(t.Context(), RolloutOutboxSettlement{OutboxID: command.ID,
			ClaimToken: claims[0].ClaimToken, PayloadSHA256: claims[0].Message.PayloadSHA256,
			Disposition: RolloutOutboxPublished, PublishedStream: upgradeCommandStream,
			PublishedSequence: winner}); err != nil {
			t.Fatalf("immutable published replay = %v", err)
		}
	})
}

func TestRolloutPersistenceSettleAndStatusUseCommandThenOutboxLockOrder(t *testing.T) {
	pool := openRolloutPersistenceIntegrationPool(t)
	identity := seedRolloutPersistenceIdentity(t, pool)
	plan := mustRolloutPlan(t)
	insertRolloutPersistencePlan(t, pool, identity, &plan)
	now := time.Now().UTC().Truncate(time.Microsecond)
	store := requireRolloutPersistence(t, NewStore(pool, nil, nil, func() time.Time { return now }))
	cause, _ := rolloutCause(t, planCommand(PlanStart, plan.Revision, "start_requested"))
	commit, err := store.TransactLocked(t.Context(), identity, plan.ID, cause,
		func(locked LockedRolloutPlan) (RolloutAtomicMutation, error) {
			return rolloutStartMutation(t, locked, cause, now), nil
		})
	if errors.Is(err, ErrInvalidPlanCommand) {
		commit, err = store.TransactLocked(t.Context(), identity, plan.ID, cause,
			func(locked LockedRolloutPlan) (RolloutAtomicMutation, error) {
				mutation := rolloutStartMutation(t, locked, cause, now)
				command := &mutation.NodeCommands[0]
				command.SignedExecutionSHA256 = base64URLFromWireDigest(t, command.SignedExecutionSHA256)
				mutation.Outbox[0].PayloadBytes = mustJSONRollout(t, rolloutCommandEnvelope(*command))
				mutation.Outbox[0].PayloadSHA256 = base64.RawURLEncoding.EncodeToString(
					rolloutSHA256(mutation.Outbox[0].PayloadBytes))
				return mutation, nil
			})
	}
	if err != nil {
		t.Fatal(err)
	}
	claims, err := store.ClaimOutbox(t.Context(), "lock-order-publisher", now, time.Minute, 1)
	if err != nil || len(claims) != 1 {
		t.Fatalf("claim lock-order command = (%#v, %v)", claims, err)
	}

	applicationName := "controlupgrade_lock_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	config := pool.Config().Copy()
	config.ConnConfig.RuntimeParams["application_name"] = applicationName
	config.MaxConns = 1
	settlePool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(settlePool.Close)
	settleConnection, err := settlePool.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	settlePID := settleConnection.Conn().PgConn().PID()
	settleConnection.Release()
	settleStore := NewStore(settlePool, nil, nil, func() time.Time { return now })

	statusTx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = statusTx.Rollback(context.Background()) }()
	if _, err := statusTx.Exec(t.Context(), `SET LOCAL deadlock_timeout='100ms'`); err != nil {
		t.Fatal(err)
	}
	commandID := commit.NodeCommands[0].ID
	if _, err := statusTx.Exec(t.Context(), `SELECT command_id FROM control_upgrade_node_commands
		WHERE command_id=$1 FOR UPDATE`, commandID); err != nil {
		t.Fatal(err)
	}

	settled := make(chan error, 1)
	go func() {
		settled <- settleStore.SettleOutbox(context.Background(), RolloutOutboxSettlement{
			OutboxID: commandID, ClaimToken: claims[0].ClaimToken,
			PayloadSHA256: claims[0].Message.PayloadSHA256,
			Disposition:   RolloutOutboxPublished, PublishedStream: upgradeCommandStream,
			PublishedSequence: 71, SettledAt: now.Add(time.Second),
		})
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		select {
		case settleErr := <-settled:
			t.Fatalf("settlement returned before waiting on command lock: %v", settleErr)
		default:
		}
		var waiting bool
		if err := statusTx.QueryRow(t.Context(), `SELECT EXISTS(
			SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock')`,
			settlePID).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("settlement did not reach the command lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
	_, lockErr := statusTx.Exec(t.Context(), `SELECT id FROM control_upgrade_outbox
		WHERE command_id=$1 FOR UPDATE`, commandID)
	if lockErr == nil {
		lockErr = statusTx.Commit(t.Context())
	} else {
		_ = statusTx.Rollback(context.Background())
	}
	var settleErr error
	select {
	case settleErr = <-settled:
	case <-time.After(5 * time.Second):
		t.Fatal("settlement remained blocked after status-style locks were released")
	}
	if lockErr != nil || settleErr != nil {
		t.Fatalf("command->outbox lock order status/settle errors = (%v, %v)", lockErr, settleErr)
	}
}

func TestRolloutPersistenceClaimAndReconcileDoNotReverseStatusLockOrder(t *testing.T) {
	t.Run("claim", func(t *testing.T) {
		pool, store, command, now := rolloutPersistenceLockOrderFixture(t)
		statusTx, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = statusTx.Rollback(context.Background()) }()
		if _, err := statusTx.Exec(t.Context(), `SELECT command_id FROM control_upgrade_node_commands
			WHERE command_id=$1 FOR UPDATE`, command.ID); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		claims, err := store.ClaimOutbox(ctx, "claim-lock-order", now, time.Minute, 1)
		cancel()
		if err != nil || len(claims) != 1 {
			t.Fatalf("claim while status-style command lock held = (%#v, %v)", claims, err)
		}
	})

	t.Run("reconcile", func(t *testing.T) {
		pool, store, command, now := rolloutPersistenceLockOrderFixture(t)
		claims, err := store.ClaimOutbox(t.Context(), "reconcile-lock-order", now, time.Minute, 1)
		if err != nil || len(claims) != 1 {
			t.Fatalf("claim reconcile fixture = (%#v, %v)", claims, err)
		}
		if err := store.SettleOutbox(t.Context(), RolloutOutboxSettlement{
			OutboxID: command.ID, ClaimToken: claims[0].ClaimToken,
			PayloadSHA256: claims[0].Message.PayloadSHA256,
			Disposition:   RolloutOutboxUnknownOutcome, ErrorCode: "publish_result_unknown", SettledAt: now.Add(time.Second),
		}); err != nil {
			t.Fatal(err)
		}
		statusTx, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = statusTx.Rollback(context.Background()) }()
		if _, err := statusTx.Exec(t.Context(), `SELECT command_id FROM control_upgrade_node_commands
			WHERE command_id=$1 FOR UPDATE`, command.ID); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		message, pending, err := store.ReconcileOutbox(ctx, command.ID, claims[0].Message.PayloadSHA256,
			now.Add(2*time.Second))
		cancel()
		if err != nil || !pending || message.ID != command.ID {
			t.Fatalf("reconcile while status-style command lock held = (%#v, %v, %v)", message, pending, err)
		}
	})
}

func rolloutPersistenceLockOrderFixture(t *testing.T) (*pgxpool.Pool, RolloutPersistence,
	RolloutNodeCommand, time.Time) {
	t.Helper()
	pool := openRolloutPersistenceIntegrationPool(t)
	identity := seedRolloutPersistenceIdentity(t, pool)
	plan := mustRolloutPlan(t)
	insertRolloutPersistencePlan(t, pool, identity, &plan)
	now := time.Now().UTC().Truncate(time.Microsecond)
	store := requireRolloutPersistence(t, NewStore(pool, nil, nil, func() time.Time { return now }))
	cause, _ := rolloutCause(t, planCommand(PlanStart, plan.Revision, "start_requested"))
	commit, err := store.TransactLocked(t.Context(), identity, plan.ID, cause,
		func(locked LockedRolloutPlan) (RolloutAtomicMutation, error) {
			return rolloutStartMutation(t, locked, cause, now), nil
		})
	if err != nil {
		t.Fatal(err)
	}
	return pool, store, commit.NodeCommands[0], now
}

func TestRolloutPersistenceStatusRevisionGraphAndConcurrentUniqueness(t *testing.T) {
	pool := openRolloutPersistenceIntegrationPool(t)
	identity := seedRolloutPersistenceIdentity(t, pool)
	plan := mustRolloutPlan(t)
	insertRolloutPersistencePlan(t, pool, identity, &plan)
	store := requireRolloutPersistence(t, NewStore(pool, nil, nil, time.Now))
	cause, _ := rolloutCause(t, planCommand(PlanStart, plan.Revision, "start_requested"))
	commit, err := store.TransactLocked(t.Context(), identity, plan.ID, cause,
		func(locked LockedRolloutPlan) (RolloutAtomicMutation, error) {
			return rolloutStartMutation(t, locked, cause, time.Now()), nil
		})
	if err != nil {
		t.Fatal(err)
	}
	command := commit.NodeCommands[0]
	publishedAt := time.Now().UTC().Truncate(time.Microsecond)
	claims, err := store.ClaimOutbox(t.Context(), "status-publisher", publishedAt, time.Minute, 1)
	if err != nil || len(claims) != 1 {
		t.Fatalf("claim status command = (%#v, %v)", claims, err)
	}
	if err := store.SettleOutbox(t.Context(), RolloutOutboxSettlement{
		OutboxID: command.ID, ClaimToken: claims[0].ClaimToken,
		PayloadSHA256: claims[0].Message.PayloadSHA256,
		Disposition:   RolloutOutboxPublished, PublishedStream: upgradeCommandStream,
		PublishedSequence: 81, SettledAt: publishedAt,
	}); err != nil {
		t.Fatal(err)
	}
	claimed := rolloutStatus(t, command, 1, "claimed", nodeID(832), time.Now())
	tampered := claimed
	var payload agentRolloutStatusV1
	if err := json.Unmarshal(tampered.StatusBytes, &payload); err != nil {
		t.Fatal(err)
	}
	payload.NodeID = nodeID(99)
	tampered.StatusBytes = mustJSONRollout(t, payload)
	tampered.StatusSHA256 = digestRolloutWireBytes(tampered.StatusBytes)
	if _, err := store.RecordStatus(t.Context(), identity, tampered); !errors.Is(err, ErrInvalidPlanEvent) {
		t.Fatalf("mismatched status bytes = %v", err)
	}
	if replayed, err := store.RecordStatus(t.Context(), identity, claimed); err != nil || replayed {
		t.Fatalf("claimed status = (%v, %v)", replayed, err)
	}
	var commandState string
	var acknowledgedAt *time.Time
	if err := pool.QueryRow(t.Context(), `SELECT state,acknowledged_at
		FROM control_upgrade_node_commands WHERE command_id=$1`, command.ID).
		Scan(&commandState, &acknowledgedAt); err != nil || commandState != "acknowledged" || acknowledgedAt == nil {
		t.Fatalf("acknowledged command = (%q, %v, %v)", commandState, acknowledgedAt, err)
	}
	if replayed, err := store.RecordStatus(t.Context(), identity, claimed); err != nil || !replayed {
		t.Fatalf("claimed replay = (%v, %v)", replayed, err)
	}

	statuses := []RolloutStatusReceipt{
		rolloutStatus(t, command, 2, "installing", nodeID(833), time.Now().Add(time.Second)),
		rolloutStatus(t, command, 2, "uncertain", nodeID(834), time.Now().Add(time.Second)),
	}
	results := make(chan error, len(statuses))
	var wait sync.WaitGroup
	for _, status := range statuses {
		status := status
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := store.RecordStatus(context.Background(), identity, status)
			results <- err
		}()
	}
	wait.Wait()
	close(results)
	var succeeded, failed int
	for err := range results {
		if err == nil {
			succeeded++
		} else {
			failed++
		}
	}
	if succeeded != 1 || failed != 1 {
		t.Fatalf("concurrent status succeeded/failed=%d/%d", succeeded, failed)
	}
	gap := rolloutStatus(t, command, 4, "healthy", nodeID(835), time.Now().Add(2*time.Second))
	if _, err := store.RecordStatus(t.Context(), identity, gap); err == nil {
		t.Fatal("status revision gap was accepted")
	}
}

func TestRolloutPersistenceAcceptsAgentProgressionAndBindsUncertainReconciliation(t *testing.T) {
	pool := openRolloutPersistenceIntegrationPool(t)
	identity := seedRolloutPersistenceIdentity(t, pool)
	plan := mustRolloutPlan(t)
	insertRolloutPersistencePlan(t, pool, identity, &plan)
	store := requireRolloutPersistence(t, NewStore(pool, nil, nil, time.Now))
	cause, _ := rolloutCause(t, planCommand(PlanStart, plan.Revision, "start_requested"))
	commit, err := store.TransactLocked(t.Context(), identity, plan.ID, cause,
		func(locked LockedRolloutPlan) (RolloutAtomicMutation, error) {
			return rolloutStartMutation(t, locked, cause, time.Now()), nil
		})
	if err != nil {
		t.Fatal(err)
	}
	command := commit.NodeCommands[0]
	publishedAt := time.Now().UTC().Truncate(time.Microsecond)
	claims, err := store.ClaimOutbox(t.Context(), "reconcile-publisher", publishedAt, time.Minute, 1)
	if err != nil || len(claims) != 1 {
		t.Fatalf("claim reconcile command = (%#v, %v)", claims, err)
	}
	if err := store.SettleOutbox(t.Context(), RolloutOutboxSettlement{
		OutboxID: command.ID, ClaimToken: claims[0].ClaimToken,
		PayloadSHA256: claims[0].Message.PayloadSHA256,
		Disposition:   RolloutOutboxPublished, PublishedStream: upgradeCommandStream,
		PublishedSequence: 91, SettledAt: publishedAt,
	}); err != nil {
		t.Fatal(err)
	}

	transactionID := "txn-control-reconcile-1"
	statuses := []RolloutStatusReceipt{
		agentRolloutStatus(t, command, 1, "accepted", nodeID(891), "", publishedAt.Add(time.Second)),
		agentRolloutStatus(t, command, 2, "claimed", nodeID(892), "", publishedAt.Add(2*time.Second)),
		agentRolloutStatus(t, command, 3, "installing", nodeID(893), transactionID, publishedAt.Add(3*time.Second)),
		agentRolloutStatus(t, command, 4, "uncertain", nodeID(894), transactionID, publishedAt.Add(4*time.Second)),
	}
	for _, status := range statuses {
		if terminalRolloutStatus(status.State) {
			if _, err := store.RecordStatus(t.Context(), identity, status); !errors.Is(err, ErrResourceUnavailable) {
				t.Fatalf("direct terminal store write = %v", err)
			}
			production := store.(*Store)
			prepared, replayed, err := production.PrepareRolloutStatus(t.Context(), identity, status)
			if err == nil && !replayed {
				replayed, err = production.FinalizeRolloutStatus(t.Context(), prepared, nil, nil)
			}
			if err != nil || replayed {
				t.Fatalf("record %s = (%v, %v)", status.State, replayed, err)
			}
			continue
		}
		if replayed, err := store.RecordStatus(t.Context(), identity, status); err != nil || replayed {
			t.Fatalf("record %s = (%v, %v)", status.State, replayed, err)
		}
	}
	mismatched := agentRolloutStatusV2(t, plan, command, 5, "healthy", nodeID(895),
		"txn-control-reconcile-2", publishedAt.Add(5*time.Second))
	production := store.(*Store)
	if _, _, err := production.PrepareRolloutStatus(t.Context(), identity, mismatched); !errors.Is(err, ErrInvalidPlanEvent) {
		t.Fatalf("mismatched reconciliation transaction = %v", err)
	}
	reconciled := agentRolloutStatusV2(t, plan, command, 5, "rolled_back", nodeID(896),
		transactionID, publishedAt.Add(5*time.Second))
	prepared, replayed, err := production.PrepareRolloutStatus(t.Context(), identity, reconciled)
	if err == nil && !replayed {
		commands, outbox := rolloutStatusDispatchFixtures(t, identity, prepared.Plan, prepared.Health, prepared.Dispatches)
		replayed, err = production.FinalizeRolloutStatus(t.Context(), prepared, commands, outbox)
	}
	if err != nil || replayed {
		t.Fatalf("reconciled status = (%v, %v)", replayed, err)
	}
}

func TestRolloutPersistenceTerminalStatusAtomicallyAdvancesPlan(t *testing.T) {
	t.Run("healthy dispatches next batch", func(t *testing.T) {
		pool, store, identity, plan, command, publishedAt := terminalStatusPersistenceFixture(t)
		status := agentRolloutStatusV2(t, plan, command, 4, "healthy", nodeID(897),
			"txn-terminal-status", publishedAt.Add(4*time.Second))
		prepared, replayed, err := store.PrepareRolloutStatus(t.Context(), identity, status)
		if err != nil || replayed || len(prepared.Dispatches) != 2 {
			t.Fatalf("prepare healthy = (%#v,%v,%v)", prepared, replayed, err)
		}
		commands, outbox := rolloutStatusDispatchFixtures(t, identity, prepared.Plan, prepared.Health, prepared.Dispatches)
		if replayed, err = store.FinalizeRolloutStatus(t.Context(), prepared, commands, outbox); err != nil || replayed {
			t.Fatalf("finalize healthy = (%v,%v)", replayed, err)
		}
		assertTerminalStatusCommit(t, pool, plan.ID, command.ID, status.StatusID,
			PlanRunning, 3, 2, 2)
		if _, replayed, err := store.PrepareRolloutStatus(t.Context(), identity, status); err != nil || !replayed {
			t.Fatalf("healthy replay = (%v,%v)", replayed, err)
		}
	})

	t.Run("failure dispatches automatic rollback", func(t *testing.T) {
		pool, store, identity, plan, command, publishedAt := terminalStatusPersistenceFixture(t)
		status := agentRolloutStatus(t, command, 4, "failed", nodeID(898),
			"txn-terminal-status", publishedAt.Add(4*time.Second))
		prepared, replayed, err := store.PrepareRolloutStatus(t.Context(), identity, status)
		if err != nil || replayed || len(prepared.Dispatches) != 1 || prepared.Dispatches[0].Action != "rollback" {
			t.Fatalf("prepare failed = (%#v,%v,%v)", prepared, replayed, err)
		}
		commands, outbox := rolloutStatusDispatchFixtures(t, identity, prepared.Plan, prepared.Health, prepared.Dispatches)
		if replayed, err = store.FinalizeRolloutStatus(t.Context(), prepared, commands, outbox); err != nil || replayed {
			t.Fatalf("finalize failed = (%v,%v)", replayed, err)
		}
		assertTerminalStatusCommit(t, pool, plan.ID, command.ID, status.StatusID,
			PlanRollingBack, 4, 1, 1)
	})
}

func terminalStatusPersistenceFixture(t *testing.T) (*pgxpool.Pool, *Store, RolloutIdentity,
	RolloutPlan, RolloutNodeCommand, time.Time) {
	t.Helper()
	pool := openRolloutPersistenceIntegrationPool(t)
	identity := seedRolloutPersistenceIdentity(t, pool)
	plan := mustRolloutPlan(t)
	insertRolloutPersistencePlan(t, pool, identity, &plan)
	store := NewStore(pool, nil, nil, time.Now)
	cause, _ := rolloutCause(t, planCommand(PlanStart, plan.Revision, "start_requested"))
	commit, err := store.TransactLocked(t.Context(), identity, plan.ID, cause,
		func(locked LockedRolloutPlan) (RolloutAtomicMutation, error) {
			return rolloutStartMutation(t, locked, cause, time.Now()), nil
		})
	if err != nil {
		t.Fatal(err)
	}
	command := commit.NodeCommands[0]
	claims, err := store.ClaimOutbox(t.Context(), "terminal-status-publisher", time.Now(), time.Minute, 1)
	if err != nil || len(claims) != 1 {
		t.Fatalf("terminal status claim = (%#v,%v)", claims, err)
	}
	if err := store.SettleOutbox(t.Context(), RolloutOutboxSettlement{OutboxID: command.ID,
		ClaimToken: claims[0].ClaimToken, PayloadSHA256: claims[0].Message.PayloadSHA256,
		Disposition: RolloutOutboxPublished, PublishedStream: upgradeCommandStream, PublishedSequence: 101}); err != nil {
		t.Fatal(err)
	}
	var publishedAt time.Time
	if err := pool.QueryRow(t.Context(), `SELECT published_at FROM control_upgrade_node_commands WHERE command_id=$1`,
		command.ID).Scan(&publishedAt); err != nil {
		t.Fatal(err)
	}
	publishedAt = publishedAt.UTC().Truncate(time.Microsecond)
	transactionID := "txn-terminal-status"
	for index, state := range []string{"accepted", "claimed", "installing"} {
		status := agentRolloutStatus(t, command, uint64(index+1), state, nodeID(910+index),
			transactionID, publishedAt.Add(time.Duration(index+1)*time.Second))
		if replayed, err := store.RecordStatus(t.Context(), identity, status); err != nil || replayed {
			t.Fatalf("record %s = (%v,%v)", state, replayed, err)
		}
	}
	return pool, store, identity, plan, command, publishedAt
}

func rolloutStatusDispatchFixtures(t *testing.T, identity RolloutIdentity, plan RolloutPlan,
	health PlanHealthEvent, dispatches []RolloutDispatchIntent) ([]RolloutNodeCommand, []RolloutOutboxMessage) {
	t.Helper()
	result, err := ApplyPlanHealth(plan, health)
	if err != nil {
		t.Fatal(err)
	}
	commands := make([]RolloutNodeCommand, 0, len(dispatches))
	outbox := make([]RolloutOutboxMessage, 0, len(dispatches))
	for _, dispatch := range dispatches {
		signingPlan := cloneRolloutPlan(result.Plan)
		grant, expiresAt, execution := rolloutSignedExecution(t, identity, signingPlan,
			dispatch.CommandID, dispatch.PlanRevision, dispatch.BatchID, dispatch.NodeID)
		command := RolloutNodeCommand{ID: dispatch.CommandID, PlanID: dispatch.PlanID,
			PlanRevision: dispatch.PlanRevision, BatchID: dispatch.BatchID, NodeID: dispatch.NodeID,
			InstallationID: dispatch.InstallationID, Action: dispatch.Action, CommandGrantBytes: grant,
			CommandGrantSHA256: digestRolloutBytes(grant), CommandGrantExpiresAt: expiresAt,
			SignedExecutionBytes: execution, SignedExecutionSHA256: digestRolloutWireBytes(execution)}
		if !validRolloutCommand(identity, signingPlan, command) {
			t.Fatalf("invalid dispatch fixture action=%s state=%s plan-revision=%d command-revision=%d node-revision=%d batch=%s",
				command.Action, signingPlan.State, signingPlan.Revision, command.PlanRevision,
				signingPlan.NodeDispatchRevisions[command.NodeID], command.BatchID)
		}
		payload := mustJSONRollout(t, rolloutCommandEnvelope(command))
		commands = append(commands, command)
		outbox = append(outbox, RolloutOutboxMessage{ID: command.ID, PlanID: command.PlanID,
			PlanRevision: command.PlanRevision, Topic: upgradeCommandSubjectPrefix + "." + command.NodeID,
			MessageKey: command.ID, PayloadBytes: payload, PayloadSHA256: digestRolloutWireBytes(payload),
			AvailableAt: time.Now().UTC()})
	}
	return commands, outbox
}

func assertTerminalStatusCommit(t *testing.T, pool *pgxpool.Pool, planID, commandID, statusID string,
	wantState PlanState, wantRevision uint64, wantCommands, wantOutbox int) {
	t.Helper()
	var snapshot, digest []byte
	if err := pool.QueryRow(t.Context(), `SELECT canonical_snapshot_bytes,canonical_snapshot_sha256
		FROM control_upgrade_rollout_plans WHERE id=$1`, planID).Scan(&snapshot, &digest); err != nil {
		t.Fatal(err)
	}
	plan, _, err := decodeRolloutPlan(snapshot, digest)
	if err != nil || plan.State != wantState || plan.Revision != wantRevision {
		t.Fatalf("terminal plan = (%#v,%v)", plan, err)
	}
	var state string
	var statusCount, commandCount, outboxCount int
	if err := pool.QueryRow(t.Context(), `SELECT state FROM control_upgrade_node_commands WHERE command_id=$1`,
		commandID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM control_upgrade_status_receipts WHERE status_id=$1`,
		statusID).Scan(&statusCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM control_upgrade_node_commands
		WHERE plan_id=$1 AND command_id<>$2`, planID, commandID).Scan(&commandCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM control_upgrade_outbox
		WHERE plan_id=$1 AND command_id<>$2`, planID, commandID).Scan(&outboxCount); err != nil {
		t.Fatal(err)
	}
	if state != "acknowledged" || statusCount != 1 || commandCount != wantCommands || outboxCount != wantOutbox {
		t.Fatalf("terminal facts = state=%q status=%d commands=%d outbox=%d",
			state, statusCount, commandCount, outboxCount)
	}
}

func requireRolloutPersistence(t *testing.T, store *Store) RolloutPersistence {
	t.Helper()
	persistence, ok := any(store).(RolloutPersistence)
	if !ok {
		t.Fatal("production Store does not implement RolloutPersistence")
	}
	return persistence
}

func rolloutStartMutation(
	t *testing.T,
	locked LockedRolloutPlan,
	cause RolloutCausation,
	availableAt time.Time,
) RolloutAtomicMutation {
	t.Helper()
	commandInput := planCommand(PlanStart, locked.Plan.Revision, "start_requested")
	result := mustPlanCommand(t, locked.Plan, commandInput)
	_, causeBytes := rolloutCause(t, commandInput)
	events := []RolloutEventMutation{rolloutEventMutation(t, cause, causeBytes, result.Event)}
	commandID := nodeID(840 + int(result.Event.Revision))
	batchID := result.Plan.Batches[result.Plan.ActiveBatch].ID
	commandGrant, commandGrantExpiresAt, signedExecution := rolloutSignedExecution(t, locked.Identity,
		result.Plan, commandID, result.Event.Revision, batchID, nodeID(1))
	command := RolloutNodeCommand{
		ID: commandID, PlanID: result.Plan.ID, PlanRevision: result.Event.Revision,
		BatchID: batchID, NodeID: nodeID(1), InstallationID: locked.Identity.InstallationID,
		Action: "upgrade", CommandGrantBytes: commandGrant,
		CommandGrantSHA256: digestRolloutBytes(commandGrant), CommandGrantExpiresAt: commandGrantExpiresAt,
		SignedExecutionBytes:  signedExecution,
		SignedExecutionSHA256: digestRolloutWireBytes(signedExecution),
	}
	payload := mustJSONRollout(t, rolloutCommandEnvelope(command))
	outbox := RolloutOutboxMessage{
		ID: command.ID, PlanID: command.PlanID, PlanRevision: command.PlanRevision,
		Topic:      upgradeCommandSubjectPrefix + "." + command.NodeID,
		MessageKey: command.ID, PayloadBytes: payload, PayloadSHA256: digestRolloutWireBytes(payload), AvailableAt: availableAt,
	}
	return rolloutMutation(t, locked.Plan.Revision, result.Plan, events,
		[]RolloutNodeCommand{command}, []RolloutOutboxMessage{outbox})
}

func rolloutMutation(t *testing.T, expected uint64, plan RolloutPlan, events []RolloutEventMutation,
	commands []RolloutNodeCommand, outbox []RolloutOutboxMessage) RolloutAtomicMutation {
	t.Helper()
	snapshot := mustJSONRollout(t, plan)
	return RolloutAtomicMutation{
		ExpectedRevision: expected, Plan: plan, CanonicalSnapshotBytes: snapshot,
		CanonicalSnapshotSHA256: digestRolloutBytes(snapshot), Events: events, NodeCommands: commands, Outbox: outbox,
	}
}

func rolloutEventMutation(t *testing.T, cause RolloutCausation, causeBytes []byte, event PlanEvent) RolloutEventMutation {
	t.Helper()
	encoded := mustJSONRollout(t, event)
	item := RolloutEventMutation{
		Causation: cause, Event: event, EventBytes: encoded, EventSHA256: digestRolloutBytes(encoded),
	}
	setRolloutCausationBytes(t, &item, causeBytes)
	return item
}

func rollbackCommandOutbox(t *testing.T, identity RolloutIdentity, plan RolloutPlan,
	planRevision uint64) ([]RolloutNodeCommand, []RolloutOutboxMessage) {
	t.Helper()
	batch := plan.RollbackBatches[plan.ActiveBatch]
	commands := make([]RolloutNodeCommand, 0, len(batch.NodeIDs))
	outbox := make([]RolloutOutboxMessage, 0, len(batch.NodeIDs))
	for index, node := range batch.NodeIDs {
		commandID := nodeID(860 + index)
		commandGrant, commandGrantExpiresAt, signedExecution := rolloutSignedExecution(t, identity, plan,
			commandID, planRevision, batch.ID, node)
		command := RolloutNodeCommand{
			ID: commandID, PlanID: plan.ID, PlanRevision: planRevision, BatchID: batch.ID, NodeID: node,
			InstallationID: identity.InstallationID, Action: "rollback", CommandGrantBytes: commandGrant,
			CommandGrantSHA256: digestRolloutBytes(commandGrant), CommandGrantExpiresAt: commandGrantExpiresAt,
			SignedExecutionBytes:  signedExecution,
			SignedExecutionSHA256: digestRolloutWireBytes(signedExecution),
		}
		payload := mustJSONRollout(t, rolloutCommandEnvelope(command))
		commands = append(commands, command)
		outbox = append(outbox, RolloutOutboxMessage{
			ID: commandID, PlanID: plan.ID, PlanRevision: planRevision,
			Topic:      upgradeCommandSubjectPrefix + "." + command.NodeID,
			MessageKey: commandID, PayloadBytes: payload, PayloadSHA256: digestRolloutWireBytes(payload), AvailableAt: time.Now(),
		})
	}
	return commands, outbox
}

func rolloutStatus(t *testing.T, command RolloutNodeCommand, revision uint64, state, statusID string,
	observed time.Time) RolloutStatusReceipt {
	return agentRolloutStatus(t, command, revision, state, statusID, "", observed)
}

// agentRolloutStatusV2 is a healthy/rolled_back receipt with active-probe
// evidence: v1 success receipts are rejected as stale evidence
// (runtime_action.go rolloutHealthFromStatus).
func agentRolloutStatusV2(t *testing.T, plan RolloutPlan, command RolloutNodeCommand, revision uint64, state,
	statusID, installerTransactionID string, observed time.Time) RolloutStatusReceipt {
	t.Helper()
	receipt := agentRolloutStatus(t, command, revision, state, statusID, installerTransactionID, observed)
	var payload rolloutStatusPayload
	if err := json.Unmarshal(receipt.StatusBytes, &payload); err != nil {
		t.Fatal(err)
	}
	// The status trigger (migration 105) requires hex digests and treats every
	// rolled_back as "rollback artifact active, forward artifact last known good".
	payload.Schema = EdgeUpgradeStatusSchemaV2
	payload.ActiveEvidence = activeProbeEvidenceForPlan(plan, state == "rolled_back", receipt.ObservedAt)
	for _, field := range []*string{&payload.ActiveEvidence.ActiveArtifactSHA256,
		&payload.ActiveEvidence.ActiveConfigSHA256, &payload.ActiveEvidence.LastKnownGoodArtifactSHA256,
		&payload.ActiveEvidence.LastKnownGoodConfigSHA256} {
		decoded, err := base64.RawURLEncoding.DecodeString(*field)
		if err != nil {
			t.Fatal(err)
		}
		*field = hex.EncodeToString(decoded)
	}
	payload.ActiveEvidence.EvidenceSHA256 = activeProbeEvidenceDigest(payload.InstallerTransactionID, *payload.ActiveEvidence)
	receipt.Schema = EdgeUpgradeStatusSchemaV2
	receipt.StatusBytes = mustJSONRollout(t, payload)
	receipt.StatusSHA256 = digestRolloutWireBytes(receipt.StatusBytes)
	receipt.ActiveEvidence = cloneControlActiveProbeEvidence(payload.ActiveEvidence)
	return receipt
}

func agentRolloutStatus(t *testing.T, command RolloutNodeCommand, revision uint64, state, statusID,
	installerTransactionID string, observed time.Time) RolloutStatusReceipt {
	t.Helper()
	commandBytes := mustJSONRollout(t, rolloutCommandEnvelope(command))
	receipt := RolloutStatusReceipt{
		StatusID: statusID, StatusRevision: revision, CommandID: command.ID, PlanID: command.PlanID,
		PlanRevision: command.PlanRevision, BatchID: command.BatchID, InstallationID: command.InstallationID,
		NodeID: command.NodeID, Action: command.Action, CommandSHA256: digestRolloutWireBytes(commandBytes),
		State: state, ObservedAt: observed.UTC().Truncate(time.Microsecond),
	}
	currentVersion, previousVersion, errorCode := "", "", ""
	alertRequired := false
	if installerTransactionID == "" && state != "accepted" && state != "claimed" {
		installerTransactionID = "txn-" + strings.ReplaceAll(command.ID, "-", "")
	}
	switch state {
	case "accepted", "claimed":
		installerTransactionID = ""
	case "installing":
	case "healthy":
		currentVersion, previousVersion = "2.0.0", "1.0.0"
	case "rolling_back":
		currentVersion, previousVersion, errorCode = "1.0.0", "2.0.0", "HEALTH_FAILED"
	case "rolled_back":
		if command.Action == "rollback" {
			currentVersion, previousVersion = "2.0.0", "1.0.0"
		} else {
			currentVersion, previousVersion, errorCode = "1.0.0", "2.0.0", "HEALTH_FAILED"
		}
	case "failed":
		currentVersion, errorCode, alertRequired = "1.0.0", "UPGRADE_FAILED", true
	case "uncertain":
		errorCode, alertRequired = "INSTALLER_OUTCOME_UNKNOWN", true
	}
	receipt.StatusBytes = mustJSONRollout(t, agentRolloutStatusV1{
		Schema: "cdnca.edge.upgrade.status/v1", StatusID: receipt.StatusID,
		StatusRevision: receipt.StatusRevision, CommandID: receipt.CommandID, PlanID: receipt.PlanID,
		PlanRevision: receipt.PlanRevision, InstallationID: receipt.InstallationID,
		NodeID: receipt.NodeID, CommandSHA256: receipt.CommandSHA256, State: receipt.State,
		CurrentVersion: currentVersion, PreviousVersion: previousVersion,
		InstallerTransactionID: installerTransactionID,
		ErrorCode:              errorCode, AlertRequired: alertRequired, ObservedAt: receipt.ObservedAt,
	})
	receipt.StatusSHA256 = digestRolloutWireBytes(receipt.StatusBytes)
	deliveryDigest := sha256.Sum256([]byte(receipt.StatusID))
	for index := 0; index < 8; index++ {
		receipt.DeliverySequence = receipt.DeliverySequence<<8 | uint64(deliveryDigest[index])
	}
	receipt.DeliverySequence &= 1<<63 - 1
	if receipt.DeliverySequence == 0 {
		receipt.DeliverySequence = 1
	}
	receipt.DeliveryStream = upgradeStatusStream
	receipt.DeliveryConsumer = upgradeStatusConsumer
	return receipt
}

func rolloutPlanStringField(t *testing.T, plan RolloutPlan, name string) string {
	t.Helper()
	field := reflect.ValueOf(plan).FieldByName(name)
	if !field.IsValid() || field.Kind() != reflect.String {
		t.Errorf("RolloutPlan missing string field %s", name)
		return ""
	}
	return field.String()
}

func rolloutPlanUintField(t *testing.T, plan RolloutPlan, name string) uint64 {
	t.Helper()
	field := reflect.ValueOf(plan).FieldByName(name)
	if !field.IsValid() || field.Kind() != reflect.Uint64 {
		t.Errorf("RolloutPlan missing uint64 field %s", name)
		return 0
	}
	return field.Uint()
}

func rolloutCause(t *testing.T, value any) (RolloutCausation, []byte) {
	t.Helper()
	encoded := mustJSONRollout(t, value)
	var id string
	switch cause := value.(type) {
	case PlanCommand:
		id = cause.ID
	case PlanHealthEvent:
		id = cause.ID
	default:
		t.Fatalf("unsupported rollout causation %T", value)
	}
	return RolloutCausation{ID: id, SHA256: digestRolloutBytes(encoded)}, encoded
}

func setRolloutCausationBytes(t *testing.T, item *RolloutEventMutation, encoded []byte) {
	t.Helper()
	field := reflect.ValueOf(item).Elem().FieldByName("CausationBytes")
	if !field.IsValid() {
		return
	}
	field.SetBytes(bytes.Clone(encoded))
}

func rolloutCommandEnvelope(command RolloutNodeCommand) rolloutCommandPayload {
	return rolloutCommandPayload{
		Schema: "cdnca.edge.upgrade.command/v1", CommandID: command.ID, PlanID: command.PlanID,
		PlanRevision: command.PlanRevision, BatchID: command.BatchID,
		InstallationID: command.InstallationID, NodeID: command.NodeID, Action: command.Action,
		SignedExecution:       command.SignedExecutionBytes,
		SignedExecutionSHA256: command.SignedExecutionSHA256,
	}
}

func rolloutSignedExecution(
	t *testing.T,
	identity RolloutIdentity,
	plan RolloutPlan,
	commandID string,
	planRevision uint64,
	batchID, targetNodeID string,
) ([]byte, time.Time, []byte) {
	t.Helper()
	releaseSequence := plan.ReleaseSequence
	operation := entitlement.UpgradeOperation
	currentVersion, targetVersion := plan.CurrentVersion, plan.TargetVersion
	artifactID, artifactDigest, artifactSize := plan.ArtifactID, plan.SHA256Digest, plan.ArtifactSizeBytes
	profile := plan.ForwardProfile
	if plan.State == PlanRollingBack {
		operation = entitlement.RollbackOperation
		currentVersion, targetVersion = plan.TargetVersion, plan.CurrentVersion
		artifactID, artifactDigest, artifactSize = plan.RollbackArtifactID, plan.RollbackSHA256Digest,
			plan.RollbackArtifactSizeBytes
		profile = plan.RollbackProfile
	}
	issuedAt := plan.ParentGrantExpiresAt - int64(10*time.Minute/time.Second)
	expiresAt := issuedAt + int64(5*time.Minute/time.Second)
	grantSigner := grantTestSigner{privateKey: executionPrivateKey(0x90)}
	manifest := entitlement.ArtifactManifestV2{
		Schema: entitlement.ArtifactManifestV2Schema, Audience: entitlement.ArtifactManifestAudience,
		Purpose: entitlement.ArtifactManifestPurpose, ArtifactID: artifactID, Component: plan.Component,
		Version: targetVersion, ProtocolMin: int(plan.Safety.ProtocolMin), ProtocolMax: int(plan.Safety.ProtocolMax),
		ArtifactSizeBytes: artifactSize, DigestAlgorithm: "sha256", SHA256Digest: artifactDigest,
		DownloadURL: "https://downloads.example.test/" + artifactID,
	}
	manifestSignature, err := entitlement.SignArtifactManifestV2(t.Context(), manifest, grantSigner)
	if err != nil {
		t.Fatal(err)
	}
	grant := entitlement.UpgradeCommandGrant{
		Schema: entitlement.UpgradeCommandGrantV2Schema, Audience: entitlement.UpgradeCommandGrantAudience,
		Purpose: entitlement.UpgradeCommandGrantPurpose, CommandID: commandID, Nonce: uuid.NewString(),
		ParentGrantID: plan.ParentGrantID, ParentGrantSHA256: plan.GrantDigest,
		ParentGrantIssuedAt:  plan.ParentGrantExpiresAt - int64(15*time.Minute/time.Second),
		ParentGrantExpiresAt: plan.ParentGrantExpiresAt,
		PlanID:               plan.ID, PlanRevision: planRevision, BatchID: batchID,
		ArtifactBundleID: plan.ArtifactBundleID, ArtifactBundleSHA256: plan.ArtifactBundleSHA256,
		CommandIssuanceNotAfter: plan.CommandIssuanceNotAfter,
		CustomerID:              nodeID(181), InstallationID: identity.InstallationID, LicenseID: nodeID(182),
		Channel: "stable", ChannelRevision: releaseSequence, Component: plan.Component, Operation: operation,
		CurrentVersion: currentVersion, Version: targetVersion, ProtocolVersion: int(plan.Safety.ProtocolMin),
		ArtifactID: artifactID, ArtifactProtocolMin: manifest.ProtocolMin, ArtifactProtocolMax: manifest.ProtocolMax,
		ArtifactSizeBytes: artifactSize, DownloadURL: manifest.DownloadURL,
		DigestAlgorithm: "sha256", SHA256Digest: artifactDigest,
		ArtifactSignatureAlgorithm: entitlement.Algorithm, ArtifactSignatureKeyID: grantSigner.KeyID(),
		ArtifactManifestSignature: base64.RawURLEncoding.EncodeToString(manifestSignature),
		NodeID:                    targetNodeID, Platform: profile.Platform, Architecture: profile.Architecture,
		Compatibility: profile.Compatibility, Health: profile.Health, Rollout: profile.Rollout,
		Rollback: profile.Rollback, IssuedAt: issuedAt, NotBefore: issuedAt, ExpiresAt: expiresAt,
	}
	signedGrant, err := entitlement.SignUpgradeCommandGrant(t.Context(), grant, grantSigner)
	if err != nil {
		t.Fatal(err)
	}
	grantBytes, err := signedGrant.Encode()
	if err != nil {
		t.Fatal(err)
	}
	grantKeys := entitlement.NewKeyRing()
	if err := grantKeys.Add(grantSigner.KeyID(), grantSigner.privateKey.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	execution, err := IssueCommandExecution(t.Context(), grantBytes, grantKeys,
		entitlement.UpgradeCommandGrantVerifyOptions{Now: time.Unix(issuedAt, 0).UTC(),
			ExpectedAudience: entitlement.UpgradeCommandGrantAudience, ExpectedInstallationID: identity.InstallationID,
			ExpectedNodeID: targetNodeID, ExpectedCommandID: commandID, ExpectedPlanID: plan.ID,
			ExpectedPlanRevision: planRevision, ExpectedBatchID: batchID},
		&executionCountingSigner{id: "control-execution-1", privateKey: executionPrivateKey(0x91)},
		&executionCountingSigner{id: "edge-consumption-1", privateKey: executionPrivateKey(0x92)})
	if err != nil {
		t.Fatal(err)
	}
	return grantBytes, time.Unix(expiresAt, 0).UTC(), execution
}

func mustJSONRollout(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func digestRolloutBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func digestRolloutWireBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func base64URLFromWireDigest(t *testing.T, value string) string {
	t.Helper()
	digest, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(digest)
}

func assertRolloutAtomicCounts(t *testing.T, pool *pgxpool.Pool, planID string, events, commands, outbox int) {
	t.Helper()
	var gotEvents, gotCommands, gotOutbox int
	if err := pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM control_upgrade_rollout_events WHERE plan_id=$1),
		(SELECT count(*) FROM control_upgrade_node_commands WHERE plan_id=$1),
		(SELECT count(*) FROM control_upgrade_outbox WHERE plan_id=$1)`, planID).Scan(&gotEvents, &gotCommands, &gotOutbox); err != nil {
		t.Fatal(err)
	}
	if gotEvents != events || gotCommands != commands || gotOutbox != outbox {
		t.Fatalf("atomic rows events/commands/outbox=%d/%d/%d", gotEvents, gotCommands, gotOutbox)
	}
}

func seedRolloutPersistenceIdentity(t *testing.T, pool *pgxpool.Pool) RolloutIdentity {
	t.Helper()
	tenantID, scopeID, userID, installationID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	username := "rollout-" + strings.ReplaceAll(userID.String(), "-", "")
	if _, err := pool.Exec(t.Context(), `
		INSERT INTO tenants(id,display_name) VALUES($1,'Rollout persistence tenant');
		INSERT INTO access_scopes(id,kind,tenant_id) VALUES($2,'tenant',$1);
		INSERT INTO users(id,username,display_name,password_hash) VALUES($3,$4,'Rollout operator','test-only');
		INSERT INTO memberships(scope_id,user_id) VALUES($2,$3)`, pgx.QueryExecModeSimpleProtocol,
		tenantID, scopeID, userID, username); err != nil {
		t.Fatal(err)
	}
	return RolloutIdentity{ActorScopeID: scopeID.String(), ActorUserID: userID.String(), InstallationID: installationID.String()}
}

func insertRolloutPersistencePlan(t *testing.T, pool *pgxpool.Pool, identity RolloutIdentity, plan *RolloutPlan) {
	t.Helper()
	binding := planGrantBindingForTest(t, identity, plan)
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	initial := initialRolloutPlan(*plan)
	initialSnapshot := mustJSONRollout(t, initial)
	initialDigest, _ := base64.RawURLEncoding.DecodeString(digestRolloutBytes(initialSnapshot))
	snapshot := mustJSONRollout(t, *plan)
	digest, _ := base64.RawURLEncoding.DecodeString(digestRolloutBytes(snapshot))
	if _, err := tx.Exec(t.Context(), `INSERT INTO control_upgrade_rollout_plans(
		id,actor_scope_id,actor_user_id,installation_id,schema_version,revision,state,resume_state,completion,
		active_batch,canonical_snapshot_bytes,canonical_snapshot_sha256,created_at,updated_at,
		parent_grant_id,parent_grant_bytes,parent_grant_sha256,parent_grant_expires_at,
		artifact_bundle_id,artifact_bundle_bytes,artifact_bundle_sha256,command_issuance_not_after,
		forward_profile_bytes,forward_profile_sha256,rollback_profile_bytes,rollback_profile_sha256,
		artifact_size_bytes,rollback_artifact_size_bytes)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,now(),now(),$13,$14,$15,to_timestamp($16),
		$17,$18,$19,to_timestamp($20),$21,$22,$23,$24,$25,$26)`,
		initial.ID, identity.ActorScopeID, identity.ActorUserID, identity.InstallationID, initial.SchemaVersion,
		initial.Revision, initial.State, initial.ResumeState, initial.Completion, initial.ActiveBatch,
		initialSnapshot, initialDigest, initial.ParentGrantID, binding.ParentGrantBytes,
		mustDecodePlanDigest(binding.ParentGrantSHA256), initial.ParentGrantExpiresAt,
		initial.ArtifactBundleID, binding.ArtifactBundleBytes,
		mustDecodePlanDigest(binding.ArtifactBundleSHA256), initial.CommandIssuanceNotAfter,
		binding.ForwardProfileBytes, mustDecodePlanDigest(binding.ForwardProfileSHA256),
		binding.RollbackProfileBytes, mustDecodePlanDigest(binding.RollbackProfileSHA256),
		initial.ArtifactSizeBytes, initial.RollbackArtifactSizeBytes); err != nil {
		t.Fatalf("insert initial rollout plan: %v", err)
	}
	intentID, requestDigest := uuid.New(), sha256.Sum256([]byte("rollout-persistence-create:"+plan.ID))
	var intentCreatedAt time.Time
	if err := tx.QueryRow(t.Context(),
		`SELECT date_trunc('second',clock_timestamp()) - interval '1 second'`).Scan(&intentCreatedAt); err != nil {
		t.Fatalf("read rollout fixture database time: %v", err)
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO control_upgrade_grant_intents_096(
		id,actor_scope_id,actor_user_id,installation_id,candidate_plan_id,plan_id,
		idempotency_key,request_digest,request_id,state,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,NULL,$6,$7,$8,'reserved',$9,$9)`, intentID,
		identity.ActorScopeID, identity.ActorUserID, identity.InstallationID, plan.ID,
		"create-"+plan.ID, requestDigest[:], "request-"+plan.ID, intentCreatedAt); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `UPDATE control_upgrade_grant_intents_096 SET state='acquired',
		parent_grant_bytes=$2,parent_grant_sha256=$3,parent_grant_expires_at=to_timestamp($4),
		artifact_bundle_id=$5,artifact_bundle_bytes=$6,artifact_bundle_sha256=$7,
		command_issuance_not_after=to_timestamp($8),forward_profile_bytes=$9,forward_profile_sha256=$10,
		rollback_profile_bytes=$11,rollback_profile_sha256=$12,updated_at=$13 WHERE id=$1`, intentID,
		binding.ParentGrantBytes, mustDecodePlanDigest(binding.ParentGrantSHA256), initial.ParentGrantExpiresAt,
		initial.ArtifactBundleID, binding.ArtifactBundleBytes, mustDecodePlanDigest(binding.ArtifactBundleSHA256),
		initial.CommandIssuanceNotAfter, binding.ForwardProfileBytes,
		mustDecodePlanDigest(binding.ForwardProfileSHA256), binding.RollbackProfileBytes,
		mustDecodePlanDigest(binding.RollbackProfileSHA256), intentCreatedAt.Add(time.Microsecond)); err != nil {
		t.Fatal(err)
	}
	scopeID, userID := uuid.MustParse(identity.ActorScopeID), uuid.MustParse(identity.ActorUserID)
	requestID := "request-" + plan.ID
	if err := audit.New(pool).Append(t.Context(), tx, audit.Event{ScopeID: scopeID, ActorUserID: &userID,
		Action: "control_upgrade_rollout.create", ResourceType: "control_upgrade_rollout",
		ResourceID: plan.ID, RequestID: requestID, Result: "success",
		Payload: map[string]any{"revision": 1, "state": initial.State}}); err != nil {
		t.Fatal(err)
	}
	var auditID uuid.UUID
	var auditOccurredAt time.Time
	if err := tx.QueryRow(t.Context(), `SELECT id,occurred_at FROM audit_events WHERE scope_id=$1 AND actor_user_id=$2
		AND action='control_upgrade_rollout.create' AND request_id=$3 AND result='success'
		ORDER BY stream_position DESC LIMIT 1`, scopeID, userID, requestID).Scan(&auditID, &auditOccurredAt); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO control_upgrade_write_receipts_096(
		id,actor_scope_id,actor_user_id,installation_id,plan_id,operation,idempotency_key,
		request_digest,request_id,result_snapshot_bytes,result_snapshot_sha256,result_revision,
		audit_event_id,created_at,completed_at)
		VALUES($1,$2,$3,$4,$5,'create',$6,$7,$8,$9,$10,1,$11,$12,$12)`, uuid.New(),
		identity.ActorScopeID, identity.ActorUserID, identity.InstallationID, plan.ID,
		"create-"+plan.ID, requestDigest[:], requestID, initialSnapshot, initialDigest, auditID,
		auditOccurredAt); err != nil {
		t.Fatal(err)
	}
	var receiptObservedAt time.Time
	if err := tx.QueryRow(t.Context(), `UPDATE control_upgrade_grant_intents_096
		SET state='consumed',plan_id=candidate_plan_id,updated_at=date_trunc('second',clock_timestamp())
		WHERE id=$1 RETURNING updated_at`, intentID).Scan(&receiptObservedAt); err != nil {
		t.Fatal(err)
	}
	if err := insertInitialParentGrantReceiptsTx(t.Context(), tx, identity, initial, receiptObservedAt); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if plan.Revision == 1 {
		return
	}
	historyTx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = historyTx.Rollback(t.Context()) }()
	type seededEvent struct {
		event PlanEvent
		cause any
		id    string
	}
	events := make(map[uint64]seededEvent, plan.Revision-1)
	for _, receipt := range plan.CommandReceipts {
		events[receipt.Event.Revision] = seededEvent{event: receipt.Event, cause: receipt.Command, id: receipt.Command.ID}
	}
	for _, receipt := range plan.HealthReceipts {
		events[receipt.Event.Revision] = seededEvent{event: receipt.Event, cause: receipt.Health, id: receipt.Health.ID}
	}
	for revision := uint64(2); revision <= plan.Revision; revision++ {
		item, ok := events[revision]
		if !ok {
			t.Fatalf("missing fixture event revision %d", revision)
		}
		eventBytes := mustJSONRollout(t, item.event)
		eventDigest, _ := base64.RawURLEncoding.DecodeString(digestRolloutBytes(eventBytes))
		causeBytes := mustJSONRollout(t, item.cause)
		causeDigest, _ := base64.RawURLEncoding.DecodeString(digestRolloutBytes(causeBytes))
		if _, err := historyTx.Exec(t.Context(), `INSERT INTO control_upgrade_rollout_events(
			plan_id,revision,event_id,actor_scope_id,actor_user_id,installation_id,
			causation_id,causation_bytes,causation_sha256,
			event_bytes,event_sha256,result_snapshot_bytes,result_snapshot_sha256,created_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,now())`, plan.ID, revision, item.event.ID,
			identity.ActorScopeID, identity.ActorUserID, identity.InstallationID, item.id, causeBytes, causeDigest,
			eventBytes, eventDigest, snapshot, digest); err != nil {
			t.Fatalf("insert rollout event revision %d: %v", revision, err)
		}
	}
	if _, err := historyTx.Exec(t.Context(), `UPDATE control_upgrade_rollout_plans
		SET revision=$2,state=$3,resume_state=$4,completion=$5,active_batch=$6,
			canonical_snapshot_bytes=$7,canonical_snapshot_sha256=$8,updated_at=clock_timestamp()
		WHERE id=$1`, plan.ID, plan.Revision, plan.State, plan.ResumeState, plan.Completion,
		plan.ActiveBatch, snapshot, digest); err != nil {
		t.Fatalf("advance seeded rollout plan: %v", err)
	}
	if err := historyTx.Commit(t.Context()); err != nil {
		t.Fatalf("commit seeded rollout history: %v", err)
	}
}

func openRolloutPersistenceIntegrationPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Minute)
	defer cancel()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "control_upgrade_rollout_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^control_upgrade_rollout_[a-f0-9]{32}$`).MatchString(schema) {
		admin.Close()
		t.Fatalf("unsafe schema %q", schema)
	}
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	var pool *pgxpool.Pool
	t.Cleanup(func() {
		if pool != nil {
			pool.Close()
		}
		cleanupCtx, cleanupCancel := databasetest.CleanupContext()
		defer cleanupCancel()
		if _, err := admin.Exec(cleanupCtx, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop rollout persistence schema: %v", err)
		}
		admin.Close()
	})
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	config.MaxConns = 8
	migrationConfig := config.Copy()
	migrationConfig.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	migrationConfig.MaxConns = 1
	migrationPool, err := pgxpool.NewWithConfig(ctx, migrationConfig)
	if err != nil {
		t.Fatal(err)
	}
	migrationErr := database.Migrate(ctx, migrationPool, "up")
	migrationPool.Close()
	if migrationErr != nil {
		t.Fatalf("migrate isolated rollout schema: %v", migrationErr)
	}
	pool, err = pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	// The full chain must apply; its head moves with every new migration, so
	// compare with the embedded files instead of a fixed number.
	var maximum int
	if err := pool.QueryRow(ctx, `SELECT max(version) FROM schema_migrations`).Scan(&maximum); err != nil {
		t.Fatal(err)
	}
	if want := embeddedMigrationHead(t); maximum != want {
		t.Fatalf("migration chain maximum=%d, want %d", maximum, want)
	}
	return pool
}

// embeddedMigrationHead is the highest numbered *.up.sql shipped in the binary.
func embeddedMigrationHead(t *testing.T) int {
	t.Helper()
	entries, err := migrations.FS.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	head := 0
	for _, entry := range entries {
		number, _, found := strings.Cut(entry.Name(), "_")
		if !found || !strings.HasSuffix(entry.Name(), ".up.sql") {
			continue
		}
		if version, err := strconv.Atoi(number); err == nil && version > head {
			head = version
		}
	}
	if head == 0 {
		t.Fatal("no embedded migrations")
	}
	return head
}
