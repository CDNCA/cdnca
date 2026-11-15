//go:build integration

package controlupgrade

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish/capabilitytest"
	"github.com/cdnca/cdnca/services/control-api/internal/nodeidentity"
	"github.com/cdnca/cdnca/services/control-api/internal/nodepresence"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Schema 3 plans (cross-version upgrade with an older rollback build, and same-version
// re-release) go through Prepare/Acquire/FinalizeCreateRollout into the database with their License
// receipts, then a v3 forward command is dispatched; rollback commands that do not match the plan are
// refused by the database itself.
func TestRolloutPlanV3CreateAndDispatchPostgres(t *testing.T) {
	for _, test := range []struct {
		name                    string
		current, target         string
		installed               uint64
		forward, rollback       uint64
		wantRollbackUnavailable bool
	}{
		{name: "cross-version", current: "1.0.22", target: "1.0.23", forward: 12, rollback: 4},
		{name: "same-version re-release", current: "1.0.22", target: "1.0.22", installed: 10, forward: 12,
			wantRollbackUnavailable: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			pool := openRolloutPersistenceIntegrationPool(t)
			actor, nodeID := seedRolloutPlanV3Node(t, pool, test.current, test.installed)
			store := NewStore(pool, nil, nil, time.Now)
			identity := RolloutIdentity{ActorScopeID: actor.ScopeID.String(), ActorUserID: actor.UserID.String(),
				InstallationID: uuid.NewString()}
			suffix := uuid.NewString()[:8]
			request := CreateRolloutRequest{CreateRolloutBody: CreateRolloutBody{
				Schema: "cdnca.control-upgrade-rollout.create/v1", NodeIDs: []string{nodeID},
				CanaryNodeIDs: []string{nodeID}, BatchSize: 1, AutomaticRollback: true},
				IdempotencyKey: "planv3-create-" + suffix, RequestID: "planv3-request-" + suffix}
			digest := sha256.Sum256([]byte("planv3:" + suffix))
			intent, replay, err := store.PrepareCreateRollout(t.Context(), actor, identity, request, digest)
			if err != nil || replay.Replayed {
				t.Fatalf("prepare = (%+v, %v)", replay, err)
			}
			cohort, err := store.LoadRolloutTargetCohort(t.Context(), actor, request.NodeIDs)
			if err != nil || cohort.CurrentReleaseSequence != test.installed {
				t.Fatalf("cohort = (%+v, %v)", cohort, err)
			}
			parent, bundle, binding := rolloutPlanV3Artifacts(t, identity, intent.PlanID, cohort,
				test.target, test.forward, test.rollback)
			profiles := rolloutProfiles(cohort, bundle.Version, RolloutProfilePolicy{ActivationTimeout: time.Minute,
				ObservationWindow: time.Minute, HealthInterval: time.Second, ProbeTimeout: time.Second,
				RequiredConsecutiveSuccesses: 1})
			binding.ForwardProfileBytes, _ = json.Marshal(profiles.forward)
			binding.RollbackProfileBytes, _ = json.Marshal(profiles.rollback)
			binding.ForwardProfileSHA256 = encodedRolloutDigest(binding.ForwardProfileBytes)
			binding.RollbackProfileSHA256 = encodedRolloutDigest(binding.RollbackProfileBytes)
			if err := store.AcquireCreateRollout(t.Context(), actor, intent, binding); err != nil {
				t.Fatalf("acquire: %v", err)
			}
			plan, err := newRolloutPlanFromArtifacts(intent.PlanID, parent, bundle, binding, cohort, request, profiles)
			if err != nil || plan.SchemaVersion != RolloutPlanSchemaVersion ||
				plan.Safety.RollbackAvailable == test.wantRollbackUnavailable {
				t.Fatalf("plan = (%+v, %v)", plan, err)
			}
			snapshot, err := encodeRolloutValue(plan)
			if err != nil {
				t.Fatal(err)
			}
			result, err := store.FinalizeCreateRollout(t.Context(), actor, identity, request, digest, intent, cohort,
				plan, binding, snapshot, encodedRolloutDigest(snapshot))
			if err != nil || result.Replayed {
				t.Fatalf("finalize = (%+v, %v)", result, err)
			}
			var schema, receipts int
			if err := pool.QueryRow(t.Context(), `SELECT plan.schema_version,
				(SELECT count(*) FROM control_upgrade_license_receipt_outbox_097 receipt WHERE receipt.plan_id=plan.id)
				FROM control_upgrade_rollout_plans plan WHERE plan.id=$1`, plan.ID).Scan(&schema, &receipts); err != nil {
				t.Fatal(err)
			}
			if schema != 3 || receipts != 2 {
				t.Fatalf("stored plan schema %d with %d License receipts", schema, receipts)
			}
			commandID := dispatchRolloutPlanV3Start(t, store, identity, plan, nodeID)
			// A rollback command cloned from the forward command never matches a v3 plan: cross-version
			// rollbacks carry RollbackReleaseSequence, re-release plans have no control rollback.
			err = pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
				_, err := tx.Exec(t.Context(), `INSERT INTO control_upgrade_node_commands(command_id,plan_id,plan_revision,batch_id,
					actor_scope_id,actor_user_id,installation_id,node_id,action,signed_execution_bytes,
					signed_execution_sha256,state,created_at,published_at,acknowledged_at,command_grant_bytes,
					command_grant_sha256,command_grant_expires_at,command_schema,execution_sequence,
					release_sequence,component)
					SELECT $2,plan_id,plan_revision,batch_id,actor_scope_id,actor_user_id,installation_id,node_id,
					'rollback',signed_execution_bytes,signed_execution_sha256,'pending',created_at,NULL,NULL,
					command_grant_bytes,command_grant_sha256,command_grant_expires_at,command_schema,
					execution_sequence,release_sequence,component
					FROM control_upgrade_node_commands WHERE command_id=$1`, commandID, uuid.NewString())
				return err
			})
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "P9602" ||
				pgErr.Message != "invalid control upgrade v3 command grant binding" {
				t.Fatalf("mismatched v3 rollback command = %v", err)
			}
		})
	}
}

// seedRolloutPlanV3Node seeds a platform operator and one active, session-authorized node running
// agentVersion; installed>0 makes it declare SAME_VERSION_UPGRADE with that installed release_sequence.
func seedRolloutPlanV3Node(t *testing.T, pool *pgxpool.Pool, agentVersion string, installed uint64) (Actor, string) {
	t.Helper()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(t.Context(), sql, append([]any{pgx.QueryExecModeSimpleProtocol}, args...)...); err != nil {
			t.Fatal(err)
		}
	}
	actor := Actor{UserID: uuid.New(), ScopeKind: "platform"}
	node, role := uuid.New(), uuid.New()
	if err := pool.QueryRow(t.Context(), `SELECT id FROM access_scopes WHERE kind='platform'`).Scan(&actor.ScopeID); errors.Is(err, pgx.ErrNoRows) {
		actor.ScopeID = uuid.New()
		exec(`INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, actor.ScopeID)
	} else if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	exec(`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'Plan v3 operator','test-only');
		INSERT INTO memberships(scope_id,user_id) VALUES($3,$1);
		INSERT INTO roles(id,scope_id,name,system_role) VALUES($4,$3,'platform_owner',true);
		INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($3,$1,$4);
		INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id,created_at,updated_at)
		VALUES($5,$3,'plan v3 node','pending',$1,1,$6,$6)`, actor.UserID, actor.UserID.String(), actor.ScopeID,
		role, node, now.Add(-7*time.Minute))
	enrolled := &agentv1.AgentCapabilities{AgentVersion: agentVersion, BuildId: "build", OperatingSystem: "linux",
		Architecture: "amd64", Features: []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_HTTP_1_1, ApiVersion: 1}}}
	identity := capabilitytest.SeedNodePublicationIdentityForTest(t, pool, actor.ScopeID, actor.UserID, node, enrolled,
		now.Add(-6*time.Minute), true)
	identity.Clock = now
	leaf, _ := pem.Decode(identity.Completion.Certificate.LeafCertificatePEM)
	certSHA := sha256.Sum256(leaf.Bytes)
	capabilities := proto.Clone(enrolled).(*agentv1.AgentCapabilities)
	capabilities.Features = append(capabilities.Features,
		&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE, ApiVersion: 1})
	if installed > 0 {
		capabilities.Features = append(capabilities.Features,
			&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_SAME_VERSION_UPGRADE, ApiVersion: 1})
		capabilities.InstalledReleaseSequence = installed
	}
	presence, err := nodepresence.NewStore(pool, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	beat := &agentv1.Heartbeat{Event: &commonv1.EventMetadata{EventId: uuid.NewString(), RequestId: uuid.NewString(),
		OccurredTime: timestamppb.Now()}, SessionEpoch: 1, HeartbeatSequence: 1, AgentVersion: &agentVersion,
		Runtime: &agentv1.EdgeRuntimeStatus{OpenrestyState: agentv1.RuntimeState_RUNTIME_STATE_STOPPED,
			FirewallState: agentv1.RuntimeState_RUNTIME_STATE_RUNNING},
		Resources: &agentv1.ResourceUsage{FilesystemTotalBytes: 1024, FilesystemAvailableBytes: 512}}
	encoded, _ := (proto.MarshalOptions{Deterministic: true}).Marshal(beat)
	projection, err := presence.Project(t.Context(), nodepresence.Envelope{NodeID: node, Heartbeat: beat,
		Digest: sha256.Sum256(encoded)})
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := presence.ConfirmOnline(t.Context(), projection); err != nil {
		t.Fatalf("confirm heartbeat %v %v", ok, err)
	}
	facts := &controlv1.GatewaySessionFactsV1{SchemaVersion: 1, NodeId: node.String(), SessionEpoch: 1,
		CertificateSha256: certSHA[:], SelectedProtocolVersion: &commonv1.ProtocolVersion{Major: 1},
		ArtifactEncryptionKeyId: identity.Completion.ArtifactEncryptionKeyID, Capabilities: capabilities}
	if _, err := identity.Service.GetAuthorization(t.Context(), nodeidentity.GetAuthorizationRequest{NodeID: node,
		CertificateSerialNumber: identity.Completion.Certificate.SerialNumber, CertificateSHA256: certSHA,
		GatewayWorkloadIdentity: "spiffe://cdn-platform/gateway/capability-test", GatewayInstanceID: uuid.NewString(),
		SessionFacts: facts}); err != nil {
		t.Fatal(err)
	}
	return actor, node.String()
}

// rolloutPlanV3Artifacts signs what the License service issues today: a parent grant and a
// plan-artifact-bundle/v2 with release.artifact/v3 manifests. A same-version bundle names the one
// registered build as forward and rollback and carries the cohort's installed release_sequence.
func rolloutPlanV3Artifacts(t *testing.T, identity RolloutIdentity, planID string, cohort RolloutTargetCohort,
	target string, forwardSequence, rollbackSequence uint64) (entitlement.UpgradeGrant,
	entitlement.UpgradePlanArtifactBundle, PlanGrantBinding) {
	t.Helper()
	signer := grantTestSigner{privateKey: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x6a}, ed25519.SeedSize))}
	protocol := int(cohort.ProtocolVersion)
	artifact := func(version string, sequence uint64, label string) entitlement.UpgradePlanArtifact {
		digest := sha256.Sum256([]byte(label))
		manifest := entitlement.ArtifactManifestV2{Schema: entitlement.ArtifactManifestV3Schema,
			Audience: entitlement.ArtifactManifestAudience, Purpose: entitlement.ArtifactManifestPurpose,
			ArtifactID: uuid.NewString(), Component: "edge-agent", Version: version, ProtocolMin: protocol,
			ProtocolMax: protocol, ArtifactSizeBytes: int64(len(label)) * 1024, ReleaseSequence: sequence,
			DigestAlgorithm: "sha256", SHA256Digest: base64.RawURLEncoding.EncodeToString(digest[:]),
			DownloadURL: "https://downloads.example.test/" + label}
		signature, err := entitlement.SignArtifactManifestV3(t.Context(), manifest, signer)
		if err != nil {
			t.Fatal(err)
		}
		return entitlement.UpgradePlanArtifact{Manifest: manifest, SignatureAlgorithm: entitlement.Algorithm,
			SignatureKeyID: signer.KeyID(), ManifestSignature: base64.RawURLEncoding.EncodeToString(signature)}
	}
	forward := artifact(target, forwardSequence, "forward-build")
	rollback, operation := forward, entitlement.ReinstallOperation
	if target != cohort.CurrentVersion {
		rollback = artifact(cohort.CurrentVersion, rollbackSequence, "rollback-build")
		operation = entitlement.UpgradeOperation
	}
	now := time.Now().Unix()
	parent := entitlement.UpgradeGrant{Schema: entitlement.UpgradeGrantSchema, Audience: entitlement.UpgradeGrantAudience,
		Purpose: entitlement.UpgradeGrantPurpose, GrantID: uuid.NewString(), Nonce: uuid.NewString(),
		CustomerID: uuid.NewString(), InstallationID: identity.InstallationID, LicenseID: uuid.NewString(),
		Channel: "stable", ChannelRevision: 3, Component: "edge-agent", Operation: operation,
		CurrentVersion: cohort.CurrentVersion, Version: target, CurrentReleaseSequence: cohort.CurrentReleaseSequence,
		ProtocolVersion: protocol, ArtifactID: forward.Manifest.ArtifactID, ArtifactProtocolMin: protocol,
		ArtifactProtocolMax: protocol, DownloadURL: forward.Manifest.DownloadURL, DigestAlgorithm: "sha256",
		SHA256Digest: forward.Manifest.SHA256Digest, ArtifactSignatureAlgorithm: entitlement.Algorithm,
		ArtifactSignatureKeyID: signer.KeyID(), ArtifactManifestSignature: forward.ManifestSignature,
		IssuedAt: now - 60, ExpiresAt: now + 600}
	signedParent, err := entitlement.SignUpgradeGrant(t.Context(), parent, signer)
	if err != nil {
		t.Fatal(err)
	}
	parentBytes, err := signedParent.Encode()
	if err != nil {
		t.Fatal(err)
	}
	parentDigest := encodedRolloutDigest(parentBytes)
	bundle := entitlement.UpgradePlanArtifactBundle{Schema: entitlement.UpgradePlanArtifactBundleV2Schema,
		Audience: entitlement.UpgradePlanArtifactBundleAudience, Purpose: entitlement.UpgradePlanArtifactBundlePurpose,
		BundleID: uuid.NewString(), PlanID: planID, InitialPlanRevision: 1, ParentGrantID: parent.GrantID,
		ParentGrantSHA256: parentDigest, ParentGrantIssuedAt: parent.IssuedAt, ParentGrantExpiresAt: parent.ExpiresAt,
		CustomerID: parent.CustomerID, InstallationID: identity.InstallationID, LicenseID: parent.LicenseID,
		Channel: "stable", ChannelRevision: 3, Component: "edge-agent", CurrentVersion: cohort.CurrentVersion,
		Version: target, CurrentReleaseSequence: cohort.CurrentReleaseSequence, ProtocolVersion: protocol,
		Forward: forward, Rollback: rollback, IssuedAt: now - 30, CommandIssuanceNotAfter: now + 3600}
	signedBundle, err := entitlement.SignUpgradePlanArtifactBundle(t.Context(), bundle, signer)
	if err != nil {
		t.Fatal(err)
	}
	bundleBytes, err := signedBundle.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return parent, bundle, PlanGrantBinding{ParentGrantBytes: parentBytes, ParentGrantSHA256: parentDigest,
		ArtifactBundleBytes: bundleBytes, ArtifactBundleSHA256: encodedRolloutDigest(bundleBytes)}
}

// dispatchRolloutPlanV3Start starts the plan and persists its first forward command as the
// orchestrator does for a v3 plan: command-grant/v3 + execution/v3 with the plan's release_sequence.
func dispatchRolloutPlanV3Start(t *testing.T, store *Store, identity RolloutIdentity, plan RolloutPlan,
	nodeID string) string {
	t.Helper()
	commandInput := planCommand(PlanStart, plan.Revision, "start_requested")
	cause, causeBytes := rolloutCause(t, commandInput)
	commandID := uuid.NewString()
	_, err := store.TransactLocked(t.Context(), identity, plan.ID, cause,
		func(locked LockedRolloutPlan) (RolloutAtomicMutation, error) {
			result := mustPlanCommand(t, locked.Plan, commandInput)
			events := []RolloutEventMutation{rolloutEventMutation(t, cause, causeBytes, result.Event)}
			batchID := result.Plan.Batches[result.Plan.ActiveBatch].ID
			grantBytes, expiresAt, execution := rolloutSignedExecutionV3(t, locked.Identity, result.Plan, commandID,
				result.Event.Revision, batchID, nodeID)
			command := RolloutNodeCommand{ID: commandID, PlanID: plan.ID, PlanRevision: result.Event.Revision,
				BatchID: batchID, NodeID: nodeID, InstallationID: identity.InstallationID, Action: "upgrade",
				CommandGrantBytes: grantBytes, CommandGrantSHA256: digestRolloutBytes(grantBytes),
				CommandGrantExpiresAt: expiresAt, SignedExecutionBytes: execution,
				SignedExecutionSHA256: digestRolloutWireBytes(execution),
				CommandSchema:         entitlement.UpgradeCommandGrantV3Schema, ExecutionSequence: 1,
				ReleaseSequence: plan.ReleaseSequence, Component: plan.Component}
			payload := mustJSONRollout(t, rolloutCommandEnvelope(command))
			outbox := RolloutOutboxMessage{ID: commandID, PlanID: plan.ID, PlanRevision: command.PlanRevision,
				Topic: upgradeCommandSubjectPrefix + "." + nodeID, MessageKey: commandID, PayloadBytes: payload,
				PayloadSHA256: digestRolloutWireBytes(payload), AvailableAt: time.Now()}
			return rolloutMutation(t, locked.Plan.Revision, result.Plan, events,
				[]RolloutNodeCommand{command}, []RolloutOutboxMessage{outbox}), nil
		})
	if err != nil {
		t.Fatalf("dispatch v3 forward command: %v", err)
	}
	return commandID
}

// rolloutSignedExecutionV3 is rolloutSignedExecution for a v3 forward command.
func rolloutSignedExecutionV3(t *testing.T, identity RolloutIdentity, plan RolloutPlan, commandID string,
	planRevision uint64, batchID, targetNodeID string) ([]byte, time.Time, []byte) {
	t.Helper()
	profile := plan.ForwardProfile
	issuedAt := time.Now().Unix() - 30
	expiresAt := issuedAt + int64(5*time.Minute/time.Second)
	grantSigner := grantTestSigner{privateKey: executionPrivateKey(0x90)}
	manifest := entitlement.ArtifactManifestV2{Schema: entitlement.ArtifactManifestV3Schema,
		Audience: entitlement.ArtifactManifestAudience, Purpose: entitlement.ArtifactManifestPurpose,
		ArtifactID: plan.ArtifactID, Component: plan.Component, Version: plan.TargetVersion,
		ProtocolMin: int(plan.Safety.ProtocolMin), ProtocolMax: int(plan.Safety.ProtocolMax),
		ArtifactSizeBytes: plan.ArtifactSizeBytes, ReleaseSequence: plan.ReleaseSequence, DigestAlgorithm: "sha256",
		SHA256Digest: plan.SHA256Digest, DownloadURL: "https://downloads.example.test/" + plan.ArtifactID}
	manifestSignature, err := entitlement.SignArtifactManifestV3(t.Context(), manifest, grantSigner)
	if err != nil {
		t.Fatal(err)
	}
	grant := entitlement.UpgradeCommandGrant{Schema: entitlement.UpgradeCommandGrantV3Schema,
		Audience: entitlement.UpgradeCommandGrantAudience, Purpose: entitlement.UpgradeCommandGrantPurpose,
		CommandID: commandID, Nonce: uuid.NewString(), ParentGrantID: plan.ParentGrantID,
		ParentGrantSHA256: plan.GrantDigest, ParentGrantIssuedAt: issuedAt - 60,
		ParentGrantExpiresAt: plan.ParentGrantExpiresAt, PlanID: plan.ID, PlanRevision: planRevision,
		BatchID: batchID, ArtifactBundleID: plan.ArtifactBundleID, ArtifactBundleSHA256: plan.ArtifactBundleSHA256,
		CommandIssuanceNotAfter: plan.CommandIssuanceNotAfter, CustomerID: uuid.NewString(),
		InstallationID: identity.InstallationID, LicenseID: uuid.NewString(), Channel: "stable",
		ChannelRevision: plan.ReleaseSequence, ExecutionSequence: 1, ReleaseSequence: plan.ReleaseSequence,
		CurrentReleaseSequence: plan.CurrentReleaseSequence, Component: plan.Component,
		Operation: entitlement.UpgradeOperation, CurrentVersion: plan.CurrentVersion, Version: plan.TargetVersion,
		ProtocolVersion: int(plan.Safety.ProtocolMin), ArtifactID: plan.ArtifactID,
		ArtifactProtocolMin: manifest.ProtocolMin, ArtifactProtocolMax: manifest.ProtocolMax,
		ArtifactSizeBytes: plan.ArtifactSizeBytes, DownloadURL: manifest.DownloadURL, DigestAlgorithm: "sha256",
		SHA256Digest: plan.SHA256Digest, ArtifactSignatureAlgorithm: entitlement.Algorithm,
		ArtifactSignatureKeyID:    grantSigner.KeyID(),
		ArtifactManifestSignature: base64.RawURLEncoding.EncodeToString(manifestSignature),
		NodeID:                    targetNodeID, Platform: profile.Platform, Architecture: profile.Architecture,
		Compatibility: profile.Compatibility, Health: profile.Health, Rollout: profile.Rollout,
		Rollback: profile.Rollback, IssuedAt: issuedAt, NotBefore: issuedAt, ExpiresAt: expiresAt}
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
