//go:build integration

package edgedeployment

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var errSecretRolloutInjected = errors.New("injected secret rollout failure")

type failingSecretRolloutAuditor struct{}

func (failingSecretRolloutAuditor) Append(context.Context, pgx.Tx, audit.Event) error {
	return errSecretRolloutInjected
}

func TestCreateSecretRolloutFreezesBindingAndReplaysWithoutRebuilding(t *testing.T) {
	fixture, scopeID, userID, actor := newSecretRolloutIAMFixture(t, nil)
	pool, store := fixture.pool, fixture.store
	nodeID := uuid.New()
	seedEdgeNode(t, pool, scopeID, userID, nodeID)
	recipientID, recipientPublicKey := seedActiveArtifactKey(t, pool, nodeID, userID, nil)
	request := testSecretRolloutRequest(actor, scopeID, []uuid.UUID{nodeID}, "certificate-secret-primary")

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var calls int
	var frozen SecretArtifactBinding
	var frozenRecipientPublicKey []byte
	builder := func(_ context.Context, binding SecretArtifactBinding) (ArtifactInput, error) {
		calls++
		frozen = binding
		frozenRecipientPublicKey = bytes.Clone(binding.RecipientPublicKey)
		return testSecretArtifact(t, binding, "certificate-secret-signer", publicKey, privateKey), nil
	}
	created, err := store.CreateSecretRollout(t.Context(), request, builder)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || created.Replayed || len(created.Rollout.Deployments) != 1 {
		t.Fatalf("created=%+v builder_calls=%d", created, calls)
	}
	deployment := created.Rollout.Deployments[0]
	if frozen.EventID == uuid.Nil || frozen.DeploymentID == uuid.Nil || frozen.ConfigVersionID == uuid.Nil ||
		frozen.ArtifactID == uuid.Nil || frozen.RolloutID == uuid.Nil || frozen.Attempt != 1 ||
		frozen.NodeID != nodeID || frozen.RecipientKeyID != recipientID ||
		!bytes.Equal(frozenRecipientPublicKey, recipientPublicKey) {
		t.Fatalf("builder binding was not fully frozen: %+v", frozen)
	}
	if created.Rollout.ID != frozen.RolloutID || created.Rollout.ConfigVersionID != frozen.ConfigVersionID ||
		created.Rollout.MaxAttempts != 1 || deployment.ID != frozen.DeploymentID ||
		deployment.Command.Event.EventId != frozen.EventID.String() || deployment.Command.Attempt != 1 ||
		deployment.Command.ConfigVersionId != frozen.ConfigVersionID.String() ||
		len(deployment.Command.Artifacts) != 1 || deployment.Command.Artifacts[0].ArtifactId != frozen.ArtifactID.String() ||
		deployment.Command.Artifacts[0].GetRecipientKeyId() != recipientID {
		t.Fatalf("persisted deployment does not match frozen builder binding: %+v", deployment.Command)
	}

	assertSecretRolloutRowCounts(t, pool, request.IdempotencyKey, 1, 1, 1, 1, 1, 1)
	assertSecretRolloutMetadataHasNoPrivateMaterial(t, pool, created.Rollout.ID)
	replayed, err := store.CreateSecretRollout(t.Context(), request, builder)
	if err != nil {
		t.Fatal(err)
	}
	if !replayed.Replayed || replayed.Rollout.ID != created.Rollout.ID || calls != 1 {
		t.Fatalf("replay=%+v builder_calls=%d", replayed, calls)
	}

	conflict := request
	conflict.PayloadDigest = sha256.Sum256([]byte("different certificate revision"))
	if _, err := store.CreateSecretRollout(t.Context(), conflict, builder); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("different payload replay error = %v", err)
	}
	if calls != 1 {
		t.Fatalf("conflicting replay invoked builder %d times", calls)
	}
}

func TestCreateSecretRolloutSortsMultipleNodesAndBuildsIndependentArtifacts(t *testing.T) {
	fixture, scopeID, userID, actor := newSecretRolloutIAMFixture(t, nil)
	pool, store := fixture.pool, fixture.store
	firstNode := uuid.MustParse("10000000-0000-0000-0000-000000000101")
	secondNode := uuid.MustParse("20000000-0000-0000-0000-000000000202")
	for _, nodeID := range []uuid.UUID{firstNode, secondNode} {
		seedEdgeNode(t, pool, scopeID, userID, nodeID)
		seedActiveArtifactKey(t, pool, nodeID, userID, nil)
	}
	request := testSecretRolloutRequest(
		actor, scopeID, []uuid.UUID{secondNode, firstNode}, "certificate-secret-multi-node",
	)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var bindings []SecretArtifactBinding
	created, err := store.CreateSecretRollout(t.Context(), request,
		func(_ context.Context, binding SecretArtifactBinding) (ArtifactInput, error) {
			bindings = append(bindings, binding)
			return testSecretArtifact(t, binding, "certificate-multi-signer", publicKey, privateKey), nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if len(bindings) != 2 || len(created.Rollout.Deployments) != 2 ||
		bindings[0].NodeID != firstNode || bindings[1].NodeID != secondNode ||
		created.Rollout.Deployments[0].NodeID != firstNode || created.Rollout.Deployments[1].NodeID != secondNode {
		t.Fatalf("bindings=%+v deployments=%+v", bindings, created.Rollout.Deployments)
	}
	if bindings[0].ArtifactID == bindings[1].ArtifactID || bindings[0].DeploymentID == bindings[1].DeploymentID ||
		bindings[0].EventID == bindings[1].EventID ||
		bytes.Equal(created.Rollout.Deployments[0].Command.Artifacts[0].Sha256,
			created.Rollout.Deployments[1].Command.Artifacts[0].Sha256) {
		t.Fatal("multi-node secret rollout reused recipient-specific identity or ciphertext")
	}
	var nodeConfigStates int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM node_config_state WHERE node_id=ANY($1::uuid[])`,
		[]uuid.UUID{firstNode, secondNode}).Scan(&nodeConfigStates); err != nil {
		t.Fatal(err)
	}
	if nodeConfigStates != 0 {
		t.Fatalf("secret publication touched node_config_state rows=%d", nodeConfigStates)
	}
	assertSecretRolloutRowCounts(t, pool, request.IdempotencyKey, 1, 2, 1, 2, 2, 1)
	replayed, err := store.CreateSecretRollout(t.Context(), request,
		func(context.Context, SecretArtifactBinding) (ArtifactInput, error) {
			t.Fatal("replay invoked builder")
			return ArtifactInput{}, nil
		})
	if err != nil || !replayed.Replayed || replayed.Rollout.ID != created.Rollout.ID {
		t.Fatalf("multi-node replay=%+v error=%v", replayed, err)
	}
}

func TestCreateSecretRolloutUnknownCommitReplayAndConcurrentDuplicate(t *testing.T) {
	fixture, scopeID, userID, actor := newSecretRolloutIAMFixture(t, nil)
	pool, store := fixture.pool, fixture.store
	nodeID := uuid.New()
	seedEdgeNode(t, pool, scopeID, userID, nodeID)
	seedActiveArtifactKey(t, pool, nodeID, userID, nil)
	request := testSecretRolloutRequest(actor, scopeID, []uuid.UUID{nodeID}, "certificate-secret-unknown-commit")
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var lock sync.Mutex
	calls := 0
	builder := func(_ context.Context, binding SecretArtifactBinding) (ArtifactInput, error) {
		lock.Lock()
		calls++
		lock.Unlock()
		return testSecretArtifact(t, binding, "certificate-unknown-signer", publicKey, privateKey), nil
	}

	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.CreateSecretRolloutTx(t.Context(), tx, request, builder)
	if err != nil {
		_ = tx.Rollback(t.Context())
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	recovered, err := store.CreateSecretRollout(t.Context(), request, builder)
	if err != nil || !recovered.Replayed || recovered.Rollout.ID != first.Rollout.ID {
		t.Fatalf("unknown commit recovery=%+v error=%v", recovered, err)
	}
	if calls != 1 {
		t.Fatalf("unknown commit replay builder calls=%d", calls)
	}

	otherNode := uuid.New()
	seedEdgeNode(t, pool, scopeID, userID, otherNode)
	seedActiveArtifactKey(t, pool, otherNode, userID, nil)
	concurrentRequest := testSecretRolloutRequest(actor, scopeID, []uuid.UUID{otherNode}, "certificate-secret-concurrent")
	start := make(chan struct{})
	results := make([]CreateRolloutResult, 2)
	errs := make([]error, 2)
	var wait sync.WaitGroup
	for index := range results {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			results[index], errs[index] = store.CreateSecretRollout(context.Background(), concurrentRequest, builder)
		}(index)
	}
	close(start)
	wait.Wait()
	if errs[0] != nil || errs[1] != nil || results[0].Rollout.ID != results[1].Rollout.ID ||
		results[0].Replayed == results[1].Replayed {
		t.Fatalf("concurrent results=%+v errors=%v", results, errs)
	}
	if calls != 2 {
		t.Fatalf("concurrent duplicate total builder calls=%d, want 2", calls)
	}
}

func TestCreateSecretRolloutFromSourceAuthorizesBeforeReplayAndMaterial(t *testing.T) {
	fixture, scopeID, userID, actor := newSecretRolloutIAMFixture(t, nil)
	pool, store := fixture.pool, fixture.store
	grantSecretRolloutPermission(t, pool, actor, "certificates.manage")
	nodeID := uuid.New()
	seedEdgeNode(t, pool, scopeID, userID, nodeID)
	seedActiveArtifactKey(t, pool, nodeID, userID, nil)
	request := testSecretRolloutRequest(actor, scopeID, []uuid.UUID{nodeID}, "certificate-secret-source")
	request.CanonicalSnapshot = nil
	request.PayloadDigest = [sha256.Size]byte{}
	domainDigest := sha256.Sum256([]byte("certificate.publish:tenant:site"))
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var sourceCalls, builderCalls int
	source := func(context.Context, pgx.Tx) (SecretRolloutMaterial, error) {
		sourceCalls++
		snapshot := []byte(`{"certificate_revisions":[1]}`)
		return SecretRolloutMaterial{
			CanonicalSnapshot: snapshot,
			PayloadDigest:     sha256.Sum256(snapshot),
			Builder: func(_ context.Context, binding SecretArtifactBinding) (ArtifactInput, error) {
				builderCalls++
				return testSecretArtifact(t, binding, "certificate-source-signer", publicKey, privateKey), nil
			},
		}, nil
	}
	create := func(input SecretRolloutRequest, digest [sha256.Size]byte, permissions []string, inputSource SecretRolloutSource) (CreateRolloutResult, error) {
		tx, beginErr := pool.Begin(t.Context())
		if beginErr != nil {
			t.Fatal(beginErr)
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		result, createErr := store.CreateSecretRolloutFromSourceTx(
			t.Context(), tx, input, digest, permissions, inputSource,
		)
		if createErr == nil {
			createErr = tx.Commit(t.Context())
		}
		return result, createErr
	}
	for _, boundary := range []struct {
		name        string
		request     SecretRolloutRequest
		digest      [sha256.Size]byte
		permissions []string
		source      SecretRolloutSource
	}{
		{name: "snapshot must be empty", request: func() SecretRolloutRequest {
			changed := request
			changed.CanonicalSnapshot = []byte(`{}`)
			return changed
		}(), digest: domainDigest, permissions: []string{"certificates.manage"}, source: source},
		{name: "payload digest must be zero", request: func() SecretRolloutRequest {
			changed := request
			changed.PayloadDigest = sha256.Sum256([]byte("material"))
			return changed
		}(), digest: domainDigest, permissions: []string{"certificates.manage"}, source: source},
		{name: "domain digest", request: request, permissions: []string{"certificates.manage"}, source: source},
		{name: "additional permissions", request: request, digest: domainDigest, source: source},
		{name: "source", request: request, digest: domainDigest, permissions: []string{"certificates.manage"}},
	} {
		if _, err := create(boundary.request, boundary.digest, boundary.permissions, boundary.source); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("invalid %s boundary error=%v", boundary.name, err)
		}
	}
	if sourceCalls != 0 || builderCalls != 0 {
		t.Fatalf("invalid boundary invoked source/builder=%d/%d", sourceCalls, builderCalls)
	}

	created, err := create(request, domainDigest, []string{"certificates.manage", "certificates.manage"}, source)
	if err != nil || created.Replayed || sourceCalls != 1 || builderCalls != 1 {
		t.Fatalf("created=%+v error=%v source/builder=%d/%d", created, err, sourceCalls, builderCalls)
	}
	replayed, err := create(request, domainDigest, []string{"certificates.manage"}, source)
	if err != nil || !replayed.Replayed || replayed.Rollout.ID != created.Rollout.ID || sourceCalls != 1 || builderCalls != 1 {
		t.Fatalf("replay=%+v error=%v source/builder=%d/%d", replayed, err, sourceCalls, builderCalls)
	}

	for _, permission := range []string{"certificates.manage", PermissionManage} {
		revokeSecretRolloutPermission(t, pool, actor, permission)
		if _, err := create(request, domainDigest, []string{"certificates.manage"}, source); !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("revoked %s replay error=%v", permission, err)
		}
		if sourceCalls != 1 || builderCalls != 1 {
			t.Fatalf("revoked %s invoked source/builder=%d/%d", permission, sourceCalls, builderCalls)
		}
		grantSecretRolloutPermission(t, pool, actor, permission)
	}

	otherActor := seedSecretPlatformActorInScope(t, fixture, actor.ScopeID, PermissionManage, "certificates.manage")
	conflicts := []struct {
		name    string
		request SecretRolloutRequest
		digest  [sha256.Size]byte
	}{
		{name: "domain digest", request: request, digest: sha256.Sum256([]byte("different site"))},
		{name: "request id", request: func() SecretRolloutRequest {
			changed := request
			changed.RequestID = uuid.NewString()
			return changed
		}(), digest: domainDigest},
		{name: "deadline", request: func() SecretRolloutRequest {
			changed := request
			changed.Deadline = changed.Deadline.Add(time.Second)
			return changed
		}(), digest: domainDigest},
		{name: "node ids", request: func() SecretRolloutRequest {
			changed := request
			changed.NodeIDs = []uuid.UUID{uuid.New()}
			return changed
		}(), digest: domainDigest},
		{name: "capabilities", request: func() SecretRolloutRequest {
			changed := request
			changed.RequiredCapabilities = []*agentv1.Capability{{
				Name: agentv1.CapabilityName_CAPABILITY_NAME_ATOMIC_RELEASE, ApiVersion: 2,
			}}
			return changed
		}(), digest: domainDigest},
		{name: "actor", request: func() SecretRolloutRequest {
			changed := request
			changed.Actor = otherActor
			return changed
		}(), digest: domainDigest},
	}
	for _, conflict := range conflicts {
		if _, err := create(conflict.request, conflict.digest, []string{"certificates.manage"}, source); !errors.Is(err, ErrIdempotencyConflict) {
			t.Fatalf("%s conflict error=%v", conflict.name, err)
		}
	}
	if sourceCalls != 1 || builderCalls != 1 {
		t.Fatalf("conflicts invoked source/builder=%d/%d", sourceCalls, builderCalls)
	}

	invalidSourceCalls := 0
	invalidSource := func(context.Context, pgx.Tx) (SecretRolloutMaterial, error) {
		invalidSourceCalls++
		return SecretRolloutMaterial{}, errSecretRolloutInjected
	}
	invalid := request
	invalid.IdempotencyKey = "certificate-secret-source-error"
	invalid.RequestID = uuid.NewString()
	invalid.CorrelationID = uuid.NewString()
	if _, err := create(invalid, domainDigest, []string{"certificates.manage"}, invalidSource); !errors.Is(err, errSecretRolloutInjected) {
		t.Fatalf("source error=%v", err)
	}
	if invalidSourceCalls != 1 || builderCalls != 1 {
		t.Fatalf("source failure calls source/builder=%d/%d", invalidSourceCalls, builderCalls)
	}
	assertSecretRolloutRowCounts(t, pool, invalid.IdempotencyKey, 0, 0, 0, 0, 0, 0)
	for _, invalidPermissions := range [][]string{nil, {}, {" certificates.manage"}} {
		if _, err := create(invalid, domainDigest, invalidPermissions, source); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("invalid additional permissions %q error=%v", invalidPermissions, err)
		}
	}
}

func TestCreateSecretRolloutFromSourceLocksEveryPermissionFact(t *testing.T) {
	for _, permission := range []string{"certificates.manage", PermissionManage} {
		t.Run(permission, func(t *testing.T) {
			fixture, scopeID, userID, actor := newSecretRolloutIAMFixture(t, nil)
			pool, store := fixture.pool, fixture.store
			grantSecretRolloutPermission(t, pool, actor, "certificates.manage")
			nodeID := uuid.New()
			seedEdgeNode(t, pool, scopeID, userID, nodeID)
			seedActiveArtifactKey(t, pool, nodeID, userID, nil)
			request := testSecretRolloutRequest(actor, scopeID, []uuid.UUID{nodeID}, "certificate-secret-permission-lock-"+permission)
			request.CanonicalSnapshot = nil
			request.PayloadDigest = [sha256.Size]byte{}
			publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			tx, err := pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(context.Background()) }()
			if _, err := store.CreateSecretRolloutFromSourceTx(t.Context(), tx, request,
				sha256.Sum256([]byte(permission)), []string{"certificates.manage"},
				func(context.Context, pgx.Tx) (SecretRolloutMaterial, error) {
					snapshot := []byte(`{"certificate_revisions":[1]}`)
					return SecretRolloutMaterial{CanonicalSnapshot: snapshot, PayloadDigest: sha256.Sum256(snapshot),
						Builder: func(_ context.Context, binding SecretArtifactBinding) (ArtifactInput, error) {
							return testSecretArtifact(t, binding, "permission-lock-signer", publicKey, privateKey), nil
						}}, nil
				}); err != nil {
				t.Fatal(err)
			}

			revoker, err := pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := revoker.Exec(t.Context(), `SET LOCAL lock_timeout='100ms'`); err != nil {
				t.Fatal(err)
			}
			_, err = revoker.Exec(t.Context(), `DELETE FROM role_assignments assignment
				USING role_permissions permission
				WHERE assignment.scope_id=$1 AND assignment.user_id=$2
				  AND permission.role_id=assignment.role_id AND permission.permission_name=$3`,
				actor.ScopeID, actor.UserID, permission)
			var postgresError *pgconn.PgError
			if !errors.As(err, &postgresError) || postgresError.Code != "55P03" {
				_ = revoker.Rollback(context.Background())
				t.Fatalf("permission %s revoke was not serialized: %v", permission, err)
			}
			_ = revoker.Rollback(context.Background())
			if err := tx.Commit(t.Context()); err != nil {
				t.Fatal(err)
			}
			revokeSecretRolloutPermission(t, pool, actor, permission)
		})
	}
}

func TestCreateSecretRolloutRollsBackBuilderSigningAndAuditFailures(t *testing.T) {
	tests := []struct {
		name string
		run  func(*testing.T, *pgxpool.Pool, *Store, SecretRolloutRequest, SecretArtifactBuilder) error
	}{
		{name: "builder", run: func(t *testing.T, _ *pgxpool.Pool, store *Store, request SecretRolloutRequest, _ SecretArtifactBuilder) error {
			_, err := store.CreateSecretRollout(t.Context(), request, func(context.Context, SecretArtifactBinding) (ArtifactInput, error) {
				return ArtifactInput{}, errSecretRolloutInjected
			})
			return err
		}},
		{name: "signing key conflict", run: func(t *testing.T, pool *pgxpool.Pool, store *Store, request SecretRolloutRequest, builder SecretArtifactBuilder) error {
			if _, err := pool.Exec(t.Context(), `INSERT INTO artifact_signing_keys(id,algorithm,public_key,created_at)
				VALUES('certificate-rollback-signer','ed25519',$1,$2)`, bytes.Repeat([]byte{0x7f}, ed25519.PublicKeySize), integrationClock); err != nil {
				t.Fatal(err)
			}
			_, err := store.CreateSecretRollout(t.Context(), request, builder)
			return err
		}},
		{name: "artifact", run: func(t *testing.T, pool *pgxpool.Pool, store *Store, request SecretRolloutRequest, builder SecretArtifactBuilder) error {
			if _, err := pool.Exec(t.Context(), `CREATE FUNCTION fail_secret_artifact() RETURNS trigger LANGUAGE plpgsql AS $$
				BEGIN RAISE EXCEPTION 'injected secret artifact failure'; END $$;
				CREATE TRIGGER fail_secret_artifact BEFORE INSERT ON configuration_artifacts
				FOR EACH ROW EXECUTE FUNCTION fail_secret_artifact()`); err != nil {
				t.Fatal(err)
			}
			_, err := store.CreateSecretRollout(t.Context(), request, builder)
			return err
		}},
		{name: "outbox", run: func(t *testing.T, pool *pgxpool.Pool, store *Store, request SecretRolloutRequest, builder SecretArtifactBuilder) error {
			if _, err := pool.Exec(t.Context(), `CREATE FUNCTION fail_secret_outbox() RETURNS trigger LANGUAGE plpgsql AS $$
				BEGIN RAISE EXCEPTION 'injected secret outbox failure'; END $$;
				CREATE TRIGGER fail_secret_outbox BEFORE INSERT ON edge_command_outbox
				FOR EACH ROW EXECUTE FUNCTION fail_secret_outbox()`); err != nil {
				t.Fatal(err)
			}
			_, err := store.CreateSecretRollout(t.Context(), request, builder)
			return err
		}},
		{name: "audit", run: func(t *testing.T, _ *pgxpool.Pool, store *Store, request SecretRolloutRequest, builder SecretArtifactBuilder) error {
			store.auditor = failingSecretRolloutAuditor{}
			_, err := store.CreateSecretRollout(t.Context(), request, builder)
			return err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture, scopeID, userID, actor := newSecretRolloutIAMFixture(t, nil)
			pool, store := fixture.pool, fixture.store
			nodeID := uuid.New()
			seedEdgeNode(t, pool, scopeID, userID, nodeID)
			seedActiveArtifactKey(t, pool, nodeID, userID, nil)
			request := testSecretRolloutRequest(actor, scopeID, []uuid.UUID{nodeID}, "certificate-rollback-"+test.name)
			publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			builder := func(_ context.Context, binding SecretArtifactBinding) (ArtifactInput, error) {
				return testSecretArtifact(t, binding, "certificate-rollback-signer", publicKey, privateKey), nil
			}
			if err := test.run(t, pool, store, request, builder); err == nil {
				t.Fatal("injected failure was accepted")
			}
			assertSecretRolloutRowCounts(t, pool, request.IdempotencyKey, 0, 0, 0, 0, 0, 0)
		})
	}
}

func TestCreateSecretRolloutRejectsCorruptActiveRecipientFact(t *testing.T) {
	fixture, scopeID, userID, actor := newSecretRolloutIAMFixture(t, nil)
	pool, store := fixture.pool, fixture.store
	nodeID := uuid.New()
	seedEdgeNode(t, pool, scopeID, userID, nodeID)
	publicKey := bytes.Repeat([]byte{0x42}, 32)
	seedArtifactKeyFact(t, pool, nodeID, userID, "x25519:"+string(bytes.Repeat([]byte{'0'}, 64)), publicKey, "active")
	request := testSecretRolloutRequest(actor, scopeID, []uuid.UUID{nodeID}, "certificate-corrupt-recipient")
	called := false
	_, err := store.CreateSecretRollout(t.Context(), request,
		func(context.Context, SecretArtifactBinding) (ArtifactInput, error) {
			called = true
			return ArtifactInput{}, nil
		})
	if !errors.Is(err, ErrNodeRecipientKeyUnavailable) || called {
		t.Fatalf("corrupt recipient error=%v builder_called=%t", err, called)
	}
	assertSecretRolloutRowCounts(t, pool, request.IdempotencyKey, 0, 0, 0, 0, 0, 0)
}

func TestCreateSecretRolloutUsesOnlyCurrentActiveRecipient(t *testing.T) {
	fixture, scopeID, userID, actor := newSecretRolloutIAMFixture(t, nil)
	pool, store := fixture.pool, fixture.store
	nodeID := uuid.New()
	seedEdgeNode(t, pool, scopeID, userID, nodeID)
	oldID, _ := seedActiveArtifactKey(t, pool, nodeID, userID, nil)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var recipients []string
	builder := func(_ context.Context, binding SecretArtifactBinding) (ArtifactInput, error) {
		recipients = append(recipients, binding.RecipientKeyID)
		return testSecretArtifact(t, binding, "certificate-rotation-signer", publicKey, privateKey), nil
	}
	first, err := store.CreateSecretRollout(t.Context(), testSecretRolloutRequest(actor, scopeID, []uuid.UUID{nodeID}, "certificate-before-rotation"), builder)
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{"delivered", "staged", "prechecked", "activated", "healthy"} {
		advanceDeploymentState(t, pool, first.Rollout.Deployments[0].ID, state)
	}
	newID, _ := rotateActiveArtifactKey(t, pool, nodeID, userID, oldID)
	second, err := store.CreateSecretRollout(t.Context(), testSecretRolloutRequest(actor, scopeID, []uuid.UUID{nodeID}, "certificate-after-rotation"), builder)
	if err != nil {
		t.Fatal(err)
	}
	if len(recipients) != 2 || recipients[0] != oldID || recipients[1] != newID ||
		second.Rollout.Deployments[0].Command.Artifacts[0].GetRecipientKeyId() != newID {
		t.Fatalf("recipient history=%v new deployment=%+v", recipients, second.Rollout.Deployments[0].Command)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE node_artifact_encryption_keys SET status='revoked',
		deactivated_at=clock_timestamp(),deactivation_reason='test revocation' WHERE id=$1`, newID); err != nil {
		t.Fatal(err)
	}
	request := testSecretRolloutRequest(actor, scopeID, []uuid.UUID{nodeID}, "certificate-after-revocation")
	if _, err := store.CreateSecretRollout(t.Context(), request, builder); !errors.Is(err, ErrNodeRecipientKeyUnavailable) {
		t.Fatalf("revoked recipient error=%v", err)
	}
	assertSecretRolloutRowCounts(t, pool, request.IdempotencyKey, 0, 0, 0, 0, 0, 0)
}

func TestReplaceSecretRolloutUsesLockedMaterialCurrentRecipientsAndReplays(t *testing.T) {
	fixture, scopeID, userID, actor := newSecretRolloutIAMFixture(t, nil)
	pool, store := fixture.pool, fixture.store
	firstNode := uuid.MustParse("30000000-0000-0000-0000-000000000301")
	secondNode := uuid.MustParse("40000000-0000-0000-0000-000000000302")
	oldRecipientIDs := make(map[uuid.UUID]string, 2)
	for _, nodeID := range []uuid.UUID{firstNode, secondNode} {
		seedEdgeNode(t, pool, scopeID, userID, nodeID)
		keyID, _ := seedActiveArtifactKey(t, pool, nodeID, userID, nil)
		oldRecipientIDs[nodeID] = keyID
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	originalRequest := testSecretRolloutRequest(
		actor, scopeID, []uuid.UUID{secondNode, firstNode}, "certificate-replacement-original",
	)
	original, err := store.CreateSecretRollout(t.Context(), originalRequest,
		func(_ context.Context, binding SecretArtifactBinding) (ArtifactInput, error) {
			return testSecretArtifact(t, binding, "certificate-replacement-signer", publicKey, privateKey), nil
		})
	if err != nil {
		t.Fatal(err)
	}
	for _, deployment := range original.Rollout.Deployments {
		advanceDeploymentState(t, pool, deployment.ID, "delivered")
		advanceDeploymentState(t, pool, deployment.ID, "failed")
	}
	rotatedRecipientID, _ := rotateActiveArtifactKey(t, pool, secondNode, userID, oldRecipientIDs[secondNode])

	replacementRequest := testSecretReplacementRequest(
		actor, scopeID, []uuid.UUID{secondNode, firstNode}, original.Rollout.ID,
		original.Rollout.Revision, "certificate-replacement-primary",
	)
	material := SecretReplacementMaterial{
		CanonicalSnapshot: bytes.Clone(originalRequest.CanonicalSnapshot),
		PayloadDigest:     sha256.Sum256([]byte("certificate-replacement-material")),
	}
	var sourceCalls, builderCalls int
	var replacementBindings []SecretArtifactBinding
	source := func(_ context.Context, _ pgx.Tx, consume SecretReplacementConsume) error {
		sourceCalls++
		return consume(material, func(_ context.Context, bindings []SecretArtifactBinding) ([]ArtifactInput, error) {
			builderCalls++
			replacementBindings = append(replacementBindings, bindings...)
			artifacts := make([]ArtifactInput, len(bindings))
			for index, binding := range bindings {
				artifacts[index] = testSecretArtifact(t, binding, "certificate-replacement-signer", publicKey, privateKey)
			}
			return artifacts, nil
		})
	}
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	replaced, err := store.ReplaceSecretRolloutTx(t.Context(), tx, replacementRequest, source)
	if err != nil {
		_ = tx.Rollback(t.Context())
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if replaced.Replayed || replaced.OriginalRolloutID != original.Rollout.ID ||
		replaced.OriginalRevision != original.Rollout.Revision+1 || len(replaced.Rollout.Deployments) != 2 ||
		sourceCalls != 1 || builderCalls != 1 {
		t.Fatalf("replacement=%+v source/builder=%d/%d", replaced, sourceCalls, builderCalls)
	}
	if replacementBindings[0].NodeID != firstNode || replacementBindings[1].NodeID != secondNode ||
		replacementBindings[0].RecipientKeyID != oldRecipientIDs[firstNode] ||
		replacementBindings[1].RecipientKeyID != rotatedRecipientID ||
		replacementBindings[1].RecipientKeyID == oldRecipientIDs[secondNode] {
		t.Fatalf("replacement recipients=%+v", replacementBindings)
	}
	for index, deployment := range replaced.Rollout.Deployments {
		if deployment.ID == original.Rollout.Deployments[index].ID || deployment.Command.Attempt != 1 ||
			len(deployment.Command.Artifacts) != 1 ||
			deployment.Command.Artifacts[0].ArtifactId == original.Rollout.Deployments[index].Command.Artifacts[0].ArtifactId {
			t.Fatalf("replacement did not create fresh attempt-one deployment: %+v", deployment.Command)
		}
	}
	var originalRevision, originalDeployments, replacementRequests, replacementAudits int
	if err := pool.QueryRow(t.Context(), `SELECT
		(SELECT revision FROM rollouts WHERE id=$1),
		(SELECT count(*) FROM node_deployments WHERE rollout_id=$1),
		(SELECT count(*) FROM edge_rollout_write_requests WHERE rollout_id=$1 AND operation='edge_rollout.retry'),
		(SELECT count(*) FROM audit_events WHERE action='edge_secret_rollout.replace'
		 AND payload->>'original_rollout_id'=$1::text AND payload->>'replacement_rollout_id'=$2::text)`,
		original.Rollout.ID, replaced.Rollout.ID).Scan(
		&originalRevision, &originalDeployments, &replacementRequests, &replacementAudits); err != nil {
		t.Fatal(err)
	}
	if originalRevision != int(replaced.OriginalRevision) || originalDeployments != 2 ||
		replacementRequests != 1 || replacementAudits != 1 {
		t.Fatalf("replacement facts revision/deployments/requests/audits=%d/%d/%d/%d",
			originalRevision, originalDeployments, replacementRequests, replacementAudits)
	}
	replayed, err := store.ReplaceSecretRollout(t.Context(), replacementRequest,
		func(context.Context, pgx.Tx, SecretReplacementConsume) error {
			t.Fatal("replacement replay reopened material source")
			return nil
		})
	if err != nil || !replayed.Replayed || replayed.Rollout.ID != replaced.Rollout.ID ||
		sourceCalls != 1 || builderCalls != 1 {
		t.Fatalf("replacement replay=%+v error=%v source/builder=%d/%d",
			replayed, err, sourceCalls, builderCalls)
	}
	conflict := replacementRequest
	conflict.GeneratorVersion = "2.0.0"
	if _, err := store.ReplaceSecretRollout(t.Context(), conflict, source); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("replacement idempotency conflict error=%v", err)
	}
}

func TestReplaceSecretRolloutRejectsStalePartialAndMaterialMismatchWithoutWrites(t *testing.T) {
	tests := []struct {
		name            string
		partial         bool
		revokeRecipient bool
		mutate          func(*SecretReplacementRequest)
		material        func(SecretRolloutRequest) SecretReplacementMaterial
		want            error
		wantSource      bool
	}{
		{name: "stale revision", mutate: func(request *SecretReplacementRequest) { request.ExpectedRevision++ },
			want: ErrRevisionConflict},
		{name: "partial success", partial: true, want: ErrSecretRetryRequiresRepublish},
		{name: "revoked current recipient", revokeRecipient: true,
			want: ErrNodeRecipientKeyUnavailable, wantSource: true},
		{name: "snapshot mismatch", material: func(original SecretRolloutRequest) SecretReplacementMaterial {
			return SecretReplacementMaterial{
				CanonicalSnapshot: []byte(`{"certificate_revisions":[999]}`),
				PayloadDigest:     sha256.Sum256([]byte("mismatched-material")),
			}
		}, want: ErrSecretArtifactContract, wantSource: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture, scopeID, userID, actor := newSecretRolloutIAMFixture(t, nil)
			pool, store := fixture.pool, fixture.store
			nodes := []uuid.UUID{uuid.New(), uuid.New()}
			recipientIDs := make([]string, len(nodes))
			for index, nodeID := range nodes {
				seedEdgeNode(t, pool, scopeID, userID, nodeID)
				recipientIDs[index], _ = seedActiveArtifactKey(t, pool, nodeID, userID, nil)
			}
			publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			keySuffix := strings.ReplaceAll(test.name, " ", "-")
			originalRequest := testSecretRolloutRequest(actor, scopeID, nodes, "replacement-reject-original-"+keySuffix)
			original, err := store.CreateSecretRollout(t.Context(), originalRequest,
				func(_ context.Context, binding SecretArtifactBinding) (ArtifactInput, error) {
					return testSecretArtifact(t, binding, "replacement-reject-signer", publicKey, privateKey), nil
				})
			if err != nil {
				t.Fatal(err)
			}
			if test.partial {
				advanceDeploymentState(t, pool, original.Rollout.Deployments[0].ID, "delivered")
				advanceDeploymentState(t, pool, original.Rollout.Deployments[0].ID, "failed")
				for _, state := range []string{"delivered", "staged", "prechecked", "activated", "healthy"} {
					advanceDeploymentState(t, pool, original.Rollout.Deployments[1].ID, state)
				}
			} else {
				for _, deployment := range original.Rollout.Deployments {
					advanceDeploymentState(t, pool, deployment.ID, "delivered")
					advanceDeploymentState(t, pool, deployment.ID, "failed")
				}
			}
			if test.revokeRecipient {
				if _, err := pool.Exec(t.Context(), `UPDATE node_artifact_encryption_keys SET status='revoked',
						deactivated_at=clock_timestamp(),deactivation_reason='test replacement revocation'
						WHERE id=$1`, recipientIDs[0]); err != nil {
					t.Fatal(err)
				}
			}
			request := testSecretReplacementRequest(actor, scopeID, nodes, original.Rollout.ID,
				original.Rollout.Revision, "replacement-reject-"+keySuffix)
			if test.mutate != nil {
				test.mutate(&request)
			}
			material := SecretReplacementMaterial{
				CanonicalSnapshot: bytes.Clone(originalRequest.CanonicalSnapshot),
				PayloadDigest:     sha256.Sum256([]byte("replacement-reject-material")),
			}
			if test.material != nil {
				material = test.material(originalRequest)
			}
			sourceCalls := 0
			builderCalls := 0
			_, err = store.ReplaceSecretRollout(t.Context(), request,
				func(_ context.Context, _ pgx.Tx, consume SecretReplacementConsume) error {
					sourceCalls++
					return consume(material, func(_ context.Context, bindings []SecretArtifactBinding) ([]ArtifactInput, error) {
						builderCalls++
						artifacts := make([]ArtifactInput, len(bindings))
						for index, binding := range bindings {
							artifacts[index] = testSecretArtifact(t, binding, "replacement-reject-signer", publicKey, privateKey)
						}
						return artifacts, nil
					})
				})
			if !errors.Is(err, test.want) || (sourceCalls > 0) != test.wantSource || builderCalls != 0 {
				t.Fatalf("replacement rejection error=%v source_calls=%d builder_calls=%d", err, sourceCalls, builderCalls)
			}
			var revision, requests, replacements int
			if err := pool.QueryRow(t.Context(), `SELECT
				(SELECT revision FROM rollouts WHERE id=$1),
				(SELECT count(*) FROM edge_rollout_write_requests WHERE idempotency_key=$2),
				(SELECT count(*) FROM audit_events WHERE action='edge_secret_rollout.replace'
				 AND payload->>'original_rollout_id'=$1::text)`, original.Rollout.ID, request.IdempotencyKey).Scan(
				&revision, &requests, &replacements); err != nil {
				t.Fatal(err)
			}
			if revision != int(original.Rollout.Revision) || requests != 0 || replacements != 0 {
				t.Fatalf("rejected replacement mutated revision/requests/audits=%d/%d/%d", revision, requests, replacements)
			}
		})
	}
}

func TestReplaceSecretRolloutRejectsConfigurationOnlyAndMixedOrigins(t *testing.T) {
	for _, test := range []struct {
		name  string
		mixed bool
	}{{name: "configuration-only"}, {name: "mixed", mixed: true}} {
		t.Run(test.name, func(t *testing.T) {
			fixture, scopeID, userID, actor := newSecretRolloutIAMFixture(t, nil)
			pool, store := fixture.pool, fixture.store
			publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			configRequest := testConfigRequest(t, scopeID, "replacement-origin-"+test.name,
				"replacement-origin-signer", publicKey, privateKey, []byte("configuration artifact"))
			if test.mixed {
				binding := SecretArtifactBinding{
					ArtifactID: uuid.New(), RecipientKeyID: "x25519:" + string(bytes.Repeat([]byte{'c'}, 64)),
				}
				configRequest.Artifacts = append(configRequest.Artifacts,
					testSecretArtifact(t, binding, "replacement-origin-signer", publicKey, privateKey))
			}
			config := persistTestConfig(t, store, configRequest)
			nodeID := uuid.New()
			seedEdgeNode(t, pool, scopeID, userID, nodeID)
			seedActiveArtifactKey(t, pool, nodeID, userID, nil)
			rolloutRequest := testRolloutRequest(scopeID, config.ID, []uuid.UUID{nodeID}, "replacement-origin-rollout-"+test.name)
			rolloutRequest.MaxAttempts = 1
			original, err := store.CreateRollout(t.Context(), rolloutRequest)
			if err != nil {
				t.Fatal(err)
			}
			advanceDeploymentState(t, pool, original.Rollout.Deployments[0].ID, "delivered")
			advanceDeploymentState(t, pool, original.Rollout.Deployments[0].ID, "failed")
			replacement := testSecretReplacementRequest(actor, scopeID, []uuid.UUID{nodeID},
				original.Rollout.ID, original.Rollout.Revision, "replacement-origin-retry-"+test.name)
			sourceCalls := 0
			_, err = store.ReplaceSecretRollout(t.Context(), replacement,
				func(context.Context, pgx.Tx, SecretReplacementConsume) error {
					sourceCalls++
					return nil
				})
			if !errors.Is(err, ErrSecretRetryRequiresRepublish) || sourceCalls != 0 {
				t.Fatalf("%s replacement error=%v source_calls=%d", test.name, err, sourceCalls)
			}
		})
	}
}

func TestReplaceSecretRolloutRollsBackSourceAndRepeatedConsumeFailures(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(*testing.T, *pgxpool.Pool, *Store)
		source  func(SecretReplacementMaterial, SecretReplacementArtifactBuilder) SecretReplacementSource
	}{
		{name: "source error", source: func(SecretReplacementMaterial, SecretReplacementArtifactBuilder) SecretReplacementSource {
			return func(context.Context, pgx.Tx, SecretReplacementConsume) error { return errSecretRolloutInjected }
		}},
		{name: "repeated consume", source: func(material SecretReplacementMaterial, builder SecretReplacementArtifactBuilder) SecretReplacementSource {
			return func(_ context.Context, _ pgx.Tx, consume SecretReplacementConsume) error {
				_ = consume(material, builder)
				_ = consume(material, builder)
				return nil
			}
		}},
		{name: "outbox", prepare: func(t *testing.T, pool *pgxpool.Pool, _ *Store) {
			if _, err := pool.Exec(t.Context(), `CREATE FUNCTION fail_replacement_outbox() RETURNS trigger LANGUAGE plpgsql AS $$
				BEGIN RAISE EXCEPTION 'injected replacement outbox failure'; END $$;
				CREATE TRIGGER fail_replacement_outbox BEFORE INSERT ON edge_command_outbox
				FOR EACH ROW EXECUTE FUNCTION fail_replacement_outbox()`); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "audit", prepare: func(_ *testing.T, _ *pgxpool.Pool, store *Store) {
			store.auditor = failingSecretRolloutAuditor{}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture, scopeID, userID, actor := newSecretRolloutIAMFixture(t, nil)
			pool, store := fixture.pool, fixture.store
			nodeID := uuid.New()
			seedEdgeNode(t, pool, scopeID, userID, nodeID)
			seedActiveArtifactKey(t, pool, nodeID, userID, nil)
			publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			keySuffix := strings.ReplaceAll(test.name, " ", "-")
			originalRequest := testSecretRolloutRequest(actor, scopeID, []uuid.UUID{nodeID}, "replacement-rollback-original-"+keySuffix)
			original, err := store.CreateSecretRollout(t.Context(), originalRequest,
				func(_ context.Context, binding SecretArtifactBinding) (ArtifactInput, error) {
					return testSecretArtifact(t, binding, "replacement-rollback-signer", publicKey, privateKey), nil
				})
			if err != nil {
				t.Fatal(err)
			}
			advanceDeploymentState(t, pool, original.Rollout.Deployments[0].ID, "delivered")
			advanceDeploymentState(t, pool, original.Rollout.Deployments[0].ID, "failed")
			if test.prepare != nil {
				test.prepare(t, pool, store)
			}
			request := testSecretReplacementRequest(actor, scopeID, []uuid.UUID{nodeID}, original.Rollout.ID,
				original.Rollout.Revision, "replacement-rollback-"+keySuffix)
			material := SecretReplacementMaterial{
				CanonicalSnapshot: bytes.Clone(originalRequest.CanonicalSnapshot),
				PayloadDigest:     sha256.Sum256([]byte("replacement-rollback-material")),
			}
			builder := func(_ context.Context, bindings []SecretArtifactBinding) ([]ArtifactInput, error) {
				artifacts := make([]ArtifactInput, len(bindings))
				for index, binding := range bindings {
					artifacts[index] = testSecretArtifact(t, binding, "replacement-rollback-signer", publicKey, privateKey)
				}
				return artifacts, nil
			}
			source := func(_ context.Context, _ pgx.Tx, consume SecretReplacementConsume) error {
				return consume(material, builder)
			}
			if test.source != nil {
				source = test.source(material, builder)
			}
			if _, err := store.ReplaceSecretRollout(t.Context(), request, source); err == nil {
				t.Fatal("replacement failure was accepted")
			}
			var revision, writeRequests, rollouts int
			if err := pool.QueryRow(t.Context(), `SELECT
				(SELECT revision FROM rollouts WHERE id=$1),
				(SELECT count(*) FROM edge_rollout_write_requests WHERE idempotency_key=$2),
				(SELECT count(*) FROM rollouts WHERE configuration_scope_id=$3)`,
				original.Rollout.ID, request.IdempotencyKey, scopeID).Scan(&revision, &writeRequests, &rollouts); err != nil {
				t.Fatal(err)
			}
			if revision != int(original.Rollout.Revision) || writeRequests != 0 || rollouts != 1 {
				t.Fatalf("failed replacement mutated revision/write_requests/rollouts=%d/%d/%d", revision, writeRequests, rollouts)
			}
		})
	}
}

func TestRetryRolloutRequiresReplacementPublicationForSecretArtifact(t *testing.T) {
	fixture, scopeID, userID, actor := newSecretRolloutIAMFixture(t, nil)
	pool, store := fixture.pool, fixture.store
	nodeID := uuid.New()
	seedEdgeNode(t, pool, scopeID, userID, nodeID)
	seedActiveArtifactKey(t, pool, nodeID, userID, nil)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	created, err := store.CreateSecretRollout(t.Context(),
		testSecretRolloutRequest(actor, scopeID, []uuid.UUID{nodeID}, "certificate-secret-no-retry"),
		func(_ context.Context, binding SecretArtifactBinding) (ArtifactInput, error) {
			return testSecretArtifact(t, binding, "certificate-no-retry-signer", publicKey, privateKey), nil
		})
	if err != nil {
		t.Fatal(err)
	}
	advanceDeploymentState(t, pool, created.Rollout.Deployments[0].ID, "delivered")
	advanceDeploymentState(t, pool, created.Rollout.Deployments[0].ID, "failed")
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	deployments, err := lockCommandDeployments(t.Context(), tx, scopeID, created.Rollout.ID)
	if err != nil {
		t.Fatal(err)
	}
	err = retryFailedDeployments(t.Context(), tx, normalizedRolloutCommand{}, "queued", 1, deployments, integrationClock)
	if !errors.Is(err, ErrSecretRetryRequiresRepublish) {
		t.Fatalf("secret rollout retry error=%v", err)
	}
	var attempts, outbox int
	if err := tx.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM node_deployments WHERE rollout_id=$1),
		(SELECT count(*) FROM edge_command_outbox outbox JOIN node_deployments deployment
		 ON deployment.id=outbox.deployment_id AND deployment.attempt=outbox.deployment_attempt
		 WHERE deployment.rollout_id=$1)`, created.Rollout.ID).Scan(&attempts, &outbox); err != nil {
		t.Fatal(err)
	}
	if attempts != 1 || outbox != 1 {
		t.Fatalf("secret retry mutated attempts/outbox=%d/%d", attempts, outbox)
	}
}

func TestRetryArtifactClassificationAllowsOnlyNonEmptyPlainConfiguration(t *testing.T) {
	fixture, scopeID, userID, actor := newSecretRolloutIAMFixture(t, nil)
	pool, store := fixture.pool, fixture.store
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	configuration := persistTestConfig(t, store, testConfigRequest(
		t, scopeID, "retry-classification-config", "retry-classification-signer", publicKey, privateKey,
		[]byte("configuration artifact"),
	))
	configurationNode := uuid.New()
	seedEdgeNode(t, pool, scopeID, userID, configurationNode)
	configurationRollout, err := store.CreateRollout(t.Context(), testRolloutRequest(
		scopeID, configuration.ID, []uuid.UUID{configurationNode}, "retry-classification-config-rollout",
	))
	if err != nil {
		t.Fatal(err)
	}

	mixedRequest := testConfigRequest(t, scopeID, "retry-classification-mixed", "retry-classification-signer",
		publicKey, privateKey, []byte("mixed configuration artifact"))
	mixedRecipient := "x25519:" + string(bytes.Repeat([]byte{'b'}, 64))
	mixedBinding := SecretArtifactBinding{ArtifactID: uuid.New(), RecipientKeyID: mixedRecipient}
	mixedRequest.Artifacts = append(mixedRequest.Artifacts,
		testSecretArtifact(t, mixedBinding, "retry-classification-signer", publicKey, privateKey))
	mixed := persistTestConfig(t, store, mixedRequest)
	mixedNode := uuid.New()
	seedEdgeNode(t, pool, scopeID, userID, mixedNode)
	mixedRollout, err := store.CreateRollout(t.Context(), testRolloutRequest(
		scopeID, mixed.ID, []uuid.UUID{mixedNode}, "retry-classification-mixed-rollout",
	))
	if err != nil {
		t.Fatal(err)
	}

	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := requireConfigurationOnlyRetry(t.Context(), tx,
		configurationRollout.Rollout.Deployments[0].ID, 1); err != nil {
		t.Fatalf("configuration-only classification error=%v", err)
	}
	if err := requireConfigurationOnlyRetry(t.Context(), tx,
		mixedRollout.Rollout.Deployments[0].ID, 1); !errors.Is(err, ErrSecretRetryRequiresRepublish) {
		t.Fatalf("mixed classification error=%v", err)
	}
	if err := requireConfigurationOnlyRetry(t.Context(), tx, uuid.New(), 1); !errors.Is(err, ErrSecretRetryRequiresRepublish) {
		t.Fatalf("empty classification error=%v", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	advanceDeploymentState(t, pool, configurationRollout.Rollout.Deployments[0].ID, "delivered")
	advanceDeploymentState(t, pool, configurationRollout.Rollout.Deployments[0].ID, "failed")
	retried, err := store.RetryRollout(t.Context(), RolloutCommandRequest{
		Actor: actor, ConfigurationScopeID: scopeID, RolloutID: configurationRollout.Rollout.ID,
		ExpectedRevision: configurationRollout.Rollout.Revision,
		IdempotencyKey:   "retry-classification-configuration-api", RequestID: uuid.NewString(),
	})
	if err != nil || retried.Replayed || retried.Rollout.Progress.Pending != 1 || retried.Rollout.Revision != 2 {
		t.Fatalf("configuration-only API retry=%+v error=%v", retried, err)
	}
}

func testSecretRolloutRequest(
	actor Actor,
	scopeID uuid.UUID,
	nodeIDs []uuid.UUID,
	idempotencyKey string,
) SecretRolloutRequest {
	return SecretRolloutRequest{
		Actor:                actor,
		ConfigurationScopeID: scopeID,
		NodeIDs:              nodeIDs,
		CanonicalSnapshot:    []byte(`{"certificate_revisions":[1]}`),
		GeneratorName:        "certificate-publication",
		GeneratorVersion:     "1.0.0",
		PayloadDigest:        sha256.Sum256([]byte(idempotencyKey + ":certificate-material")),
		RequiredCapabilities: []*agentv1.Capability{{
			Name: agentv1.CapabilityName_CAPABILITY_NAME_ATOMIC_RELEASE, ApiVersion: 1,
		}},
		HealthCheck:    HealthCheckPolicy{ActivationTimeout: time.Minute, ObservationWindow: 5 * time.Second, RequiredConsecutiveSuccesses: 2},
		Deadline:       integrationClock.Add(time.Hour),
		IdempotencyKey: idempotencyKey,
		RequestID:      uuid.NewString(),
		CorrelationID:  uuid.NewString(),
		Traceparent:    "",
	}
}

func testSecretReplacementRequest(
	actor Actor,
	scopeID uuid.UUID,
	nodeIDs []uuid.UUID,
	originalRolloutID uuid.UUID,
	expectedRevision int64,
	idempotencyKey string,
) SecretReplacementRequest {
	return SecretReplacementRequest{
		Actor: actor, ConfigurationScopeID: scopeID, NodeIDs: nodeIDs,
		OriginalRolloutID: originalRolloutID, ExpectedRevision: expectedRevision,
		GeneratorName: "certificate-publication", GeneratorVersion: "1.0.0",
		RequiredCapabilities: []*agentv1.Capability{{
			Name: agentv1.CapabilityName_CAPABILITY_NAME_ATOMIC_RELEASE, ApiVersion: 1,
		}},
		HealthCheck: HealthCheckPolicy{
			ActivationTimeout: time.Minute, ObservationWindow: 5 * time.Second,
			RequiredConsecutiveSuccesses: 2,
		},
		Deadline: integrationClock.Add(time.Hour), IdempotencyKey: idempotencyKey,
		RequestID: uuid.NewString(), CorrelationID: uuid.NewString(),
	}
}

func newSecretRolloutIAMFixture(
	t *testing.T,
	appender auditAppender,
) (*commandIAMFixture, uuid.UUID, uuid.UUID, Actor) {
	t.Helper()
	fixture := newCommandIAMFixture(t, appender)
	scopeID, userID := seedEdgeScope(t, fixture.pool)
	actor := seedSecretPlatformActor(t, fixture)
	return fixture, scopeID, userID, actor
}

func seedSecretPlatformActor(t *testing.T, fixture *commandIAMFixture) Actor {
	t.Helper()
	scopeID, userID, roleID := seedCommandScope(t, fixture.pool, ScopeKindPlatform), uuid.New(), uuid.New()
	username := "secret-platform-" + strings.ReplaceAll(userID.String(), "-", "")[:16]
	if _, err := fixture.pool.Exec(t.Context(), `WITH inserted_user AS (
		INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'Secret publication operator','not-used')
	), inserted_membership AS (
		INSERT INTO memberships(scope_id,user_id) VALUES($3,$1)
	), inserted_role AS (
		INSERT INTO roles(id,scope_id,name,description,system_role)
		VALUES($4,$3,'platform_owner','Secret publication platform owner',true)
	), inserted_permission AS (
		INSERT INTO role_permissions(role_id,permission_name) VALUES($4,$5) ON CONFLICT DO NOTHING
	)
	INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($3,$1,$4)`,
		userID, username, scopeID, roleID, PermissionManage); err != nil {
		t.Fatal(err)
	}
	sessionID := uuid.New()
	now := time.Now().UTC().Truncate(time.Microsecond)
	refreshDigest := sha256.Sum256(sessionID[:])
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO auth_sessions(
		id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at
	) VALUES($1,$2,$3,$4,$5,$6,$7)`, sessionID, uuid.New(), userID, scopeID,
		refreshDigest[:], now.Add(-time.Minute), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	return fixture.mintActor(t, userID, scopeID, ScopeKindPlatform, sessionID)
}

func seedSecretPlatformActorInScope(
	t *testing.T,
	fixture *commandIAMFixture,
	scopeID uuid.UUID,
	permissions ...string,
) Actor {
	t.Helper()
	userID, roleID := uuid.New(), uuid.New()
	username := "secret-platform-" + strings.ReplaceAll(userID.String(), "-", "")[:16]
	if _, err := fixture.pool.Exec(t.Context(), `WITH inserted_user AS (
		INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'Secret publication operator','not-used')
	), inserted_membership AS (
		INSERT INTO memberships(scope_id,user_id) VALUES($3,$1)
	), inserted_role AS (
		INSERT INTO roles(id,scope_id,name,description,system_role)
		VALUES($4,$3,$5,'Secret publication platform owner',true)
	), inserted_permissions AS (
		INSERT INTO role_permissions(role_id,permission_name)
		SELECT $4,name FROM permissions WHERE name=ANY($6::text[])
	)
	INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($3,$1,$4)`,
		userID, username, scopeID, roleID, "secret_"+strings.ReplaceAll(roleID.String(), "-", "")[:16], permissions); err != nil {
		t.Fatal(err)
	}
	sessionID := uuid.New()
	now := time.Now().UTC().Truncate(time.Microsecond)
	refreshDigest := sha256.Sum256(sessionID[:])
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO auth_sessions(
		id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at
	) VALUES($1,$2,$3,$4,$5,$6,$7)`, sessionID, uuid.New(), userID, scopeID,
		refreshDigest[:], now.Add(-time.Minute), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	return fixture.mintActor(t, userID, scopeID, ScopeKindPlatform, sessionID)
}

func grantSecretRolloutPermission(t *testing.T, pool *pgxpool.Pool, actor Actor, permission string) {
	t.Helper()
	var roleID uuid.UUID
	err := pool.QueryRow(t.Context(), `SELECT role.id FROM roles role
		JOIN role_permissions permission ON permission.role_id=role.id AND permission.permission_name=$2
		WHERE role.scope_id=$1 ORDER BY role.id LIMIT 1`, actor.ScopeID, permission).Scan(&roleID)
	if errors.Is(err, pgx.ErrNoRows) {
		roleID = uuid.New()
		name := "secret_" + strings.ReplaceAll(permission, ".", "_")
		if _, err = pool.Exec(t.Context(), `WITH inserted_role AS (
			INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$2,$3,'Secret rollout permission',true)
		) INSERT INTO role_permissions(role_id,permission_name) VALUES($1,$4)`,
			roleID, actor.ScopeID, name, permission); err != nil {
			t.Fatal(err)
		}
	} else if err != nil {
		t.Fatal(err)
	}
	command, err := pool.Exec(t.Context(), `INSERT INTO role_assignments(scope_id,user_id,role_id)
		VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, actor.ScopeID, actor.UserID, roleID)
	if err != nil || command.RowsAffected() != 1 {
		t.Fatalf("grant secret rollout permission %s assignment rows=%d error=%v", permission, command.RowsAffected(), err)
	}
}

func revokeSecretRolloutPermission(t *testing.T, pool *pgxpool.Pool, actor Actor, permission string) {
	t.Helper()
	command, err := pool.Exec(t.Context(), `DELETE FROM role_assignments assignment
		USING role_permissions permission
		WHERE assignment.scope_id=$1 AND assignment.user_id=$2
		  AND permission.role_id=assignment.role_id AND permission.permission_name=$3`,
		actor.ScopeID, actor.UserID, permission)
	if err != nil || command.RowsAffected() != 1 {
		t.Fatalf("revoke secret rollout permission %s rows=%d error=%v", permission, command.RowsAffected(), err)
	}
}

func testSecretArtifact(
	t *testing.T,
	binding SecretArtifactBinding,
	signingKeyID string,
	publicKey ed25519.PublicKey,
	privateKey ed25519.PrivateKey,
) ArtifactInput {
	t.Helper()
	wire := bytes.Repeat(binding.ArtifactID[:], 5)
	digest := sha256.Sum256(wire)
	recipientID := binding.RecipientKeyID
	return ArtifactInput{
		ID: binding.ArtifactID, Kind: agentv1.ArtifactKind_ARTIFACT_KIND_NODE_SECRET_BUNDLE,
		WireBytes: wire, SizeBytes: uint64(len(wire)), SHA256: digest[:], Signature: ed25519.Sign(privateKey, wire),
		SigningKeyID: signingKeyID, SigningPublicKey: publicKey,
		SignatureAlgorithm:  agentv1.ArtifactSignatureAlgorithm_ARTIFACT_SIGNATURE_ALGORITHM_ED25519,
		Compression:         agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_NONE,
		MediaType:           "application/vnd.cdnca.edge-certificate-bundle+json;version=1",
		EncryptionAlgorithm: agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_HPKE_X25519_HKDF_SHA256_AES_256_GCM,
		RecipientKeyID:      &recipientID,
	}
}

func seedActiveArtifactKey(
	t *testing.T,
	pool *pgxpool.Pool,
	nodeID, userID uuid.UUID,
	publicKey []byte,
) (string, []byte) {
	t.Helper()
	if publicKey == nil {
		publicKey = make([]byte, 32)
		if _, err := rand.Read(publicKey); err != nil {
			t.Fatal(err)
		}
	}
	digest := sha256.Sum256(publicKey)
	keyID := "x25519:" + hex.EncodeToString(digest[:])
	seedArtifactKeyFact(t, pool, nodeID, userID, keyID, publicKey, "active")
	return keyID, bytes.Clone(publicKey)
}

func rotateActiveArtifactKey(t *testing.T, pool *pgxpool.Pool, nodeID, userID uuid.UUID, oldID string) (string, []byte) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), `UPDATE node_artifact_encryption_keys SET status='retired',
		deactivated_at=clock_timestamp(),deactivation_reason='test rotation' WHERE id=$1`, oldID); err != nil {
		t.Fatal(err)
	}
	publicKey := make([]byte, 32)
	if _, err := rand.Read(publicKey); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(publicKey)
	keyID := "x25519:" + hex.EncodeToString(digest[:])
	seedArtifactKeyFact(t, pool, nodeID, userID, keyID, publicKey, "active")
	return keyID, publicKey
}

func seedArtifactKeyFact(t *testing.T, pool *pgxpool.Pool, nodeID, userID uuid.UUID, keyID string, publicKey []byte, status string) {
	t.Helper()
	tokenID, authorizationID, requestID := uuid.New(), uuid.New(), uuid.New()
	digest := sha256.Sum256(publicKey)
	now := integrationClock
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(t.Context(), `INSERT INTO node_enrollment_tokens(
		id,node_id,purpose,token_hash,created_by_user_id,created_at,expires_at,consumed_at,consume_request_id,consume_request_digest
	) VALUES($1,$2,'initial_enrollment',$3,$4,$5,$6,$5,$7,$8)`, tokenID, nodeID, randomDigest(t), userID,
		now.Add(-time.Minute), now.Add(time.Hour), requestID.String(), randomDigest(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO node_enrollment_authorizations(
		id,token_id,node_id,purpose,request_id,request_digest,authorized_at
	) VALUES($1,$2,$3,'initial_enrollment',$4,$5,$6)`, authorizationID, tokenID, nodeID,
		requestID.String(), randomDigest(t), now.Add(-30*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO node_identity_authorizations(
		id,token_id,node_id,purpose,request_id,request_digest,token_hash,csr_der,csr_sha256,
		machine_fingerprint_sha256,protocol_min_major,protocol_min_minor,protocol_max_major,protocol_max_minor,
		selected_protocol_major,selected_protocol_minor,capabilities_snapshot,capabilities_sha256,
		gateway_workload_identity,gateway_instance_id,artifact_key_id,artifact_public_key,status,authorized_at,expires_at
	) VALUES($1,$2,$3,'initial_enrollment',$4,$5,$6,$7,$8,$9,1,0,1,0,1,0,$10,$11,
		'spiffe://cdnca.test/gateway','secret-rollout-test',$12,$13,'authorized',$14,$15)`,
		authorizationID, tokenID, nodeID, requestID, randomDigest(t), randomDigest(t), []byte{0x30}, randomDigest(t),
		randomDigest(t), []byte{0x01}, randomDigest(t), keyID, publicKey, now.Add(-30*time.Second), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	activatedAt := any(nil)
	if status == "active" {
		activatedAt = now
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO node_artifact_encryption_keys(
		id,node_id,authorization_id,public_key,public_key_sha256,status,created_at,activated_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, keyID, nodeID, authorizationID, publicKey, digest[:], status,
		now.Add(-time.Second), activatedAt); err != nil {
		t.Fatal(err)
	}
	if status == "active" {
		if _, err := tx.Exec(t.Context(), `UPDATE node_identity_state SET active_artifact_key_id=$2,
			authorization_revision=authorization_revision+1,updated_at=updated_at+interval '1 microsecond' WHERE node_id=$1`, nodeID, keyID); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func randomDigest(t *testing.T) []byte {
	t.Helper()
	value := make([]byte, sha256.Size)
	if _, err := rand.Read(value); err != nil {
		t.Fatal(err)
	}
	return value
}

func assertSecretRolloutRowCounts(
	t *testing.T,
	pool *pgxpool.Pool,
	key string,
	wantConfigs, wantArtifacts, wantRollouts, wantDeployments, wantOutbox, wantAudits int,
) {
	t.Helper()
	var configs, artifacts, rollouts, deployments, outbox, audits int
	if err := pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM config_versions WHERE idempotency_key=$1),
		(SELECT count(*) FROM configuration_artifacts artifact JOIN config_versions config ON config.id=artifact.config_version_id WHERE config.idempotency_key=$1),
		(SELECT count(*) FROM rollouts WHERE idempotency_key=$1),
		(SELECT count(*) FROM node_deployments deployment JOIN rollouts rollout ON rollout.id=deployment.rollout_id WHERE rollout.idempotency_key=$1),
		(SELECT count(*) FROM edge_command_outbox outbox JOIN node_deployments deployment ON deployment.id=outbox.deployment_id AND deployment.attempt=outbox.deployment_attempt JOIN rollouts rollout ON rollout.id=deployment.rollout_id WHERE rollout.idempotency_key=$1),
		(SELECT count(*) FROM audit_events WHERE action='edge_secret_rollout.create' AND payload->>'idempotency_key'=$1)`, key).Scan(
		&configs, &artifacts, &rollouts, &deployments, &outbox, &audits); err != nil {
		t.Fatal(err)
	}
	if configs != wantConfigs || artifacts != wantArtifacts || rollouts != wantRollouts || deployments != wantDeployments ||
		outbox != wantOutbox || audits != wantAudits {
		t.Fatalf("rows config/artifact/rollout/deployment/outbox/audit=%d/%d/%d/%d/%d/%d want=%d/%d/%d/%d/%d/%d",
			configs, artifacts, rollouts, deployments, outbox, audits,
			wantConfigs, wantArtifacts, wantRollouts, wantDeployments, wantOutbox, wantAudits)
	}
}

func assertSecretRolloutMetadataHasNoPrivateMaterial(t *testing.T, pool *pgxpool.Pool, rolloutID uuid.UUID) {
	t.Helper()
	var snapshot, command, outbox, auditPayload []byte
	if err := pool.QueryRow(t.Context(), `SELECT config.canonical_snapshot,deployment.command_bytes,outbox.payload,audit.payload::text::bytea
		FROM rollouts rollout
		JOIN config_versions config ON config.id=rollout.config_version_id
		JOIN node_deployments deployment ON deployment.rollout_id=rollout.id
		JOIN edge_command_outbox outbox ON outbox.deployment_id=deployment.id AND outbox.deployment_attempt=deployment.attempt
		JOIN audit_events audit ON audit.action='edge_secret_rollout.create' AND audit.resource_id=rollout.id::text
		WHERE rollout.id=$1`, rolloutID).Scan(&snapshot, &command, &outbox, &auditPayload); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string][]byte{"snapshot": snapshot, "command": command, "outbox": outbox, "audit": auditPayload} {
		for _, forbidden := range [][]byte{[]byte("PRIVATE KEY"), []byte("private_key_pem"), []byte("certificate-material")} {
			if bytes.Contains(value, forbidden) {
				t.Fatalf("%s contains sensitive marker %q", name, forbidden)
			}
		}
	}
}
