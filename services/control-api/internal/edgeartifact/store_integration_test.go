//go:build integration

package edgeartifact

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type artifactTestFixture struct {
	pool      *pgxpool.Pool
	admin     *pgxpool.Pool
	schema    string
	now       time.Time
	scopeID   uuid.UUID
	userID    uuid.UUID
	gatewayID uuid.UUID
	store     *Store
}

type artifactDeployment struct {
	nodeID       uuid.UUID
	configID     uuid.UUID
	rolloutID    uuid.UUID
	deploymentID uuid.UUID
	eventID      uuid.UUID
	artifactID   uuid.UUID
	signingKeyID string
	wireBytes    []byte
	digest       [sha256.Size]byte
	signature    []byte
}

func TestStoreFetchChunkLifecycle(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	fixture := newArtifactTestFixture(t, databaseURL)
	defer fixture.close(t)

	t.Run("multi chunk resume eof and immutable replay", func(t *testing.T) {
		deployment := fixture.seedDeployment(t, []byte("abcdefghijklmnopqrstuvwxyz"), "queued")
		var assembled []byte
		var firstRequest *controlv1.FetchArtifactRequest
		for offset := uint64(0); offset < uint64(len(deployment.wireBytes)); {
			request := fixture.request(deployment, offset)
			if firstRequest == nil {
				firstRequest = proto.Clone(request).(*controlv1.FetchArtifactRequest)
			}
			result, err := fixture.store.FetchChunk(context.Background(), request)
			if err != nil {
				t.Fatal(err)
			}
			assertChunkIdentity(t, result, request, deployment, fixture.store.config.MaxChunkBytes)
			assembled = append(assembled, result.Response.Chunk.Data...)
			offset += uint64(len(result.Response.Chunk.Data))
			assertAudit(t, fixture.pool, request.Request.RequestId, "completed", int64(len(result.Response.Chunk.Data)), true)
		}
		if !bytes.Equal(assembled, deployment.wireBytes) {
			t.Fatalf("assembled artifact = %q, want %q", assembled, deployment.wireBytes)
		}

		first, err := fixture.store.FetchChunk(context.Background(), firstRequest)
		if err != nil || !first.Replayed {
			t.Fatalf("first replay = (%+v, %v)", first, err)
		}
		first.Response.Chunk.Data[0] ^= 0xff
		first.Descriptor.Sha256[0] ^= 0xff
		again, err := fixture.store.FetchChunk(context.Background(), firstRequest)
		if err != nil || !again.Replayed || !bytes.Equal(again.Response.Chunk.Data, deployment.wireBytes[:fixture.store.config.MaxChunkBytes]) ||
			!bytes.Equal(again.Descriptor.Sha256, deployment.digest[:]) {
			t.Fatalf("replay aliased caller-owned bytes: (%+v, %v)", again, err)
		}

		eofRequest := fixture.request(deployment, uint64(len(deployment.wireBytes)))
		eof, err := fixture.store.FetchChunk(context.Background(), eofRequest)
		if err != nil || !eof.EOF || eof.Response != nil || eof.Descriptor == nil || eof.Descriptor.ArtifactId != deployment.artifactID.String() {
			t.Fatalf("EOF result = (%+v, %v)", eof, err)
		}
		assertAudit(t, fixture.pool, eofRequest.Request.RequestId, "completed", 0, true)

		tooFar := fixture.request(deployment, uint64(len(deployment.wireBytes)+1))
		if result, err := fixture.store.FetchChunk(context.Background(), tooFar); !errors.Is(err, ErrOffsetOutOfRange) || result.EOF {
			t.Fatalf("offset beyond EOF = (%+v, %v)", result, err)
		}
		assertAudit(t, fixture.pool, tooFar.Request.RequestId, "failed", 0, true)
		if result, err := fixture.store.FetchChunk(context.Background(), tooFar); !errors.Is(err, ErrOffsetOutOfRange) || result.EOF {
			t.Fatalf("failed request replay = (%+v, %v)", result, err)
		}

		conflict := proto.Clone(firstRequest).(*controlv1.FetchArtifactRequest)
		conflict.Offset++
		if _, err := fixture.store.FetchChunk(context.Background(), conflict); !errors.Is(err, ErrIdempotencyConflict) {
			t.Fatalf("idempotency conflict error = %v", err)
		}
		assertAudit(t, fixture.pool, firstRequest.Request.RequestId, "completed", int64(fixture.store.config.MaxChunkBytes), true)
	})

	t.Run("completed replay survives deployment progress", func(t *testing.T) {
		deployment := fixture.seedDeployment(t, []byte("state-progress-artifact"), "queued")
		request := fixture.request(deployment, 0)
		initial, err := fixture.store.FetchChunk(context.Background(), request)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.pool.Exec(context.Background(), `UPDATE node_deployments SET state = 'staged' WHERE id = $1 AND attempt = 1`, deployment.deploymentID); err != nil {
			t.Fatal(err)
		}
		replay, err := fixture.store.FetchChunk(context.Background(), request)
		if err != nil || !replay.Replayed || !proto.Equal(initial.Response, replay.Response) {
			t.Fatalf("post-progress replay = (%+v, %v)", replay, err)
		}
		fresh := fixture.request(deployment, uint64(len(initial.Response.Chunk.Data)))
		if _, err := fixture.store.FetchChunk(context.Background(), fresh); !errors.Is(err, ErrDeploymentIneligible) {
			t.Fatalf("new fetch after staging error = %v", err)
		}
		assertAudit(t, fixture.pool, fresh.Request.RequestId, "failed", 0, true)
	})

	t.Run("concurrent identical request has one original", func(t *testing.T) {
		deployment := fixture.seedDeployment(t, []byte("concurrent-fetch-artifact"), "delivered")
		request := fixture.request(deployment, 0)
		const workers = 12
		start := make(chan struct{})
		results := make(chan FetchResult, workers)
		errorsSeen := make(chan error, workers)
		var wait sync.WaitGroup
		for index := 0; index < workers; index++ {
			wait.Add(1)
			go func() {
				defer wait.Done()
				<-start
				result, err := fixture.store.FetchChunk(context.Background(), request)
				results <- result
				errorsSeen <- err
			}()
		}
		close(start)
		wait.Wait()
		close(results)
		close(errorsSeen)
		for err := range errorsSeen {
			if err != nil {
				t.Fatal(err)
			}
		}
		originals := 0
		for result := range results {
			if !result.Replayed {
				originals++
			}
			assertChunkIdentity(t, result, request, deployment, fixture.store.config.MaxChunkBytes)
		}
		if originals != 1 {
			t.Fatalf("original results = %d, want 1", originals)
		}
		var count int
		if err := fixture.pool.QueryRow(context.Background(), `SELECT count(*) FROM artifact_fetch_requests WHERE request_id = $1`, request.Request.RequestId).Scan(&count); err != nil || count != 1 {
			t.Fatalf("request audit count = %d, %v", count, err)
		}
	})
}

func TestStoreRejectsBindingAndEligibilityConflicts(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	fixture := newArtifactTestFixture(t, databaseURL)
	defer fixture.close(t)
	primary := fixture.seedDeployment(t, []byte("primary-artifact"), "queued")
	other := fixture.seedDeployment(t, []byte("other-artifact"), "queued")

	tests := []struct {
		name        string
		mutate      func(*controlv1.FetchArtifactRequest)
		want        error
		auditStatus string
	}{
		{name: "node", mutate: func(value *controlv1.FetchArtifactRequest) { value.NodeId = other.nodeID.String() }, want: ErrBindingConflict, auditStatus: "failed"},
		{name: "command event", mutate: func(value *controlv1.FetchArtifactRequest) { value.EventId = other.eventID.String() }, want: ErrBindingConflict, auditStatus: "failed"},
		{name: "deployment", mutate: func(value *controlv1.FetchArtifactRequest) { value.DeploymentId = other.deploymentID.String() }, want: ErrBindingConflict},
		{name: "attempt", mutate: func(value *controlv1.FetchArtifactRequest) { value.Attempt = 2 }, want: ErrBindingConflict},
		{name: "artifact", mutate: func(value *controlv1.FetchArtifactRequest) { value.ArtifactId = other.artifactID.String() }, want: ErrBindingConflict},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := fixture.request(primary, 0)
			test.mutate(request)
			if result, err := fixture.store.FetchChunk(context.Background(), request); !errors.Is(err, test.want) || result.EOF {
				t.Fatalf("result = (%+v, %v), want %v", result, err, test.want)
			}
			if test.auditStatus == "" {
				assertNoAudit(t, fixture.pool, request.Request.RequestId)
			} else {
				assertAudit(t, fixture.pool, request.Request.RequestId, test.auditStatus, 0, true)
			}
		})
	}

	staged := fixture.seedDeployment(t, []byte("staged-artifact"), "staged")
	stagedRequest := fixture.request(staged, 0)
	if _, err := fixture.store.FetchChunk(context.Background(), stagedRequest); !errors.Is(err, ErrDeploymentIneligible) {
		t.Fatalf("staged deployment error = %v", err)
	}
	assertAudit(t, fixture.pool, stagedRequest.Request.RequestId, "failed", 0, true)

	revoked := fixture.seedDeployment(t, []byte("revoked-artifact"), "queued")
	if _, err := fixture.pool.Exec(context.Background(), `UPDATE config_versions SET status = 'revoked' WHERE id = $1`, revoked.configID); err != nil {
		t.Fatal(err)
	}
	revokedRequest := fixture.request(revoked, 0)
	if _, err := fixture.store.FetchChunk(context.Background(), revokedRequest); !errors.Is(err, ErrDeploymentIneligible) {
		t.Fatalf("revoked config error = %v", err)
	}

	expired := fixture.seedDeployment(t, []byte("expired-artifact"), "queued")
	expiredConfig := fixture.store.config
	expiredStore, err := NewStoreWithClock(fixture.pool, expiredConfig, func() time.Time { return fixture.now.Add(2 * time.Hour) })
	if err != nil {
		t.Fatal(err)
	}
	expiredRequest := fixture.requestAt(expired, 0, fixture.now.Add(2*time.Hour))
	if _, err := expiredStore.FetchChunk(context.Background(), expiredRequest); !errors.Is(err, ErrDeploymentIneligible) {
		t.Fatalf("expired deployment error = %v", err)
	}
}

func TestStoreFailsClosedOnArtifactTampering(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	fixture := newArtifactTestFixture(t, databaseURL)
	defer fixture.close(t)

	tests := []struct {
		name   string
		mutate func(*testing.T, artifactDeployment)
	}{
		{name: "wire bytes", mutate: func(t *testing.T, deployment artifactDeployment) {
			changed := bytes.Clone(deployment.wireBytes)
			changed[0] ^= 0xff
			fixture.mutateArtifact(t, `UPDATE configuration_artifacts SET wire_bytes = $2 WHERE id = $1`, deployment.artifactID, changed)
		}},
		{name: "sha256 metadata", mutate: func(t *testing.T, deployment artifactDeployment) {
			changed := bytes.Clone(deployment.digest[:])
			changed[0] ^= 0xff
			fixture.mutateArtifact(t, `UPDATE configuration_artifacts SET sha256 = $2 WHERE id = $1`, deployment.artifactID, changed)
		}},
		{name: "signature metadata", mutate: func(t *testing.T, deployment artifactDeployment) {
			changed := bytes.Clone(deployment.signature)
			changed[0] ^= 0xff
			fixture.mutateArtifact(t, `UPDATE configuration_artifacts SET signature = $2 WHERE id = $1`, deployment.artifactID, changed)
		}},
		{name: "signing key", mutate: func(t *testing.T, deployment artifactDeployment) {
			otherPublic, _, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := fixture.pool.Exec(context.Background(), `ALTER TABLE artifact_signing_keys DISABLE TRIGGER artifact_signing_keys_immutable`); err != nil {
				t.Fatal(err)
			}
			if _, err := fixture.pool.Exec(context.Background(), `UPDATE artifact_signing_keys SET public_key = $2 WHERE id = $1`, deployment.signingKeyID, otherPublic); err != nil {
				t.Fatal(err)
			}
			if _, err := fixture.pool.Exec(context.Background(), `ALTER TABLE artifact_signing_keys ENABLE TRIGGER artifact_signing_keys_immutable`); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			deployment := fixture.seedDeployment(t, []byte("tamper-resistant-wire-bytes"), "queued")
			test.mutate(t, deployment)
			request := fixture.request(deployment, 0)
			if result, err := fixture.store.FetchChunk(context.Background(), request); !errors.Is(err, ErrArtifactIntegrity) || result.EOF {
				t.Fatalf("tampered fetch = (%+v, %v)", result, err)
			}
			assertAudit(t, fixture.pool, request.Request.RequestId, "failed", 0, true)
		})
	}
}

func TestStoreFailsClosedOnCommandAndOrdinalTampering(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	fixture := newArtifactTestFixture(t, databaseURL)
	defer fixture.close(t)

	tests := []struct {
		name   string
		mutate func(*testing.T, artifactDeployment)
	}{
		{name: "command digest", mutate: func(t *testing.T, deployment artifactDeployment) {
			changed := make([]byte, sha256.Size)
			changed[0] = 1
			fixture.mutateDeploymentCommand(t, `UPDATE node_deployments SET command_sha256 = $2 WHERE id = $1 AND attempt = 1`, deployment.deploymentID, changed)
		}},
		{name: "unknown protobuf field", mutate: func(t *testing.T, deployment artifactDeployment) {
			commandBytes := fixture.commandBytes(t, deployment)
			commandBytes = append(commandBytes, 0xa0, 0x06, 0x01)
			digest := sha256.Sum256(commandBytes)
			fixture.mutateDeploymentCommand(t, `UPDATE node_deployments SET command_bytes = $2, command_sha256 = $3 WHERE id = $1 AND attempt = 1`, deployment.deploymentID, commandBytes, digest[:])
		}},
		{name: "nested unknown descriptor field", mutate: func(t *testing.T, deployment artifactDeployment) {
			fixture.rewriteDeploymentCommand(t, deployment, func(command *agentv1.DeploymentCommand) {
				command.Artifacts[0].ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x01})
			})
		}},
		{name: "command event identity", mutate: func(t *testing.T, deployment artifactDeployment) {
			fixture.rewriteDeploymentCommand(t, deployment, func(command *agentv1.DeploymentCommand) {
				command.Event.EventId = uuid.NewString()
			})
		}},
		{name: "command config identity", mutate: func(t *testing.T, deployment artifactDeployment) {
			fixture.rewriteDeploymentCommand(t, deployment, func(command *agentv1.DeploymentCommand) {
				command.ConfigVersionId = uuid.NewString()
			})
		}},
		{name: "command action identity", mutate: func(t *testing.T, deployment artifactDeployment) {
			fixture.rewriteDeploymentCommand(t, deployment, func(command *agentv1.DeploymentCommand) {
				command.Action = agentv1.DeploymentAction_DEPLOYMENT_ACTION_ROLLBACK
			})
		}},
		{name: "descriptor field", mutate: func(t *testing.T, deployment artifactDeployment) {
			fixture.rewriteDeploymentCommand(t, deployment, func(command *agentv1.DeploymentCommand) {
				command.Artifacts[0].MediaType = "application/octet-stream"
			})
		}},
		{name: "descriptor ordinal", mutate: func(t *testing.T, deployment artifactDeployment) {
			if _, err := fixture.pool.Exec(context.Background(), `ALTER TABLE node_deployment_artifacts DISABLE TRIGGER node_deployment_artifacts_immutable`); err != nil {
				t.Fatal(err)
			}
			if _, err := fixture.pool.Exec(context.Background(), `UPDATE node_deployment_artifacts SET ordinal = 2 WHERE deployment_id = $1 AND deployment_attempt = 1`, deployment.deploymentID); err != nil {
				t.Fatal(err)
			}
			if _, err := fixture.pool.Exec(context.Background(), `ALTER TABLE node_deployment_artifacts ENABLE TRIGGER node_deployment_artifacts_immutable`); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			deployment := fixture.seedDeployment(t, []byte("command-bound-artifact"), "queued")
			test.mutate(t, deployment)
			request := fixture.request(deployment, 0)
			if result, err := fixture.store.FetchChunk(context.Background(), request); !errors.Is(err, ErrArtifactIntegrity) || result.EOF {
				t.Fatalf("tampered command fetch = (%+v, %v)", result, err)
			}
			assertAudit(t, fixture.pool, request.Request.RequestId, "failed", 0, true)
		})
	}
}

func TestStoreValidatesEveryBoundDescriptor(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	fixture := newArtifactTestFixture(t, databaseURL)
	defer fixture.close(t)

	t.Run("non-requested command descriptor", func(t *testing.T) {
		deployment := fixture.seedDeployment(t, []byte("requested-artifact"), "queued")
		fixture.addSecondArtifact(t, deployment, []byte("non-requested-artifact"))
		if _, err := fixture.store.FetchChunk(context.Background(), fixture.request(deployment, 0)); err != nil {
			t.Fatalf("valid two-artifact command failed: %v", err)
		}
		fixture.rewriteDeploymentCommand(t, deployment, func(command *agentv1.DeploymentCommand) {
			command.Artifacts[1].MediaType = "application/octet-stream"
		})
		request := fixture.request(deployment, 0)
		if _, err := fixture.store.FetchChunk(context.Background(), request); !errors.Is(err, ErrArtifactIntegrity) {
			t.Fatalf("non-requested command descriptor error = %v", err)
		}
		assertAudit(t, fixture.pool, request.Request.RequestId, "failed", 0, true)
	})

	t.Run("non-requested database descriptor", func(t *testing.T) {
		deployment := fixture.seedDeployment(t, []byte("requested-database-artifact"), "queued")
		second := fixture.addSecondArtifact(t, deployment, []byte("other-database-artifact"))
		fixture.mutateArtifact(t, `UPDATE configuration_artifacts SET media_type = 'application/octet-stream' WHERE id = $1`, second.ArtifactId)
		request := fixture.request(deployment, 0)
		if _, err := fixture.store.FetchChunk(context.Background(), request); !errors.Is(err, ErrArtifactIntegrity) {
			t.Fatalf("non-requested database descriptor error = %v", err)
		}
	})

	t.Run("swapped binding ordinals", func(t *testing.T) {
		deployment := fixture.seedDeployment(t, []byte("first-ordinal-artifact"), "queued")
		second := fixture.addSecondArtifact(t, deployment, []byte("second-ordinal-artifact"))
		secondID := uuid.MustParse(second.ArtifactId)
		tx, err := fixture.pool.Begin(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		if _, err := tx.Exec(context.Background(), `ALTER TABLE node_deployment_artifacts DISABLE TRIGGER node_deployment_artifacts_immutable`); err != nil {
			t.Fatal(err)
		}
		for _, change := range []struct {
			artifactID uuid.UUID
			ordinal    int
		}{{secondID, 3}, {deployment.artifactID, 2}, {secondID, 1}} {
			if _, err := tx.Exec(context.Background(), `
				UPDATE node_deployment_artifacts SET ordinal = $3
				WHERE deployment_id = $1 AND deployment_attempt = 1 AND artifact_id = $2`,
				deployment.deploymentID, change.artifactID, change.ordinal); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := tx.Exec(context.Background(), `ALTER TABLE node_deployment_artifacts ENABLE TRIGGER node_deployment_artifacts_immutable`); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(context.Background()); err != nil {
			t.Fatal(err)
		}
		request := fixture.request(deployment, 0)
		if _, err := fixture.store.FetchChunk(context.Background(), request); !errors.Is(err, ErrArtifactIntegrity) {
			t.Fatalf("swapped binding ordinal error = %v", err)
		}
	})
}

func TestStoreRollsBackAuditOnDatabaseFailure(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	fixture := newArtifactTestFixture(t, databaseURL)
	defer fixture.close(t)
	deployment := fixture.seedDeployment(t, []byte("transactional-fetch"), "queued")
	request := fixture.request(deployment, 0)
	if _, err := fixture.pool.Exec(context.Background(), `
		CREATE FUNCTION edgeartifact_fail_finish() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.status = 'completed' THEN RAISE EXCEPTION 'injected finish failure'; END IF;
			RETURN NEW;
		END;
		$$;
		CREATE TRIGGER edgeartifact_fail_finish_trigger
		BEFORE UPDATE ON artifact_fetch_requests
		FOR EACH ROW EXECUTE FUNCTION edgeartifact_fail_finish()`); err != nil {
		t.Fatal(err)
	}
	result, err := fixture.store.FetchChunk(context.Background(), request)
	if !errors.Is(err, ErrStorage) || result.EOF {
		t.Fatalf("injected database failure = (%+v, %v)", result, err)
	}
	assertNoAudit(t, fixture.pool, request.Request.RequestId)
	if _, err := fixture.pool.Exec(context.Background(), `DROP TRIGGER edgeartifact_fail_finish_trigger ON artifact_fetch_requests; DROP FUNCTION edgeartifact_fail_finish()`); err != nil {
		t.Fatal(err)
	}
	if retry, err := fixture.store.FetchChunk(context.Background(), request); err != nil || retry.Response == nil {
		t.Fatalf("request lock was not released after rollback: (%+v, %v)", retry, err)
	}

	cancelledRequest := fixture.request(deployment, 0)
	if _, err := fixture.pool.Exec(context.Background(), `
		CREATE FUNCTION edgeartifact_slow_start() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			PERFORM pg_sleep(1);
			RETURN NEW;
		END;
		$$;
		CREATE TRIGGER edgeartifact_slow_start_trigger
		BEFORE INSERT ON artifact_fetch_requests
		FOR EACH ROW EXECUTE FUNCTION edgeartifact_slow_start()`); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	result, err = fixture.store.FetchChunk(ctx, cancelledRequest)
	if !errors.Is(err, ErrStorage) || !errors.Is(err, context.DeadlineExceeded) || result.EOF {
		t.Fatalf("cancelled database operation = (%+v, %v)", result, err)
	}
	if _, err := fixture.pool.Exec(context.Background(), `DROP TRIGGER edgeartifact_slow_start_trigger ON artifact_fetch_requests; DROP FUNCTION edgeartifact_slow_start()`); err != nil {
		t.Fatal(err)
	}
	assertNoAudit(t, fixture.pool, cancelledRequest.Request.RequestId)
	if retry, err := fixture.store.FetchChunk(context.Background(), cancelledRequest); err != nil || retry.Response == nil {
		t.Fatalf("request lock was not released after cancellation: (%+v, %v)", retry, err)
	}
}

func newArtifactTestFixture(t *testing.T, databaseURL string) *artifactTestFixture {
	t.Helper()
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	if err := admin.Ping(ctx); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	schema := "edge_artifact_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^edge_artifact_test_[a-f0-9]{32}$`).MatchString(schema) {
		t.Fatalf("unsafe schema %q", schema)
	}
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	var pool *pgxpool.Pool
	ready := false
	defer func() {
		if ready {
			return
		}
		if pool != nil {
			pool.Close()
		}
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA IF EXISTS "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
		admin.Close()
	}()
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err = pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	if err := applyMigrationsThrough018(ctx, pool); err != nil {
		pool.Close()
		admin.Close()
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)
	storeConfig := DefaultConfig()
	storeConfig.MaxChunkBytes = 8
	store, err := NewStoreWithClock(pool, storeConfig, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	fixture := &artifactTestFixture{
		pool: pool, admin: admin, schema: schema, now: now,
		scopeID: uuid.New(), userID: uuid.New(), gatewayID: uuid.New(), store: store,
	}
	tenantID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants (id, display_name) VALUES ($1, 'Edge artifact integration tenant')`, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO access_scopes (id, kind, tenant_id) VALUES ($1, 'tenant', $2)`, fixture.scopeID, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO users (id, username, display_name, password_hash)
		VALUES ($1, $2, 'Edge artifact tester', 'unused')`,
		fixture.userID, "edge-artifact-"+strings.ReplaceAll(fixture.userID.String(), "-", "")[:16]); err != nil {
		t.Fatal(err)
	}
	ready = true
	return fixture
}

func applyMigrationsThrough018(ctx context.Context, pool *pgxpool.Pool) error {
	for version := 1; version <= 18; version++ {
		pattern := fmt.Sprintf("%03d_*.up.sql", version)
		matches, err := fs.Glob(migrations.FS, pattern)
		if err != nil || len(matches) != 1 {
			return fmt.Errorf("migration %03d match count %d: %w", version, len(matches), err)
		}
		script, err := fs.ReadFile(migrations.FS, matches[0])
		if err != nil {
			return err
		}
		if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, string(script))
			return err
		}); err != nil {
			return fmt.Errorf("apply migration %03d: %w", version, err)
		}
	}
	return nil
}

func (f *artifactTestFixture) seedDeployment(t *testing.T, wireBytes []byte, state string) artifactDeployment {
	t.Helper()
	ctx := context.Background()
	deployment := artifactDeployment{
		nodeID: uuid.New(), configID: uuid.New(), rolloutID: uuid.New(), deploymentID: uuid.New(),
		eventID: uuid.New(), artifactID: uuid.New(), signingKeyID: "edge-key-" + uuid.NewString(),
		wireBytes: bytes.Clone(wireBytes),
	}
	deployment.digest = sha256.Sum256(deployment.wireBytes)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	deployment.signature = ed25519.Sign(privateKey, deployment.wireBytes)
	createdAt := f.now.Add(-time.Minute)
	deadline := f.now.Add(time.Hour)
	command := &agentv1.DeploymentCommand{
		Event: &commonv1.EventMetadata{
			EventId: deployment.eventID.String(), RequestId: uuid.NewString(),
			OccurredTime: timestamppb.New(createdAt), CorrelationId: uuid.NewString(),
		},
		DeploymentId: deployment.deploymentID.String(), Attempt: 1,
		RolloutId: deployment.rolloutID.String(), ConfigVersionId: deployment.configID.String(),
		Action: agentv1.DeploymentAction_DEPLOYMENT_ACTION_APPLY,
		Artifacts: []*agentv1.ArtifactDescriptor{{
			ArtifactId: deployment.artifactID.String(), Kind: agentv1.ArtifactKind_ARTIFACT_KIND_CONFIGURATION,
			SizeBytes: uint64(len(deployment.wireBytes)), Sha256: bytes.Clone(deployment.digest[:]),
			Signature: bytes.Clone(deployment.signature), SigningKeyId: deployment.signingKeyID,
			SignatureAlgorithm:  agentv1.ArtifactSignatureAlgorithm_ARTIFACT_SIGNATURE_ALGORITHM_ED25519,
			Compression:         agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_NONE,
			MediaType:           "application/vnd.cdnca.edgeconfig",
			EncryptionAlgorithm: agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_NONE,
		}},
		HealthCheck: &agentv1.HealthCheckPolicy{
			ActivationTimeoutDuration: durationpb.New(time.Minute),
			ObservationWindowDuration: durationpb.New(time.Minute), RequiredConsecutiveSuccesses: 1,
		},
		DeadlineTime: timestamppb.New(deadline),
	}
	commandBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	commandDigest := sha256.Sum256(commandBytes)
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO nodes (id, scope_id, name, admin_state, created_by_user_id) VALUES ($1, $2, $3, 'active', $4)`, []any{deployment.nodeID, f.scopeID, "edge-artifact-" + strings.ReplaceAll(deployment.nodeID.String(), "-", "")[:10], f.userID}},
		{`INSERT INTO artifact_signing_keys (id, algorithm, public_key, created_at) VALUES ($1, 'ed25519', $2, $3)`, []any{deployment.signingKeyID, publicKey, createdAt}},
		{`INSERT INTO config_versions (
			id, configuration_scope_id, canonical_snapshot, canonical_snapshot_sha256,
			generator_name, generator_version, status, idempotency_key, request_digest, created_at
		) VALUES ($1, $2, $3, $4, 'integration', '1', 'building', $5, $6, $7)`, []any{deployment.configID, f.scopeID, deployment.wireBytes, deployment.digest[:], deployment.configID.String(), deployment.digest[:], createdAt}},
		{`INSERT INTO configuration_artifacts (
			id, config_version_id, ordinal, kind, wire_bytes, size_bytes, sha256, signature,
			signing_key_id, signature_algorithm, compression, media_type, encryption_algorithm, created_at
		) VALUES ($1, $2, 1, 'configuration', $3, $4, $5, $6, $7, 'ed25519', 'none',
		          'application/vnd.cdnca.edgeconfig', 'none', $8)`, []any{deployment.artifactID, deployment.configID, deployment.wireBytes, len(deployment.wireBytes), deployment.digest[:], deployment.signature, deployment.signingKeyID, createdAt}},
		{`UPDATE config_versions SET status = 'validating' WHERE id = $1`, []any{deployment.configID}},
		{`UPDATE config_versions SET status = 'releasable', published_at = $2 WHERE id = $1`, []any{deployment.configID, createdAt}},
		{`INSERT INTO rollouts (
			id, configuration_scope_id, config_version_id, action, status, idempotency_key,
			request_digest, request_id, correlation_id, activation_timeout_ms, observation_window_ms,
			required_consecutive_successes, deadline_at, created_at, queued_at
		) VALUES ($1, $2, $3, 'apply', 'queued', $4, $5, $6, $7, 60000, 60000, 1, $8, $9, $9)`, []any{deployment.rolloutID, f.scopeID, deployment.configID, deployment.rolloutID.String(), deployment.digest[:], uuid.New(), uuid.New(), deadline, createdAt}},
		{`INSERT INTO node_deployments (
			id, rollout_id, node_id, attempt, config_version_id, action, state, command_event_id,
			command_bytes, command_sha256, deadline_at, created_at, updated_at
		) VALUES ($1, $2, $3, 1, $4, 'apply', $5, $6, $7, $8, $9, $10, $10)`, []any{deployment.deploymentID, deployment.rolloutID, deployment.nodeID, deployment.configID, state, deployment.eventID, commandBytes, commandDigest[:], deadline, createdAt}},
		{`INSERT INTO node_deployment_artifacts (deployment_id, deployment_attempt, config_version_id, artifact_id, ordinal) VALUES ($1, 1, $2, $3, 1)`, []any{deployment.deploymentID, deployment.configID, deployment.artifactID}},
	}
	for _, statement := range statements {
		if _, err := tx.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return deployment
}

func (f *artifactTestFixture) request(deployment artifactDeployment, offset uint64) *controlv1.FetchArtifactRequest {
	return f.requestAt(deployment, offset, f.now)
}

func (f *artifactTestFixture) addSecondArtifact(t *testing.T, deployment artifactDeployment, wireBytes []byte) *agentv1.ArtifactDescriptor {
	t.Helper()
	artifactID := uuid.New()
	signingKeyID := "edge-key-" + uuid.NewString()
	digest := sha256.Sum256(wireBytes)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(privateKey, wireBytes)
	descriptor := &agentv1.ArtifactDescriptor{
		ArtifactId: artifactID.String(), Kind: agentv1.ArtifactKind_ARTIFACT_KIND_CONFIGURATION,
		SizeBytes: uint64(len(wireBytes)), Sha256: bytes.Clone(digest[:]), Signature: bytes.Clone(signature),
		SigningKeyId:        signingKeyID,
		SignatureAlgorithm:  agentv1.ArtifactSignatureAlgorithm_ARTIFACT_SIGNATURE_ALGORITHM_ED25519,
		Compression:         agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_NONE,
		MediaType:           "application/vnd.cdnca.edgeconfig",
		EncryptionAlgorithm: agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_NONE,
	}
	ctx := context.Background()
	if _, err := f.pool.Exec(ctx, `INSERT INTO artifact_signing_keys (id, algorithm, public_key, created_at) VALUES ($1, 'ed25519', $2, $3)`, signingKeyID, publicKey, f.now); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `ALTER TABLE configuration_artifacts DISABLE TRIGGER configuration_artifacts_immutable`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO configuration_artifacts (
			id, config_version_id, ordinal, kind, wire_bytes, size_bytes, sha256, signature,
			signing_key_id, signature_algorithm, compression, media_type, encryption_algorithm, created_at
		) VALUES ($1, $2, 2, 'configuration', $3, $4, $5, $6, $7, 'ed25519', 'none',
		          'application/vnd.cdnca.edgeconfig', 'none', $8)`,
		artifactID, deployment.configID, wireBytes, len(wireBytes), digest[:], signature, signingKeyID, f.now); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `ALTER TABLE configuration_artifacts ENABLE TRIGGER configuration_artifacts_immutable`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO node_deployment_artifacts (deployment_id, deployment_attempt, config_version_id, artifact_id, ordinal)
		VALUES ($1, 1, $2, $3, 2)`, deployment.deploymentID, deployment.configID, artifactID); err != nil {
		t.Fatal(err)
	}
	f.rewriteDeploymentCommand(t, deployment, func(command *agentv1.DeploymentCommand) {
		command.Artifacts = append(command.Artifacts, proto.Clone(descriptor).(*agentv1.ArtifactDescriptor))
	})
	return descriptor
}

func (f *artifactTestFixture) requestAt(deployment artifactDeployment, offset uint64, sentAt time.Time) *controlv1.FetchArtifactRequest {
	return &controlv1.FetchArtifactRequest{
		Request: &commonv1.RequestMetadata{
			RequestId: uuid.NewString(), SentTime: timestamppb.New(sentAt), CorrelationId: uuid.NewString(),
		},
		EventId: deployment.eventID.String(), NodeId: deployment.nodeID.String(),
		DeploymentId: deployment.deploymentID.String(), Attempt: 1,
		ArtifactId: deployment.artifactID.String(), Offset: offset, GatewayInstanceId: f.gatewayID.String(),
	}
}

func (f *artifactTestFixture) mutateArtifact(t *testing.T, query string, args ...any) {
	t.Helper()
	if _, err := f.pool.Exec(context.Background(), `ALTER TABLE configuration_artifacts DISABLE TRIGGER configuration_artifacts_immutable`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(context.Background(), query, args...); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(context.Background(), `ALTER TABLE configuration_artifacts ENABLE TRIGGER configuration_artifacts_immutable`); err != nil {
		t.Fatal(err)
	}
}

func (f *artifactTestFixture) commandBytes(t *testing.T, deployment artifactDeployment) []byte {
	t.Helper()
	var commandBytes []byte
	if err := f.pool.QueryRow(context.Background(), `SELECT command_bytes FROM node_deployments WHERE id = $1 AND attempt = 1`, deployment.deploymentID).Scan(&commandBytes); err != nil {
		t.Fatal(err)
	}
	return bytes.Clone(commandBytes)
}

func (f *artifactTestFixture) mutateDeploymentCommand(t *testing.T, query string, args ...any) {
	t.Helper()
	if _, err := f.pool.Exec(context.Background(), `ALTER TABLE node_deployments DISABLE TRIGGER node_deployment_commands_immutable`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(context.Background(), query, args...); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(context.Background(), `ALTER TABLE node_deployments ENABLE TRIGGER node_deployment_commands_immutable`); err != nil {
		t.Fatal(err)
	}
}

func (f *artifactTestFixture) rewriteDeploymentCommand(t *testing.T, deployment artifactDeployment, mutate func(*agentv1.DeploymentCommand)) {
	t.Helper()
	command := new(agentv1.DeploymentCommand)
	if err := proto.Unmarshal(f.commandBytes(t, deployment), command); err != nil {
		t.Fatal(err)
	}
	mutate(command)
	commandBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(commandBytes)
	f.mutateDeploymentCommand(t, `UPDATE node_deployments SET command_bytes = $2, command_sha256 = $3 WHERE id = $1 AND attempt = 1`, deployment.deploymentID, commandBytes, digest[:])
}

func (f *artifactTestFixture) close(t *testing.T) {
	t.Helper()
	f.pool.Close()
	defer f.admin.Close()
	if _, err := f.admin.Exec(context.Background(), "DROP SCHEMA "+pgx.Identifier{f.schema}.Sanitize()+" CASCADE"); err != nil {
		t.Errorf("drop artifact test schema: %v", err)
	}
}

func assertChunkIdentity(t *testing.T, result FetchResult, request *controlv1.FetchArtifactRequest, deployment artifactDeployment, maxChunk int) {
	t.Helper()
	if result.EOF || result.Response == nil || result.Response.Chunk == nil || result.Descriptor == nil {
		t.Fatalf("incomplete chunk result %+v", result)
	}
	chunk := result.Response.Chunk
	if chunk.RequestId != request.Request.RequestId || chunk.ArtifactId != request.ArtifactId ||
		chunk.Offset != request.Offset || chunk.TotalSizeBytes != uint64(len(deployment.wireBytes)) ||
		len(chunk.Data) == 0 || len(chunk.Data) > maxChunk ||
		chunk.EndOfArtifact != (request.Offset+uint64(len(chunk.Data)) == uint64(len(deployment.wireBytes))) {
		t.Fatalf("chunk identity = %+v", chunk)
	}
	chunkDigest := sha256.Sum256(chunk.Data)
	if !bytes.Equal(chunk.ChunkSha256, chunkDigest[:]) {
		t.Fatal("chunk digest mismatch")
	}
	descriptor := result.Descriptor
	if descriptor.ArtifactId != deployment.artifactID.String() || descriptor.SizeBytes != uint64(len(deployment.wireBytes)) ||
		!bytes.Equal(descriptor.Sha256, deployment.digest[:]) || !bytes.Equal(descriptor.Signature, deployment.signature) ||
		descriptor.SigningKeyId != deployment.signingKeyID || descriptor.MediaType != "application/vnd.cdnca.edgeconfig" {
		t.Fatalf("descriptor identity = %+v", descriptor)
	}
}

func assertAudit(t *testing.T, pool *pgxpool.Pool, requestID, wantStatus string, wantBytes int64, wantCompleted bool) {
	t.Helper()
	var status string
	var bytesServed int64
	var completed bool
	if err := pool.QueryRow(context.Background(), `
		SELECT status, bytes_served, completed_at IS NOT NULL
		FROM artifact_fetch_requests WHERE request_id = $1`, requestID).Scan(&status, &bytesServed, &completed); err != nil {
		t.Fatal(err)
	}
	if status != wantStatus || bytesServed != wantBytes || completed != wantCompleted {
		t.Fatalf("audit = (%q, %d, %t), want (%q, %d, %t)", status, bytesServed, completed, wantStatus, wantBytes, wantCompleted)
	}
}

func assertNoAudit(t *testing.T, pool *pgxpool.Pool, requestID string) {
	t.Helper()
	var count int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM artifact_fetch_requests WHERE request_id = $1`, requestID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("artifact fetch audit count = %d, want 0", count)
	}
}
