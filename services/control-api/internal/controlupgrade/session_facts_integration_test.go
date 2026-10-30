//go:build integration

package controlupgrade

import (
	"crypto/sha256"
	"encoding/pem"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish/capabilitytest"
	"github.com/cdnca/cdnca/services/control-api/internal/nodeidentity"
	"github.com/cdnca/cdnca/services/control-api/internal/nodepresence"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestSessionFactsUpgradeReadersPostgres(t *testing.T) {
	connection := os.Getenv("TEST_DATABASE_URL")
	if connection == "" {
		t.Skip("TEST_DATABASE_URL is required")
	}
	admin, err := pgxpool.New(t.Context(), connection)
	if err != nil {
		t.Fatal(err)
	}
	schema := "session_upgrade_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(t.Context(), "CREATE SCHEMA "+quoted); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	cfg, err := pgxpool.ParseConfig(connection)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	cfg.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		ctx, cancel := databasetest.CleanupContext()
		defer cancel()
		if _, err := admin.Exec(ctx, "DROP SCHEMA "+quoted+" CASCADE"); err != nil {
			t.Error(err)
		}
		admin.Close()
	})
	if err := database.Migrate(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	pool.Close()
	cfg.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeCacheStatement
	pool, err = pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(t.Context(), sql, append([]any{pgx.QueryExecModeSimpleProtocol}, args...)...); err != nil {
			t.Fatal(err)
		}
	}
	actor := Actor{UserID: uuid.New(), ScopeKind: "platform"}
	nodeID := uuid.New()
	role := uuid.New()
	if err := pool.QueryRow(t.Context(), `SELECT id FROM access_scopes WHERE kind='platform'`).Scan(&actor.ScopeID); errors.Is(err, pgx.ErrNoRows) {
		actor.ScopeID = uuid.New()
		exec(`INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, actor.ScopeID)
	} else if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	exec(`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'Session reader test','test-only'); INSERT INTO memberships(scope_id,user_id) VALUES($3,$1); INSERT INTO roles(id,scope_id,name,system_role) VALUES($4,$3,'platform_owner',true); INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($3,$1,$4); INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id,created_at,updated_at) VALUES($5,$3,'session reader node','pending',$1,1,$6,$6)`, actor.UserID, actor.UserID.String(), actor.ScopeID, role, nodeID, now.Add(-7*time.Minute))
	enrolledCaps := &agentv1.AgentCapabilities{AgentVersion: "1.0.22", BuildId: "build", OperatingSystem: "linux", Architecture: "amd64", Features: []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_HTTP_1_1, ApiVersion: 1}}}
	identity := capabilitytest.SeedNodePublicationIdentityForTest(t, pool, actor.ScopeID, actor.UserID, nodeID, enrolledCaps, now.Add(-6*time.Minute), true)
	identity.Clock = now
	leaf, _ := pem.Decode(identity.Completion.Certificate.LeafCertificatePEM)
	certSHA := sha256.Sum256(leaf.Bytes)
	capabilities := proto.Clone(enrolledCaps).(*agentv1.AgentCapabilities)
	capabilities.Features = append(capabilities.Features, &agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE, ApiVersion: 1})
	facts := &controlv1.GatewaySessionFactsV1{SchemaVersion: 1, NodeId: nodeID.String(), SessionEpoch: 1, CertificateSha256: certSHA[:], SelectedProtocolVersion: &commonv1.ProtocolVersion{Major: 1}, ArtifactEncryptionKeyId: identity.Completion.ArtifactEncryptionKeyID, Capabilities: capabilities}
	request := nodeidentity.GetAuthorizationRequest{NodeID: nodeID, CertificateSerialNumber: identity.Completion.Certificate.SerialNumber, CertificateSHA256: certSHA, GatewayWorkloadIdentity: "spiffe://cdn-platform/gateway/capability-test", GatewayInstanceID: uuid.NewString(), SessionFacts: facts}
	presence, err := nodepresence.NewStore(pool, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	heartbeat := func(epoch uint64, confirm bool) {
		t.Helper()
		version := "1.0.22"
		beat := &agentv1.Heartbeat{Event: &commonv1.EventMetadata{EventId: uuid.NewString(), RequestId: uuid.NewString(), OccurredTime: timestamppb.Now()}, SessionEpoch: epoch, HeartbeatSequence: 1, AgentVersion: &version, Runtime: &agentv1.EdgeRuntimeStatus{OpenrestyState: agentv1.RuntimeState_RUNTIME_STATE_STOPPED, FirewallState: agentv1.RuntimeState_RUNTIME_STATE_RUNNING}, Resources: &agentv1.ResourceUsage{FilesystemTotalBytes: 1024, FilesystemAvailableBytes: 512}}
		encoded, _ := (proto.MarshalOptions{Deterministic: true}).Marshal(beat)
		projection, err := presence.Project(t.Context(), nodepresence.Envelope{NodeID: nodeID, Heartbeat: beat, Digest: sha256.Sum256(encoded)})
		if err != nil {
			t.Fatal(err)
		}
		if confirm {
			if ok, err := presence.ConfirmOnline(t.Context(), projection); err != nil {
				t.Fatalf("confirm heartbeat %v %v", ok, err)
			}
		}
	}
	heartbeat(1, true)
	store := NewStore(pool, nil, nil, nil)
	ids := []string{nodeID.String()}
	check := func(t *testing.T, allowed bool) {
		t.Helper()
		_, err := store.LoadRolloutTargetCohort(t.Context(), actor, ids)
		if allowed && err != nil || !allowed && !errors.Is(err, ErrCohortIncompatible) {
			t.Fatalf("preflight allowed=%v err=%v", allowed, err)
		}
		err = pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
			_, err := loadRolloutTargetCohortTx(t.Context(), tx, actor.ScopeID, ids)
			if allowed && err != nil || !allowed && !errors.Is(err, ErrCohortIncompatible) {
				t.Fatalf("finalize allowed=%v err=%v", allowed, err)
			}
			rows, err := readMaintenanceNodeFacts(t.Context(), tx, actor, ids, time.Now(), time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			if len(rows) != 1 || (rows[0].Status.Reason == "") != allowed {
				t.Fatalf("maintenance allowed=%v facts=%+v", allowed, rows)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Run("enrollment-only-is-unknown", func(t *testing.T) { check(t, false) })
	t.Run("connect-after-five-minutes", func(t *testing.T) {
		if _, err := identity.Service.GetAuthorization(t.Context(), request); err != nil {
			t.Fatal(err)
		}
		check(t, true)
	})
	t.Run("higher-registration-needs-confirmed-heartbeat", func(t *testing.T) {
		facts.SessionEpoch = 2
		if _, err := identity.Service.GetAuthorization(t.Context(), request); err != nil {
			t.Fatal(err)
		}
		check(t, false)
		heartbeat(2, true)
		check(t, true)
	})
	t.Run("unregistered-new-heartbeat-cannot-reuse-old-facts", func(t *testing.T) {
		heartbeat(3, true)
		check(t, false)
		facts.SessionEpoch = 3
		if _, err := identity.Service.GetAuthorization(t.Context(), request); err != nil {
			t.Fatal(err)
		}
		check(t, true)
	})
	t.Run("unconfirmed-heartbeat-cannot-reuse-confirmed-epoch", func(t *testing.T) {
		heartbeat(4, false)
		check(t, false)
		facts.SessionEpoch = 4
		if _, err := identity.Service.GetAuthorization(t.Context(), request); err != nil {
			t.Fatal(err)
		}
		check(t, false)
	})
	t.Run("tenant-actor-denied", func(t *testing.T) {
		tenant := actor
		tenant.ScopeKind = "tenant"
		if _, err := store.LoadRolloutTargetCohort(t.Context(), tenant, ids); !errors.Is(err, ErrInvalidInput) {
			t.Fatal(err)
		}
	})
	t.Run("reconnect-then-revoke", func(t *testing.T) {
		facts.SessionEpoch = 5
		if _, err := identity.Service.GetAuthorization(t.Context(), request); err != nil {
			t.Fatal(err)
		}
		heartbeat(5, true)
		check(t, true)
		if err := identity.Service.Revoke(t.Context(), nodeidentity.RevokeRequest{RequestID: uuid.NewString(), NodeID: nodeID, SerialNumber: identity.Completion.Certificate.SerialNumber, Reason: "session reader test"}); err != nil {
			t.Fatal(err)
		}
		check(t, false)
	})
}
