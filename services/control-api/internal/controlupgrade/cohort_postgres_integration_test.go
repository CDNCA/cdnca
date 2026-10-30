package controlupgrade

import (
	"crypto/sha256"
	"errors"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestLoadRolloutTargetCohortPostgres(t *testing.T) {
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	admin, err := pgxpool.New(t.Context(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := pgx.Identifier{"control_upgrade_cohort_" + strings.ReplaceAll(uuid.NewString(), "-", "")}.Sanitize()
	if _, err := admin.Exec(t.Context(), "CREATE SCHEMA "+schema); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	var pool *pgxpool.Pool
	t.Cleanup(func() {
		if pool != nil {
			pool.Close()
		}
		ctx, cancel := databasetest.CleanupContext()
		defer cancel()
		if _, err := admin.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE"); err != nil {
			t.Errorf("drop cohort schema: %v", err)
		}
		admin.Close()
	})
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	config.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	pool, err = pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Migrate(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	pool.Close()
	config.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeCacheStatement
	pool, err = pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(t.Context(), sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	actor := Actor{ScopeID: uuid.New(), UserID: uuid.New(), ScopeKind: "platform"}
	if err := pool.QueryRow(t.Context(), "SELECT id FROM access_scopes WHERE kind='platform'").Scan(&actor.ScopeID); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal(err)
	}
	roleID := uuid.New()
	exec(`INSERT INTO access_scopes(id,kind) VALUES($1,'platform') ON CONFLICT(id) DO NOTHING`, actor.ScopeID)
	exec(`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'Cohort operator','test-only')`, actor.UserID, actor.UserID.String())
	exec(`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, actor.ScopeID, actor.UserID)
	exec(`INSERT INTO roles(id,scope_id,name,system_role) VALUES($1,$2,'platform_owner',true)`, roleID, actor.ScopeID)
	exec(`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, actor.ScopeID, actor.UserID, roleID)
	var now time.Time
	if err := pool.QueryRow(t.Context(), "SELECT transaction_timestamp()").Scan(&now); err != nil {
		t.Fatal(err)
	}
	displayID := 0
	seed := func(fact rolloutNodeCapabilityFact, authorized bool) string {
		t.Helper()
		nodeID := uuid.MustParse(fact.NodeID)
		displayID++
		exec(`INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id) VALUES($1,$2,$3,'active',$4,$5)`, nodeID, actor.ScopeID, nodeID.String(), actor.UserID, displayID)
		exec(`INSERT INTO node_presence(node_id,status,session_epoch,heartbeat_sequence,event_id,request_id,
			payload_digest,occurred_at,projected_at,last_seen_at,confirmed_session_epoch,confirmed_heartbeat_sequence,
			confirmed_event_id,confirmed_request_id,confirmed_payload_digest,online_since,openresty_state,firewall_state,
			filesystem_total_bytes,filesystem_available_bytes,cache_used_bytes,updated_at,confirmed_agent_version)
			VALUES($1,'online',1,1,$2,$3,$4,$5,$5,$5,1,1,$2,$3,$4,$5,'running','running',1024,512,0,$5,$6)`,
			nodeID, uuid.New(), uuid.New(), fact.CapabilitySHA256, now, fact.PresenceVersion)
		if !authorized {
			return fact.NodeID
		}
		tokenID, authorityID, certificateID := uuid.New(), uuid.New(), uuid.New()
		digest := sha256.Sum256([]byte(nodeID.String()))
		exec(`INSERT INTO node_enrollment_tokens(id,node_id,purpose,token_hash,created_by_user_id,created_at,expires_at)
			VALUES($1,$2,'initial_enrollment',$3,$4,$5,$6)`, tokenID, nodeID, digest[:], actor.UserID, now.Add(-time.Minute), now.Add(time.Hour))
		exec(`INSERT INTO node_enrollment_authorizations(id,token_id,node_id,purpose,request_id,request_digest,authorized_at)
			VALUES($1,$2,$3,'initial_enrollment',$4,$5,$6)`, authorityID, tokenID, nodeID, authorityID.String(), digest[:], now.Add(-time.Minute))
		exec(`INSERT INTO node_identity_authorizations(id,token_id,node_id,purpose,request_id,request_digest,token_hash,
			csr_der,csr_sha256,machine_fingerprint_sha256,protocol_min_major,protocol_min_minor,protocol_max_major,
			protocol_max_minor,selected_protocol_major,selected_protocol_minor,capabilities_snapshot,capabilities_sha256,
			gateway_workload_identity,gateway_instance_id,artifact_key_id,artifact_public_key,status,authorized_at,expires_at,
			signing_attempt,signing_lease_id,signing_lease_expires_at)
			VALUES($1,$2,$3,'initial_enrollment',$1,$4,$4,'test',$4,$4,1,0,3,0,$5,0,$6,$7,
			'spiffe://cdn-platform/gateway/test','test','test-key',$4,'signing',$8,$9,1,$10,$9)`,
			authorityID, tokenID, nodeID, digest[:], fact.ProtocolVersion, fact.CapabilityBytes, fact.CapabilitySHA256,
			now.Add(-time.Minute), now.Add(time.Hour), uuid.New())
		exec(`INSERT INTO node_certificates(id,node_id,issuance_kind,enrollment_authorization_id,serial_number,
			csr_sha256,certificate_public_key_sha256,uri_san,not_before,not_after,renewal_at,leaf_certificate_pem,
			issuing_chain_pem,leaf_certificate_sha256,status,issued_at)
			VALUES($1,$2,'initial',$3,$4,$5,$5,$6,$7,$8,$9,'test',ARRAY['test'::bytea],$5,'active',$7)`,
			certificateID, nodeID, authorityID, strings.ReplaceAll(certificateID.String(), "-", ""), digest[:],
			"spiffe://cdn-platform/node/"+nodeID.String(), now.Add(-time.Minute), now.Add(time.Hour), now.Add(30*time.Minute))
		exec(`UPDATE node_identity_authorizations SET status='issued',issued_certificate_id=$2,completed_at=$3,
			signing_lease_id=NULL,signing_lease_expires_at=NULL WHERE id=$1`, authorityID, certificateID, now)
		return fact.NodeID
	}
	newFact := func() rolloutNodeCapabilityFact {
		return rolloutCapabilityFact(t, uuid.NewString(), "1.4.0", "linux", "amd64", 2)
	}
	store := NewStore(pool, nil, nil, nil)
	first, second := seed(newFact(), true), seed(newFact(), true)
	ids := []string{first, second}
	sort.Strings(ids)
	t.Run("legacy enrollment alone cannot authorize upgrades", func(t *testing.T) {
		cohort, err := store.LoadRolloutTargetCohort(t.Context(), actor, ids)
		if !errors.Is(err, ErrCohortIncompatible) || len(cohort.Targets) != 0 {
			t.Fatalf("enrollment-only cohort must remain unknown: cohort=%+v error=%v", cohort, err)
		}
	})
	for _, test := range []struct {
		name       string
		fact       rolloutNodeCapabilityFact
		authorized bool
	}{
		{"missing authority", newFact(), false},
		{"missing upgrade capability", rolloutCapabilityFactWithFeatures(t, uuid.NewString(), "1.4.0", "linux", "amd64", 2, []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_HTTP_1_1, ApiVersion: 1}}), true},
		{"mixed architecture", rolloutCapabilityFact(t, uuid.NewString(), "1.4.0", "linux", "arm64", 2), true},
		{"mixed protocol", rolloutCapabilityFact(t, uuid.NewString(), "1.4.0", "linux", "amd64", 1), true},
		{"mixed version", rolloutCapabilityFact(t, uuid.NewString(), "1.5.0", "linux", "amd64", 2), true},
	} {
		t.Run(test.name, func(t *testing.T) {
			targets := []string{first, seed(test.fact, test.authorized)}
			sort.Strings(targets)
			if _, err := store.LoadRolloutTargetCohort(t.Context(), actor, targets); !errors.Is(err, ErrCohortIncompatible) {
				t.Fatalf("incompatible cohort must fail closed: %v", err)
			}
		})
	}
	t.Run("missing node", func(t *testing.T) {
		if _, err := store.LoadRolloutTargetCohort(t.Context(), actor, []string{uuid.NewString()}); !errors.Is(err, ErrNodeNotFound) {
			t.Fatalf("missing node: %v", err)
		}
	})
	t.Run("permission revoked", func(t *testing.T) {
		exec(`DELETE FROM role_assignments WHERE role_id=$1`, roleID)
		if _, err := store.LoadRolloutTargetCohort(t.Context(), actor, ids); !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("revoked permission: %v", err)
		}
	})
}
