//go:build integration

package nodegatewayaddr

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type integrationFixture struct {
	pool  *pgxpool.Pool
	store *Store
	actor Actor
	nodes map[string]uuid.UUID // name → id; regions hk, hk, sg
	now   time.Time
}

func newIntegrationFixture(t *testing.T) *integrationFixture {
	t.Helper()
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	pool := databasetest.ClonedMigratedPool(t, nil)
	if pool == nil {
		t.Skip("TEST_DATABASE_TEMPLATE is not set (run through scripts/control-api-integration-sharded.sh)")
	}
	f := &integrationFixture{pool: pool, nodes: map[string]uuid.UUID{"hk-1": uuid.New(), "hk-2": uuid.New(), "sg-1": uuid.New()},
		now: time.Date(2026, 10, 28, 3, 0, 0, 0, time.UTC)}
	f.store = NewStore(pool, func() time.Time { return f.now })
	user := uuid.New()
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		var failed error
		exec := func(sql string, args ...any) {
			if failed == nil {
				if _, err := tx.Exec(t.Context(), sql, args...); err != nil {
					failed = fmt.Errorf("%s: %w", strings.Fields(sql)[0:3], err)
				}
			}
		}
		exec(`SET LOCAL session_replication_role = replica`)
		exec(`INSERT INTO access_scopes(id,kind) SELECT gen_random_uuid(),'platform'
			WHERE NOT EXISTS (SELECT 1 FROM access_scopes WHERE kind='platform')`)
		exec(`INSERT INTO users(id,username,display_name,password_hash,created_at,updated_at)
			VALUES($1,$2,'ngw','x',now(),now())`, user, "ngw-"+user.String()[:8])
		for name, id := range f.nodes {
			exec(`INSERT INTO nodes(id,scope_id,name,region,admin_state,created_by_user_id,display_id)
				VALUES($1,(SELECT id FROM access_scopes WHERE kind='platform'),$2,$3,'active',$4,
				(SELECT COALESCE(max(display_id),0)+1 FROM nodes))`, id, name, name[:2], user)
		}
		if failed != nil {
			return failed
		}
		return tx.QueryRow(t.Context(), `SELECT id FROM access_scopes WHERE kind='platform'`).Scan(&f.actor.ScopeID)
	})
	if err != nil {
		t.Fatal(err)
	}
	f.actor.UserID, f.actor.RequestID = user, "ngw-test"
	return f
}

func (f *integrationFixture) auditCount(t *testing.T, action string) int {
	t.Helper()
	var count int
	if err := f.pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE action=$1`, action).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

// Create by region resolves only that region, audits once, and every node
// gets its own increasing revision; a later change supersedes the open row.
func TestStoreCreateByRegionSupersedesAndAudits(t *testing.T) {
	f := newIntegrationFixture(t)
	request, _ := CreateRequest{Address: "gateway.cdnca.com:9443", TargetKind: TargetRegion, Region: "hk"}.Normalize()
	first, err := f.store.Create(t.Context(), f.actor, request)
	if err != nil || first.NodeCount != 2 {
		t.Fatalf("create = %+v %v", first, err)
	}
	if f.auditCount(t, AuditCreate) != 1 {
		t.Fatal("create not audited")
	}
	all, _ := CreateRequest{Address: "gateway2.cdnca.com:9443", TargetKind: TargetAll}.Normalize()
	second, err := f.store.Create(t.Context(), f.actor, all)
	if err != nil || second.NodeCount != 3 {
		t.Fatalf("create all = %+v %v", second, err)
	}
	old, err := f.store.Get(t.Context(), f.actor.ScopeID, first.ID)
	if err != nil || old.Counts.Superseded != 2 {
		t.Fatalf("first after second = %+v %v", old.Counts, err)
	}
	var revision int64
	if err := f.pool.QueryRow(t.Context(), `SELECT revision FROM node_gateway_address_change_nodes WHERE change_id=$1 AND node_id=$2`,
		second.ID, f.nodes["hk-1"]).Scan(&revision); err != nil || revision != 2 {
		t.Fatalf("hk-1 revision = %d %v", revision, err)
	}
	if _, err := f.store.Create(t.Context(), f.actor, CreateRequest{Address: "g.cdnca.com:443", ServerName: "g.cdnca.com",
		TargetKind: TargetRegion, Region: "us"}); !errors.Is(err, ErrNoNodes) {
		t.Fatalf("empty region = %v", err)
	}
}

// Publish → probing → switched / failed, retry a failed node with a new
// revision; reports for other bytes or a stale revision are ignored; final
// outcomes are audited as node actions.
func TestStoreLifecycleReportAndRetry(t *testing.T) {
	f := newIntegrationFixture(t)
	request, _ := CreateRequest{Address: "gateway.cdnca.com:9443", TargetKind: TargetAll}.Normalize()
	change, err := f.store.Create(t.Context(), f.actor, request)
	if err != nil {
		t.Fatal(err)
	}
	_, private, _ := ed25519.GenerateKey(nil)
	distributor, err := NewDistributor(DistributorConfig{Store: f.store, Transport: &fakeTransport{}, KeyID: "edge-1",
		Sign:     func(_ context.Context, payload []byte) ([]byte, error) { return ed25519.Sign(private, payload), nil },
		Interval: time.Second, Now: func() time.Time { return f.now }})
	if err != nil {
		t.Fatal(err)
	}
	if err := distributor.PublishOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	transport := distributor.config.Transport.(*fakeTransport)
	digestOf := func(node string) []byte {
		value := sha256.Sum256(transport.sent[f.nodes[node].String()])
		return value[:]
	}
	report := func(node string, revision uint64, state, code string) {
		t.Helper()
		if _, err := f.store.Report(t.Context(), Report{NodeID: f.nodes[node], Revision: revision, DocumentSHA256: digestOf(node),
			State: state, ErrorCode: code, ActiveAddress: "old.cdnca.com:443"}); err != nil {
			t.Fatal(err)
		}
	}
	report("hk-1", 1, StateProbing, "")
	report("hk-1", 1, StateSwitched, "")
	report("hk-2", 1, StateFailed, "dial_failed")
	report("sg-1", 1, StateFailed, "not_supported")
	report("hk-1", 1, StateFailed, "dial_failed") // after switched: ignored
	report("sg-1", 9, StateSwitched, "")          // unknown revision: ignored
	got, err := f.store.Get(t.Context(), f.actor.ScopeID, change.ID)
	if err != nil || got.Counts.Switched != 1 || got.Counts.Failed != 2 || got.Counts.Complete() {
		t.Fatalf("counts = %+v %v", got.Counts, err)
	}
	if f.auditCount(t, AuditReport) != 3 {
		t.Fatal("final outcomes not audited once each")
	}
	retried, err := f.store.Retry(t.Context(), f.actor, change.ID, []uuid.UUID{f.nodes["hk-2"]})
	if err != nil || retried != 1 || f.auditCount(t, AuditRetry) != 1 {
		t.Fatalf("retry = %d %v", retried, err)
	}
	due, err := f.store.Due(t.Context(), f.now, 10)
	if err != nil || len(due) != 1 || due[0].NodeID != f.nodes["hk-2"] || due[0].Revision != 2 || due[0].Published != nil {
		t.Fatalf("due after retry = %+v %v", due, err)
	}
	if _, err := f.store.Retry(t.Context(), f.actor, change.ID, []uuid.UUID{f.nodes["hk-1"]}); !errors.Is(err, ErrNothingToRetry) {
		t.Fatalf("retry switched = %v", err)
	}
	if _, err := f.store.Retry(t.Context(), Actor{ScopeID: uuid.New(), UserID: f.actor.UserID}, change.ID, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("other scope = %v", err)
	}
}

// A delivered document unanswered for its whole lifetime fails as undelivered.
func TestStoreUndeliveredExpires(t *testing.T) {
	f := newIntegrationFixture(t)
	request, _ := CreateRequest{Address: "gateway.cdnca.com:9443", TargetKind: TargetNodes, NodeIDs: []uuid.UUID{f.nodes["sg-1"]}}.Normalize()
	change, err := f.store.Create(t.Context(), f.actor, request)
	if err != nil {
		t.Fatal(err)
	}
	_, private, _ := ed25519.GenerateKey(nil)
	distributor, _ := NewDistributor(DistributorConfig{Store: f.store, Transport: &fakeTransport{}, KeyID: "edge-1",
		Sign:     func(_ context.Context, payload []byte) ([]byte, error) { return ed25519.Sign(private, payload), nil },
		Interval: time.Second, Now: func() time.Time { return f.now }})
	if err := distributor.PublishOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(DocumentLifetime + time.Minute)
	if err := distributor.PublishOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	got, _ := f.store.Get(t.Context(), f.actor.ScopeID, change.ID)
	if len(got.Nodes) != 1 || got.Nodes[0].State != StateFailed || got.Nodes[0].ErrorCode != ErrorUndelivered {
		t.Fatalf("nodes = %+v", got.Nodes)
	}
}
