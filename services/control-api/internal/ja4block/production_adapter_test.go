package ja4block

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/nodescheduler"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestProductionTargetResolverRequiresExactHealthyImmutableAuthority(t *testing.T) {
	now := time.Date(2026, 8, 8, 10, 0, 0, 0, time.UTC)
	tenantID, siteID, policyID := uuid.New(), uuid.New(), uuid.New()
	nodes := canonicalNodes([]uuid.UUID{uuid.New(), uuid.New()})
	digest := nodescheduler.CanonicalNodeSetDigest(nodes)
	document, err := json.Marshal(map[string]any{
		"tenant_scope_id": tenantID, "site_id": siteID, "authority_ready": true,
		"target_snapshot_id": uuid.New(), "target_snapshot_revision": 3,
		"target_snapshot_sha256": digest, "target_nodes": nodes,
		"binding_revision": 7, "active_policy_version": 4,
		"current_policy": securitypolicy.Policy{ID: policyID, ScopeID: tenantID, Kind: securitypolicy.KindWAF,
			Name: "JA4 automatic blocks", Enabled: true, DefaultAction: securitypolicy.ActionAllow, Revision: 4},
	})
	if err != nil {
		t.Fatal(err)
	}
	database := &productionAdapterDB{rows: []pgx.Row{adapterRow{values: []any{document}}}}
	resolver, err := newPostgresPublicationTargetResolver(database, func() time.Time { return now }, 45*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	target, err := resolver.LoadPublicationTarget(t.Context(), tenantID, siteID)
	if err != nil || target.TenantScopeID != tenantID || target.SiteID != siteID ||
		target.ExpectedBindingRevision != 7 || target.ExpectedActiveVersion != 4 ||
		target.CurrentPolicy == nil || target.CurrentPolicy.ID != policyID || !reflect.DeepEqual(target.TargetNodeIDs, nodes) {
		t.Fatalf("LoadPublicationTarget() = (%#v,%v)", target, err)
	}
	if len(database.queries) != 1 || !strings.Contains(database.queries[0], "edge_target_snapshots") ||
		!strings.Contains(database.queries[0], "node_presence") ||
		!strings.Contains(database.queries[0], "security_policy_site_bindings") ||
		!strings.Contains(database.queries[0], "security_policy_versions") {
		t.Fatalf("target authority query is not atomic/exact: %q", database.queries)
	}
	// sec-followup: a site following its package (node_group_id NULL) takes
	// the package's primary line group, not "no target".
	if !strings.Contains(database.queries[0], "COALESCE(site.node_group_id,(subscription.product_snapshot->'spec'->>'node_group_id')::uuid)") {
		t.Fatalf("target authority ignores package-following sites: %q", database.queries[0])
	}

	invalid := map[string]func(map[string]any){
		"unhealthy":       func(value map[string]any) { value["authority_ready"] = false },
		"cross tenant":    func(value map[string]any) { value["tenant_scope_id"] = uuid.New() },
		"digest mismatch": func(value map[string]any) { value["target_snapshot_sha256"] = [32]byte{1} },
	}
	for name, mutate := range invalid {
		t.Run(name, func(t *testing.T) {
			var value map[string]any
			if err := json.Unmarshal(document, &value); err != nil {
				t.Fatal(err)
			}
			mutate(value)
			encoded, _ := json.Marshal(value)
			query := &productionAdapterDB{rows: []pgx.Row{adapterRow{values: []any{encoded}}}}
			candidate, _ := newPostgresPublicationTargetResolver(query, func() time.Time { return now }, 45*time.Second)
			if _, err := candidate.LoadPublicationTarget(t.Context(), tenantID, siteID); !errors.Is(err, ErrDependencyUnavailable) {
				t.Fatalf("LoadPublicationTarget() error=%v", err)
			}
		})
	}
}

func TestPostgresEdgeReceiptQueueClaimsWithLeaseFencingAndExactIdentity(t *testing.T) {
	now := time.Date(2026, 8, 8, 10, 0, 0, 0, time.UTC)
	actor := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform", SessionID: uuid.New()}
	receipt := exactReceiptFixture(now, uuid.New())
	receipt.NodeID, receipt.ConfigSHA256, receipt.ReceiptSHA256 = uuid.New(), [32]byte{1}, [32]byte{2}
	token := uuid.New()
	database := &productionAdapterDB{rows: []pgx.Row{adapterRow{values: []any{
		token, receipt.ReceiptID, receipt.TenantScopeID, receipt.SiteID, receipt.WorkflowID,
		receipt.PolicyID, receipt.PolicyRevision, receipt.BindingID, receipt.BindingRevision,
		receipt.PublicationID, receipt.RolloutID, receipt.NodeID, receipt.ConfigSHA256[:], receipt.ReceiptSHA256[:],
		receipt.ExpectedRevision, receipt.ActivePolicyRevision, receipt.State, receipt.ReasonCode, receipt.ObservedAt,
		actor.UserID, actor.ScopeID, actor.ScopeKind, actor.SessionID,
	}}}, tags: []pgconn.CommandTag{
		pgconn.NewCommandTag("UPDATE 1"), pgconn.NewCommandTag("UPDATE 1"), pgconn.NewCommandTag("UPDATE 1"),
	}}
	queue, err := newPostgresEdgeReceiptQueue(database)
	if err != nil {
		t.Fatal(err)
	}
	claim, found, err := queue.Claim(t.Context(), "ja4-edge-1", now, 30*time.Second)
	if err != nil || !found || claim.Token != token || claim.Actor != actor || claim.Receipt != receipt {
		t.Fatalf("Claim() = (%#v,%v,%v)", claim, found, err)
	}
	if len(database.queries) != 1 || !strings.Contains(database.queries[0], "FOR UPDATE SKIP LOCKED") ||
		!strings.Contains(database.queries[0], "claim_expires_at<=$1") {
		t.Fatalf("claim is not lease-fenced: %q", database.queries)
	}
	if err := queue.Complete(t.Context(), claim); err != nil {
		t.Fatal(err)
	}
	if err := queue.Retry(t.Context(), claim, "store_unavailable", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := queue.Reject(t.Context(), claim, "receipt_mismatch"); err != nil {
		t.Fatal(err)
	}
	for _, statement := range database.execs {
		if !strings.Contains(statement, "claim_token=$") {
			t.Fatalf("settlement is not claim-token fenced: %q", statement)
		}
	}

	lost := &productionAdapterDB{tags: []pgconn.CommandTag{pgconn.NewCommandTag("UPDATE 0")}}
	lostQueue, _ := newPostgresEdgeReceiptQueue(lost)
	if err := lostQueue.Complete(t.Context(), claim); !errors.Is(err, ErrClaimLost) {
		t.Fatalf("Complete(lost claim) error=%v", err)
	}
}

type productionAdapterDB struct {
	rows    []pgx.Row
	tags    []pgconn.CommandTag
	queries []string
	execs   []string
}

func (database *productionAdapterDB) QueryRow(_ context.Context, query string, _ ...any) pgx.Row {
	database.queries = append(database.queries, query)
	if len(database.rows) == 0 {
		return adapterRow{err: pgx.ErrNoRows}
	}
	row := database.rows[0]
	database.rows = database.rows[1:]
	return row
}

func (database *productionAdapterDB) Exec(_ context.Context, query string, _ ...any) (pgconn.CommandTag, error) {
	database.execs = append(database.execs, query)
	if len(database.tags) == 0 {
		return pgconn.NewCommandTag("UPDATE 0"), nil
	}
	tag := database.tags[0]
	database.tags = database.tags[1:]
	return tag, nil
}

type adapterRow struct {
	values []any
	err    error
}

func (row adapterRow) Scan(destinations ...any) error {
	if row.err != nil {
		return row.err
	}
	if len(destinations) != len(row.values) {
		return errors.New("adapter row destination mismatch")
	}
	for index := range destinations {
		destination := reflect.ValueOf(destinations[index])
		value := reflect.ValueOf(row.values[index])
		if destination.Kind() != reflect.Pointer || !value.IsValid() || !value.Type().AssignableTo(destination.Elem().Type()) {
			return errors.New("adapter row type mismatch")
		}
		destination.Elem().Set(value)
	}
	return nil
}
