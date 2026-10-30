//go:build integration

package acmehttp01

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ADR-0003 (migration 342): epochs, cleanup debt, serving gate, cleanup_only,
// 063 backfill.

// hold takes the node out of (or back into) the site candidate set like the
// availability monitor does.
func (f *nodeFixture) hold(t *testing.T, node uuid.UUID, held bool) {
	t.Helper()
	seedTx(t, f.pool, func(exec func(string, ...any)) {
		exec(`INSERT INTO node_serving_holds(node_id,source,held,reason_code,revision,held_since,changed_at,updated_at)
			VALUES($1,'availability_monitor',$2,'probe_unhealthy',1,CASE WHEN $2 THEN now() END,now(),now())
			ON CONFLICT (node_id,source) DO UPDATE SET held=$2,held_since=CASE WHEN $2 THEN now() END,
			    revision=node_serving_holds.revision+1,changed_at=now(),updated_at=now()`, node, held)
	})
}

func (f *nodeFixture) setAdmin(t *testing.T, node uuid.UUID, state string) {
	t.Helper()
	seedTx(t, f.pool, func(exec func(string, ...any)) {
		exec(`UPDATE nodes SET admin_state=$2 WHERE id=$1`, node, state)
	})
}

// addNode adds a capable node to the fixture's line group.
func (f *nodeFixture) addNode(t *testing.T) uuid.UUID {
	t.Helper()
	node := uuid.New()
	f.nodes = append(f.nodes, node)
	snapshot, _ := proto.Marshal(&agentv1.AgentCapabilities{Features: []*agentv1.Capability{
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_ACME_HTTP01_OVERLAY, ApiVersion: 1}}})
	digest := sha256.Sum256(snapshot)
	seedTx(t, f.pool, func(exec func(string, ...any)) {
		exec(`INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id)
			VALUES($1,(SELECT id FROM access_scopes WHERE kind='platform'),$2,'active',$3,
			(SELECT COALESCE(max(display_id),0)+1 FROM nodes))`, node, "http01-"+node.String()[:8], f.user)
		exec(`INSERT INTO node_line_endpoints(id,node_id,tenant_scope_id,line_group_id,config_revision,address,
			address_family,port,region,carrier,priority,weight,enabled)
			VALUES(gen_random_uuid(),$1,(SELECT id FROM access_scopes WHERE kind='platform'),$2,1,$3::inet,4,80,'cn','BGP',0,1,true)`,
			node, f.group, fmt.Sprintf("198.51.100.%d", len(f.nodes)))
		exec(`INSERT INTO node_session_capabilities(node_id,session_epoch,certificate_id,certificate_sha256,
			artifact_key_id,selected_protocol_major,selected_protocol_minor,capabilities_snapshot,capabilities_sha256,
			facts_snapshot,facts_sha256,gateway_workload_identity,gateway_instance_id,registered_at)
			VALUES($1,1,gen_random_uuid(),$2,'k',1,0,$3,$2,'\x00',$2,'gw','gw-1',now())`, node, digest[:], snapshot)
	})
	return node
}

// gate is acme_http01_site_node_serving_blocked ("" when the node may serve).
func (f *nodeFixture) gate(t *testing.T, domain string, node uuid.UUID) string {
	t.Helper()
	var reason *string
	if err := f.pool.QueryRow(t.Context(), `SELECT acme_http01_site_node_serving_blocked($1,$2,$3)`,
		f.scope, f.sites[domain], node).Scan(&reason); err != nil {
		t.Fatal(err)
	}
	if reason == nil {
		return ""
	}
	return *reason
}

// debtEvents lists the events of the node's debts for the site, oldest first.
func (f *nodeFixture) debtEvents(t *testing.T, domain string, node uuid.UUID) []string {
	t.Helper()
	rows, err := f.pool.Query(t.Context(), `SELECT event.event || COALESCE(':'||event.reason,'')
		FROM acme_http01_node_overlay_cleanup_debt_events event
		JOIN acme_http01_node_overlay_cleanup_debts debt ON debt.id=event.debt_id
		WHERE debt.tenant_scope_id=$1 AND debt.site_id=$2 AND debt.node_id=$3
		ORDER BY debt.opened_at,debt.id,event.sequence`, f.scope, f.sites[domain], node)
	if err != nil {
		t.Fatal(err)
	}
	events, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	return events
}

func (f *nodeFixture) reconcile(t *testing.T) NodeReconcileResult {
	t.Helper()
	result, err := f.store.Reconcile(t.Context(), 100)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

// healthyAll delivers every pending attempt and reports it healthy.
func (f *nodeFixture) healthyAll(t *testing.T) map[uuid.UUID]NodeDelivery {
	t.Helper()
	deliveries := f.deliver(t)
	for _, delivery := range deliveries {
		f.receipt(t, delivery, "healthy", "")
	}
	return deliveries
}

func (f *nodeFixture) currentCoverage(t *testing.T, node uuid.UUID) []string {
	t.Helper()
	rows, err := f.pool.Query(t.Context(), `SELECT coverage.coverage_kind||':'||site.domain
		FROM acme_http01_node_overlay_states state
		JOIN acme_http01_node_overlay_generation_coverages coverage ON coverage.generation_id=state.current_generation_id
		JOIN sites site ON site.id=coverage.site_id
		WHERE state.node_id=$1 ORDER BY site.domain`, node)
	if err != nil {
		t.Fatal(err)
	}
	coverage, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	return coverage
}

func (f *nodeFixture) currentVersionHealthy(t *testing.T, domain string) bool {
	t.Helper()
	var healthy bool
	if err := f.pool.QueryRow(t.Context(), `SELECT acme_http01_site_version_healthy(current_version_id)
		FROM acme_http01_site_overlay_states WHERE tenant_scope_id=$1 AND site_id=$2`,
		f.scope, f.sites[domain]).Scan(&healthy); err != nil {
		t.Fatal(err)
	}
	return healthy
}

func wantCode(t *testing.T, name string, err error, prefix string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || !strings.HasPrefix(pgErr.Code, prefix) {
		t.Errorf("%s: want SQLSTATE %s*, got %v", name, prefix, err)
	}
}

func equalStrings(got []string, want ...string) bool {
	return strings.Join(got, ",") == strings.Join(want, ",")
}

// A member that leaves the site's serving set mid-epoch owes a cleanup debt:
// it is released (no longer blocks the issuance), gets a zero-token
// cleanup_debt coverage, and stays out of the site's DNS until a healthy
// generation proves the cleanup and the epoch closes. The final empty
// cleanup is healthy only because every member left with a durable debt.
func TestNodeHTTP01RemovedNodeDebtLifecycle(t *testing.T) {
	f := newNodeFixture(t, true, true, true)
	n0, n1, n2 := f.nodes[0], f.nodes[1], f.nodes[2]
	a := f.challenge(t, "a.example.test")
	if err := f.store.PublishChallenge(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	f.healthyAll(t)
	if !f.currentVersionHealthy(t, "a.example.test") || f.gate(t, "a.example.test", n2) != "" {
		t.Fatal("version not healthy or member gated before removal")
	}
	f.hold(t, n2, true)
	f.reconcile(t)
	if got := f.debtEvents(t, "a.example.test", n2); !equalStrings(got, "opened:member_removed", "scheduled") {
		t.Fatalf("debt events %v", got)
	}
	if got := f.gate(t, "a.example.test", n2); got != "cleanup_debt" {
		t.Fatalf("gate %q", got)
	}
	if got := f.currentCoverage(t, n2); !equalStrings(got, "cleanup_debt:a.example.test") {
		t.Fatalf("n2 coverage %v", got)
	}
	if got := f.servedTokens(t, n2, false); len(got) != 0 {
		t.Fatalf("cleanup generation carries %v", got)
	}
	status := f.status(t, a)
	if len(status.Released) != 1 || status.Released[0] != n2 || len(status.Confirmed) != 2 || len(status.Pending) != 0 {
		t.Fatalf("status %+v", status)
	}
	provider, _ := NewNodeProvider(f.store, time.Millisecond, 0, nil)
	if err := provider.Publish(t.Context(), a); err != nil {
		t.Fatalf("released node blocked the issuance: %v", err)
	}
	// The cleanup is pending while n2 is away: the other members keep
	// serving and the debt delivery does not touch them.
	if got := f.deliver(t); len(got) != 1 {
		t.Fatalf("deliveries %v", got)
	} else {
		f.receipt(t, got[n2], "healthy", "")
	}
	if got := f.debtEvents(t, "a.example.test", n2); !equalStrings(got, "opened:member_removed", "scheduled", "resolved_cleanup") {
		t.Fatalf("debt events after cleanup %v", got)
	}
	// Debt cleared, but n2 rejoining mid-epoch would serve without the
	// epoch's tokens.
	f.hold(t, n2, false)
	if got := f.gate(t, "a.example.test", n2); got != "epoch_not_member" {
		t.Fatalf("gate after cleanup %q", got)
	}
	f.reconcile(t)
	if status := f.status(t, a); len(status.Released) != 1 {
		t.Fatalf("a re-active node rejoined the frozen epoch: %+v", status)
	}
	if err := f.store.WithdrawChallenge(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	for _, node := range []uuid.UUID{n0, n1} {
		if got := f.debtEvents(t, "a.example.test", node); !equalStrings(got, "opened:site_emptied", "scheduled") {
			t.Fatalf("node %s events %v", node, got)
		}
		if got := f.gate(t, "a.example.test", node); got != "" {
			t.Fatalf("site_emptied debt gated %s: %q", node, got)
		}
	}
	if got := f.gate(t, "a.example.test", n2); got != "" {
		t.Fatalf("closed epoch still gates n2: %q", got)
	}
	if !f.currentVersionHealthy(t, "a.example.test") {
		t.Fatal("final empty cleanup with every member owing a durable debt is not healthy")
	}
	f.healthyAll(t)
	for _, node := range []uuid.UUID{n0, n1} {
		if got := f.debtEvents(t, "a.example.test", node); !equalStrings(got, "opened:site_emptied", "scheduled", "resolved_cleanup") {
			t.Fatalf("node %s events after cleanup %v", node, got)
		}
	}
}

// A node that went offline across several generations keeps one debt with
// its earliest source; it is only cleared once it is required again in a new
// epoch and a healthy generation exactly covers the current version
// (resolved_required); becoming active alone never clears it.
func TestNodeHTTP01DebtSpansGenerationsUntilRequired(t *testing.T) {
	f := newNodeFixture(t, true, true)
	n1 := f.nodes[1]
	first := f.challenge(t, "a.example.test")
	if err := f.store.PublishChallenge(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	f.healthyAll(t)
	var earliest uuid.UUID
	if err := f.pool.QueryRow(t.Context(), `SELECT current_version_id FROM acme_http01_site_overlay_states
		WHERE site_id=$1`, f.sites["a.example.test"]).Scan(&earliest); err != nil {
		t.Fatal(err)
	}
	f.hold(t, n1, true)
	f.reconcile(t)
	// More tokens for a (g2, g3 on the remaining node) while n1 is away.
	for range 2 {
		f.clock.Advance(time.Second)
		if err := f.store.PublishChallenge(t.Context(), f.challenge(t, "a.example.test")); err != nil {
			t.Fatal(err)
		}
	}
	var debts int
	var source uuid.UUID
	if err := f.pool.QueryRow(t.Context(), `SELECT count(*),min(earliest_uncovered_site_version_id::text)::uuid
		FROM acme_http01_node_overlay_cleanup_debts WHERE node_id=$1`, n1).Scan(&debts, &source); err != nil ||
		debts != 1 || source != earliest {
		t.Fatalf("debts %d source %s (want %s) %v", debts, source, earliest, err)
	}
	// n1 comes back: active again, still owing a; withdrawing everything
	// closes the epoch (n1 already released, nothing coalesced).
	f.hold(t, n1, false)
	f.reconcile(t)
	if got := f.gate(t, "a.example.test", n1); got != "cleanup_debt" {
		t.Fatalf("re-active node with debt not gated: %q", got)
	}
	f.clock.Advance(20 * time.Minute) // every challenge expires
	f.reconcile(t)
	// A new epoch: n1 is a candidate again, so it is required; its required
	// coverage carries the debt.
	next := f.challenge(t, "a.example.test")
	if err := f.store.PublishChallenge(t.Context(), next); err != nil {
		t.Fatal(err)
	}
	if got := f.currentCoverage(t, n1); !equalStrings(got, "required:a.example.test") {
		t.Fatalf("n1 coverage %v", got)
	}
	if got := f.gate(t, "a.example.test", n1); got != "cleanup_debt" {
		t.Fatalf("required node with debt not gated before healthy: %q", got)
	}
	deliveries := f.deliver(t)
	for node, delivery := range deliveries {
		if node != n1 {
			f.receipt(t, delivery, "healthy", "")
		}
	}
	if got := f.gate(t, "a.example.test", n1); got != "cleanup_debt" {
		t.Fatalf("debt cleared before n1 was healthy: %q", got)
	}
	// Direct SQL cannot clear it without the proof.
	_, err := f.pool.Exec(t.Context(), `INSERT INTO acme_http01_node_overlay_cleanup_debt_events(debt_id,sequence,event,
		generation_id,occurred_at)
		SELECT debt.id,(SELECT max(sequence)+1 FROM acme_http01_node_overlay_cleanup_debt_events WHERE debt_id=debt.id),
		       'resolved_cleanup',state.current_generation_id,now()
		FROM acme_http01_node_overlay_cleanup_debts debt JOIN acme_http01_node_overlay_states state ON state.node_id=debt.node_id
		WHERE debt.node_id=$1`, n1)
	wantCode(t, "forged resolution", err, "P3426")
	f.receipt(t, deliveries[n1], "healthy", "")
	events := f.debtEvents(t, "a.example.test", n1)
	if events[0] != "opened:member_removed" || events[len(events)-1] != "resolved_required" {
		t.Fatalf("events %v", events)
	}
	if got := f.gate(t, "a.example.test", n1); got != "" {
		t.Fatalf("gate after resolved_required %q", got)
	}
	if status := f.status(t, next); len(status.Confirmed) != 2 {
		t.Fatalf("status %+v", status)
	}
}
// Membership is frozen when the epoch opens: a node joining the line group
// mid-epoch is neither targeted nor allowed to serve the site until the final
// empty cleanup closes the epoch.
func TestNodeHTTP01EpochFrozenAgainstDrift(t *testing.T) {
	f := newNodeFixture(t, true, true)
	a := f.challenge(t, "a.example.test")
	if err := f.store.PublishChallenge(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	f.healthyAll(t)
	n2 := f.addNode(t)
	if got := f.gate(t, "a.example.test", n2); got != "epoch_not_member" {
		t.Fatalf("drift node gate %q", got)
	}
	if got := f.gate(t, "b.example.test", n2); got != "" {
		t.Fatalf("site without an epoch gated the new node: %q", got)
	}
	f.reconcile(t)
	f.clock.Advance(time.Second)
	second := f.challenge(t, "a.example.test")
	if err := f.store.PublishChallenge(t.Context(), second); err != nil {
		t.Fatal(err)
	}
	if status := f.status(t, second); len(status.Pending) != 2 || slicesContain(status.Pending, n2) {
		t.Fatalf("second challenge targets %+v", status)
	}
	if err := f.store.WithdrawChallenge(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	if got := f.gate(t, "a.example.test", n2); got != "epoch_not_member" {
		t.Fatalf("epoch closed while a token is live: %q", got)
	}
	if err := f.store.WithdrawChallenge(t.Context(), second); err != nil {
		t.Fatal(err)
	}
	if got := f.gate(t, "a.example.test", n2); got != "" {
		t.Fatalf("closed epoch still gates the new node: %q", got)
	}
	// The next epoch includes it.
	third := f.challenge(t, "a.example.test")
	if err := f.store.PublishChallenge(t.Context(), third); err != nil {
		t.Fatal(err)
	}
	if status := f.status(t, third); len(status.Pending) != 3 {
		t.Fatalf("next epoch targets %+v", status)
	}
}

func slicesContain(nodes []uuid.UUID, node uuid.UUID) bool {
	for _, item := range nodes {
		if item == node {
			return true
		}
	}
	return false
}

// A retired node that owes a cleanup and serves nothing gets a cleanup_only
// generation: no token, no required coverage, every debt covered, bound to a
// non-serving proof. Forged generations violating the counting rules are
// rejected at commit.
func TestNodeHTTP01CleanupOnlyForNonServingNode(t *testing.T) {
	f := newNodeFixture(t, true, true)
	n0, n1 := f.nodes[0], f.nodes[1]
	a := f.challenge(t, "a.example.test")
	if err := f.store.PublishChallenge(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	f.healthyAll(t)
	f.setAdmin(t, n1, "retired")
	f.reconcile(t)
	var purpose string
	var tokens, required, debts int
	var proof []byte
	var generation int64
	if err := f.pool.QueryRow(t.Context(), `SELECT generation.purpose,generation.token_count,
		generation.required_coverage_count,generation.cleanup_debt_coverage_count,generation.non_serving_proof_sha256,
		generation.generation
		FROM acme_http01_node_overlay_states state
		JOIN acme_http01_node_overlay_generations generation ON generation.id=state.current_generation_id
		WHERE state.node_id=$1`, n1).Scan(&purpose, &tokens, &required, &debts, &proof, &generation); err != nil {
		t.Fatal(err)
	}
	want := nonServingProof(n1, "retired", generation)
	if purpose != "cleanup_only" || tokens != 0 || required != 0 || debts != 1 || string(proof) != string(want[:]) {
		t.Fatalf("retired node generation %s tokens=%d required=%d debts=%d", purpose, tokens, required, debts)
	}
	// The active node keeps an apply generation with its required coverage.
	if got := f.currentCoverage(t, n0); !equalStrings(got, "required:a.example.test") {
		t.Fatalf("n0 coverage %v", got)
	}
	forge := func(node uuid.UUID, purpose string, admin string, withDebt bool) error {
		return pgx.BeginFunc(t.Context(), f.pool, func(tx pgx.Tx) error {
			var current int64
			if err := tx.QueryRow(t.Context(), `SELECT current_generation FROM acme_http01_node_overlay_states
				WHERE node_id=$1`, node).Scan(&current); err != nil {
				return err
			}
			next := current + 1
			id := uuid.New()
			digest := nodeGenerationDigest(node, next, nil)
			var proof []byte
			debtCount := 0
			if purpose == "cleanup_only" {
				value := nonServingProof(node, admin, next)
				proof = value[:]
			}
			if withDebt {
				debtCount = 1
			}
			if _, err := tx.Exec(t.Context(), `INSERT INTO acme_http01_node_overlay_generations(id,node_id,generation,
				previous_generation,snapshot_sha256,token_count,deadline_at,created_at,purpose,required_coverage_count,
				cleanup_debt_coverage_count,non_serving_proof_sha256)
				VALUES($1,$2,$3,$4,$5,0,now()+interval '1 hour',now(),$6,0,$7,$8)`,
				id, node, next, current, digest[:], purpose, debtCount, proof); err != nil {
				return err
			}
			if withDebt {
				if _, err := tx.Exec(t.Context(), `INSERT INTO acme_http01_node_overlay_generation_coverages(generation_id,
					node_id,tenant_scope_id,site_id,coverage_kind,site_version_id,site_token_set_sha256,site_token_count,
					required_epoch_id,cleanup_debt_id)
					SELECT $1,coverage.node_id,coverage.tenant_scope_id,coverage.site_id,coverage.coverage_kind,
					       coverage.site_version_id,coverage.site_token_set_sha256,0,coverage.required_epoch_id,coverage.cleanup_debt_id
					FROM acme_http01_node_overlay_generation_coverages coverage
					JOIN acme_http01_node_overlay_states state ON state.current_generation_id=coverage.generation_id
					WHERE state.node_id=$2`, id, node); err != nil {
					return err
				}
			}
			if _, err := tx.Exec(t.Context(), `INSERT INTO acme_http01_node_overlay_deliveries(generation_id,node_id,generation,
				attempt,state,not_before,created_at,updated_at) VALUES($1,$2,$3,1,'pending',now(),now(),now())`, id, node, next); err != nil {
				return err
			}
			_, err := tx.Exec(t.Context(), `UPDATE acme_http01_node_overlay_states SET current_generation=$2,
				current_generation_id=$3,updated_at=greatest(updated_at,now()) WHERE node_id=$1`, node, next, id)
			return err
		})
	}
	wantCode(t, "empty apply dropping a required site", forge(n0, "apply", "", false), "P3425")
	wantCode(t, "apply dropping a debt", forge(n1, "apply", "", false), "P3425")
	f.setAdmin(t, n1, "active")
	wantCode(t, "cleanup_only on a serving node", forge(n1, "cleanup_only", "active", true), "P3427")
}
// seed063 records a 063 site overlay history (revisions 1..revision, the last
// one in mode, every revision targeting nodes) with one token fact per apply
// revision; value seeds the token's value digest.
func (f *nodeFixture) seed063(t *testing.T, site uuid.UUID, revision int, mode string, domain, token, value string,
	nodes ...uuid.UUID) {
	t.Helper()
	tokenDigest := sha256.Sum256([]byte(token))
	valueDigest := sha256.Sum256([]byte(value))
	seedTx(t, f.pool, func(exec func(string, ...any)) {
		exec(`INSERT INTO acme_http01_overlay_states(tenant_scope_id,site_id,current_revision,created_at,updated_at)
			VALUES($1,$2,$3,now(),now())`, f.scope, site, revision)
		for current := 1; current <= revision; current++ {
			currentMode, count := "apply", 1
			if current == revision && mode == "cleanup" {
				currentMode, count = "cleanup", 0
			}
			publication, version := uuid.New(), uuid.New()
			exec(`INSERT INTO acme_http01_overlay_publications(id,mode,tenant_scope_id,site_id,expected_revision,revision,
				idempotency_key,request_digest,request_id,token_count,node_count,max_attempts,deadline_at,created_at)
				VALUES($1,$2,$3,$4,$5-1,$5,$6,$7,gen_random_uuid(),$8,$9,3,now()+interval '1 hour',now())`,
				publication, currentMode, f.scope, site, current, fmt.Sprintf("k%d", current), tokenDigest[:], count, len(nodes))
			exec(`INSERT INTO acme_http01_overlay_versions(id,publication_id,tenant_scope_id,site_id,revision,
				sealed_snapshot_sha256,created_at) VALUES($1,$2,$3,$4,$5,$6,now())`,
				version, publication, f.scope, site, current, tokenDigest[:])
			if count == 1 {
				exec(`INSERT INTO acme_http01_overlay_token_facts(version_id,tenant_scope_id,site_id,revision,ordinal,
					operation_id,challenge_attempt_id,domain,token_sha256,value_sha256,key_id,nonce,ciphertext,aad_sha256,created_at)
					VALUES($1,$2,$3,$4,1,$5,$6,$7,$8,$9,'k1',$10,'\x01',$8,now())`,
					version, f.scope, site, current, "op-"+site.String()[:8], uuid.NewSHA1(site, []byte(token)), domain,
					tokenDigest[:], valueDigest[:], make([]byte, 12))
			}
			for index, node := range nodes {
				exec(`INSERT INTO acme_http01_overlay_targets(version_id,tenant_scope_id,site_id,revision,ordinal,node_id,created_at)
					VALUES($1,$2,$3,$4,$5,$6,now())`, version, f.scope, site, current, index+1, node)
			}
		}
	})
}

// The 063 backfill keeps every 063 fact, inherits no healthy receipt, turns
// each site into a closed epoch whose targets owe a cleanup, gives those
// nodes a bootstrap generation above every 063 revision, quarantines a node
// whose sites disagree on a token (and keeps it out of those sites), and is
// a no-op when run again.
func TestNodeHTTP01Backfill063(t *testing.T) {
	f := newNodeFixture(t, true, true, true)
	n0, n1, n2 := f.nodes[0], f.nodes[1], f.nodes[2]
	siteC := uuid.New()
	seedTx(t, f.pool, func(exec func(string, ...any)) {
		exec(`INSERT INTO sites(id,scope_id,owner_user_id,domain,origins,origin_hosts,created_by_user_id,
			updated_by_user_id,display_id,node_group_id,http_ports)
			VALUES($1,$2,$3,'c.example.test',ARRAY['127.0.0.1:8080'],ARRAY[''],$3,$3,
			(SELECT COALESCE(max(display_id),0)+1 FROM sites),$4,ARRAY['80'])`, siteC, f.scope, f.user, f.group)
	})
	f.sites["c.example.test"] = siteC
	token := "tok-shared-" + strings.Repeat("x", 30)
	f.seed063(t, f.sites["a.example.test"], 4, "cleanup", "a.example.test", "tok-a-"+strings.Repeat("a", 30), "va", n0, n1)
	// b and c serve the same host and token with different values on n2.
	f.seed063(t, f.sites["b.example.test"], 2, "apply", "shared.example.test", token, "value-1", n2)
	f.seed063(t, siteC, 1, "apply", "shared.example.test", token, "value-2", n2)
	var legacyBefore int
	if err := f.pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM acme_http01_overlay_versions)+
		(SELECT count(*) FROM acme_http01_overlay_targets)+(SELECT count(*) FROM acme_http01_overlay_token_facts)`).Scan(&legacyBefore); err != nil {
		t.Fatal(err)
	}
	run := func() [4]int {
		var counts [4]int
		if err := f.pool.QueryRow(t.Context(), `SELECT * FROM acme_http01_backfill_063()`).Scan(
			&counts[0], &counts[1], &counts[2], &counts[3]); err != nil {
			t.Fatal(err)
		}
		return counts
	}
	if got := run(); got != [4]int{1, 2, 2, 1} {
		t.Fatalf("first backfill %v (bootstrapped sites, quarantined sites, pending nodes, quarantined nodes)", got)
	}
	if got := run(); got != [4]int{0, 0, 2, 1} {
		t.Fatalf("rerun was not a no-op: %v", got)
	}
	for _, node := range []uuid.UUID{n0, n1} {
		if got := f.debtEvents(t, "a.example.test", node); !equalStrings(got, "opened:backfill_063_serving") {
			t.Fatalf("node %s events %v", node, got)
		}
		if got := f.gate(t, "a.example.test", node); got != "" {
			t.Fatalf("a still-serving 063 target was gated: %q", got)
		}
	}
	for _, domain := range []string{"b.example.test", "c.example.test"} {
		if got := f.gate(t, domain, n2); got != "backfill_quarantined" {
			t.Fatalf("%s gate for the conflicting node %q", domain, got)
		}
	}
	// No 063 healthy receipt is inherited: the bootstrap generation is
	// above every 063 revision a node saw and starts unhealthy.
	f.reconcile(t)
	deliveries := f.deliver(t)
	if len(deliveries) != 2 || deliveries[n0].Generation < 5 || deliveries[n1].Generation < 5 {
		t.Fatalf("bootstrap deliveries %+v", deliveries)
	}
	var healthy int
	if err := f.pool.QueryRow(t.Context(), `SELECT count(*) FROM acme_http01_node_overlay_states
		WHERE latest_healthy_generation > 0`).Scan(&healthy); err != nil || healthy != 0 {
		t.Fatalf("healthy states before any receipt: %d %v", healthy, err)
	}
	var states []string
	rows, err := f.pool.Query(t.Context(), `SELECT state FROM acme_http01_overlay_backfill_nodes ORDER BY node_id`)
	if err != nil {
		t.Fatal(err)
	}
	if states, err = pgx.CollectRows(rows, pgx.RowTo[string]); err != nil || strings.Count(strings.Join(states, ","), "bootstrapped") != 2 {
		t.Fatalf("backfill node states %v %v", states, err)
	}
	for _, delivery := range deliveries {
		f.receipt(t, delivery, "healthy", "")
	}
	for _, node := range []uuid.UUID{n0, n1} {
		if got := f.debtEvents(t, "a.example.test", node); !equalStrings(got, "opened:backfill_063_serving", "scheduled", "resolved_cleanup") {
			t.Fatalf("node %s after bootstrap %v", node, got)
		}
	}
	if got := run(); got != [4]int{0, 0, 0, 1} {
		t.Fatalf("rerun after bootstrap %v", got)
	}
	var legacyAfter int
	if err := f.pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM acme_http01_overlay_versions)+
		(SELECT count(*) FROM acme_http01_overlay_targets)+(SELECT count(*) FROM acme_http01_overlay_token_facts)`).Scan(&legacyAfter); err != nil ||
		legacyAfter != legacyBefore {
		t.Fatalf("063 facts changed: %d -> %d %v", legacyBefore, legacyAfter, err)
	}
}

// Over a real NATS server (CDNCA_TEST_NATS_URL): a removed member's
// zero-token cleanup generation goes out through the dispatcher, the agent's
// HEALTHY status comes back through the status consumer and resolves the
// debt, and the serving gate lifts once the epoch closes.
func TestNodeHTTP01DebtResolvedOverNATS(t *testing.T) {
	natsURL := os.Getenv("CDNCA_TEST_NATS_URL")
	if natsURL == "" {
		t.Skip("CDNCA_TEST_NATS_URL is not set")
	}
	f := newNodeFixture(t, true, true)
	n0, n1 := f.nodes[0], f.nodes[1]
	a := f.challenge(t, "a.example.test")
	if err := f.store.PublishChallenge(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	f.healthyAll(t)
	f.hold(t, n1, true)
	f.reconcile(t)
	connection, err := nats.Connect(natsURL, nats.Timeout(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	jetstream, err := connection.JetStream(nats.MaxWait(2 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	commandSubject := commandSubjectPrefix + "." + n1.String()
	statusSubject := statusSubjectPrefix + "." + n1.String()
	for name, subject := range map[string]string{"CMD_" + suffix: commandSubject, "STATUS_" + suffix: statusSubject} {
		if _, err := jetstream.AddStream(&nats.StreamConfig{Name: name, Subjects: []string{subject}, Storage: nats.MemoryStorage}); err != nil {
			t.Fatal(err)
		}
		defer func(name string) { _ = jetstream.DeleteStream(name) }(name)
	}
	_, private, _ := ed25519.GenerateKey(nil)
	artifactConfig := DefaultNodeArtifactConfig()
	artifactConfig.Clock = f.clock.Now
	artifacts, err := NewNodeArtifactStore(f.store, testSigner{private}, artifactConfig)
	if err != nil {
		t.Fatal(err)
	}
	dispatchConfig := DefaultDispatcherConfig()
	dispatchConfig.Stream = "CMD_" + suffix
	dispatcher, err := NewNodeDispatcher(f.store, artifacts, connection, dispatchConfig, nil)
	if err != nil {
		t.Fatal(err)
	}
	if published, err := dispatcher.PublishBatch(t.Context()); err != nil || published != 1 {
		t.Fatalf("PublishBatch = %d, %v", published, err)
	}
	subscription, err := jetstream.PullSubscribe(commandSubject, "agent_"+suffix, nats.BindStream("CMD_"+suffix))
	if err != nil {
		t.Fatal(err)
	}
	messages, err := subscription.Fetch(1, nats.MaxWait(2*time.Second))
	if err != nil || len(messages) != 1 {
		t.Fatalf("fetch command: %v", err)
	}
	command := new(agentv1.AcmeHTTP01OverlayCommand)
	if err := proto.Unmarshal(messages[0].Data, command); err != nil {
		t.Fatal(err)
	}
	chunk, err := artifacts.FetchChunk(t.Context(), fetchRequest(NodeDelivery{
		GenerationID: uuid.MustParse(command.OverlayDeploymentId), NodeID: n1}, command.Attempt))
	if err != nil {
		t.Fatal(err)
	}
	var document snapshot
	if err := json.Unmarshal(chunk.Response.Chunk.Data, &document); err != nil || len(document.Entries) != 0 {
		t.Fatalf("cleanup artifact %s %v", chunk.Response.Chunk.Data, err)
	}
	statusConfig := DefaultStatusConfig()
	statusConfig.Stream, statusConfig.Durable = "STATUS_"+suffix, "control_"+suffix
	consumer, err := NewNodeStatusConsumer(f.store, connection, statusConfig, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer consumer.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() { _ = consumer.Run(ctx) }()
	for sequence, state := range []agentv1.AcmeHTTP01OverlayState{
		agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_ACTIVATED,
		agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_HEALTHY,
	} {
		causation := command.Event.EventId
		active := command.OverlayVersionId
		payload, _ := proto.Marshal(&agentv1.AcmeHTTP01OverlayStatus{
			Event: &commonv1.EventMetadata{EventId: uuid.NewString(), RequestId: command.Event.RequestId,
				OccurredTime: timestamppb.Now(), CausationId: &causation, CorrelationId: command.Event.CorrelationId},
			OverlayDeploymentId: command.OverlayDeploymentId, Attempt: command.Attempt,
			OverlayVersionId: command.OverlayVersionId, OverlayRevision: command.OverlayRevision,
			State: state, TransitionSequence: uint64(sequence + 4), ActiveOverlayVersionId: &active,
			ActiveOverlayRevision: command.OverlayRevision,
			ResultCode:            agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_OK,
		})
		if _, err := jetstream.Publish(statusSubject, payload); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(10 * time.Second)
	for !equalStrings(f.debtEvents(t, "a.example.test", n1), "opened:member_removed", "scheduled", "resolved_cleanup") {
		if time.Now().After(deadline) {
			t.Fatalf("debt not resolved over NATS: %v", f.debtEvents(t, "a.example.test", n1))
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := f.gate(t, "a.example.test", n1); got != "epoch_not_member" {
		t.Fatalf("gate while the epoch is open %q", got)
	}
	if err := f.store.WithdrawChallenge(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	if got := f.gate(t, "a.example.test", n1); got != "" {
		t.Fatalf("gate after the epoch closed %q", got)
	}
	if got := f.debtEvents(t, "a.example.test", n0); !equalStrings(got, "opened:site_emptied", "scheduled") {
		t.Fatalf("n0 events %v", got)
	}
}
