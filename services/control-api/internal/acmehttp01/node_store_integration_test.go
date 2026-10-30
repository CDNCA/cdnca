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
	"sync"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/acmeworker"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

type nodeFixture struct {
	pool    *pgxpool.Pool
	clock   *testClock
	store   *NodeStore
	scope   uuid.UUID
	user    uuid.UUID
	group   uuid.UUID
	sites   map[string]uuid.UUID
	nodes   []uuid.UUID
	counter int
}

func openNodePool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	pool := databasetest.ClonedMigratedPool(t, nil)
	if pool == nil {
		t.Skip("TEST_DATABASE_TEMPLATE is not set (run through scripts/control-api-integration-sharded.sh)")
	}
	return pool
}

func seedTx(t *testing.T, pool *pgxpool.Pool, statements func(exec func(string, ...any))) {
	t.Helper()
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
		statements(exec)
		return failed
	})
	if err != nil {
		t.Fatal(err)
	}
}

// newNodeFixture: one tenant scope with sites a.example.test and
// b.example.test on one line group of nodeCount platform nodes; capable[i]
// says whether node i declares ACME_HTTP01_OVERLAY v1.
func newNodeFixture(t *testing.T, capable ...bool) *nodeFixture {
	t.Helper()
	pool := openNodePool(t)
	clock := &testClock{now: time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)}
	config := DefaultNodeStoreConfig()
	config.Clock = clock.Now
	config.MaxAttempts = 2
	store, err := NewNodeStore(pool, config)
	if err != nil {
		t.Fatal(err)
	}
	f := &nodeFixture{pool: pool, clock: clock, store: store, scope: uuid.New(), user: uuid.New(), group: uuid.New(),
		sites: map[string]uuid.UUID{"a.example.test": uuid.New(), "b.example.test": uuid.New()}}
	for range capable {
		f.nodes = append(f.nodes, uuid.New())
	}
	withOverlay, _ := proto.Marshal(&agentv1.AgentCapabilities{Features: []*agentv1.Capability{
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_ACME_HTTP01_OVERLAY, ApiVersion: 1}}})
	without, _ := proto.Marshal(&agentv1.AgentCapabilities{Features: []*agentv1.Capability{
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_QUIC, ApiVersion: 1}}})
	seedTx(t, pool, func(exec func(string, ...any)) {
		exec(`INSERT INTO access_scopes(id,kind) SELECT gen_random_uuid(),'platform'
			WHERE NOT EXISTS (SELECT 1 FROM access_scopes WHERE kind='platform')`)
		exec(`INSERT INTO tenants(id,display_name) VALUES($1,'http01')`, f.scope)
		exec(`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$1)`, f.scope)
		exec(`INSERT INTO users(id,username,display_name,password_hash,created_at,updated_at)
			VALUES($1,$2,'http01','x',now(),now())`, f.user, "http01-"+f.user.String()[:8])
		exec(`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, f.scope, f.user)
		exec(`INSERT INTO node_line_groups(id,tenant_scope_id,name,current_revision,created_by_user_id,
			updated_by_user_id,created_at,updated_at,display_id,resolved_value,ipv4_resolved_value)
			VALUES($1,(SELECT id FROM access_scopes WHERE kind='platform'),'http01',1,$2,$2,now(),now(),
			(SELECT COALESCE(max(display_id),0)+1 FROM node_line_groups),
			'lg-'||replace($1::uuid::text,'-',''),'lg4-'||replace($1::uuid::text,'-',''))`, f.group, f.user)
		for domain, site := range f.sites {
			exec(`INSERT INTO sites(id,scope_id,owner_user_id,domain,origins,origin_hosts,created_by_user_id,
				updated_by_user_id,display_id,node_group_id,http_ports)
				VALUES($1,$2,$3,$4,ARRAY['127.0.0.1:8080'],ARRAY[''],$3,$3,
				(SELECT COALESCE(max(display_id),0)+1 FROM sites),$5,ARRAY['80'])`, site, f.scope, f.user, domain, f.group)
		}
		for index, node := range f.nodes {
			exec(`INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id)
				VALUES($1,(SELECT id FROM access_scopes WHERE kind='platform'),$2,'active',$3,
				(SELECT COALESCE(max(display_id),0)+1 FROM nodes))`, node, "http01-"+node.String()[:8], f.user)
			exec(`INSERT INTO node_line_endpoints(id,node_id,tenant_scope_id,line_group_id,config_revision,address,
				address_family,port,region,carrier,priority,weight,enabled)
				VALUES(gen_random_uuid(),$1,(SELECT id FROM access_scopes WHERE kind='platform'),$2,1,$3::inet,4,80,'cn','BGP',0,1,true)`,
				node, f.group, fmt.Sprintf("198.51.100.%d", index+1))
			snapshot := without
			if capable[index] {
				snapshot = withOverlay
			}
			digest := sha256.Sum256(snapshot)
			exec(`INSERT INTO node_session_capabilities(node_id,session_epoch,certificate_id,certificate_sha256,
				artifact_key_id,selected_protocol_major,selected_protocol_minor,capabilities_snapshot,capabilities_sha256,
				facts_snapshot,facts_sha256,gateway_workload_identity,gateway_instance_id,registered_at)
				VALUES($1,1,gen_random_uuid(),$2,'k',1,0,$3,$2,'\x00',$2,'gw','gw-1',now())`, node, digest[:], snapshot)
		}
	})
	return f
}

// challenge records an ACME http-01 attempt for domain and returns its
// worker identity.
func (f *nodeFixture) challenge(t *testing.T, domain string) acmeworker.ChallengeIdentity {
	t.Helper()
	f.counter++
	operation := uuid.New()
	attempt := uuid.New()
	token := fmt.Sprintf("tok%040d", f.counter)
	value := token + "." + strings.Repeat("T", 43)
	snapshot, _ := json.Marshal(map[string]any{
		"TenantID": f.scope.String(), "ScopeID": f.scope.String(), "ActorUserID": f.user.String(),
		"OperationID": operation.String(), "DirectoryURL": "https://acme.example.test/directory",
		"CertificateKeyRef": "cert-key", "AccountKeyRef": "account-key", "ProviderRef": "",
		"Domains": []string{domain}, "ChallengeType": "http-01",
	})
	digest := sha256.Sum256(snapshot)
	authorizationURL := "https://acme.example.test/authz/" + operation.String()
	seedTx(t, f.pool, func(exec func(string, ...any)) {
		for _, key := range [][2]string{{"account-key", "account"}, {"cert-key", "certificate"}} {
			public := sha256.Sum256([]byte(key[0] + operation.String()))
			exec(`INSERT INTO acme_tenant_key_facts(tenant_scope_id,id,key_ref,purpose,algorithm,public_key_spki_sha256,
				external_key_reference,created_by_user_id) VALUES($1,gen_random_uuid(),$2,$3,'ecdsa',$4,$5,$6)
				ON CONFLICT DO NOTHING`, f.scope, key[0], key[1], public[:], "kms://http01/"+key[0], f.user)
		}
		exec(`INSERT INTO certificate_orders(id,scope_id,domains,challenge_type,created_by_user_id,updated_by_user_id)
			VALUES($1,$2,$3,'http-01',$4,$4)`, operation, f.scope, []string{domain}, f.user)
		exec(`INSERT INTO acme_issuance_operations(tenant_scope_id,operation_id,request_digest,request_snapshot,
			directory_url,certificate_key_ref,created_at,certificate_order_id,actor_user_id,account_key_ref)
			VALUES($1,$2,$3,$4,'https://acme.example.test/directory','cert-key',now(),$6,$5,'account-key')`,
			f.scope, operation.String(), digest[:], snapshot, f.user, operation)
		accountURI := "https://acme.example.test/account/" + f.scope.String()
		orderURL := "https://acme.example.test/order/" + operation.String()
		finalizeURL := "https://acme.example.test/finalize/" + operation.String()
		authorizations := []string{authorizationURL}
		exec(`INSERT INTO acme_account_registration_facts(tenant_scope_id,id,account_key_id,directory_url,account_uri,
			contacts,terms_agreed_at,registered_at,created_by_user_id)
			SELECT $1,gen_random_uuid(),id,'https://acme.example.test/directory',$2,ARRAY['mailto:ops@example.test'],now(),now(),$3
			FROM acme_tenant_key_facts WHERE tenant_scope_id=$1 AND key_ref='account-key'
			ON CONFLICT DO NOTHING`, f.scope, accountURI, f.user)
		lease := uuid.New()
		for _, event := range []struct {
			revision      int
			kind, phase   string
			intent        bool
			account       *string
			order, final  *string
			authorization []string
		}{
			{1, "claim_created", "claimed", false, nil, nil, nil, []string{}},
			{2, "account_registered", "claimed", false, &accountURI, nil, nil, []string{}},
			{3, "order_intent", "claimed", true, &accountURI, nil, nil, []string{}},
			{4, "order_created", "ordered", false, &accountURI, &orderURL, &finalizeURL, authorizations},
			{5, "authorizing", "authorizing", false, &accountURI, &orderURL, &finalizeURL, authorizations},
		} {
			exec(`INSERT INTO acme_issuance_operation_events(tenant_scope_id,operation_id,revision,event_type,phase,status,
				fence_token,order_intent_pending,lease_token,lease_expires_at,account_uri,order_url,finalize_url,
				authorization_urls,occurred_at)
				VALUES($1,$2,$3,$4,$5,'active',$6,$7,$6,now()+interval '1 day',$8,$9,$10,$11,now())`,
				f.scope, operation.String(), event.revision, event.kind, event.phase, lease, event.intent,
				event.account, event.order, event.final, event.authorization)
		}
		exec(`INSERT INTO acme_issuance_challenge_attempts(tenant_scope_id,operation_id,attempt_id,attempt_number,
			authorization_url,challenge_url,challenge_type,identifier,wildcard,record_name,token,exact_value,created_at)
			VALUES($1,$2,$3,1,$7,'https://acme.example.test/chall/1','http-01',$4,false,$4,$5,$6,now())`,
			f.scope, operation.String(), attempt, domain, token, value, authorizationURL)
		exec(`INSERT INTO acme_issuance_challenge_events(tenant_scope_id,operation_id,attempt_id,revision,state,
			lease_token,occurred_at) VALUES($1,$2,$3,1,'intent',$4,now())`, f.scope, operation.String(), attempt, lease)
	})
	return acmeworker.ChallengeIdentity{
		TenantID: f.scope, ScopeID: f.scope, OperationID: operation.String(), AttemptID: attempt,
		ChallengeType: acmeworker.ChallengeHTTP01, Identifier: domain, RecordName: domain, Token: token, ExactValue: value,
	}
}

// deliver claims the pending attempts and marks them published, as the
// dispatcher does after the NATS PubAck.
func (f *nodeFixture) deliver(t *testing.T) map[uuid.UUID]NodeDelivery {
	t.Helper()
	deliveries, err := f.store.ClaimDeliveries(t.Context(), 64)
	if err != nil {
		t.Fatal(err)
	}
	result := make(map[uuid.UUID]NodeDelivery, len(deliveries))
	for _, delivery := range deliveries {
		if err := f.store.CompleteDelivery(t.Context(), delivery, true, false, ""); err != nil {
			t.Fatal(err)
		}
		result[delivery.NodeID] = delivery
	}
	return result
}

func (f *nodeFixture) receipt(t *testing.T, delivery NodeDelivery, state, code string) {
	t.Helper()
	if err := f.store.RecordReceipt(t.Context(), NodeReceipt{
		GenerationID: delivery.GenerationID, NodeID: delivery.NodeID, Generation: delivery.Generation,
		Attempt: delivery.Attempt, State: state, FailureCode: code,
	}); err != nil {
		t.Fatalf("receipt %s/%s: %v", state, code, err)
	}
}

func (f *nodeFixture) status(t *testing.T, challenge acmeworker.ChallengeIdentity) NodeChallengeStatus {
	t.Helper()
	status, err := f.store.ChallengeStatus(t.Context(), challenge)
	if err != nil {
		t.Fatal(err)
	}
	return status
}

func (f *nodeFixture) servedTokens(t *testing.T, node uuid.UUID, healthy bool) []string {
	t.Helper()
	column := "current_generation_id"
	if healthy {
		column = "latest_healthy_generation_id"
	}
	rows, err := f.pool.Query(t.Context(), `SELECT attempt.token FROM acme_http01_node_overlay_states state
		JOIN acme_http01_node_overlay_generation_tokens token ON token.generation_id=state.`+column+`
		JOIN acme_issuance_challenge_attempts attempt ON attempt.tenant_scope_id=token.tenant_scope_id
		 AND attempt.operation_id=token.operation_id AND attempt.attempt_id=token.attempt_id
		WHERE state.node_id=$1 ORDER BY token.ordinal`, node)
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	return tokens
}

// The CA may only be asked to validate once every target node serves the
// token: Publish blocks until all three nodes report healthy.
func TestNodeHTTP01PublishWaitsForEveryNode(t *testing.T) {
	f := newNodeFixture(t, true, true, true)
	provider, err := NewNodeProvider(f.store, 5*time.Millisecond, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	challenge := f.challenge(t, "a.example.test")
	done := make(chan error, 1)
	go func() { done <- provider.Publish(t.Context(), challenge) }()
	var deliveries map[uuid.UUID]NodeDelivery
	deadline := time.Now().Add(10 * time.Second)
	for len(deliveries) == 0 && time.Now().Before(deadline) {
		deliveries = f.deliver(t)
	}
	if len(deliveries) != 3 {
		t.Fatalf("want a delivery per node, got %d", len(deliveries))
	}
	for index, node := range f.nodes {
		delivery := deliveries[node]
		if delivery.Generation != 1 || delivery.Attempt != 1 {
			t.Fatalf("node %d delivery %+v", index, delivery)
		}
		f.receipt(t, delivery, "applied", "")
		f.receipt(t, delivery, "healthy", "")
		select {
		case err := <-done:
			if index < len(f.nodes)-1 {
				t.Fatalf("publish returned after %d of 3 nodes: %v", index+1, err)
			}
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(100 * time.Millisecond):
			if index == len(f.nodes)-1 {
				t.Fatal("publish did not return after every node was healthy")
			}
		}
	}
	if status := f.status(t, challenge); len(status.Confirmed) != 3 {
		t.Fatalf("status %+v", status)
	}
	// Replaying Publish (worker retry) is a no-op and confirmed at once.
	if err := provider.Publish(t.Context(), challenge); err != nil {
		t.Fatal(err)
	}
	if got := f.deliver(t); len(got) != 0 {
		t.Fatalf("replay created deliveries: %v", got)
	}
}

// One node failing for good fails Publish with that node listed; the other
// nodes are confirmed.
func TestNodeHTTP01PartialNodeFailure(t *testing.T) {
	f := newNodeFixture(t, true, true)
	challenge := f.challenge(t, "a.example.test")
	if err := f.store.PublishChallenge(t.Context(), challenge); err != nil {
		t.Fatal(err)
	}
	deliveries := f.deliver(t)
	good, bad := deliveries[f.nodes[0]], deliveries[f.nodes[1]]
	f.receipt(t, good, "healthy", "")
	f.receipt(t, bad, "failed", "invalid_artifact") // not retryable
	status := f.status(t, challenge)
	if len(status.Confirmed) != 1 || status.Confirmed[0] != f.nodes[0] || len(status.Failed) != 1 || status.Failed[0] != f.nodes[1] {
		t.Fatalf("status %+v", status)
	}
	provider, _ := NewNodeProvider(f.store, time.Millisecond, 0, nil)
	var delivery *NodeDeliveryError
	if err := provider.Publish(t.Context(), challenge); !errors.As(err, &delivery) || len(delivery.Failed) != 1 || delivery.Failed[0] != f.nodes[1] {
		t.Fatalf("publish err %v", err)
	}
}

// A retryable agent failure gets a new attempt of the same generation; once
// MaxAttempts (2) are used the node is failed.
func TestNodeHTTP01RetryThenExhausted(t *testing.T) {
	f := newNodeFixture(t, true)
	challenge := f.challenge(t, "a.example.test")
	if err := f.store.PublishChallenge(t.Context(), challenge); err != nil {
		t.Fatal(err)
	}
	first := f.deliver(t)[f.nodes[0]]
	f.receipt(t, first, "failed", "health_failed")
	if status := f.status(t, challenge); len(status.Pending) != 1 {
		t.Fatalf("after first failure %+v", status)
	}
	if got := f.deliver(t); len(got) != 0 {
		t.Fatal("retry was not backed off")
	}
	f.clock.Advance(time.Minute)
	second := f.deliver(t)[f.nodes[0]]
	if second.GenerationID != first.GenerationID || second.Attempt != 2 {
		t.Fatalf("retry %+v after %+v", second, first)
	}
	f.receipt(t, second, "failed", "health_failed")
	if status := f.status(t, challenge); len(status.Failed) != 1 {
		t.Fatalf("after exhausting attempts %+v", status)
	}
}

// An attempt without a receipt times out and is retried; a node that never
// answers is failed after MaxAttempts and Publish gives up within its
// deadline listing the node.
func TestNodeHTTP01Timeout(t *testing.T) {
	f := newNodeFixture(t, true, true)
	challenge := f.challenge(t, "a.example.test")
	if err := f.store.PublishChallenge(t.Context(), challenge); err != nil {
		t.Fatal(err)
	}
	deliveries := f.deliver(t)
	f.receipt(t, deliveries[f.nodes[0]], "healthy", "")
	f.clock.Advance(2 * time.Minute)
	result, err := f.store.Reconcile(t.Context(), 100)
	if err != nil || result.TimedOut != 1 {
		t.Fatalf("reconcile %+v %v", result, err)
	}
	f.clock.Advance(time.Minute)
	retry := f.deliver(t)
	if retry[f.nodes[1]].Attempt != 2 || len(retry) != 1 {
		t.Fatalf("retry %+v", retry)
	}
	provider, _ := NewNodeProvider(f.store, time.Millisecond, 0, nil)
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	var pending *NodeDeliveryError
	if err := provider.Publish(ctx, challenge); !errors.As(err, &pending) || len(pending.Pending) != 1 || pending.Pending[0] != f.nodes[1] {
		t.Fatalf("publish err %v", err)
	}
	f.clock.Advance(2 * time.Minute)
	if result, err := f.store.Reconcile(t.Context(), 100); err != nil || result.TimedOut != 1 {
		t.Fatalf("second reconcile %+v %v", result, err)
	}
	if status := f.status(t, challenge); len(status.Failed) != 1 || status.Failed[0] != f.nodes[1] {
		t.Fatalf("after exhausting %+v", status)
	}
}

// Two sites on the same nodes share one node generation (the union).
// Withdrawing A's token produces a generation that keeps B's; the old
// undelivered generation is superseded; Delete waits for the removal.
func TestNodeHTTP01UnionAndWithdrawal(t *testing.T) {
	f := newNodeFixture(t, true, true)
	a, b := f.challenge(t, "a.example.test"), f.challenge(t, "b.example.test")
	for _, challenge := range []acmeworker.ChallengeIdentity{a, b} {
		if err := f.store.PublishChallenge(t.Context(), challenge); err != nil {
			t.Fatal(err)
		}
	}
	// Generation 1 (A) was superseded by generation 2 (A+B) before delivery.
	var superseded int
	if err := f.pool.QueryRow(t.Context(), `SELECT count(*) FROM acme_http01_node_overlay_deliveries
		WHERE state='superseded' AND generation=1`).Scan(&superseded); err != nil || superseded != 2 {
		t.Fatalf("superseded %d %v", superseded, err)
	}
	deliveries := f.deliver(t)
	for _, node := range f.nodes {
		if deliveries[node].Generation != 2 {
			t.Fatalf("node %s delivery %+v", node, deliveries[node])
		}
		f.receipt(t, deliveries[node], "healthy", "")
		if got := f.servedTokens(t, node, true); len(got) != 2 || got[0] != a.Token || got[1] != b.Token {
			t.Fatalf("node serves %v", got)
		}
	}
	provider, _ := NewNodeProvider(f.store, 5*time.Millisecond, 5*time.Second, nil)
	done := make(chan error, 1)
	go func() { done <- provider.Delete(t.Context(), a) }()
	var cleanup map[uuid.UUID]NodeDelivery
	for deadline := time.Now().Add(5 * time.Second); len(cleanup) == 0 && time.Now().Before(deadline); {
		cleanup = f.deliver(t)
	}
	for _, node := range f.nodes {
		if cleanup[node].Generation != 3 {
			t.Fatalf("cleanup delivery %+v", cleanup[node])
		}
		if got := f.servedTokens(t, node, false); len(got) != 1 || got[0] != b.Token {
			t.Fatalf("cleanup generation carries %v", got)
		}
		f.receipt(t, cleanup[node], "healthy", "")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if status := f.status(t, a); !status.Withdrawn || len(status.Confirmed) != 0 {
		t.Fatalf("A after withdrawal %+v", status)
	}
	if status := f.status(t, b); len(status.Confirmed) != 2 {
		t.Fatalf("B after A's withdrawal %+v", status)
	}
	// A withdrawn challenge cannot be published again; withdrawal replays.
	if err := f.store.PublishChallenge(t.Context(), a); !errors.Is(err, ErrChallengeWithdrawn) {
		t.Fatalf("republish withdrawn: %v", err)
	}
	if err := f.store.WithdrawChallenge(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	// Last token gone: an empty generation for every node.
	if err := f.store.WithdrawChallenge(t.Context(), b); err != nil {
		t.Fatal(err)
	}
	for _, delivery := range f.deliver(t) {
		f.receipt(t, delivery, "healthy", "")
		if got := f.servedTokens(t, delivery.NodeID, true); len(got) != 0 {
			t.Fatalf("empty generation serves %v", got)
		}
	}
}

// Delete returns once the withdrawal is recorded even if a node never
// confirms; the reconciler keeps re-delivering to that node.
func TestNodeHTTP01OfflineNodeCleanupRedelivered(t *testing.T) {
	f := newNodeFixture(t, true)
	challenge := f.challenge(t, "a.example.test")
	if err := f.store.PublishChallenge(t.Context(), challenge); err != nil {
		t.Fatal(err)
	}
	f.receipt(t, f.deliver(t)[f.nodes[0]], "healthy", "")
	provider, _ := NewNodeProvider(f.store, time.Millisecond, 20*time.Millisecond, nil)
	if err := provider.Delete(t.Context(), challenge); err != nil {
		t.Fatalf("delete with an offline node: %v", err)
	}
	cleanup := f.deliver(t)[f.nodes[0]]
	for range 2 { // both attempts time out
		f.clock.Advance(2 * time.Minute)
		if _, err := f.store.Reconcile(t.Context(), 100); err != nil {
			t.Fatal(err)
		}
		f.clock.Advance(time.Minute)
		f.deliver(t)
	}
	if got := f.servedTokens(t, f.nodes[0], true); len(got) != 1 {
		t.Fatalf("node should still serve the stale token: %v", got)
	}
	f.clock.Advance(10 * time.Minute)
	result, err := f.store.Reconcile(t.Context(), 100)
	if err != nil || result.Redelivered != 1 {
		t.Fatalf("stale redelivery %+v %v", result, err)
	}
	f.clock.Advance(time.Minute)
	redelivered := f.deliver(t)[f.nodes[0]]
	if redelivered.GenerationID != cleanup.GenerationID || redelivered.Attempt != 3 {
		t.Fatalf("redelivered %+v (cleanup %+v)", redelivered, cleanup)
	}
	f.receipt(t, redelivered, "healthy", "")
	if got := f.servedTokens(t, f.nodes[0], true); len(got) != 0 {
		t.Fatalf("after reconnect the node serves %v", got)
	}
	if result, err := f.store.Reconcile(t.Context(), 100); err != nil || result != (NodeReconcileResult{}) {
		t.Fatalf("converged node reconciled again: %+v %v", result, err)
	}
}

// An agent that reports a newer active revision (conflict) moves the node
// to a generation above it.
func TestNodeHTTP01ConflictJumpsGeneration(t *testing.T) {
	f := newNodeFixture(t, true)
	challenge := f.challenge(t, "a.example.test")
	if err := f.store.PublishChallenge(t.Context(), challenge); err != nil {
		t.Fatal(err)
	}
	delivery := f.deliver(t)[f.nodes[0]]
	if err := f.store.RecordReceipt(t.Context(), NodeReceipt{GenerationID: delivery.GenerationID, NodeID: delivery.NodeID,
		Generation: 1, Attempt: 1, State: "failed", FailureCode: "stale_attempt", ActiveRevision: 41}); err != nil {
		t.Fatal(err)
	}
	next := f.deliver(t)[f.nodes[0]]
	if next.Generation != 42 || next.Attempt != 1 {
		t.Fatalf("after conflict %+v", next)
	}
	f.receipt(t, next, "healthy", "")
	if status := f.status(t, challenge); len(status.Confirmed) != 1 {
		t.Fatalf("status %+v", status)
	}
}

// A target node without the overlay capability refuses the challenge before
// anything is recorded; a domain outside the scope's sites has no target.
func TestNodeHTTP01CapabilityAndSiteGate(t *testing.T) {
	f := newNodeFixture(t, true, false)
	var unsupported *NodeUnsupportedError
	if err := f.store.PublishChallenge(t.Context(), f.challenge(t, "a.example.test")); !errors.As(err, &unsupported) ||
		len(unsupported.NodeIDs) != 1 || unsupported.NodeIDs[0] != f.nodes[1] {
		t.Fatalf("publish err %v", err)
	}
	provider, _ := NewNodeProvider(f.store, time.Millisecond, 0, nil)
	if err := provider.Publish(t.Context(), f.challenge(t, "a.example.test")); acmeworker.ErrorCodeOf(err) != acmeworker.CodeHTTP01NodeUnsupported {
		t.Fatalf("provider err %v", err)
	}
	if err := provider.Publish(t.Context(), f.challenge(t, "c.example.test")); acmeworker.ErrorCodeOf(err) != acmeworker.CodeHTTP01NoServingNode {
		t.Fatalf("unknown domain err %v", err)
	}
	var challenges int
	if err := f.pool.QueryRow(t.Context(), `SELECT count(*) FROM acme_http01_node_challenges`).Scan(&challenges); err != nil || challenges != 0 {
		t.Fatalf("refused challenges were recorded: %d %v", challenges, err)
	}
}

// Direct SQL cannot forge a generation, move state backwards or rewrite a
// terminal delivery.
func TestNodeHTTP01TamperRejected(t *testing.T) {
	f := newNodeFixture(t, true)
	challenge := f.challenge(t, "a.example.test")
	if err := f.store.PublishChallenge(t.Context(), challenge); err != nil {
		t.Fatal(err)
	}
	f.receipt(t, f.deliver(t)[f.nodes[0]], "healthy", "")
	node := f.nodes[0]
	for name, sql := range map[string]string{
		"rewrite generation":  `UPDATE acme_http01_node_overlay_generations SET token_count=0 WHERE node_id=$1`,
		"delete token":        `DELETE FROM acme_http01_node_overlay_generation_tokens WHERE generation_id IN (SELECT id FROM acme_http01_node_overlay_generations WHERE node_id=$1)`,
		"rewind state":        `UPDATE acme_http01_node_overlay_states SET latest_healthy_generation=0,latest_healthy_generation_id=NULL WHERE node_id=$1`,
		"reopen delivery":     `UPDATE acme_http01_node_overlay_deliveries SET state='pending',failure_code=NULL WHERE node_id=$1`,
		"unwithdraw":          `UPDATE acme_http01_node_challenges SET target_count=2 WHERE site_id IS NOT NULL AND $1::uuid IS NOT NULL`,
		"forged empty gen":    `INSERT INTO acme_http01_node_overlay_generations(id,node_id,generation,previous_generation,snapshot_sha256,token_count,deadline_at,created_at) VALUES(gen_random_uuid(),$1,9,1,'\x` + strings.Repeat("00", 32) + `',0,now()+interval '1 hour',now())`,
		"skip delivery chain": `INSERT INTO acme_http01_node_overlay_deliveries(generation_id,node_id,generation,attempt,state,not_before,created_at,updated_at) SELECT id,node_id,generation,5,'pending',now(),now(),now() FROM acme_http01_node_overlay_generations WHERE node_id=$1`,
	} {
		_, err := f.pool.Exec(t.Context(), sql, node)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || !strings.HasPrefix(pgErr.Code, "P337") {
			t.Errorf("%s: want P337x rejection, got %v", name, err)
		}
	}
}

// The command, artifact and chunk carry the generation snapshot signed with
// the configured key; only the newest attempt of the current generation is
// fetchable.
func TestNodeHTTP01ArtifactAndCommand(t *testing.T) {
	f := newNodeFixture(t, true)
	challenge := f.challenge(t, "a.example.test")
	if err := f.store.PublishChallenge(t.Context(), challenge); err != nil {
		t.Fatal(err)
	}
	delivery := f.deliver(t)[f.nodes[0]]
	public, private, _ := ed25519.GenerateKey(nil)
	config := DefaultNodeArtifactConfig()
	config.Clock = f.clock.Now
	artifacts, err := NewNodeArtifactStore(f.store, testSigner{private}, config)
	if err != nil {
		t.Fatal(err)
	}
	command, err := artifacts.BuildCommand(t.Context(), delivery)
	if err != nil {
		t.Fatal(err)
	}
	if command.OverlayDeploymentId != delivery.GenerationID.String() || command.OverlayVersionId != command.OverlayDeploymentId ||
		command.OverlayRevision != 1 || command.Attempt != 1 || command.PreviousOverlayVersionId != nil ||
		command.Event.EventId != nodeCommandEventID(delivery.GenerationID, 1).String() {
		t.Fatalf("command %+v", command)
	}
	binding, err := f.store.loadDeliveryBinding(t.Context(), delivery.GenerationID, 1)
	if err != nil {
		t.Fatal(err)
	}
	wire, descriptor, err := artifacts.artifact(t.Context(), binding)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(public, wire, descriptor.Signature) || !proto.Equal(descriptor, command.Artifact) {
		t.Fatal("artifact signature or descriptor mismatch")
	}
	var decoded snapshot
	if err := json.Unmarshal(wire, &decoded); err != nil || len(decoded.Entries) != 1 ||
		decoded.Entries[0].Host != "a.example.test" || decoded.Entries[0].Token != challenge.Token ||
		decoded.Entries[0].Value != challenge.ExactValue || decoded.OverlayRevision != 1 {
		t.Fatalf("snapshot %s %v", wire, err)
	}
	// A newer attempt makes the old one unfetchable.
	f.receipt(t, delivery, "failed", "health_failed")
	if _, err := artifacts.FetchChunk(t.Context(), fetchRequest(delivery, 1)); err == nil {
		t.Fatal("superseded attempt was fetchable")
	}
	f.clock.Advance(time.Minute)
	retry := f.deliver(t)[f.nodes[0]]
	result, err := artifacts.FetchChunk(t.Context(), fetchRequest(retry, 2))
	if err != nil || result.Response == nil || string(result.Response.Chunk.Data) != string(wire) {
		t.Fatalf("fetch retry: %v", err)
	}
}

type testSigner struct{ key ed25519.PrivateKey }

func (testSigner) KeyID() string { return "test-key" }
func (s testSigner) Sign(_ context.Context, payload []byte) ([]byte, error) {
	return ed25519.Sign(s.key, payload), nil
}

func fetchRequest(delivery NodeDelivery, attempt uint32) *controlv1.FetchArtifactRequest {
	return &controlv1.FetchArtifactRequest{
		Request:      &commonv1.RequestMetadata{RequestId: uuid.NewString(), SentTime: timestamppb.Now()},
		EventId:      nodeCommandEventID(delivery.GenerationID, int(attempt)).String(),
		NodeId:       delivery.NodeID.String(),
		DeploymentId: delivery.GenerationID.String(), Attempt: attempt,
		ArtifactId:        overlayArtifactID(delivery.GenerationID).String(),
		GatewayInstanceId: uuid.NewString(),
	}
}

// End to end over a real NATS server (CDNCA_TEST_NATS_URL): the dispatcher
// publishes the signed command to the node subject, the artifact is fetched
// through the gateway path, the agent-style ACTIVATED/HEALTHY statuses go
// through the status consumer (which creates its durable) and the challenge
// is confirmed.
func TestNodeHTTP01DispatchAndStatusOverNATS(t *testing.T) {
	natsURL := os.Getenv("CDNCA_TEST_NATS_URL")
	if natsURL == "" {
		t.Skip("CDNCA_TEST_NATS_URL is not set")
	}
	f := newNodeFixture(t, true)
	challenge := f.challenge(t, "a.example.test")
	if err := f.store.PublishChallenge(t.Context(), challenge); err != nil {
		t.Fatal(err)
	}
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
	node := f.nodes[0]
	commandSubject := commandSubjectPrefix + "." + node.String()
	statusSubject := statusSubjectPrefix + "." + node.String()
	for name, subject := range map[string]string{"CMD_" + suffix: commandSubject, "STATUS_" + suffix: statusSubject} {
		if _, err := jetstream.AddStream(&nats.StreamConfig{Name: name, Subjects: []string{subject}, Storage: nats.MemoryStorage}); err != nil {
			t.Fatal(err)
		}
		defer func(name string) { _ = jetstream.DeleteStream(name) }(name)
	}
	public, private, _ := ed25519.GenerateKey(nil)
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
	if err := proto.Unmarshal(messages[0].Data, command); err != nil || messages[0].Header.Get(nats.MsgIdHdr) != command.Event.EventId {
		t.Fatalf("command decode: %v", err)
	}
	generationID := uuid.MustParse(command.OverlayDeploymentId)
	chunk, err := artifacts.FetchChunk(t.Context(), fetchRequest(NodeDelivery{GenerationID: generationID, NodeID: node}, command.Attempt))
	if err != nil || !chunk.Response.Chunk.EndOfArtifact || !ed25519.Verify(public, chunk.Response.Chunk.Data, command.Artifact.Signature) {
		t.Fatalf("fetch artifact: %v", err)
	}
	var document snapshot
	if err := json.Unmarshal(chunk.Response.Chunk.Data, &document); err != nil || len(document.Entries) != 1 ||
		document.Entries[0].Value != challenge.ExactValue {
		t.Fatalf("artifact %s", chunk.Response.Chunk.Data)
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
		status := &agentv1.AcmeHTTP01OverlayStatus{
			Event: &commonv1.EventMetadata{
				EventId: uuid.NewString(), RequestId: command.Event.RequestId, OccurredTime: timestamppb.Now(),
				CausationId: &causation, CorrelationId: command.Event.CorrelationId,
			},
			OverlayDeploymentId: command.OverlayDeploymentId, Attempt: command.Attempt,
			OverlayVersionId: command.OverlayVersionId, OverlayRevision: command.OverlayRevision,
			State: state, TransitionSequence: uint64(sequence + 4), ActiveOverlayVersionId: &active,
			ActiveOverlayRevision: command.OverlayRevision,
			ResultCode:            agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_OK,
		}
		payload, _ := proto.Marshal(status)
		if _, err := jetstream.Publish(statusSubject, payload); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		if status := f.status(t, challenge); len(status.Confirmed) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("challenge not confirmed over NATS: %+v", f.status(t, challenge))
		}
		time.Sleep(20 * time.Millisecond)
	}
}
