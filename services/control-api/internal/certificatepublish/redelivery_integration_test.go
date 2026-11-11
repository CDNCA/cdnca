//go:build integration

package certificatepublish

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/certificateasset"
	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cdnca/cdnca/services/control-api/internal/edgestatus"
	"github.com/cdnca/cdnca/services/control-api/internal/nodeidentity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// 证书私钥只在绑定/续期发布那一刻发给当时的目标节点；
// 之后加入线路组、同 ID 重装或恢复上线的节点永远拿不到，HTTPS 握手失败。补发器按“当前主机”的
// 部署历史判断缺什么，用系统 secret rollout 补发，节点收下后按 node_sync 重新发布一次。

// redeliveryClock is the fixture's clock: every store and the redeliverer
// read it, the test moves it forward.
type redeliveryClock struct {
	mu    sync.Mutex
	value time.Time
}

func (clock *redeliveryClock) now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.value
}

func (clock *redeliveryClock) advance(step time.Duration) {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	clock.value = clock.value.Add(step)
}

type redeliveryFixture struct {
	pool       *pgxpool.Pool
	clock      *redeliveryClock
	tenant     publicationTenant
	nodeA      publicationNode
	nodeB      publicationNode
	privateKey []byte
	binding    certificateasset.Binding
	assets     *certificateasset.Store
	rollouts   *edgedeployment.Store
	status     *edgestatus.Store
	producer   *Producer
	created    map[uuid.UUID]edgedeployment.Rollout
	// serving and ready stand in for the line groups and node identity
	// (covered by TestSitesTargetNodeIDsMatchesSiteTargetNodeIDs and
	// TestRedeliveryNodeReadyTx).
	serving []uuid.UUID
	ready   map[uuid.UUID]bool
	synced  []uuid.UUID
}

// newRedeliveryFixture: one site bound to an uploaded certificate, published
// (the user's publication) to node A only, healthy there. Node B exists and
// serves nothing yet.
func newRedeliveryFixture(t *testing.T) *redeliveryFixture {
	t.Helper()
	// The node_sync dedupe compares the database's clock with the stores'
	// clock: keep the fixture just behind wall time (as production runs);
	// the test moves it forward by seconds only.
	previous := publicationIntegrationNow
	publicationIntegrationNow = time.Now().UTC().Add(-10 * time.Minute).Truncate(time.Microsecond)
	t.Cleanup(func() { publicationIntegrationNow = previous })
	pool := openPublicationIntegrationDatabase(t)
	clock := &redeliveryClock{value: publicationIntegrationNow}
	f := &redeliveryFixture{pool: pool, clock: clock, created: map[uuid.UUID]edgedeployment.Rollout{},
		ready: map[uuid.UUID]bool{}}
	var err error
	if f.assets, err = certificateasset.NewStoreWithDependencies(pool, integrationCertificateEnveloper{}, audit.New(pool), clock.now); err != nil {
		t.Fatal(err)
	}
	f.tenant = seedPublicationTenant(t, pool)
	f.nodeA = seedPublicationNode(t, pool, f.tenant.scopeID, f.tenant.userID)
	f.nodeB = seedPublicationNode(t, pool, f.tenant.scopeID, f.tenant.userID)
	certificatePEM, privateKeyPEM := issuePublicationCertificate(t, f.tenant.domain)
	f.privateKey = privateKeyPEM
	imported, err := f.assets.Import(t.Context(), f.tenant.certificateActor, certificateasset.ImportRequest{
		TenantScopeID: f.tenant.scopeID, Name: "redelivery certificate", Source: certificateasset.SourceUploaded,
		CertificatePEM: certificatePEM, PrivateKeyPEM: privateKeyPEM,
		IdempotencyKey: "redelivery-import", RequestID: uuid.NewString()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.assets.Activate(t.Context(), f.tenant.certificateActor, certificateasset.ActivateRequest{
		TenantScopeID: f.tenant.scopeID, AssetID: imported.Asset.ID, VersionID: imported.Version.ID,
		ExpectedRevision: imported.Asset.Revision, IdempotencyKey: "redelivery-activate", RequestID: uuid.NewString()}); err != nil {
		t.Fatal(err)
	}
	if f.binding, err = f.assets.Bind(t.Context(), f.tenant.certificateActor, certificateasset.BindRequest{
		TenantScopeID: f.tenant.scopeID, SiteID: f.tenant.siteID, AssetID: imported.Asset.ID,
		// Default: the binding the site configuration serves (site runtime v2).
		VersionID: imported.Version.ID, Default: true, IdempotencyKey: "redelivery-bind", RequestID: uuid.NewString()}); err != nil {
		t.Fatal(err)
	}
	// The user's publication reaches node A only (B joins later).
	actor, deploymentStore := seedPublicationDeploymentActor(t, pool)
	publisherStore, err := edgedeployment.NewCertificatePublisherStore(deploymentStore, NewActorRevalidator())
	if err != nil {
		t.Fatal(err)
	}
	signer := &integrationPublicationSigner{}
	if _, signer.private, err = ed25519.GenerateKey(rand.Reader); err != nil {
		t.Fatal(err)
	}
	if f.producer, err = NewProducer(signer); err != nil {
		t.Fatal(err)
	}
	service, err := NewPublicationService(pool, f.assets, publisherStore, f.producer, DefaultPublicationConfig())
	if err != nil {
		t.Fatal(err)
	}
	published, err := service.Publish(t.Context(), publicationIntegrationRequest(t, pool, actor, f.tenant,
		[]publicationNode{f.nodeA}, f.binding, "redelivery-user-publication"))
	if err != nil {
		t.Fatal(err)
	}
	if f.status, err = edgestatus.NewStoreWithClock(pool, clock.now); err != nil {
		t.Fatal(err)
	}
	f.project(t, published.Rollout.Deployments[0], true)
	// The binding's publication intent settled (the worker would mark it).
	f.exec(t, `INSERT INTO certificate_publication_intent_state_facts(tenant_scope_id,site_id,binding_revision,sequence,state,
		attempt,idempotency_key,failure_code,occurred_at)
		SELECT tenant_scope_id,site_id,binding_revision,2,'permanent_failed',1,
		  'certificate.publication/'||tenant_scope_id||'/'||site_id||'/'||binding_revision,'legacy_reissue_required',
		  transaction_timestamp()
		FROM certificate_publication_intents WHERE tenant_scope_id=$1`, f.tenant.scopeID)
	// The scope publishes site configuration (node_sync republication target).
	f.exec(t, `INSERT INTO edge_configuration_scopes(scope_id,source_revision,updated_at) VALUES($1,1,now())
		ON CONFLICT DO NOTHING`, f.tenant.scopeID)
	if f.rollouts, err = edgedeployment.NewStoreWithClockAndAuditor(pool, clock.now, audit.New(pool)); err != nil {
		t.Fatal(err)
	}
	f.serving = []uuid.UUID{f.nodeA.id}
	f.ready[f.nodeA.id] = true
	return f
}
func (f *redeliveryFixture) exec(t *testing.T, query string, args ...any) {
	t.Helper()
	if _, err := f.pool.Exec(t.Context(), query, args...); err != nil {
		t.Fatal(err)
	}
}

func (f *redeliveryFixture) count(t *testing.T, query string, args ...any) int {
	t.Helper()
	var value int
	if err := f.pool.QueryRow(t.Context(), query, args...).Scan(&value); err != nil {
		t.Fatal(err)
	}
	return value
}

// newRedeliverer is the production redeliverer with the fixture's node
// selection; a new one has no memory (another process, a restart).
func (f *redeliveryFixture) newRedeliverer(t *testing.T) *Redeliverer {
	t.Helper()
	retrier := edgeautopublish.NewNodeSyncRetrier(f.pool)
	config := DefaultRedelivererConfig()
	config.RetryBase, config.RetryMaximum = time.Second, 4*time.Second
	redeliverer, err := NewRedeliverer(f.pool, f.assets, &capturingRolloutStore{Store: f.rollouts, created: f.created},
		f.producer,
		func(_ context.Context, _ pgx.Tx, scopeID uuid.UUID, siteIDs []uuid.UUID) (map[uuid.UUID][]uuid.UUID, error) {
			if scopeID != f.tenant.scopeID || !slices.Equal(siteIDs, []uuid.UUID{f.tenant.siteID}) {
				t.Errorf("site nodes asked for scope %s sites %v", scopeID, siteIDs)
			}
			return map[uuid.UUID][]uuid.UUID{f.tenant.siteID: slices.Clone(f.serving)}, nil
		},
		func(_ context.Context, _ pgx.Tx, nodeID uuid.UUID, _ time.Time) (bool, error) {
			return f.ready[nodeID], nil
		},
		func(ctx context.Context, nodeID, scopeID uuid.UUID, notBefore time.Time) (bool, error) {
			f.synced = append(f.synced, nodeID)
			return retrier.RetryNodeSync(ctx, nodeID, scopeID, notBefore)
		}, nil, config, f.clock.now)
	if err != nil {
		t.Fatal(err)
	}
	return redeliverer
}

func (f *redeliveryFixture) sweep(t *testing.T, redeliverer *Redeliverer) RedeliverySweep {
	t.Helper()
	result, err := redeliverer.SweepOnce(t.Context())
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	return result
}

// project reports the deployment's outcome as its node would, at the
// fixture's time.
func (f *redeliveryFixture) project(t *testing.T, deployment edgedeployment.Deployment, healthy bool) {
	t.Helper()
	states := []agentv1.NodeDeploymentState{agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STAGED, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_PRECHECKED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ACTIVATED, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY}
	if !healthy {
		states = []agentv1.NodeDeploymentState{agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED}
	}
	for index, state := range states {
		causationID := deployment.Command.Event.EventId
		status := &agentv1.DeploymentStatus{
			Event: &commonv1.EventMetadata{EventId: uuid.NewString(), RequestId: deployment.Command.Event.RequestId,
				OccurredTime: timestamppb.New(f.clock.now()), CausationId: &causationID,
				CorrelationId: deployment.Command.Event.CorrelationId},
			DeploymentId: deployment.ID.String(), Attempt: 1, ConfigVersionId: deployment.Command.ConfigVersionId,
			State: state, TransitionSequence: uint64(index + 1),
		}
		if state == agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED {
			status.RunningConfigUnchanged = true
			status.Error = &commonv1.ProtocolError{Code: commonv1.ErrorCode_ERROR_CODE_UNAVAILABLE,
				Message: "injected certificate activation failure"}
		}
		payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(status)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(payload)
		result, err := f.status.Project(t.Context(), edgestatus.Envelope{NodeID: deployment.NodeID,
			DeploymentID: deployment.ID, ConfigID: uuid.MustParse(status.ConfigVersionId),
			EventID: uuid.MustParse(status.Event.EventId), RequestID: uuid.MustParse(status.Event.RequestId),
			Status: status, Payload: payload, Digest: digest})
		if err != nil || result.Outcome != edgestatus.OutcomeAdvanced {
			t.Fatalf("project %s: result=%+v error=%v", state, result, err)
		}
	}
}

// delivered is the one rollout the sweep created, checked against the node
// and the site's current binding.
func (f *redeliveryFixture) delivered(t *testing.T, result RedeliverySweep, node publicationNode) edgedeployment.Rollout {
	t.Helper()
	if len(result.Rollouts) != 1 {
		t.Fatalf("rollouts created = %v, want one for node %s", result.Rollouts, node.id)
	}
	rollout, ok := f.created[result.Rollouts[0]]
	if !ok || len(rollout.Deployments) != 1 || rollout.Deployments[0].NodeID != node.id {
		t.Fatalf("rollout %s = %+v, want one deployment to %s", result.Rollouts[0], rollout, node.id)
	}
	// The node's artifact carries the site's key, sealed to the node.
	assertPublicationArtifacts(t, f.pool, rollout, []publicationNode{node}, f.privateKey)
	var raw []byte
	var key string
	if err := f.pool.QueryRow(t.Context(), `SELECT version.canonical_snapshot,rollout.idempotency_key
		FROM rollouts rollout JOIN config_versions version ON version.id=rollout.config_version_id
		WHERE rollout.id=$1`, rollout.ID).Scan(&raw, &key); err != nil {
		t.Fatal(err)
	}
	var snapshot publicationSnapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Certificates) != 1 || snapshot.Certificates[0].SiteID != f.tenant.siteID.String() ||
		snapshot.Certificates[0].CertificateVersionID != f.binding.VersionID.String() ||
		snapshot.Certificates[0].BindingRevision != f.binding.Revision || len(key) < len(redeliveryIdempotencyPrefix) ||
		key[:len(redeliveryIdempotencyPrefix)] != redeliveryIdempotencyPrefix {
		t.Fatalf("redelivery snapshot = %+v key %q, want site %s version %s revision %d", snapshot, key,
			f.tenant.siteID, f.binding.VersionID, f.binding.Revision)
	}
	if got := f.count(t, `SELECT count(*) FROM audit_events WHERE scope_id=$1 AND action=$2 AND actor_kind='system'
		AND actor_user_id IS NULL AND resource_id=$3 AND payload->>'rollout_id'=$4`, f.tenant.scopeID,
		auditRedeliveryDeliver, node.id.String(), rollout.ID.String()); got != 1 {
		t.Fatalf("system audit of the redelivery = %d", got)
	}
	return rollout
}

// ① A node that joined the site's line group after the binding was
// published gets the site's certificate once it is ready; ③ the node that
// holds a healthy bundle (A) is never sent one; ④ a round in flight is not
// created again (by this process after its backoff, nor by another one); the
// confirmed delivery republishes the scope to the node once (node_sync).
func TestCertificateRedeliveryReachesNodeThatJoinedTheLineGroup(t *testing.T) {
	f := newRedeliveryFixture(t)
	redeliverer := f.newRedeliverer(t)
	if result := f.sweep(t, redeliverer); len(result.Rollouts) != 0 || result.Synced != 0 {
		t.Fatalf("BUG node A holds the certificate and was sent it again: %+v", result)
	}
	// B joins the site's line group, still offline: wait, no failed round.
	f.serving = []uuid.UUID{f.nodeA.id, f.nodeB.id}
	if result := f.sweep(t, redeliverer); len(result.Rollouts) != 0 {
		t.Fatalf("offline node B was sent %v", result.Rollouts)
	}
	f.ready[f.nodeB.id] = true
	rollout := f.delivered(t, f.sweep(t, redeliverer), f.nodeB)

	// In flight: past the backoff, and from a process with no memory, no second rollout.
	f.clock.advance(5 * time.Second)
	if result := f.sweep(t, redeliverer); len(result.Rollouts) != 0 || result.Synced != 0 {
		t.Fatalf("BUG in-flight redelivery created again: %+v", result)
	}
	if result := f.sweep(t, f.newRedeliverer(t)); len(result.Rollouts) != 0 {
		t.Fatalf("BUG another process created the in-flight redelivery again: %+v", result)
	}

	// B confirms: the scope is republished to B once (node_sync), nothing is sent again.
	f.clock.advance(time.Second)
	f.project(t, rollout.Deployments[0], true)
	f.clock.advance(time.Second)
	result := f.sweep(t, redeliverer)
	if len(result.Rollouts) != 0 || result.Synced != 1 || !slices.Equal(f.synced, []uuid.UUID{f.nodeB.id}) {
		t.Fatalf("after B confirmed: %+v synced %v, want one node_sync republication to B", result, f.synced)
	}
	if got := f.count(t, `SELECT count(*) FROM edge_system_republication_heads WHERE scope_id=$1
		AND 'node_sync'=ANY(triggers)`, f.tenant.scopeID); got != 1 {
		t.Fatalf("node_sync republications queued = %d", got)
	}
	f.clock.advance(5 * time.Second)
	if result := f.sweep(t, redeliverer); len(result.Rollouts) != 0 || result.Synced != 0 {
		t.Fatalf("BUG B holds the certificate and was sent or republished again: %+v", result)
	}
}

// ② "重装此节点" and reset-node-host-delivery: the same node ID enrolls a new
// host (a newer initial certificate); what the previous host held does not
// count (edgedeployment.CurrentHostDeployment), so the next sweep sends the
// certificate again; node A is untouched.
func TestCertificateRedeliveryAfterReinstallUnderTheSameNodeID(t *testing.T) {
	f := newRedeliveryFixture(t)
	f.serving = []uuid.UUID{f.nodeA.id, f.nodeB.id}
	f.ready[f.nodeB.id] = true
	f.seedInitialEnrollment(t, f.nodeB.id, f.clock.now().Add(-time.Hour))
	redeliverer := f.newRedeliverer(t)
	first := f.delivered(t, f.sweep(t, redeliverer), f.nodeB)
	f.clock.advance(time.Second)
	f.project(t, first.Deployments[0], true)
	f.clock.advance(time.Second)
	if result := f.sweep(t, redeliverer); len(result.Rollouts) != 0 {
		t.Fatalf("B holds the certificate, sent again: %+v", result)
	}

	// The node is reinstalled: a new host enrolls under the same ID, then the
	// operator runs reset-node-host-delivery (nodeidentity.ResetReinstalledHost).
	f.clock.advance(time.Minute)
	f.seedInitialEnrollment(t, f.nodeB.id, f.clock.now())
	if _, err := nodeidentity.NewStore(f.pool).ResetReinstalledHost(t.Context(), f.nodeB.id, "certificate-redelivery-reset"); err != nil {
		t.Fatalf("reset-node-host-delivery: %v", err)
	}
	f.clock.advance(time.Second)
	redeliverer = f.newRedeliverer(t)
	second := f.delivered(t, f.sweep(t, redeliverer), f.nodeB)
	if second.ID == first.ID {
		t.Fatal("BUG the reinstalled host was given the previous host's rollout")
	}
}

// A failed round backs off (no rollout per sweep) and is retried after it.
func TestCertificateRedeliveryFailedRoundBacksOff(t *testing.T) {
	f := newRedeliveryFixture(t)
	f.serving = []uuid.UUID{f.nodeA.id, f.nodeB.id}
	f.ready[f.nodeB.id] = true
	redeliverer := f.newRedeliverer(t)
	first := f.delivered(t, f.sweep(t, redeliverer), f.nodeB)
	f.project(t, first.Deployments[0], false)
	if result := f.sweep(t, redeliverer); len(result.Rollouts) != 0 {
		t.Fatalf("BUG failed round retried within its backoff: %+v", result)
	}
	f.clock.advance(1500 * time.Millisecond)
	retry := f.delivered(t, f.sweep(t, redeliverer), f.nodeB)
	if retry.ID == first.ID {
		t.Fatal("retry reused the failed rollout")
	}
	// The second failure waits twice as long.
	f.project(t, retry.Deployments[0], false)
	f.clock.advance(1500 * time.Millisecond)
	if result := f.sweep(t, redeliverer); len(result.Rollouts) != 0 {
		t.Fatalf("BUG second failure retried after the first backoff: %+v", result)
	}
	f.clock.advance(time.Second)
	if result := f.sweep(t, redeliverer); len(result.Rollouts) != 1 {
		t.Fatalf("second retry not made after its backoff: %+v", result)
	}
}

// The backoff is in memory, per scope and node ID;
// a reinstall keeps the ID, so a node (an hour of backoff from failed rounds of
// the old agent) got their certificates 35-60 minutes after the new host
// enrolled. A newer enrollment of the node starts its backoff over, in the
// same process: the new host is tried at the next sweep.
func TestCertificateRedeliveryReinstallResetsTheBackoff(t *testing.T) {
	f := newRedeliveryFixture(t)
	f.serving = []uuid.UUID{f.nodeA.id, f.nodeB.id}
	f.ready[f.nodeB.id] = true
	f.seedInitialEnrollment(t, f.nodeB.id, f.clock.now().Add(-time.Hour))
	redeliverer := f.newRedeliverer(t)
	first := f.delivered(t, f.sweep(t, redeliverer), f.nodeB)
	f.project(t, first.Deployments[0], false)
	f.clock.advance(1500 * time.Millisecond)
	retry := f.delivered(t, f.sweep(t, redeliverer), f.nodeB)
	f.project(t, retry.Deployments[0], false)
	f.clock.advance(100 * time.Millisecond)
	if result := f.sweep(t, redeliverer); len(result.Rollouts) != 0 {
		t.Fatalf("failed round retried within its backoff: %+v", result)
	}
	// "重装此节点": a new host enrolls under the same node ID
	f.seedInitialEnrollment(t, f.nodeB.id, f.clock.now())
	f.clock.advance(100 * time.Millisecond)
	reinstalled := f.delivered(t, f.sweep(t, redeliverer), f.nodeB)
	if reinstalled.ID == retry.ID || reinstalled.ID == first.ID {
		t.Fatal("the reinstalled host was given a previous rollout")
	}
	// its own failure backs off from the start (one base delay), not from
	// the previous host's count
	f.project(t, reinstalled.Deployments[0], false)
	f.clock.advance(1500 * time.Millisecond)
	if result := f.sweep(t, redeliverer); len(result.Rollouts) != 1 {
		t.Fatalf("the new host's first failure did not back off from the base delay: %+v", result)
	}
}

// Once the redelivery carried the certificates
// to the reinstalled nodes the console still showed the four publications permanent_failed
// (the redeliverer never wrote the intent state); the operator had to bind
// each site again. A failed publication whose binding every serving node now
// holds through a redelivery is settled as succeeded, naming that rollout
// (migration 650), once; the status store reads it back.
func TestCertificateRedeliverySettlesTheFailedPublication(t *testing.T) {
	f := newRedeliveryFixture(t)
	latest := func() (string, *uuid.UUID) {
		var state string
		var recovered *uuid.UUID
		if err := f.pool.QueryRow(t.Context(), `SELECT state,recovered_by_rollout_id FROM certificate_publication_intent_state_facts
			WHERE tenant_scope_id=$1 AND site_id=$2 ORDER BY binding_revision DESC,sequence DESC LIMIT 1`,
			f.tenant.scopeID, f.tenant.siteID).Scan(&state, &recovered); err != nil {
			t.Fatal(err)
		}
		return state, recovered
	}
	f.serving = []uuid.UUID{f.nodeA.id, f.nodeB.id}
	f.ready[f.nodeB.id] = true
	redeliverer := f.newRedeliverer(t)
	rollout := f.delivered(t, f.sweep(t, redeliverer), f.nodeB)
	if state, _ := latest(); state != "permanent_failed" {
		t.Fatalf("settled before node B held the certificate: %s", state)
	}
	f.clock.advance(time.Second)
	f.project(t, rollout.Deployments[0], true)
	f.clock.advance(time.Second)
	f.sweep(t, redeliverer)
	state, recovered := latest()
	if state != "succeeded" || recovered == nil || *recovered != rollout.ID {
		t.Fatalf("after every node held the certificate: %s recovered by %v, want succeeded by %s", state, recovered, rollout.ID)
	}
	f.clock.advance(5 * time.Second)
	f.sweep(t, redeliverer)
	if got := f.count(t, `SELECT count(*) FROM certificate_publication_intent_state_facts WHERE tenant_scope_id=$1
		AND state='succeeded'`, f.tenant.scopeID); got != 1 {
		t.Fatalf("succeeded facts = %d, want one", got)
	}
	statuses, err := certificateasset.NewPublicationStatusStore(f.pool)
	if err != nil {
		t.Fatal(err)
	}
	page, err := statuses.List(t.Context(), f.tenant.certificateActor, f.tenant.scopeID, certificateasset.PublicationStatusFilter{},
		certificateasset.PublicationStatusCursor{}, 10)
	if err != nil || len(page.Items) == 0 || page.Items[0].State != "succeeded" || page.Items[0].RecoveredByRolloutID == nil ||
		*page.Items[0].RecoveredByRolloutID != rollout.ID || page.Items[0].RolloutID != nil {
		t.Fatalf("status store: %+v %v", page.Items, err)
	}
	// a hand-written recovery naming a rollout that is no redelivery is refused (657 trigger)
	_, err = f.pool.Exec(t.Context(), `INSERT INTO certificate_publication_intent_state_facts(tenant_scope_id,site_id,
		binding_revision,sequence,state,attempt,idempotency_key,lease_owner,lease_token,lease_expires_at,occurred_at,
		recovered_by_rollout_id)
		SELECT tenant_scope_id,site_id,binding_revision,sequence+1,'succeeded',attempt,idempotency_key,
		  'certificate-redelivery',gen_random_uuid(),transaction_timestamp(),transaction_timestamp(),gen_random_uuid()
		FROM certificate_publication_intent_state_facts WHERE tenant_scope_id=$1 ORDER BY sequence DESC LIMIT 1`,
		f.tenant.scopeID)
	if err == nil {
		t.Fatal("a recovery after succeeded, or naming no redelivery rollout, was accepted")
	}
}

// seedInitialEnrollment records an initial node certificate issued at
// issuedAt (the enrollment of a host); FKs are off while seeding.
func (f *redeliveryFixture) seedInitialEnrollment(t *testing.T, nodeID uuid.UUID, issuedAt time.Time) {
	t.Helper()
	certificateID := uuid.New()
	digest := sha256.Sum256(certificateID[:])
	if err := pgx.BeginFunc(t.Context(), f.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO node_certificates(id,node_id,issuance_kind,enrollment_authorization_id,
			serial_number,csr_sha256,certificate_public_key_sha256,uri_san,not_before,not_after,renewal_at,
			leaf_certificate_pem,issuing_chain_pem,leaf_certificate_sha256,status,issued_at)
			VALUES($1,$2,'initial',$3,$4,$5,$5,$6,$7,$7::timestamptz+interval '2 days',$7::timestamptz+interval '1 day',
			  'test',ARRAY['test'::bytea],$5,'active',$7)`, certificateID, nodeID, uuid.New(),
			hex.EncodeToString(digest[:8]), digest[:], "spiffe://cdn-platform/node/"+nodeID.String(), issuedAt)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// The redeliverer's batched site → nodes read is the renewal's per-site
// selection (edgeautopublish.SiteTargetNodeIDsTx), site by site.
func TestSitesTargetNodeIDsMatchesSiteTargetNodeIDs(t *testing.T) {
	pool := openPublicationIntegrationDatabase(t)
	tenant := seedPublicationTenant(t, pool)
	nodeA := seedPublicationNode(t, pool, tenant.scopeID, tenant.userID)
	nodeB := seedPublicationNode(t, pool, tenant.scopeID, tenant.userID)
	seedPublicationNode(t, pool, tenant.scopeID, tenant.userID) // in no line group
	groupID, unserved := uuid.New(), uuid.New()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO node_line_groups(id,tenant_scope_id,name,current_revision,created_by_user_id,updated_by_user_id,created_at,updated_at)
			VALUES($1,$2,'redelivery-group',1,$3,$3,now(),now())`, []any{groupID, tenant.scopeID, tenant.userID}},
		{`INSERT INTO node_line_group_revisions(line_group_id,tenant_scope_id,revision,name,resolved_value,probe_interval_ms,probe_timeout_ms,
			failure_threshold,recovery_threshold,failure_debounce_ms,recovery_debounce_ms,endpoint_count,configuration_digest,created_by_user_id,created_at)
			VALUES($1,$2,1,'redelivery-group','lg-'||replace($1::uuid::text,'-',''),10000,3000,3,3,0,0,2,$3,$4,now())`,
			[]any{groupID, tenant.scopeID, make([]byte, 32), tenant.userID}},
		{`INSERT INTO node_line_endpoints(id,node_id,tenant_scope_id,line_group_id,config_revision,address,address_family,port,region,carrier,priority,weight,enabled)
			VALUES($1,$2,$3,$4,1,'192.0.2.71',4,443,'','',0,1,true)`, []any{uuid.New(), nodeA.id, tenant.scopeID, groupID}},
		{`INSERT INTO node_line_endpoints(id,node_id,tenant_scope_id,line_group_id,config_revision,address,address_family,port,region,carrier,priority,weight,enabled)
			VALUES($1,$2,$3,$4,1,'192.0.2.72',4,443,'','',0,1,true)`, []any{uuid.New(), nodeB.id, tenant.scopeID, groupID}},
		{`INSERT INTO node_line_endpoint_health(tenant_scope_id,line_group_id,config_revision,endpoint_id,status,consecutive_successes,
			consecutive_failures,last_sequence,last_changed_at,row_revision,created_at,updated_at)
			SELECT $1,$2,1,id,'unknown',0,0,0,now(),1,now(),now() FROM node_line_endpoints WHERE tenant_scope_id=$1 AND line_group_id=$2`,
			[]any{tenant.scopeID, groupID}},
		{`UPDATE node_line_group_revisions SET sealed_at=now() WHERE tenant_scope_id=$1 AND line_group_id=$2 AND revision=1`,
			[]any{tenant.scopeID, groupID}},
		{`UPDATE sites SET node_group_id=$2 WHERE id=$1`, []any{tenant.siteID, groupID}},
		{`INSERT INTO sites(id,display_id,scope_id,owner_user_id,domain,origins,origin_hosts,created_by_user_id,updated_by_user_id)
			VALUES($1,(SELECT COALESCE(max(display_id),0)+1 FROM sites WHERE scope_id=$2),$2,$3,'unserved.example.test',
			ARRAY['origin.example.test:443'],ARRAY['origin.example.test'],$3,$3)`, []any{unserved, tenant.scopeID, tenant.userID}},
		{`INSERT INTO site_origin_pools(site_id) VALUES($1)`, []any{unserved}},
		{`INSERT INTO site_origins(site_id,position,host,port) VALUES($1,1,'origin.example.test',443)`, []any{unserved}},
	}
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		for _, statement := range statements {
			if _, err := tx.Exec(t.Context(), statement.query, statement.args...); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		batched, err := edgeautopublish.SitesTargetNodeIDsTx(t.Context(), tx, tenant.scopeID, []uuid.UUID{tenant.siteID, unserved})
		if err != nil {
			return err
		}
		for _, siteID := range []uuid.UUID{tenant.siteID, unserved} {
			single, err := edgeautopublish.SiteTargetNodeIDsTx(t.Context(), tx, tenant.scopeID, siteID)
			if err != nil {
				return err
			}
			if !slices.Equal(batched[siteID], single) {
				t.Errorf("site %s: batched %v, per site %v", siteID, batched[siteID], single)
			}
		}
		want := []uuid.UUID{nodeA.id, nodeB.id}
		slices.SortFunc(want, compareRenewalUUID)
		if !slices.Equal(batched[tenant.siteID], want) || len(batched[unserved]) != 0 || len(batched) != 1 {
			t.Errorf("batched = %v, want %s -> %v only", batched, tenant.siteID, want)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// A node offline, or online without a usable identity, is not ready (a
// wait, not an error).
func TestRedeliveryNodeReadyTx(t *testing.T) {
	pool := openPublicationIntegrationDatabase(t)
	tenant := seedPublicationTenant(t, pool)
	node := seedPublicationNode(t, pool, tenant.scopeID, tenant.userID)
	check := func(want bool) {
		t.Helper()
		if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
			ready, err := RedeliveryNodeReadyTx(t.Context(), tx, node.id, time.Now().UTC())
			if err != nil || ready != want {
				t.Errorf("ready = %t, %v; want %t", ready, err, want)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	check(false) // no presence
	digest := sha256.Sum256(node.id[:])
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO node_presence(
			node_id,status,session_epoch,heartbeat_sequence,event_id,request_id,payload_digest,occurred_at,projected_at,
			last_seen_at,confirmed_session_epoch,confirmed_heartbeat_sequence,confirmed_event_id,confirmed_request_id,
			confirmed_payload_digest,online_since,openresty_state,firewall_state,
			filesystem_total_bytes,filesystem_available_bytes,cache_used_bytes,updated_at)
			VALUES($1,'online',1,1,$2,$3,$4,clock_timestamp(),clock_timestamp(),clock_timestamp(),1,1,$2,$3,$4,
			  clock_timestamp(),'running','running',100,50,0,clock_timestamp())`, node.id, uuid.New(), uuid.New(), digest[:])
		return err
	}); err != nil {
		t.Fatal(err)
	}
	check(false) // online, no node certificate
}
