package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/deployment"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/eventspool"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/gatewayclient"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/telemetryclient"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
)

// (22 access events of config version
// 850c25fa): the first apply's rollback failed while its generation kept
// serving. The agent that ran it left a scope journal with only that result
// (no current, previous or pending release), and the node's artifact store
// no longer serves the command's artifacts, so no agent can rebuild the
// release. The records go only when both sides allow it: the operator
// reconciles the scope with the source deployment's own version (the
// Gateway's authorization then carries it) and the tenant publishes again
// (the new release is current, its sites map to the scope, and its command
// names the reconciled version as the previous one). The records keep their
// own config version: the new current's site mapping releases them.

const (
	heldTestNode   = "44444444-4444-4444-8444-444444444444"
	heldTestTenant = "7e000000-0000-4000-8000-000000000001"
	heldTestSite   = "a0000000-0000-4000-8000-0000000000aa"
	heldTestFailed = "850c25fa-0000-4000-8000-000000000001" // the rollback_failed apply's version
	heldTestEvents = 22
)

type heldTestGateway struct {
	agentv1.UnimplementedAgentGatewayServiceServer
	authorized func(configVersionID string) bool
	mu         sync.Mutex
	batches    []*agentv1.TelemetryBatch
	rejected   int
}

func (g *heldTestGateway) StreamTelemetry(stream grpc.BidiStreamingServer[agentv1.StreamTelemetryRequest, agentv1.StreamTelemetryResponse]) error {
	if _, err := stream.Recv(); err != nil {
		return err
	}
	meta := func(sequence uint64) *commonv1.StreamMetadata {
		return &commonv1.StreamMetadata{MessageId: uuid.NewString(), Sequence: sequence, SentTime: timestamppb.Now()}
	}
	if err := stream.Send(&agentv1.StreamTelemetryResponse{Stream: meta(1), Payload: &agentv1.StreamTelemetryResponse_Hello{
		Hello: &agentv1.TelemetryGatewayHello{SelectedProtocolVersion: &commonv1.ProtocolVersion{Major: 1}, GatewayVersion: "test",
			ServerTime: timestamppb.Now(), MaximumRecordsPerBatch: 64, MaximumRecordBytes: 1 << 20, MaximumBatchBytes: 4 << 20,
			MaximumInflightBatches: 1, ScopedRecords: true}}}); err != nil {
		return err
	}
	for sequence := uint64(2); ; sequence++ {
		request, err := stream.Recv()
		if err != nil {
			return err
		}
		batch := request.GetBatch()
		g.mu.Lock()
		g.batches = append(g.batches, batch)
		for _, record := range batch.GetRecords() {
			if !g.authorized(heldTestRecordVersion(record)) {
				// The Gateway refuses a config version its node authorization
				// does not carry.
				g.rejected++
				g.mu.Unlock()
				return status.Error(codes.InvalidArgument, "telemetry record config version is not authorized")
			}
		}
		g.mu.Unlock()
		last := batch.Records[len(batch.Records)-1]
		if err := stream.Send(&agentv1.StreamTelemetryResponse{Stream: meta(sequence), Payload: &agentv1.StreamTelemetryResponse_Ack{
			Ack: &agentv1.TelemetryAck{BatchId: batch.BatchId, AcceptedRecordCount: uint32(len(batch.Records)),
				AcceptedThroughSequence: last.LastSequence, AcceptedThroughMessageId: last.MessageId,
				AcceptedThroughEventId: last.LastEventId, AcceptedTime: timestamppb.Now()}}}); err != nil {
			return err
		}
	}
}

func heldTestRecordVersion(record *agentv1.TelemetryRecord) string {
	var envelope struct {
		Events []struct {
			ConfigVersionID string `json:"config_version_id"`
		} `json:"events"`
	}
	if json.Unmarshal(record.GetPayload(), &envelope) != nil || len(envelope.Events) == 0 {
		return ""
	}
	return envelope.Events[0].ConfigVersionID
}

func (g *heldTestGateway) sent() ([]*agentv1.TelemetryBatch, int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]*agentv1.TelemetryBatch(nil), g.batches...), g.rejected
}

type heldTestDialer struct{ listener *bufconn.Listener }

type heldTestConnection struct{ connection *grpc.ClientConn }

func (c *heldTestConnection) Client() agentv1.AgentGatewayServiceClient {
	return agentv1.NewAgentGatewayServiceClient(c.connection)
}

func (c *heldTestConnection) Close() error { return c.connection.Close() }

func (d *heldTestDialer) Dial(context.Context) (telemetryclient.Connection, error) {
	connection, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return d.listener.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	return &heldTestConnection{connection: connection}, nil
}

// heldTestPipeline is the daemon's telemetry wiring (assembleTelemetryPipeline):
// a scoped client resolving sites and held versions through manager. The
// spool holds the 22 events of the held version, then one access event per
// version in after (sequences 23, 24, ...).
func heldTestPipeline(t *testing.T, manager *dynamicRoutingManager, gateway *heldTestGateway, after ...string) (*eventspool.Spool, *telemetryclient.Publisher) {
	t.Helper()
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	agentv1.RegisterAgentGatewayServiceServer(server, gateway)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { server.Stop(); _ = listener.Close() })

	root, _ := filepath.EvalSymlinks(t.TempDir())
	now := time.Now().UTC().Truncate(time.Second)
	spool, err := eventspool.New(eventspool.Config{Root: filepath.Join(root, "spool"), MaxEventBytes: 64 << 10, MaxSegmentBytes: 16 << 20,
		SoftLimitBytes: 1 << 30, HardLimitBytes: 2 << 30, MaxTenantBytes: 1 << 30, MaxBatchEvents: 10000,
		PressureMode: eventspool.PressureBackpressure, SoftAgeLimit: 24 * time.Hour, HardAgeLimit: 168 * time.Hour,
		Now: func() time.Time { return now.Add(time.Minute) }})
	if err != nil {
		t.Fatal(err)
	}
	events := make([]eventspool.Envelope, 0, heldTestEvents)
	for i := 0; i < heldTestEvents; i++ {
		events = append(events, eventspool.Envelope{SchemaVersion: eventspool.SchemaVersion, Type: eventspool.EventAccess,
			EventID: fmt.Sprintf("evt-%d", i), OccurredAt: now, TenantID: heldTestTenant, SiteID: heldTestSite, NodeID: heldTestNode,
			ConfigVersionID: heldTestFailed, RequestID: fmt.Sprintf("r%d", i), Host: "a.example.test", Path: "/",
			ClientIP: "198.51.100.7", Method: "GET", Protocol: "HTTP/1.1", CacheStatus: "MISS", StatusCode: 200, ResponseBytes: 512})
	}
	for i, version := range after {
		events = append(events, eventspool.Envelope{SchemaVersion: eventspool.SchemaVersion, Type: eventspool.EventAccess,
			EventID: fmt.Sprintf("evt-after-%d", i), OccurredAt: now, TenantID: heldTestTenant, SiteID: heldTestSite, NodeID: heldTestNode,
			ConfigVersionID: version, RequestID: fmt.Sprintf("after-%d", i), Host: "a.example.test", Path: "/",
			ClientIP: "198.51.100.7", Method: "GET", Protocol: "HTTP/1.1", CacheStatus: "MISS", StatusCode: 200, ResponseBytes: 512})
	}
	if _, err := spool.AppendBatch(context.Background(), events); err != nil {
		t.Fatal(err)
	}
	config := telemetryclient.DefaultConfig()
	config.NodeID, config.BootID, config.Cursor = heldTestNode, uuid.NewString(), telemetryclient.NewDurableCursor(spool)
	config.HandshakeTimeout, config.AckTimeout = time.Second, time.Second
	config.InitialBackoff, config.MaximumBackoff = time.Millisecond, 100*time.Millisecond
	config.ScopedRecords, config.ScopeForSite, config.HeldVersion = true, manager.ScopeForSite, manager.HeldVersion
	client, err := telemetryclient.New(config, &heldTestDialer{listener: listener})
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := telemetryclient.NewPublisher(heldTestNode, client)
	if err != nil {
		t.Fatal(err)
	}
	return spool, publisher
}

// requireHeld: flushes find the queue held (transient, nothing sent or
// acknowledged, the Gateway sees no batch).
func requireHeld(t *testing.T, spool *eventspool.Spool, publisher *telemetryclient.Publisher, gateway *heldTestGateway, when string) {
	t.Helper()
	for attempt := 0; attempt < 3; attempt++ {
		result, err := spool.Flush(context.Background(), publisher, 1000)
		if !errors.Is(err, telemetryclient.ErrAttributionUnconfirmed) || result.Published != 0 {
			t.Fatalf("%s: flush = (%+v, %v), want the queue held (ErrAttributionUnconfirmed)", when, result, err)
		}
	}
	if stats, err := spool.Stats(); err != nil || stats.AckedSequence != 0 || stats.PendingEvents != heldTestEvents {
		t.Fatalf("%s: queue = (%+v, %v), want %d events pending, cursor 0", when, stats, err, heldTestEvents)
	}
	if batches, rejected := gateway.sent(); len(batches) != 0 || rejected != 0 {
		t.Fatalf("%s: gateway saw %d batches (%d rejected), want none", when, len(batches), rejected)
	}
}

// legacyRollbackFailedScope is an older agent's journal: the rollback_failed result
// only, written by an agent from before HeldVersions.
func legacyRollbackFailedScope(t *testing.T, manager *dynamicRoutingManager) {
	t.Helper()
	result := deployment.Result{DeploymentID: "d1330000-0000-4000-8000-000000000001", Attempt: 1, Action: deployment.ActionApply,
		ConfigVersionID: heldTestFailed, State: deployment.StateRollbackFailed, ErrorCode: "ROLLBACK_FAILED"}
	if err := manager.save(revisionTestScope, dynamicRoutingScope{
		Results: []dynamicRoutingResult{{DeploymentID: result.DeploymentID, Result: result}}}); err != nil {
		t.Fatal(err)
	}
}

// republish is the tenant's next publication of the same site; previous is
// its command's previous version (the reconciled one, or "" after a
// reconciliation that named no version).
func republish(t *testing.T, manager *dynamicRoutingManager, previous string) {
	t.Helper()
	digest, raw := dynamicTestSite(t, revisionTestScope, heldTestSite, "a.example.test")
	if err := manager.objects.Put(digest, raw); err != nil {
		t.Fatal(err)
	}
	release := revisionRelease(versionR2, 14, rootR2)
	release.PreviousConfigVersionID = previous
	release.Sites = map[string][]byte{digest: raw}
	manager.apply = (&fakeDynamicRuntime{}).apply
	if result := applyRevision(t, manager, "d1330000-0000-4000-8000-000000000002", release); result.State != deployment.StateHealthy {
		t.Fatalf("republish result = %+v, want healthy", result)
	}
	if scope, ok := manager.ScopeForSite(heldTestSite); !ok || scope != revisionTestScope {
		t.Fatalf("site after the republish maps to (%q, %v), want its scope", scope, ok)
	}
}

func requireReleasedInOrder(t *testing.T, spool *eventspool.Spool, publisher *telemetryclient.Publisher, gateway *heldTestGateway) {
	t.Helper()
	result, err := spool.Flush(context.Background(), publisher, 1000)
	if err != nil || result.Published != heldTestEvents {
		t.Fatalf("flush after the republish = (%+v, %v), want all %d events", result, err, heldTestEvents)
	}
	batches, rejected := gateway.sent()
	if rejected != 0 || len(batches) != 1 || batches[0].FirstSequence != 1 || batches[0].LastSequence != heldTestEvents {
		t.Fatalf("gateway saw %d batches (%d rejected), want one of sequences 1..%d", len(batches), rejected, heldTestEvents)
	}
	next := uint64(1)
	for _, record := range batches[0].Records {
		if record.FirstSequence != next || record.GetConfigurationScopeId() != revisionTestScope || heldTestRecordVersion(record) != heldTestFailed {
			t.Fatalf("record %d..%d scope %q version %q, want sequence %d of %s at its own version %s", record.FirstSequence,
				record.LastSequence, record.GetConfigurationScopeId(), heldTestRecordVersion(record), next, revisionTestScope, heldTestFailed)
		}
		next = record.LastSequence + 1
	}
	if next != heldTestEvents+1 {
		t.Fatalf("records end at %d, want %d", next-1, heldTestEvents)
	}
	if stats, err := spool.Stats(); err != nil || stats.AckedSequence != heldTestEvents || stats.PendingEvents != 0 {
		t.Fatalf("queue after the upload = (%+v, %v), want cursor %d", stats, err, heldTestEvents)
	}
}

// Operator reconciled with the source deployment's version, the tenant
// published again: the 22 records go in order at their own version.
func TestLegacyRollbackFailedRecordsGoAfterReconciliationAndRepublish(t *testing.T) {
	manager, _ := revisionTestManager(t)
	legacyRollbackFailedScope(t, manager)
	gateway := &heldTestGateway{authorized: func(version string) bool { return version == heldTestFailed || version == versionR2 }}
	spool, publisher := heldTestPipeline(t, manager, gateway)

	requireHeld(t, spool, publisher, gateway, "no current release")
	if !manager.HeldVersion(revisionTestScope, heldTestFailed) {
		t.Fatal("the legacy journal's rollback_failed version is not held")
	}
	republish(t, manager, heldTestFailed)
	if manager.HeldVersion(revisionTestScope, heldTestFailed) {
		t.Fatal("the version the republish names as previous is still held")
	}
	requireReleasedInOrder(t, spool, publisher, gateway)
}

// A reconciliation that named no version: the republish maps the site, but
// the control plane never confirmed the failed version, so the Gateway would
// refuse its records on every retry. They stay held and are not sent.
func TestLegacyRollbackFailedRecordsStayHeldAfterReconciliationWithoutVersion(t *testing.T) {
	manager, _ := revisionTestManager(t)
	legacyRollbackFailedScope(t, manager)
	gateway := &heldTestGateway{authorized: func(version string) bool { return version == versionR2 }}
	spool, publisher := heldTestPipeline(t, manager, gateway)

	republish(t, manager, "")
	requireHeld(t, spool, publisher, gateway, "republished without a reconciled version")
	if !manager.HeldVersion(revisionTestScope, heldTestFailed) || manager.HeldVersion(revisionTestScope, versionR2) {
		t.Fatal("held versions after the republish are wrong")
	}
}

// The new agent's path: the serving release is current with its mark; its
// records wait while the mark (and the held version) last, and go after the
// agent_observed reconciliation's republish.
func TestServingAfterRollbackFailureRecordsWaitForTheNextAcceptedRelease(t *testing.T) {
	manager, _ := revisionTestManager(t)
	digest, raw := dynamicTestSite(t, revisionTestScope, heldTestSite, "a.example.test")
	if err := manager.objects.Put(digest, raw); err != nil {
		t.Fatal(err)
	}
	manager.apply = rollbackFailedApply(1)
	manager.serves = func(_ context.Context, generation uint64) bool { return generation == 1 }
	failed := revisionRelease(heldTestFailed, 10, rootR1)
	failed.Sites = map[string][]byte{digest: raw}
	if result := applyRevision(t, manager, "d1330000-0000-4000-8000-000000000001", failed); result.State != deployment.StateRollbackFailed {
		t.Fatalf("result = %+v", result)
	}
	gateway := &heldTestGateway{authorized: func(version string) bool { return version == heldTestFailed || version == versionR2 }}
	spool, publisher := heldTestPipeline(t, manager, gateway)
	requireHeld(t, spool, publisher, gateway, "serving after the rollback failure")

	republish(t, manager, heldTestFailed)
	requireReleasedInOrder(t, spool, publisher, gateway)
}

// publishSite applies release carrying the held test site as healthy (a
// later publication of the tenant).
func publishSite(t *testing.T, manager *dynamicRoutingManager, deploymentID string, release gatewayclient.DynamicRoutingRelease) {
	t.Helper()
	digest, raw := dynamicTestSite(t, revisionTestScope, heldTestSite, "a.example.test")
	if err := manager.objects.Put(digest, raw); err != nil {
		t.Fatal(err)
	}
	release.Sites = map[string][]byte{digest: raw}
	manager.apply = (&fakeDynamicRuntime{}).apply
	if result := applyRevision(t, manager, deploymentID, release); result.State != deployment.StateHealthy {
		t.Fatalf("publication %s result = %+v, want healthy", deploymentID, result)
	}
}

// heldTestAccepted: the Gateway authorizes the versions listed, and later
// those added with confirm (the supplemental confirmation entering the
// node's authorization).
type heldTestAccepted struct {
	mu       sync.Mutex
	versions map[string]bool
}

func newHeldTestAccepted(versions ...string) *heldTestAccepted {
	accepted := &heldTestAccepted{versions: map[string]bool{}}
	accepted.confirm(versions...)
	return accepted
}

func (a *heldTestAccepted) confirm(versions ...string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, version := range versions {
		a.versions[version] = true
	}
}

func (a *heldTestAccepted) authorized(version string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.versions[version]
}

// requireQueueHeld: flushes find the whole queue held behind its head (the
// telemetry stream acknowledges contiguous sequences, so a record after a
// held one waits too): nothing sent, cursor 0.
func requireQueueHeld(t *testing.T, spool *eventspool.Spool, publisher *telemetryclient.Publisher, gateway *heldTestGateway, pending uint64, when string) {
	t.Helper()
	for attempt := 0; attempt < 3; attempt++ {
		result, err := spool.Flush(context.Background(), publisher, 1000)
		if !errors.Is(err, telemetryclient.ErrAttributionUnconfirmed) || result.Published != 0 {
			t.Fatalf("%s: flush = (%+v, %v), want the queue held (ErrAttributionUnconfirmed)", when, result, err)
		}
	}
	if stats, err := spool.Stats(); err != nil || stats.AckedSequence != 0 || uint64(stats.PendingEvents) != pending {
		t.Fatalf("%s: queue = (%+v, %v), want %d events pending, cursor 0", when, stats, err, pending)
	}
	if batches, rejected := gateway.sent(); len(batches) != 0 || rejected != 0 {
		t.Fatalf("%s: gateway saw %d batches (%d rejected), want none", when, len(batches), rejected)
	}
}

// requireSentInOrder: one flush sends every event, sequences 1..len(versions)
// in order, each at its own config version, and the cursor reaches the end.
func requireSentInOrder(t *testing.T, spool *eventspool.Spool, publisher *telemetryclient.Publisher, gateway *heldTestGateway, versions []string) {
	t.Helper()
	total := uint64(len(versions))
	result, err := spool.Flush(context.Background(), publisher, 1000)
	if err != nil || uint64(result.Published) != total {
		t.Fatalf("flush after the release = (%+v, %v), want all %d events", result, err, total)
	}
	batches, rejected := gateway.sent()
	if rejected != 0 || len(batches) == 0 {
		t.Fatalf("gateway saw %d batches (%d rejected)", len(batches), rejected)
	}
	next := uint64(1)
	for _, batch := range batches {
		for _, record := range batch.Records {
			var envelope struct {
				Events []struct {
					ConfigVersionID string `json:"config_version_id"`
				} `json:"events"`
			}
			if record.FirstSequence != next || record.GetConfigurationScopeId() != revisionTestScope ||
				json.Unmarshal(record.GetPayload(), &envelope) != nil ||
				uint64(len(envelope.Events)) != record.LastSequence-record.FirstSequence+1 {
				t.Fatalf("record %d..%d scope %q, want sequence %d of %s", record.FirstSequence, record.LastSequence,
					record.GetConfigurationScopeId(), next, revisionTestScope)
			}
			for _, event := range envelope.Events {
				if next > total || event.ConfigVersionID != versions[next-1] {
					t.Fatalf("event %d at version %q, want %q", next, event.ConfigVersionID, versions[min(next, total)-1])
				}
				next++
			}
		}
	}
	if next != total+1 {
		t.Fatalf("records end at %d, want %d", next-1, total)
	}
	if stats, err := spool.Stats(); err != nil || stats.AckedSequence != total || stats.PendingEvents != 0 {
		t.Fatalf("queue after the upload = (%+v, %v), want cursor %d", stats, err, total)
	}
}

// heldThenNew: the 22 held events, then one of the healthy republish.
func heldThenNew() []string {
	versions := make([]string, 0, heldTestEvents+1)
	for range heldTestEvents {
		versions = append(versions, heldTestFailed)
	}
	return append(versions, versionR2)
}

// The operator reconciled
// the scope without a version; the automatic publication then reached the node
// and activated (previous none). The node keeps 22 records of the held
// version and one normal record of the new release behind them; while the
// version is held the whole queue waits (cursor 0, nothing sent), the new
// record included. The supplemental confirmation puts the old version in the
// Gateway's authorization (and nothing else: other versions stay refused). A
// command that does not list it keeps the queue held; the next apply command
// listing it in released_config_version_ids lets 1..23 go in order, cursor 23.
func TestHeldRecordsGoWhenALaterCommandListsTheSupplementedVersion(t *testing.T) {
	manager, _ := revisionTestManager(t)
	legacyRollbackFailedScope(t, manager)
	accepted := newHeldTestAccepted(versionR2, versionR3)
	gateway := &heldTestGateway{authorized: accepted.authorized}
	spool, publisher := heldTestPipeline(t, manager, gateway, versionR2)

	republish(t, manager, "") // the automatic publication after the null reconciliation, activated
	requireQueueHeld(t, spool, publisher, gateway, heldTestEvents+1, "published after a reconciliation without a version")

	accepted.confirm(heldTestFailed) // the supplemental confirmation
	if accepted.authorized(versionR1) {
		t.Fatal("the supplement authorized an unconfirmed version")
	}
	withoutReleased := revisionRelease(versionR3, 15, rootR3)
	withoutReleased.PreviousConfigVersionID = versionR2
	publishSite(t, manager, "d1330000-0000-4000-8000-000000000003", withoutReleased)
	requireQueueHeld(t, spool, publisher, gateway, heldTestEvents+1, "a command without released versions")
	if !manager.HeldVersion(revisionTestScope, heldTestFailed) {
		t.Fatal("the supplemented version is released without being listed")
	}

	listed := revisionRelease(versionR2, 16, rootR2b)
	listed.PreviousConfigVersionID = versionR3
	listed.ReleasedConfigVersionIDs = []string{heldTestFailed}
	publishSite(t, manager, "d1330000-0000-4000-8000-000000000004", listed)
	if manager.HeldVersion(revisionTestScope, heldTestFailed) {
		t.Fatal("the version the command lists as released is still held")
	}
	requireSentInOrder(t, spool, publisher, gateway, heldThenNew())
}

// An agent from before released_config_version_ids drops the field: the
// command it gets after the supplement leaves the version held, the queue
// stays on disk unsent. Upgraded (a new manager over the same journal), the
// next apply command listing the version lets 1..23 go in order.
func TestHeldRecordsWaitForAnOldAgentAndGoAfterItsUpgrade(t *testing.T) {
	manager, _ := revisionTestManager(t)
	legacyRollbackFailedScope(t, manager)
	accepted := newHeldTestAccepted(versionR2, versionR3, heldTestFailed)
	gateway := &heldTestGateway{authorized: accepted.authorized}
	spool, publisher := heldTestPipeline(t, manager, gateway, versionR2)
	republish(t, manager, "")

	ignored := revisionRelease(versionR3, 15, rootR3)
	ignored.PreviousConfigVersionID = versionR2 // released_config_version_ids not read by the old agent
	publishSite(t, manager, "d1330000-0000-4000-8000-000000000003", ignored)
	requireQueueHeld(t, spool, publisher, gateway, heldTestEvents+1, "an old agent ignoring released versions")

	upgraded := &dynamicRoutingManager{objects: manager.objects, root: manager.root, now: manager.now,
		apply: manager.apply, activeVersion: manager.activeVersion}
	listed := revisionRelease(versionR2, 16, rootR2b)
	listed.PreviousConfigVersionID = versionR3
	listed.ReleasedConfigVersionIDs = []string{heldTestFailed}
	publishSite(t, upgraded, "d1330000-0000-4000-8000-000000000004", listed)
	// The pipeline reads the same scope journals (HeldVersion, ScopeForSite).
	requireSentInOrder(t, spool, publisher, gateway, heldThenNew())
}

// The listed version goes even when the apply carrying it does not activate
// (a refused stale revision): the confirmation is the control plane's, not
// this apply's.
func TestReleasedVersionsGoWhateverTheApplyOutcome(t *testing.T) {
	manager, _ := revisionTestManager(t)
	legacyRollbackFailedScope(t, manager)
	republish(t, manager, "")
	stale := revisionRelease(versionR3, 1, rootR3)
	stale.ReleasedConfigVersionIDs = []string{heldTestFailed}
	if result := applyRevision(t, manager, "d1330000-0000-4000-8000-000000000005", stale); result.State != deployment.StateFailed {
		t.Fatalf("stale apply result = %+v, want refused", result)
	}
	if manager.HeldVersion(revisionTestScope, heldTestFailed) {
		t.Fatal("the listed version is still held after a refused apply")
	}
}

// (two rollback failures): the scope failed
// its rollback twice (versions held: the first one, then versionR1). The
// second was confirmed with its own version first; a command releasing only
// it leaves the oldest records at the head of the queue, so nothing goes.
// Once the older source is supplemented too, the next command releases both
// and the cursor advances over 1..23.
func TestOldestHeldRecordsGoOnceBothRollbackFailuresAreReleased(t *testing.T) {
	manager, _ := revisionTestManager(t)
	results := []dynamicRoutingResult{}
	for index, version := range []string{heldTestFailed, versionR1} {
		result := deployment.Result{DeploymentID: fmt.Sprintf("d1330000-0000-4000-8000-00000000010%d", index), Attempt: 1,
			Action: deployment.ActionApply, ConfigVersionID: version, State: deployment.StateRollbackFailed, ErrorCode: "ROLLBACK_FAILED"}
		results = append(results, dynamicRoutingResult{DeploymentID: result.DeploymentID, Result: result})
	}
	if err := manager.save(revisionTestScope, dynamicRoutingScope{Results: results}); err != nil {
		t.Fatal(err)
	}
	accepted := newHeldTestAccepted(versionR1, versionR2, versionR3, heldTestFailed)
	gateway := &heldTestGateway{authorized: accepted.authorized}
	spool, publisher := heldTestPipeline(t, manager, gateway, versionR1)

	onlyNewer := revisionRelease(versionR2, 14, rootR2)
	onlyNewer.ReleasedConfigVersionIDs = []string{versionR1}
	publishSite(t, manager, "d1330000-0000-4000-8000-000000000003", onlyNewer)
	if manager.HeldVersion(revisionTestScope, versionR1) || !manager.HeldVersion(revisionTestScope, heldTestFailed) {
		t.Fatal("held versions after releasing only the newer failure are wrong")
	}
	requireQueueHeld(t, spool, publisher, gateway, heldTestEvents+1, "only the newer failure released")

	both := revisionRelease(versionR3, 15, rootR3)
	both.PreviousConfigVersionID = versionR2
	both.ReleasedConfigVersionIDs = []string{heldTestFailed, versionR1}
	publishSite(t, manager, "d1330000-0000-4000-8000-000000000004", both)
	versions := make([]string, 0, heldTestEvents+1)
	for range heldTestEvents {
		versions = append(versions, heldTestFailed)
	}
	requireSentInOrder(t, spool, publisher, gateway, append(versions, versionR1))
}
