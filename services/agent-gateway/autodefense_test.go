package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/autodefense"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type autoDefenseDeliveryStub struct {
	command          *agentv1.AutoDefenseCommand
	acks, naks, term chan string
}

func (delivery *autoDefenseDeliveryStub) Command() *agentv1.AutoDefenseCommand {
	return proto.Clone(delivery.command).(*agentv1.AutoDefenseCommand)
}
func (delivery *autoDefenseDeliveryStub) Ack(context.Context) error {
	delivery.acks <- delivery.command.Event.EventId
	return nil
}
func (delivery *autoDefenseDeliveryStub) Nak(context.Context) error {
	delivery.naks <- delivery.command.Event.EventId
	return nil
}
func (delivery *autoDefenseDeliveryStub) Term() error {
	delivery.term <- delivery.command.Event.EventId
	return nil
}

type autoDefenseBusStub struct {
	deliveries chan AutoDefenseDelivery
	subscribed chan string
	mu         sync.Mutex
	receipts   []*agentv1.AutoDefenseReceipt
	reports    map[string][]byte
	reported   chan string
	failReport bool
}

func newAutoDefenseBusStub() *autoDefenseBusStub {
	return &autoDefenseBusStub{deliveries: make(chan AutoDefenseDelivery, 4), subscribed: make(chan string, 4),
		reports: map[string][]byte{}, reported: make(chan string, 256)}
}

func (bus *autoDefenseBusStub) SubscribeAutoDefense(_ context.Context, nodeID string) (AutoDefenseSubscription, error) {
	bus.subscribed <- nodeID
	return bus, nil
}
func (bus *autoDefenseBusStub) Next(ctx context.Context) (AutoDefenseDelivery, error) {
	select {
	case delivery := <-bus.deliveries:
		return delivery, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (*autoDefenseBusStub) Close() error { return nil }
func (bus *autoDefenseBusStub) PublishAutoDefenseReceipt(_ context.Context, _ string, receipt *agentv1.AutoDefenseReceipt) (AutoDefensePublication, error) {
	bus.mu.Lock()
	defer bus.mu.Unlock()
	bus.receipts = append(bus.receipts, receipt)
	return AutoDefensePublication{Stream: autodefense.ReceiptStream, Sequence: uint64(len(bus.receipts))}, nil
}
func (bus *autoDefenseBusStub) PublishAutoDefenseReport(_ context.Context, _ string, msgID string, report []byte) (AutoDefensePublication, error) {
	bus.mu.Lock()
	defer bus.mu.Unlock()
	if bus.failReport {
		return AutoDefensePublication{}, context.DeadlineExceeded
	}
	_, replayed := bus.reports[msgID]
	bus.reports[msgID] = report
	bus.reported <- msgID
	return AutoDefensePublication{Stream: autodefense.ReportStream, Sequence: uint64(len(bus.reports)), Replayed: replayed}, nil
}

// testAutoDefenseCommand signs an empty snapshot ("automatic defense off"), the smallest valid part.
func testAutoDefenseCommand(t *testing.T, nodeID string, revision uint64) *agentv1.AutoDefenseCommand {
	t.Helper()
	_, private, _ := ed25519.GenerateKey(nil)
	encoded, err := autodefense.Sign(autodefense.Snapshot{Schema: autodefense.Schema, NodeID: nodeID, Revision: revision,
		Part: 1, Parts: 1, IssuedAt: time.Now().Unix()}, "edge-publish", private)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(encoded)
	return &agentv1.AutoDefenseCommand{
		Event:  &commonv1.EventMetadata{EventId: uuid.NewString(), RequestId: uuid.NewString(), OccurredTime: timestamppb.Now()},
		NodeId: nodeID, Revision: revision, SnapshotJson: encoded, SnapshotSha256: digest[:],
	}
}

func testAutoDefenseReceipt(command *agentv1.AutoDefenseCommand) *agentv1.AutoDefenseReceipt {
	return &agentv1.AutoDefenseReceipt{
		Event:  &commonv1.EventMetadata{EventId: uuid.NewString(), RequestId: uuid.NewString(), OccurredTime: timestamppb.Now()},
		NodeId: command.NodeId, CommandEventId: command.Event.EventId, Revision: command.Revision,
		SnapshotSha256: command.SnapshotSha256, Applied: true, Sites: 2, Signatures: 1,
	}
}

func testAutoDefenseReport(t *testing.T, nodeID string, seq uint64, reason string) *agentv1.AutoDefenseReport {
	t.Helper()
	encoded, err := autodefense.EncodeReport(autodefense.Report{Schema: autodefense.ReportSchema, Kind: autodefense.ReportState,
		NodeID: nodeID, SiteID: "22222222-2222-4222-8222-222222222222", TenantID: "33333333-3333-4333-8333-333333333333",
		Seq: seq, At: time.Now().Unix(), Revision: 1,
		State: &autodefense.StateChange{From: autodefense.StateNormal, To: autodefense.StateAttack, Level: autodefense.LevelChallenge, Reason: reason}})
	if err != nil {
		t.Fatal(err)
	}
	return &agentv1.AutoDefenseReport{ReportJson: encoded}
}

func TestValidateAutoDefenseCommandAndReceiptBindings(t *testing.T) {
	command := testAutoDefenseCommand(t, testNodeID, 4)
	if err := validateAutoDefenseCommand(command, testNodeID); err != nil {
		t.Fatalf("valid command rejected: %v", err)
	}
	for name, mutate := range map[string]func(*agentv1.AutoDefenseCommand){
		"node":       func(value *agentv1.AutoDefenseCommand) { value.NodeId = uuid.NewString() },
		"revision":   func(value *agentv1.AutoDefenseCommand) { value.Revision = 5 },
		"zero rev":   func(value *agentv1.AutoDefenseCommand) { value.Revision = 0 },
		"digest":     func(value *agentv1.AutoDefenseCommand) { value.SnapshotSha256 = make([]byte, sha256.Size) },
		"body":       func(value *agentv1.AutoDefenseCommand) { value.SnapshotJson = []byte(`{}`) },
		"event":      func(value *agentv1.AutoDefenseCommand) { value.Event.EventId = "x" },
		"no time":    func(value *agentv1.AutoDefenseCommand) { value.Event.OccurredTime = nil },
		"other node": func(value *agentv1.AutoDefenseCommand) { *value = *testAutoDefenseCommand(t, uuid.NewString(), 4) },
	} {
		changed := proto.Clone(command).(*agentv1.AutoDefenseCommand)
		mutate(changed)
		if err := validateAutoDefenseCommand(changed, testNodeID); err == nil {
			t.Fatalf("%s drift accepted", name)
		}
	}
	receipt := testAutoDefenseReceipt(command)
	if err := validateAutoDefenseReceipt(receipt, command, testNodeID); err != nil {
		t.Fatalf("valid receipt rejected: %v", err)
	}
	refused := proto.Clone(receipt).(*agentv1.AutoDefenseReceipt)
	refused.Applied, refused.Sites, refused.Signatures, refused.ErrorCode = false, 0, 0, autodefense.ErrorStale
	if err := validateAutoDefenseReceipt(refused, command, testNodeID); err != nil {
		t.Fatalf("valid refusal rejected: %v", err)
	}
	for name, mutate := range map[string]func(*agentv1.AutoDefenseReceipt){
		"command event":  func(value *agentv1.AutoDefenseReceipt) { value.CommandEventId = uuid.NewString() },
		"digest":         func(value *agentv1.AutoDefenseReceipt) { value.SnapshotSha256 = make([]byte, sha256.Size) },
		"revision":       func(value *agentv1.AutoDefenseReceipt) { value.Revision = 3 },
		"node":           func(value *agentv1.AutoDefenseReceipt) { value.NodeId = uuid.NewString() },
		"applied+error":  func(value *agentv1.AutoDefenseReceipt) { value.ErrorCode = autodefense.ErrorStale },
		"refused no err": func(value *agentv1.AutoDefenseReceipt) { value.Applied, value.Sites, value.Signatures = false, 0, 0 },
		"unknown code": func(value *agentv1.AutoDefenseReceipt) {
			value.Applied, value.Sites, value.Signatures, value.ErrorCode = false, 0, 0, "boom"
		},
		"refused counts": func(value *agentv1.AutoDefenseReceipt) {
			value.Applied, value.ErrorCode = false, autodefense.ErrorUntrusted
		},
	} {
		changed := proto.Clone(receipt).(*agentv1.AutoDefenseReceipt)
		mutate(changed)
		if err := validateAutoDefenseReceipt(changed, command, testNodeID); err == nil {
			t.Fatalf("%s drift accepted", name)
		}
	}
}

func TestAutoDefenseReportKeyIsNodeScopeSeq(t *testing.T) {
	key, err := autoDefenseReportKey(testAutoDefenseReport(t, testNodeID, 7, "z=9"), testNodeID)
	if err != nil || key != testNodeID+"/site:22222222-2222-4222-8222-222222222222/7" {
		t.Fatalf("key = %q %v", key, err)
	}
	if _, err := autoDefenseReportKey(testAutoDefenseReport(t, uuid.NewString(), 7, "z=9"), testNodeID); err == nil {
		t.Fatal("report of another node accepted")
	}
	if _, err := autoDefenseReportKey(&agentv1.AutoDefenseReport{ReportJson: []byte(`{"schema":"x"}`)}, testNodeID); err == nil {
		t.Fatal("invalid report accepted")
	}
	// F4 platform node security events are node scoped.
	event, err := autodefense.EncodeReport(autodefense.Report{Schema: autodefense.ReportSchema, NodeID: testNodeID, Seq: 9, At: time.Now().Unix(),
		Kind: autodefense.ReportNodeEvent, NodeEvent: &autodefense.NodeEvent{Source: "ddos", Kind: "empty_connection_ban",
			Client: "198.51.100.7", Count: 12, DurationSeconds: 600, Level: autodefense.LevelKernel, Reason: "empty_connections"}})
	if err != nil {
		t.Fatal(err)
	}
	if key, err := autoDefenseReportKey(&agentv1.AutoDefenseReport{ReportJson: event}, testNodeID); err != nil || key != testNodeID+"/node/9" {
		t.Fatalf("node event key = %q %v", key, err)
	}
	// CC rule statistics are node scoped with their own seq.
	now := time.Now().Unix()
	stats, err := autodefense.EncodeReport(autodefense.Report{Schema: autodefense.ReportSchema, NodeID: testNodeID, Seq: 9, At: now,
		Kind: autodefense.ReportCCStats, CCStats: []autodefense.CCStat{{TenantID: uuid.NewString(), SiteID: uuid.NewString(),
			PolicyID: uuid.NewString(), PolicyVersion: 1, Minute: now - now%60, Blocked: 1, Triggered: 1,
			TopClients: []autodefense.Count{}, TopPaths: []autodefense.Count{}}}})
	if err != nil {
		t.Fatal(err)
	}
	if key, err := autoDefenseReportKey(&agentv1.AutoDefenseReport{ReportJson: stats}, testNodeID); err != nil || key != testNodeID+"/cc_stats/9" {
		t.Fatalf("cc stats key = %q %v", key, err)
	}
}

func connectAutoDefenseSession(t *testing.T, bus AutoDefenseBus, features []*agentv1.Capability) (
	agentv1.AgentGatewayService_ConnectClient, *agentv1.GatewayHello, *Gateway, context.Context,
) {
	t.Helper()
	pki := newTestPKI(t)
	now := time.Now()
	clientCertificate := pki.client(t, 10, nodeSPIFFEPrefix+testNodeID, now.Add(-time.Hour), now.Add(time.Hour))
	config := DefaultConfig()
	config.GatewayInstanceID, config.GatewayVersion = "gateway-test", "test"
	// defaultFakeControl does not allow deployments: snapshots are delivered regardless.
	service, err := New(config, defaultFakeControl(), NewMemorySessionCoordinator())
	if err != nil {
		t.Fatal(err)
	}
	if err := service.ConfigureAutoDefense(bus); err != nil {
		t.Fatal(err)
	}
	servers, err := NewServers(service, &tls.Config{Certificates: []tls.Certificate{pki.server}},
		&tls.Config{Certificates: []tls.Certificate{pki.server}, ClientCAs: pki.rootPool})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = servers.MTLS.Serve(listener) }()
	t.Cleanup(servers.MTLS.Stop)
	connection := dialGateway(t, listener.Addr().String(), pki.rootPool, clientCertificate)
	t.Cleanup(func() { _ = connection.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	stream, err := agentv1.NewAgentGatewayServiceClient(connection).Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	hello := validHello(testNodeID, versionRange(1, 0), 1)
	hello.GetHello().Capabilities.Features = features
	if err := stream.Send(hello); err != nil {
		t.Fatal(err)
	}
	response, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	return stream, response.GetHello(), service, ctx
}

func autoDefenseFeatures() []*agentv1.Capability {
	return []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_AUTO_DEFENSE, ApiVersion: autodefense.APIVersion}}
}

func sendAutoDefense(t *testing.T, stream agentv1.AgentGatewayService_ConnectClient, sequence uint64, request *agentv1.ConnectRequest) {
	t.Helper()
	request.Stream = &commonv1.StreamMetadata{MessageId: uuid.NewString(), Sequence: sequence, SentTime: timestamppb.Now()}
	if err := stream.Send(request); err != nil {
		t.Fatal(err)
	}
}

// An Agent without AUTO_DEFENSE gets no subscription and may not send a receipt.
func TestAutoDefenseNotNegotiatedWithoutCapability(t *testing.T) {
	bus := newAutoDefenseBusStub()
	stream, hello, _, _ := connectAutoDefenseSession(t, bus, nil)
	for _, capability := range hello.EnabledCapabilities {
		if capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_AUTO_DEFENSE {
			t.Fatal("auto defense enabled without the Agent declaring it")
		}
	}
	command := testAutoDefenseCommand(t, testNodeID, 1)
	sendAutoDefense(t, stream, 2, &agentv1.ConnectRequest{Payload: &agentv1.ConnectRequest_AutoDefenseReceipt{AutoDefenseReceipt: testAutoDefenseReceipt(command)}})
	if _, err := stream.Recv(); err == nil || !strings.Contains(err.Error(), "not negotiated") {
		t.Fatalf("unnegotiated receipt: %v", err)
	}
	select {
	case nodeID := <-bus.subscribed:
		t.Fatalf("subscribed for %s without AUTO_DEFENSE", nodeID)
	default:
	}
}

// With deployments paused (defaultFakeControl) an AUTO_DEFENSE Agent still gets the capability and the part;
// a part with a broken binding is dropped without closing the session; the delivery is acknowledged only
// after its receipt is published; a receipt for another revision is refused.
func TestAutoDefenseSessionDeliversWhilePausedAndAcksAfterReceipt(t *testing.T) {
	bus := newAutoDefenseBusStub()
	stream, hello, _, ctx := connectAutoDefenseSession(t, bus, autoDefenseFeatures())
	enabled := false
	for _, capability := range hello.EnabledCapabilities {
		enabled = enabled || (capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_AUTO_DEFENSE && capability.ApiVersion == 1)
	}
	if !enabled {
		t.Fatal("AUTO_DEFENSE not enabled while deployments are paused")
	}
	select {
	case nodeID := <-bus.subscribed:
		if nodeID != testNodeID {
			t.Fatalf("subscribed for %s", nodeID)
		}
	case <-ctx.Done():
		t.Fatal("gateway did not subscribe for the authenticated node")
	}
	acks, naks, terms := make(chan string, 4), make(chan string, 4), make(chan string, 4)
	broken := testAutoDefenseCommand(t, testNodeID, 3)
	broken.Revision = 9
	bus.deliveries <- &autoDefenseDeliveryStub{command: broken, acks: acks, naks: naks, term: terms}
	command := testAutoDefenseCommand(t, testNodeID, 5)
	bus.deliveries <- &autoDefenseDeliveryStub{command: command, acks: acks, naks: naks, term: terms}
	response, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if delivered := response.GetAutoDefenseCommand(); delivered == nil || !proto.Equal(delivered, command) {
		t.Fatalf("delivered %v, want the valid part", response.Payload)
	}
	if dropped := <-terms; dropped != broken.Event.EventId {
		t.Fatalf("terminated %s, want the broken part", dropped)
	}
	select {
	case id := <-acks:
		t.Fatalf("part %s acknowledged before its receipt", id)
	case <-time.After(100 * time.Millisecond):
	}
	receipt := testAutoDefenseReceipt(command)
	sendAutoDefense(t, stream, 2, &agentv1.ConnectRequest{Payload: &agentv1.ConnectRequest_AutoDefenseReceipt{AutoDefenseReceipt: receipt}})
	select {
	case id := <-acks:
		if id != command.Event.EventId {
			t.Fatalf("acknowledged %s", id)
		}
	case <-ctx.Done():
		t.Fatal("part was not acknowledged after its receipt")
	}
	bus.mu.Lock()
	if len(bus.receipts) != 1 || !proto.Equal(bus.receipts[0], receipt) {
		t.Fatalf("published receipts = %v", bus.receipts)
	}
	bus.mu.Unlock()

	// Next part: a receipt bound to another revision ends the session and the part is redelivered (nak).
	next := testAutoDefenseCommand(t, testNodeID, 6)
	bus.deliveries <- &autoDefenseDeliveryStub{command: next, acks: acks, naks: naks, term: terms}
	if response, err := stream.Recv(); err != nil || response.GetAutoDefenseCommand() == nil {
		t.Fatalf("second part: %v %v", response, err)
	}
	wrong := testAutoDefenseReceipt(next)
	wrong.Revision = 5
	sendAutoDefense(t, stream, 3, &agentv1.ConnectRequest{Payload: &agentv1.ConnectRequest_AutoDefenseReceipt{AutoDefenseReceipt: wrong}})
	if _, err := stream.Recv(); err == nil || !strings.Contains(err.Error(), "receipt is invalid") {
		t.Fatalf("mismatched receipt: %v", err)
	}
	select {
	case id := <-naks:
		if id != next.Event.EventId {
			t.Fatalf("nak %s", id)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("unsettled part was not released")
	}
}

// Reports are display only: valid ones are published with node/scope/seq, invalid, foreign and over-budget
// ones are dropped and counted, and none of them closes the session or gets an answer.
func TestAutoDefenseReportsArePublishedRateLimitedAndNeverFatal(t *testing.T) {
	bus := newAutoDefenseBusStub()
	stream, _, service, ctx := connectAutoDefenseSession(t, bus, autoDefenseFeatures())
	<-bus.subscribed
	sequence := uint64(1)
	send := func(report *agentv1.AutoDefenseReport) {
		sequence++
		sendAutoDefense(t, stream, sequence, &agentv1.ConnectRequest{Payload: &agentv1.ConnectRequest_AutoDefenseReport{AutoDefenseReport: report}})
	}
	send(testAutoDefenseReport(t, testNodeID, 1, "z=9"))
	send(testAutoDefenseReport(t, uuid.NewString(), 2, "z=9"))
	send(&agentv1.AutoDefenseReport{ReportJson: []byte(`not json`)})
	send(testAutoDefenseReport(t, testNodeID, 1, "z=9")) // Agent retry: same key
	for range 2 {
		select {
		case <-bus.reported:
		case <-ctx.Done():
			t.Fatal("report was not published")
		}
	}
	// Burst: 40 near-limit reports (~230 KiB each) at once exceed the 1 MiB bucket.
	for seq := uint64(100); seq < 140; seq++ {
		send(&agentv1.AutoDefenseReport{ReportJson: nearLimitReport(t, seq)})
	}
	// The session is still alive: a heartbeat-free round trip through a command proves it.
	command := testAutoDefenseCommand(t, testNodeID, 1)
	acks := make(chan string, 1)
	bus.deliveries <- &autoDefenseDeliveryStub{command: command, acks: acks, naks: make(chan string, 1), term: make(chan string, 1)}
	if response, err := stream.Recv(); err != nil || response.GetAutoDefenseCommand() == nil {
		t.Fatalf("session closed by reports: %v %v", response, err)
	}
	deadline := time.After(5 * time.Second)
	for {
		stats := service.AutoDefenseReportStats()
		// 44 offered: 1 valid, 2 invalid (foreign node, not JSON), 1 retry, 40 near-limit.
		if stats.Published+stats.Duplicates+stats.RateLimited+stats.QueueFull+stats.Invalid+stats.PublishFailed == 44 {
			if stats.Invalid != 2 || stats.Duplicates != 1 || stats.PublishFailed != 0 || stats.RateLimited == 0 ||
				stats.Published < 2 || stats.Published > 1+autoDefenseReportBurstBytes/(200<<10) {
				t.Fatalf("stats = %+v", stats)
			}
			break
		}
		select {
		case <-deadline:
			t.Fatalf("stats = %+v", service.AutoDefenseReportStats())
		case <-time.After(20 * time.Millisecond):
		}
	}
}

// nearLimitReport is a valid verdicts report close to MaxReportBytes.
func nearLimitReport(t *testing.T, seq uint64) []byte {
	t.Helper()
	now := time.Now().Unix()
	verdicts := make([]autodefense.Verdict, 0, autodefense.MaxVerdicts)
	reason := strings.Repeat("v", 400)
	for index := range autodefense.MaxVerdicts {
		verdicts = append(verdicts, autodefense.Verdict{Kind: autodefense.TargetIP,
			Target: net.IPv4(198, 51, byte(index/256), byte(index%256)).String(), Score: 90, Level: autodefense.LevelBan,
			Until: now + 600, Reason: reason})
	}
	encoded, err := autodefense.EncodeReport(autodefense.Report{Schema: autodefense.ReportSchema, Kind: autodefense.ReportVerdicts,
		NodeID: testNodeID, SiteID: "22222222-2222-4222-8222-222222222222", TenantID: "33333333-3333-4333-8333-333333333333",
		Seq: seq, At: now, Revision: 1, Verdicts: verdicts})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
