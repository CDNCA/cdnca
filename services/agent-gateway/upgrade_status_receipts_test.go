package gateway

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type receiptTestUpgradeStore struct {
	records      []upgradeStatusAckRecord
	confirmed    map[[32]byte]*agentv1.UpgradeStatusAckReceipt
	events       *[]string
	listCalls    atomic.Int32
	saveCalls    atomic.Int32
	confirmCalls atomic.Int32
	saveErr      error
	confirmErr   error
	completed    map[[32]byte]UpgradeCommandRecord
}

func (s *receiptTestUpgradeStore) listUpgradeStatusAcks(_ context.Context, nodeID string, limit int) ([]upgradeStatusAckRecord, error) {
	s.listCalls.Add(1)
	if limit <= 0 || !canonicalUpgradeUUID(nodeID) {
		return nil, errors.New("invalid list")
	}
	result := make([]upgradeStatusAckRecord, 0, len(s.records))
	for _, record := range s.records {
		if record.NodeID == nodeID {
			result = append(result, cloneUpgradeStatusAckRecord(record))
		}
	}
	return result, nil
}

func (s *receiptTestUpgradeStore) saveUpgradeStatusAck(_ context.Context, candidate upgradeStatusAckRecord, limit int) (upgradeStatusAckRecord, error) {
	s.saveCalls.Add(1)
	if s.events != nil {
		*s.events = append(*s.events, "save")
	}
	if s.saveErr != nil {
		return upgradeStatusAckRecord{}, s.saveErr
	}
	for _, record := range s.records {
		if sameUpgradeStatusAckBinding(record, candidate) {
			return cloneUpgradeStatusAckRecord(record), nil
		}
		if record.NodeID == candidate.NodeID && record.Ack.GetStatusEventId() == candidate.Ack.GetStatusEventId() {
			return upgradeStatusAckRecord{}, errors.New("conflict")
		}
	}
	if len(s.records) >= limit {
		return upgradeStatusAckRecord{}, errors.New("limit")
	}
	s.records = append(s.records, cloneUpgradeStatusAckRecord(candidate))
	return cloneUpgradeStatusAckRecord(candidate), nil
}

func (s *receiptTestUpgradeStore) saveUpgradeStatusAckHorizon(_ context.Context, candidate upgradeStatusAckRecord, limit int) (upgradeStatusAckRecord, error) {
	s.saveCalls.Add(1)
	if s.saveErr != nil {
		return upgradeStatusAckRecord{}, s.saveErr
	}
	for _, record := range s.records {
		if sameUpgradeStatusAckBinding(record, candidate) {
			return cloneUpgradeStatusAckRecord(record), nil
		}
		if record.Ack.GetStatusEventId() == candidate.Ack.GetStatusEventId() {
			return upgradeStatusAckRecord{}, errors.New("conflict")
		}
	}
	s.records = append(s.records, cloneUpgradeStatusAckRecord(candidate))
	sortUpgradeStatusAckRecords(s.records)
	if len(s.records) > limit {
		s.records = s.records[len(s.records)-limit:]
	}
	return cloneUpgradeStatusAckRecord(candidate), nil
}

func (s *receiptTestUpgradeStore) confirmUpgradeStatusAck(_ context.Context, nodeID string, receipt *agentv1.UpgradeStatusAckReceipt, _ int) (*agentv1.UpgradeStatusAckReceipt, error) {
	s.confirmCalls.Add(1)
	if s.events != nil {
		*s.events = append(*s.events, "confirm")
	}
	if s.confirmErr != nil {
		return nil, s.confirmErr
	}
	var digest [32]byte
	if len(receipt.GetAckSha256()) == len(digest) {
		copy(digest[:], receipt.GetAckSha256())
	}
	if previous := s.confirmed[digest]; previous != nil {
		if !proto.Equal(previous, receipt) {
			return nil, errors.New("confirmation conflict")
		}
		return proto.Clone(previous).(*agentv1.UpgradeStatusAckReceipt), nil
	}
	for index, record := range s.records {
		if record.NodeID != nodeID || validateUpgradeStatusAckReceipt(record, receipt) != nil {
			continue
		}
		if s.confirmed == nil {
			s.confirmed = make(map[[32]byte]*agentv1.UpgradeStatusAckReceipt)
		}
		stored := proto.Clone(receipt).(*agentv1.UpgradeStatusAckReceipt)
		s.confirmed[digest] = stored
		s.records = append(s.records[:index], s.records[index+1:]...)
		return proto.Clone(stored).(*agentv1.UpgradeStatusAckReceipt), nil
	}
	return nil, errors.New("pending acknowledgement not found")
}

func (s *receiptTestUpgradeStore) hasCompletedUpgradeCommand(_ context.Context, command UpgradeCommandRecord, limit int) (bool, error) {
	if limit <= 0 {
		return false, errors.New("invalid limit")
	}
	completed, ok := s.completed[command.SHA256]
	if !ok {
		return false, nil
	}
	if completed.NodeID != command.NodeID || completed.InstallationID != command.InstallationID ||
		completed.CommandID != command.CommandID || completed.SHA256 != command.SHA256 ||
		!bytes.Equal(completed.Encoded, command.Encoded) {
		return false, errUpgradeStatusAckConflict
	}
	return true, nil
}

type receiptTestUpgradeBus struct {
	store          *receiptTestUpgradeStore
	events         *[]string
	publication    UpgradeStatusPublication
	publishErr     error
	publishCalls   atomic.Int32
	subscription   UpgradeCommandSubscription
	publishStarted chan struct{}
	releasePublish chan struct{}
	publishOnce    sync.Once
}

func (b *receiptTestUpgradeBus) SubscribeUpgrade(context.Context, string) (UpgradeCommandSubscription, error) {
	if b.subscription != nil {
		return b.subscription, nil
	}
	return &receiptTestUpgradeSubscription{}, nil
}

func (b *receiptTestUpgradeBus) PublishUpgradeStatus(ctx context.Context, _ string, _ []byte) (UpgradeStatusPublication, error) {
	b.publishCalls.Add(1)
	if b.publishStarted != nil {
		b.publishOnce.Do(func() { close(b.publishStarted) })
	}
	if b.releasePublish != nil {
		select {
		case <-b.releasePublish:
		case <-ctx.Done():
			return UpgradeStatusPublication{}, ctx.Err()
		}
	}
	if b.events != nil {
		*b.events = append(*b.events, "publish")
	}
	if b.publishErr != nil {
		return UpgradeStatusPublication{}, b.publishErr
	}
	if b.publication.Stream == "" {
		return UpgradeStatusPublication{Stream: UpgradeStatusStream, Sequence: 41}, nil
	}
	return b.publication, nil
}

type rejectingUpgradeStatusLease struct {
	done        chan struct{}
	fencedCalls atomic.Int32
}

func (lease *rejectingUpgradeStatusLease) ID() string                  { return "rejecting-upgrade-status-lease" }
func (lease *rejectingUpgradeStatusLease) Epoch() uint64               { return 1 }
func (lease *rejectingUpgradeStatusLease) Superseded() <-chan struct{} { return lease.done }
func (lease *rejectingUpgradeStatusLease) FencedSend(func() error) error {
	lease.fencedCalls.Add(1)
	return ErrSessionSuperseded
}
func (*rejectingUpgradeStatusLease) Release() {}

func (b *receiptTestUpgradeBus) listUpgradeStatusAcks(ctx context.Context, nodeID string, limit int) ([]upgradeStatusAckRecord, error) {
	return b.store.listUpgradeStatusAcks(ctx, nodeID, limit)
}

func (b *receiptTestUpgradeBus) saveUpgradeStatusAck(ctx context.Context, record upgradeStatusAckRecord, limit int) (upgradeStatusAckRecord, error) {
	return b.store.saveUpgradeStatusAck(ctx, record, limit)
}

func (b *receiptTestUpgradeBus) saveUpgradeStatusAckHorizon(ctx context.Context, record upgradeStatusAckRecord, limit int) (upgradeStatusAckRecord, error) {
	return b.store.saveUpgradeStatusAckHorizon(ctx, record, limit)
}

func (b *receiptTestUpgradeBus) confirmUpgradeStatusAck(ctx context.Context, nodeID string, receipt *agentv1.UpgradeStatusAckReceipt, limit int) (*agentv1.UpgradeStatusAckReceipt, error) {
	return b.store.confirmUpgradeStatusAck(ctx, nodeID, receipt, limit)
}

func (b *receiptTestUpgradeBus) hasCompletedUpgradeCommand(ctx context.Context, command UpgradeCommandRecord, limit int) (bool, error) {
	return b.store.hasCompletedUpgradeCommand(ctx, command, limit)
}

type receiptTestUpgradeSubscription struct{}

func (*receiptTestUpgradeSubscription) Next(ctx context.Context) (UpgradeCommandDelivery, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
func (*receiptTestUpgradeSubscription) Close() error { return nil }

type orderedReceiptUpgradeDelivery struct {
	command UpgradeCommandRecord
	events  *[]string
	acks    atomic.Int32
	ackErr  error
}

func (d *orderedReceiptUpgradeDelivery) Command() UpgradeCommandRecord { return d.command }
func (d *orderedReceiptUpgradeDelivery) Ack(context.Context) error {
	d.acks.Add(1)
	*d.events = append(*d.events, "command-ack")
	return d.ackErr
}
func (*orderedReceiptUpgradeDelivery) Nak(context.Context) error { return nil }

type oneShotReceiptUpgradeSubscription struct {
	delivery  UpgradeCommandDelivery
	delivered atomic.Bool
}

func (s *oneShotReceiptUpgradeSubscription) Next(ctx context.Context) (UpgradeCommandDelivery, error) {
	if s.delivered.CompareAndSwap(false, true) {
		return s.delivery, nil
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func (*oneShotReceiptUpgradeSubscription) Close() error { return nil }

func TestGatewayUpgradeStatusAckReceiptCapabilityDependency(t *testing.T) {
	gateway := &Gateway{config: DefaultConfig()}
	base := &agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE, ApiVersion: 1}
	pubAck := &agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE_STATUS_PUBACK, ApiVersion: 1}
	receipt := &agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE_STATUS_ACK_RECEIPT, ApiVersion: 1}
	for _, test := range []struct {
		name     string
		features []*agentv1.Capability
		valid    bool
	}{
		{name: "legacy base", features: []*agentv1.Capability{base}, valid: true},
		{name: "puback pair", features: []*agentv1.Capability{base, pubAck}, valid: true},
		{name: "receipt chain", features: []*agentv1.Capability{base, pubAck, receipt}, valid: true},
		{name: "receipt without base", features: []*agentv1.Capability{pubAck, receipt}},
		{name: "receipt without puback", features: []*agentv1.Capability{base, receipt}},
		{name: "unsupported receipt version", features: []*agentv1.Capability{base, pubAck, {Name: receipt.Name, ApiVersion: 2}}},
		{name: "duplicate receipt", features: []*agentv1.Capability{base, pubAck, receipt, receipt}},
	} {
		t.Run(test.name, func(t *testing.T) {
			hello := validHello(testNodeID, versionRange(1, 0), 1).GetHello()
			hello.Capabilities.Features = test.features
			err := gateway.validateHello(hello)
			if test.valid && err != nil {
				t.Fatalf("valid capability set rejected: %v", err)
			}
			if !test.valid && err == nil {
				t.Fatal("invalid receipt capability set accepted")
			}
		})
	}
}

func TestGatewayUpgradeStatusPersistenceDoesNotStartOutsideLeaseFence(t *testing.T) {
	command := validUpgradeCommandRecord(t)
	statusRecord := validUpgradeStatusRecord(t, command)
	store := &receiptTestUpgradeStore{}
	bus := &receiptTestUpgradeBus{store: store}
	config := DefaultConfig()
	config.CommandOperationTimeout = time.Second
	gateway := &Gateway{config: config, upgrades: bus, upgradeReceipts: store, now: time.Now}
	lease := &rejectingUpgradeStatusLease{done: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := &capturingBidiStream{ctx: ctx, sent: make(chan *agentv1.ConnectResponse, 1)}
	received := make(chan connectReceive, 1)
	done := make(chan error, 1)
	go func() {
		done <- gateway.serveSessionWithInstallation(
			stream, received, lease, newMessageReplayWindow(defaultMessageReplayWindow), 1,
			nodeIdentity{NodeID: command.NodeID, SerialNumber: "10"}, "test-agent", versionRange(1, 0),
			&commonv1.ProtocolVersion{Major: 1}, "artifact-key", command.InstallationID,
			time.Now().Add(time.Hour), true, false, false, false, false, true, true, false,
		)
	}()
	received <- connectReceive{request: upgradeStatusConnectRequest(statusRecord)}
	select {
	case err := <-done:
		if !errors.Is(err, ErrSessionSuperseded) && status.Code(err) != codes.Aborted {
			t.Fatalf("session error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("session did not apply the rejected operation fence")
	}
	if bus.publishCalls.Load() != 0 || store.saveCalls.Load() != 0 || lease.fencedCalls.Load() == 0 {
		t.Fatalf("outside-fence calls: publish=%d save=%d fenced=%d",
			bus.publishCalls.Load(), store.saveCalls.Load(), lease.fencedCalls.Load())
	}
}

func TestGatewayUpgradeStatusPersistenceFencesSessionTakeover(t *testing.T) {
	command := validUpgradeCommandRecord(t)
	statusRecord := validUpgradeStatusRecord(t, command)
	publishStarted := make(chan struct{})
	releasePublish := make(chan struct{})
	store := &receiptTestUpgradeStore{}
	bus := &receiptTestUpgradeBus{store: store, publishStarted: publishStarted, releasePublish: releasePublish}
	config := DefaultConfig()
	config.CommandOperationTimeout = time.Second
	gateway := &Gateway{config: config, upgrades: bus, upgradeReceipts: store, now: time.Now}
	coordinator := NewMemorySessionCoordinator()
	lease, err := coordinator.Acquire(t.Context(), command.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	stream := &capturingBidiStream{ctx: ctx, sent: make(chan *agentv1.ConnectResponse, 1)}
	received := make(chan connectReceive, 1)
	done := make(chan error, 1)
	go func() {
		done <- gateway.serveSessionWithInstallation(
			stream, received, lease, newMessageReplayWindow(defaultMessageReplayWindow), 1,
			nodeIdentity{NodeID: command.NodeID, SerialNumber: "10"}, "test-agent", versionRange(1, 0),
			&commonv1.ProtocolVersion{Major: 1}, "artifact-key", command.InstallationID,
			time.Now().Add(time.Hour), true, false, false, false, false, true, true, false,
		)
	}()
	received <- connectReceive{request: upgradeStatusConnectRequest(statusRecord)}
	select {
	case <-publishStarted:
	case <-time.After(time.Second):
		t.Fatal("upgrade status persistence did not start")
	}
	takeover := make(chan SessionLease, 1)
	go func() {
		next, _ := coordinator.Acquire(context.Background(), command.NodeID)
		takeover <- next
	}()
	early := false
	var next SessionLease
	select {
	case next = <-takeover:
		early = true
	case <-time.After(30 * time.Millisecond):
	}
	close(releasePublish)
	if !early {
		select {
		case next = <-takeover:
		case <-time.After(time.Second):
			t.Fatal("takeover did not resume after persistence")
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("superseded session did not stop")
	}
	lease.Release()
	if next != nil {
		next.Release()
	}
	if early {
		t.Fatal("same-node takeover overlapped upgrade status persistence")
	}
	if bus.publishCalls.Load() != 1 {
		t.Fatalf("publish calls=%d", bus.publishCalls.Load())
	}
}

func upgradeStatusConnectRequest(record UpgradeStatusRecord) *agentv1.ConnectRequest {
	return &agentv1.ConnectRequest{
		Stream: &commonv1.StreamMetadata{MessageId: uuid.NewString(), Sequence: 2, SentTime: timestamppb.Now()},
		Payload: &agentv1.ConnectRequest_UpgradeStatus{UpgradeStatus: &agentv1.UpgradeStatus{
			Status: append([]byte(nil), record.Encoded...), StatusSha256: append([]byte(nil), record.SHA256[:]...),
		}},
	}
}

func TestUpgradeStatusAckReceiptBindsExactAcknowledgement(t *testing.T) {
	record := receiptTestUpgradeStatusAckRecord(t)
	valid := receiptTestUpgradeStatusAckReceipt(t, record)
	if err := validateUpgradeStatusAckReceipt(record, valid); err != nil {
		t.Fatalf("valid receipt rejected: %v", err)
	}
	mutations := []struct {
		name   string
		mutate func(*agentv1.UpgradeStatusAckReceipt)
	}{
		{name: "status event", mutate: func(value *agentv1.UpgradeStatusAckReceipt) { value.StatusEventId = uuid.NewString() }},
		{name: "command", mutate: func(value *agentv1.UpgradeStatusAckReceipt) { value.CommandId = uuid.NewString() }},
		{name: "revision", mutate: func(value *agentv1.UpgradeStatusAckReceipt) { value.StatusRevision++ }},
		{name: "status digest", mutate: func(value *agentv1.UpgradeStatusAckReceipt) { value.StatusSha256[0] ^= 0xff }},
		{name: "persisted time", mutate: func(value *agentv1.UpgradeStatusAckReceipt) { value.PersistedTime.Nanos++ }},
		{name: "stream", mutate: func(value *agentv1.UpgradeStatusAckReceipt) { value.PublishedStream = "OTHER" }},
		{name: "sequence", mutate: func(value *agentv1.UpgradeStatusAckReceipt) { value.PublishedSequence++ }},
		{name: "ack digest", mutate: func(value *agentv1.UpgradeStatusAckReceipt) { value.AckSha256[0] ^= 0xff }},
		{name: "unknown field", mutate: func(value *agentv1.UpgradeStatusAckReceipt) {
			value.ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x01})
		}},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			candidate := proto.Clone(valid).(*agentv1.UpgradeStatusAckReceipt)
			mutation.mutate(candidate)
			if validateUpgradeStatusAckReceipt(record, candidate) == nil {
				t.Fatal("mismatched receipt was accepted")
			}
		})
	}
}

func TestUpgradeStatusAckPersistsBeforeCommandAckAndExactReplayDoesNotPublish(t *testing.T) {
	command := validUpgradeCommandRecord(t)
	statusRecord := validUpgradeStatusRecord(t, command)
	events := make([]string, 0, 3)
	store := &receiptTestUpgradeStore{events: &events}
	bus := &receiptTestUpgradeBus{store: store, events: &events}
	delivery := &orderedReceiptUpgradeDelivery{command: command, events: &events}
	pending := pendingUpgradeCommandSet{command.CommandID: {command: command, deliveries: []UpgradeCommandDelivery{delivery}}}
	gateway := &Gateway{config: DefaultConfig(), upgrades: bus, upgradeReceipts: store,
		now: func() time.Time { return time.Unix(123, 456).UTC() }}

	ack, err := gateway.persistUpgradeStatusAndAckCommand(t.Context(), command.NodeID, command.InstallationID,
		statusRecord.Encoded, pending, true, true)
	if err != nil {
		t.Fatal(err)
	}
	if got := events; len(got) != 3 || got[0] != "publish" || got[1] != "save" || got[2] != "command-ack" {
		t.Fatalf("durability order = %v", got)
	}
	if ack.GetPublishedStream() != UpgradeStatusStream || ack.GetPublishedSequence() != 41 || delivery.acks.Load() != 1 {
		t.Fatalf("ack=%+v command_acks=%d", ack, delivery.acks.Load())
	}

	events = events[:0]
	replayed, err := gateway.persistUpgradeStatusAndAckCommand(t.Context(), command.NodeID, command.InstallationID,
		statusRecord.Encoded, make(pendingUpgradeCommandSet), true, true)
	if err != nil {
		t.Fatal(err)
	}
	if bus.publishCalls.Load() != 1 || !proto.Equal(replayed, ack) || len(events) != 0 {
		t.Fatalf("replay ack_equal=%t publishes=%d events=%v", proto.Equal(replayed, ack), bus.publishCalls.Load(), events)
	}
}

func TestUpgradeStatusPubAckSequenceSurvivesGatewaySessionResponse(t *testing.T) {
	command := validUpgradeCommandRecord(t)
	statusRecord := validUpgradeStatusRecord(t, command)
	bus := &receiptTestUpgradeBus{publication: UpgradeStatusPublication{Stream: UpgradeStatusStream, Sequence: 73}}
	gateway := &Gateway{config: DefaultConfig(), upgrades: bus, now: time.Now}
	coordinator := NewMemorySessionCoordinator()
	lease, err := coordinator.Acquire(t.Context(), command.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := &capturingBidiStream{ctx: ctx, sent: make(chan *agentv1.ConnectResponse, 2)}
	received := make(chan connectReceive, 1)
	done := make(chan error, 1)
	go func() {
		done <- gateway.serveSessionWithInstallation(
			stream, received, lease, newMessageReplayWindow(defaultMessageReplayWindow), 1,
			nodeIdentity{NodeID: command.NodeID, SerialNumber: "10"}, "test-agent", versionRange(1, 0),
			&commonv1.ProtocolVersion{Major: 1}, "artifact-key", command.InstallationID,
			time.Now().Add(time.Hour), true, false, false, false, false, true, true, false,
		)
	}()

	received <- connectReceive{request: upgradeStatusConnectRequest(statusRecord)}
	select {
	case response := <-stream.sent:
		ack := response.GetUpgradeStatusAck()
		if ack == nil || ack.GetPublishedStream() != UpgradeStatusStream || ack.GetPublishedSequence() != 73 {
			t.Fatalf("Gateway response lost exact status PubAck: %+v", response)
		}
	case <-time.After(time.Second):
		t.Fatal("Gateway did not return the upgrade status acknowledgement")
	}
	if bus.publishCalls.Load() != 1 {
		t.Fatalf("status publish calls = %d, want 1", bus.publishCalls.Load())
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Gateway session did not stop")
	}
}

func TestUpgradeStatusAckPersistenceFailureKeepsCommandPending(t *testing.T) {
	command := validUpgradeCommandRecord(t)
	statusRecord := validUpgradeStatusRecord(t, command)
	events := make([]string, 0, 2)
	store := &receiptTestUpgradeStore{events: &events, saveErr: errors.New("unavailable")}
	bus := &receiptTestUpgradeBus{store: store, events: &events}
	delivery := &orderedReceiptUpgradeDelivery{command: command, events: &events}
	pending := pendingUpgradeCommandSet{command.CommandID: {command: command, deliveries: []UpgradeCommandDelivery{delivery}}}
	gateway := &Gateway{config: DefaultConfig(), upgrades: bus, upgradeReceipts: store, now: time.Now}

	if ack, err := gateway.persistUpgradeStatusAndAckCommand(t.Context(), command.NodeID, command.InstallationID,
		statusRecord.Encoded, pending, true, true); err == nil || ack != nil {
		t.Fatalf("failed persistence returned ack=%+v err=%v", ack, err)
	}
	if delivery.acks.Load() != 0 || len(pending) != 1 {
		t.Fatalf("persistence failure changed command: acks=%d pending=%d", delivery.acks.Load(), len(pending))
	}
}

func TestCompletedUpgradeCommandRedeliveryIsBrokerAckedWithoutAgentReplay(t *testing.T) {
	command := validUpgradeCommandRecord(t)
	statusRecord := validUpgradeStatusRecord(t, command)
	events := make([]string, 0, 4)
	store := &receiptTestUpgradeStore{}
	bus := &receiptTestUpgradeBus{store: store}
	failedDelivery := &orderedReceiptUpgradeDelivery{command: command, events: &events, ackErr: errors.New("ack response lost")}
	pending := pendingUpgradeCommandSet{command.CommandID: {command: command, deliveries: []UpgradeCommandDelivery{failedDelivery}}}
	gateway := &Gateway{config: DefaultConfig(), upgrades: bus, upgradeReceipts: store, now: time.Now}
	if ack, err := gateway.persistUpgradeStatusAndAckCommand(t.Context(), command.NodeID, command.InstallationID,
		statusRecord.Encoded, pending, true, true); err == nil || ack != nil || len(store.records) != 1 {
		t.Fatalf("initial broker failure ack=%+v err=%v durable=%d", ack, err, len(store.records))
	}
	store.completed = map[[32]byte]UpgradeCommandRecord{command.SHA256: command}

	coordinator := NewMemorySessionCoordinator()
	run := func(expectPendingAck bool) {
		t.Helper()
		retryEvents := make([]string, 0, 1)
		retry := &orderedReceiptUpgradeDelivery{command: command, events: &retryEvents}
		bus.subscription = &oneShotReceiptUpgradeSubscription{delivery: retry}
		lease, err := coordinator.Acquire(t.Context(), command.NodeID)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		stream := &capturingBidiStream{ctx: ctx, sent: make(chan *agentv1.ConnectResponse, 4)}
		received := make(chan connectReceive, 1)
		done := make(chan error, 1)
		go func() {
			done <- gateway.serveSessionWithInstallation(
				stream, received, lease, newMessageReplayWindow(defaultMessageReplayWindow), 1,
				nodeIdentity{NodeID: command.NodeID, SerialNumber: "10"}, "test-agent", versionRange(1, 0),
				&commonv1.ProtocolVersion{Major: 1}, "artifact-key", command.InstallationID,
				time.Now().Add(time.Hour), true, false, false, false, false, true, true, true,
			)
		}()
		if expectPendingAck {
			select {
			case response := <-stream.sent:
				if response.GetUpgradeStatusAck() == nil {
					t.Fatalf("first recovery response=%+v", response)
				}
			case <-time.After(time.Second):
				t.Fatal("pending acknowledgement was not recovered")
			}
		}
		deadline := time.After(time.Second)
		for retry.acks.Load() == 0 {
			select {
			case response := <-stream.sent:
				t.Fatalf("completed command was replayed to Agent: %+v", response)
			case <-deadline:
				t.Fatal("completed broker delivery was not acknowledged")
			default:
				time.Sleep(time.Millisecond)
			}
		}
		select {
		case response := <-stream.sent:
			t.Fatalf("completed command produced an Agent response: %+v", response)
		case <-time.After(20 * time.Millisecond):
		}
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("session did not stop")
		}
		lease.Release()
	}

	run(true)
	receipt := receiptTestUpgradeStatusAckReceipt(t, store.records[0])
	if _, err := store.confirmUpgradeStatusAck(t.Context(), command.NodeID, receipt, 1); err != nil || len(store.records) != 0 {
		t.Fatalf("confirm durable completion: pending=%d err=%v", len(store.records), err)
	}
	run(false)
}

func TestUpgradeStatusAckReconnectReplayAndConfirmationResponseLoss(t *testing.T) {
	record := receiptTestUpgradeStatusAckRecord(t)
	receipt := receiptTestUpgradeStatusAckReceipt(t, record)
	store := &receiptTestUpgradeStore{records: []upgradeStatusAckRecord{record}}
	bus := &receiptTestUpgradeBus{store: store}
	config := DefaultConfig()
	config.CommandOperationTimeout = 100 * time.Millisecond
	gateway := &Gateway{config: config, upgrades: bus, upgradeReceipts: store, now: time.Now}
	coordinator := NewMemorySessionCoordinator()

	run := func(expectReplay bool) {
		t.Helper()
		lease, err := coordinator.Acquire(t.Context(), record.NodeID)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		stream := &capturingBidiStream{ctx: ctx, sent: make(chan *agentv1.ConnectResponse, 3)}
		received := make(chan connectReceive, 1)
		done := make(chan error, 1)
		go func() {
			done <- gateway.serveSessionWithInstallation(
				stream, received, lease, newMessageReplayWindow(defaultMessageReplayWindow), 1,
				nodeIdentity{NodeID: record.NodeID, SerialNumber: "10"}, "test-agent", versionRange(1, 0),
				&commonv1.ProtocolVersion{Major: 1}, "artifact-key", record.InstallationID,
				time.Now().Add(time.Hour), true, false, false, false, false, true, true, true,
			)
		}()
		if expectReplay {
			select {
			case response := <-stream.sent:
				if !proto.Equal(response.GetUpgradeStatusAck(), record.Ack) {
					t.Fatalf("replayed acknowledgement = %+v", response)
				}
			case <-time.After(time.Second):
				t.Fatal("durable acknowledgement was not replayed")
			}
		}
		received <- connectReceive{request: &agentv1.ConnectRequest{
			Stream:  &commonv1.StreamMetadata{MessageId: uuid.NewString(), Sequence: 2, SentTime: timestamppb.Now()},
			Payload: &agentv1.ConnectRequest_UpgradeStatusAckReceipt{UpgradeStatusAckReceipt: proto.Clone(receipt).(*agentv1.UpgradeStatusAckReceipt)},
		}}
		select {
		case response := <-stream.sent:
			if !proto.Equal(response.GetUpgradeStatusAckReceipt(), receipt) {
				t.Fatalf("receipt confirmation = %+v", response)
			}
		case <-time.After(time.Second):
			t.Fatal("receipt confirmation was not returned")
		}
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("session did not stop")
		}
		lease.Release()
	}

	run(true)
	run(false)
	if bus.publishCalls.Load() != 0 || store.confirmCalls.Load() != 2 || len(store.records) != 0 {
		t.Fatalf("publishes=%d confirmations=%d pending=%d", bus.publishCalls.Load(), store.confirmCalls.Load(), len(store.records))
	}
}

func TestLegacyUpgradeStatusDoesNotAccessReceiptStore(t *testing.T) {
	command := validUpgradeCommandRecord(t)
	statusRecord := validUpgradeStatusRecord(t, command)
	store := &receiptTestUpgradeStore{}
	bus := &receiptTestUpgradeBus{store: store}
	gateway := &Gateway{config: DefaultConfig(), upgrades: bus, upgradeReceipts: store, now: time.Now}
	pending := pendingUpgradeCommandSet{command.CommandID: {
		command: command, deliveries: []UpgradeCommandDelivery{&fakeUpgradeDelivery{command: command}},
	}}
	ack, err := gateway.persistUpgradeStatusAndAckCommand(t.Context(), command.NodeID, command.InstallationID,
		statusRecord.Encoded, pending)
	if err != nil || ack == nil {
		t.Fatalf("legacy status ack=(%+v,%v)", ack, err)
	}
	if store.listCalls.Load() != 0 || store.saveCalls.Load() != 0 || store.confirmCalls.Load() != 0 {
		t.Fatalf("legacy calls list=%d save=%d confirm=%d", store.listCalls.Load(), store.saveCalls.Load(), store.confirmCalls.Load())
	}
}

func TestUpgradeStatusPubAckPersistsWithoutReceiptCapability(t *testing.T) {
	command := validUpgradeCommandRecord(t)
	statusRecord := validUpgradeStatusRecord(t, command)
	store := &receiptTestUpgradeStore{}
	bus := &receiptTestUpgradeBus{store: store}
	gateway := &Gateway{config: DefaultConfig(), upgrades: bus, upgradeReceipts: store, now: time.Now}

	first, err := gateway.persistUpgradeStatusAndAckCommand(t.Context(), command.NodeID, command.InstallationID,
		statusRecord.Encoded, make(pendingUpgradeCommandSet), true, false)
	if err != nil || first == nil {
		t.Fatalf("first PubAck-only status=(%+v,%v)", first, err)
	}
	second, err := gateway.persistUpgradeStatusAndAckCommand(t.Context(), command.NodeID, command.InstallationID,
		statusRecord.Encoded, make(pendingUpgradeCommandSet), true, false)
	if err != nil || second == nil {
		t.Fatalf("replayed PubAck-only status=(%+v,%v)", second, err)
	}
	if !proto.Equal(first, second) || first.GetPublishedStream() != UpgradeStatusStream || first.GetPublishedSequence() == 0 {
		t.Fatalf("PubAck-only replay changed durable acknowledgement: first=%+v second=%+v", first, second)
	}
	if bus.publishCalls.Load() != 1 || store.saveCalls.Load() != 1 || store.listCalls.Load() != 2 {
		t.Fatalf("PubAck-only persistence calls: publishes=%d saves=%d lists=%d",
			bus.publishCalls.Load(), store.saveCalls.Load(), store.listCalls.Load())
	}
}

func TestUpgradeStatusPubAckHorizonIsBounded(t *testing.T) {
	store := &receiptTestUpgradeStore{}
	first := receiptTestUpgradeStatusAckRecord(t)
	second := cloneUpgradeStatusAckRecord(first)
	second.Ack.StatusEventId = "00000000-0000-4000-8000-000000000022"
	second.Ack.PublishedSequence = 42
	third := cloneUpgradeStatusAckRecord(first)
	third.Ack.StatusEventId = "00000000-0000-4000-8000-000000000023"
	third.Ack.PublishedSequence = 43

	for _, record := range []upgradeStatusAckRecord{first, second, third} {
		if _, err := store.saveUpgradeStatusAckHorizon(t.Context(), record, 2); err != nil {
			t.Fatalf("save horizon sequence=%d: %v", record.Ack.GetPublishedSequence(), err)
		}
	}
	records, err := store.listUpgradeStatusAcks(t.Context(), first.NodeID, 2)
	if err != nil || len(records) != 2 || records[0].Ack.GetPublishedSequence() != 42 || records[1].Ack.GetPublishedSequence() != 43 {
		t.Fatalf("bounded PubAck horizon records=%+v err=%v", records, err)
	}
}

func receiptTestUpgradeStatusAckRecord(t *testing.T) upgradeStatusAckRecord {
	t.Helper()
	ack := &agentv1.UpgradeStatusAck{
		StatusEventId:     "00000000-0000-4000-8000-000000000021",
		CommandId:         "00000000-0000-4000-8000-000000000011",
		StatusRevision:    3,
		StatusSha256:      bytes.Repeat([]byte{0x42}, 32),
		PersistedTime:     timestamppb.New(time.Unix(123, 456).UTC()),
		PublishedStream:   UpgradeStatusStream,
		PublishedSequence: 41,
	}
	record := upgradeStatusAckRecord{
		NodeID: "00000000-0000-4000-8000-000000000014", InstallationID: "00000000-0000-4000-8000-000000000013", Ack: ack,
	}
	if err := validateUpgradeStatusAckRecord(record); err != nil {
		t.Fatal(err)
	}
	return record
}

func receiptTestUpgradeStatusAckReceipt(t *testing.T, record upgradeStatusAckRecord) *agentv1.UpgradeStatusAckReceipt {
	t.Helper()
	digest, err := upgradeStatusAckSHA256(record.Ack)
	if err != nil {
		t.Fatal(err)
	}
	return &agentv1.UpgradeStatusAckReceipt{
		StatusEventId: record.Ack.StatusEventId, CommandId: record.Ack.CommandId,
		StatusRevision: record.Ack.StatusRevision, StatusSha256: append([]byte(nil), record.Ack.StatusSha256...),
		PersistedTime:   proto.Clone(record.Ack.PersistedTime).(*timestamppb.Timestamp),
		PublishedStream: record.Ack.PublishedStream, PublishedSequence: record.Ack.PublishedSequence,
		AckSha256: append([]byte(nil), digest[:]...),
	}
}
