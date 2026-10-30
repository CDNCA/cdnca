package nodepresence

import (
	"context"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type fakeDelivery struct {
	subject     string
	data        []byte
	ackErr      error
	nakErr      error
	termErr     error
	ackCount    int
	nakCount    int
	termCount   int
	nakDuration time.Duration
}

func (d *fakeDelivery) Subject() string { return d.subject }
func (d *fakeDelivery) Data() []byte    { return d.data }
func (d *fakeDelivery) Ack(context.Context) error {
	d.ackCount++
	return d.ackErr
}
func (d *fakeDelivery) Nak(_ context.Context, delay time.Duration) error {
	d.nakCount++
	d.nakDuration = delay
	return d.nakErr
}
func (d *fakeDelivery) Term(context.Context) error {
	d.termCount++
	return d.termErr
}

type fakeProjector struct {
	result       ProjectionResult
	err          error
	confirmErr   error
	calls        int
	confirmCalls int
}

func (p *fakeProjector) Project(context.Context, Envelope) (ProjectionResult, error) {
	p.calls++
	return p.result, p.err
}
func (p *fakeProjector) ConfirmOnline(context.Context, ProjectionResult) (bool, error) {
	p.confirmCalls++
	return p.confirmErr == nil, p.confirmErr
}

type fakeLeaseStore struct {
	putErr    error
	putCalls  []LeaseRecord
	exists    map[uuid.UUID]bool
	existsErr error
}

func (s *fakeLeaseStore) Put(_ context.Context, lease LeaseRecord) error {
	s.putCalls = append(s.putCalls, lease)
	return s.putErr
}
func (s *fakeLeaseStore) Exists(_ context.Context, nodeID uuid.UUID) (bool, error) {
	return s.exists[nodeID], s.existsErr
}

type fakeOfflineRepository struct {
	candidates []OfflineCandidate
	marked     []OfflineCandidate
	listErr    error
	markErr    error
}

type fakeHeartbeatJetStream struct {
	calls        []string
	addInfo      *nats.ConsumerInfo
	addErr       error
	readInfo     *nats.ConsumerInfo
	readErr      error
	subscription *nats.Subscription
	subscribeErr error
}

func (f *fakeHeartbeatJetStream) AddConsumer(stream string, _ *nats.ConsumerConfig, _ ...nats.JSOpt) (*nats.ConsumerInfo, error) {
	f.calls = append(f.calls, "AddConsumer:"+stream)
	return f.addInfo, f.addErr
}

func (f *fakeHeartbeatJetStream) ConsumerInfo(stream, consumer string, _ ...nats.JSOpt) (*nats.ConsumerInfo, error) {
	f.calls = append(f.calls, "ConsumerInfo:"+stream+":"+consumer)
	return f.readInfo, f.readErr
}

func (f *fakeHeartbeatJetStream) PullSubscribe(subject, durable string, _ ...nats.SubOpt) (*nats.Subscription, error) {
	f.calls = append(f.calls, "PullSubscribe:"+subject+":"+durable)
	return f.subscription, f.subscribeErr
}

func TestNewNATSConsumerRequiresFinalReadback(t *testing.T) {
	config := NATSConsumerConfig{
		Stream: "AGENT_HEARTBEATS", SubjectPrefix: "cdnca.agent.heartbeats",
		Durable: "control_api_node_presence", AckWait: 45 * time.Second,
		FetchTimeout: 5 * time.Second, OperationTimeout: time.Second, NakDelay: time.Second,
		MaxAckPending: 256, MaxWaiting: 32,
	}
	expected := nats.ConsumerConfig{
		Durable: config.Durable, DeliverPolicy: nats.DeliverAllPolicy,
		AckPolicy: nats.AckExplicitPolicy, AckWait: config.AckWait, MaxDeliver: -1,
		FilterSubject: config.SubjectPrefix + ".*", ReplayPolicy: nats.ReplayInstantPolicy,
		MaxAckPending: config.MaxAckPending, MaxWaiting: config.MaxWaiting,
		MaxRequestBatch: 1, MaxRequestExpires: config.FetchTimeout,
	}
	consumerInfo := func(drift bool) *nats.ConsumerInfo {
		info := &nats.ConsumerInfo{Stream: config.Stream, Name: config.Durable, Config: expected}
		if drift {
			info.Config.MaxRequestBatch++
		}
		return info
	}
	addErr := errors.New("add consumer failed")
	readErr := errors.New("consumer readback failed")
	tests := []struct {
		name        string
		addInfo     *nats.ConsumerInfo
		addErr      error
		readInfo    *nats.ConsumerInfo
		readErr     error
		wantSuccess bool
		wantCalls   string
	}{
		{
			name: "successful add uses final readback", addInfo: consumerInfo(true), readInfo: consumerInfo(false),
			wantSuccess: true,
			wantCalls:   "AddConsumer:AGENT_HEARTBEATS,ConsumerInfo:AGENT_HEARTBEATS:control_api_node_presence,PullSubscribe:cdnca.agent.heartbeats.*:control_api_node_presence",
		},
		{
			name: "successful existing consumer drifts before readback", addInfo: consumerInfo(false), readInfo: consumerInfo(true),
			wantCalls: "AddConsumer:AGENT_HEARTBEATS,ConsumerInfo:AGENT_HEARTBEATS:control_api_node_presence",
		},
		{
			name: "add error recovers from exact readback", addErr: addErr, readInfo: consumerInfo(false),
			wantSuccess: true,
			wantCalls:   "AddConsumer:AGENT_HEARTBEATS,ConsumerInfo:AGENT_HEARTBEATS:control_api_node_presence,PullSubscribe:cdnca.agent.heartbeats.*:control_api_node_presence",
		},
		{
			name: "readback failure never subscribes", addInfo: consumerInfo(false), readErr: readErr,
			wantCalls: "AddConsumer:AGENT_HEARTBEATS,ConsumerInfo:AGENT_HEARTBEATS:control_api_node_presence",
		},
		{
			name: "add error and drifted readback never subscribe", addErr: addErr, readInfo: consumerInfo(true),
			wantCalls: "AddConsumer:AGENT_HEARTBEATS,ConsumerInfo:AGENT_HEARTBEATS:control_api_node_presence",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			js := &fakeHeartbeatJetStream{
				addInfo: test.addInfo, addErr: test.addErr, readInfo: test.readInfo, readErr: test.readErr,
				subscription: &nats.Subscription{},
			}
			consumer, err := newNATSConsumer(js, config)
			if (err == nil) != test.wantSuccess || (consumer != nil) != test.wantSuccess {
				t.Fatalf("newNATSConsumer() = (%v, %v), want success %t", consumer, err, test.wantSuccess)
			}
			if calls := strings.Join(js.calls, ","); calls != test.wantCalls {
				t.Fatalf("calls = %q, want %q", calls, test.wantCalls)
			}
		})
	}
}

func TestHeartbeatConsumerConfigRejectsBehaviorDrift(t *testing.T) {
	const stream = "AGENT_HEARTBEATS"
	expected := &nats.ConsumerConfig{
		Durable: "control_api_node_presence", DeliverPolicy: nats.DeliverAllPolicy,
		AckPolicy: nats.AckExplicitPolicy, AckWait: 45 * time.Second, MaxDeliver: -1,
		FilterSubject: "cdnca.agent.heartbeats.*", ReplayPolicy: nats.ReplayInstantPolicy,
		MaxAckPending: 256, MaxWaiting: 32, MaxRequestBatch: 1, MaxRequestExpires: 5 * time.Second,
	}
	exact := &nats.ConsumerInfo{Stream: stream, Name: expected.Durable, Config: *expected}
	if !sameHeartbeatConsumer(exact, stream, expected) {
		t.Fatal("exact durable heartbeat consumer was rejected")
	}
	if sameHeartbeatConsumer(nil, stream, expected) {
		t.Fatal("nil durable heartbeat consumer was accepted")
	}
	t.Run("nil expected", func(t *testing.T) {
		if sameHeartbeatConsumer(exact, stream, nil) {
			t.Fatal("nil expected heartbeat consumer was accepted")
		}
	})
	zeroTime := time.Time{}
	equivalent := []struct {
		name     string
		actual   nats.ConsumerConfig
		expected nats.ConsumerConfig
	}{
		{name: "nil and empty backoff", actual: func() nats.ConsumerConfig {
			value := *expected
			value.BackOff = []time.Duration{}
			return value
		}(), expected: *expected},
		{name: "empty and nil backoff", actual: *expected, expected: func() nats.ConsumerConfig {
			value := *expected
			value.BackOff = []time.Duration{}
			return value
		}()},
		{name: "nil and empty filter subjects", actual: func() nats.ConsumerConfig {
			value := *expected
			value.FilterSubjects = []string{}
			return value
		}(), expected: *expected},
		{name: "singular and plural filter", actual: func() nats.ConsumerConfig {
			value := *expected
			value.FilterSubject = ""
			value.FilterSubjects = []string{expected.FilterSubject}
			return value
		}(), expected: *expected},
		{name: "plural and singular filter", actual: *expected, expected: func() nats.ConsumerConfig {
			value := *expected
			value.FilterSubjects = []string{value.FilterSubject}
			value.FilterSubject = ""
			return value
		}()},
		{name: "plural filter order", actual: func() nats.ConsumerConfig {
			value := *expected
			value.FilterSubject = ""
			value.FilterSubjects = []string{"heartbeat.eu.*", "heartbeat.ap.*"}
			return value
		}(), expected: func() nats.ConsumerConfig {
			value := *expected
			value.FilterSubject = ""
			value.FilterSubjects = []string{"heartbeat.ap.*", "heartbeat.eu.*"}
			return value
		}()},
		{name: "nil and zero start time", actual: func() nats.ConsumerConfig {
			value := *expected
			value.OptStartTime = &zeroTime
			return value
		}(), expected: *expected},
		{name: "server normalized config name", actual: func() nats.ConsumerConfig {
			value := *expected
			value.Name = value.Durable
			return value
		}(), expected: *expected},
	}
	for _, test := range equivalent {
		t.Run(test.name, func(t *testing.T) {
			candidate := &nats.ConsumerInfo{Stream: stream, Name: test.expected.Durable, Config: test.actual}
			if !sameHeartbeatConsumer(candidate, stream, &test.expected) {
				t.Fatal("server-equivalent durable heartbeat consumer was rejected")
			}
		})
	}

	nonEquivalent := []struct {
		name     string
		actual   nats.ConsumerConfig
		expected nats.ConsumerConfig
	}{
		{name: "backoff order", actual: func() nats.ConsumerConfig {
			value := *expected
			value.BackOff = []time.Duration{2 * time.Second, time.Second}
			return value
		}(), expected: func() nats.ConsumerConfig {
			value := *expected
			value.BackOff = []time.Duration{time.Second, 2 * time.Second}
			return value
		}()},
		{name: "different filter set", actual: func() nats.ConsumerConfig {
			value := *expected
			value.FilterSubject = ""
			value.FilterSubjects = []string{"heartbeat.ap.*", "heartbeat.us.*"}
			return value
		}(), expected: func() nats.ConsumerConfig {
			value := *expected
			value.FilterSubject = ""
			value.FilterSubjects = []string{"heartbeat.ap.*", "heartbeat.eu.*"}
			return value
		}()},
		{name: "duplicate filter", actual: func() nats.ConsumerConfig {
			value := *expected
			value.FilterSubject = ""
			value.FilterSubjects = []string{"heartbeat.ap.*", "heartbeat.ap.*"}
			return value
		}(), expected: func() nats.ConsumerConfig {
			value := *expected
			value.FilterSubject = ""
			value.FilterSubjects = []string{"heartbeat.ap.*"}
			return value
		}()},
		{name: "additional filter", actual: func() nats.ConsumerConfig {
			value := *expected
			value.FilterSubject = ""
			value.FilterSubjects = []string{"heartbeat.ap.*", "heartbeat.eu.*"}
			return value
		}(), expected: func() nats.ConsumerConfig {
			value := *expected
			value.FilterSubject = ""
			value.FilterSubjects = []string{"heartbeat.ap.*"}
			return value
		}()},
	}
	for _, test := range nonEquivalent {
		t.Run(test.name, func(t *testing.T) {
			candidate := &nats.ConsumerInfo{Stream: stream, Name: test.expected.Durable, Config: test.actual}
			if sameHeartbeatConsumer(candidate, stream, &test.expected) {
				t.Fatal("behaviorally different durable heartbeat consumer was accepted")
			}
		})
	}

	startTime := time.Unix(1_700_000_000, 0).UTC()
	tests := []struct {
		name   string
		mutate func(*nats.ConsumerInfo)
	}{
		{name: "stream identity", mutate: func(info *nats.ConsumerInfo) { info.Stream = "OTHER" }},
		{name: "consumer identity", mutate: func(info *nats.ConsumerInfo) { info.Name = "other" }},
		{name: "durable identity", mutate: func(info *nats.ConsumerInfo) { info.Config.Durable = "other" }},
		{name: "config name identity", mutate: func(info *nats.ConsumerInfo) { info.Config.Name = "other" }},
		{name: "start sequence", mutate: func(info *nats.ConsumerInfo) { info.Config.OptStartSeq = 2 }},
		{name: "start time", mutate: func(info *nats.ConsumerInfo) { info.Config.OptStartTime = &startTime }},
		{name: "deliver policy", mutate: func(info *nats.ConsumerInfo) { info.Config.DeliverPolicy = nats.DeliverLastPolicy }},
		{name: "ack policy", mutate: func(info *nats.ConsumerInfo) { info.Config.AckPolicy = nats.AckAllPolicy }},
		{name: "ack wait", mutate: func(info *nats.ConsumerInfo) { info.Config.AckWait++ }},
		{name: "max deliver", mutate: func(info *nats.ConsumerInfo) { info.Config.MaxDeliver = 3 }},
		{name: "backoff", mutate: func(info *nats.ConsumerInfo) { info.Config.BackOff = []time.Duration{time.Second} }},
		{name: "filter subject", mutate: func(info *nats.ConsumerInfo) { info.Config.FilterSubject = "other.>" }},
		{name: "filter subjects", mutate: func(info *nats.ConsumerInfo) {
			info.Config.FilterSubject = ""
			info.Config.FilterSubjects = []string{"other.>"}
		}},
		{name: "replay policy", mutate: func(info *nats.ConsumerInfo) { info.Config.ReplayPolicy = nats.ReplayOriginalPolicy }},
		{name: "rate limit", mutate: func(info *nats.ConsumerInfo) { info.Config.RateLimit = 1 }},
		{name: "sample frequency", mutate: func(info *nats.ConsumerInfo) { info.Config.SampleFrequency = "100%" }},
		{name: "max waiting", mutate: func(info *nats.ConsumerInfo) { info.Config.MaxWaiting++ }},
		{name: "max ack pending", mutate: func(info *nats.ConsumerInfo) { info.Config.MaxAckPending++ }},
		{name: "flow control", mutate: func(info *nats.ConsumerInfo) { info.Config.FlowControl = true }},
		{name: "heartbeat", mutate: func(info *nats.ConsumerInfo) { info.Config.Heartbeat = time.Second }},
		{name: "headers only", mutate: func(info *nats.ConsumerInfo) { info.Config.HeadersOnly = true }},
		{name: "max request batch", mutate: func(info *nats.ConsumerInfo) { info.Config.MaxRequestBatch++ }},
		{name: "max request expires", mutate: func(info *nats.ConsumerInfo) { info.Config.MaxRequestExpires++ }},
		{name: "max request bytes", mutate: func(info *nats.ConsumerInfo) { info.Config.MaxRequestMaxBytes = 1 }},
		{name: "deliver subject", mutate: func(info *nats.ConsumerInfo) { info.Config.DeliverSubject = "push" }},
		{name: "deliver group", mutate: func(info *nats.ConsumerInfo) { info.Config.DeliverGroup = "workers" }},
		{name: "inactive threshold", mutate: func(info *nats.ConsumerInfo) { info.Config.InactiveThreshold = time.Minute }},
		{name: "replicas", mutate: func(info *nats.ConsumerInfo) { info.Config.Replicas = 1 }},
		{name: "memory storage", mutate: func(info *nats.ConsumerInfo) { info.Config.MemoryStorage = true }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := &nats.ConsumerInfo{Stream: exact.Stream, Name: exact.Name, Config: *expected}
			test.mutate(candidate)
			if sameHeartbeatConsumer(candidate, stream, expected) {
				t.Fatal("behavioral durable heartbeat consumer mismatch was accepted")
			}
		})
	}
}

func (r *fakeOfflineRepository) OfflineCandidates(context.Context, time.Time, int) ([]OfflineCandidate, error) {
	return r.candidates, r.listErr
}
func (r *fakeOfflineRepository) MarkOffline(_ context.Context, candidate OfflineCandidate, _ time.Time) (bool, error) {
	if r.markErr != nil {
		return false, r.markErr
	}
	r.marked = append(r.marked, candidate)
	return true, nil
}

func TestValidatorAcceptsCanonicalBoundedHeartbeat(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	validator := newTestValidator(t, now)
	nodeID := uuid.New()
	heartbeat := validPresenceHeartbeat(3, 7, now)
	agentVersion := "2.4.1+build.7"
	heartbeat.AgentVersion = &agentVersion
	payload := marshalHeartbeat(t, heartbeat)
	envelope, err := validator.Decode("cdnca.agent.heartbeats."+nodeID.String(), payload)
	if err != nil {
		t.Fatal(err)
	}
	if envelope.NodeID != nodeID || !proto.Equal(envelope.Heartbeat, heartbeat) || envelope.Digest == [32]byte{} {
		t.Fatalf("decoded heartbeat = %+v", envelope)
	}
	boundary := validPresenceHeartbeat(3, 8, now.Add(-45*time.Second))
	if _, err := validator.Decode("cdnca.agent.heartbeats."+nodeID.String(), marshalHeartbeat(t, boundary)); err != nil {
		t.Fatalf("heartbeat at maximum past-age boundary rejected: %v", err)
	}
}

func TestValidatorRejectsInvalidSubjectPayloadAndVersion(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	validator := newTestValidator(t, now)
	nodeID := uuid.NewString()
	valid := validPresenceHeartbeat(1, 1, now)
	tests := []struct {
		name      string
		subject   string
		heartbeat *agentv1.Heartbeat
		payload   []byte
	}{
		{name: "non-canonical node", subject: "cdnca.agent.heartbeats." + strings.ToUpper(nodeID), heartbeat: valid},
		{name: "extra subject token", subject: "cdnca.agent.heartbeats." + nodeID + ".extra", heartbeat: valid},
		{name: "malformed protobuf", subject: "cdnca.agent.heartbeats." + nodeID, payload: []byte{0xff}},
		{name: "missing runtime", subject: "cdnca.agent.heartbeats." + nodeID, heartbeat: cloneHeartbeat(valid, func(value *agentv1.Heartbeat) { value.Runtime = nil })},
		{name: "unknown runtime", subject: "cdnca.agent.heartbeats." + nodeID, heartbeat: cloneHeartbeat(valid, func(value *agentv1.Heartbeat) { value.Runtime.OpenrestyState = 99 })},
		{name: "unknown market probe role", subject: "cdnca.agent.heartbeats." + nodeID, heartbeat: cloneHeartbeat(valid, func(value *agentv1.Heartbeat) { value.Runtime.MarketProbe = 9 })},
		{name: "oversized epoch", subject: "cdnca.agent.heartbeats." + nodeID, heartbeat: cloneHeartbeat(valid, func(value *agentv1.Heartbeat) { value.SessionEpoch = math.MaxUint64 })},
		{name: "empty agent version", subject: "cdnca.agent.heartbeats." + nodeID, heartbeat: cloneHeartbeat(valid, func(value *agentv1.Heartbeat) { value.AgentVersion = new(string) })},
		{name: "unsafe agent version", subject: "cdnca.agent.heartbeats." + nodeID, heartbeat: cloneHeartbeat(valid, func(value *agentv1.Heartbeat) { version := "2.4.1 beta"; value.AgentVersion = &version })},
		{name: "future timestamp", subject: "cdnca.agent.heartbeats." + nodeID, heartbeat: cloneHeartbeat(valid, func(value *agentv1.Heartbeat) { value.Event.OccurredTime = timestamppb.New(now.Add(6 * time.Minute)) })},
		{name: "expired timestamp", subject: "cdnca.agent.heartbeats." + nodeID, heartbeat: cloneHeartbeat(valid, func(value *agentv1.Heartbeat) {
			value.Event.OccurredTime = timestamppb.New(now.Add(-45*time.Second - time.Nanosecond))
		})},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload := test.payload
			if payload == nil {
				payload = marshalHeartbeat(t, test.heartbeat)
			}
			if _, err := validator.Decode(test.subject, payload); !errors.Is(err, ErrInvalidHeartbeat) {
				t.Fatalf("Decode() error = %v", err)
			}
		})
	}
}

func TestProcessorTerminatesExpiredHeartbeatBeforeProjection(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	validator := newTestValidator(t, now)
	nodeID := uuid.New()
	heartbeat := validPresenceHeartbeat(1, 1, now.Add(-time.Minute))
	delivery := &fakeDelivery{
		subject: "cdnca.agent.heartbeats." + nodeID.String(), data: marshalHeartbeat(t, heartbeat),
	}
	projector := &fakeProjector{}
	leases := &fakeLeaseStore{}
	processor, err := NewProcessor(validator, projector, leases, time.Second, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	disposition, err := processor.Process(context.Background(), delivery)
	if err != nil || disposition != DispositionTerm || delivery.termCount != 1 || projector.calls != 0 ||
		projector.confirmCalls != 0 || len(leases.putCalls) != 0 || delivery.ackCount != 0 || delivery.nakCount != 0 {
		t.Fatalf("expired heartbeat result=(%q,%v) term=%d project=%d confirm=%d lease=%d ack=%d nak=%d",
			disposition, err, delivery.termCount, projector.calls, projector.confirmCalls,
			len(leases.putCalls), delivery.ackCount, delivery.nakCount)
	}
}

func TestProcessorClassifiesAckNakAndTerm(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	validator := newTestValidator(t, now)
	nodeID := uuid.New()
	heartbeat := validPresenceHeartbeat(2, 4, now)
	deliveryFor := func() *fakeDelivery {
		return &fakeDelivery{subject: "cdnca.agent.heartbeats." + nodeID.String(), data: marshalHeartbeat(t, heartbeat)}
	}
	projection := ProjectionResult{
		NodeID: nodeID, SessionEpoch: 2, HeartbeatSequence: 4,
		EventID: uuid.MustParse(heartbeat.Event.EventId), Digest: [32]byte{1}, ProjectedAt: now,
		LeaseExpiresAt: now.Add(45 * time.Second), Status: StatusOnline,
		Outcome: OutcomeAdvanced, RefreshLease: true,
	}
	tests := []struct {
		name          string
		mutate        func(*fakeDelivery, *fakeProjector, *fakeLeaseStore)
		want          string
		wantError     bool
		wantAck       int
		wantNak       int
		wantTerm      int
		wantLeasePuts int
		wantConfirms  int
	}{
		{name: "success", want: DispositionAck, wantAck: 1, wantLeasePuts: 1, wantConfirms: 1},
		{name: "stale skips lease", mutate: func(_ *fakeDelivery, projector *fakeProjector, _ *fakeLeaseStore) {
			projector.result.Outcome = OutcomeStale
			projector.result.RefreshLease = false
		}, want: DispositionAck, wantAck: 1},
		{name: "postgres transient", mutate: func(_ *fakeDelivery, projector *fakeProjector, _ *fakeLeaseStore) {
			projector.err = errors.New("postgres unavailable")
		}, want: DispositionNak, wantNak: 1},
		{name: "redis transient", mutate: func(_ *fakeDelivery, _ *fakeProjector, leases *fakeLeaseStore) {
			leases.putErr = errors.New("redis unavailable")
		}, want: DispositionNak, wantNak: 1, wantLeasePuts: 1},
		{name: "online confirmation transient", mutate: func(_ *fakeDelivery, projector *fakeProjector, _ *fakeLeaseStore) {
			projector.confirmErr = errors.New("postgres unavailable")
		}, want: DispositionNak, wantNak: 1, wantLeasePuts: 1, wantConfirms: 1},
		{name: "unknown node", mutate: func(_ *fakeDelivery, projector *fakeProjector, _ *fakeLeaseStore) {
			projector.err = ErrNodeNotFound
		}, want: DispositionTerm, wantTerm: 1},
		{name: "projection conflict", mutate: func(_ *fakeDelivery, projector *fakeProjector, _ *fakeLeaseStore) {
			projector.err = ErrProjectionConflict
		}, want: DispositionTerm, wantTerm: 1},
		{name: "malformed", mutate: func(delivery *fakeDelivery, _ *fakeProjector, _ *fakeLeaseStore) {
			delivery.data = []byte{0xff}
		}, want: DispositionTerm, wantTerm: 1},
		{name: "ack transport failure", mutate: func(delivery *fakeDelivery, _ *fakeProjector, _ *fakeLeaseStore) {
			delivery.ackErr = errors.New("ack failed")
		}, want: DispositionAck, wantError: true, wantAck: 1, wantLeasePuts: 1, wantConfirms: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			delivery := deliveryFor()
			projector := &fakeProjector{result: projection}
			leases := &fakeLeaseStore{}
			if test.mutate != nil {
				test.mutate(delivery, projector, leases)
			}
			processor, err := NewProcessor(validator, projector, leases, time.Second, 5*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			disposition, err := processor.Process(context.Background(), delivery)
			if disposition != test.want || (err != nil) != test.wantError {
				t.Fatalf("Process() = (%q, %v)", disposition, err)
			}
			if delivery.ackCount != test.wantAck || delivery.nakCount != test.wantNak ||
				delivery.termCount != test.wantTerm || len(leases.putCalls) != test.wantLeasePuts ||
				projector.confirmCalls != test.wantConfirms {
				t.Fatalf("calls ack=%d nak=%d term=%d lease=%d confirm=%d", delivery.ackCount, delivery.nakCount,
					delivery.termCount, len(leases.putCalls), projector.confirmCalls)
			}
		})
	}
}

func TestOfflineWorkerRequiresExpiredPostgresAndMissingRedisLease(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	leased := uuid.New()
	expired := uuid.New()
	repository := &fakeOfflineRepository{candidates: []OfflineCandidate{
		{NodeID: leased, SessionEpoch: 1, HeartbeatSequence: 2, LastSeenAt: now.Add(-time.Minute)},
		{NodeID: expired, SessionEpoch: 2, HeartbeatSequence: 3, LastSeenAt: now.Add(-time.Minute)},
	}}
	leases := &fakeLeaseStore{exists: map[uuid.UUID]bool{leased: true}}
	worker, err := NewOfflineWorker(repository, leases, 45*time.Second, time.Second, 5*time.Second, 100)
	if err != nil {
		t.Fatal(err)
	}
	worker.now = func() time.Time { return now }
	changed, err := worker.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if changed != 1 || len(repository.marked) != 1 || repository.marked[0].NodeID != expired {
		t.Fatalf("offline transitions = %d marked=%+v", changed, repository.marked)
	}
}

func TestOfflineWorkerDoesNotTreatRedisFailureAsLeaseAbsence(t *testing.T) {
	nodeID := uuid.New()
	repository := &fakeOfflineRepository{candidates: []OfflineCandidate{{NodeID: nodeID}}}
	leases := &fakeLeaseStore{existsErr: errors.New("redis unavailable")}
	worker, err := NewOfflineWorker(repository, leases, 45*time.Second, time.Second, time.Second, 10)
	if err != nil {
		t.Fatal(err)
	}
	if changed, err := worker.RunOnce(context.Background()); err == nil || changed != 0 || len(repository.marked) != 0 {
		t.Fatalf("RunOnce() = (%d, %v), marked=%d", changed, err, len(repository.marked))
	}
}

func newTestValidator(t *testing.T, now time.Time) *Validator {
	t.Helper()
	validator, err := NewValidator(ValidatorConfig{
		SubjectPrefix: "cdnca.agent.heartbeats", MaxHeartbeatBytes: 1 << 20,
		MaxActiveDeployments: 128, MaxFutureSkew: 5 * time.Minute, MaxPastAge: 45 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	validator.now = func() time.Time { return now }
	return validator
}

func validPresenceHeartbeat(epoch, sequence uint64, occurredAt time.Time) *agentv1.Heartbeat {
	return &agentv1.Heartbeat{
		Event: &commonv1.EventMetadata{
			EventId: uuid.NewString(), RequestId: uuid.NewString(), OccurredTime: timestamppb.New(occurredAt),
		},
		SessionEpoch: epoch, HeartbeatSequence: sequence,
		Runtime: &agentv1.EdgeRuntimeStatus{
			OpenrestyState: agentv1.RuntimeState_RUNTIME_STATE_RUNNING,
			FirewallState:  agentv1.RuntimeState_RUNTIME_STATE_RUNNING,
		},
		Resources: &agentv1.ResourceUsage{FilesystemTotalBytes: 1024, FilesystemAvailableBytes: 512, CacheUsedBytes: 128},
	}
}

func marshalHeartbeat(t *testing.T, heartbeat *agentv1.Heartbeat) []byte {
	t.Helper()
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(heartbeat)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func cloneHeartbeat(heartbeat *agentv1.Heartbeat, mutate func(*agentv1.Heartbeat)) *agentv1.Heartbeat {
	cloned := proto.Clone(heartbeat).(*agentv1.Heartbeat)
	mutate(cloned)
	return cloned
}
