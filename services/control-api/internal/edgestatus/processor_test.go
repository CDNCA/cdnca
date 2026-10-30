package edgestatus

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
)

type fakeDelivery struct {
	subject        string
	data           []byte
	acks           int
	naks           int
	terms          int
	nakDelay       time.Duration
	dispositionErr error
	delivered      uint64
}

func (d *fakeDelivery) NumDelivered() uint64 { return d.delivered }

func (d *fakeDelivery) Subject() string { return d.subject }
func (d *fakeDelivery) Data() []byte    { return d.data }
func (d *fakeDelivery) Ack(context.Context) error {
	d.acks++
	return d.dispositionErr
}
func (d *fakeDelivery) Nak(_ context.Context, delay time.Duration) error {
	d.naks++
	d.nakDelay = delay
	return d.dispositionErr
}
func (d *fakeDelivery) Term(context.Context) error {
	d.terms++
	return d.dispositionErr
}

type fakeProjector struct {
	err           error
	waitForCancel bool
	calls         int
}

func (p *fakeProjector) Project(ctx context.Context, _ Envelope) (ProjectionResult, error) {
	p.calls++
	if p.waitForCancel {
		<-ctx.Done()
		return ProjectionResult{}, ctx.Err()
	}
	return ProjectionResult{Outcome: OutcomeAdvanced}, p.err
}

func TestProcessorAckNakAndTerm(t *testing.T) {
	now := time.Now().UTC()
	nodeID := uuid.New()
	valid := validStatus(now, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED, 1)
	tests := []struct {
		name       string
		payload    []byte
		projectErr error
		want       string
	}{
		{name: "ack committed status", payload: marshalStatus(t, valid), want: DispositionAck},
		{name: "nak database failure", payload: marshalStatus(t, valid), projectErr: errors.New("database unavailable"), want: DispositionNak},
		{name: "term binding conflict", payload: marshalStatus(t, valid), projectErr: ErrBindingConflict, want: DispositionTerm},
		{name: "term malformed protobuf", payload: []byte("invalid"), want: DispositionTerm},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			validator := testValidator(t, now)
			projector := &fakeProjector{err: test.projectErr}
			processor, err := NewProcessor(validator, projector, 25*time.Millisecond, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			delivery := &fakeDelivery{subject: DefaultSubjectPrefix + "." + nodeID.String(), data: test.payload}
			disposition, err := processor.Process(context.Background(), delivery)
			if err != nil || disposition != test.want {
				t.Fatalf("Process() = (%q, %v), want (%q, nil)", disposition, err, test.want)
			}
			if delivery.acks+delivery.naks+delivery.terms != 1 {
				t.Fatalf("delivery dispositions = ack:%d nak:%d term:%d", delivery.acks, delivery.naks, delivery.terms)
			}
			if test.want == DispositionNak && delivery.nakDelay != 25*time.Millisecond {
				t.Fatalf("nak delay = %s", delivery.nakDelay)
			}
		})
	}
}

func TestProcessorDoesNotDispositionAfterCancellation(t *testing.T) {
	now := time.Now().UTC()
	validator := testValidator(t, now)
	projector := &fakeProjector{waitForCancel: true}
	processor, err := NewProcessor(validator, projector, time.Millisecond, 10*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	delivery := &fakeDelivery{
		subject: DefaultSubjectPrefix + "." + uuid.NewString(),
		data:    marshalStatus(t, validStatus(now, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED, 1)),
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	disposition, err := processor.Process(ctx, delivery)
	if !errors.Is(err, context.Canceled) || disposition != "" || delivery.acks+delivery.naks+delivery.terms != 0 {
		t.Fatalf("cancelled Process() = (%q, %v), delivery=%+v", disposition, err, delivery)
	}
}

func TestProcessorReportsAckFailureAfterProjection(t *testing.T) {
	now := time.Now().UTC()
	processor, err := NewProcessor(testValidator(t, now), &fakeProjector{}, time.Millisecond, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	delivery := &fakeDelivery{
		subject:        DefaultSubjectPrefix + "." + uuid.NewString(),
		data:           marshalStatus(t, validStatus(now, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED, 1)),
		dispositionErr: errors.New("ack unavailable"),
	}
	disposition, err := processor.Process(context.Background(), delivery)
	if disposition != DispositionAck || err == nil || delivery.acks != 1 {
		t.Fatalf("ack failure result = (%q, %v), delivery=%+v", disposition, err, delivery)
	}
}

// Reproduction: the healthy status of the last deployment of a rollout
// failed its projection on every delivery (P8903 from the 089 site claim guard
// on the IPv6 observation write) and was Nak'd forever with nothing in the
// control-api log, while the node held the gateway's persisted receipt. Every
// retry and refusal now names the deployment and transition sequence.
func TestProcessorLogsRetriedAndRefusedStatuses(t *testing.T) {
	now := time.Now().UTC()
	nodeID := uuid.New()
	healthy := validStatus(now, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY, 7)
	claimGuard := errors.New("project deployment status: project site IPv6 rollout terminal state: " +
		"ERROR: active DNS provider mutation claim blocks site authority mutation (SQLSTATE P8903)")
	for _, test := range []struct {
		name       string
		projectErr error
		delivered  uint64
		want       string
		logged     []string
	}{
		{name: "first retry", projectErr: claimGuard, delivered: 1, want: DispositionNak,
			logged: []string{"level=WARN", "will be redelivered", "transition_sequence=7", "state=NODE_DEPLOYMENT_STATE_HEALTHY", "deliveries=1", "P8903"}},
		{name: "minute retry", projectErr: claimGuard, delivered: 120, want: DispositionNak,
			logged: []string{"will be redelivered", "deliveries=120"}},
		{name: "quiet retry", projectErr: claimGuard, delivered: 17, want: DispositionNak},
		{name: "refused", projectErr: ErrInvalidTransition, delivered: 1, want: DispositionTerm,
			logged: []string{"level=ERROR", "projection refused, terminated", "transition_sequence=7"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			processor, err := NewProcessor(testValidator(t, now), &fakeProjector{err: test.projectErr}, time.Second, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			processor.SetLogger(slog.New(slog.NewTextHandler(&output, nil)))
			delivery := &fakeDelivery{subject: DefaultSubjectPrefix + "." + nodeID.String(),
				data: marshalStatus(t, healthy), delivered: test.delivered}
			disposition, err := processor.Process(context.Background(), delivery)
			if err != nil || disposition != test.want || delivery.acks != 0 {
				t.Fatalf("Process() = (%q, %v), acks=%d, want %q without ack", disposition, err, delivery.acks, test.want)
			}
			logged := output.String()
			if len(test.logged) == 0 {
				if logged != "" {
					t.Fatalf("unexpected log %q", logged)
				}
				return
			}
			for _, want := range append(test.logged, "deployment_id="+healthy.DeploymentId, "node_id="+nodeID.String()) {
				if !strings.Contains(logged, want) {
					t.Errorf("log %q missing %q", logged, want)
				}
			}
		})
	}
}

func TestProcessorLogsUndecodableStatus(t *testing.T) {
	var output bytes.Buffer
	processor, err := NewProcessor(testValidator(t, time.Now().UTC()), &fakeProjector{}, time.Second, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	processor.SetLogger(slog.New(slog.NewTextHandler(&output, nil)))
	delivery := &fakeDelivery{subject: DefaultSubjectPrefix + "." + uuid.NewString(), data: []byte("invalid")}
	if disposition, err := processor.Process(context.Background(), delivery); err != nil || disposition != DispositionTerm {
		t.Fatalf("Process() = (%q, %v)", disposition, err)
	}
	if !strings.Contains(output.String(), "undecodable, terminated") || !strings.Contains(output.String(), delivery.subject) {
		t.Fatalf("log %q", output.String())
	}
}
