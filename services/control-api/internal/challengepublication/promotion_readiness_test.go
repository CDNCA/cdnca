package challengepublication

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/google/uuid"
)

// A challenge secret rollout promotes once at least
// one target node installed it and no online node failed it; nodes that are
// offline, isolated or disabled do not hold the promotion back (they are
// deferred to the redeliverer).
func TestClassifyPromotionNodes(t *testing.T) {
	ids := make([]uuid.UUID, 11)
	for index := range ids {
		ids[index] = uuid.New()
	}
	online := func(id uuid.UUID, state string) PromotionNodeFact {
		return PromotionNodeFact{NodeID: id, DeploymentState: state, Active: true, Online: true}
	}
	facts := []PromotionNodeFact{
		online(ids[0], "healthy"),
		online(ids[1], "queued"),
		online(ids[2], "failed"),
		online(ids[3], "cancelled"),
		{NodeID: ids[4], DeploymentState: "queued", Active: true, Online: true, DeadlinePassed: true},
		{NodeID: ids[5], DeploymentState: "queued", Active: true},
		{NodeID: ids[6], DeploymentState: "failed", Active: true},
		{NodeID: ids[7], DeploymentState: "staged", Active: true, Online: true, Isolated: true},
		{NodeID: ids[8], DeploymentState: "healthy", Active: true, Isolated: true},
		{NodeID: ids[9], DeploymentState: "healthy", Online: true},
		online(ids[10], "healthy"),
	}
	planned := slices.Delete(slices.Clone(ids), 10, 11)
	readiness := ClassifyPromotionNodes(facts, planned)
	assertNodes := func(name string, got []uuid.UUID, want ...uuid.UUID) {
		t.Helper()
		slices.SortFunc(want, func(a, b uuid.UUID) int { return bytes.Compare(a[:], b[:]) })
		if !slices.Equal(got, want) {
			t.Fatalf("%s = %v, want %v", name, got, want)
		}
	}
	// Healthy nodes are ready wherever they are (a binding to an offline or
	// isolated node waits in its queue as any release does).
	assertNodes("ready", readiness.Ready, ids[0], ids[8])
	// An online node still applying holds the promotion.
	assertNodes("waiting", readiness.Waiting, ids[1])
	// An online node that failed, was cancelled or is past its deadline
	// refuses it.
	assertNodes("failed", readiness.Failed, ids[2], ids[3], ids[4])
	// Offline, isolated and disabled nodes, and nodes the scope no longer
	// plans (here ids[10]), are left to the redeliverer.
	assertNodes("deferred", readiness.Deferred, ids[5], ids[6], ids[7], ids[9], ids[10])
}

// A node that ignored the secret as an old release (it runs a
// newer revision) does not refuse the promotion; it is left to the
// redeliverer, as the newer revision may not carry this secret.
func TestClassifyPromotionNodesDefersIgnoredOldRelease(t *testing.T) {
	ready, ignored := uuid.New(), uuid.New()
	readiness := ClassifyPromotionNodes([]PromotionNodeFact{
		{NodeID: ready, DeploymentState: "healthy", Active: true, Online: true},
		{NodeID: ignored, DeploymentState: "failed", Superseded: true, Active: true, Online: true},
	}, []uuid.UUID{ready, ignored})
	if !slices.Equal(readiness.Ready, []uuid.UUID{ready}) || len(readiness.Failed) != 0 ||
		!slices.Equal(readiness.Deferred, []uuid.UUID{ignored}) {
		t.Fatalf("readiness = %+v", readiness)
	}
}

func TestRuntimePromoteGatesOnNodeReadiness(t *testing.T) {
	request := validRuntimePublishRequest(uuid.New(), uuid.New(), uuid.New(), uuid.New())
	ready, offline := request.NodeIDs[0], request.NodeIDs[1]
	secret := SecretPublication{RolloutID: uuid.New(), ConfigVersionID: uuid.New(), Revision: 1}
	// The rollout as a whole still runs: the offline node never received it.
	rollouts := &runtimeRolloutReaderStub{status: RolloutStatus{RolloutID: secret.RolloutID,
		ConfigVersionID: secret.ConfigVersionID, Revision: 1, State: StateRunning, Reason: ReasonWaitingForNodes,
		Total: 2, Healthy: 1, Pending: 1}}
	bindings := &bindingRecorder{result: ConfigPublication{PublicationID: uuid.New(), Revision: 3}}
	runtime, err := NewRuntime(&runtimeKeyResolverStub{}, &runtimeSecretPublisherStub{}, rollouts, bindings)
	if err != nil {
		t.Fatal(err)
	}
	promote := func(readiness NodeReadiness) (PromotionStatus, error) {
		return runtime.Promote(context.Background(), PromoteRequest{PublishRequest: request, Secret: secret,
			Readiness: readiness})
	}

	status, err := promote(NodeReadiness{Ready: []uuid.UUID{ready}, Deferred: []uuid.UUID{offline}})
	if err != nil || status.State != StateActive || status.ConfigPublication == nil || len(bindings.requests) != 1 {
		t.Fatalf("Promote with an offline node = (%+v, %v), bindings %d", status, err, len(bindings.requests))
	}
	binding := bindings.requests[0]
	if !slices.Equal(binding.NodeIDs, []uuid.UUID{ready}) || !slices.Equal(binding.DeferredNodeIDs, []uuid.UUID{offline}) {
		t.Fatalf("binding nodes = %v deferred %v", binding.NodeIDs, binding.DeferredNodeIDs)
	}

	// An online node still applying: wait, nothing published.
	status, err = promote(NodeReadiness{Ready: []uuid.UUID{ready}, Waiting: []uuid.UUID{offline}})
	if !errors.Is(err, ErrRolloutNotHealthy) || status.State != StateRunning || status.Reason != ReasonWaitingForNodes ||
		len(bindings.requests) != 1 {
		t.Fatalf("Promote while a node applies = (%+v, %v)", status, err)
	}
	// An online node failed: refused even though another node is healthy.
	status, err = promote(NodeReadiness{Ready: []uuid.UUID{ready}, Failed: []uuid.UUID{offline}})
	if !errors.Is(err, ErrRolloutFailed) || status.State != StateFailed || status.Reason != ReasonNodeApplyFailed ||
		len(bindings.requests) != 1 {
		t.Fatalf("Promote with a failed online node = (%+v, %v)", status, err)
	}
	// No node installed it yet: nothing to promote.
	status, err = promote(NodeReadiness{Deferred: []uuid.UUID{ready, offline}})
	if !errors.Is(err, ErrRolloutNotHealthy) || status.State != StateRunning || len(bindings.requests) != 1 {
		t.Fatalf("Promote with every node deferred = (%+v, %v)", status, err)
	}
	// The classification must cover the rollout's nodes exactly once.
	for _, readiness := range []NodeReadiness{
		{Ready: []uuid.UUID{ready}},
		{Ready: []uuid.UUID{ready, offline}, Deferred: []uuid.UUID{offline}},
		{Ready: []uuid.UUID{ready}, Deferred: []uuid.UUID{uuid.New()}},
	} {
		if _, err := promote(readiness); !errors.Is(err, ErrInvalidRuntime) {
			t.Fatalf("Promote(%+v) error = %v, want ErrInvalidRuntime", readiness, err)
		}
	}
	if len(bindings.requests) != 1 {
		t.Fatalf("bindings = %d", len(bindings.requests))
	}
}

type bindingRecorder struct {
	result   ConfigPublication
	requests []BindingRequest
}

func (recorder *bindingRecorder) PublishChallengeBinding(_ context.Context, request BindingRequest) (ConfigPublication, error) {
	recorder.requests = append(recorder.requests, request)
	return recorder.result, nil
}
