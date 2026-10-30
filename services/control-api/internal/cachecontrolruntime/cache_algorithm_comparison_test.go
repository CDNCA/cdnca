package cachecontrolruntime

import (
	"context"
	"crypto/sha256"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/cachecontrol"
	"github.com/google/uuid"
)

var cacheAlgorithmDelaySink time.Duration

func TestCacheAlgorithmComparisonReadyNodePagination(t *testing.T) {
	scopeID := cacheAlgorithmUUID("ready-scope")
	onlineNodeID := cacheAlgorithmUUID("ready-node-1000")
	nodes := make([]queuedNode, 1001)
	for index := range nodes {
		nodes[index] = queuedNode{
			ScopeID: scopeID, NodeID: cacheAlgorithmUUID(fmt.Sprintf("ready-node-%04d", index)),
			FirstCreated: runtimeTestNow.Add(time.Duration(index) * time.Microsecond),
		}
	}
	nodes[len(nodes)-1].NodeID = onlineNodeID
	events := []string{}
	claim := cacheAlgorithmClaim("ready-claim", scopeID, onlineNodeID)
	control := &cacheAlgorithmControl{claims: map[uuid.UUID][]cachecontrol.Claim{scopeID: {claim}}, events: &events}
	repository := &cacheAlgorithmRepository{scopes: []uuid.UUID{scopeID}, nodes: nodes}
	bus := &cacheAlgorithmBus{labels: map[string]string{claim.OperationID.String(): "ready"}, events: &events}
	config := DefaultConfig()
	config.Clock = func() time.Time { return runtimeTestNow }
	config.ClaimBatch = 1
	runtime := &Runtime{
		config: config, control: control, repository: repository,
		leases: cacheAlgorithmLeases{online: map[uuid.UUID]bool{onlineNodeID: true}}, bus: bus,
	}

	result, err := runtime.RunSchedulerOnce(context.Background())
	if err != nil || result.Claimed != 1 || result.Published != 1 || result.Offline != 1000 || repository.calls != 2 {
		t.Fatalf("current pagination result=%+v calls=%d events=%v error=%v", result, repository.calls, events, err)
	}
	baselineClaimed := 0
	for _, node := range nodes[:1000] {
		if node.NodeID == onlineNodeID {
			baselineClaimed = 1
			break
		}
	}
	if baselineClaimed != 0 {
		t.Fatal("first-page baseline unexpectedly reached the online node")
	}
	t.Logf("CACHE_COMPARE ready_pagination current_claimed=%d current_pages=%d current_inspected=%d baseline_claimed=%d baseline_pages=1 baseline_inspected=1000",
		result.Claimed, repository.calls, result.Offline+result.Claimed, baselineClaimed)
}

func TestCacheAlgorithmComparisonCompensationBeforeNewClaim(t *testing.T) {
	scopeID := cacheAlgorithmUUID("compensation-scope")
	nodeID := cacheAlgorithmUUID("compensation-node")
	recovery := cacheAlgorithmClaim("recovery", scopeID, nodeID)
	fresh := cacheAlgorithmClaim("fresh", scopeID, nodeID)
	events := []string{}
	control := &cacheAlgorithmControl{
		open: []cachecontrol.Claim{recovery}, claims: map[uuid.UUID][]cachecontrol.Claim{scopeID: {fresh}}, events: &events,
	}
	repository := &cacheAlgorithmRepository{scopes: []uuid.UUID{scopeID}, nodes: []queuedNode{{
		ScopeID: scopeID, NodeID: nodeID, FirstCreated: runtimeTestNow,
	}}}
	bus := &cacheAlgorithmBus{labels: map[string]string{
		recovery.OperationID.String(): "recovery", fresh.OperationID.String(): "fresh",
	}, events: &events}
	config := DefaultConfig()
	config.Clock = func() time.Time { return runtimeTestNow }
	config.ClaimBatch = 2
	runtime := &Runtime{
		config: config, control: control, repository: repository,
		leases: cacheAlgorithmLeases{online: map[uuid.UUID]bool{nodeID: true}}, bus: bus,
	}

	result, err := runtime.RunSchedulerOnce(context.Background())
	want := []string{"open", "publish:recovery", "claim:fresh", "publish:fresh"}
	if err != nil || result.Recovered != 1 || result.Claimed != 1 || !reflect.DeepEqual(events, want) {
		t.Fatalf("compensation result=%+v events=%v want=%v error=%v", result, events, want, err)
	}
	baseline := []string{"claim:fresh", "publish:fresh", "publish:recovery"}
	t.Logf("CACHE_COMPARE compensation_order current=%s current_recovery_rank=1 baseline=%s baseline_recovery_rank=3",
		strings.Join(events, ">"), strings.Join(baseline, ">"))
}

func TestCacheAlgorithmComparisonBoundedBackoff(t *testing.T) {
	current := make([]time.Duration, 8)
	baseline := make([]time.Duration, 8)
	for index := range current {
		delivery := uint64(index + 1)
		current[index] = retryDelay(time.Second, 30*time.Second, delivery)
		baseline[index] = time.Second << index
	}
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 30 * time.Second, 30 * time.Second, 30 * time.Second}
	if !reflect.DeepEqual(current, want) || baseline[len(baseline)-1] != 128*time.Second {
		t.Fatalf("backoff current=%v baseline=%v", current, baseline)
	}
	t.Logf("CACHE_COMPARE transport_backoff current=%v baseline_uncapped=%v current_max=%s baseline_max=%s",
		current, baseline, current[len(current)-1], baseline[len(baseline)-1])
}

func BenchmarkCacheAlgorithmComparisonRetryDelay(b *testing.B) {
	b.Run("current_bounded", func(b *testing.B) {
		for index := 0; index < b.N; index++ {
			cacheAlgorithmDelaySink = retryDelay(time.Second, 30*time.Second, uint64(index%8+1))
		}
	})
	b.Run("simple_uncapped", func(b *testing.B) {
		for index := 0; index < b.N; index++ {
			cacheAlgorithmDelaySink = time.Second << (index % 8)
		}
	})
}

type cacheAlgorithmControl struct {
	open   []cachecontrol.Claim
	claims map[uuid.UUID][]cachecontrol.Claim
	events *[]string
}

func (control *cacheAlgorithmControl) OpenClaims(context.Context, cachecontrol.OpenClaimsRequest) ([]cachecontrol.Claim, error) {
	*control.events = append(*control.events, "open")
	return append([]cachecontrol.Claim(nil), control.open...), nil
}

func (*cacheAlgorithmControl) ResolveClaim(context.Context, cachecontrol.ClaimIdentity) (cachecontrol.Claim, error) {
	return cachecontrol.Claim{}, nil
}

func (*cacheAlgorithmControl) ReconcileExpired(context.Context, uuid.UUID, string) error { return nil }

func (control *cacheAlgorithmControl) Claim(_ context.Context, request cachecontrol.ClaimRequest) ([]cachecontrol.Claim, error) {
	values := control.claims[request.ScopeID]
	if len(values) == 0 {
		return nil, nil
	}
	claim := values[0]
	control.claims[request.ScopeID] = values[1:]
	*control.events = append(*control.events, "claim:"+controlLabel(claim.OperationID))
	return []cachecontrol.Claim{claim}, nil
}

func (*cacheAlgorithmControl) Report(context.Context, cachecontrol.ReportRequest) (cachecontrol.ReportResult, error) {
	return cachecontrol.ReportResult{}, nil
}

type cacheAlgorithmRepository struct {
	scopes []uuid.UUID
	nodes  []queuedNode
	calls  int
}

func (repository *cacheAlgorithmRepository) activeScopes(context.Context) ([]uuid.UUID, error) {
	return append([]uuid.UUID(nil), repository.scopes...), nil
}

func (repository *cacheAlgorithmRepository) readyNodes(_ context.Context, _ time.Time, after *queuedNode, limit int) ([]queuedNode, error) {
	repository.calls++
	start := 0
	if after != nil {
		for index, node := range repository.nodes {
			if node.ScopeID == after.ScopeID && node.NodeID == after.NodeID && node.FirstCreated.Equal(after.FirstCreated) {
				start = index + 1
				break
			}
		}
	}
	end := min(start+limit, len(repository.nodes))
	return append([]queuedNode(nil), repository.nodes[start:end]...), nil
}

type cacheAlgorithmLeases struct{ online map[uuid.UUID]bool }

func (leases cacheAlgorithmLeases) Exists(_ context.Context, nodeID uuid.UUID) (bool, error) {
	return leases.online[nodeID], nil
}

type cacheAlgorithmBus struct {
	labels map[string]string
	events *[]string
}

func (bus *cacheAlgorithmBus) PublishCommand(_ context.Context, _ string, command *agentv1.CacheControlCommand) (bool, error) {
	*bus.events = append(*bus.events, "publish:"+bus.labels[command.ControlOperationId])
	return false, nil
}

func (*cacheAlgorithmBus) PublishDLQ(context.Context, delivery, string) error { return nil }
func (*cacheAlgorithmBus) PublishCancel(context.Context, string, *agentv1.CacheControlCancel) error {
	return nil
}

func cacheAlgorithmClaim(label string, scopeID, nodeID uuid.UUID) cachecontrol.Claim {
	digest := sha256.Sum256([]byte("cache-algorithm-" + label))
	return cachecontrol.Claim{
		OperationID: cacheAlgorithmUUID("operation-" + label), ScopeID: scopeID,
		TenantID: cacheAlgorithmUUID("tenant-" + label), SiteID: cacheAlgorithmUUID("site-" + label),
		NodeID: nodeID, Action: cachecontrol.ActionPurge, TargetType: cachecontrol.TargetExactURL,
		Attempt: 1, LeaseID: cacheAlgorithmUUID("lease-" + label), WorkerID: "algorithm-worker",
		ClaimedAt: runtimeTestNow, LeaseExpiresAt: runtimeTestNow.Add(time.Hour),
		RequestDigest: digest, Priority: "normal", ConfigVersionID: cacheAlgorithmUUID("config-" + label), ConfigRevision: 1,
		Targets: []cachecontrol.Target{{Ordinal: 1, CanonicalURL: "https://cache.example/" + label, CanonicalPath: "/" + label}},
	}
}

func cacheAlgorithmUUID(label string) uuid.UUID {
	return uuid.NewSHA1(cacheCommandNamespace, []byte("algorithm-comparison:"+label))
}

func controlLabel(operationID uuid.UUID) string {
	switch operationID {
	case cacheAlgorithmUUID("operation-ready-claim"):
		return "ready"
	case cacheAlgorithmUUID("operation-recovery"):
		return "recovery"
	case cacheAlgorithmUUID("operation-fresh"):
		return "fresh"
	default:
		return operationID.String()
	}
}

func (repository *cacheAlgorithmRepository) automaticScopes(context.Context, time.Time) ([]uuid.UUID, error) { return nil, nil }

func (control *cacheAlgorithmControl) SyncCarryingNodes(context.Context, uuid.UUID, string) (int, error) { return 0, nil }
