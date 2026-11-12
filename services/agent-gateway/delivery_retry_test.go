package gateway

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/protobuf/proto"
)

// flakySecurityBanBus 的 Next 前 failures 次返回错误（0 表示一直失败），之后才投递。
type flakySecurityBanBus struct {
	*securityBanBusStub
	failures int32
	calls    atomic.Int32
}

func (bus *flakySecurityBanBus) SubscribeSecurityBans(ctx context.Context, nodeID string) (SecurityBanSubscription, error) {
	bus.securityBanBusStub.subscribed <- nodeID
	return bus, nil
}

func (bus *flakySecurityBanBus) Next(ctx context.Context) (SecurityBanDelivery, error) {
	call := bus.calls.Add(1)
	if bus.failures == 0 || call <= bus.failures {
		return nil, errors.New("bus unavailable")
	}
	return bus.securityBanBusStub.Next(ctx)
}

func fastDeliveryRetry(t *testing.T, limit int) {
	t.Helper()
	base, max, lim := deliveryRetryBase, deliveryRetryMax, deliveryRetryLimit
	deliveryRetryBase, deliveryRetryMax, deliveryRetryLimit = 10*time.Millisecond, 40*time.Millisecond, limit
	t.Cleanup(func() { deliveryRetryBase, deliveryRetryMax, deliveryRetryLimit = base, max, lim })
}

// 总线单次投递出错不再断整条会话：会话内退避重试，之后的命令仍在同一条流上送达。
func TestSecurityBanDeliveryErrorRetriesWithinSession(t *testing.T) {
	fastDeliveryRetry(t, 6)
	inner := &securityBanBusStub{deliveries: make(chan SecurityBanDelivery, 4), subscribed: make(chan string, 4)}
	bus := &flakySecurityBanBus{securityBanBusStub: inner, failures: 2}
	stream, ctx := connectSecurityBanSession(t, bus, []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_WAF, ApiVersion: 2}})
	acks, naks, terms := make(chan string, 4), make(chan string, 4), make(chan string, 4)
	command := testSecurityBanCommand(t, testNodeID, 5)
	inner.deliveries <- &securityBanDeliveryStub{command: command, acks: acks, naks: naks, term: terms}
	response, err := stream.Recv()
	if err != nil {
		t.Fatalf("session ended by a single delivery error: %v", err)
	}
	if delivered := response.GetSecurityBanCommand(); delivered == nil || !proto.Equal(delivered, command) {
		t.Fatalf("delivered %v, want the snapshot after retries", response.Payload)
	}
	if calls := bus.calls.Load(); calls < 3 {
		t.Fatalf("Next calls = %d, want >= 3 (two failures then delivery)", calls)
	}
	_ = ctx
}

// 连续失败超过上限才结束会话（与改动前一致，由 agent 重连）。
func TestSecurityBanDeliveryErrorsBeyondLimitEndSession(t *testing.T) {
	fastDeliveryRetry(t, 3)
	inner := &securityBanBusStub{deliveries: make(chan SecurityBanDelivery, 1), subscribed: make(chan string, 4)}
	bus := &flakySecurityBanBus{securityBanBusStub: inner}
	stream, _ := connectSecurityBanSession(t, bus, []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_WAF, ApiVersion: 2}})
	done := make(chan error, 1)
	go func() { _, err := stream.Recv(); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("stream closed without error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("session survived persistent delivery failures")
	}
	if calls := bus.calls.Load(); calls != 4 {
		t.Fatalf("Next calls = %d, want limit+1 = 4", calls)
	}
}
