package gateway

import (
	"log"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// 单个下发源（封禁列表、签名者信任、自动防御等）从总线取消息失败时，
// 不再断开整条节点会话：会话内按源退避重试，其余流（心跳、配置）照常。
// 连续失败超过 deliveryRetryLimit 次才结束会话，由 agent 重连（与改动前一致）。
//
// 幂等性依据：失败发生在 Next() 取消息阶段，此时没有任何消息被发送或确认；
// 重试只是再次 Next()。已投递但未确认的消息由现有的 pending/ack 机制处理
// （每源同时只允许一条在途，状态回报后才 Ack，未确认的由总线按 AckWait 重投），
// 命令本身带 revision，agent 侧按 revision 去重，重投不会重复生效。
var (
	deliveryRetryBase  = time.Second
	deliveryRetryMax   = 30 * time.Second
	deliveryRetryLimit = 6
)

type deliveryRetry struct {
	mu           sync.Mutex
	failures     map[string]int
	blockedUntil map[string]time.Time
	wake         chan struct{}
}

func newDeliveryRetry() *deliveryRetry {
	return &deliveryRetry{failures: map[string]int{}, blockedUntil: map[string]time.Time{}, wake: make(chan struct{}, 1)}
}

func (r *deliveryRetry) blocked(name string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return time.Now().Before(r.blockedUntil[name])
}

func (r *deliveryRetry) reset(name string) {
	r.mu.Lock()
	delete(r.failures, name)
	delete(r.blockedUntil, name)
	r.mu.Unlock()
}

// fail 记录一次失败。返回 nil 表示已安排会话内重试；返回错误表示连续失败超限，应结束会话。
func (r *deliveryRetry) fail(g *Gateway, name, message string, cause error) error {
	r.mu.Lock()
	r.failures[name]++
	count := r.failures[name]
	if count > deliveryRetryLimit {
		r.mu.Unlock()
		log.Printf("agent-gateway: %s failed %d times in a row; ending session: %v", name, count, cause)
		return status.Error(codes.Unavailable, message)
	}
	delay := deliveryRetryBase << (count - 1)
	if delay <= 0 || delay > deliveryRetryMax {
		delay = deliveryRetryMax
	}
	r.blockedUntil[name] = time.Now().Add(delay)
	r.mu.Unlock()
	g.deliveryRetries.Add(1)
	log.Printf("agent-gateway: warn: %s failed (%d/%d), retrying in %s within the session: %v", name, count, deliveryRetryLimit, delay, cause)
	time.AfterFunc(delay, func() {
		select {
		case r.wake <- struct{}{}:
		default:
		}
	})
	return nil
}

// gated 在该源处于退避期间返回 nil（select 中永不触发）。
func gated[T any](r *deliveryRetry, name string, receive func() <-chan T) <-chan T {
	if r.blocked(name) {
		return nil
	}
	return receive()
}

// DeliveryRetries 返回会话内下发重试的累计次数。
func (g *Gateway) DeliveryRetries() int64 { return g.deliveryRetries.Load() }

func (r *deliveryRetry) retryAt(name string) time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.blockedUntil[name]
}
