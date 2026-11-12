package gatewayclient

import (
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

// LiveCapability is a capability whose availability changes while the Agent
// runs (XDP_FILTER is lost on a run time fallback to
// nftables and regained on a successful reattach; ACME_HTTP01_OVERLAY waits
// for the dynamic routing skeleton written after the first hello). The Agent
// protocol carries capabilities only in AgentHello, so a change ends the
// session and the next hello declares the new set at once (no wait for an
// unrelated reconnect).
type LiveCapability struct {
	Name       agentv1.CapabilityName
	APIVersion uint32
	// Ready reports whether the capability may be declared now.
	Ready func() bool
	// Changed is signalled when Ready may have changed (coalesced, never
	// closed); nil disables the signal. At most one live capability has one.
	Changed <-chan struct{}
	// Poll re-checks Ready this often during a session (0: no polling), for
	// a capability without a change signal.
	Poll time.Duration
}

// errLiveCapabilityChanged: a live capability changed after this session's
// hello; the client reconnects immediately with the current set.
var errLiveCapabilityChanged = errors.New("live capability changed")

type liveCapability struct {
	LiveCapability
	declared atomic.Bool
}

// WithLiveCapability declares capability while Ready and re-declares it on
// every change (a reconnect with a new hello).
func WithLiveCapability(capability LiveCapability) ClientOption {
	return func(client *Client) error {
		return client.addLiveCapability(capability)
	}
}

func (c *Client) addLiveCapability(capability LiveCapability) error {
	if capability.Ready == nil || capability.APIVersion == 0 || capability.Poll < 0 ||
		capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_UNSPECIFIED {
		return fmt.Errorf("%w: live capability is invalid", ErrInvalidConfiguration)
	}
	for _, live := range c.liveCapabilities {
		if live.Name == capability.Name {
			return fmt.Errorf("%w: live capability %s is configured twice", ErrInvalidConfiguration, capability.Name)
		}
		if live.Changed != nil && capability.Changed != nil {
			return fmt.Errorf("%w: one live capability change signal is supported", ErrInvalidConfiguration)
		}
	}
	c.liveCapabilities = append(c.liveCapabilities, &liveCapability{LiveCapability: capability})
	return nil
}

// declareLiveCapability adds each ready live capability to a hello's set and
// records what was declared.
func (c *Client) declareLiveCapability(capabilities *agentv1.AgentCapabilities) {
	for _, live := range c.liveCapabilities {
		capabilities.Features = removeCapability(capabilities.Features, live.Name)
		ready := live.Ready()
		if ready {
			capabilities.Features = append(capabilities.Features, &agentv1.Capability{Name: live.Name, ApiVersion: live.APIVersion})
		}
		live.declared.Store(ready)
	}
}

// declareLiveCapabilityReadOnly 与 declareLiveCapability 生成相同的能力集合，但不记录 declared。
func (c *Client) declareLiveCapabilityReadOnly(capabilities *agentv1.AgentCapabilities) {
	for _, live := range c.liveCapabilities {
		capabilities.Features = removeCapability(capabilities.Features, live.Name)
		if live.Ready() {
			capabilities.Features = append(capabilities.Features, &agentv1.Capability{Name: live.Name, ApiVersion: live.APIVersion})
		}
	}
}

// liveCapabilityChanged returns the session's change signal (nil without
// one: a nil channel never fires in select).
func (c *Client) liveCapabilityChanged() <-chan struct{} {
	for _, live := range c.liveCapabilities {
		if live.Changed != nil {
			return live.Changed
		}
	}
	return nil
}

// liveCapabilityPoll returns a ticker for the shortest live capability poll
// interval (nil without polling) and its stop function.
func (c *Client) liveCapabilityPoll() (<-chan time.Time, func()) {
	var interval time.Duration
	for _, live := range c.liveCapabilities {
		if live.Poll > 0 && (interval == 0 || live.Poll < interval) {
			interval = live.Poll
		}
	}
	if interval == 0 {
		return nil, func() {}
	}
	ticker := time.NewTicker(interval)
	return ticker.C, ticker.Stop
}

// liveCapabilityStale reports whether the session's hello no longer matches.
func (c *Client) liveCapabilityStale() bool {
	for _, live := range c.liveCapabilities {
		if live.Ready() != live.declared.Load() {
			return true
		}
	}
	return false
}
