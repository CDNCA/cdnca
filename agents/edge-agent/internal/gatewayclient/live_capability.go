package gatewayclient

import (
	"errors"
	"fmt"
	"sync/atomic"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

// LiveCapability is a capability whose availability changes while the Agent
// runs (XDP_FILTER is lost on a run time fallback to
// nftables and regained on a successful reattach). The Agent protocol carries
// capabilities only in AgentHello, so a change ends the session and the next
// hello declares the new set at once (no wait for an unrelated reconnect).
type LiveCapability struct {
	Name       agentv1.CapabilityName
	APIVersion uint32
	// Ready reports whether the capability may be declared now.
	Ready func() bool
	// Changed is signalled when Ready may have changed (coalesced, never
	// closed); nil disables the in-session check.
	Changed <-chan struct{}
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
		if capability.Ready == nil || capability.APIVersion == 0 ||
			capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_UNSPECIFIED {
			return fmt.Errorf("%w: live capability is invalid", ErrInvalidConfiguration)
		}
		if client.liveCapability != nil {
			return fmt.Errorf("%w: one live capability is supported", ErrInvalidConfiguration)
		}
		client.liveCapability = &liveCapability{LiveCapability: capability}
		return nil
	}
}

// declareLiveCapability adds the live capability to a hello's set when
// ready and records what was declared.
func (c *Client) declareLiveCapability(capabilities *agentv1.AgentCapabilities) {
	live := c.liveCapability
	if live == nil {
		return
	}
	capabilities.Features = removeCapability(capabilities.Features, live.Name)
	ready := live.Ready()
	if ready {
		capabilities.Features = append(capabilities.Features, &agentv1.Capability{Name: live.Name, ApiVersion: live.APIVersion})
	}
	live.declared.Store(ready)
}

// liveCapabilityChanged returns the session's change signal (nil without a
// live capability: a nil channel never fires in select).
func (c *Client) liveCapabilityChanged() <-chan struct{} {
	if c.liveCapability == nil {
		return nil
	}
	return c.liveCapability.Changed
}

// liveCapabilityStale reports whether the session's hello no longer matches.
func (c *Client) liveCapabilityStale() bool {
	live := c.liveCapability
	return live != nil && live.Ready() != live.declared.Load()
}
