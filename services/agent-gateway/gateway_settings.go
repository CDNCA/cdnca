package gateway

// Gateway settings published by the control plane's Gateway management page
// (ADR 0013 §3.4/§4.4/§4.5, GW-06/GW-07), polled over ControlInternal
// GetGatewaySettings: the trusted CDN back-to-origin ranges replace
// TrustedProxies atomically, and the node endpoint list goes out in every
// GatewayHello. A failed poll keeps the last good settings (the shipped
// Cloudflare list until the first success).

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const DefaultSettingsPollInterval = time.Minute

// DisabledEvictAfter: a disabled Gateway closes the node sessions still left
// this long after it learned it was disabled (ADR 0013 §5.2).
const DisabledEvictAfter = 30 * time.Minute

// GatewaySettingsClient is the ControlInternal method used here.
type GatewaySettingsClient interface {
	GetGatewaySettings(ctx context.Context, in *controlv1.GetGatewaySettingsRequest, opts ...grpc.CallOption) (*controlv1.GetGatewaySettingsResponse, error)
}

type endpointSnapshot struct {
	endpoints []*agentv1.GatewayEndpointV1
	version   string
}

// NodeEndpoints is the endpoint list the Gateway hands out (zero value: none).
type NodeEndpoints struct {
	current atomic.Pointer[endpointSnapshot]
}

func (n *NodeEndpoints) set(endpoints []*agentv1.GatewayEndpointV1, version string) {
	cloned := make([]*agentv1.GatewayEndpointV1, 0, len(endpoints))
	for _, endpoint := range endpoints {
		cloned = append(cloned, proto.Clone(endpoint).(*agentv1.GatewayEndpointV1))
	}
	n.current.Store(&endpointSnapshot{endpoints: cloned, version: version})
}

// Snapshot returns fresh copies (safe to put into a message).
func (n *NodeEndpoints) Snapshot() ([]*agentv1.GatewayEndpointV1, string) {
	if n == nil {
		return nil, ""
	}
	snapshot := n.current.Load()
	if snapshot == nil {
		return nil, ""
	}
	out := make([]*agentv1.GatewayEndpointV1, 0, len(snapshot.endpoints))
	for _, endpoint := range snapshot.endpoints {
		out = append(out, proto.Clone(endpoint).(*agentv1.GatewayEndpointV1))
	}
	return out, snapshot.version
}

// GatewayDrain is whether an administrator disabled this Gateway (ADR 0013
// §5.2, GetGatewaySettings.disabled): it then takes no new node session,
// asks connected nodes to migrate and closes the rest DisabledEvictAfter
// later. Re-enabling clears it. The zero value is enabled.
type GatewayDrain struct {
	mu         sync.Mutex
	disabledAt time.Time
	signal     chan struct{} // closed while disabled
}

func (d *GatewayDrain) set(disabled bool, now time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.signal == nil {
		d.signal = make(chan struct{})
	}
	switch {
	case disabled && d.disabledAt.IsZero():
		d.disabledAt = now
		close(d.signal)
	case !disabled && !d.disabledAt.IsZero():
		d.disabledAt = time.Time{}
		d.signal = make(chan struct{})
	}
}

// Disabled reports the state and, when disabled, the session eviction time.
func (d *GatewayDrain) Disabled() (bool, time.Time) {
	if d == nil {
		return false, time.Time{}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.disabledAt.IsZero() {
		return false, time.Time{}
	}
	return true, d.disabledAt.Add(DisabledEvictAfter)
}

// disabledSignal is closed once the Gateway is disabled (nil: never).
func (d *GatewayDrain) disabledSignal() <-chan struct{} {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.signal == nil {
		d.signal = make(chan struct{})
	}
	return d.signal
}

// SettingsSync applies one GetGatewaySettings answer.
type SettingsSync struct {
	Client     GatewaySettingsClient
	InstanceID string
	Proxies    *TrustedProxies
	Endpoints  *NodeEndpoints
	// Drain, when set, follows the disabled flag.
	Drain *GatewayDrain
	Now   func() time.Time
}

// Apply validates the whole answer first; a bad range or endpoint keeps the
// previous settings.
func (s SettingsSync) Apply(response *controlv1.GetGatewaySettingsResponse) error {
	items := make([]string, 0, len(response.GetTrustedProxies()))
	for _, item := range response.GetTrustedProxies() {
		items = append(items, item.GetCidr()+"="+item.GetHeader())
	}
	ranges, err := ParseTrustedProxyRanges(strings.Join(items, ","))
	if err != nil {
		return err
	}
	for _, endpoint := range response.GetEndpoints() {
		if endpoint.GetAddress() == "" || endpoint.GetServerName() == "" ||
			(endpoint.GetTransport() != "grpc" && endpoint.GetTransport() != "ws") ||
			(endpoint.GetEnrollmentAddress() != "" && endpoint.GetTransport() != "grpc") {
			return fmt.Errorf("control plane published an invalid node endpoint")
		}
	}
	s.Proxies.Set(ranges)
	s.Endpoints.set(response.GetEndpoints(), response.GetEndpointsVersion())
	if s.Drain != nil {
		now := time.Now
		if s.Now != nil {
			now = s.Now
		}
		s.Drain.set(response.GetDisabled(), now())
	}
	return nil
}

func (s SettingsSync) Poll(ctx context.Context) error {
	response, err := s.Client.GetGatewaySettings(ctx, &controlv1.GetGatewaySettingsRequest{
		Request:           &commonv1.RequestMetadata{RequestId: uuid.NewString(), SentTime: timestamppb.Now()},
		GatewayInstanceId: s.InstanceID,
	})
	if err != nil {
		return err
	}
	return s.Apply(response)
}

// Run polls every interval until ctx ends (the caller polled once at startup).
func (s SettingsSync) Run(ctx context.Context, interval time.Duration, timeout time.Duration, logf func(string, ...any)) {
	if interval <= 0 {
		interval = DefaultSettingsPollInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		pollCtx, cancel := context.WithTimeout(ctx, timeout)
		if err := s.Poll(pollCtx); err != nil && ctx.Err() == nil {
			logf("gateway settings refresh failed, keeping the previous settings: %v", err)
		}
		cancel()
	}
}

// ConfigureDrain makes the Gateway follow the disabled flag (ADR 0013 §5.2).
func (g *Gateway) ConfigureDrain(drain *GatewayDrain) error {
	if g == nil || drain == nil || g.disableState != nil {
		return fmt.Errorf("gateway drain is invalid or already configured")
	}
	g.disableState = drain
	return nil
}

// endpointMigrationCapable: the node accepts GatewayEndpointMigration v1.
func endpointMigrationCapable(features []*agentv1.Capability) bool {
	for _, capability := range features {
		if capability != nil && capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_GATEWAY_ENDPOINT_MIGRATION &&
			capability.ApiVersion == endpointMigrationAPIVersion {
			return true
		}
	}
	return false
}

const endpointMigrationAPIVersion = 1

// ConfigureNodeEndpoints makes every GatewayHello carry the endpoint list.
func (g *Gateway) ConfigureNodeEndpoints(endpoints *NodeEndpoints) error {
	if g == nil || endpoints == nil || g.endpoints != nil {
		return fmt.Errorf("gateway node endpoints are invalid or already configured")
	}
	g.endpoints = endpoints
	return nil
}
