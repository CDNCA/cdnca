package edgepublish

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
)

// ADR 0012 ML-07: a site or stream carrying market supply limits (TCP
// connections, new connections per second, QPS, stop) requires
// SUBSCRIPTION_LIMITS v1, and a target node without it is refused naming
// every such node (no downgrade); a limit with only the concurrent request
// budget or bandwidth does not.
func TestSubscriptionLimitsRequireTheCapability(t *testing.T) {
	subscription := uuid.NewString()
	document := func(limit *edgeconfig.PackageConnectionLimit, required ...siteRuntimeV2Capability) siteRuntimeV2Document {
		var value siteRuntimeV2Document
		if err := json.Unmarshal(siteRuntimeV2DocumentFixture(), &value); err != nil {
			t.Fatal(err)
		}
		value.Sites[0].PackageLimits = limit
		value.RequiredCapabilities = append(value.RequiredCapabilities, required...)
		slices.SortFunc(value.RequiredCapabilities, func(a, b siteRuntimeV2Capability) int { return strings.Compare(a.Name, b.Name) })
		return value
	}
	need := siteRuntimeV2Capability{Name: edgeconfig.SubscriptionLimitsCapability, APIVersion: 1}
	for name, limit := range map[string]edgeconfig.PackageConnectionLimit{
		"tcp connections": {SubscriptionID: subscription, Connections: -1, MaxConnections: 10},
		"new per second":  {SubscriptionID: subscription, Connections: -1, NewPerSecond: 5},
		"qps":             {SubscriptionID: subscription, Connections: -1, QPS: 100},
		"stopped":         {SubscriptionID: subscription, Connections: -1, Stopped: true},
	} {
		if _, _, err := validateSiteRuntimeV2Document(document(&limit)); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("%s without subscription_limits accepted: %v", name, err)
		}
		capabilities, _, err := validateSiteRuntimeV2Document(document(&limit, need))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !slices.ContainsFunc(capabilities, func(c *agentv1.Capability) bool {
			return c.Name == agentv1.CapabilityName_CAPABILITY_NAME_SUBSCRIPTION_LIMITS && c.ApiVersion == 1
		}) {
			t.Errorf("%s: capabilities %v lack SUBSCRIPTION_LIMITS v1", name, capabilities)
		}
	}
	legacy := edgeconfig.PackageConnectionLimit{SubscriptionID: subscription, Connections: 20, BandwidthBPS: 8_000_000}
	if _, _, err := validateSiteRuntimeV2Document(document(&legacy)); err != nil {
		t.Fatalf("request budget and bandwidth alone need no capability: %v", err)
	}
	for name, limit := range map[string]edgeconfig.PackageConnectionLimit{
		"negative qps":     {SubscriptionID: subscription, Connections: -1, QPS: -1},
		"too many conns":   {SubscriptionID: subscription, Connections: -1, MaxConnections: edgeconfig.MaxSubscriptionConnections + 1},
		"too many new/sec": {SubscriptionID: subscription, Connections: -1, NewPerSecond: edgeconfig.MaxSubscriptionNewPerSecond + 1},
	} {
		if _, _, err := validateSiteRuntimeV2Document(document(&limit, need)); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}

	// The sold package path recomputes the capability from the limits.
	sold := document(&edgeconfig.PackageConnectionLimit{SubscriptionID: subscription, Connections: -1, QPS: 7}, need)
	sold.Sites[0].PackageLimits = nil
	soldLimits := map[uuid.UUID]soldPackageLimits{}
	applySoldPackageRuntimeV2Limits(&sold, soldLimits)
	if slices.Contains(sold.RequiredCapabilities, need) {
		t.Fatalf("a site without limits keeps subscription_limits: %v", sold.RequiredCapabilities)
	}

	// A stream with subscription limits requires the capability as well.
	stream := l4V2ContractStream("tcp")
	stream.SubscriptionLimits = &edgeconfig.L4SubscriptionLimitsV2{SubscriptionID: subscription, MaxConnections: 3}
	if err := siteRuntimeV2StreamsFragmentError(stream.TenantID, 18080, stream); err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(siteRuntimeV2StreamsRequired([]edgeconfig.L4StreamRuntimeV2{stream}), func(c *agentv1.Capability) bool {
		return c.Name == agentv1.CapabilityName_CAPABILITY_NAME_SUBSCRIPTION_LIMITS && c.ApiVersion == 1
	}) {
		t.Fatal("stream subscription limits do not require SUBSCRIPTION_LIMITS v1")
	}
	stream.SubscriptionLimits = &edgeconfig.L4SubscriptionLimitsV2{SubscriptionID: subscription}
	if err := siteRuntimeV2StreamsFragmentError(stream.TenantID, 18080, stream); err == nil {
		t.Fatal("a stream subscription limit that limits nothing was accepted")
	}

	// Refusal before anything is persisted, naming every node without it.
	first, second, ready := uuid.MustParse("00000000-0000-4000-8000-000000000011"),
		uuid.MustParse("00000000-0000-4000-8000-000000000012"), uuid.MustParse("00000000-0000-4000-8000-000000000013")
	sessions := map[uuid.UUID]*agentv1.AgentCapabilities{
		first:  {AgentVersion: "1.0.35", Features: edge134Features()},
		second: {AgentVersion: "1.0.35", Features: edge134Features()},
		ready: {AgentVersion: "1.0.35", Features: append(edge134Features(),
			&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_SUBSCRIPTION_LIMITS, ApiVersion: 1})},
	}
	required := []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_SUBSCRIPTION_LIMITS, ApiVersion: 1}}
	err := capabilityTargetsError([]uuid.UUID{ready, first, second}, required, sessions)
	var refusal *TargetCapabilityError
	if !errors.As(err, &refusal) || refusal.NodeID != first || len(refusal.OtherNodeIDs) != 1 || refusal.OtherNodeIDs[0] != second ||
		!strings.Contains(err.Error(), "订阅限额") || strings.Contains(err.Error(), ready.String()) {
		t.Fatalf("subscription limits on nodes without the capability: %v (%+v)", err, refusal)
	}
	if err := capabilityTargetsError([]uuid.UUID{ready}, required, sessions); err != nil {
		t.Fatalf("a SUBSCRIPTION_LIMITS node: %v", err)
	}
}

// ADR 0012 ML-08: a market subscription's node share (market_supply_limits)
// replaces the package's connections and bandwidth in the site object and
// raises SUBSCRIPTION_LIMITS v1; a share with no market field does not.
func TestMarketShareReplacesSoldPackageLimits(t *testing.T) {
	var document siteRuntimeV2Document
	if err := json.Unmarshal(siteRuntimeV2DocumentFixture(), &document); err != nil {
		t.Fatal(err)
	}
	site := uuid.MustParse(document.Sites[0].ID)
	subscription := uuid.New()
	twenty, bandwidth := int64(20), int64(1000)
	share := edgeconfig.PackageConnectionLimit{SubscriptionID: subscription.String(), Connections: 3, BandwidthBPS: 500,
		MaxConnections: 4, NewPerSecond: 2, QPS: 34, Stopped: true}
	applySoldPackageRuntimeV2Limits(&document, map[uuid.UUID]soldPackageLimits{site: {subscriptionID: subscription,
		Connections: &twenty, BandwidthBPS: &bandwidth, market: &share}})
	if got := document.Sites[0].PackageLimits; got == nil || *got != share {
		t.Fatalf("site limits %+v want %+v", got, share)
	}
	need := siteRuntimeV2Capability{Name: edgeconfig.SubscriptionLimitsCapability, APIVersion: 1}
	if !slices.Contains(document.RequiredCapabilities, need) {
		t.Fatalf("capabilities %v", document.RequiredCapabilities)
	}
	unlimited := edgeconfig.PackageConnectionLimit{SubscriptionID: subscription.String(), Connections: -1}
	document = siteRuntimeV2Document{}
	if err := json.Unmarshal(siteRuntimeV2DocumentFixture(), &document); err != nil {
		t.Fatal(err)
	}
	applySoldPackageRuntimeV2Limits(&document, map[uuid.UUID]soldPackageLimits{site: {subscriptionID: subscription,
		Connections: &twenty, market: &unlimited}})
	if document.Sites[0].PackageLimits != nil || slices.Contains(document.RequiredCapabilities, need) {
		t.Fatalf("an unlimited share limits nothing: %+v %v", document.Sites[0].PackageLimits, document.RequiredCapabilities)
	}
}
