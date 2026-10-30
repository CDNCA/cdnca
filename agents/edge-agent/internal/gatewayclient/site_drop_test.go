package gatewayclient

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/sitedrop"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type siteDropApplierStub struct {
	calls  int
	result SiteDropResult
}

func (stub *siteDropApplierStub) ApplySiteDrop([]byte) SiteDropResult {
	stub.calls++
	return stub.result
}

func TestSiteDropNegotiation(t *testing.T) {
	hello := func(versions ...uint32) *agentv1.GatewayHello {
		value := &agentv1.GatewayHello{}
		for _, version := range versions {
			value.EnabledCapabilities = append(value.EnabledCapabilities,
				&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_DROP, ApiVersion: version})
		}
		return value
	}
	stub := &siteDropApplierStub{}
	if on, err := negotiateSiteDropV1(hello(), nil); err != nil || on {
		t.Fatalf("not enabled: %v %v", on, err)
	}
	if _, err := negotiateSiteDropV1(hello(1), nil); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("enabled without being advertised: %v", err)
	}
	if _, err := negotiateSiteDropV1(hello(2), stub); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("v2 accepted: %v", err)
	}
	if _, err := negotiateSiteDropV1(hello(1, 1), stub); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("duplicate accepted: %v", err)
	}
	if on, err := negotiateSiteDropV1(hello(1), stub); err != nil || !on {
		t.Fatalf("negotiate: %v %v", on, err)
	}
	client, _ := artifactSetClient(t, &fakeArtifactSets{})
	declared := func() uint32 {
		hello, err := client.agentHello()
		if err != nil {
			t.Fatal(err)
		}
		for _, capability := range hello.Capabilities.Features {
			if capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_SITE_DROP {
				return capability.ApiVersion
			}
		}
		return 0
	}
	if got := declared(); got != 0 {
		t.Fatalf("SITE_DROP declared without an applier: v%d", got)
	}
	client.siteDrop = stub
	if got := declared(); got != 1 {
		t.Fatalf("SITE_DROP = v%d", got)
	}
}

func TestSiteDropReceipt(t *testing.T) {
	nodeID := uuid.NewString()
	_, key, _ := ed25519.GenerateKey(nil)
	now := time.Now()
	list, err := sitedrop.Sign(sitedrop.List{NodeID: nodeID, Revision: 4, IssuedAt: now.Unix(), Sites: []sitedrop.Site{
		{SiteID: uuid.NewString(), TenantID: uuid.NewString(), Since: now.Unix(), Until: now.Unix() + 60}}}, "edge-1", key)
	if err != nil {
		t.Fatal(err)
	}
	siteID := uuid.NewString()
	stub := &siteDropApplierStub{result: SiteDropResult{Applied: true, Mode: "xdp", Sites: 1, Ports: 1, ServerNames: 2,
		Rejected: []SiteDropRejection{{SiteID: siteID, Port: 443, Reason: sitedrop.RejectSNIUnavailable}}}}
	client := &Client{config: Config{NodeID: nodeID}, siteDrop: stub}
	digest := sha256.Sum256(list)
	command := func() *agentv1.SiteDropCommand {
		return &agentv1.SiteDropCommand{
			Event:  &commonv1.EventMetadata{EventId: uuid.NewString(), RequestId: uuid.NewString(), OccurredTime: timestamppb.Now()},
			NodeId: nodeID, Revision: 4, ListJson: list, ListSha256: digest[:]}
	}
	sent := command()
	receipt, err := client.siteDropReceipt(sent, now)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.NodeId != nodeID || receipt.CommandEventId != sent.Event.EventId || receipt.Revision != 4 || !receipt.Applied ||
		receipt.Mode != "xdp" || receipt.Sites != 1 || receipt.Ports != 1 || receipt.ServerNames != 2 || receipt.ErrorCode != "" ||
		len(receipt.Rejected) != 1 || receipt.Rejected[0].SiteId != siteID || receipt.Rejected[0].Port != 443 ||
		receipt.Rejected[0].Reason != sitedrop.RejectSNIUnavailable || string(receipt.ListSha256) != string(digest[:]) {
		t.Fatalf("receipt = %v", receipt)
	}

	// The carrier must repeat the body's revision: refused before the runtime.
	mismatch := command()
	mismatch.Revision = 5
	receipt, err = client.siteDropReceipt(mismatch, now)
	if err != nil || receipt.Applied || receipt.ErrorCode != sitedrop.ErrorInvalid || stub.calls != 1 {
		t.Fatalf("revision mismatch: %v %v calls %d", receipt, err, stub.calls)
	}
	// A runtime failure without its own code is runtime_unavailable.
	stub.result = SiteDropResult{}
	if receipt, err = client.siteDropReceipt(command(), now); err != nil || receipt.ErrorCode != sitedrop.ErrorRuntime {
		t.Fatalf("runtime failure: %v %v", receipt, err)
	}
	for name, mutate := range map[string]func(*agentv1.SiteDropCommand){
		"digest":     func(c *agentv1.SiteDropCommand) { c.ListSha256 = append([]byte{1}, c.ListSha256[1:]...) },
		"other node": func(c *agentv1.SiteDropCommand) { c.NodeId = uuid.NewString() },
		"no event":   func(c *agentv1.SiteDropCommand) { c.Event = nil },
		"revision 0": func(c *agentv1.SiteDropCommand) { c.Revision = 0 },
		"empty list": func(c *agentv1.SiteDropCommand) { c.ListJson = nil },
	} {
		bad := command()
		mutate(bad)
		if _, err := client.siteDropReceipt(bad, now); !errors.Is(err, ErrInvalidMessage) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
}

// A list over sitedrop.MaxListBytes is answered invalid_list without reaching
// the runtime (same constant as the control plane signs with).
func TestSiteDropReceiptRefusesOverLimitList(t *testing.T) {
	nodeID := uuid.NewString()
	over := make([]byte, sitedrop.MaxListBytes+1)
	digest := sha256.Sum256(over)
	stub := &siteDropApplierStub{result: SiteDropResult{Applied: true}}
	client := &Client{config: Config{NodeID: nodeID}, siteDrop: stub}
	receipt, err := client.siteDropReceipt(&agentv1.SiteDropCommand{
		Event:  &commonv1.EventMetadata{EventId: uuid.NewString(), RequestId: uuid.NewString(), OccurredTime: timestamppb.Now()},
		NodeId: nodeID, Revision: 1, ListJson: over, ListSha256: digest[:]}, time.Now())
	if err != nil || receipt.Applied || receipt.ErrorCode != sitedrop.ErrorInvalid || stub.calls != 0 {
		t.Fatalf("over-limit list: receipt %v, err %v, runtime calls %d", receipt, err, stub.calls)
	}
}
