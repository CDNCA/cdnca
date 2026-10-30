package gateway

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/securityban"
	"github.com/cdnca/cdnca/libs/edgeconfig/sitedrop"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Largest-encoding values the contracts accept: 19-digit times, 20-digit
// revision, 128-byte key ID, longest canonical IPv6 client.
const (
	limitIssuedAt = int64(1<<63-1) - int64(sitedrop.MaxDuration/time.Second)
	limitKeyID    = "k0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde"
	limitClient   = "2001:db8:1111:2222:3333:4444:5555:6666"
)

func limitEvent() *commonv1.EventMetadata {
	return &commonv1.EventMetadata{EventId: uuid.NewString(), RequestId: uuid.NewString(), OccurredTime: timestamppb.Now()}
}

// largestSiteDropCommand: MaxSites sites of the largest encoding.
func largestSiteDropCommand(t *testing.T, sites int) *agentv1.SiteDropCommand {
	t.Helper()
	_, private, _ := ed25519.GenerateKey(nil)
	list := sitedrop.List{NodeID: testNodeID, Revision: 1<<64 - 1, IssuedAt: limitIssuedAt}
	for index := range sites {
		list.Sites = append(list.Sites, sitedrop.Site{SiteID: fmt.Sprintf("%08x-0000-4000-8000-000000000000", index),
			TenantID: "33333333-3333-4333-8333-333333333333", Since: limitIssuedAt,
			Until: limitIssuedAt + int64(sitedrop.MaxDuration/time.Second)})
	}
	encoded, err := sitedrop.Sign(list, limitKeyID, private)
	if err != nil {
		t.Fatalf("sign %d sites: %v", sites, err)
	}
	digest := sha256.Sum256(encoded)
	return &agentv1.SiteDropCommand{Event: limitEvent(), NodeId: testNodeID, Revision: list.Revision, ListJson: encoded, ListSha256: digest[:]}
}

func largestSecurityBanCommand(t *testing.T, entries int) *agentv1.SecurityBanCommand {
	t.Helper()
	_, private, _ := ed25519.GenerateKey(nil)
	list := securityban.List{Schema: securityban.Schema, NodeID: testNodeID, Revision: 1<<64 - 1, IssuedAt: limitIssuedAt,
		Bans: []securityban.Ban{}, Releases: []securityban.Release{}, Algorithm: securityban.Algorithm, KeyID: limitKeyID}
	for index := range entries {
		site := fmt.Sprintf("%08x-0000-4000-8000-000000000000", index)
		if index%2 == 0 {
			list.Bans = append(list.Bans, securityban.Ban{SiteID: site, Client: limitClient, Until: 1<<63 - 1, Source: "autodefense"})
		} else {
			list.Releases = append(list.Releases, securityban.Release{SiteID: site, Client: limitClient, ReleasedAt: 1<<63 - 1})
		}
	}
	list.Canonical()
	payload, err := securityban.SigningPayload(list)
	if err != nil {
		t.Fatalf("signing payload %d entries: %v", entries, err)
	}
	encoded, err := securityban.Seal(list, ed25519.Sign(private, payload))
	if err != nil {
		t.Fatalf("seal %d entries: %v", entries, err)
	}
	digest := sha256.Sum256(encoded)
	return &agentv1.SecurityBanCommand{Event: limitEvent(), NodeId: testNodeID, Revision: list.Revision, ListJson: encoded, ListSha256: digest[:]}
}

// The largest site drop list the contract accepts reaches the Agent through
// the gateway's real gRPC stream (default 1 MiB message limit).
func TestSiteDropLargestListPassesGRPC(t *testing.T) {
	command := largestSiteDropCommand(t, sitedrop.MaxSites)
	if size := len(command.ListJson); size > sitedrop.MaxListBytes {
		t.Fatalf("largest list is %d bytes, over MaxListBytes %d", size, sitedrop.MaxListBytes)
	}
	if err := validateSiteDropCommand(command, testNodeID); err != nil {
		t.Fatal(err)
	}
	bus := newSiteDropBusStub(command)
	stream, _, _ := connectSiteDropSession(t, bus,
		[]*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_DROP, ApiVersion: 1}})
	response, err := stream.Recv()
	if err != nil {
		t.Fatalf("largest list (%d bytes) not delivered: %v", len(command.ListJson), err)
	}
	if !proto.Equal(response.GetSiteDropCommand(), command) {
		t.Fatal("delivered another command")
	}
	t.Logf("site drop: %d sites, list %d bytes, response %d bytes", sitedrop.MaxSites, len(command.ListJson), proto.Size(response))
}

// The same for the largest security ban list.
func TestSecurityBanLargestListPassesGRPC(t *testing.T) {
	command := largestSecurityBanCommand(t, securityban.MaxEntries)
	if err := validateSecurityBanCommand(command, testNodeID); err != nil {
		t.Fatal(err)
	}
	acks := make(chan string, 1)
	bus := &securityBanBusStub{deliveries: make(chan SecurityBanDelivery, 1), subscribed: make(chan string, 1)}
	bus.deliveries <- &securityBanDeliveryStub{command: command, acks: acks, naks: make(chan string, 4), term: make(chan string, 1)}
	stream, _ := connectSecurityBanSession(t, bus, []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_WAF, ApiVersion: 2}})
	response, err := stream.Recv()
	if err != nil {
		t.Fatalf("largest list (%d entries, %d bytes) not delivered: %v", securityban.MaxEntries, len(command.ListJson), err)
	}
	if !proto.Equal(response.GetSecurityBanCommand(), command) {
		t.Fatal("delivered another command")
	}
	t.Logf("security ban: %d entries, list %d bytes, response %d bytes", securityban.MaxEntries, len(command.ListJson), proto.Size(response))
}
