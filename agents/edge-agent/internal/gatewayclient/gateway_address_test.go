package gatewayclient

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/gatewayaddr"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const addressTestNode = "6f1c1d2e-3b4a-4c5d-8e9f-0a1b2c3d4e5f"

type addressProber struct {
	err   error
	calls []string
}

func (p *addressProber) ProbeAddress(_ context.Context, address, serverName string) error {
	p.calls = append(p.calls, address+"|"+serverName)
	return p.err
}

type addressFixture struct {
	runtime *GatewayAddressRuntime
	store   *FileGatewayEndpointStateStore
	prober  *addressProber
	key     ed25519.PrivateKey
	now     time.Time
	dir     string
}

func newAddressFixture(t *testing.T) *addressFixture {
	t.Helper()
	public, private, _ := ed25519.GenerateKey(nil)
	dir := filepath.Join(secureTempDir(t), "gateway-endpoint")
	store, err := NewFileGatewayEndpointStateStore(dir, GatewayEndpointState{Address: "old.cdnca.com:443", ServerName: "old.cdnca.com", Revision: 4})
	if err != nil {
		t.Fatal(err)
	}
	fixture := &addressFixture{store: store, prober: &addressProber{}, key: private, now: time.Unix(1_800_000_000, 0), dir: dir}
	fixture.runtime, err = NewGatewayAddressRuntime(addressTestNode, func(string) (ed25519.PublicKey, bool) { return public, true },
		store, dir, fixture.prober, time.Second, func() time.Time { return fixture.now })
	if err != nil {
		t.Fatal(err)
	}
	return fixture
}

func (f *addressFixture) command(t *testing.T, revision uint64, address, serverName string, key ed25519.PrivateKey) *agentv1.GatewayAddressChangeCommand {
	t.Helper()
	encoded, err := gatewayaddr.Sign(gatewayaddr.Change{NodeID: addressTestNode, ChangeID: "0c9b5f0e-6a51-4d3e-9a52-2f6a3c1d7b80",
		Revision: revision, Address: address, ServerName: serverName, IssuedAt: f.now.Unix(), ExpiresAt: f.now.Add(time.Hour).Unix()}, "edge-1", key)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(encoded)
	return &agentv1.GatewayAddressChangeCommand{Event: &commonv1.EventMetadata{EventId: "1d2c3b4a-0000-4000-8000-00000000000" + string(rune('0'+revision%10)),
		RequestId: "2d2c3b4a-0000-4000-8000-000000000001", OccurredTime: timestamppb.New(f.now)},
		NodeId: addressTestNode, Revision: revision, DocumentJson: encoded, DocumentSha256: digest[:]}
}

func collect(receipts *[]*agentv1.GatewayAddressChangeReceipt) func(*agentv1.GatewayAddressChangeReceipt) error {
	return func(receipt *agentv1.GatewayAddressChangeReceipt) error {
		*receipts = append(*receipts, receipt)
		return nil
	}
}

func states(receipts []*agentv1.GatewayAddressChangeReceipt) []string {
	out := []string{}
	for _, receipt := range receipts {
		out = append(out, receipt.State+":"+receipt.ErrorCode)
	}
	return out
}

func TestGatewayAddressChangeProbesThenSwitchesAndReportsOnReplay(t *testing.T) {
	f := newAddressFixture(t)
	command := f.command(t, 1, "gateway.cdnca.com:9443", "gateway.cdnca.com", f.key)
	var receipts []*agentv1.GatewayAddressChangeReceipt
	switched, err := f.runtime.Handle(context.Background(), command, collect(&receipts))
	if err != nil || !switched {
		t.Fatalf("handle = %v %v", switched, err)
	}
	if got := states(receipts); len(got) != 1 || got[0] != "probing:" {
		t.Fatalf("receipts before reconnect = %v", got)
	}
	if len(f.prober.calls) != 1 || f.prober.calls[0] != "gateway.cdnca.com:9443|gateway.cdnca.com" {
		t.Fatalf("probe = %v", f.prober.calls)
	}
	active := f.store.Active()
	if active.Address != "gateway.cdnca.com:9443" || active.ServerName != "gateway.cdnca.com" || active.Revision != 4 {
		t.Fatalf("active = %+v", active)
	}
	// Persisted: a restarted agent dials the new address.
	reloaded, err := NewFileGatewayEndpointStateStore(f.dir, GatewayEndpointState{Address: "old.cdnca.com:443", ServerName: "old.cdnca.com"})
	if err != nil || reloaded.Active().Address != "gateway.cdnca.com:9443" {
		t.Fatalf("reloaded = %+v %v", reloaded.Active(), err)
	}
	// The new session receives the same document again: answered switched, no second probe.
	receipts = nil
	switched, err = f.runtime.Handle(context.Background(), command, collect(&receipts))
	if err != nil || switched || len(f.prober.calls) != 1 {
		t.Fatalf("replay = %v %v probes=%d", switched, err, len(f.prober.calls))
	}
	if got := states(receipts); len(got) != 1 || got[0] != "switched:" || receipts[0].ActiveAddress != "gateway.cdnca.com:9443" {
		t.Fatalf("replay receipts = %v", got)
	}
}

func TestGatewayAddressChangeFailedProbeKeepsOldAddress(t *testing.T) {
	for name, probeErr := range map[string]error{
		gatewayaddr.ErrorDial:      errGatewayAddressDial,
		gatewayaddr.ErrorHandshake: errGatewayAddressHandshake,
	} {
		f := newAddressFixture(t)
		f.prober.err = probeErr
		command := f.command(t, 1, "gateway.cdnca.com:9443", "gateway.cdnca.com", f.key)
		var receipts []*agentv1.GatewayAddressChangeReceipt
		switched, err := f.runtime.Handle(context.Background(), command, collect(&receipts))
		if err != nil || switched {
			t.Fatalf("%s: handle = %v %v", name, switched, err)
		}
		if got := states(receipts); len(got) != 2 || got[0] != "probing:" || got[1] != "failed:"+name {
			t.Fatalf("%s: receipts = %v", name, got)
		}
		if receipts[1].ActiveAddress != "old.cdnca.com:443" || f.store.Active().Address != "old.cdnca.com:443" {
			t.Fatalf("%s: old address not kept: %+v", name, f.store.Active())
		}
		// Replay answers the stored failure without probing again; a retry is a new revision.
		receipts = nil
		if _, err := f.runtime.Handle(context.Background(), command, collect(&receipts)); err != nil || len(f.prober.calls) != 1 ||
			len(receipts) != 1 || receipts[0].ErrorCode != name {
			t.Fatalf("%s: replay = %v %v", name, states(receipts), err)
		}
		f.prober.err = nil
		receipts = nil
		retry := f.command(t, 2, "gateway.cdnca.com:9443", "gateway.cdnca.com", f.key)
		if switched, err := f.runtime.Handle(context.Background(), retry, collect(&receipts)); err != nil || !switched {
			t.Fatalf("%s: retry = %v %v", name, switched, err)
		}
	}
}

func TestGatewayAddressChangeRejectsUntrustedStaleAndExpired(t *testing.T) {
	f := newAddressFixture(t)
	_, other, _ := ed25519.GenerateKey(nil)
	var receipts []*agentv1.GatewayAddressChangeReceipt
	if _, err := f.runtime.Handle(context.Background(), f.command(t, 1, "evil.test:443", "evil.test", other), collect(&receipts)); err != nil {
		t.Fatal(err)
	}
	if got := states(receipts); len(got) != 1 || got[0] != "failed:"+gatewayaddr.ErrorUntrusted || len(f.prober.calls) != 0 {
		t.Fatalf("untrusted = %v", got)
	}
	receipts = nil
	if switched, _ := f.runtime.Handle(context.Background(), f.command(t, 5, "gateway.cdnca.com:9443", "gateway.cdnca.com", f.key), collect(&receipts)); !switched {
		t.Fatal("revision 5 not applied")
	}
	receipts = nil
	if _, err := f.runtime.Handle(context.Background(), f.command(t, 3, "old.cdnca.com:443", "old.cdnca.com", f.key), collect(&receipts)); err != nil {
		t.Fatal(err)
	}
	if got := states(receipts); len(got) != 1 || got[0] != "failed:"+gatewayaddr.ErrorStale {
		t.Fatalf("stale = %v", got)
	}
	expired := f.command(t, 9, "x.cdnca.com:443", "x.cdnca.com", f.key)
	f.now = f.now.Add(2 * time.Hour)
	receipts = nil
	if _, err := f.runtime.Handle(context.Background(), expired, collect(&receipts)); err != nil {
		t.Fatal(err)
	}
	if got := states(receipts); len(got) != 1 || got[0] != "failed:"+gatewayaddr.ErrorExpired || f.store.Active().Address != "gateway.cdnca.com:9443" {
		t.Fatalf("expired = %v", got)
	}
}

func TestGatewayAddressChangeRejectsBadCarrier(t *testing.T) {
	f := newAddressFixture(t)
	command := f.command(t, 1, "gateway.cdnca.com:9443", "gateway.cdnca.com", f.key)
	command.DocumentSha256 = make([]byte, 32)
	if _, err := f.runtime.Handle(context.Background(), command, func(*agentv1.GatewayAddressChangeReceipt) error { return nil }); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("digest mismatch = %v", err)
	}
	command = f.command(t, 1, "gateway.cdnca.com:9443", "gateway.cdnca.com", f.key)
	command.NodeId = "7f1c1d2e-3b4a-4c5d-8e9f-0a1b2c3d4e5f"
	if _, err := f.runtime.Handle(context.Background(), command, func(*agentv1.GatewayAddressChangeReceipt) error { return nil }); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("wrong carrier node = %v", err)
	}
}

func TestGatewayAddressChangeRefusedDuringPortTransition(t *testing.T) {
	f := newAddressFixture(t)
	if err := f.store.Stage(GatewayEndpointState{TransitionID: "0c9b5f0e-6a51-4d3e-9a52-2f6a3c1d7b81", Address: "old.cdnca.com:8443", ServerName: "old.cdnca.com", Revision: 5}); err != nil {
		t.Fatal(err)
	}
	if err := f.store.Activate(GatewayEndpointState{TransitionID: "0c9b5f0e-6a51-4d3e-9a52-2f6a3c1d7b81", Address: "old.cdnca.com:8443", ServerName: "old.cdnca.com", Revision: 5}); err != nil {
		t.Fatal(err)
	}
	var receipts []*agentv1.GatewayAddressChangeReceipt
	if _, err := f.runtime.Handle(context.Background(), f.command(t, 1, "gateway.cdnca.com:9443", "gateway.cdnca.com", f.key), collect(&receipts)); err != nil {
		t.Fatal(err)
	}
	if got := states(receipts); got[len(got)-1] != "failed:"+gatewayaddr.ErrorBusy || len(f.prober.calls) != 0 {
		t.Fatalf("busy = %v", got)
	}
}

func TestNegotiateGatewayAddressChangeV1(t *testing.T) {
	enabled := &agentv1.GatewayHello{EnabledCapabilities: []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_GATEWAY_ADDRESS_CHANGE, ApiVersion: 1}}}
	if ok, err := negotiateGatewayAddressChangeV1(enabled, nil); ok || !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("unadvertised = %v %v", ok, err)
	}
	f := newAddressFixture(t)
	if ok, err := negotiateGatewayAddressChangeV1(enabled, f.runtime); !ok || err != nil {
		t.Fatalf("enabled = %v %v", ok, err)
	}
	if ok, err := negotiateGatewayAddressChangeV1(&agentv1.GatewayHello{}, f.runtime); ok || err != nil {
		t.Fatalf("not enabled = %v %v", ok, err)
	}
}
