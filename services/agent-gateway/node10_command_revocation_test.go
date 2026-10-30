package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
)

func TestDeploymentCommandRevocationBlocksNewDeliveryWithoutClosingSession(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	cache, err := NewRevocationCheckpointCache("01HZXNODE10INSTALLATION", map[string]ed25519.PublicKey{"revocation-key-1": publicKey}, func() time.Time { return now }, 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	wire := gatewaySignedCheckpoint(t, privateKey, gatewayCheckpointBody{
		Schema: revocationCheckpointSchema, InstallationID: "01HZXNODE10INSTALLATION", Revision: 1,
		IssuedAt: now, ExpiresAt: now.Add(time.Hour), KeyID: "revocation-key-1",
		Certificates: []gatewayRevokedCertificate{{NodeID: testNodeID, SerialNumber: "10", AuthorizationRevision: 1}},
	})
	if _, err := cache.ApplyRevocationCheckpoint(wire); err != nil {
		t.Fatal(err)
	}
	bus := &fakeCommandBus{subscription: newFakeCommandSubscription()}
	gateway := newCommandGateway(t, defaultFakeControl(), bus, nil)
	if err := gateway.ConfigureRevocationCheckpointCache(cache); err != nil {
		t.Fatal(err)
	}
	delivery := &fakeCommandDelivery{command: validDeploymentCommand()}
	bus.subscription.deliveries <- delivery
	lease, err := NewMemorySessionCoordinator().Acquire(context.Background(), testNodeID)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := &capturingBidiStream{ctx: ctx, sent: make(chan *agentv1.ConnectResponse, 1)}
	done := make(chan error, 1)
	go func() {
		done <- gateway.serveSession(
			stream, make(chan connectReceive), lease, newMessageReplayWindow(defaultMessageReplayWindow), 1,
			nodeIdentity{NodeID: testNodeID, SerialNumber: "10"}, "", versionRange(1, 0),
			&commonv1.ProtocolVersion{Major: 1}, "artifact-key", now.Add(time.Hour), true, false,
		)
	}()
	waitForTest(t, time.Second, func() bool { return delivery.naks.Load() == 1 })
	select {
	case response := <-stream.sent:
		t.Fatalf("revoked command was sent: %+v", response)
	default:
	}
	select {
	case err := <-done:
		t.Fatalf("revocation closed established session: %v", err)
	default:
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("session did not stop after test cancellation")
	}
}

func TestDeploymentCommandRevocationAllowsNewCertificateSerial(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	cache, err := NewRevocationCheckpointCache("01HZXNODE10INSTALLATION", map[string]ed25519.PublicKey{"revocation-key-1": publicKey}, func() time.Time { return now }, 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	wire := gatewaySignedCheckpoint(t, privateKey, gatewayCheckpointBody{
		Schema: revocationCheckpointSchema, InstallationID: "01HZXNODE10INSTALLATION", Revision: 1,
		IssuedAt: now, ExpiresAt: now.Add(time.Hour), KeyID: "revocation-key-1",
		Certificates: []gatewayRevokedCertificate{{NodeID: testNodeID, SerialNumber: "10", AuthorizationRevision: 1}},
	})
	if _, err := cache.ApplyRevocationCheckpoint(wire); err != nil {
		t.Fatal(err)
	}
	bus := &fakeCommandBus{subscription: newFakeCommandSubscription()}
	gateway := newCommandGateway(t, defaultFakeControl(), bus, nil)
	if err := gateway.ConfigureRevocationCheckpointCache(cache); err != nil {
		t.Fatal(err)
	}
	delivery := &fakeCommandDelivery{command: validDeploymentCommand()}
	bus.subscription.deliveries <- delivery
	lease, err := NewMemorySessionCoordinator().Acquire(context.Background(), testNodeID)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := &capturingBidiStream{ctx: ctx, sent: make(chan *agentv1.ConnectResponse, 1)}
	done := make(chan error, 1)
	go func() {
		done <- gateway.serveSession(
			stream, make(chan connectReceive), lease, newMessageReplayWindow(defaultMessageReplayWindow), 1,
			nodeIdentity{NodeID: testNodeID, SerialNumber: "11"}, "", versionRange(1, 0),
			&commonv1.ProtocolVersion{Major: 1}, "artifact-key", now.Add(time.Hour), true, false,
		)
	}()
	select {
	case response := <-stream.sent:
		if response.GetDeploymentCommand() == nil {
			t.Fatalf("response = %+v, want deployment command", response)
		}
	case <-time.After(time.Second):
		t.Fatal("new certificate command was not delivered")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("session did not stop after test cancellation")
	}
	if delivery.naks.Load() != 1 {
		// The command is NAKed by the session cleanup because it remains pending.
		t.Fatalf("naks=%d, want cleanup NAK", delivery.naks.Load())
	}
}

func TestConfigureRevocationCheckpointCacheRejectsNilOrDuplicate(t *testing.T) {
	gateway := &Gateway{}
	if err := gateway.ConfigureRevocationCheckpointCache(nil); err == nil {
		t.Fatal("nil revocation cache was accepted")
	}
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cache, err := NewRevocationCheckpointCache("01HZXNODE10INSTALLATION", map[string]ed25519.PublicKey{"revocation-key-1": publicKey}, time.Now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := gateway.ConfigureRevocationCheckpointCache(cache); err != nil {
		t.Fatal(err)
	}
	if err := gateway.ConfigureRevocationCheckpointCache(cache); err == nil {
		t.Fatal("duplicate revocation cache was accepted")
	}
}
