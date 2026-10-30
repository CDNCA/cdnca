package gatewayclient

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/certstore"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
)

type certificateRuntime struct {
	mu          sync.Mutex
	activations int
	prechecks   int
	health      int
}

func (runtime *certificateRuntime) Precheck(context.Context, string) error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.prechecks++
	return nil
}

func (runtime *certificateRuntime) Activate(context.Context, string) error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.activations++
	return nil
}

func (runtime *certificateRuntime) Healthy(context.Context, []certstore.HealthTarget) error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.health++
	return nil
}

func (*certificateRuntime) Stop(context.Context, string) error { return nil }

func (runtime *certificateRuntime) activationCount() int {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return runtime.activations
}

func TestCertificateGatewayConnectFetchActivateAndReport(t *testing.T) {
	harness := newCertificateHarness(t)
	bundle := certificateBundle(t, "cert-connect-v1", time.Now().Add(-time.Hour), time.Now().Add(time.Hour), false)
	command, wire := encryptedCertificateCommand(t, harness.signingKey, harness.recipientKey, harness.recipientID, bundle, 1, nil)
	gateway := &fakeGateway{command: command, artifact: wire, statusEvents: make(chan *agentv1.DeploymentStatus, 128)}
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	agentv1.RegisterAgentGatewayServiceServer(server, gateway)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})

	closeGatewayClientForRestart(t, harness.client)
	client, err := New(harness.config, &bufDialer{listener: listener}, noOpManager{}, harness.trust, WithCertificateConsumer(harness.manager))
	if err != nil {
		t.Fatal(err)
	}
	client.jitter = func(time.Duration) time.Duration { return time.Millisecond }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()
	waitForState(t, gateway.statusEvents, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY)
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context canceled", err)
	}
	if harness.runtime.activationCount() != 1 {
		t.Fatalf("activation count = %d, want 1", harness.runtime.activationCount())
	}
	offsets, _ := gateway.transferRequests()
	if len(offsets) < 2 || offsets[0] != 0 || offsets[1] == 0 {
		t.Fatalf("ciphertext offsets = %v, want interrupted transfer resume", offsets)
	}
	assertNoPrivateMaterial(t, harness.root)
}

func TestCertificateGatewayEncryptedRotationReplayAndRestart(t *testing.T) {
	harness := newCertificateHarness(t)
	bundleV1 := certificateBundle(t, "cert-v1", time.Now().Add(-time.Hour), time.Now().Add(time.Hour), false)
	commandV1, wireV1 := encryptedCertificateCommand(t, harness.signingKey, harness.recipientKey, harness.recipientID, bundleV1, 1, nil)
	statuses := harness.execute(t, commandV1, wireV1)
	assertCertificateStates(t, statuses, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY)
	if harness.runtime.activationCount() != 1 {
		t.Fatalf("activation count = %d, want 1", harness.runtime.activationCount())
	}

	bundleV2 := certificateBundle(t, "cert-v2", time.Now().Add(-time.Hour), time.Now().Add(time.Hour), false)
	commandV2, wireV2 := encryptedCertificateCommand(t, harness.signingKey, harness.recipientKey, harness.recipientID, bundleV2, 2, nil)
	statuses = harness.execute(t, commandV2, wireV2)
	assertCertificateStates(t, statuses, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY)
	if harness.runtime.activationCount() != 2 {
		t.Fatalf("rotation activation count = %d, want 2", harness.runtime.activationCount())
	}
	status, err := harness.manager.Status(context.Background())
	if err != nil || status.VersionID != "cert-v2" || status.Activation == nil || status.Activation.Certificates[0].Version != 2 {
		t.Fatalf("active certificate status = (%#v, %v)", status, err)
	}

	for index := 0; index < 8; index++ {
		if err := harness.client.executeRecord(context.Background(), newFetchGatewayClient(t, wireV2), recordKey(commandV2.DeploymentId, commandV2.Attempt), 1<<20); err != nil {
			t.Fatal(err)
		}
	}
	if harness.runtime.activationCount() != 2 {
		t.Fatalf("duplicate command reactivated certificates %d times", harness.runtime.activationCount())
	}
	assertNoPrivateMaterial(t, harness.root)

	restartedRuntime := &certificateRuntime{}
	restartedManager, err := certstore.NewManager(certstore.RuntimeConfig{
		StateRoot: filepath.Join(harness.root, "certstore"), ListenAddress: "127.0.0.1", ListenPort: 18443,
	}, restartedRuntime)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restartedManager.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	closeGatewayClientForRestart(t, harness.client)
	restarted, err := New(harness.config, &failingDialer{}, noOpManager{}, harness.trust, WithCertificateConsumer(restartedManager))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restarted.Close() })
	if err := restarted.executeRecord(context.Background(), newFetchGatewayClient(t, wireV2), recordKey(commandV2.DeploymentId, commandV2.Attempt), 1<<20); err != nil {
		t.Fatal(err)
	}
	if restartedRuntime.activationCount() != 1 {
		t.Fatalf("restart replay activation count = %d, want only Recover activation", restartedRuntime.activationCount())
	}
}

// Every activation names its certificate version, scope and binding revision.
func TestCertificateGatewayRejectsArtifactWithoutVersionIdentity(t *testing.T) {
	harness := newCertificateHarness(t)
	for name, mutate := range map[string]func(*certificateArtifactDocument){
		"version identity": func(document *certificateArtifactDocument) {
			document.Activation.Certificates[0].TenantScopeID = ""
			document.Activation.Certificates[0].CertificateVersionID = ""
		},
		"binding revision": func(document *certificateArtifactDocument) {
			document.Activation.Certificates[0].BindingRevision = 0
		},
	} {
		t.Run(name, func(t *testing.T) {
			bundle := certificateBundle(t, "cert-without-identity", time.Now().Add(-time.Hour), time.Now().Add(time.Hour), false)
			command, wire := encryptedCertificateCommand(t, harness.signingKey, harness.recipientKey, harness.recipientID, bundle, 1, mutate)
			failed := lastStatus(t, harness.execute(t, command, wire))
			if failed.State != agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED || failed.Error == nil ||
				failed.Error.Code != commonv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT || !failed.RunningConfigUnchanged {
				t.Fatalf("status = %#v", failed)
			}
		})
	}
}

func TestConcurrentCertificateGatewayConsumersCannotDowngrade(t *testing.T) {
	harness := newCertificateHarness(t)
	base := certificateBundle(t, "cert-concurrent-v1", time.Now().Add(-time.Hour), time.Now().Add(time.Hour), false)
	baseCommand, baseWire := encryptedCertificateCommand(t, harness.signingKey, harness.recipientKey, harness.recipientID, base, 1, nil)
	harness.execute(t, baseCommand, baseWire)

	secondManager, err := certstore.NewManager(certstore.RuntimeConfig{
		StateRoot: filepath.Join(harness.root, "certstore"), ListenAddress: "127.0.0.1", ListenPort: 18443,
	}, &certificateRuntime{})
	if err != nil {
		t.Fatal(err)
	}
	secondConfig := harness.config
	secondConfig.JournalDir = filepath.Join(harness.root, "journal-second")
	secondClient, err := New(secondConfig, &failingDialer{}, noOpManager{}, harness.trust, WithCertificateConsumer(secondManager))
	if err != nil {
		t.Fatal(err)
	}
	bundleV2 := certificateBundle(t, "cert-concurrent-v2", time.Now().Add(-time.Hour), time.Now().Add(time.Hour), false)
	bundleV3 := certificateBundle(t, "cert-concurrent-v3", time.Now().Add(-time.Hour), time.Now().Add(time.Hour), false)
	commandV2, wireV2 := encryptedCertificateCommand(t, harness.signingKey, harness.recipientKey, harness.recipientID, bundleV2, 2, nil)
	commandV3, wireV3 := encryptedCertificateCommand(t, harness.signingKey, harness.recipientKey, harness.recipientID, bundleV3, 3, nil)
	recordV2, _, err := harness.client.store.putCommand(commandV2, deliveredStatus(commandV2))
	if err != nil {
		t.Fatal(err)
	}
	recordV3, _, err := secondClient.store.putCommand(commandV3, deliveredStatus(commandV3))
	if err != nil {
		t.Fatal(err)
	}
	gatewayV2 := newFetchGatewayClient(t, wireV2)
	gatewayV3 := newFetchGatewayClient(t, wireV3)

	start := make(chan struct{})
	results := make(chan error, 2)
	go func() {
		<-start
		results <- harness.client.executeRecord(context.Background(), gatewayV2, recordV2.RecordKey, 1<<20)
	}()
	go func() {
		<-start
		results <- secondClient.executeRecord(context.Background(), gatewayV3, recordV3.RecordKey, 1<<20)
	}()
	close(start)
	for index := 0; index < 2; index++ {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	status, err := harness.manager.Status(context.Background())
	if err != nil || status.Activation == nil || status.Activation.Certificates[0].Version != 3 || status.VersionID != bundleV3.VersionID {
		t.Fatalf("concurrent final status = (%#v, %v)", status, err)
	}
}

func TestCertificateGatewayFailuresPreserveLastKnownGood(t *testing.T) {
	harness := newCertificateHarness(t)
	baselineBundle := certificateBundle(t, "cert-v2", time.Now().Add(-time.Hour), time.Now().Add(time.Hour), false)
	baselineCommand, baselineWire := encryptedCertificateCommand(t, harness.signingKey, harness.recipientKey, harness.recipientID, baselineBundle, 2, nil)
	harness.execute(t, baselineCommand, baselineWire)
	baseline, err := harness.manager.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		bundle    func(*testing.T) certstore.Bundle
		version   uint64
		mutate    func(*agentv1.DeploymentCommand, []byte) []byte
		mutateDoc func(*certificateArtifactDocument)
		wantCode  commonv1.ErrorCode
	}{
		{
			name: "stale-version", bundle: func(t *testing.T) certstore.Bundle {
				return certificateBundle(t, "cert-stale", time.Now().Add(-time.Hour), time.Now().Add(time.Hour), false)
			}, version: 1, wantCode: commonv1.ErrorCode_ERROR_CODE_STALE_ATTEMPT,
		},
		{
			name: "expired-certificate", bundle: func(t *testing.T) certstore.Bundle {
				return certificateBundle(t, "cert-expired", time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour), false)
			}, version: 3, wantCode: commonv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT,
		},
		{
			name: "wrong-private-key", bundle: func(t *testing.T) certstore.Bundle {
				return certificateBundle(t, "cert-wrong-key", time.Now().Add(-time.Hour), time.Now().Add(time.Hour), true)
			}, version: 3, wantCode: commonv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT,
		},
		{
			name: "inner-binding", bundle: func(t *testing.T) certstore.Bundle {
				return certificateBundle(t, "cert-inner-binding", time.Now().Add(-time.Hour), time.Now().Add(time.Hour), false)
			}, version: 3, mutateDoc: func(document *certificateArtifactDocument) {
				document.Activation.CommandEventID = "wrong-event"
			}, wantCode: commonv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT,
		},
		{
			name: "missing-certificate-version-uuid", bundle: func(t *testing.T) certstore.Bundle {
				return certificateBundle(t, "cert-missing-version-uuid", time.Now().Add(-time.Hour), time.Now().Add(time.Hour), false)
			}, version: 3, mutateDoc: func(document *certificateArtifactDocument) {
				document.Activation.Certificates[0].CertificateVersionID = ""
			}, wantCode: commonv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT,
		},
		{
			name: "signature-tamper", bundle: func(t *testing.T) certstore.Bundle {
				return certificateBundle(t, "cert-signature", time.Now().Add(-time.Hour), time.Now().Add(time.Hour), false)
			}, version: 3, mutate: func(command *agentv1.DeploymentCommand, wire []byte) []byte {
				command.Artifacts[0].Signature[0] ^= 0x80
				return wire
			}, wantCode: commonv1.ErrorCode_ERROR_CODE_DIGEST_MISMATCH,
		},
		{
			name: "ciphertext-tamper", bundle: func(t *testing.T) certstore.Bundle {
				return certificateBundle(t, "cert-ciphertext", time.Now().Add(-time.Hour), time.Now().Add(time.Hour), false)
			}, version: 3, mutate: func(_ *agentv1.DeploymentCommand, wire []byte) []byte {
				wire[len(wire)-1] ^= 0x80
				return wire
			}, wantCode: commonv1.ErrorCode_ERROR_CODE_DIGEST_MISMATCH,
		},
		{
			name: "outer-command-binding", bundle: func(t *testing.T) certstore.Bundle {
				return certificateBundle(t, "cert-outer-binding", time.Now().Add(-time.Hour), time.Now().Add(time.Hour), false)
			}, version: 3, mutate: func(command *agentv1.DeploymentCommand, wire []byte) []byte {
				command.Event.EventId = newUUID(t)
				return wire
			}, wantCode: commonv1.ErrorCode_ERROR_CODE_DIGEST_MISMATCH,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			command, wire := encryptedCertificateCommand(t, harness.signingKey, harness.recipientKey, harness.recipientID, test.bundle(t), test.version, test.mutateDoc)
			if test.mutate != nil {
				wire = test.mutate(command, wire)
			}
			statuses := harness.execute(t, command, wire)
			failed := lastStatus(t, statuses)
			if failed.State != agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED || failed.Error == nil || failed.Error.Code != test.wantCode || !failed.RunningConfigUnchanged {
				t.Fatalf("failure status = %#v", failed)
			}
			if strings.Contains(strings.ToLower(failed.Error.Message), "private") || strings.Contains(failed.Error.Message, "BEGIN") {
				t.Fatalf("failure leaked private material: %q", failed.Error.Message)
			}
			current, statusErr := harness.manager.Status(context.Background())
			if statusErr != nil || current.Digest != baseline.Digest || current.VersionID != baseline.VersionID {
				t.Fatalf("LKG changed after failure: (%#v, %v)", current, statusErr)
			}
		})
	}

	t.Run("wrong-recipient", func(t *testing.T) {
		bundle := certificateBundle(t, "cert-recipient", time.Now().Add(-time.Hour), time.Now().Add(time.Hour), false)
		command, wire := encryptedCertificateCommand(t, harness.signingKey, harness.recipientKey, harness.recipientID, bundle, 3, nil)
		wrong := "x25519:" + strings.Repeat("0", 64)
		command.Artifacts[0].RecipientKeyId = &wrong
		statuses := harness.execute(t, command, wire)
		failed := lastStatus(t, statuses)
		if failed.State != agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED || failed.Error.Code != commonv1.ErrorCode_ERROR_CODE_FAILED_PRECONDITION {
			t.Fatalf("wrong recipient status = %#v", failed)
		}
	})
	assertNoPrivateMaterial(t, harness.root)
}

func TestCertificateArtifactStrictDecodeAndBinding(t *testing.T) {
	for name, raw := range map[string][]byte{
		"empty":     nil,
		"unknown":   []byte(`{"schema_version":"cdnca.edge.certificate-artifact/v1","activation":{},"bundle":{},"unknown":true}`),
		"duplicate": []byte(`{"schema_version":"v1","schema_version":"v1","activation":{},"bundle":{}}`),
		"multiple":  []byte(`{} {}`),
		"oversized": bytes.Repeat([]byte(" "), maxCertificateArtifactPlaintextBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeCertificateArtifact(raw); !errors.Is(err, ErrInvalidCertificateArtifact) {
				t.Fatalf("decode error = %v", err)
			}
		})
	}
}

type certificateHarness struct {
	root         string
	config       Config
	manager      *certstore.Manager
	runtime      *certificateRuntime
	client       *Client
	trust        *TrustStore
	signingKey   ed25519.PrivateKey
	recipientKey []byte
	recipientID  string
}

func newCertificateHarness(t *testing.T) *certificateHarness {
	t.Helper()
	root := secureTempDir(t)
	t.Cleanup(func() { makeTestTreeWritable(root) })
	publicKey, signingKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	recipientKey, recipientID := newArtifactRecipient(t)
	runtime := &certificateRuntime{}
	manager, err := certstore.NewManager(certstore.RuntimeConfig{
		StateRoot: filepath.Join(root, "certstore"), ListenAddress: "127.0.0.1", ListenPort: 18443,
	}, runtime)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := NewTrustStore(map[string]crypto.PublicKey{"test-signing-key": publicKey})
	if err != nil {
		t.Fatal(err)
	}
	config := testClientConfig(filepath.Join(root, "journal"))
	config.ArtifactEncryptionKeyID = recipientID
	config.ArtifactDecryptionPrivateKey = recipientKey
	client, err := New(config, &failingDialer{}, noOpManager{}, trust, WithCertificateConsumer(manager))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return &certificateHarness{
		root: root, config: config, manager: manager, runtime: runtime, client: client, trust: trust,
		signingKey: signingKey, recipientKey: recipientKey, recipientID: recipientID,
	}
}

func (harness *certificateHarness) execute(t *testing.T, command *agentv1.DeploymentCommand, wire []byte) []*agentv1.DeploymentStatus {
	t.Helper()
	record, _, err := harness.client.store.putCommand(command, deliveredStatus(command))
	if err != nil {
		t.Fatal(err)
	}
	if err := harness.client.executeRecord(context.Background(), newFetchGatewayClient(t, wire), record.RecordKey, 1<<20); err != nil {
		t.Fatal(err)
	}
	record, err = harness.client.store.record(record.RecordKey)
	if err != nil {
		t.Fatal(err)
	}
	statuses, err := statusesFromRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	return statuses
}

func newFetchGatewayClient(t *testing.T, wire []byte) agentv1.AgentGatewayServiceClient {
	t.Helper()
	gateway := &fakeGateway{artifact: wire, statusEvents: make(chan *agentv1.DeploymentStatus, 1)}
	gateway.dropFirstFetch.Store(true)
	listener := bufconnListen(t)
	server := grpc.NewServer()
	agentv1.RegisterAgentGatewayServiceServer(server, gateway)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})
	connection, err := (&bufDialer{listener: listener}).Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	return connection.Client()
}

func bufconnListen(t *testing.T) *bufconn.Listener {
	t.Helper()
	return bufconn.Listen(1 << 20)
}

func encryptedCertificateCommand(t *testing.T, signingKey ed25519.PrivateKey, recipientKey []byte, recipientID string, bundle certstore.Bundle, version uint64, mutateDocument func(*certificateArtifactDocument)) (*agentv1.DeploymentCommand, []byte) {
	t.Helper()
	command, _ := signedBundleTestCommand(t, signingKey)
	command.ConfigVersionId = bundle.VersionID
	descriptor := command.Artifacts[0]
	descriptor.Kind = agentv1.ArtifactKind_ARTIFACT_KIND_NODE_SECRET_BUNDLE
	descriptor.MediaType = CertificateArtifactMediaType
	document := certificateArtifactDocument{
		SchemaVersion: CertificateArtifactSchemaVersion,
		Activation: certstore.ActivationMetadata{
			SchemaVersion: certstore.ActivationSchemaVersion, ConfigVersionID: bundle.VersionID,
			RecipientKeyID: recipientID, CommandEventID: command.Event.EventId,
			DeploymentID: command.DeploymentId, Attempt: command.Attempt, ArtifactID: descriptor.ArtifactId,
			Certificates: []certstore.CertificateRevision{{
				TenantID: "tenant-a", TenantScopeID: "018f47a2-5b9c-7d31-8a60-104c9c0b7101",
				SiteID: "site-a", CertificateID: "certificate-a",
				CertificateVersionID: uuid.NewSHA1(uuid.NameSpaceOID, []byte(fmt.Sprintf("certificate-a:%d", version))).String(),
				Version:              version, BindingRevision: version,
			}},
		},
		Bundle: bundle,
	}
	if mutateDocument != nil {
		mutateDocument(&document)
	}
	plaintext, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return command, encryptTestArtifact(t, command, descriptor, plaintext, recipientKey, recipientID, signingKey)
}

func certificateBundle(t *testing.T, version string, notBefore, notAfter time.Time, wrongPrivateKey bool) certstore.Bundle {
	t.Helper()
	chain, privateKey := certificatePEM(t, "edge.example.test", notBefore, notAfter)
	if wrongPrivateKey {
		_, privateKey = certificatePEM(t, "edge.example.test", notBefore, notAfter)
	}
	return certstore.Bundle{
		SchemaVersion: certstore.SchemaVersion, VersionID: version,
		Bindings: []certstore.Binding{{
			SiteID: "site-a", Domains: []string{"edge.example.test"},
			CertificateChainPEM: chain, PrivateKeyPEM: privateKey,
		}},
	}
}

func certificatePEM(t *testing.T, domain string, notBefore, notAfter time.Time) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: domain}, DNSNames: []string{domain},
		NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}))
}

func assertCertificateStates(t *testing.T, statuses []*agentv1.DeploymentStatus, final agentv1.NodeDeploymentState) {
	t.Helper()
	want := []agentv1.NodeDeploymentState{
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STAGED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_PRECHECKED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ACTIVATED,
		final,
	}
	if len(statuses) != len(want) {
		t.Fatalf("status count = %d, want %d", len(statuses), len(want))
	}
	for index := range want {
		if statuses[index].State != want[index] {
			t.Fatalf("status %d = %s, want %s", index, statuses[index].State, want[index])
		}
	}
}

func lastStatus(t *testing.T, statuses []*agentv1.DeploymentStatus) *agentv1.DeploymentStatus {
	t.Helper()
	if len(statuses) == 0 {
		t.Fatal("no certificate statuses")
	}
	return statuses[len(statuses)-1]
}

func assertNoPrivateMaterial(t *testing.T, root string) {
	t.Helper()
	for _, path := range []string{filepath.Join(root, "journal"), filepath.Join(root, "certstore", "status.json")} {
		err := filepath.WalkDir(path, func(name string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || strings.Contains(name, string(filepath.Separator)+"versions"+string(filepath.Separator)) {
				return nil
			}
			content, err := os.ReadFile(name)
			if err != nil {
				return err
			}
			lower := bytes.ToLower(content)
			if bytes.Contains(lower, []byte("private_key_pem")) || bytes.Contains(lower, []byte("begin private key")) {
				t.Fatalf("private material leaked to %s", name)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
