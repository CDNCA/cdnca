package gatewayclient

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/artifactset"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type fakeArtifactSets struct {
	objects map[string][]byte
	applied []artifactset.Set
	result  string
	ready   bool
}

func (runtime *fakeArtifactSets) PutObject(digest string, data []byte) error {
	if runtime.objects == nil {
		runtime.objects = map[string][]byte{}
	}
	runtime.objects[digest] = bytes.Clone(data)
	return nil
}

func (runtime *fakeArtifactSets) Apply(set artifactset.Set, setSHA256 string, now time.Time) (artifactset.Receipt, error) {
	runtime.applied = append(runtime.applied, set)
	receipt := artifactset.Receipt{NodeID: set.NodeID, Revision: set.Revision, SetSHA256: setSHA256, ReportedAt: now,
		Items: []artifactset.ItemResult{}}
	for _, item := range set.Items {
		result := artifactset.ItemResult{ArtifactID: item.ArtifactID, Version: item.Version, SHA256: item.SHA256, Result: artifactset.ResultApplied}
		if runtime.result == artifactset.ResultRejected {
			result.Result, result.Reason = artifactset.ResultRejected, artifactset.ReasonSegmentMismatch
		}
		receipt.Items = append(receipt.Items, result)
	}
	if runtime.result == artifactset.ResultRejected {
		receipt.Result = artifactset.ResultRejected
		return receipt, nil
	}
	receipt.Result, receipt.ActiveRevision, receipt.ActiveSetSHA256 = artifactset.ResultApplied, set.Revision, setSHA256
	runtime.ready = len(set.Items) > 0
	return receipt, nil
}

func (runtime *fakeArtifactSets) IPIntelReady() bool { return runtime.ready }

func artifactSetClient(t *testing.T, runtime *fakeArtifactSets) (*Client, ed25519.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := NewTrustStore(map[string]crypto.PublicKey{"edge-key": publicKey})
	if err != nil {
		t.Fatal(err)
	}
	client, err := New(site13ClientConfig(filepath.Join(site13SecureTempDir(t), "journal")), site13FailingDialer{}, site13NoOpManager{},
		trust, WithArtifactSetRuntime(runtime))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client, privateKey
}

func artifactSetCommand(mediaType string, wire []byte, privateKey ed25519.PrivateKey, required ...*agentv1.Capability) *agentv1.DeploymentCommand {
	digest := sha256.Sum256(wire)
	scope := uuid.NewString()
	return &agentv1.DeploymentCommand{
		Event:        &commonv1.EventMetadata{EventId: uuid.NewString(), RequestId: uuid.NewString(), OccurredTime: timestamppb.Now(), CorrelationId: uuid.NewString()},
		DeploymentId: uuid.NewString(), Attempt: 1, RolloutId: uuid.NewString(), ConfigVersionId: uuid.NewString(),
		ConfigurationScopeId: &scope, Action: agentv1.DeploymentAction_DEPLOYMENT_ACTION_APPLY,
		Artifacts: []*agentv1.ArtifactDescriptor{{
			ArtifactId: uuid.NewString(), Kind: agentv1.ArtifactKind_ARTIFACT_KIND_CONFIGURATION, MediaType: mediaType,
			SizeBytes: uint64(len(wire)), Sha256: digest[:], Signature: ed25519.Sign(privateKey, wire), SigningKeyId: "edge-key",
			SignatureAlgorithm:  agentv1.ArtifactSignatureAlgorithm_ARTIFACT_SIGNATURE_ALGORITHM_ED25519,
			Compression:         agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_NONE,
			EncryptionAlgorithm: agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_NONE,
		}},
		RequiredCapabilities: required,
		HealthCheck: &agentv1.HealthCheckPolicy{ActivationTimeoutDuration: durationpb.New(time.Minute),
			ObservationWindowDuration: durationpb.New(time.Second), RequiredConsecutiveSuccesses: 1},
		DeadlineTime: timestamppb.New(time.Now().Add(time.Hour)),
	}
}

func runArtifactSetCommand(t *testing.T, client *Client, command *agentv1.DeploymentCommand, wire []byte) []*agentv1.DeploymentStatus {
	t.Helper()
	record, _, err := client.store.putCommand(command, deliveredStatus(command))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.executeRecord(t.Context(), site13FetchGatewayClient(t, wire), record.RecordKey, 1<<20); err != nil {
		t.Fatal(err)
	}
	persisted, err := client.store.record(record.RecordKey)
	if err != nil {
		t.Fatal(err)
	}
	statuses, err := statusesFromRecord(persisted)
	if err != nil || !persisted.ExecutionDone {
		t.Fatalf("statuses=%v err=%v done=%t", statuses, err, persisted.ExecutionDone)
	}
	return statuses
}

func signedSet(t *testing.T, client *Client, privateKey ed25519.PrivateKey, revision uint64) []byte {
	t.Helper()
	segment := []byte("segment")
	digest := artifactset.Digest(segment)
	set := artifactset.Set{NodeID: client.config.NodeID, Revision: revision, IssuedAt: time.Now(), Items: []artifactset.Item{{
		ArtifactID: "ipintel/base", Version: fmt.Sprint(revision), Revision: revision, MediaType: artifactset.MediaTypeIPIntel,
		SHA256: digest, Size: int64(len(segment)), Compression: artifactset.CompressionNone,
		CompressedSHA256: digest, CompressedSize: int64(len(segment)), Encryption: artifactset.EncryptionNone,
		Segments: []artifactset.Segment{{SHA256: digest, Size: int64(len(segment))}},
	}}}
	wire, err := artifactset.Sign(set, "edge-key", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestArtifactSegmentCommandStoresTheObject(t *testing.T) {
	runtime := &fakeArtifactSets{}
	client, privateKey := artifactSetClient(t, runtime)
	segment := []byte("compressed library segment")
	statuses := runArtifactSetCommand(t, client, artifactSetCommand(artifactset.MediaTypeSegment, segment, privateKey), segment)
	final := statuses[len(statuses)-1]
	if final.State != agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY || !final.RunningConfigUnchanged ||
		!bytes.Equal(runtime.objects[artifactset.Digest(segment)], segment) {
		t.Fatalf("final=%+v objects=%d", final, len(runtime.objects))
	}
}

func TestArtifactSetCommandAppliesAndReportsTheReceipt(t *testing.T) {
	runtime := &fakeArtifactSets{}
	client, privateKey := artifactSetClient(t, runtime)
	wire := signedSet(t, client, privateKey, 3)
	statuses := runArtifactSetCommand(t, client, artifactSetCommand(artifactset.MediaTypeSet, wire, privateKey), wire)
	final := statuses[len(statuses)-1]
	receipt, err := artifactset.DecodeReceipt(final.ArtifactSetReceipt)
	if final.State != agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY || err != nil ||
		receipt.Result != artifactset.ResultApplied || receipt.Revision != 3 || receipt.SetSHA256 != artifactset.Digest(wire) ||
		len(runtime.applied) != 1 {
		t.Fatalf("final=%+v receipt=%+v err=%v", final, receipt, err)
	}
}

func TestRejectedArtifactSetFailsWithTheReceipt(t *testing.T) {
	runtime := &fakeArtifactSets{result: artifactset.ResultRejected}
	client, privateKey := artifactSetClient(t, runtime)
	wire := signedSet(t, client, privateKey, 2)
	statuses := runArtifactSetCommand(t, client, artifactSetCommand(artifactset.MediaTypeSet, wire, privateKey), wire)
	final := statuses[len(statuses)-1]
	receipt, err := artifactset.DecodeReceipt(final.ArtifactSetReceipt)
	if final.State != agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED || !final.RunningConfigUnchanged || err != nil ||
		receipt.Result != artifactset.ResultRejected || receipt.Items[0].Reason != artifactset.ReasonSegmentMismatch {
		t.Fatalf("final=%+v receipt=%+v err=%v", final, receipt, err)
	}
}

func TestArtifactSetWithForeignSignatureIsNotApplied(t *testing.T) {
	runtime := &fakeArtifactSets{}
	client, privateKey := artifactSetClient(t, runtime)
	_, otherKey, _ := ed25519.GenerateKey(rand.Reader)
	// The set document is signed by an untrusted key; the transport
	// signature is the trusted one.
	wire := signedSet(t, client, otherKey, 1)
	statuses := runArtifactSetCommand(t, client, artifactSetCommand(artifactset.MediaTypeSet, wire, privateKey), wire)
	if final := statuses[len(statuses)-1]; final.State != agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED ||
		len(runtime.applied) != 0 || final.ArtifactSetReceipt != nil {
		t.Fatalf("final=%+v applied=%d", final, len(runtime.applied))
	}
}

func TestHelloDeclaresArtifactSetAndIPIntelWhenReady(t *testing.T) {
	runtime := &fakeArtifactSets{}
	client, _ := artifactSetClient(t, runtime)
	versions := func() map[agentv1.CapabilityName]uint32 {
		hello, err := client.agentHello()
		if err != nil {
			t.Fatal(err)
		}
		out := map[agentv1.CapabilityName]uint32{}
		for _, capability := range hello.Capabilities.Features {
			out[capability.Name] = capability.ApiVersion
		}
		return out
	}
	if got := versions(); got[agentv1.CapabilityName_CAPABILITY_NAME_ARTIFACT_SET] != 1 ||
		got[agentv1.CapabilityName_CAPABILITY_NAME_IP_INTEL] != 0 || client.declaredIPIntel.Load() {
		t.Fatalf("without a library: %v", got)
	}
	runtime.ready = true
	if got := versions(); got[agentv1.CapabilityName_CAPABILITY_NAME_IP_INTEL] != 2 || !client.declaredIPIntel.Load() {
		t.Fatalf("with a library: %v", got)
	}
}

func TestCommandsRequiringIPIntelFollowTheAppliedSet(t *testing.T) {
	runtime := &fakeArtifactSets{}
	client, privateKey := artifactSetClient(t, runtime)
	segment := []byte("x")
	command := artifactSetCommand(artifactset.MediaTypeSegment, segment, privateKey,
		&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_IP_INTEL, ApiVersion: 2})
	if err := validateArtifactSetRoutedCommand(command, client.commandConfig(), time.Now()); err == nil {
		t.Fatal("a command requiring IP_INTEL was accepted before a library was applied")
	}
	runtime.ready = true
	if err := validateArtifactSetRoutedCommand(command, client.commandConfig(), time.Now()); err != nil {
		t.Fatalf("with a library: %v", err)
	}
}

// A platform-scope node artifact queued on a multi-tenant session is not a
// configuration apply: recording it as the scope's last apply result put an
// unclaimed scope into every heartbeat, which the control plane terminates,
// so the node stayed offline after its first artifact set (live-site D1).
func TestQueuedArtifactSetIsNotRecordedAsAScopeApplyResult(t *testing.T) {
	runtime := &fakeArtifactSets{}
	client, privateKey := artifactSetClient(t, runtime)
	wire := signedSet(t, client, privateKey, 1)
	command := artifactSetCommand(artifactset.MediaTypeSet, wire, privateKey)
	record, _, err := client.store.putCommand(command, deliveredStatus(command))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.store.appendStatuses(record.RecordKey, []*agentv1.DeploymentStatus{scopedQueuedStatus(command, time.Now())}, false); err != nil {
		t.Fatal(err)
	}
	if err := client.executeRecord(t.Context(), site13FetchGatewayClient(t, wire), record.RecordKey, 1<<20); err != nil {
		t.Fatal(err)
	}
	persisted, err := client.store.record(record.RecordKey)
	if err != nil || !persisted.ExecutionDone {
		t.Fatalf("record=%+v err=%v", persisted, err)
	}
	results, err := client.store.scopeApplyResults()
	if err != nil || len(results) != 0 {
		t.Fatalf("scope apply results=%+v err=%v", results, err)
	}
}
