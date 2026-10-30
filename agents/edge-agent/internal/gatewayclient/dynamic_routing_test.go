package gatewayclient

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/deployment"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/objectstore"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type fakeDynamicRouting struct {
	DeploymentManager
	mu      sync.Mutex
	applied []DynamicRoutingRelease
	fail    error
}

func (f *fakeDynamicRouting) ApplyDynamicRouting(_ context.Context, deploymentID string, attempt uint32,
	release DynamicRoutingRelease) (deployment.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applied = append(f.applied, release)
	return DynamicRoutingResult(deploymentID, attempt, deployment.ActionApply, release.ConfigVersionID, time.Now(), time.Now(), f.fail), nil
}

func (f *fakeDynamicRouting) activationCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.applied)
}

// dynamicRoutingRelease builds, seals and signs a v2 root release.
func (h *siteObjectHarness) dynamicRoutingRelease(t *testing.T, sites int, referenced []byte) *siteObjectTestRelease {
	t.Helper()
	return h.dynamicRoutingReleaseFor(t, "5c0b0000-0000-4000-8000-0000000000aa", sites, referenced)
}

// dynamicRoutingReleaseFor is dynamicRoutingRelease for scopeID.
func (h *siteObjectHarness) dynamicRoutingReleaseFor(t *testing.T, scopeID string, sites int, referenced []byte) *siteObjectTestRelease {
	t.Helper()
	return newSiteObjectRelease(t, h.key, h.client.config.ArtifactDecryptionPrivateKey, h.client.config.ArtifactEncryptionKeyID,
		h.contentKey, scopeID, sites, referenced)
}

// newSiteObjectRelease builds, seals and signs a v2 root release for scopeID
// (the only configuration release a node takes) with its key envelope sealed
// to the recipient.
func newSiteObjectRelease(t *testing.T, signingKey ed25519.PrivateKey, recipientKey []byte, recipientID string,
	contentKey []byte, scopeID string, sites int, referenced []byte) *siteObjectTestRelease {
	t.Helper()
	configID := uuid.NewString()
	input := siteobject.BuildV2Input{
		ConfigurationScopeID: scopeID, ConfigVersionID: configID, SourceRevision: 2, KeyEpoch: 1,
		RequiredCapabilities: []siteobject.Capability{{Name: "http1", APIVersion: 1}, {Name: "site_runtime", APIVersion: 9}},
		DocumentSHA256:       siteobject.Digest([]byte("doc")), Referenced: map[string][]byte{siteobject.Digest(referenced): referenced},
		ScopeFiles: map[string][]byte{"security/modsecurity/crs/a.conf": []byte("SecRule")},
	}
	for index := range sites {
		id := fmt.Sprintf("a0000000-0000-4000-8000-%012d", index+1)
		input.Sites = append(input.Sites, siteobject.SiteV2{SiteID: id, Revision: 1, Plaintext: []byte(`{"site":"` + id + `"}`)})
	}
	publication, _, err := siteobject.BuildV2(input)
	if err != nil {
		t.Fatal(err)
	}
	release := &siteObjectTestRelease{artifacts: map[string][]byte{}, objects: map[string][]byte{}, kinds: map[string]siteobject.ObjectKind{}}
	for _, object := range publication.Objects {
		digest, wire, err := siteobject.Seal(contentKey, scopeID, object.Plaintext)
		if err != nil {
			t.Fatal(err)
		}
		release.objects[digest], release.kinds[digest] = wire, object.Kind
	}
	rootDigest := sha256.Sum256(publication.RootBytes)
	root := &agentv1.ArtifactDescriptor{
		ArtifactId: uuid.NewString(), Kind: agentv1.ArtifactKind_ARTIFACT_KIND_CONFIGURATION, MediaType: siteobject.RootMediaTypeV2,
		SizeBytes: uint64(len(publication.RootBytes)), Sha256: rootDigest[:], Signature: ed25519.Sign(signingKey, publication.RootBytes),
		SigningKeyId: "test-signing-key", SignatureAlgorithm: agentv1.ArtifactSignatureAlgorithm_ARTIFACT_SIGNATURE_ALGORITHM_ED25519,
		Compression:         agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_NONE,
		EncryptionAlgorithm: agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_NONE,
	}
	key := proto.Clone(root).(*agentv1.ArtifactDescriptor)
	key.ArtifactId, key.MediaType = uuid.NewString(), siteobject.KeyMediaType
	command := &agentv1.DeploymentCommand{
		Event: &commonv1.EventMetadata{
			EventId: uuid.NewString(), RequestId: uuid.NewString(), OccurredTime: timestamppb.Now(), CorrelationId: uuid.NewString(),
		},
		DeploymentId: uuid.NewString(), Attempt: 1, RolloutId: uuid.NewString(), ConfigVersionId: configID,
		ConfigurationScopeId: proto.String(scopeID),
		Action:               agentv1.DeploymentAction_DEPLOYMENT_ACTION_APPLY,
		Artifacts:            []*agentv1.ArtifactDescriptor{root, key},
		RequiredCapabilities: []*agentv1.Capability{
			{Name: agentv1.CapabilityName_CAPABILITY_NAME_HTTP_1_1, ApiVersion: 1},
			{Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME, ApiVersion: edgeconfig.DynamicRoutingSiteRuntimeVersion},
		},
		HealthCheck: &agentv1.HealthCheckPolicy{
			ActivationTimeoutDuration: durationpb.New(time.Second), ObservationWindowDuration: durationpb.New(time.Second), RequiredConsecutiveSuccesses: 1,
		},
		DeadlineTime: timestamppb.New(time.Now().Add(time.Hour)),
	}
	release.artifacts[root.ArtifactId] = publication.RootBytes
	keyPlaintext, err := siteobject.Encode(siteobject.KeyDocument{Schema: siteobject.KeySchema, ConfigurationScopeID: scopeID,
		ConfigVersionID: configID, RootSHA256: publication.RootSHA256, KeyEpoch: 1, ContentKey: contentKey,
		NodeRegion: "region-7"})
	if err != nil {
		t.Fatal(err)
	}
	release.artifacts[key.ArtifactId] = encryptTestArtifact(t, command, key, keyPlaintext, recipientKey, recipientID, signingKey)
	release.command = command
	return release
}

func newDynamicRoutingHarness(t *testing.T, applier *fakeDynamicRouting) *siteObjectHarness {
	t.Helper()
	h := newSiteObjectHarness(t)
	closeGatewayClientForRestart(t, h.client)
	config := h.client.config
	config.Capabilities = proto.Clone(config.Capabilities).(*agentv1.AgentCapabilities)
	for _, capability := range config.Capabilities.Features {
		if capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME {
			capability.ApiVersion = edgeconfig.DynamicRoutingSiteRuntimeVersion
		}
	}
	store, err := objectstore.Open(filepath.Join(h.root, "dynamic-objects"))
	if err != nil {
		t.Fatal(err)
	}
	options := []ClientOption{WithSiteObjectStore(store)}
	if applier != nil {
		applier.DeploymentManager = h.manager
		options = append(options, WithDynamicRouting(applier))
	}
	client, err := New(config, &failingDialer{}, h.manager, h.client.trust, options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	h.client, h.store = client, store
	return h
}

func TestDynamicRoutingDeliveryHandsObjectsToTheApplier(t *testing.T) {
	applier := &fakeDynamicRouting{}
	h := newDynamicRoutingHarness(t, applier)
	referenced := []byte(`{"cc":1}`)
	release := h.dynamicRoutingRelease(t, 3, referenced)
	gateway := &siteObjectGateway{release: release}
	status := executeSiteObjectRelease(t, h.client, newSiteObjectGatewayClient(t, gateway), release.command)
	if status.State != agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY {
		t.Fatalf("state %v: %v", status.State, status.Error)
	}
	if len(applier.applied) != 1 {
		t.Fatalf("%d applies", len(applier.applied))
	}
	got := applier.applied[0]
	if len(got.Sites) != 3 || string(got.Referenced[siteobject.Digest(referenced)]) != string(referenced) ||
		string(got.ScopeFiles["security/modsecurity/crs/a.conf"]) != "SecRule" || got.RootSHA256 == "" ||
		got.NodeRegion != "region-7" { // fz-x12: the key document's region code
		t.Fatalf("release %+v", got)
	}
	current, err := h.store.Current(siteObjectOwner(release.command.GetConfigurationScopeId()))
	if err != nil || len(current) != len(release.objects) {
		t.Fatalf("committed %d of %d objects: %v", len(current), len(release.objects), err)
	}
}

func TestDynamicRoutingFailureAndMissingApplier(t *testing.T) {
	applier := &fakeDynamicRouting{fail: errors.New("generation unhealthy")}
	h := newDynamicRoutingHarness(t, applier)
	release := h.dynamicRoutingRelease(t, 1, []byte(`{"cc":1}`))
	status := executeSiteObjectRelease(t, h.client, newSiteObjectGatewayClient(t, &siteObjectGateway{release: release}), release.command)
	if status.State != agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED || !status.RunningConfigUnchanged {
		t.Fatalf("state %v unchanged %v", status.State, status.RunningConfigUnchanged)
	}
	if current, _ := h.store.Current(siteObjectOwner(release.command.GetConfigurationScopeId())); len(current) != 0 {
		t.Fatal("a failed release was committed")
	}

	h = newDynamicRoutingHarness(t, nil)
	release = h.dynamicRoutingRelease(t, 1, []byte(`{"cc":1}`))
	status = executeSiteObjectRelease(t, h.client, newSiteObjectGatewayClient(t, &siteObjectGateway{release: release}), release.command)
	if status.State != agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED {
		t.Fatalf("a node without dynamic routing applied a v2 root: %v", status.State)
	}
}
