package gatewayclient

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/objectstore"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Site object delivery (site_runtime 9, ADR 0009 section 8.3): a deployment
// carries a signed v2 root (one artifact for every node) and this node's HPKE
// key envelope. The node fetches only the objects its object store lacks and
// hands the release to dynamic routing (dynamic_routing.go); any failure
// leaves the running release untouched.

// maxSiteObjectsPerRequest bounds one FetchSiteObjects request.
const maxSiteObjectsPerRequest = 256

// siteObjectWireOverhead is the AES-256-GCM tag on each object.
const siteObjectWireOverhead = 16

// WithSiteObjectStore enables site_runtime 9 deployments with the agent's
// object store.
func WithSiteObjectStore(store *objectstore.Store) ClientOption {
	return func(client *Client) error {
		if store == nil {
			return fmt.Errorf("%w: site object store is required", ErrInvalidConfiguration)
		}
		client.siteObjects = store
		return nil
	}
}

// SiteObjectFetchStats is what the last site object deployment transferred.
type SiteObjectFetchStats struct {
	Referenced   int
	Fetched      int
	FetchedBytes int64
	Requests     int
	// Duration covers the root, key and object fetches and the assembly.
	Duration time.Duration
}

func isSiteObjectCommand(command *agentv1.DeploymentCommand) bool {
	return command != nil && (command.Action == agentv1.DeploymentAction_DEPLOYMENT_ACTION_APPLY ||
		command.Action == agentv1.DeploymentAction_DEPLOYMENT_ACTION_RECONCILE) && len(command.Artifacts) == 2 &&
		command.Artifacts[0] != nil && command.Artifacts[0].Kind == agentv1.ArtifactKind_ARTIFACT_KIND_CONFIGURATION &&
		command.Artifacts[0].MediaType == siteobject.RootMediaTypeV2 &&
		command.Artifacts[1] != nil && command.Artifacts[1].Kind == agentv1.ArtifactKind_ARTIFACT_KIND_CONFIGURATION &&
		command.Artifacts[1].MediaType == siteobject.KeyMediaType
}

func validateSiteObjectCommand(command *agentv1.DeploymentCommand, config Config, now time.Time) error {
	root, key := command.Artifacts[0], command.Artifacts[1]
	if !canonicalUUID(command.ConfigVersionId) || !canonicalUUID(command.GetConfigurationScopeId()) {
		return fmt.Errorf("%w: site object command identity is invalid", ErrInvalidMessage)
	}
	if !canonicalUUID(root.ArtifactId) || root.ArtifactId == key.ArtifactId ||
		root.EncryptionAlgorithm != agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_NONE ||
		root.RecipientKeyId != nil || root.Compression != agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_NONE ||
		root.SignatureAlgorithm != agentv1.ArtifactSignatureAlgorithm_ARTIFACT_SIGNATURE_ALGORITHM_ED25519 ||
		len(root.Signature) != ed25519.SignatureSize || !safeIdentifier(root.SigningKeyId) ||
		root.SizeBytes == 0 || root.SizeBytes > siteobject.MaxRootBytes || len(root.Sha256) != sha256.Size {
		return fmt.Errorf("%w: site object root artifact is invalid", ErrInvalidMessage)
	}
	if key.EncryptionAlgorithm != agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_HPKE_X25519_HKDF_SHA256_AES_256_GCM ||
		key.Compression != agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_NONE || key.SizeBytes > 4096 {
		return fmt.Errorf("%w: site object key artifact is invalid", ErrInvalidMessage)
	}
	// The key envelope carries the generic checks: integrity metadata, HPKE
	// recipient, health policy, deadline and the local capabilities.
	validationCopy := proto.Clone(command).(*agentv1.DeploymentCommand)
	validationCopy.Artifacts = validationCopy.Artifacts[1:]
	validationCopy.Artifacts[0].MediaType = ConfigurationBundleMediaType
	if err := validateCommand(validationCopy, config, now); err != nil {
		return err
	}
	want := edgeconfig.DynamicRoutingSiteRuntimeVersion
	for _, capability := range command.RequiredCapabilities {
		if capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME && capability.ApiVersion == want {
			return nil
		}
	}
	return fmt.Errorf("%w: site object delivery requires site runtime %d", ErrUnsupportedCommand, want)
}

func (c *Client) executeSiteObjectRecord(ctx context.Context, gateway agentv1.AgentGatewayServiceClient, record *durableRecord, command *agentv1.DeploymentCommand, maximumChunkBytes uint32, activeIdentityEnabled bool) error {
	fail := func(err error) error {
		status := failedStatus(command, 2, c.now(), classifyError(err), err.Error(), false)
		return c.completeDeploymentRecord(record.RecordKey, []*agentv1.DeploymentStatus{status}, activeIdentityEnabled)
	}
	if c.siteObjects == nil {
		return fail(fmt.Errorf("%w: site object store is not configured", ErrUnsupportedCommand))
	}
	if record.ArtifactOffset > command.Artifacts[0].SizeBytes {
		return fail(fmt.Errorf("%w: durable artifact offset exceeds descriptor size", ErrArtifactIntegrity))
	}
	if !isDynamicRoutingCommand(command) {
		return fail(fmt.Errorf("%w: site object root media type is not supported", ErrUnsupportedCommand))
	}
	return c.executeDynamicRoutingRecord(ctx, gateway, record, command, maximumChunkBytes, activeIdentityEnabled)
}

func siteObjectOwner(scopeID string) string { return "site-" + scopeID }

func (c *Client) recordSiteObjectStats(stats SiteObjectFetchStats) {
	c.siteObjectStatsMu.Lock()
	c.siteObjectStats = stats
	c.siteObjectStatsMu.Unlock()
}

// LastSiteObjectFetch reports what the last assembled site object release
// referenced and transferred.
func (c *Client) LastSiteObjectFetch() SiteObjectFetchStats {
	c.siteObjectStatsMu.Lock()
	defer c.siteObjectStatsMu.Unlock()
	return c.siteObjectStats
}

// sameSiteObjectCapabilities requires the command to carry exactly the
// root's capabilities (both name site_runtime 9).
func sameSiteObjectCapabilities(root []siteobject.Capability, command []*agentv1.Capability) error {
	if len(root) != len(command) {
		return fmt.Errorf("%w: site object capability set differs from command", ErrArtifactIntegrity)
	}
	commandVersions := make(map[string]uint32, len(command))
	for _, capability := range command {
		name, known := siteRuntimeCapabilityName(capability.Name)
		if !known {
			return fmt.Errorf("%w: site object command capability is unknown", ErrArtifactIntegrity)
		}
		commandVersions[name] = capability.ApiVersion
	}
	for _, capability := range root {
		if version, present := commandVersions[capability.Name]; !present || version != capability.APIVersion {
			return fmt.Errorf("%w: site object capability version differs from command", ErrArtifactIntegrity)
		}
	}
	return nil
}

type siteObjectFetcher struct {
	client            *Client
	gateway           agentv1.AgentGatewayServiceClient
	command           *agentv1.DeploymentCommand
	rootSHA256        string
	scopeID           string
	contentKey        []byte
	maximumChunkBytes uint32

	plaintext  map[string][]byte
	referenced []string
	releases   []func()
	stats      SiteObjectFetchStats
}

func (f *siteObjectFetcher) unstage() {
	for _, release := range f.releases {
		release()
	}
	f.releases = nil
}

// ensure makes every digest available in plaintext: stored objects are read
// (and verified) from the object store, the rest fetched, opened, verified
// and stored. Digests are staged before the store is consulted so a
// concurrent collection cannot remove them.
func (f *siteObjectFetcher) ensure(ctx context.Context, digests []string) error {
	seen := make(map[string]struct{}, len(digests))
	var wanted []string
	for _, digest := range digests {
		_, done := f.plaintext[digest]
		_, duplicate := seen[digest]
		if done || duplicate {
			continue
		}
		seen[digest] = struct{}{}
		wanted = append(wanted, digest)
	}
	if len(wanted) == 0 {
		return nil
	}
	store := f.client.siteObjects
	f.releases = append(f.releases, store.Stage(wanted))
	f.referenced = append(f.referenced, wanted...)
	f.stats.Referenced += len(wanted)
	var missing []string
	for _, digest := range wanted {
		content, err := store.Get(digest)
		switch {
		case err == nil:
			f.plaintext[digest] = content
		case errors.Is(err, objectstore.ErrNotFound) || errors.Is(err, objectstore.ErrDigest):
			missing = append(missing, digest)
		default:
			return err
		}
	}
	for start := 0; start < len(missing); {
		end := min(start+maxSiteObjectsPerRequest, len(missing))
		received, err := f.fetchBatch(ctx, missing[start:end])
		start += received
		if err != nil {
			if received == 0 || errors.Is(err, ErrArtifactIntegrity) || ctx.Err() != nil {
				return err
			}
			// A stream that ended early after progress resumes with the rest.
		}
	}
	return nil
}

// fetchBatch requests digests and stores the objects in order; it returns how
// many complete objects it stored.
func (f *siteObjectFetcher) fetchBatch(ctx context.Context, digests []string) (int, error) {
	requestID := uuid.NewString()
	fetchCtx, cancel := context.WithTimeout(ctx, f.client.config.FetchTimeout)
	defer cancel()
	f.stats.Requests++
	stream, err := f.gateway.FetchSiteObjects(fetchCtx, &agentv1.FetchSiteObjectsRequest{
		Request: &commonv1.RequestMetadata{
			RequestId: requestID, SentTime: timestamppb.New(f.client.now().UTC()), Traceparent: f.command.Event.Traceparent,
			CorrelationId: f.command.Event.CorrelationId, TaskId: f.command.Event.TaskId,
		},
		EventId: f.command.Event.EventId, DeploymentId: f.command.DeploymentId, Attempt: f.command.Attempt,
		RootSha256: f.rootSHA256, Sha256: append([]string(nil), digests...),
	})
	if err != nil {
		return 0, err
	}
	stored := 0
	var wire []byte
	var total uint64
	for {
		response, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			if stored != len(digests) {
				return stored, fmt.Errorf("site object stream ended after %d of %d objects", stored, len(digests))
			}
			return stored, nil
		}
		if err != nil {
			return stored, err
		}
		chunk := response.GetChunk()
		if stored == len(digests) || chunk == nil || chunk.RequestId != requestID || chunk.Sha256 != digests[stored] ||
			chunk.Offset != uint64(len(wire)) || len(chunk.Data) == 0 || uint32(len(chunk.Data)) > f.maximumChunkBytes ||
			chunk.TotalSizeBytes < siteObjectWireOverhead || chunk.TotalSizeBytes > siteobject.MaxObjectBytes+siteObjectWireOverhead ||
			(chunk.Offset != 0 && chunk.TotalSizeBytes != total) ||
			chunk.Offset+uint64(len(chunk.Data)) > chunk.TotalSizeBytes ||
			chunk.EndOfObject != (chunk.Offset+uint64(len(chunk.Data)) == chunk.TotalSizeBytes) {
			return stored, fmt.Errorf("%w: site object chunk metadata is invalid", ErrArtifactIntegrity)
		}
		total = chunk.TotalSizeBytes
		wire = append(wire, chunk.Data...)
		if !chunk.EndOfObject {
			continue
		}
		digest := digests[stored]
		plaintext, err := siteobject.Open(f.contentKey, f.scopeID, digest, wire)
		if err != nil {
			return stored, fmt.Errorf("%w: site object %s: %v", ErrArtifactIntegrity, digest, err)
		}
		if err := f.client.siteObjects.Put(digest, plaintext); err != nil {
			return stored, err
		}
		f.plaintext[digest] = plaintext
		f.stats.Fetched++
		f.stats.FetchedBytes += int64(len(wire))
		stored++
		wire, total = nil, 0
	}
}
