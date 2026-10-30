//go:build integration

package edgepublish

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
)

// SiteObjectReleaseForTest is what a node receives from one dynamic routing
// deployment (integration tests only; not built into the service). Bundle
// carries only the release's v2 document (DocumentPath): a v2 root names the
// document by digest and splits the rest into site objects.
type SiteObjectReleaseForTest struct {
	Command    *agentv1.DeploymentCommand
	Root       siteobject.RootV2
	RootSHA256 string
	Bundle     edgeconfig.Bundle
	// Members are the publication's object digests (what the node may fetch).
	Members map[string]bool
	// Scope, Sites (decoded, bucket order) and Objects (every loaded object
	// by digest: scope files, sites and the objects they reference) are what
	// the node serves the release from.
	Scope   siteobject.ScopeV2
	Sites   []edgesite.Site
	Objects map[string][]byte
	// L4WithheldStreams: the scope's forwards this node's key document
	// withholds (L4_STREAM_SELECTION).
	L4WithheldStreams []string
	// NodeRegion: the region code this node's key document carries
	// (NODE_REGION, fz-x12).
	NodeRegion string
	// NodeStorage: the storage settings this node's key document carries
	// (NODE_STORAGE, fix-nodesettings).
	NodeStorage *siteobject.NodeStorage
}

// OpenSiteObjectReleaseForTest does what a node does with deploymentID's
// command: it verifies the signed v2 root, opens its own key envelope with
// privateKey, loads every object the root references (scope, buckets, sites
// and their files) from the control store and opens each with the content
// key.
func OpenSiteObjectReleaseForTest(ctx context.Context, pool *pgxpool.Pool, deploymentID uuid.UUID,
	privateKey []byte) (SiteObjectReleaseForTest, error) {
	var nodeID, eventID, configID, scopeID uuid.UUID
	var commandBytes []byte
	if err := pool.QueryRow(ctx, `SELECT deployment.node_id,deployment.command_event_id,deployment.config_version_id,
		deployment.command_bytes,version.configuration_scope_id
		FROM node_deployments deployment JOIN config_versions version ON version.id=deployment.config_version_id
		WHERE deployment.id=$1`, deploymentID).Scan(&nodeID, &eventID, &configID, &commandBytes, &scopeID); err != nil {
		return SiteObjectReleaseForTest{}, fmt.Errorf("deployment: %w", err)
	}
	command := new(agentv1.DeploymentCommand)
	if err := proto.Unmarshal(commandBytes, command); err != nil {
		return SiteObjectReleaseForTest{}, err
	}
	if len(command.Artifacts) != 2 || command.Artifacts[0].MediaType != siteobject.RootMediaTypeV2 ||
		command.Artifacts[1].MediaType != siteobject.KeyMediaType {
		return SiteObjectReleaseForTest{}, fmt.Errorf("command artifacts are not [root, key]: %v", command.Artifacts)
	}
	load := func(descriptor *agentv1.ArtifactDescriptor) (edgedeployment.ArtifactInput, error) {
		artifactID, err := uuid.Parse(descriptor.ArtifactId)
		if err != nil {
			return edgedeployment.ArtifactInput{}, err
		}
		var wire, publicKey []byte
		if err := pool.QueryRow(ctx, `SELECT artifact.wire_bytes,key.public_key
			FROM node_deployment_artifacts binding
			JOIN configuration_artifacts artifact ON artifact.id=binding.artifact_id AND artifact.config_version_id=binding.config_version_id
			JOIN artifact_signing_keys key ON key.id=artifact.signing_key_id
			WHERE binding.deployment_id=$1 AND binding.artifact_id=$2`, deploymentID, artifactID).Scan(&wire, &publicKey); err != nil {
			return edgedeployment.ArtifactInput{}, fmt.Errorf("artifact %s is not bound to the deployment: %w", artifactID, err)
		}
		if !ed25519.Verify(publicKey, wire, descriptor.Signature) {
			return edgedeployment.ArtifactInput{}, fmt.Errorf("artifact %s signature", artifactID)
		}
		return edgedeployment.ArtifactInput{
			ID: artifactID, Kind: descriptor.Kind, WireBytes: wire, SizeBytes: descriptor.SizeBytes,
			SHA256: descriptor.Sha256, Signature: descriptor.Signature, SigningKeyID: descriptor.SigningKeyId,
			SigningPublicKey: publicKey, SignatureAlgorithm: descriptor.SignatureAlgorithm,
			Compression: descriptor.Compression, MediaType: descriptor.MediaType,
			EncryptionAlgorithm: descriptor.EncryptionAlgorithm, RecipientKeyID: descriptor.RecipientKeyId,
		}, nil
	}
	rootArtifact, err := load(command.Artifacts[0])
	if err != nil {
		return SiteObjectReleaseForTest{}, err
	}
	keyArtifact, err := load(command.Artifacts[1])
	if err != nil {
		return SiteObjectReleaseForTest{}, err
	}
	root, err := siteobject.ParseRootV2(rootArtifact.WireBytes)
	if err != nil {
		return SiteObjectReleaseForTest{}, err
	}
	keyPlaintext, err := OpenConfigurationArtifactForTest(privateKey, edgedeployment.NodeArtifactBinding{
		NodeID: nodeID, DeploymentID: deploymentID, EventID: eventID, Attempt: 1, ConfigVersionID: configID,
		ArtifactID: keyArtifact.ID, RecipientKeyID: command.Artifacts[1].GetRecipientKeyId(),
	}, keyArtifact)
	if err != nil {
		return SiteObjectReleaseForTest{}, fmt.Errorf("open key envelope: %w", err)
	}
	key, err := siteobject.ParseKeyDocument(keyPlaintext)
	rootSHA256 := siteobject.Digest(rootArtifact.WireBytes)
	if err != nil || key.RootSHA256 != rootSHA256 || key.ConfigVersionID != configID.String() ||
		key.ConfigurationScopeID != scopeID.String() || key.KeyEpoch != root.KeyEpoch {
		return SiteObjectReleaseForTest{}, fmt.Errorf("key document %+v does not match root %s: %v", key, rootSHA256, err)
	}
	var members []byte
	var publishedRoot []byte
	if err := pool.QueryRow(ctx, `SELECT member_sha256,root_sha256 FROM edge_site_object_publications
		WHERE config_version_id=$1`, configID).Scan(&members, &publishedRoot); err != nil {
		return SiteObjectReleaseForTest{}, fmt.Errorf("publication: %w", err)
	}
	if hex.EncodeToString(publishedRoot) != rootSHA256 {
		return SiteObjectReleaseForTest{}, fmt.Errorf("publication root differs from the command root")
	}
	memberSet := make(map[string]bool, len(members)/32)
	for offset := 0; offset+32 <= len(members); offset += 32 {
		memberSet[hex.EncodeToString(members[offset:offset+32])] = true
	}
	loadObject := func(digest string) ([]byte, error) {
		if !memberSet[digest] {
			return nil, fmt.Errorf("%w: %s is not a publication member", siteobject.ErrMissing, digest)
		}
		raw, _ := hex.DecodeString(digest)
		var wire []byte
		if err := pool.QueryRow(ctx, `SELECT ciphertext FROM edge_site_objects
			WHERE configuration_scope_id=$1 AND key_epoch=$2 AND sha256=$3`, scopeID, key.KeyEpoch, raw).Scan(&wire); err != nil {
			return nil, fmt.Errorf("%w: %s: %v", siteobject.ErrMissing, digest, err)
		}
		return siteobject.Open(key.ContentKey, scopeID.String(), digest, wire)
	}
	scopeBytes, err := loadObject(root.ScopeSHA256)
	if err != nil {
		return SiteObjectReleaseForTest{}, err
	}
	scope, err := siteobject.ParseScopeV2(scopeBytes)
	if err != nil {
		return SiteObjectReleaseForTest{}, err
	}
	objects := map[string][]byte{root.ScopeSHA256: scopeBytes}
	var sites []edgesite.Site
	referenced := append(siteobject.FileDigests(scope.Files), scope.Objects...)
	for _, bucketDigest := range root.Buckets {
		raw, err := loadObject(bucketDigest)
		if err != nil {
			return SiteObjectReleaseForTest{}, err
		}
		bucket, err := siteobject.ParseBucketV2(raw)
		if err != nil {
			return SiteObjectReleaseForTest{}, err
		}
		for _, digest := range bucket.SiteDigests() {
			plaintext, err := loadObject(digest)
			if err != nil {
				return SiteObjectReleaseForTest{}, err
			}
			site, err := edgesite.Decode(plaintext)
			if err != nil {
				return SiteObjectReleaseForTest{}, fmt.Errorf("site object %s: %w", digest, err)
			}
			objects[digest], sites = plaintext, append(sites, site)
		}
	}
	for _, digest := range referenced {
		plaintext, err := loadObject(digest)
		if err != nil {
			return SiteObjectReleaseForTest{}, err
		}
		objects[digest] = plaintext
	}
	var canonical []byte
	if err := pool.QueryRow(ctx, `SELECT canonical_snapshot FROM config_versions WHERE id=$1`, configID).Scan(&canonical); err != nil {
		return SiteObjectReleaseForTest{}, err
	}
	if siteobject.Digest(canonical) != root.DocumentSHA256 {
		return SiteObjectReleaseForTest{}, fmt.Errorf("root does not name the published document")
	}
	bundle := edgeconfig.Bundle{Files: map[string][]byte{siteobject.DocumentPath: bytes.Clone(canonical)}}
	return SiteObjectReleaseForTest{Command: command, Root: root, RootSHA256: rootSHA256, Bundle: bundle, Members: memberSet,
		Scope: scope, Sites: sites, Objects: objects, L4WithheldStreams: key.L4WithheldStreams, NodeRegion: key.NodeRegion,
		NodeStorage: key.NodeStorage}, nil
}
