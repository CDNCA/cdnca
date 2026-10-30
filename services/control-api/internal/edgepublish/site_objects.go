package edgepublish

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Site object delivery (ADR 0009 §8.3, libs/edgeconfig/siteobject): every
// v2 release is converted into content-addressed v2 site objects, each sealed once
// with the scope's content key and stored once (edge_site_objects, migration
// 354); the release is one signed plaintext root shared by every target node
// plus one HPKE key envelope per node. Only objects not stored yet are sealed
// and inserted, so an unchanged site costs nothing on the next publication.

const (
	// siteObjectKeyEpoch: 1.0.35 does not rotate content keys.
	siteObjectKeyEpoch = int64(1)
	// siteObjectLookupBatch bounds one "which digests exist" query.
	siteObjectLookupBatch = 8192
)

// siteObjectRelease is a built site object release before its config version exists.
type siteObjectRelease struct {
	scopeID, configID uuid.UUID
	rootSHA256        [sha256.Size]byte
	members           []byte
	root              edgedeployment.ArtifactInput
	bindings          []edgedeployment.NodeArtifactBinding
	// artifacts is [root, one key envelope per binding], in binding order.
	artifacts []edgedeployment.ArtifactInput
	// stored counts objects sealed and inserted by this release.
	stored int
}

// buildSiteObjectRelease stores bundle's new objects and builds the root and
// one key envelope per recipient, bound to fresh deployment and event IDs.
func (s *Service) buildSiteObjectRelease(
	ctx context.Context,
	tx pgx.Tx,
	scopeID, configID uuid.UUID,
	bundle edgeconfig.Bundle,
	recipients []configurationArtifactRecipientBinding,
	capabilities []*agentv1.Capability,
	now time.Time,
) (*siteObjectRelease, error) {
	if err := releaseRequiresDynamicRouting(capabilities); err != nil {
		return nil, err
	}
	if len(recipients) == 0 || scopeID == uuid.Nil || configID == uuid.Nil {
		return nil, ErrInvalidInput
	}
	contentKey, err := ensureSiteObjectContentKey(ctx, tx, scopeID, now, rand.Reader)
	if err != nil {
		return nil, err
	}
	defer clear(contentKey)
	// cdnca.edge.site/v2 objects under a v2 root, built from the release.
	source, err := siteObjectsV2SourceFromBundle(bundle)
	if err != nil {
		return nil, err
	}
	if source.ScopeID != scopeID.String() || source.ConfigVersionID != configID.String() {
		return nil, fmt.Errorf("%w: site object root identity", ErrInvalidInput)
	}
	publication, packs, err := s.dynamicRoutingPublication(ctx, tx, scopeID, source)
	if err != nil {
		return nil, err
	}
	nodeIDs := make([]uuid.UUID, len(recipients))
	for index, recipient := range recipients {
		nodeIDs[index] = recipient.NodeID
	}
	advertised, err := loadSiteRuntimeV2TargetCapabilities(ctx, tx, scopeID, nodeIDs, now)
	if err != nil {
		return nil, err
	}
	if err := validateRulePackCapabilityTargets(ctx, tx, nodeIDs, packs, advertised); err != nil {
		return nil, err
	}
	if err := validateRulePackTargets(ctx, tx, nodeIDs, packs); err != nil {
		return nil, err
	}
	trafficStopped, err := loadTrafficStoppedStreams(ctx, tx, scopeID)
	if err != nil {
		return nil, err
	}
	streamNodes, err := streamServingNodes(ctx, tx, scopeID, source.Streams)
	if err != nil {
		return nil, err
	}
	regionCodes, err := loadNodeRegionCodes(ctx, tx, nodeIDs)
	if err != nil {
		return nil, err
	}
	nodeStorage, err := loadNodeStorage(ctx, tx, nodeIDs)
	if err != nil {
		return nil, err
	}
	stored, err := storeSiteObjects(ctx, tx, scopeID, contentKey, publication.Objects, now)
	if err != nil {
		return nil, err
	}
	release := &siteObjectRelease{scopeID: scopeID, configID: configID, stored: stored}
	release.rootSHA256 = sha256.Sum256(publication.RootBytes)
	if hex.EncodeToString(release.rootSHA256[:]) != publication.RootSHA256 {
		return nil, fmt.Errorf("%w: site object root digest", ErrInvalidInput)
	}
	if release.members, err = siteObjectMembers(publication.Objects); err != nil {
		return nil, err
	}
	if release.root, err = s.signSiteObjectRoot(ctx, configID, publication.RootBytes, siteobject.RootMediaTypeV2); err != nil {
		return nil, err
	}
	producer, err := newConfigurationArtifactProducer(s.signer, rand.Reader)
	if err != nil {
		return nil, err
	}
	release.bindings = make([]edgedeployment.NodeArtifactBinding, len(recipients))
	release.artifacts = make([]edgedeployment.ArtifactInput, 0, len(recipients)+1)
	release.artifacts = append(release.artifacts, release.root)
	for index, recipient := range recipients {
		binding := edgedeployment.NodeArtifactBinding{
			NodeID: recipient.NodeID, DeploymentID: uuid.New(), EventID: uuid.New(), Attempt: 1,
			ConfigVersionID: configID, ArtifactID: uuid.New(), RecipientKeyID: recipient.KeyID,
		}
		plaintext, err := siteobject.Encode(siteobject.KeyDocument{
			Schema: siteobject.KeySchema, ConfigurationScopeID: scopeID.String(), ConfigVersionID: configID.String(),
			RootSHA256: publication.RootSHA256, KeyEpoch: siteObjectKeyEpoch, ContentKey: contentKey,
			TrafficStopStreams: trafficStopFor(advertised[recipient.NodeID], trafficStopped),
			L4WithheldStreams:  withheldStreamsFor(advertised[recipient.NodeID], recipient.NodeID, source.Streams, streamNodes),
			NodeRegion:         nodeRegionFor(advertised[recipient.NodeID], regionCodes[recipient.NodeID]),
			NodeStorage: func() *siteobject.NodeStorage {
				storage, set := nodeStorage[recipient.NodeID]
				return nodeStorageFor(advertised[recipient.NodeID], storage, set)
			}(),
		})
		if err != nil {
			return nil, ErrInvalidInput
		}
		envelope, buildErr := producer.Build(ctx, binding, recipient.PublicKey, plaintext, siteobject.KeyMediaType)
		clear(plaintext)
		if buildErr != nil {
			return nil, buildErr
		}
		release.bindings[index] = binding
		release.artifacts = append(release.artifacts, envelope)
	}
	return release, nil
}

// artifactSetDigest identifies the release's artifact set: the root digest
// followed by the key envelope set's (configurationArtifactSetDigest).
func (release *siteObjectRelease) artifactSetDigest() ([sha256.Size]byte, error) {
	envelopes, err := configurationArtifactSetDigest(release.bindings, release.artifacts[1:])
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(append(append([]byte("cdnca-edge-site-object-release-v1\x00"), release.rootSHA256[:]...), envelopes[:]...)), nil
}

// persist records the publication once its config version exists.
func (release *siteObjectRelease) persist(ctx context.Context, tx pgx.Tx, now time.Time) error {
	if _, err := tx.Exec(ctx, `INSERT INTO edge_site_object_publications(
		config_version_id,configuration_scope_id,key_epoch,root_sha256,member_sha256,created_at)
		VALUES($1,$2,$3,$4,$5,$6)`, release.configID, release.scopeID, siteObjectKeyEpoch,
		release.rootSHA256[:], release.members, now); err != nil {
		return fmt.Errorf("%w: persist site object publication", ErrPersistence)
	}
	return nil
}

func (s *Service) signSiteObjectRoot(ctx context.Context, configID uuid.UUID, root []byte, mediaType string) (edgedeployment.ArtifactInput, error) {
	if len(root) == 0 || len(root) > siteobject.MaxRootBytes {
		return edgedeployment.ArtifactInput{}, ErrInvalidInput
	}
	publicKey := slices.Clone(s.signer.PublicKey())
	signature, err := s.signer.Sign(ctx, bytes.Clone(root))
	if err != nil || len(publicKey) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize ||
		!ed25519.Verify(publicKey, root, signature) {
		return edgedeployment.ArtifactInput{}, ErrSigningFailed
	}
	digest := sha256.Sum256(root)
	return edgedeployment.ArtifactInput{
		ID: uuid.NewSHA1(configID, []byte("site-object-root")), Kind: agentv1.ArtifactKind_ARTIFACT_KIND_CONFIGURATION,
		WireBytes: bytes.Clone(root), SizeBytes: uint64(len(root)), SHA256: digest[:], Signature: signature,
		SigningKeyID: s.signer.KeyID(), SigningPublicKey: publicKey,
		SignatureAlgorithm:  agentv1.ArtifactSignatureAlgorithm_ARTIFACT_SIGNATURE_ALGORITHM_ED25519,
		Compression:         agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_NONE,
		MediaType:           mediaType,
		EncryptionAlgorithm: agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_NONE,
	}, nil
}

// ensureSiteObjectContentKey returns the scope's epoch-1 content key,
// creating it on first use. The caller holds the scope's publication lock.
func ensureSiteObjectContentKey(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, now time.Time, random io.Reader) ([]byte, error) {
	var key []byte
	err := tx.QueryRow(ctx, `SELECT content_key FROM edge_site_object_keys
		WHERE configuration_scope_id=$1 AND key_epoch=$2`, scopeID, siteObjectKeyEpoch).Scan(&key)
	if err == nil {
		if len(key) != siteobject.ContentKeySize {
			return nil, fmt.Errorf("%w: site object content key", ErrPersistence)
		}
		return key, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: read site object content key", ErrPersistence)
	}
	key = make([]byte, siteobject.ContentKeySize)
	if _, err := io.ReadFull(random, key); err != nil {
		return nil, ErrSigningFailed
	}
	if _, err := tx.Exec(ctx, `INSERT INTO edge_site_object_keys(configuration_scope_id,key_epoch,content_key,created_at)
		VALUES($1,$2,$3,$4)`, scopeID, siteObjectKeyEpoch, key, now); err != nil {
		return nil, fmt.Errorf("%w: create site object content key", ErrPersistence)
	}
	return key, nil
}

// storeSiteObjects seals and inserts the objects the scope does not store
// yet (one query per siteObjectLookupBatch digests, one COPY for the rest)
// and returns how many it inserted.
func storeSiteObjects(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, contentKey []byte,
	objects []siteobject.Object, now time.Time) (int, error) {
	existing := make(map[[sha256.Size]byte]struct{}, len(objects))
	for start := 0; start < len(objects); start += siteObjectLookupBatch {
		batch := objects[start:min(start+siteObjectLookupBatch, len(objects))]
		digests := make([][]byte, len(batch))
		for index, object := range batch {
			digest, err := hex.DecodeString(object.SHA256)
			if err != nil || len(digest) != sha256.Size {
				return 0, ErrInvalidInput
			}
			digests[index] = digest
		}
		rows, err := tx.Query(ctx, `SELECT sha256 FROM edge_site_objects
			WHERE configuration_scope_id=$1 AND key_epoch=$2 AND sha256=ANY($3::bytea[])`,
			scopeID, siteObjectKeyEpoch, digests)
		if err != nil {
			return 0, fmt.Errorf("%w: read stored site objects", ErrPersistence)
		}
		for rows.Next() {
			var digest []byte
			if err := rows.Scan(&digest); err != nil || len(digest) != sha256.Size {
				rows.Close()
				return 0, fmt.Errorf("%w: scan stored site objects", ErrPersistence)
			}
			existing[[sha256.Size]byte(digest)] = struct{}{}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return 0, fmt.Errorf("%w: iterate stored site objects", ErrPersistence)
		}
	}
	var missing [][]any
	for _, object := range objects {
		digest, _ := hex.DecodeString(object.SHA256)
		if _, stored := existing[[sha256.Size]byte(digest)]; stored {
			continue
		}
		sealedDigest, wire, err := siteobject.Seal(contentKey, scopeID.String(), object.Plaintext)
		if err != nil || sealedDigest != object.SHA256 {
			return 0, fmt.Errorf("%w: seal site object", ErrInvalidInput)
		}
		missing = append(missing, []any{scopeID, siteObjectKeyEpoch, digest, string(object.Kind), wire, now})
	}
	if len(missing) == 0 {
		return 0, nil
	}
	copied, err := tx.CopyFrom(ctx, pgx.Identifier{"edge_site_objects"},
		[]string{"configuration_scope_id", "key_epoch", "sha256", "kind", "ciphertext", "created_at"},
		pgx.CopyFromRows(missing))
	if err != nil || copied != int64(len(missing)) {
		return 0, fmt.Errorf("%w: store site objects", ErrPersistence)
	}
	return len(missing), nil
}

// siteObjectMembers is the ascending concatenation of the release's object
// digests (edge_site_object_publications.member_sha256).
func siteObjectMembers(objects []siteobject.Object) ([]byte, error) {
	digests := make([][]byte, len(objects))
	for index, object := range objects {
		digest, err := hex.DecodeString(object.SHA256)
		if err != nil || len(digest) != sha256.Size {
			return nil, ErrInvalidInput
		}
		digests[index] = digest
	}
	sort.Slice(digests, func(i, j int) bool { return bytes.Compare(digests[i], digests[j]) < 0 })
	members := make([]byte, 0, len(digests)*sha256.Size)
	for index, digest := range digests {
		if index > 0 && bytes.Equal(digests[index-1], digest) {
			return nil, ErrInvalidInput
		}
		members = append(members, digest...)
	}
	if len(members) < 2*sha256.Size {
		return nil, ErrInvalidInput
	}
	return members, nil
}

// dynamicRoutingDeliveryCapabilities: a v2 root release requires the
// document's capabilities with site_runtime 9.
func dynamicRoutingDeliveryCapabilities(document []*agentv1.Capability) ([]*agentv1.Capability, error) {
	delivery, err := edgedeployment.DynamicRoutingDeliveryCapabilities(document)
	if err != nil {
		return nil, ErrInvalidInput
	}
	return delivery, nil
}

// releaseRequiresDynamicRouting: the release names site_runtime 9.
func releaseRequiresDynamicRouting(capabilities []*agentv1.Capability) error {
	for _, capability := range capabilities {
		if capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME &&
			capability.GetApiVersion() == edgeconfig.DynamicRoutingSiteRuntimeVersion {
			return nil
		}
	}
	return fmt.Errorf("%w: site object release site_runtime", ErrInvalidInput)
}
