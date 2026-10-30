// Package artifactsetdist delivers node artifact sets (ADR 0007 section 4.3,
// libs/edgeconfig/artifactset) to edge nodes; it replaces the ip-intel-only
// ipinteldist. Both kinds of delivery are platform-scope node-side
// deployments (edgedeployment.CreateNodeArtifactRolloutTx, edgestatus
// node_artifact domain):
//
//   - a segment object: one shared configuration per segment SHA-256
//     (node_artifact_segments), stored by the agent in its object store;
//   - a set: one configuration per node and revision (node_artifact_sets)
//     holding only the signed cdnca.edge.artifact-set/v1, which names items
//     and their segments by digest.
//
// Each sweep announces nodes whose applied set (written by edgestatus from
// the node's receipt) gained an item, so the scopes held for them are
// republished; builds the desired items from the control plane's local
// artifacts (Source, artifactsync: one IP intelligence library — the
// license base ipintel/base or the plugin-built ipintel/local, whichever has
// newer data — and the OWASP CRS engine modules engine_module/*); and, for
// every active node declaring ARTIFACT_SET v1 whose newest set is not its
// desired one (nodeItems: an engine module only for the node's OpenResty
// version and architecture, when it declares WAF_CRS_MODULE) or not
// applied, issues a newer set when its items changed, then delivers the segments the node
// lacks one deployment at a time and the set last. A failed set is retried
// after RetryAfter, segments first: a rejected receipt usually means an
// object is missing or altered on the node, and resending it repairs the
// object store.
//
// Issuing a set, every delivery and every receipt is audited
// (node.artifact_set.*, platform scope, system actor).
package artifactsetdist

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/artifactset"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/artifactsync"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Signer is the edge publication key the agents trust for deployments.
type Signer interface {
	KeyID() string
	PublicKey() ed25519.PublicKey
	Sign(context.Context, []byte) ([]byte, error)
}

// Auditor appends an audit event in the caller's transaction (audit.Log).
type Auditor interface {
	Append(context.Context, pgx.Tx, audit.Event) error
}

type Config struct {
	Pool        *pgxpool.Pool
	Deployments *edgedeployment.Store
	Source      Source
	Signer      Signer
	// Auditor defaults to audit.New(Pool).
	Auditor Auditor
	// SegmentBytes bounds a segment (default and maximum
	// artifactset.MaxSegmentBytes).
	SegmentBytes int
	// Interval between sweeps (default 1m); Wake triggers one early.
	Interval time.Duration
	// WakeChannel, when set, is a PostgreSQL notification channel signalled
	// when a node artifact delivery ends (edgestatus
	// NodeArtifactDeliveryChannel): Run wakes on it, so a node gets its next
	// segment as soon as it took the previous one instead of one per
	// Interval (O2: a new node's 21 segments took 21 minutes). Interval
	// stays the fallback for a missed notification.
	WakeChannel string
	// RetryAfter a failed delivery to one node (default 30m).
	RetryAfter time.Duration
	// BatchSize bounds the deployments created and nodes announced per sweep
	// (default 50).
	BatchSize int
	Now       func() time.Time
	Logger    *slog.Logger
}

type Distributor struct {
	config        Config
	wake          chan struct{}
	platformScope uuid.UUID
	// prepared items by content digest (only the current desired ones)
	cached   map[string]prepared
	segments map[string]uuid.UUID
	// ipIntelChoice is the IP library of the last desired list.
	ipIntelChoice IPIntelChoice
}

const (
	generatorName         = "node-artifact-set"
	generatorVersion      = "1"
	deliveryDeadline      = 2 * time.Hour
	artifactSetAPIVersion = 1
	terminalStates        = `('healthy','failed','reverted','rollback_failed','cancelled')`
	failedStates          = `('failed','reverted','rollback_failed','cancelled')`
)

var nodeArtifactMediaTypes = []string{artifactset.MediaTypeSet, artifactset.MediaTypeSegment}

func New(config Config) (*Distributor, error) {
	if config.Pool == nil || config.Deployments == nil || config.Source == nil || config.Signer == nil ||
		len(config.Signer.PublicKey()) != ed25519.PublicKeySize || config.Signer.KeyID() == "" {
		return nil, errors.New("invalid node artifact set distributor configuration")
	}
	if config.Interval <= 0 {
		config.Interval = time.Minute
	}
	if config.RetryAfter <= 0 {
		config.RetryAfter = 30 * time.Minute
	}
	if config.BatchSize <= 0 {
		config.BatchSize = 50
	}
	if config.SegmentBytes <= 0 || config.SegmentBytes > artifactset.MaxSegmentBytes {
		config.SegmentBytes = artifactset.MaxSegmentBytes
	}
	if config.Auditor == nil {
		config.Auditor = audit.New(config.Pool)
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	return &Distributor{config: config, wake: make(chan struct{}, 1), cached: map[string]prepared{},
		segments: map[string]uuid.UUID{}}, nil
}

// Wake asks for a sweep now (the local artifacts changed:
// artifactsync SyncerConfig.OnChanged).
func (distributor *Distributor) Wake() {
	select {
	case distributor.wake <- struct{}{}:
	default:
	}
}

func (distributor *Distributor) Run(ctx context.Context) error {
	if distributor.config.WakeChannel != "" {
		go distributor.listen(ctx)
	}
	for {
		if err := distributor.SweepOnce(ctx); err != nil && ctx.Err() == nil {
			distributor.config.Logger.Warn("node artifact set sweep failed", "error", err)
		}
		timer := time.NewTimer(distributor.config.Interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-distributor.wake:
			timer.Stop()
		case <-timer.C:
		}
	}
}

// listen wakes the distributor on every WakeChannel notification until ctx
// ends, reconnecting after a lost connection.
func (distributor *Distributor) listen(ctx context.Context) {
	for ctx.Err() == nil {
		conn, err := distributor.config.Pool.Acquire(ctx)
		if err == nil {
			_, err = conn.Exec(ctx, "LISTEN "+pgx.Identifier{distributor.config.WakeChannel}.Sanitize())
			for err == nil {
				if _, err = conn.Conn().WaitForNotification(ctx); err == nil {
					distributor.Wake()
				}
			}
			conn.Release()
		}
		if ctx.Err() != nil {
			return
		}
		distributor.config.Logger.Warn("node artifact delivery listener reconnecting", "error", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}

// SweepOnce runs one announce + delivery pass. Run calls it serially.
func (distributor *Distributor) SweepOnce(ctx context.Context) error {
	if err := distributor.announce(ctx); err != nil {
		return err
	}
	desired, err := distributor.desired(ctx)
	if err != nil {
		return err
	}
	if err := distributor.ensureSegments(ctx, desired); err != nil {
		return err
	}
	nodes, err := distributor.pendingNodes(ctx)
	if err != nil {
		return err
	}
	created := 0
	for _, node := range nodes {
		if created >= distributor.config.BatchSize {
			break
		}
		capabilities, ok := declaredCapabilities(node.snapshot, node.snapshotSHA256)
		if !ok {
			continue
		}
		wraps, err := distributor.nodeKeyWraps(ctx, node.nodeID)
		if err != nil {
			return err
		}
		items := nodeItems(desired, capabilities, wraps)
		digest := itemsDigest(items)
		if node.revision == 0 && len(items) == 0 || node.revision != 0 && node.itemsSHA256 == digest && node.newestHealthy {
			continue
		}
		rolled, err := distributor.reconcile(ctx, node, items, digest)
		switch {
		case errors.Is(err, edgedeployment.ErrNodeDeploymentActive) || errors.Is(err, edgedeployment.ErrNodeNotFound):
		case err != nil:
			distributor.config.Logger.Warn("node artifact set delivery failed", "node_id", node.nodeID, "error", err)
		case rolled:
			created++
		}
	}
	return nil
}

// desired is the complete item list every node should run, sorted by
// artifact ID. Any failure to read or prepare a usable artifact fails the
// sweep: a set without it would uninstall it from every node.
func (distributor *Distributor) desired(ctx context.Context) ([]prepared, error) {
	artifacts, err := distributor.config.Source.LocalArtifacts(ctx)
	if err != nil {
		return nil, fmt.Errorf("read local artifacts: %w", err)
	}
	var desired []prepared
	var base, local *prepared
	next := map[string]prepared{}
	for _, artifact := range artifacts {
		if !nodeArtifact(artifact) {
			continue
		}
		key := artifact.ArtifactID + "\x00" + artifact.SHA256
		entry, found := distributor.cached[key]
		if !found || entry.item.Version != artifact.Version || entry.item.Revision != artifact.Revision {
			content, err := distributor.config.Source.Object(ctx, artifact.SHA256)
			if err != nil {
				return nil, fmt.Errorf("read local artifact %s: %w", artifact.ArtifactID, err)
			}
			if entry, err = prepareItem(artifact, content, distributor.config.SegmentBytes); err != nil {
				return nil, err
			}
		}
		next[key] = entry
		switch artifact.ArtifactID {
		case IPIntelArtifactID:
			base = &entry
		case IPIntelLocalArtifactID:
			local = &entry
		default:
			desired = append(desired, entry)
		}
	}
	if packs, ok := distributor.config.Source.(RulePackSource); ok {
		mounted, err := packs.MountedRulePacks(ctx)
		if err != nil {
			return nil, err
		}
		system, err := packs.SystemRulePacks(ctx)
		if err != nil {
			return nil, err
		}
		seen := map[string]bool{}
		for _, pack := range append(mounted, system...) {
			// A system pack version that a site also mounts is one item (by digest).
			if seen[pack.SHA256] {
				continue
			}
			seen[pack.SHA256] = true
			key := RulePackArtifactID(pack.SHA256) + "\x00" + pack.SHA256
			entry, found := distributor.cached[key]
			if !found {
				if entry, err = mountedRulePackItem(pack, distributor.config.SegmentBytes); err != nil {
					return nil, err
				}
			}
			next[key] = entry
			desired = append(desired, entry)
		}
	}
	chosen, choice := selectIPIntel(base, local)
	if chosen != nil {
		desired = append(desired, *chosen)
	}
	if choice != distributor.ipIntelChoice {
		if choice.ArtifactID != "" {
			distributor.config.Logger.Info("node IP intelligence library selected", "artifact_id", choice.ArtifactID,
				"data_updated_at", choice.DataUpdatedAt, "reason", choice.Reason)
		}
		distributor.ipIntelChoice = choice
	}
	if len(desired) > artifactset.MaxItems {
		return nil, fmt.Errorf("%d node artifacts exceed the node artifact set bound %d", len(desired), artifactset.MaxItems)
	}
	sort.Slice(desired, func(left, right int) bool { return desired[left].item.ArtifactID < desired[right].item.ArtifactID })
	distributor.cached = next
	return desired, nil
}

// nodeKeyWraps are the node's wrapped content keys by sealed digest (none
// without a RulePackSource).
func (distributor *Distributor) nodeKeyWraps(ctx context.Context, nodeID uuid.UUID) (map[string]artifactsync.NodeKeyWrap, error) {
	packs, ok := distributor.config.Source.(RulePackSource)
	if !ok {
		return nil, nil
	}
	list, err := packs.NodeKeyWraps(ctx, nodeID)
	if err != nil {
		return nil, fmt.Errorf("read node %s rule pack keys: %w", nodeID, err)
	}
	wraps := make(map[string]artifactsync.NodeKeyWrap, len(list))
	for _, wrap := range list {
		wraps[wrap.SealedSHA256] = wrap
	}
	return wraps, nil
}

func (distributor *Distributor) platformScopeID(ctx context.Context) (uuid.UUID, error) {
	if distributor.platformScope != uuid.Nil {
		return distributor.platformScope, nil
	}
	if err := distributor.config.Pool.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform'`).
		Scan(&distributor.platformScope); err != nil {
		return uuid.Nil, fmt.Errorf("read platform scope: %w", err)
	}
	return distributor.platformScope, nil
}

// ensureSegments makes sure every desired segment has its configuration.
func (distributor *Distributor) ensureSegments(ctx context.Context, desired []prepared) error {
	known := make(map[string]uuid.UUID, len(distributor.segments))
	for _, entry := range desired {
		for index, segment := range entry.item.Segments {
			configID, found := distributor.segments[segment.SHA256]
			if !found {
				var err error
				if configID, err = distributor.ensureSegment(ctx, segment.SHA256, entry.segments[index]); err != nil {
					return err
				}
			}
			known[segment.SHA256] = configID
		}
	}
	distributor.segments = known
	return nil
}

func (distributor *Distributor) ensureSegment(ctx context.Context, digest string, data []byte) (uuid.UUID, error) {
	var configID uuid.UUID
	err := distributor.config.Pool.QueryRow(ctx, `SELECT config_version_id FROM node_artifact_segments WHERE sha256=$1`,
		digest).Scan(&configID)
	if err == nil {
		return configID, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, fmt.Errorf("read node artifact segment: %w", err)
	}
	platformScopeID, err := distributor.platformScopeID(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	configID = uuid.NewSHA1(platformScopeID, []byte("cdnca.edge.artifact-segment.config/v1\x00"+digest))
	err = pgx.BeginFunc(ctx, distributor.config.Pool, func(tx pgx.Tx) error {
		artifact, err := distributor.artifact(ctx, configID, artifactset.MediaTypeSegment, data)
		if err != nil {
			return err
		}
		if _, err := distributor.config.Deployments.PersistReleasableConfigTx(ctx, tx, configID, edgedeployment.PersistConfigRequest{
			ConfigurationScopeID: platformScopeID,
			CanonicalSnapshot:    []byte(fmt.Sprintf(`{"segment_sha256":%q,"size":%d}`, digest, len(data))),
			GeneratorName:        generatorName, GeneratorVersion: generatorVersion,
			Artifacts: []edgedeployment.ArtifactInput{artifact}, IdempotencyKey: "artifact-segment." + digest,
		}); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO node_artifact_segments(sha256,config_version_id,size_bytes,created_at)
			VALUES($1,$2,$3,$4) ON CONFLICT (sha256) DO NOTHING`, digest, configID, len(data), distributor.config.Now().UTC())
		return err
	})
	if err != nil {
		return uuid.Nil, fmt.Errorf("persist node artifact segment: %w", err)
	}
	return configID, nil
}

func (distributor *Distributor) artifact(ctx context.Context, configID uuid.UUID, mediaType string, wire []byte) (edgedeployment.ArtifactInput, error) {
	signature, err := distributor.config.Signer.Sign(ctx, bytes.Clone(wire))
	if err != nil {
		return edgedeployment.ArtifactInput{}, fmt.Errorf("sign node artifact: %w", err)
	}
	digest := sha256.Sum256(wire)
	return edgedeployment.ArtifactInput{
		ID:   uuid.NewSHA1(configID, []byte("cdnca.edge.node-artifact/v1\x00"+mediaType+"\x00"+hex.EncodeToString(digest[:]))),
		Kind: agentv1.ArtifactKind_ARTIFACT_KIND_CONFIGURATION, WireBytes: bytes.Clone(wire), SizeBytes: uint64(len(wire)),
		SHA256: digest[:], Signature: signature, SigningKeyID: distributor.config.Signer.KeyID(),
		SigningPublicKey:   append(ed25519.PublicKey(nil), distributor.config.Signer.PublicKey()...),
		SignatureAlgorithm: agentv1.ArtifactSignatureAlgorithm_ARTIFACT_SIGNATURE_ALGORITHM_ED25519,
		Compression:        agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_NONE, MediaType: mediaType,
		EncryptionAlgorithm: agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_NONE,
	}, nil
}
