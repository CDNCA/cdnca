package edgepublish

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/packageaddon"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Node settings redelivery (ADR 0030
// section 4, migration 701). A node's settings (node storage) reach it
// only in a tenant scope's key documents. When a trigger that changes nothing
// but them meets a publication the scope's own facts refuse (a package quota,
// an entitlement, a site that does not compile: NodeSettingsContentRefusal),
// the scope's release in effect on its nodes (the base) goes out again as it
// is, under a new config version and the request's source revision, with
// fresh key documents: the same site objects (members), the same snapshot and
// root apart from their identity (config_version_id, source_revision, the
// root's document_sha256), which migration 701 checks on insert. Nothing is
// compiled and the package quotas are not read: nothing the refused content
// adds goes out. The publication says so (publication_kind node_settings,
// content_refusal); the publication page keeps showing the refusal.
//
// The key documents are built as every release's are (sealSiteObjectKeys):
// the websites and forwards a node withholds follow the base's serving nodes
// (migration 702; a line group change the tenant has not published does not
// apply yet), and those an explicit stop holds now (a traffic stop, a package
// out of publication) are withheld on every node, as a stop overlay drops
// them; the traffic stopped forwards are the current ones.
//
// The checks that decide what may run on the nodes still run: the lease
// (AuthorizePublication), the modules the base uses, the target nodes'
// capabilities, JS challenge policies and cross scope composition. The
// redelivery reaches only the nodes that run the base now.

// Publication kinds (edge_config_publications.publication_kind, migration 701).
const (
	PublicationKindContent      = "content"
	PublicationKindNodeSettings = "node_settings"
)

// Source request ID prefix of the trigger that changes node settings only:
// the node storage (the node networks watcher's node_storage sweep). Node
// regions and addresses also change the v2 document (nginx region overrides,
// DDoS exemptions): not node settings only.
const NodeSettingsRequestPrefixStorage = "node-storage."

// NodeSettingsOnlyRequest reports whether an automatic request's source
// request ID is a node settings only trigger's.
func NodeSettingsOnlyRequest(sourceRequestID string) bool {
	return strings.HasPrefix(sourceRequestID, NodeSettingsRequestPrefixStorage)
}

// nodeSettingsOnlyTriggers: a system republication's triggers change node
// settings only.
func nodeSettingsOnlyTriggers(triggers []string) bool {
	return len(triggers) > 0 && !slices.ContainsFunc(triggers, func(trigger string) bool {
		return !nodeSettingsTrigger(trigger)
	})
}

// nodeSettingsTriggered: some of a system republication's triggers change
// node settings (G8): a content refusal still redelivers them, whatever
// else was queued with them (the other triggers' content stays refused).
func nodeSettingsTriggered(triggers []string) bool {
	return slices.ContainsFunc(triggers, nodeSettingsTrigger)
}

func nodeSettingsTrigger(trigger string) bool {
	return trigger == SystemTriggerNodeStorage
}

// NodeSettingsContentRefusal is the reason code of a publication the scope's
// own facts refuse whatever the nodes or the moment (the automatic failure
// codes of the same names), or false for anything else: a lost connection,
// a lock or revision conflict, a persistence error, a node lacking a
// capability (held until it upgrades), a permission or lease denial.
func NodeSettingsContentRefusal(err error) (string, bool) {
	var invalid *SiteConfigInvalidError
	switch {
	case err == nil:
		return "", false
	case errors.As(err, &invalid):
		return AutomaticFailureSiteConfigInvalid, true
	case errors.Is(err, packageaddon.ErrSubscriptionInactive):
		return AutomaticFailurePackageSubscriptionInactive, true
	case errors.Is(err, packageaddon.ErrQuotaExceeded):
		return AutomaticFailurePackageQuotaExceeded, true
	case errors.Is(err, packageaddon.ErrFeatureDenied):
		return AutomaticFailurePackageFeatureDenied, true
	case errors.Is(err, ErrModuleNotEntitled):
		return AutomaticFailureModuleNotEntitled, true
	case errors.Is(err, ErrSiteL2Unavailable):
		return AutomaticFailureSiteL2Unavailable, true
	case errors.As(err, new(*CRSOutOfProfileError)):
		return AutomaticFailureRulePackOutOfProfile, true
	default:
		return "", false
	}
}

// NodeSettingsRefusalCode reports whether code is one NodeSettingsContentRefusal returns.
func NodeSettingsRefusalCode(code string) bool {
	switch code {
	case AutomaticFailureSiteConfigInvalid, AutomaticFailurePackageSubscriptionInactive, AutomaticFailurePackageQuotaExceeded,
		AutomaticFailurePackageFeatureDenied, AutomaticFailureModuleNotEntitled, AutomaticFailureSiteL2Unavailable,
		AutomaticFailureRulePackOutOfProfile, AutomaticFailureSDKShieldPortShared:
		return true
	}
	return false
}

// nodeSettingsRedeliveryRefused: the redelivery itself was refused for
// good (the base uses a revoked module, a node no longer takes it, the base
// cannot be redelivered as it is): the content refusal stands. Anything else
// is an outcome nobody decided.
func nodeSettingsRedeliveryRefused(err error) bool {
	if _, refused := NodeSettingsContentRefusal(err); refused {
		return true
	}
	if _, refused := systemRefusalOf(err); refused {
		return true
	}
	return errors.As(err, new(*CrossScopeConflictError)) || errors.Is(err, ErrTargetIneligible) || errors.Is(err, ErrInvalidInput)
}

// nodeSettingsRedelivery marks a publish request as the redelivery of base
// for a content refusal.
type nodeSettingsRedelivery struct {
	refusal string
	base    *nodeSettingsBase
}

// nodeSettingsBase is the scope's publication in effect on the nodes.
type nodeSettingsBase struct {
	configID       uuid.UUID
	sourceRevision int64
	snapshot       []byte
	root           []byte
	members        []byte
	// nodes: the candidates that run it (sorted).
	nodes []uuid.UUID
}

// loadNodeSettingsBaseTx is the scope's newest publication some of
// candidates run (node_config_state, no reconciliation pending), with the
// candidates running it; nil when none runs a site object release of it.
func loadNodeSettingsBaseTx(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, candidates []uuid.UUID) (*nodeSettingsBase, error) {
	if len(candidates) == 0 {
		return nil, nil
	}
	var base nodeSettingsBase
	err := tx.QueryRow(ctx, `SELECT publication.config_version_id,publication.source_revision,version.canonical_snapshot,
			root.wire_bytes,objects.member_sha256,
			ARRAY(SELECT state.node_id FROM node_config_state state WHERE state.configuration_scope_id=$1
			  AND state.current_config_version_id=publication.config_version_id AND NOT state.reconciliation_required
			  AND state.node_id=ANY($2::uuid[]) ORDER BY state.node_id)
		FROM edge_config_publications publication
		JOIN config_versions version ON version.id=publication.config_version_id AND version.configuration_scope_id=$1
		JOIN configuration_artifacts root ON root.config_version_id=publication.config_version_id AND root.media_type=$3
		JOIN edge_site_object_publications objects ON objects.config_version_id=publication.config_version_id
		  AND objects.configuration_scope_id=$1 AND objects.key_epoch=$4
		WHERE publication.configuration_scope_id=$1 AND publication.contract_version=1
		  AND EXISTS(SELECT 1 FROM node_config_state state WHERE state.configuration_scope_id=$1
		    AND state.current_config_version_id=publication.config_version_id AND NOT state.reconciliation_required
		    AND state.node_id=ANY($2::uuid[]))
		ORDER BY publication.source_revision DESC LIMIT 1`, scopeID, candidates, siteobject.RootMediaTypeV2, siteObjectKeyEpoch).
		Scan(&base.configID, &base.sourceRevision, &base.snapshot, &base.root, &base.members, &base.nodes)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: read node settings base publication", ErrPersistence)
	}
	return &base, nil
}

// nodeSettingsIdempotencyKey is the redelivery's own publication key: the
// refused content attempt's key stays free for the content.
func nodeSettingsIdempotencyKey(key string) string {
	digest := sha256.Sum256([]byte("cdnca.node-settings\x00" + key))
	return "nodeset." + hex.EncodeToString(digest[:16])
}

// publishNodeSettingsTx redelivers, after request's content was refused for
// refusal, the scope's base to the request's target nodes that run it, in
// savepoints of tx, and returns the nodes it went to. None, with nothing
// written, when none of them runs a site object release of the scope.
func (s *Service) publishNodeSettingsTx(ctx context.Context, tx pgx.Tx, request normalizedPublishRequest,
	refusal string, now time.Time) (PublishResult, []uuid.UUID, error) {
	candidates := request.NodeIDs
	if request.TargetSnapshot != nil {
		target, _, err := s.resolveTarget(ctx, tx, request)
		if err != nil {
			return PublishResult{}, nil, err
		}
		candidates = target.NodeIDs
	}
	base, err := loadNodeSettingsBaseTx(ctx, tx, request.ConfigurationScopeID, candidates)
	if err != nil || base == nil || len(base.nodes) == 0 {
		return PublishResult{}, nil, err
	}
	request.NodeIDs, request.TargetSnapshot = slices.Clone(base.nodes), nil
	request.IdempotencyKey = nodeSettingsIdempotencyKey(request.IdempotencyKey)
	request.nodeSettings = &nodeSettingsRedelivery{refusal: refusal, base: base}
	// Nodes left out for their key envelope keep the base; no capability
	// hold: a hold would republish this revision's content once they upgrade.
	request.capabilityHoldByCaller, request.keyEnvelopeOversized = true, nil
	result, err := s.publishAuthorizedTx(ctx, tx, request, now)
	if err != nil {
		return PublishResult{}, nil, err
	}
	nodes := slices.DeleteFunc(slices.Clone(base.nodes), func(nodeID uuid.UUID) bool {
		return slices.Contains(result.KeyEnvelopeOversizedNodeIDs, nodeID)
	})
	return result, nodes, nil
}

// buildNodeSettingsRelease is the redelivery's snapshot and site object
// release: base's document and root under configID at sourceRevision, base's
// members, fresh key envelopes for recipients.
func (s *Service) buildNodeSettingsRelease(ctx context.Context, tx pgx.Tx, scopeID, configID uuid.UUID,
	sourceRevision int64, base *nodeSettingsBase, recipients []configurationArtifactRecipientBinding, now time.Time,
) ([]byte, [sha256.Size]byte, []*agentv1.Capability, *siteObjectRelease, error) {
	fail := func(err error) ([]byte, [sha256.Size]byte, []*agentv1.Capability, *siteObjectRelease, error) {
		return nil, [sha256.Size]byte{}, nil, nil, err
	}
	if base == nil || len(recipients) == 0 || configID == uuid.Nil || sourceRevision <= base.sourceRevision {
		return fail(ErrInvalidInput)
	}
	snapshot, digest, documentCapabilities, requiresTLS, err := nodeSettingsDocument(base.snapshot, base.configID,
		base.sourceRevision, configID, sourceRevision)
	if err != nil {
		return fail(err)
	}
	capabilities, err := dynamicRoutingDeliveryCapabilities(documentCapabilities)
	if err != nil {
		return fail(err)
	}
	nodeIDs := make([]uuid.UUID, len(recipients))
	advertisedTLS := make(map[uuid.UUID]bool, len(recipients))
	for index, recipient := range recipients {
		nodeIDs[index] = recipient.NodeID
		advertisedTLS[recipient.NodeID] = requiresTLS
	}
	advertised, err := loadSiteRuntimeV2TargetCapabilities(ctx, tx, scopeID, nodeIDs, now)
	if err != nil {
		return fail(err)
	}
	if err := validateSiteRuntimeV2TargetCapabilities(capabilities, requiresTLS, advertised, advertisedTLS); err != nil {
		return fail(readableTargetCapabilityError(ctx, tx, nodeIDs, capabilities, advertised, err))
	}
	root, err := nodeSettingsRoot(base.root, base.configID, base.sourceRevision, configID, sourceRevision,
		hex.EncodeToString(digest[:]))
	if err != nil {
		return fail(err)
	}
	if err := requireStoredSiteObjects(ctx, tx, scopeID, base.members); err != nil {
		return fail(err)
	}
	contentKey, err := ensureSiteObjectContentKey(ctx, tx, scopeID, now, rand.Reader)
	if err != nil {
		return fail(err)
	}
	defer clear(contentKey)
	release := &siteObjectRelease{scopeID: scopeID, configID: configID, members: bytes.Clone(base.members),
		rootSHA256: sha256.Sum256(root)}
	if release.root, err = s.signSiteObjectRoot(ctx, configID, root, siteobject.RootMediaTypeV2); err != nil {
		return fail(err)
	}
	var document siteRuntimeV2Document
	if err := json.Unmarshal(snapshot, &document); err != nil {
		return fail(fmt.Errorf("%w: node settings document", ErrInvalidInput))
	}
	siteIDs := make([]string, len(document.Sites))
	for index, site := range document.Sites {
		siteIDs[index] = site.ID
	}
	streams := document.Streams
	if streams != nil && len(streams.StreamsV2) == 0 {
		streams = nil // a streamless runtime: the scope object carries no streams (siteObjectsV2SourceFromBundle)
	}
	// The base's serving nodes, its stops now (releaseStops).
	stops, err := loadReleaseStops(ctx, tx, scopeID, siteIDs, streams)
	if err != nil {
		return fail(err)
	}
	if err := s.sealSiteObjectKeys(ctx, tx, release, contentKey, siteIDs, streams, recipients, advertised,
		[]uuid.UUID{base.configID}, stops); err != nil {
		return fail(err)
	}
	return snapshot, digest, capabilities, release, nil
}

// nodeSettingsDocument is base, the canonical v2 document of baseConfigID at
// baseRevision, as configID at sourceRevision: only those two fields change.
func nodeSettingsDocument(base []byte, baseConfigID uuid.UUID, baseRevision int64, configID uuid.UUID,
	sourceRevision int64) ([]byte, [sha256.Size]byte, []*agentv1.Capability, bool, error) {
	invalid := func(what string) ([]byte, [sha256.Size]byte, []*agentv1.Capability, bool, error) {
		return nil, [sha256.Size]byte{}, nil, false, fmt.Errorf("%w: node settings document %s", ErrInvalidInput, what)
	}
	value, err := parseSiteRuntimeV2JSON(base)
	if err != nil {
		return invalid("is not JSON")
	}
	fields, ok := value.(map[string]any)
	var reencoded bytes.Buffer
	if !ok || writeSiteRuntimeV2CanonicalJSON(&reencoded, value) != nil || !bytes.Equal(reencoded.Bytes(), base) {
		return invalid("is not canonical")
	}
	if fields["config_version_id"] != baseConfigID.String() ||
		fields["source_revision"] != json.Number(strconv.FormatInt(baseRevision, 10)) {
		return invalid("identity is not its publication's")
	}
	fields["config_version_id"] = configID.String()
	fields["source_revision"] = json.Number(strconv.FormatInt(sourceRevision, 10))
	var raw bytes.Buffer
	if err := writeSiteRuntimeV2CanonicalJSON(&raw, fields); err != nil {
		return invalid("cannot be encoded")
	}
	canonical, digest, capabilities, requiresTLS, err := compileSiteRuntimeV2Document(raw.Bytes())
	if err != nil {
		return nil, [sha256.Size]byte{}, nil, false, err
	}
	if !bytes.Equal(canonical, raw.Bytes()) {
		return invalid("changed beyond its identity")
	}
	return canonical, digest, capabilities, requiresTLS, nil
}

// nodeSettingsRoot is base, the v2 root of baseConfigID at baseRevision, for
// configID at sourceRevision and its document digest; nothing else changes.
func nodeSettingsRoot(base []byte, baseConfigID uuid.UUID, baseRevision int64, configID uuid.UUID,
	sourceRevision int64, documentSHA256 string) ([]byte, error) {
	root, err := siteobject.ParseRootV2(base)
	if err != nil {
		return nil, fmt.Errorf("%w: node settings root: %v", ErrInvalidInput, err)
	}
	if encoded, err := siteobject.Encode(root); err != nil || !bytes.Equal(encoded, base) ||
		root.ConfigVersionID != baseConfigID.String() || root.SourceRevision != baseRevision || root.KeyEpoch != siteObjectKeyEpoch {
		return nil, fmt.Errorf("%w: node settings root is not its publication's", ErrInvalidInput)
	}
	root.ConfigVersionID, root.SourceRevision, root.DocumentSHA256 = configID.String(), sourceRevision, documentSHA256
	return siteobject.Encode(root)
}

// requireStoredSiteObjects: every member digest is a stored object of the
// scope's key epoch (the redelivery seals nothing).
func requireStoredSiteObjects(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, members []byte) error {
	if len(members) == 0 || len(members)%sha256.Size != 0 {
		return fmt.Errorf("%w: node settings members", ErrInvalidInput)
	}
	digests := make([][]byte, 0, len(members)/sha256.Size)
	for start := 0; start < len(members); start += sha256.Size {
		digests = append(digests, members[start:start+sha256.Size])
	}
	var stored int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM edge_site_objects
		WHERE configuration_scope_id=$1 AND key_epoch=$2 AND sha256=ANY($3::bytea[])`,
		scopeID, siteObjectKeyEpoch, digests).Scan(&stored); err != nil {
		return fmt.Errorf("%w: read node settings members", ErrPersistence)
	}
	if stored != len(digests) {
		return fmt.Errorf("%w: node settings base objects are not stored", ErrInvalidInput)
	}
	return nil
}

// copyNodeSettingsFactsTx gives the redelivery its base's telemetry site
// bindings (the gateway authorizes the sites' telemetry per config version)
// and compile inputs, marked overlay: the redelivery did not publish the
// scope's rows, and a stop overlay takes it as the release the nodes run.
func copyNodeSettingsFactsTx(ctx context.Context, tx pgx.Tx, base *nodeSettingsBase, configID uuid.UUID,
	sourceRevision int64, now time.Time) error {
	if _, err := tx.Exec(ctx, `INSERT INTO config_version_telemetry_site_bindings(config_version_id,site_id,package_subscription_id)
		SELECT $2,site_id,package_subscription_id FROM config_version_telemetry_site_bindings WHERE config_version_id=$1
		ON CONFLICT (config_version_id,site_id) DO NOTHING`, base.configID, configID); err != nil {
		return fmt.Errorf("%w: copy node settings telemetry site bindings", ErrPersistence)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO edge_publication_compile_inputs(
		config_version_id,configuration_scope_id,source_revision,overlay,spec,site_runtime_v2,required_capabilities,created_at)
		SELECT $2,configuration_scope_id,$3,true,spec,site_runtime_v2,required_capabilities,$4
		FROM edge_publication_compile_inputs WHERE config_version_id=$1`, base.configID, configID, sourceRevision, now); err != nil {
		return fmt.Errorf("%w: copy node settings compile inputs", ErrPersistence)
	}
	return nil
}
