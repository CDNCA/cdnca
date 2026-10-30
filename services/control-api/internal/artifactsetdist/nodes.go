package artifactsetdist

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/artifactset"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"google.golang.org/protobuf/proto"
)

type pendingNode struct {
	nodeID         uuid.UUID
	snapshot       []byte
	snapshotSHA256 []byte
	// latest set issued to the node (revision 0: none)
	revision       int64
	itemsSHA256    string
	setConfigID    uuid.UUID
	activeRevision int64
	// newestHealthy: the newest set was delivered (the node applied it)
	newestHealthy bool
}

// pendingNodes are active nodes with no node artifact delivery in flight,
// with their newest set; which of them need a set is decided per node
// (their items depend on their capabilities).
func (distributor *Distributor) pendingNodes(ctx context.Context) ([]pendingNode, error) {
	rows, err := distributor.config.Pool.Query(ctx, `SELECT node.id, latest.capabilities_snapshot, latest.capabilities_sha256,
			COALESCE(newest.revision,0), COALESCE(newest.items_sha256,''), newest.config_version_id,
			COALESCE(receipt.active_revision,0),
			newest.revision IS NOT NULL AND EXISTS (SELECT 1 FROM node_deployments deployment
			    WHERE deployment.node_id=node.id AND deployment.config_version_id=newest.config_version_id
			      AND deployment.state='healthy')
		FROM nodes node
		JOIN LATERAL (SELECT capabilities_snapshot,capabilities_sha256 FROM node_session_capabilities
			WHERE node_id=node.id ORDER BY session_epoch DESC LIMIT 1) latest ON true
		LEFT JOIN LATERAL (SELECT revision,items_sha256,config_version_id FROM node_artifact_sets
			WHERE node_id=node.id ORDER BY revision DESC LIMIT 1) newest ON true
		LEFT JOIN node_artifact_set_receipts receipt ON receipt.node_id=node.id
		WHERE node.admin_state='active'
		  AND NOT EXISTS (SELECT 1 FROM node_deployments deployment
		      JOIN configuration_artifacts artifact ON artifact.config_version_id=deployment.config_version_id
		      WHERE deployment.node_id=node.id AND artifact.media_type=ANY($1::text[])
		        AND deployment.state NOT IN `+terminalStates+`)
		ORDER BY node.id`, nodeArtifactMediaTypes)
	if err != nil {
		return nil, fmt.Errorf("read node artifact set targets: %w", err)
	}
	nodes, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (pendingNode, error) {
		var node pendingNode
		var configID *uuid.UUID
		err := row.Scan(&node.nodeID, &node.snapshot, &node.snapshotSHA256, &node.revision, &node.itemsSHA256, &configID,
			&node.activeRevision, &node.newestHealthy)
		if configID != nil {
			node.setConfigID = *configID
		}
		return node, err
	})
	if err != nil {
		return nil, fmt.Errorf("read node artifact set targets: %w", err)
	}
	return nodes, nil
}

// declaredCapabilities decodes an authentic session snapshot that declares
// ARTIFACT_SET v1 or newer.
func declaredCapabilities(snapshot, digest []byte) (*agentv1.AgentCapabilities, bool) {
	actual := sha256.Sum256(snapshot)
	capabilities := new(agentv1.AgentCapabilities)
	if !bytes.Equal(actual[:], digest) || proto.Unmarshal(snapshot, capabilities) != nil {
		return nil, false
	}
	for _, feature := range capabilities.Features {
		if feature.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_ARTIFACT_SET && feature.GetApiVersion() >= artifactSetAPIVersion {
			return capabilities, true
		}
	}
	return nil, false
}

// declaresArtifactSet: the session snapshot is authentic and declares
// ARTIFACT_SET v1 or newer.
func declaresArtifactSet(snapshot, digest []byte) bool {
	_, ok := declaredCapabilities(snapshot, digest)
	return ok
}

type deliveryHistory struct {
	attempts    int
	lastHealthy time.Time
	lastFailed  time.Time
}

// reconcile takes the node one step: issue a newer set if needed, then roll
// out the first segment the node lacks, or the set. It reports whether a
// deployment was created.
func (distributor *Distributor) reconcile(ctx context.Context, node pendingNode, items []artifactset.Item, digest string) (bool, error) {
	if node.revision == 0 || node.itemsSHA256 != digest {
		revision := max(node.revision, node.activeRevision) + 1
		configID, err := distributor.issueSet(ctx, node.nodeID, uint64(revision), items, digest)
		if err != nil {
			return false, err
		}
		node.revision, node.setConfigID = revision, configID
	}
	configs := []uuid.UUID{node.setConfigID}
	for _, item := range items {
		for _, segment := range item.Segments {
			configs = append(configs, distributor.segments[segment.SHA256])
		}
	}
	history, err := distributor.history(ctx, node.nodeID, configs)
	if err != nil {
		return false, err
	}
	now := distributor.config.Now().UTC()
	set := history[node.setConfigID]
	if !set.lastHealthy.IsZero() {
		return false, nil
	}
	if !set.lastFailed.IsZero() && now.Sub(set.lastFailed) < distributor.config.RetryAfter {
		return false, nil
	}
	for _, configID := range configs[1:] {
		segment := history[configID]
		// A segment counts once delivered after the set last failed: the
		// failure may be that object missing or altered on the node.
		if segment.lastHealthy.After(set.lastFailed) {
			continue
		}
		if !segment.lastFailed.IsZero() && segment.lastFailed.After(set.lastFailed) &&
			now.Sub(segment.lastFailed) < distributor.config.RetryAfter {
			return false, nil
		}
		return true, distributor.rollout(ctx, "segment", configID, node.nodeID, segment.attempts, map[string]any{
			"set_revision": node.revision, "segment_sha256": segmentDigest(items, configID, distributor.segments)})
	}
	return true, distributor.rollout(ctx, "set", node.setConfigID, node.nodeID, set.attempts,
		map[string]any{"set_revision": node.revision})
}

// segmentDigest names the segment a configuration delivers.
func segmentDigest(items []artifactset.Item, configID uuid.UUID, segments map[string]uuid.UUID) string {
	for _, item := range items {
		for _, segment := range item.Segments {
			if segments[segment.SHA256] == configID {
				return segment.SHA256
			}
		}
	}
	return ""
}

func (distributor *Distributor) history(ctx context.Context, nodeID uuid.UUID, configs []uuid.UUID) (map[uuid.UUID]deliveryHistory, error) {
	rows, err := distributor.config.Pool.Query(ctx, `SELECT config_version_id, count(DISTINCT rollout_id),
			COALESCE(max(updated_at) FILTER (WHERE state='healthy'),'epoch'),
			COALESCE(max(updated_at) FILTER (WHERE state IN `+failedStates+`),'epoch')
		FROM node_deployments WHERE node_id=$1 AND config_version_id=ANY($2::uuid[])
		GROUP BY config_version_id`, nodeID, configs)
	if err != nil {
		return nil, fmt.Errorf("read node artifact deliveries: %w", err)
	}
	defer rows.Close()
	history := map[uuid.UUID]deliveryHistory{}
	for rows.Next() {
		var configID uuid.UUID
		var entry deliveryHistory
		if err := rows.Scan(&configID, &entry.attempts, &entry.lastHealthy, &entry.lastFailed); err != nil {
			return nil, err
		}
		if entry.lastHealthy.Equal(time.Unix(0, 0)) {
			entry.lastHealthy = time.Time{}
		}
		if entry.lastFailed.Equal(time.Unix(0, 0)) {
			entry.lastFailed = time.Time{}
		}
		history[configID] = entry
	}
	return history, rows.Err()
}

// rollout delivers one segment or set configuration to the node and audits
// it (node.artifact_set.deliver; attempt counts deliveries of that
// configuration to the node, a retry is attempt > 1).
func (distributor *Distributor) rollout(ctx context.Context, kind string, configID, nodeID uuid.UUID, attempts int,
	detail map[string]any) error {
	platformScopeID, err := distributor.platformScopeID(ctx)
	if err != nil {
		return err
	}
	now := distributor.config.Now().UTC().Truncate(time.Microsecond)
	return pgx.BeginFunc(ctx, distributor.config.Pool, func(tx pgx.Tx) error {
		result, err := distributor.config.Deployments.CreateNodeArtifactRolloutTx(ctx, tx, edgedeployment.CreateRolloutRequest{
			ConfigurationScopeID: platformScopeID, ConfigVersionID: configID,
			Action: agentv1.DeploymentAction_DEPLOYMENT_ACTION_APPLY, NodeIDs: []uuid.UUID{nodeID},
			RequiredCapabilities: []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_ARTIFACT_SET,
				ApiVersion: artifactSetAPIVersion}},
			HealthCheck: edgedeployment.HealthCheckPolicy{ActivationTimeout: time.Minute, ObservationWindow: time.Second,
				RequiredConsecutiveSuccesses: 1},
			Deadline: now.Add(deliveryDeadline), MaxAttempts: 3,
			IdempotencyKey: fmt.Sprintf("artifact-%s.%s.%s.%d", kind, configID, nodeID, attempts+1),
			RequestID:      uuid.NewString(), CorrelationID: uuid.NewString(),
		})
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return edgedeployment.ErrNodeDeploymentActive
		}
		if err != nil || result.Replayed {
			return err
		}
		detail["kind"], detail["config_version_id"], detail["rollout_id"] = kind, configID.String(), result.Rollout.ID.String()
		detail["attempt"] = attempts + 1
		return distributor.appendAudit(ctx, tx, AuditActionDeliver, nodeID, detail)
	})
}

// issueSet signs and persists set revision for the node.
func (distributor *Distributor) issueSet(ctx context.Context, nodeID uuid.UUID, revision uint64, items []artifactset.Item,
	digest string) (uuid.UUID, error) {
	platformScopeID, err := distributor.platformScopeID(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	wire, err := artifactset.SignWith(artifactset.Set{NodeID: nodeID.String(), Revision: revision,
		Items: append([]artifactset.Item{}, items...), IssuedAt: distributor.config.Now()},
		setSigner{ctx: ctx, signer: distributor.config.Signer})
	if err != nil {
		return uuid.Nil, err
	}
	configID := uuid.NewSHA1(platformScopeID, []byte("cdnca.edge.artifact-set.config/v1\x00"+nodeID.String()+"\x00"+
		strconv.FormatUint(revision, 10)))
	err = pgx.BeginFunc(ctx, distributor.config.Pool, func(tx pgx.Tx) error {
		artifact, err := distributor.artifact(ctx, configID, artifactset.MediaTypeSet, wire)
		if err != nil {
			return err
		}
		if _, err := distributor.config.Deployments.PersistReleasableConfigTx(ctx, tx, configID, edgedeployment.PersistConfigRequest{
			ConfigurationScopeID: platformScopeID, CanonicalSnapshot: bytes.Clone(wire),
			GeneratorName: generatorName, GeneratorVersion: generatorVersion,
			Artifacts:      []edgedeployment.ArtifactInput{artifact},
			IdempotencyKey: "artifact-set." + nodeID.String() + "." + strconv.FormatUint(revision, 10),
		}); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO node_artifact_sets(node_id,revision,set_sha256,items_sha256,config_version_id,created_at)
			VALUES($1,$2,$3,$4,$5,$6)`, nodeID, int64(revision), artifactset.Digest(wire), digest, configID,
			distributor.config.Now().UTC()); err != nil {
			return err
		}
		before, err := appliedAuditItems(ctx, tx, nodeID)
		if err != nil {
			return err
		}
		return distributor.appendAudit(ctx, tx, AuditActionIssue, nodeID, map[string]any{
			"set_revision": revision, "set_sha256": artifactset.Digest(wire), "config_version_id": configID.String(),
			"changes": map[string]any{"items": map[string]any{"before": before, "after": auditItems(items)}}})
	})
	if err != nil {
		return uuid.Nil, fmt.Errorf("issue node artifact set %d: %w", revision, err)
	}
	distributor.config.Logger.Info("node artifact set issued", "node_id", nodeID, "revision", revision, "items", len(items))
	return configID, nil
}

type setSigner struct {
	ctx    context.Context
	signer Signer
}

func (signer setSigner) KeyID() string { return signer.signer.KeyID() }
func (signer setSigner) Sign(payload []byte) ([]byte, error) {
	signature, err := signer.signer.Sign(signer.ctx, payload)
	if err == nil && !ed25519.Verify(signer.signer.PublicKey(), payload, signature) {
		err = errors.New("edge publication signature does not verify")
	}
	return signature, err
}

// announce republishes, once per newly applied item, the scopes held for
// nodes whose applied set gained it (a capability hold naming the node, or
// a system republication that excluded it): having the item, not declaring
// a capability, is what the publication gate waits for.
func (distributor *Distributor) announce(ctx context.Context) error {
	return pgx.BeginFunc(ctx, distributor.config.Pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `WITH due AS (
				SELECT node_id, artifact_id FROM node_artifact_applied_items WHERE announced_at IS NULL
				ORDER BY node_id, artifact_id LIMIT $1 FOR UPDATE SKIP LOCKED)
			UPDATE node_artifact_applied_items item SET announced_at=$2 FROM due
			WHERE item.node_id=due.node_id AND item.artifact_id=due.artifact_id
			RETURNING item.node_id, item.set_revision`, distributor.config.BatchSize, distributor.config.Now().UTC())
		if err != nil {
			return fmt.Errorf("claim applied node artifacts: %w", err)
		}
		type applied struct {
			nodeID   uuid.UUID
			revision int64
		}
		items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (applied, error) {
			var item applied
			return item, row.Scan(&item.nodeID, &item.revision)
		})
		if err != nil {
			return err
		}
		announced := map[uuid.UUID]int64{}
		for _, item := range items {
			announced[item.nodeID] = max(announced[item.nodeID], item.revision)
		}
		for nodeID, revision := range announced {
			if _, err := edgeautopublish.RequestNodeReadyRepublicationsTx(ctx, tx, nodeID,
				"artifact-set-applied/"+nodeID.String()+"/"+strconv.FormatInt(revision, 10),
				edgepublish.SystemRepublicationDebounce); err != nil {
				return err
			}
		}
		return nil
	})
}
