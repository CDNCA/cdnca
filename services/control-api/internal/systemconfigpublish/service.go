package systemconfigpublish

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/cdnca/cdnca/services/control-api/internal/nodemonitoringoutbox"
	"github.com/cdnca/cdnca/services/control-api/internal/systemconfig"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const activationReasonCode = "system_configuration_activated"

type Service struct {
	pool           *pgxpool.Pool
	publisher      *edgepublish.Service
	nodeMonitoring nodeMonitoringEnqueuer
}

type nodeMonitoringEnqueuer interface {
	EnqueueNodeMonitoringArtifact(context.Context, pgx.Tx, *agentv1.NodeMonitoringArtifact) error
}

func New(pool *pgxpool.Pool, publisher *edgepublish.Service) (*Service, error) {
	if pool == nil || publisher == nil {
		return nil, systemconfig.ErrInvalidStore
	}
	nodeMonitoring, err := nodemonitoringoutbox.NewStore(pool, time.Now)
	if err != nil {
		return nil, err
	}
	return &Service{pool: pool, publisher: publisher, nodeMonitoring: nodeMonitoring}, nil
}

func (service *Service) PublishActivation(
	ctx context.Context,
	tx pgx.Tx,
	request systemconfig.ActivationPublicationRequest,
) ([]systemconfig.ActivationPublication, error) {
	if service == nil || service.pool == nil || service.publisher == nil || ctx == nil || tx == nil ||
		request.Actor.UserID == uuid.Nil || request.Actor.ScopeID == uuid.Nil || request.Actor.ScopeKind != "platform" ||
		request.Revision < 1 || request.ActivatedAt.IsZero() || request.SnapshotSHA256 == "" {
		return nil, systemconfig.ErrInvalidInput
	}
	digestBytes, err := hex.DecodeString(request.SnapshotSHA256)
	if err != nil || len(digestBytes) != sha256.Size || hex.EncodeToString(digestBytes) != request.SnapshotSHA256 {
		return nil, systemconfig.ErrInvalidInput
	}
	var snapshotDigest [sha256.Size]byte
	copy(snapshotDigest[:], digestBytes)
	targets, err := loadTargets(ctx, tx)
	if err != nil {
		return nil, err
	}
	nginx := projectNginx(request.Configuration)
	actor := edgepublish.Actor{
		UserID: request.Actor.UserID, ScopeID: request.Actor.ScopeID, ScopeKind: edgepublish.ScopeKindPlatform,
	}
	correlationID := uuid.NewSHA1(request.Actor.ScopeID,
		[]byte("system-configuration/"+strconv.FormatInt(request.Revision, 10)+"/"+request.SnapshotSHA256)).String()
	results := make([]systemconfig.ActivationPublication, 0, len(targets))
	for _, target := range targets {
		seed := strconv.FormatInt(request.Revision, 10) + "/" + request.SnapshotSHA256 + "/" + target.scopeID.String()
		requestID := uuid.NewSHA1(request.Actor.ScopeID, []byte("system-configuration/request/"+seed)).String()
		keyDigest := sha256.Sum256([]byte(seed))
		result, publishErr := service.publisher.PublishSystemConfigurationTx(ctx, tx,
			edgepublish.SystemConfigurationPublishRequest{
				Actor: actor, PlatformScopeID: request.Actor.ScopeID, Revision: request.Revision,
				SnapshotSHA256: snapshotDigest, ConfigurationScopeID: target.scopeID,
				ExpectedSourceRevision: target.sourceRevision, NodeIDs: target.nodeIDs, Nginx: nginx,
				DDoS:            systemconfig.EdgeDDoSProtection(request.Configuration.DDoSProtection),
				AccessLogFields: request.Configuration.AccessLogFields,
				IdempotencyKey:  "systemcfg." + strconv.FormatInt(request.Revision, 10) + "." + hex.EncodeToString(keyDigest[:12]),
				RequestID:       requestID, CorrelationID: correlationID,
			})
		if publishErr != nil {
			slog.Error("system configuration edge publication failed",
				"stage", "edge", "tenant_scope_id", target.scopeID.String(),
				"revision", request.Revision, "error", publishErr)
			return nil, fmt.Errorf("publish system configuration for tenant scope %s: %w", target.scopeID, publishErr)
		}
		results = append(results, systemconfig.ActivationPublication{
			TenantScopeID: target.scopeID, TenantSourceRevision: result.SourceRevision,
			PublicationID: result.PublicationID, ConfigVersionID: result.ConfigVersionID,
			RolloutID: result.RolloutID, ArtifactSHA256: hex.EncodeToString(result.ArtifactSHA256[:]),
			ReasonCode: activationReasonCode,
		})
	}
	if err := service.publishNodeMonitoring(ctx, tx, request); err != nil {
		slog.Error("system configuration node monitoring publication failed",
			"stage", "node_monitoring", "revision", request.Revision, "error", err)
		return nil, err
	}
	return results, nil
}

func (service *Service) publishNodeMonitoring(
	ctx context.Context,
	tx pgx.Tx,
	request systemconfig.ActivationPublicationRequest,
) error {
	if service == nil || service.nodeMonitoring == nil {
		return systemconfig.ErrInvalidStore
	}
	rows, err := tx.Query(ctx, `SELECT `+nodemonitoringoutbox.TargetColumns+` FROM nodes node `+
		nodemonitoringoutbox.TargetJoin+` WHERE `+nodemonitoringoutbox.ServingNodePredicate+` ORDER BY node.id FOR SHARE OF node`)
	if err != nil {
		return fmt.Errorf("load node monitoring publication targets: %w", err)
	}
	targets, err := nodemonitoringoutbox.ScanTargets(rows)
	if err != nil {
		return fmt.Errorf("load node monitoring publication targets: %w", err)
	}
	active := systemconfig.EffectiveNodeMonitoring(request.Configuration.NodeMonitoring)
	document := systemconfig.CategoryDocument{
		Schema:         "cdnca.system-configuration/v2",
		Category:       systemconfig.CategoryNodeMonitoring,
		HeadRevision:   request.Revision,
		ActiveRevision: request.Revision,
		Revision:       request.Revision,
		Status:         systemconfig.StatusActive,
		SnapshotSHA256: request.SnapshotSHA256,
		Value:          active,
	}
	for _, target := range targets {
		artifact, buildErr := target.Artifact(document, request.ActivatedAt)
		if buildErr != nil {
			return fmt.Errorf("build node monitoring artifact for %s: %w", target.NodeID, buildErr)
		}
		if err := service.nodeMonitoring.EnqueueNodeMonitoringArtifact(ctx, tx, artifact); err != nil {
			return fmt.Errorf("enqueue node monitoring artifact for %s: %w", target.NodeID, err)
		}
	}
	return nil
}

type publicationTarget struct {
	scopeID        uuid.UUID
	sourceRevision int64
	nodeIDs        []uuid.UUID
}

func loadTargets(ctx context.Context, tx pgx.Tx) ([]publicationTarget, error) {
	rows, err := tx.Query(ctx, `SELECT edge_scope.scope_id,edge_scope.source_revision
		FROM edge_configuration_scopes edge_scope
		JOIN access_scopes scope ON scope.id=edge_scope.scope_id AND scope.kind='tenant' AND scope.tenant_id IS NOT NULL
		WHERE (EXISTS (SELECT 1 FROM sites site WHERE site.scope_id=edge_scope.scope_id
		                    AND site.deleted_at IS NULL AND site.enabled)
		    OR EXISTS (SELECT 1 FROM l4_forwards stream WHERE stream.scope_id=edge_scope.scope_id
		                    AND stream.deleted_at IS NULL AND stream.enabled))
		  AND EXISTS (SELECT 1 FROM nodes node
		      JOIN access_scopes node_scope ON node_scope.id=node.scope_id
		      LEFT JOIN node_config_state config ON config.node_id=node.id
		        AND config.configuration_scope_id=edge_scope.scope_id
		      WHERE node.admin_state='active' AND (node.scope_id=edge_scope.scope_id OR
		          (node_scope.kind='platform' AND config.node_id IS NOT NULL)))
		ORDER BY edge_scope.scope_id FOR UPDATE OF edge_scope`)
	if err != nil {
		return nil, fmt.Errorf("load system configuration publication scopes: %w", err)
	}
	defer rows.Close()
	var targets []publicationTarget
	for rows.Next() {
		var target publicationTarget
		if err := rows.Scan(&target.scopeID, &target.sourceRevision); err != nil ||
			target.scopeID == uuid.Nil || target.sourceRevision < 1 {
			return nil, errors.New("invalid system configuration publication scope")
		}
		targets = append(targets, target)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate system configuration publication scopes: %w", err)
	}
	rows.Close()
	for index := range targets {
		nodeRows, queryErr := tx.Query(ctx, `SELECT node.id,node_scope.kind FROM nodes node
			JOIN access_scopes node_scope ON node_scope.id=node.scope_id
			LEFT JOIN node_config_state config ON config.node_id=node.id AND config.configuration_scope_id=$1
			WHERE node.admin_state='active' AND (node.scope_id=$1 OR
			    (node_scope.kind='platform' AND config.node_id IS NOT NULL))
			ORDER BY node.id FOR SHARE OF node`, targets[index].scopeID)
		if queryErr != nil {
			return nil, fmt.Errorf("load system configuration publication nodes: %w", queryErr)
		}
		var platformNodeIDs []uuid.UUID
		for nodeRows.Next() {
			var nodeID uuid.UUID
			var scopeKind string
			if scanErr := nodeRows.Scan(&nodeID, &scopeKind); scanErr != nil || nodeID == uuid.Nil {
				nodeRows.Close()
				return nil, errors.New("invalid system configuration publication node")
			}
			targets[index].nodeIDs = append(targets[index].nodeIDs, nodeID)
			if scopeKind == "platform" {
				platformNodeIDs = append(platformNodeIDs, nodeID)
			}
		}
		iterationErr := nodeRows.Err()
		nodeRows.Close()
		if iterationErr != nil || len(targets[index].nodeIDs) == 0 {
			return nil, errors.New("system configuration publication target has no active nodes")
		}
		if len(platformNodeIDs) == 0 {
			continue
		}
		// Hold existing platform bindings until publication finishes. Without
		// this lock, a concurrent unbind could turn discovery into a new claim.
		bindings, err := tx.Query(ctx, `SELECT node_id FROM node_config_state
			WHERE node_id=ANY($1::uuid[]) AND configuration_scope_id=$2
			ORDER BY node_id FOR SHARE`, platformNodeIDs, targets[index].scopeID)
		if err != nil {
			return nil, fmt.Errorf("lock system configuration platform bindings: %w", err)
		}
		seen := 0
		for bindings.Next() {
			var nodeID uuid.UUID
			if err := bindings.Scan(&nodeID); err != nil || seen >= len(platformNodeIDs) || nodeID != platformNodeIDs[seen] {
				bindings.Close()
				return nil, errors.New("system configuration platform binding changed")
			}
			seen++
		}
		iterationErr = bindings.Err()
		bindings.Close()
		if iterationErr != nil || seen != len(platformNodeIDs) {
			return nil, errors.New("system configuration platform binding changed")
		}
	}
	return targets, nil
}

func projectNginx(value systemconfig.Configuration) edgeconfig.NginxSettings {
	return systemconfig.EdgeNginxSettings(value)
}
