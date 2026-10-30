package edgepublish

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cdnca/cdnca/services/control-api/internal/systemconfig"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const systemConfigurationPermission = "system_configuration.manage"

// PublishSystemConfigurationTx is the only platform-authority path into the
// tenant Edge publication transaction. It revalidates the real platform actor
// and the immutable system revision before advancing any tenant source fact.
func (s *Service) PublishSystemConfigurationTx(
	ctx context.Context,
	tx pgx.Tx,
	request SystemConfigurationPublishRequest,
) (PublishResult, error) {
	if s == nil || ctx == nil || tx == nil || request.Actor.UserID == uuid.Nil ||
		request.Actor.ScopeID == uuid.Nil || request.Actor.ScopeKind != ScopeKindPlatform ||
		request.PlatformScopeID == uuid.Nil || request.Actor.ScopeID != request.PlatformScopeID ||
		request.Revision < 1 || request.SnapshotSHA256 == ([32]byte{}) ||
		request.ConfigurationScopeID == uuid.Nil || request.ExpectedSourceRevision < 1 || len(request.NodeIDs) == 0 {
		return PublishResult{}, ErrInvalidInput
	}
	if err := authorizeSystemConfigurationActor(ctx, tx, request.Actor); err != nil {
		return PublishResult{}, err
	}
	var storedHash []byte
	var status string
	if err := tx.QueryRow(ctx, `SELECT snapshot_sha256,status FROM system_configuration_revisions
		WHERE platform_scope_id=$1 AND revision=$2 FOR SHARE`, request.PlatformScopeID, request.Revision).
		Scan(&storedHash, &status); errors.Is(err, pgx.ErrNoRows) {
		return PublishResult{}, ErrInvalidInput
	} else if err != nil {
		return PublishResult{}, fmt.Errorf("%w: load system configuration revision", ErrPersistence)
	}
	if status != "validated" || !bytes.Equal(storedHash, request.SnapshotSHA256[:]) {
		return PublishResult{}, ErrRevisionConflict
	}
	now := s.config.Clock().UTC().Truncate(time.Microsecond)
	var nextRevision int64
	if err := tx.QueryRow(ctx, `UPDATE edge_configuration_scopes
		SET source_revision=source_revision+1,updated_at=$3
		WHERE scope_id=$1 AND source_revision=$2 AND source_revision<9223372036854775806
		RETURNING source_revision`, request.ConfigurationScopeID, request.ExpectedSourceRevision, now).
		Scan(&nextRevision); errors.Is(err, pgx.ErrNoRows) {
		return PublishResult{}, ErrRevisionConflict
	} else if err != nil {
		return PublishResult{}, fmt.Errorf("%w: advance system configuration tenant source revision", ErrPersistence)
	}
	source := &SystemConfigurationSource{
		PlatformScopeID: request.PlatformScopeID, Revision: request.Revision,
		SnapshotSHA256: request.SnapshotSHA256, Nginx: request.Nginx, DDoS: request.DDoS, AccessLogFields: request.AccessLogFields,
	}
	source.Nginx.ResolverAddresses = slices.Clone(request.Nginx.ResolverAddresses)
	source.Nginx.ProxyCacheMethods = slices.Clone(request.Nginx.ProxyCacheMethods)
	publish := PublishRequest{
		Actor: request.Actor, ConfigurationScopeID: request.ConfigurationScopeID,
		ExpectedSourceRevision: nextRevision, NodeIDs: slices.Clone(request.NodeIDs),
		HealthCheck: edgedeployment.HealthCheckPolicy{
			ActivationTimeout: time.Minute, ObservationWindow: 10 * time.Second,
			RequiredConsecutiveSuccesses: 3,
		},
		MaxAttempts: 3, Deadline: now.Add(15 * time.Minute), IdempotencyKey: request.IdempotencyKey,
		RequestID: request.RequestID, CorrelationID: request.CorrelationID, SystemConfiguration: source,
	}
	normalizeInput := publish
	normalizeInput.SystemConfiguration = nil
	normalized, err := normalizeAutomaticPublishRequest(normalizeInput, now)
	if err != nil {
		return PublishResult{}, err
	}
	normalized.SystemConfiguration = source
	result, err := s.publishAuthorizedTx(ctx, tx, normalized, now)
	if err != nil {
		return PublishResult{}, err
	}
	if result.SourceRevision != nextRevision || result.ConfigurationScopeID != request.ConfigurationScopeID {
		return PublishResult{}, fmt.Errorf("%w: system configuration publication identity mismatch", ErrPersistence)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO system_configuration_edge_publications(
		platform_scope_id,system_revision,system_snapshot_sha256,tenant_scope_id,tenant_source_revision,
		publication_id,config_version_id,rollout_id,artifact_sha256,reason_code,created_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'system_configuration_activated',$10)`,
		request.PlatformScopeID, request.Revision, request.SnapshotSHA256[:], request.ConfigurationScopeID,
		nextRevision, result.PublicationID, result.ConfigVersionID, result.RolloutID, result.ArtifactSHA256[:], now); err != nil {
		return PublishResult{}, fmt.Errorf("%w: bind system configuration publication", ErrPersistence)
	}
	return result, nil
}

func authorizeSystemConfigurationActor(ctx context.Context, tx pgx.Tx, actor Actor) error {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended(
		'system-configuration-authorization:' || $1::text || ':' || $2::text,0))`, actor.ScopeID, actor.UserID); err != nil {
		return fmt.Errorf("%w: lock system configuration authority", ErrPersistence)
	}
	var kind, accountStatus, membershipStatus string
	var tenantID *uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT scope.kind,scope.tenant_id,account.status,membership.status
		FROM access_scopes scope
		JOIN users account ON account.id=$2
		JOIN memberships membership ON membership.scope_id=scope.id AND membership.user_id=account.id
		WHERE scope.id=$1 FOR UPDATE OF scope,account,membership`, actor.ScopeID, actor.UserID).
		Scan(&kind, &tenantID, &accountStatus, &membershipStatus); errors.Is(err, pgx.ErrNoRows) {
		return ErrPermissionDenied
	} else if err != nil {
		return fmt.Errorf("%w: validate system configuration actor", ErrPersistence)
	}
	if kind != ScopeKindPlatform || tenantID != nil || accountStatus != "active" || membershipStatus != "active" {
		return ErrPermissionDenied
	}
	var roleID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT assignment.role_id
		FROM role_assignments assignment
		JOIN roles role ON role.id=assignment.role_id AND role.scope_id=assignment.scope_id
		JOIN role_permissions grant_row ON grant_row.role_id=role.id
		WHERE assignment.scope_id=$1 AND assignment.user_id=$2 AND grant_row.permission_name IN ($3,'platform.admin')
		ORDER BY assignment.role_id LIMIT 1 FOR UPDATE OF assignment,role,grant_row`,
		actor.ScopeID, actor.UserID, systemConfigurationPermission).Scan(&roleID); errors.Is(err, pgx.ErrNoRows) {
		return ErrPermissionDenied
	} else if err != nil {
		return fmt.Errorf("%w: validate system configuration permission", ErrPersistence)
	}
	return nil
}

// loadSiteRuntimeV2System is the system block a v2 publication carries: the
// activation's own revision when one is being published, otherwise the
// platform's active revision, so a tenant publication never drops the
// platform values (the v1 renderer only carried them on activation). nil
// before any activation. Activation locks every tenant scope it republishes
// before it switches the active revision, and this read follows the scope
// lock, so a concurrent tenant publication carries the new revision.
//
// nodeIDs are the publication's target nodes: each gets its own nginx base
// when region or node overrides change it (node_nginx, refreshNodeNginx).
func loadSiteRuntimeV2System(ctx context.Context, tx pgx.Tx, source *SystemConfigurationSource,
	nodeIDs []uuid.UUID) (*edgeconfig.SiteRuntimeSystem, error) {
	var (
		platformScopeID uuid.UUID
		revision        int64
		digest          string
		settings        edgeconfig.NginxSettings
		ddos            *edgeconfig.DDoSProtection
	)
	if source != nil {
		platformScopeID, revision, digest, settings, ddos = source.PlatformScopeID, source.Revision,
			hex.EncodeToString(source.SnapshotSHA256[:]), source.Nginx, source.DDoS
	} else {
		active, found, err := systemconfig.LoadActiveEdgeNginx(ctx, tx)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrPersistence, err)
		}
		if !found {
			return nil, nil
		}
		platformScopeID, revision, digest, settings, ddos = active.PlatformScopeID, active.Revision, active.SnapshotSHA256, active.Nginx, active.DDoS
	}
	system, err := edgeconfig.NewSiteRuntimeSystem(platformScopeID.String(), revision, digest, settings)
	if err != nil {
		return nil, ErrInvalidInput
	}
	if ddos != nil {
		networks, err := loadNodeNetworks(ctx, tx)
		if err != nil {
			return nil, err
		}
		value, err := edgeconfig.NewSiteRuntimeDDoS(*ddos, networks)
		if err != nil {
			return nil, ErrInvalidInput
		}
		system.DDoS = &value
	}
	return refreshNodeNginx(ctx, tx, &system, nodeIDs)
}

// refreshNodeNginx sets system's per-node nginx bases for nodeIDs from its
// platform revision and the nodes' current regions (区域及节点配置). A node
// changing region, or a region override, is a platform fact: the stop
// overlay refreshes it as it does node networks.
func refreshNodeNginx(ctx context.Context, tx pgx.Tx, system *edgeconfig.SiteRuntimeSystem,
	nodeIDs []uuid.UUID) (*edgeconfig.SiteRuntimeSystem, error) {
	if system == nil {
		return nil, nil
	}
	platformScopeID, err := uuid.Parse(system.PlatformScopeID)
	if err != nil {
		return nil, ErrInvalidInput
	}
	nodes, err := systemconfig.LoadEdgeNodeNginx(ctx, tx, platformScopeID, system.Revision, nodeIDs)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	refreshed, err := system.WithNodeNginx(nodes)
	if err != nil {
		return nil, ErrInvalidInput
	}
	return &refreshed, nil
}

// loadNodeNetworks is every registered node's addresses (primary IPv4/IPv6
// and secondary IPs) that DDoS protection exempts: node to node traffic (L1
// to L2 origin requests, probes) is a node's own, never an attack. Retired
// nodes are left out.
func loadNodeNetworks(ctx context.Context, tx pgx.Tx) ([]string, error) {
	rows, err := tx.Query(ctx, `SELECT DISTINCT address FROM (
		SELECT host(ipv4) AS address FROM nodes WHERE ipv4 IS NOT NULL AND admin_state<>'retired'
		UNION SELECT host(ipv6) FROM nodes WHERE ipv6 IS NOT NULL AND admin_state<>'retired'
		UNION SELECT secondary.value FROM nodes node,
		    jsonb_array_elements_text(COALESCE(node.management_settings->'secondary_ips','[]'::jsonb)) secondary(value)
		    WHERE node.admin_state<>'retired'
	) addresses ORDER BY address LIMIT $1`, edgeconfig.DDoSMaxNodeNetworks+1)
	if err != nil {
		return nil, fmt.Errorf("%w: load node networks", ErrPersistence)
	}
	defer rows.Close()
	networks := []string{}
	for rows.Next() {
		var address string
		if err := rows.Scan(&address); err != nil {
			return nil, fmt.Errorf("%w: scan node network", ErrPersistence)
		}
		networks = append(networks, address)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: iterate node networks", ErrPersistence)
	}
	if len(networks) > edgeconfig.DDoSMaxNodeNetworks {
		return nil, fmt.Errorf("%w: more than %d node addresses", ErrInvalidInput, edgeconfig.DDoSMaxNodeNetworks)
	}
	return networks, nil
}
