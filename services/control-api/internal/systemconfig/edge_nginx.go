package systemconfig

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ActiveEdgeNginx is the active platform revision's nginx base as edge
// publications carry it.
type ActiveEdgeNginx struct {
	PlatformScopeID uuid.UUID
	Revision        int64
	SnapshotSHA256  string
	Nginx           edgeconfig.NginxSettings
	// DDoS is the ddos_protection category when it turns something on.
	DDoS *edgeconfig.DDoSProtection
	// AccessLogFields is the effective access_log_fields category.
	AccessLogFields edgeconfig.AccessLogFields
}

// LoadActiveEdgeNginx reads the active system configuration in the caller's
// transaction. found is false when no platform has activated one (the node
// keeps its built-in defaults). More than one active platform stream fails.
func LoadActiveEdgeNginx(ctx context.Context, tx pgx.Tx) (ActiveEdgeNginx, bool, error) {
	rows, err := tx.Query(ctx, `SELECT platform_scope_id,active_revision FROM system_configuration_streams
		WHERE active_revision IS NOT NULL ORDER BY platform_scope_id LIMIT 2`)
	if err != nil {
		return ActiveEdgeNginx{}, false, fmt.Errorf("load active system configuration stream: %w", err)
	}
	var scopes []uuid.UUID
	var revisions []int64
	for rows.Next() {
		var scopeID uuid.UUID
		var revision int64
		if err := rows.Scan(&scopeID, &revision); err != nil {
			rows.Close()
			return ActiveEdgeNginx{}, false, fmt.Errorf("scan active system configuration stream: %w", err)
		}
		scopes, revisions = append(scopes, scopeID), append(revisions, revision)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return ActiveEdgeNginx{}, false, fmt.Errorf("iterate active system configuration streams: %w", err)
	}
	switch len(scopes) {
	case 0:
		return ActiveEdgeNginx{}, false, nil
	case 1:
	default:
		return ActiveEdgeNginx{}, false, errors.New("more than one platform has an active system configuration")
	}
	revision, err := loadRevision(ctx, tx, scopes[0], revisions[0])
	if err != nil {
		return ActiveEdgeNginx{}, false, fmt.Errorf("load active system configuration revision: %w", err)
	}
	if revision.Status != StatusActive {
		return ActiveEdgeNginx{}, false, errors.New("active system configuration revision is not active")
	}
	return ActiveEdgeNginx{PlatformScopeID: scopes[0], Revision: revision.Revision,
		SnapshotSHA256: revision.SnapshotSHA256, Nginx: EdgeNginxSettings(revision.Configuration),
		DDoS:            EdgeDDoSProtection(revision.Configuration.DDoSProtection),
		AccessLogFields: edgeconfig.EffectiveAccessLogFields(revision.Configuration.AccessLogFields)}, true, nil
}

// EdgeNginxSettings projects the stored nginx limits, and the website
// defaults' gzip switch and MIME types (网站默认 > 其它), onto
// the edge renderer. Sites with their own compression override them.
func EdgeNginxSettings(configuration Configuration) edgeconfig.NginxSettings {
	settings := edgeNginxLimits(configuration.Nginx)
	other := configuration.Defaults.Website.Other
	settings.GzipDisabled = !other.GzipEnabled
	if other.GzipEnabled && len(other.GzipTypes) != 0 {
		settings.GzipTypes = make([]string, 0, len(other.GzipTypes))
		for _, value := range other.GzipTypes {
			settings.GzipTypes = append(settings.GzipTypes, strings.ToLower(value))
		}
		slices.Sort(settings.GzipTypes)
		settings.GzipTypes = slices.Compact(settings.GzipTypes)
	}
	return settings
}

func edgeNginxLimits(value NginxLimits) edgeconfig.NginxSettings {
	return edgeconfig.NginxSettings{
		WorkerProcesses: value.WorkerProcesses, WorkerRlimitNoFile: value.WorkerRlimitNoFile,
		WorkerShutdownTimeout: time.Duration(value.WorkerShutdownTimeoutMS) * time.Millisecond,
		WorkerConnections:     value.WorkerConnections, ResolverAddresses: append([]string(nil), value.ResolverAddresses...),
		ResolverTimeout: time.Duration(value.ResolverTimeoutMS) * time.Millisecond,
		GzipLevel:       value.GzipLevel, GzipMinimumBytes: value.GzipMinimumBytes, GzipVary: value.GzipVary,
		ProxyBuffering: value.ProxyBuffering, ProxyCacheMethods: append([]string(nil), value.ProxyCacheMethods...),
		ProxyCacheMaxBytes: value.ProxyCacheMaxBytes, ProxyCacheZoneBytes: value.ProxyCacheZoneBytes,
		ProxyCacheMinFreeBytes: value.ProxyCacheMinFreeBytes,
		ProxyMaxTempFileBytes:  value.ProxyMaxTempFileBytes,
		ProxyConnectTimeout:    time.Duration(value.ProxyConnectTimeoutMS) * time.Millisecond,
		ProxySendTimeout:       time.Duration(value.ProxySendTimeoutMS) * time.Millisecond,
		ProxyReadTimeout:       time.Duration(value.ProxyReadTimeoutMS) * time.Millisecond,
		StreamProxyTimeout:     time.Duration(value.StreamProxyTimeoutMS) * time.Millisecond,
		ServerHeader:           value.ServerHeader, ClientMaxBodyBytes: value.ClientMaxBodyBytes,
		DefaultMIMEType: value.DefaultMIMEType, KeepaliveRequests: value.KeepaliveRequests,
		KeepaliveTimeout: time.Duration(value.KeepaliveTimeoutMS) * time.Millisecond,
		LogNotFound:      value.LogNotFound, ServerNamesHashMaxSize: value.ServerNamesHashMaxSize,
		ServerTokens: value.ServerTokens, GzipHTTPVersion: value.GzipHTTPVersion,
		ProxyRequestBufferingDisabled: !value.ProxyRequestBuffering, ProxyHTTPVersion: value.ProxyHTTPVersion,
		ProxyNextUpstream:            slices.Clone(value.ProxyNextUpstream),
		LargeClientHeaderBufferCount: value.LargeClientHeaderBuffers.Count,
		LargeClientHeaderBufferBytes: value.LargeClientHeaderBuffers.SizeBytes,
		ServerNamesHashBucketSize:    value.ServerNamesHashBucketSize, ServerAddrOutgoing: value.ServerAddrOutgoing,
		ClientBodyBufferBytes: value.ClientBodyBufferSizeBytes,
	}
}

// EdgeNodeTarget is a node a publication goes to and the region catalog
// display ID of its region ("" = none): the scope of region overrides.
type EdgeNodeTarget struct {
	NodeID   uuid.UUID
	RegionID string
}

// EdgeNodeNginxSettings is each target node's nginx base: the global
// values, then the node's region overrides, then its own (区域及节点配置,
// ResolveScopedConfiguration), for Nginx and for the website defaults the
// edge renders (gzip switch and types).
func EdgeNodeNginxSettings(configuration Configuration, targets []EdgeNodeTarget) (map[string]edgeconfig.NginxSettings, error) {
	result := make(map[string]edgeconfig.NginxSettings, len(targets))
	if len(configuration.Nginx.Overrides) == 0 && len(configuration.Defaults.Overrides) == 0 {
		return result, nil
	}
	for _, target := range targets {
		resolved, err := ResolveScopedConfiguration(configuration, target.RegionID, target.NodeID.String())
		if err != nil {
			return nil, fmt.Errorf("resolve node %s system configuration: %w", target.NodeID, err)
		}
		result[target.NodeID.String()] = EdgeNginxSettings(resolved)
	}
	return result, nil
}

// LoadEdgeNodeTargets maps nodes to their region's catalog display ID:
// nodes.region holds the region name, overrides name the catalog's
// display_id (category.go configurationReferencesAvailable). A catalogued
// region referenced by a live node cannot be renamed or deleted (235), so
// the mapping holds while the node is in it.
func LoadEdgeNodeTargets(ctx context.Context, tx pgx.Tx, nodeIDs []uuid.UUID) ([]EdgeNodeTarget, error) {
	rows, err := tx.Query(ctx, `SELECT node.id,COALESCE((SELECT region.display_id::text FROM region_catalog region
			JOIN access_scopes platform ON platform.id=region.platform_scope_id AND platform.kind='platform'
			WHERE region.name=btrim(node.region) LIMIT 1),'')
		FROM nodes node WHERE node.id=ANY($1::uuid[]) ORDER BY node.id`, nodeIDs)
	if err != nil {
		return nil, fmt.Errorf("load node regions: %w", err)
	}
	targets, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (EdgeNodeTarget, error) {
		var target EdgeNodeTarget
		return target, row.Scan(&target.NodeID, &target.RegionID)
	})
	if err != nil {
		return nil, fmt.Errorf("load node regions: %w", err)
	}
	return targets, nil
}

// LoadEdgeNodeNginx is EdgeNodeNginxSettings for a stored platform
// revision and the nodes' current regions.
func LoadEdgeNodeNginx(ctx context.Context, tx pgx.Tx, platformScopeID uuid.UUID, revision int64,
	nodeIDs []uuid.UUID) (map[string]edgeconfig.NginxSettings, error) {
	stored, err := loadRevision(ctx, tx, platformScopeID, revision)
	if err != nil {
		return nil, fmt.Errorf("load system configuration revision %d: %w", revision, err)
	}
	if len(stored.Configuration.Nginx.Overrides) == 0 && len(stored.Configuration.Defaults.Overrides) == 0 {
		return map[string]edgeconfig.NginxSettings{}, nil
	}
	targets, err := LoadEdgeNodeTargets(ctx, tx, nodeIDs)
	if err != nil {
		return nil, err
	}
	return EdgeNodeNginxSettings(stored.Configuration, targets)
}

// EdgeDDoSProtection is the ddos_protection category as edge publications
// carry it (the default when never saved). Never nil: with nothing on the
// block still carries the node networks (system.ddos.node_networks), which an
// L2 node trusts an L1's hop by; nodes install no table for it.
func EdgeDDoSProtection(value *edgeconfig.DDoSProtection) *edgeconfig.DDoSProtection {
	effective := EffectiveDDoSProtection(value)
	return &effective
}
