package edgepublish

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Site L2 of a node-list publication (fix-autol2b: "L1 直接按网站原来的回源端口连 L2，L2 再按原端口回源站，端口一路透传"):
// automatic, system and node-list publications carry no target snapshot,
// so each site's L2 is worked out at publication from the site's own line
// group (its node_group_id, else its package's primary group; the platform
// default group is not used):
//   - the line group's current revision names the L2 configuration and the
//     probe settings; l2_mode off / custom apply as under a snapshot;
//   - the L2 endpoints are the configuration's enabled members that are
//     publication targets (the automatic target set adds them,
//     edgeautopublish lineGroupNodeIDs), at the node's address, with its
//     current certificate as the mTLS identity;
//   - the L1 reaches them on the visitor's protocol and port (Passthrough;
//     the endpoint port is nominal) and an L2 node goes straight to the
//     origin (cdnca_origin, L2_ROUTING v2).
// A site without a line group, or whose configuration has no usable member,
// publishes without L2 and the reason goes to the publication audit.

// Reasons a site of a node-list publication goes without L2 (audit).
const (
	SiteL2SkippedNoLineGroup = "no_line_group"
	SiteL2SkippedNoL2Node    = "no_l2_node"
)

// siteL2PublicationSkip: a site left without L2 and why.
type siteL2PublicationSkip struct {
	SiteID uuid.UUID
	Reason string
}

// siteL2LineGroup is a line group revision as a site's L2 reads it.
type siteL2LineGroup struct {
	ID, ScopeID                                          uuid.UUID
	Revision                                             int64
	ProbeIntervalMS, FailureThreshold, RecoveryThreshold int
	ConfigID                                             *uuid.UUID
}

// siteL2Node is an L2 configuration member node as an endpoint reads it.
type siteL2Node struct {
	Address string
	MTLS    [sha256.Size]byte
}

// siteL2NominalPort: the port an L2 endpoint of a pass-through pool names
// (the node replaces it with the visitor's port).
const siteL2NominalPort = 80

// siteL2PublicationTopology is the publication's topology for a node-list
// target: per site (Sites), nil when no site has L2.
func siteL2PublicationTopology(
	ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, sourceRevision int64,
	facts []siteFact, targetNodeIDs []uuid.UUID, now time.Time,
) (*L2TopologySnapshot, []siteL2PublicationSkip, error) {
	if len(facts) == 0 || len(targetNodeIDs) == 0 {
		return nil, nil, nil
	}
	siteIDs := make([]uuid.UUID, len(facts))
	for index, fact := range facts {
		siteIDs[index] = fact.id
	}
	groups, err := loadSiteL2LineGroups(ctx, tx, scopeID, siteIDs)
	if err != nil {
		return nil, nil, err
	}
	// the line groups' configurations, read in each group's scope
	configs := map[uuid.UUID]*L2TopologyConfig{}
	byScope := map[uuid.UUID][]uuid.UUID{}
	for _, group := range groups {
		if group.ConfigID != nil && !slices.Contains(byScope[group.ScopeID], *group.ConfigID) {
			byScope[group.ScopeID] = append(byScope[group.ScopeID], *group.ConfigID)
		}
	}
	for configScope, ids := range byScope {
		loaded, err := loadL2TopologyConfigs(ctx, tx, configScope, ids)
		if err != nil {
			return nil, nil, err
		}
		for id, config := range loaded {
			configs[id] = config
		}
	}
	identities, err := siteL2TargetIdentities(ctx, tx, targetNodeIDs, now)
	if err != nil {
		return nil, nil, err
	}
	members := map[uuid.UUID]bool{}
	for _, fact := range facts {
		if fact.forwarding != nil && fact.forwarding.l2Config != nil {
			for _, member := range fact.forwarding.l2Config.Members {
				members[member.NodeID] = true
			}
		}
	}
	for _, config := range configs {
		for _, member := range config.Members {
			members[member.NodeID] = true
		}
	}
	nodes := map[uuid.UUID]siteL2Node{}
	for nodeID := range members {
		if !slices.Contains(targetNodeIDs, nodeID) {
			continue
		}
		node, err := loadSiteL2Node(ctx, tx, nodeID, now)
		if err != nil {
			return nil, nil, err
		}
		if node != nil {
			nodes[nodeID] = *node
		}
	}
	return resolveSiteL2Publication(sourceRevision, facts, groups, configs, identities, nodes)
}

// resolveSiteL2Publication works each site's L2 out of the read facts:
// groups by site, configurations by id, the targets' L1 identities and the
// usable L2 nodes (targets with an address and a current certificate).
func resolveSiteL2Publication(
	sourceRevision int64, facts []siteFact, groups map[uuid.UUID]siteL2LineGroup,
	configs map[uuid.UUID]*L2TopologyConfig, identities []L2TopologyIdentity, nodes map[uuid.UUID]siteL2Node,
) (*L2TopologySnapshot, []siteL2PublicationSkip, error) {
	if len(identities) == 0 {
		return nil, nil, nil
	}
	var skipped []siteL2PublicationSkip
	result := &L2TopologySnapshot{Revision: sourceRevision, SourceRevision: sourceRevision, Passthrough: true,
		TargetIdentities: identities, Sites: map[uuid.UUID]*L2TopologySnapshot{}}
	for _, fact := range facts {
		mode := "package"
		if fact.forwarding != nil && fact.forwarding.l2Mode != "" {
			mode = fact.forwarding.l2Mode
		}
		group, hasGroup := groups[fact.id]
		var config *L2TopologyConfig
		switch mode {
		case "off":
			continue
		case "package":
			if !hasGroup {
				skipped = append(skipped, siteL2PublicationSkip{SiteID: fact.id, Reason: SiteL2SkippedNoLineGroup})
				continue
			}
			if group.ConfigID == nil {
				continue // the line group names no L2 configuration: no L2
			}
			config = configs[*group.ConfigID]
		case "custom":
			config = fact.forwarding.l2Config
		default:
			return nil, nil, ErrInvalidInput
		}
		if config == nil {
			skipped = append(skipped, siteL2PublicationSkip{SiteID: fact.id, Reason: SiteL2SkippedNoL2Node})
			continue
		}
		site := &L2TopologySnapshot{Revision: sourceRevision, SourceRevision: sourceRevision, Passthrough: true,
			TargetIdentities: identities, ProbeIntervalMS: 10000, FailureThreshold: 3, RecoveryThreshold: 3}
		if hasGroup {
			site.SourceLineGroupID, site.SourceRevision = group.ID, group.Revision
			site.ProbeIntervalMS, site.FailureThreshold, site.RecoveryThreshold =
				group.ProbeIntervalMS, group.FailureThreshold, group.RecoveryThreshold
		}
		for _, member := range config.Members {
			node, ok := nodes[member.NodeID]
			if !ok || slices.ContainsFunc(site.Endpoints, func(endpoint L2TopologyEndpoint) bool {
				return endpoint.NodeID == member.NodeID
			}) {
				continue // not a usable target of this publication (or listed twice)
			}
			site.Endpoints = append(site.Endpoints, L2TopologyEndpoint{
				// one id per configuration member node: stable across publications
				EndpointID: uuid.NewSHA1(config.ID, member.NodeID[:]), NodeID: member.NodeID,
				Address: node.Address, Port: siteL2NominalPort, Weight: member.Weight, MTLSIdentitySHA256: node.MTLS,
			})
		}
		// the members' conditions and weights as under a snapshot (siteL2Topology)
		selected, err := siteL2Topology(site, siteFact{id: fact.id, forwarding: &originForwardingFact{
			l2Mode: "custom", l2Config: config}})
		if errors.Is(err, ErrSiteL2Unavailable) {
			skipped = append(skipped, siteL2PublicationSkip{SiteID: fact.id, Reason: SiteL2SkippedNoL2Node})
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		result.Sites[fact.id] = selected
	}
	if len(result.Sites) == 0 {
		return nil, skipped, nil
	}
	return result, skipped, nil
}

// loadSiteL2LineGroups: each site's line group (its own, else its package's
// primary group), current revision, live.
func loadSiteL2LineGroups(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, siteIDs []uuid.UUID) (map[uuid.UUID]siteL2LineGroup, error) {
	rows, err := tx.Query(ctx, `SELECT site.id,line_group.id,line_group.tenant_scope_id,revision.revision,
		       revision.probe_interval_ms,revision.failure_threshold,revision.recovery_threshold,revision.l2_config_id
		FROM sites site
		LEFT JOIN package_subscriptions subscription ON subscription.tenant_scope_id=site.scope_id
		 AND subscription.id=site.package_subscription_id AND subscription.deleted_at IS NULL
		JOIN node_line_groups line_group ON line_group.deleted_at IS NULL AND line_group.id=COALESCE(site.node_group_id,
		     (subscription.product_snapshot->'spec'->>'node_group_id')::uuid)
		JOIN node_line_group_revisions revision ON revision.tenant_scope_id=line_group.tenant_scope_id
		 AND revision.line_group_id=line_group.id AND revision.revision=line_group.current_revision
		WHERE site.scope_id=$1 AND site.id=ANY($2::uuid[]) AND site.deleted_at IS NULL
		ORDER BY site.id FOR SHARE OF line_group`, scopeID, siteIDs)
	if err != nil {
		return nil, fmt.Errorf("%w: load site line groups", ErrPersistence)
	}
	defer rows.Close()
	result := make(map[uuid.UUID]siteL2LineGroup, len(siteIDs))
	for rows.Next() {
		var siteID uuid.UUID
		var group siteL2LineGroup
		if err := rows.Scan(&siteID, &group.ID, &group.ScopeID, &group.Revision, &group.ProbeIntervalMS,
			&group.FailureThreshold, &group.RecoveryThreshold, &group.ConfigID); err != nil {
			return nil, fmt.Errorf("%w: scan site line group", ErrPersistence)
		}
		result[siteID] = group
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: iterate site line groups", ErrPersistence)
	}
	return result, nil
}

// siteL2TargetIdentities: the publication's targets as L1 identities, with
// the location L2 condition node rules match; one without a current
// certificate is left out.
func siteL2TargetIdentities(ctx context.Context, tx pgx.Tx, nodeIDs []uuid.UUID, now time.Time) ([]L2TopologyIdentity, error) {
	rows, err := tx.Query(ctx, `SELECT node.id,COALESCE((`+siteL2CurrentCertificateLateral+`),'\x'::bytea),
		COALESCE(node.display_id::text,''),COALESCE(node.management_settings#>>'{ip_location,country_code}',''),
		COALESCE(node.management_settings#>>'{ip_location,isp}',''),
		COALESCE(node.management_settings#>>'{ip_location,province}',''),
		COALESCE(node.management_settings#>>'{ip_location,city}','')
		FROM nodes node WHERE node.id=ANY($1::uuid[]) ORDER BY node.id`, nodeIDs, now)
	if err != nil {
		return nil, fmt.Errorf("%w: load L1 identities", ErrPersistence)
	}
	defer rows.Close()
	var result []L2TopologyIdentity
	for rows.Next() {
		var identity L2TopologyIdentity
		var digest []byte
		if err := rows.Scan(&identity.NodeID, &digest, &identity.Location.DisplayID, &identity.Location.CountryCode,
			&identity.Location.ISP, &identity.Location.Province, &identity.Location.City); err != nil {
			return nil, fmt.Errorf("%w: scan L1 identity", ErrPersistence)
		}
		if len(digest) != sha256.Size {
			continue // no current certificate: never an L1 of an L2 hop
		}
		copy(identity.MTLSIdentitySHA256[:], digest)
		result = append(result, identity)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: iterate L1 identities", ErrPersistence)
	}
	return result, nil
}

// siteL2CurrentCertificateLateral: siteL2CurrentCertificate for node.id at $2.
const siteL2CurrentCertificateLateral = `SELECT COALESCE(current.leaf_der_sha256,current.leaf_certificate_sha256)
	FROM node_certificates current
	WHERE current.node_id=node.id AND current.status='active' AND current.not_before <= $2 AND current.not_after > $2
	  AND (current.rotation_status IN ('current','overlap') OR current.rotation_status='legacy_unbound')
	ORDER BY current.issued_at DESC,current.id DESC LIMIT 1`

// loadSiteL2Node: an active member node's address (IPv4, else IPv6) and
// current certificate; nil when it lacks either.
func loadSiteL2Node(ctx context.Context, tx pgx.Tx, nodeID uuid.UUID, now time.Time) (*siteL2Node, error) {
	var address string
	var digest []byte
	err := tx.QueryRow(ctx, `SELECT COALESCE(host(node.ipv4),host(node.ipv6),''),
		COALESCE((`+siteL2CurrentCertificateLateral+`),'\x'::bytea)
		FROM nodes node WHERE node.id=$1 AND node.admin_state='active'`, nodeID, now).Scan(&address, &digest)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (address == "" || len(digest) != sha256.Size) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: load L2 node", ErrPersistence)
	}
	node := &siteL2Node{Address: address}
	copy(node.MTLS[:], digest)
	return node, nil
}

// siteL2SkippedPayload: the publication audit's "未走 L2" list, by site:
// no_line_group (无线路分组) / no_l2_node (L2 配置无可用节点).
func siteL2SkippedPayload(skipped []siteL2PublicationSkip) []map[string]string {
	result := make([]map[string]string, len(skipped))
	for index, value := range skipped {
		result[index] = map[string]string{"site_id": value.SiteID.String(), "reason": value.Reason}
	}
	return result
}
