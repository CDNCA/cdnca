package edgepublish

import (
	"context"
	"fmt"
	"sort"

	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Per-node websites, the site counterpart of per-node L4
// forwards (site_objects_stream_selection.go): the release is one signed
// root for every target node, so each node used to serve every website of
// the scope, also after it left a website's line group or the website moved
// to another group, until the scope had no website left. A website is served
// by the nodes of its line groups (its own, its package's primary and backup
// group, its escalation route's groups) and the members of its L2
// configuration, the sets automatic publication targets
// (edgeautopublish.lineGroupNodeIDs). The node's key document, sealed for it
// alone, names the root's websites it does not serve
// (siteobject.KeyDocument.WithheldSites). The root and its signature are
// unchanged.

// siteServingNodes maps each of the release's websites whose line groups
// resolve (at least one live group) to the nodes serving them: the enabled
// endpoints of the groups' current revisions plus the enabled members of the
// website's L2 configuration. A website absent from the map has no live line
// group to go by and is served by every target node, as before; a website
// whose groups have no serving node maps to an empty set (served by none).
func siteServingNodes(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, siteIDs []string,
) (map[string]map[uuid.UUID]struct{}, error) {
	if len(siteIDs) == 0 {
		return nil, nil
	}
	ids := make([]uuid.UUID, 0, len(siteIDs))
	for _, siteID := range siteIDs {
		id, err := uuid.Parse(siteID)
		if err != nil {
			return nil, fmt.Errorf("%w: release website id", ErrInvalidInput)
		}
		ids = append(ids, id)
	}
	// Branch 1 resolves the website (a row even without an endpoint);
	// branch 2 adds its L2 members, only to a website branch 1 resolved.
	rows, err := tx.Query(ctx, `
		SELECT site.id::text,endpoint.node_id,false
		FROM sites site
		LEFT JOIN package_subscriptions subscription ON subscription.tenant_scope_id=site.scope_id
		 AND subscription.id=site.package_subscription_id AND subscription.deleted_at IS NULL
		LEFT JOIN escalate_site_routes route ON route.tenant_scope_id=site.scope_id AND route.site_id=site.id
		JOIN node_line_groups line_group ON line_group.deleted_at IS NULL AND line_group.id IN (
		     site.node_group_id,
		     (subscription.product_snapshot->'spec'->>'node_group_id')::uuid,
		     (subscription.product_snapshot->'spec'->>'backup_node_group_id')::uuid,
		     route.line_group_id, route.next_group_id)
		LEFT JOIN node_line_endpoints endpoint ON endpoint.tenant_scope_id=line_group.tenant_scope_id
		 AND endpoint.line_group_id=line_group.id AND endpoint.config_revision=line_group.current_revision
		 AND endpoint.enabled AND endpoint.node_id IS NOT NULL
		 AND line_group.tenant_scope_id IN (site.scope_id,(SELECT scope_id FROM nodes WHERE id=endpoint.node_id))
		WHERE site.scope_id=$1 AND site.id=ANY($2::uuid[]) AND site.deleted_at IS NULL
		UNION ALL
		SELECT site.id::text,member.node_id,true
		FROM sites site
		JOIN site_origin_pools pool ON pool.site_id=site.id AND pool.l2_mode<>'off'
		LEFT JOIN package_subscriptions subscription ON subscription.tenant_scope_id=site.scope_id
		 AND subscription.id=site.package_subscription_id AND subscription.deleted_at IS NULL
		LEFT JOIN node_line_groups line_group ON pool.l2_mode='package' AND line_group.deleted_at IS NULL
		 AND line_group.id=COALESCE(site.node_group_id, (subscription.product_snapshot->'spec'->>'node_group_id')::uuid)
		JOIN l2_topology_configs config ON config.deleted_at IS NULL AND (
		     pool.l2_mode='custom' AND config.tenant_scope_id=site.scope_id AND config.id=pool.l2_config_id OR
		     pool.l2_mode='package' AND config.tenant_scope_id=line_group.tenant_scope_id AND config.id=line_group.l2_config_id)
		JOIN l2_topology_nodes member ON member.tenant_scope_id=config.tenant_scope_id AND member.config_id=config.id
		 AND member.enabled AND member.deleted_at IS NULL
		WHERE site.scope_id=$1 AND site.id=ANY($2::uuid[]) AND site.deleted_at IS NULL`, scopeID, ids)
	if err != nil {
		return nil, fmt.Errorf("%w: read website line group nodes", ErrPersistence)
	}
	defer rows.Close()
	result := make(map[string]map[uuid.UUID]struct{})
	type member struct {
		siteID string
		nodeID uuid.UUID
	}
	var members []member // L2 rows, applied once every website is resolved
	for rows.Next() {
		var siteID string
		var nodeID *uuid.UUID
		var l2Member bool
		if err := rows.Scan(&siteID, &nodeID, &l2Member); err != nil {
			return nil, fmt.Errorf("%w: scan website line group nodes", ErrPersistence)
		}
		if l2Member {
			members = append(members, member{siteID, *nodeID})
			continue
		}
		nodes := result[siteID]
		if nodes == nil {
			nodes = make(map[uuid.UUID]struct{})
			result[siteID] = nodes
		}
		if nodeID != nil {
			nodes[*nodeID] = struct{}{}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: iterate website line group nodes", ErrPersistence)
	}
	for _, l2 := range members {
		if nodes := result[l2.siteID]; nodes != nil {
			nodes[l2.nodeID] = struct{}{}
		}
	}
	return result, nil
}

// withheldSitesFor is what node's key document withholds: the release's
// websites with a line group none of whose nodes is node, when the node
// declares SITE_SELECTION; else none (an older node serves them all) and
// unsupported says whether it would have been withheld any (the
// publication reports such a node).
func withheldSitesFor(advertised []*agentv1.Capability, nodeID uuid.UUID, siteIDs []string,
	serving map[string]map[uuid.UUID]struct{}) (withheld []string, unsupported bool) {
	if len(siteIDs) == 0 || len(serving) == 0 {
		return nil, false
	}
	for _, siteID := range siteIDs {
		nodes, resolved := serving[siteID]
		if !resolved {
			continue
		}
		if _, serves := nodes[nodeID]; !serves {
			withheld = append(withheld, siteID)
		}
	}
	if !declaresSiteSelection(advertised) {
		return nil, len(withheld) > 0
	}
	sort.Strings(withheld)
	return withheld, false
}

func declaresSiteSelection(advertised []*agentv1.Capability) bool {
	for _, capability := range advertised {
		if capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_SITE_SELECTION &&
			capability.GetApiVersion() >= siteobject.SiteSelectionAPIVersion {
			return true
		}
	}
	return false
}

func withheldSet(siteIDs []string) map[string]bool {
	if len(siteIDs) == 0 {
		return nil
	}
	set := make(map[string]bool, len(siteIDs))
	for _, id := range siteIDs {
		set[id] = true
	}
	return set
}

// keyEnvelopeFits refuses a release whose key envelope for nodeID is larger
// than its Agent takes: siteobject.MaxKeyEnvelopeBytes for an
// Agent declaring SITE_SELECTION v1, else the 4096
// bytes of the Agents before it (their withheld forwards / traffic stop
// lists are the only growing fields). The node would otherwise refuse every
// release of the scope after commit.
func keyEnvelopeFits(nodeID uuid.UUID, advertised []*agentv1.Capability, size uint64) error {
	if declaresSiteSelection(advertised) {
		if size > siteobject.MaxKeyEnvelopeBytes {
			return fmt.Errorf("%w: site object key envelope for node %s is %d bytes, more than the %d an agent takes",
				ErrInvalidInput, nodeID, size, siteobject.MaxKeyEnvelopeBytes)
		}
		return nil
	}
	if size <= siteobject.LegacyMaxKeyEnvelopeBytes {
		return nil
	}
	var declared uint32
	for _, capability := range advertised {
		if capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_SITE_SELECTION {
			declared = capability.GetApiVersion()
		}
	}
	return &TargetCapabilityError{NodeID: nodeID, Feature: fmt.Sprintf(
		"a site object key document of %d bytes (more than the %d an agent before SITE_SELECTION takes: too many withheld L4 forwards or traffic stopped forwards; 节点版本过旧，本次下发的密钥文档超出其上限，请升级节点)",
		size, siteobject.LegacyMaxKeyEnvelopeBytes), Capability: agentv1.CapabilityName_CAPABILITY_NAME_SITE_SELECTION,
		Required: siteobject.SiteSelectionAPIVersion, Advertised: declared}
}

// oversizedKeyEnvelope is a target node left out of a release because its
// key envelope is larger than its older Agent takes (keyEnvelopeFits).
type oversizedKeyEnvelope struct {
	refusal   *TargetCapabilityError
	sizeBytes uint64
}

// KeyEnvelopeOversizedError names every target node whose Agent predates
// SITE_SELECTION and cannot take its key envelope. publishRoundTx publishes
// to the other nodes instead; when no node is left it unwraps to the first
// node's TargetCapabilityError.
type KeyEnvelopeOversizedError struct {
	Nodes []oversizedKeyEnvelope
}

func (e *KeyEnvelopeOversizedError) Error() string {
	return e.Nodes[0].refusal.Error()
}

func (e *KeyEnvelopeOversizedError) Unwrap() error {
	return e.Nodes[0].refusal
}

// keyEnvelopeOversizedPayload is the publication audit entry of the nodes
// left out: they keep their previous configuration, so websites withheld and
// forwards deleted by this release still serve there until they upgrade.
func keyEnvelopeOversizedPayload(nodes []oversizedKeyEnvelope) []map[string]any {
	result := make([]map[string]any, len(nodes))
	for index, node := range nodes {
		result[index] = map[string]any{
			"node_id": node.refusal.NodeID.String(), "key_envelope_bytes": node.sizeBytes,
			"limit_bytes": siteobject.LegacyMaxKeyEnvelopeBytes,
			"reason":      "节点版本过旧（未声明 SITE_SELECTION），本次密钥文档超出其上限，未下发本版本；旧配置仍生效，本次新屏蔽的站点、删除的转发在该节点上仍然生效。升级节点到支持能力 82（SITE_SELECTION）的版本即可",
		}
	}
	return result
}
