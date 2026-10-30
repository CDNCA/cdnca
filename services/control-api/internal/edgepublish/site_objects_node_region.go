package edgepublish

import (
	"context"
	"fmt"

	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Node regions: a node's region is the control plane's fact
// (nodes.region names a region catalog entry), so the node is told its
// region's code (region_catalog.code, migration 525) in its key document
// (siteobject.KeyDocument.NodeRegion, NODE_REGION v1) and has no region
// setting of its own. Error page region overrides and origin routes'
// node_regions name the same code.

// loadNodeRegionCodes maps each node to its region's code; a node without a
// region (or whose region is not catalogued) is absent.
func loadNodeRegionCodes(ctx context.Context, tx pgx.Tx, nodeIDs []uuid.UUID) (map[uuid.UUID]string, error) {
	rows, err := tx.Query(ctx, `SELECT node.id,region.code FROM nodes node
		JOIN LATERAL (SELECT catalog.code FROM region_catalog catalog
			JOIN access_scopes platform ON platform.id=catalog.platform_scope_id AND platform.kind='platform'
			WHERE catalog.name=btrim(node.region) ORDER BY catalog.display_id LIMIT 1) region ON true
		WHERE node.id=ANY($1::uuid[])`, nodeIDs)
	if err != nil {
		return nil, fmt.Errorf("%w: load node region codes", ErrPersistence)
	}
	defer rows.Close()
	codes := make(map[uuid.UUID]string, len(nodeIDs))
	for rows.Next() {
		var nodeID uuid.UUID
		var code string
		if err := rows.Scan(&nodeID, &code); err != nil {
			return nil, fmt.Errorf("%w: scan node region code", ErrPersistence)
		}
		codes[nodeID] = code
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: iterate node region codes", ErrPersistence)
	}
	return codes, nil
}

// nodeRegionFor is the region code a node's key document carries: only for
// an Agent declaring NODE_REGION (an older node picks nothing by region).
func nodeRegionFor(advertised []*agentv1.Capability, code string) string {
	for _, capability := range advertised {
		if capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_NODE_REGION &&
			capability.GetApiVersion() >= siteobject.NodeRegionAPIVersion {
			return code
		}
	}
	return ""
}

// NodeRegionScopesTx is, in scope order, every tenant scope with a
// publication: a node changing region changes the region code its key
// documents carry, so each scope is republished (region changes are rare;
// which scopes the node serves is the publication's business).
func NodeRegionScopesTx(ctx context.Context, tx pgx.Tx) ([]uuid.UUID, error) {
	if ctx == nil || tx == nil {
		return nil, ErrInvalidInput
	}
	releases, err := latestTenantReleasesTx(ctx, tx)
	if err != nil {
		return nil, err
	}
	scopes := make([]uuid.UUID, 0, len(releases))
	for _, release := range releases {
		scopes = append(scopes, release.scopeID)
	}
	return scopes, nil
}
