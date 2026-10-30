package nodescheduler

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

// attachPublished fills Endpoint.Published from node_line_endpoint_published
// (migration 501: per carrier and address family) for the loaded revision, so
// the line resolution table can show whether DNS actually publishes each IP.
// An endpoint missing from the view keeps Published nil (unknown).
func attachPublished(ctx context.Context, pool revisionQuerier, group *LineGroupRevision) error {
	if len(group.Endpoints) == 0 {
		return nil
	}
	rows, err := pool.Query(ctx, `
		SELECT endpoint_id,published FROM node_line_endpoint_published
		WHERE tenant_scope_id=$1 AND line_group_id=$2 AND config_revision=$3`,
		group.TenantScopeID, group.GroupID, group.Revision)
	if err != nil {
		return fmt.Errorf("load node line endpoint publication: %w", err)
	}
	defer rows.Close()
	published := make(map[uuid.UUID]bool, len(group.Endpoints))
	for rows.Next() {
		var endpointID uuid.UUID
		var value bool
		if err := rows.Scan(&endpointID, &value); err != nil {
			return fmt.Errorf("scan node line endpoint publication: %w", err)
		}
		published[endpointID] = value
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate node line endpoint publication: %w", err)
	}
	for index := range group.Endpoints {
		if value, ok := published[group.Endpoints[index].ID]; ok {
			group.Endpoints[index].Published = &value
		}
	}
	return nil
}
