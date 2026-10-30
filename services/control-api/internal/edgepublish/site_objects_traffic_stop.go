package edgepublish

import (
	"context"
	"fmt"

	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// l4TrafficStopAPIVersion is the CAPABILITY_NAME_L4_TRAFFIC_STOP version a
// node needs to be told which forwards to cut off.
const l4TrafficStopAPIVersion = 1

// loadTrafficStoppedStreams lists the scope's forwards withdrawn because
// their package went over its monthly traffic (an open migration 508
// suspension, admin_status traffic_exceeded). An administrator's stop
// (locked, disabled) is not among them: those forwards still drain.
func loadTrafficStoppedStreams(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID) ([]string, error) {
	rows, err := tx.Query(ctx, `SELECT forward.id::text FROM l4_forwards forward
		WHERE forward.scope_id=$1 AND forward.deleted_at IS NULL AND forward.admin_status='traffic_exceeded'
		  AND EXISTS (SELECT 1 FROM package_traffic_stream_suspensions suspension
		    WHERE suspension.stream_id=forward.id AND suspension.tenant_scope_id=$1 AND suspension.recovered_at IS NULL)
		ORDER BY forward.id::text LIMIT $2`, scopeID, siteobject.MaxTrafficStopStreams)
	if err != nil {
		return nil, fmt.Errorf("%w: read traffic stopped L4 forwards", ErrPersistence)
	}
	defer rows.Close()
	var result []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("%w: scan traffic stopped L4 forwards", ErrPersistence)
		}
		result = append(result, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: iterate traffic stopped L4 forwards", ErrPersistence)
	}
	return result, nil
}

// trafficStopFor is what node's key document names: the stopped forwards
// when the node declares L4_TRAFFIC_STOP, else none (an older node drains
// them as before).
func trafficStopFor(advertised []*agentv1.Capability, stopped []string) []string {
	if len(stopped) == 0 {
		return nil
	}
	for _, capability := range advertised {
		if capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_L4_TRAFFIC_STOP &&
			capability.GetApiVersion() >= l4TrafficStopAPIVersion {
			return stopped
		}
	}
	return nil
}
