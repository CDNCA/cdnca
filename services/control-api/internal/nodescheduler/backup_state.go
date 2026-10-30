package nodescheduler

import (
	"context"
	"fmt"
	"time"
)

// LineBackupState is one address family's backup IP state recorded by the
// node serving worker (node_line_group_backup_states, migration 571).
type LineBackupState struct {
	AddressFamily   int       `json:"address_family"`
	State           string    `json:"state"`
	BackupAddresses []string  `json:"backup_addresses"`
	ChangedAt       time.Time `json:"changed_at"`
}

// attachBackupStates fills LineGroupRevision.BackupStates for line group reads
// (List/GetCurrent). A family never switched to backup has no row: normal.
func attachBackupStates(ctx context.Context, pool revisionQuerier, group *LineGroupRevision) error {
	rows, err := pool.Query(ctx, `SELECT address_family::integer,state,
			ARRAY(SELECT host(address) FROM unnest(backup_addresses) address),changed_at
		FROM node_line_group_backup_states WHERE tenant_scope_id=$1 AND line_group_id=$2
		ORDER BY address_family`, group.TenantScopeID, group.GroupID)
	if err != nil {
		return fmt.Errorf("load line group backup states: %w", err)
	}
	defer rows.Close()
	states := make([]LineBackupState, 0, 2)
	for rows.Next() {
		var state LineBackupState
		if err := rows.Scan(&state.AddressFamily, &state.State, &state.BackupAddresses, &state.ChangedAt); err != nil {
			return fmt.Errorf("scan line group backup state: %w", err)
		}
		states = append(states, state)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate line group backup states: %w", err)
	}
	group.BackupStates = states
	return nil
}

// attachReadState attaches what line group reads show beyond the revision.
func attachReadState(ctx context.Context, pool revisionQuerier, group *LineGroupRevision) error {
	if err := attachPublished(ctx, pool, group); err != nil {
		return err
	}
	return attachBackupStates(ctx, pool, group)
}
