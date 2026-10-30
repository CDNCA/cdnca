//go:build integration

package edgepublish

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// AdvanceRevision is a tenant edit with no row change: the scope's next
// publication takes a new source revision.
func (scope *SystemRepublishScope) AdvanceRevision(t *testing.T) {
	t.Helper()
	if _, err := scope.Pool.Exec(t.Context(), `SELECT advance_edge_configuration_scope_revision($1)`, scope.ScopeID); err != nil {
		t.Fatal(err)
	}
}

// Hold is the scope's capability hold at its latest source revision.
type Hold struct {
	SourceRevision     int64
	Requested, Refused []uuid.UUID
}

func (scope *SystemRepublishScope) LatestHold(t *testing.T) (Hold, bool) {
	t.Helper()
	var hold Hold
	err := scope.Pool.QueryRow(t.Context(), `SELECT source_revision,requested_node_ids,refused_node_ids
		FROM edge_capability_publication_holds WHERE scope_id=$1 ORDER BY source_revision DESC LIMIT 1`, scope.ScopeID).
		Scan(&hold.SourceRevision, &hold.Requested, &hold.Refused)
	if errors.Is(err, pgx.ErrNoRows) {
		return Hold{}, false
	}
	if err != nil {
		t.Fatal(err)
	}
	return hold, true
}
