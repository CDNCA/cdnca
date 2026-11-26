//go:build integration

package edgepublish

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// SetSubscriptionCancelled writes a cancel version and the row change as
// packagesubscription.Store.Cancel does, then runs republish in the same
// transaction with the scope revision read before the change (user
// a cancelled subscription's sites leave the publication as a suspended
// one's do).
func (scope *SystemRepublishScope) SetSubscriptionCancelled(t *testing.T, subscriptionID uuid.UUID,
	republish func(tx pgx.Tx, fromRevision int64) error,
) {
	t.Helper()
	if err := pgx.BeginFunc(t.Context(), scope.Pool, func(tx pgx.Tx) error {
		var from int64
		if err := tx.QueryRow(t.Context(), `SELECT source_revision FROM edge_configuration_scopes WHERE scope_id=$1 FOR UPDATE`,
			scope.ScopeID).Scan(&from); err != nil {
			return err
		}
		var now string
		if err := tx.QueryRow(t.Context(), `SELECT clock_timestamp()::text`).Scan(&now); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO package_subscription_versions(subscription_id,revision,operation,snapshot,
			created_by_user_id,created_at) SELECT id,revision+1,'cancel','{}'::jsonb,$2,$3::timestamptz FROM package_subscriptions WHERE id=$1`,
			subscriptionID, scope.UserID, now); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `UPDATE package_subscriptions SET lifecycle_status='cancelled',cancelled_at=$3::timestamptz,
			revision=revision+1,updated_by_user_id=$2,updated_at=$3::timestamptz WHERE id=$1`,
			subscriptionID, scope.UserID, now); err != nil {
			return err
		}
		return republish(tx, from)
	}); err != nil {
		t.Fatal(err)
	}
}
