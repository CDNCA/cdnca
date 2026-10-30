//go:build integration

package nodeidentity

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TelemetrySiteScopesForTest is the telemetry sites GetAuthorization puts in
// the snapshot of a node serving one configuration scope of tenantID
// (loadTelemetrySiteScopes), for cross-process harnesses whose gateway PKI is
// not the enrolled certificate (tests/telemetry-e2e). Integration builds only.
func TelemetrySiteScopesForTest(ctx context.Context, pool *pgxpool.Pool, nodeID, scopeID, tenantID uuid.UUID, now time.Time) ([]TelemetrySiteScope, error) {
	var sites []TelemetrySiteScope
	err := pgx.BeginTxFunc(ctx, pool, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		var err error
		sites, _, err = loadTelemetrySiteScopes(ctx, tx, nodeID, map[uuid.UUID]*uuid.UUID{scopeID: &tenantID}, false,
			now.UTC().Truncate(time.Microsecond))
		return err
	})
	return sites, err
}
