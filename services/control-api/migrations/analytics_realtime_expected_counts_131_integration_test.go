//go:build integration

package migrations_test

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// The 130<->131 round trip and the P1311 down guard were dropped with the 1.0.35 baseline
// (no rollback below the initial release); the immutability fence is checked on the release head.
func TestAnalyticsRealtimeExpectedCounts131Fences(t *testing.T) {
	pool := releaseHeadMigrationPool(t)
	identity := seedSiteGroup082Identity(t, pool, "realtime-131")
	siteID := uuid.New()
	createdAt := time.Date(2026, 8, 7, 1, 0, 0, 0, time.UTC)
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `INSERT INTO sites(
			id,display_id,scope_id,owner_user_id,domain,http_ports,https_ports,origins,origin_hosts,
			https_enabled,enabled,status,created_by_user_id,updated_by_user_id,created_at,updated_at
		) VALUES($1,1,$2,$3,'realtime-131.example.test',ARRAY['80'],ARRAY[]::text[],
			ARRAY['192.0.2.1'],ARRAY['192.0.2.1'],false,true,'active',$3,$3,$4,$4)`,
			siteID, identity.scopeID, identity.userID, createdAt); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO site_origin_pools(site_id,updated_at) VALUES($1,$2)`,
			siteID, createdAt); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO site_origins(site_id,position,host,port,weight,enabled)
			VALUES($1,1,'192.0.2.1',80,1,true)`, siteID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	generation := seedAnalyticsIngestHistoryGeneration098(t, pool)
	receipt := insertAnalyticsIngestReceipt098(t, pool, generation.historyEpoch, 41, 1)
	if _, err := pool.Exec(t.Context(), `INSERT INTO analytics_realtime_expected_counts_131(
		history_epoch,stream_sequence,hour,scope_id,tenant_id,site_id,host,listen_port,expected_events,created_at
	) VALUES($1,$2,$3,$4,$5,$6,'realtime-131.example.test',443,1,$3)`,
		receipt.epoch, receipt.sequence, createdAt,
		identity.scopeID, identity.tenantID, siteID); err != nil {
		t.Fatal(err)
	}

	_, err := pool.Exec(t.Context(), `UPDATE analytics_realtime_expected_counts_131
		SET expected_events=2 WHERE history_epoch=$1 AND stream_sequence=$2`, receipt.epoch, receipt.sequence)
	assertAnalyticsRealtimeExpectedCounts131Code(t, err, "P1310")
}

func assertAnalyticsRealtimeExpectedCounts131Code(t *testing.T, err error, want string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != want {
		t.Fatalf("error = %v, want SQLSTATE %s", err, want)
	}
}
