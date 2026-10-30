//go:build integration

package migrations_test

import (
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analytics"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestAnalyticsAccessSourceWindowContributions208RoundTripAndFences(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 207)
	if err := migrateVersionIsolated(t.Context(), pool, "up", 208); err != nil {
		t.Fatalf("207 -> 208: %v", err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, 208)
	if err := migrateVersionIsolated(t.Context(), pool, "down", 208); err != nil {
		t.Fatalf("empty 208 down: %v", err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, 207)
	if err := migrateVersionIsolated(t.Context(), pool, "up", 208); err != nil {
		t.Fatalf("207 -> 208 reapply: %v", err)
	}

	identity := seedSiteGroup082Identity(t, pool, "access-window-208")
	siteID := uuid.New()
	now := time.Date(2026, 8, 27, 11, 0, 0, 0, time.UTC)
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	if _, err := tx.Exec(t.Context(), `INSERT INTO sites(
		id,scope_id,owner_user_id,domain,http_ports,https_ports,origins,origin_hosts,
		https_enabled,enabled,status,created_by_user_id,updated_by_user_id,created_at,updated_at
	) VALUES($1,$2,$3,'access-window-208.example.test',ARRAY['80'],ARRAY[]::text[],
		ARRAY['192.0.2.1'],ARRAY['192.0.2.1'],false,true,'active',$3,$3,$4,$4)`,
		siteID, identity.scopeID, identity.userID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO site_origin_pools(site_id,updated_at) VALUES($1,$2)`, siteID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO site_origins(site_id,position,host,port,weight,enabled)
		VALUES($1,1,'192.0.2.1',80,1,true)`, siteID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	seedAnalyticsObservability083Installation(t, pool)
	generation := validAnalyticsHistorySeed083("ANALYTICS_WINDOW_208", "analytics_window_208")
	if err := execAnalyticsHistorySeed083(t, pool, generation); err != nil {
		t.Fatalf("seed analytics history generation: %v", err)
	}
	receipt := insertAnalyticsIngestReceipt098(t, pool, generation.historyEpoch, 1, 1)
	mismatchTx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer mismatchTx.Rollback(t.Context())
	_, err = mismatchTx.Exec(t.Context(), `INSERT INTO analytics_access_source_window_contributions_208(
		history_epoch,stream_sequence,event_id,scope_id,tenant_id,installation_id,site_id,node_id,
		config_version_id,host,listen_port,window_start,window_end,source_watermark,
		finalized_through,dependency_state,evidence_sha256,recorded_at
	) VALUES($1,$2,'access_window_208',$3,$4,'installation-208',$5,$6,$7,
		'access-window-208.example.test',443,$8::timestamptz,$8::timestamptz+interval '1 hour',7,
		$8::timestamptz+interval '1 hour','ready',decode(repeat('ab',32),'hex'),
		$8::timestamptz+interval '1 hour')`, receipt.epoch, receipt.sequence,
		identity.scopeID, identity.tenantID, siteID, uuid.New(), uuid.New(), now)
	assertAnalyticsAccessWindow208Code(t, err, "23503")
	if err := mismatchTx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}

	recordedAt := now.Add(time.Hour)
	history, openedGeneration, err := analytics.OpenPostgresIngestHistoryV1(t.Context(), pool,
		analytics.PostgresIngestHistoryConfig{
			InstallationID: generation.installationID, NATSDomain: generation.natsDomain,
			StreamName: generation.streamName, DurableName: generation.durableName,
			ClaimedBy: "access-window-208-test", Now: func() time.Time { return recordedAt },
		})
	if err != nil {
		t.Fatal(err)
	}
	contribution := analytics.AccessWindowContributionV1{
		MetricVersion: 1, EventID: "access_window_208_receive", WindowStart: now,
		WindowEnd: recordedAt, TenantID: identity.tenantID.String(), SiteID: siteID.String(),
		NodeID: uuid.NewString(), InstallationID: generation.installationID,
		ConfigVersionID: uuid.NewString(), Host: "access-window-208.example.test", ListenPort: 443,
		SourceWatermark: 7, FinalizedThrough: recordedAt, DependencyState: "ready",
		EvidenceSHA256: sha256.Sum256([]byte("access-window-208-evidence")),
	}
	decoded := analytics.DecodedIngest{
		SchemaVersion: analytics.IngestSchemaVersion, Kind: analytics.AccessWindowEnvelopeType,
		MessageID: "access-window-208-receive", ProducedAt: recordedAt,
		TenantID: identity.tenantID.String(), NodeID: contribution.NodeID,
		InstallationID:            generation.installationID,
		AccessWindowContributions: []analytics.AccessWindowContributionV1{contribution},
		PayloadDigest:             sha256.Sum256([]byte("access-window-208-payload")),
	}
	badDecoded := decoded
	badDecoded.MessageID = "access-window-208-atomic-rollback"
	badDecoded.PayloadDigest = sha256.Sum256([]byte("access-window-208-bad-payload"))
	badDecoded.AccessWindowContributions = append([]analytics.AccessWindowContributionV1(nil), decoded.AccessWindowContributions...)
	badDecoded.AccessWindowContributions[0].SiteID = uuid.NewString()
	badReceipt, err := analytics.NewIngestReceiptV1(openedGeneration, 2, badDecoded)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := history.Receive(t.Context(), badReceipt); err == nil {
		t.Fatal("invalid contribution unexpectedly committed")
	}
	var rolledBackReceipts int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM analytics_ingest_receipts
		WHERE history_epoch=$1 AND stream_sequence=2`, generation.historyEpoch).Scan(&rolledBackReceipts); err != nil {
		t.Fatal(err)
	}
	if rolledBackReceipts != 0 {
		t.Fatalf("failed contribution left %d receipt rows, want 0", rolledBackReceipts)
	}

	validReceipt, err := analytics.NewIngestReceiptV1(openedGeneration, 2, decoded)
	if err != nil {
		t.Fatal(err)
	}
	state, err := history.Receive(t.Context(), validReceipt)
	if err != nil || state != analytics.IngestReceiptStateReceived {
		t.Fatalf("valid receive = (%v, %v)", state, err)
	}
	if state, err = history.Receive(t.Context(), validReceipt); err != nil || state != analytics.IngestReceiptStateReceived {
		t.Fatalf("same receive replay = (%v, %v)", state, err)
	}
	var receiptState, persistedInstallation string
	var persistedRows int
	if err := pool.QueryRow(t.Context(), `SELECT min(receipt.state),min(contribution.installation_id),count(*)
		FROM analytics_ingest_receipts receipt
		JOIN analytics_access_source_window_contributions_208 contribution
		  USING(history_epoch,stream_sequence)
		WHERE receipt.history_epoch=$1 AND receipt.stream_sequence=2`, generation.historyEpoch).
		Scan(&receiptState, &persistedInstallation, &persistedRows); err != nil {
		t.Fatal(err)
	}
	if receiptState != "received" || persistedInstallation != generation.installationID || persistedRows != 1 {
		t.Fatalf("receipt/contribution round trip = %q/%q/%d", receiptState, persistedInstallation, persistedRows)
	}

	_, err = pool.Exec(t.Context(), `UPDATE analytics_access_source_window_contributions_208
		SET source_watermark=8 WHERE history_epoch=$1 AND stream_sequence=2`, generation.historyEpoch)
	assertAnalyticsAccessWindow208Code(t, err, "P2081")
	_, err = pool.Exec(t.Context(), `DELETE FROM analytics_access_source_window_contributions_208
		WHERE history_epoch=$1 AND stream_sequence=2`, generation.historyEpoch)
	assertAnalyticsAccessWindow208Code(t, err, "P2081")
	assertAnalyticsAccessWindow208Code(t, migrateVersionIsolated(t.Context(), pool, "down", 208), "P2082")
}

func assertAnalyticsAccessWindow208Code(t *testing.T, err error, want string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != want {
		t.Fatalf("error = %v, want SQLSTATE %s", err, want)
	}
}
