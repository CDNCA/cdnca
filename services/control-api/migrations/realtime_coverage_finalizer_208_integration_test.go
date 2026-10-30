//go:build integration

package migrations_test

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analytics"
	"github.com/cdnca/cdnca/services/control-api/internal/analyticsrealtime"
	"github.com/google/uuid"
)

// The finalizer store reads tables added after 208 (analytics_realtime_source_rosters_247),
// so it runs on the release head.
func TestRealtimeCoverageFinalizerPostgres208RoundTrip(t *testing.T) {
	pool := releaseHeadMigrationPool(t)
	identity := seedSiteGroup082Identity(t, pool, "realtime-coverage-finalizer-208")
	windowStart := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	windowEnd := windowStart.Add(time.Hour)
	stableAt := windowStart.Add(-time.Minute)
	siteID, nodeID, configVersionID := uuid.New(), uuid.New(), uuid.New()
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	if _, err := tx.Exec(t.Context(), `INSERT INTO sites(
		id,display_id,scope_id,owner_user_id,domain,http_ports,https_ports,origins,origin_hosts,
		https_enabled,enabled,status,created_by_user_id,updated_by_user_id,created_at,updated_at
	) VALUES($1,1,$2,$3,'coverage-finalizer.example.test',ARRAY['80'],ARRAY['443','8443'],
		ARRAY['192.0.2.10'],ARRAY['192.0.2.10'],true,true,'active',$3,$3,$4,$4)`,
		siteID, identity.scopeID, identity.userID, stableAt); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO site_origin_pools(site_id,updated_at) VALUES($1,$2)`,
		siteID, stableAt); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO site_origins(site_id,position,host,port,weight,enabled)
		VALUES($1,1,'192.0.2.10',80,1,true)`, siteID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	snapshotBytes := []byte(`{"schema":"cdnca.edge.site-runtime/v2"}`)
	snapshotDigest := sha256.Sum256(snapshotBytes)
	requestDigest := sha256.Sum256([]byte("realtime-coverage-finalizer-config"))
	if _, err := pool.Exec(t.Context(), `INSERT INTO config_versions(
		id,configuration_scope_id,canonical_snapshot,canonical_snapshot_sha256,generator_name,
		generator_version,status,idempotency_key,request_digest,created_at,published_at
	) VALUES($1,$2,$3,$4,'realtime-coverage-finalizer','1','releasable',$5,$6,$7,$7)`,
		configVersionID, identity.scopeID, snapshotBytes, snapshotDigest[:], uuid.NewString(), requestDigest[:], stableAt); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO nodes(
		id,display_id,scope_id,name,admin_state,created_by_user_id,created_at,updated_at
	) VALUES($1,(SELECT COALESCE(max(display_id),0)+1 FROM nodes),$2,$3,'active',$4,$5,$5)`,
		nodeID, identity.scopeID, "coverage-node-"+nodeID.String(), identity.userID, stableAt); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO node_config_state(
		node_id,configuration_scope_id,current_config_version_id,updated_at
	) VALUES($1,$2,$3,$4)`, nodeID, identity.scopeID, configVersionID, stableAt); err != nil {
		t.Fatal(err)
	}

	// Migration 247 makes the finalizer read an hourly source roster captured from published
	// config-source snapshots. This test owns the 208 contribution path, so it records the rosters
	// directly (the capture skips an hour that already has one): the window lists this node on both
	// ports, and the cutoff hour is empty.
	rosterSource := func(port int) map[string]any {
		return map[string]any{
			"scope_id": identity.scopeID.String(), "tenant_id": identity.tenantID.String(), "site_id": siteID.String(),
			"host": "coverage-finalizer.example.test", "listen_port": port, "node_id": nodeID.String(),
			"config_version_id": configVersionID.String(), "stable": true,
		}
	}
	for _, roster := range []struct {
		start   time.Time
		sources []map[string]any
	}{
		{start: windowStart, sources: []map[string]any{rosterSource(443), rosterSource(8443)}},
		{start: windowEnd, sources: []map[string]any{}},
	} {
		encoded, err := json.Marshal(roster.sources)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(t.Context(), `INSERT INTO analytics_realtime_source_rosters_247(
			window_start,sources,evidence_sha256,captured_at
		) VALUES($1,$2::jsonb,sha256(convert_to(($2::jsonb)::text,'UTF8')),clock_timestamp())`,
			roster.start, encoded); err != nil {
			t.Fatal(err)
		}
	}

	seedAnalyticsObservability083Installation(t, pool)
	generation := validAnalyticsHistorySeed083("REALTIME_COVERAGE_FINALIZER_208", "realtime_coverage_finalizer_208")
	if err := execAnalyticsHistorySeed083(t, pool, generation); err != nil {
		t.Fatal(err)
	}
	accessRecordedAt := windowEnd.Add(time.Minute)
	insertContribution := func(receipt analyticsIngestReceipt098, eventID string, port int, watermark uint64) {
		t.Helper()
		accessEvidence := sha256.Sum256([]byte(eventID))
		if _, err := pool.Exec(t.Context(), `INSERT INTO analytics_access_source_window_contributions_208(
			history_epoch,stream_sequence,event_id,scope_id,tenant_id,installation_id,site_id,node_id,
			config_version_id,host,listen_port,window_start,window_end,source_watermark,
			finalized_through,dependency_state,evidence_sha256,recorded_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'coverage-finalizer.example.test',$10,$11,$12,$13,$12,'ready',$14,$15)`,
			receipt.epoch, receipt.sequence, eventID, identity.scopeID, identity.tenantID, generation.installationID,
			siteID, nodeID, configVersionID, port, windowStart, windowEnd, watermark, accessEvidence[:], accessRecordedAt); err != nil {
			t.Fatal(err)
		}
	}
	insertContribution(insertAnalyticsIngestReceipt098(t, pool, generation.historyEpoch, 1, 1),
		"realtime_coverage_finalizer_208_443", 443, 7)
	insertContribution(insertAnalyticsIngestReceipt098(t, pool, generation.historyEpoch, 2, 2),
		"realtime_coverage_finalizer_208_8443", 8443, 8)

	store, err := analytics.NewPostgresRealtimeCoverageStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	candidates, err := store.PendingRealtimeCoverage(t.Context(), windowEnd.Add(2*time.Minute), 10)
	if err != nil || len(candidates) != 2 {
		t.Fatalf("pending candidates = %#v, error=%v", candidates, err)
	}
	connectionRecordedAt := windowEnd.Add(2 * time.Minute)
	var firstSnapshot analytics.RealtimeCoverageSnapshotV1
	var firstFact analytics.RealtimeCoverageFactV1
	for index, candidate := range candidates {
		snapshot, loadErr := store.LoadRealtimeCoverage(t.Context(), candidate)
		if loadErr != nil || len(snapshot.Sources) != 1 || !snapshot.Sources[0].AccessPresent ||
			snapshot.Sources[0].NodeID != nodeID.String() || snapshot.Sources[0].ConfigVersionID != configVersionID.String() {
			t.Fatalf("coverage snapshot = %#v, error=%v", snapshot, loadErr)
		}
		fact := analytics.RealtimeCoverageFactV1{
			Candidate: snapshot.Candidate, AccessSourcesExpected: 1, AccessSourcesFinalized: 1,
			ConnectionSourcesExpected: 1, ConnectionSourcesFinalized: 1,
			AccessSourceWatermark: snapshot.Sources[0].AccessRecordedAt, AccessFinalizedThrough: windowEnd,
			ConnectionSourceWatermark: connectionRecordedAt, ConnectionFinalizedThrough: windowEnd,
			EvidenceSHA256: sha256.Sum256([]byte("realtime-coverage-finalizer-combined-" + strconv.Itoa(int(candidate.ListenPort)))),
			RecordedAt:     connectionRecordedAt,
		}
		inserted, commitErr := store.CommitRealtimeCoverage(t.Context(), snapshot, fact)
		if commitErr != nil || !inserted {
			t.Fatalf("commit port %d = %v, %v", candidate.ListenPort, inserted, commitErr)
		}
		if index == 0 {
			firstSnapshot, firstFact = snapshot, fact
		}
	}
	inserted, err := store.CommitRealtimeCoverage(t.Context(), firstSnapshot, firstFact)
	if err != nil || inserted {
		t.Fatalf("idempotent commit = %v, %v", inserted, err)
	}
	candidates, err = store.PendingRealtimeCoverage(t.Context(), windowEnd.Add(2*time.Minute), 10)
	if err != nil || len(candidates) != 0 {
		t.Fatalf("pending after commit = %#v, error=%v", candidates, err)
	}

	reader, err := analytics.NewPostgresRealtimeExpectedCountReader(pool)
	if err != nil {
		t.Fatal(err)
	}
	scope := analyticsrealtime.Scope{TenantID: identity.tenantID.String()}
	baseFilter := analyticsrealtime.Filter{
		From: windowStart, To: windowEnd, Timezone: "UTC", Bucket: time.Minute,
	}
	for _, test := range []struct {
		name               string
		mutate             func(*analyticsrealtime.Filter)
		expectedDimensions uint64
	}{
		{name: "empty", expectedDimensions: 2},
		{name: "site only", mutate: func(filter *analyticsrealtime.Filter) { filter.SiteID = siteID.String() }, expectedDimensions: 2},
		{name: "host only", mutate: func(filter *analyticsrealtime.Filter) { filter.Domain = "coverage-finalizer.example.test" }, expectedDimensions: 2},
		{name: "port only", mutate: func(filter *analyticsrealtime.Filter) { filter.ListenPort = 443 }, expectedDimensions: 1},
		{name: "exact", mutate: func(filter *analyticsrealtime.Filter) {
			filter.SiteID, filter.Domain, filter.ListenPort = siteID.String(), "coverage-finalizer.example.test", 8443
		}, expectedDimensions: 1},
	} {
		t.Run("projection "+test.name, func(t *testing.T) {
			filter := baseFilter
			if test.mutate != nil {
				test.mutate(&filter)
			}
			authority, coverageErr := reader.RealtimeV2Coverage(t.Context(), scope, filter)
			if coverageErr != nil || authority.ExpectedDimensions != test.expectedDimensions ||
				authority.CoveredDimensions != test.expectedDimensions || authority.RequestedWindows != 1 ||
				authority.CoveredWindows != 1 || !authority.FinalizedThrough.Equal(windowEnd) ||
				authority.SourceWatermark.Before(windowEnd) {
				t.Fatalf("authority=%#v error=%v", authority, coverageErr)
			}
		})
	}

	insertContribution(insertAnalyticsIngestReceipt098(t, pool, generation.historyEpoch, 3, 3),
		"realtime_coverage_finalizer_208_missing", 9443, 9)
	if _, err := reader.RealtimeV2Coverage(t.Context(), scope, baseFilter); !errors.Is(err, analyticsrealtime.ErrDependencyUnavailable) {
		t.Fatalf("missing exact projection error=%v", err)
	}
}
