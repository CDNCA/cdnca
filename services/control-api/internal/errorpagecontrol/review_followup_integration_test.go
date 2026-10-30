package errorpagecontrol

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const followupReconcileOperation = "error_page.asset.reconcile_finalize"

type followupReconcileLimits struct {
	mu     sync.Mutex
	denied bool
	checks []EntitlementCheck
}

func (provider *followupReconcileLimits) Limits(
	ctx context.Context,
	tx pgx.Tx,
	check EntitlementCheck,
) (EntitlementLimits, error) {
	if check.Operation == followupReconcileOperation {
		value := reflect.ValueOf(check)
		principalKind := value.FieldByName("PrincipalKind")
		principalID := value.FieldByName("PrincipalID")
		if !principalKind.IsValid() || !principalID.IsValid() ||
			principalKind.Kind() != reflect.String || principalID.Kind() != reflect.String ||
			principalKind.String() != "system" || principalID.String() != "error-page-reconciler" {
			return EntitlementLimits{}, ErrUnavailable
		}
		var scopeID uuid.UUID
		var status string
		if err := tx.QueryRow(ctx, `SELECT scope_id,status FROM error_page_assets
			WHERE id=$1 FOR UPDATE`, check.ResourceID).Scan(&scopeID, &status); err != nil {
			return EntitlementLimits{}, err
		}
		if scopeID != check.ScopeID || status != StatusFinalizing {
			return EntitlementLimits{}, ErrUnavailable
		}
		provider.mu.Lock()
		provider.checks = append(provider.checks, check)
		denied := provider.denied
		provider.mu.Unlock()
		if denied {
			return EntitlementLimits{}, ErrEntitlementDenied
		}
	}
	limits := baselineEntitlementLimits()
	limits.AssetQuota.MaxAssets = 100
	limits.AssetQuota.MaxTotalBytes = 8 << 20
	return limits, nil
}

func (provider *followupReconcileLimits) setDenied(denied bool) {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	provider.denied = denied
}

func (provider *followupReconcileLimits) reconcileChecks() []EntitlementCheck {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	return append([]EntitlementCheck(nil), provider.checks...)
}

func TestReviewFollowupReconcileReadyRequiresCurrentEntitlement(t *testing.T) {
	fixture := openErrorPageDatabase(t)
	identities := seedErrorPageIdentities(t, fixture.pool)
	store := newMemoryContentStore()
	limits := &followupReconcileLimits{}
	service := newReviewService(t, fixture.pool, store, limits, testTxAuthorizer{})
	body := []byte("reconcile-entitlement")
	asset := initiateAsset(t, service, identities.tenantOwner, identities.tenantScope,
		"followup-reconcile", body, "text/plain")
	mustUpload(t, service, identities.tenantOwner, asset, "followup-reconcile-upload", body)
	staged, err := store.Stat(t.Context(), assetObjectRef(asset, asset.stagingObjectKey))
	if err != nil {
		t.Fatal(err)
	}
	if err := service.recordScan(t.Context(), identities.tenantOwner,
		writeMetadata("followup-reconcile-scan"), asset.ID, "passed", "",
		StatusFinalizing, staged.ImmutableToken); err != nil {
		t.Fatal(err)
	}

	limits.setDenied(true)
	if _, err := service.ReconcileAssets(t.Context(), 100); !errors.Is(err, ErrEntitlementDenied) {
		t.Fatalf("denied reconcile error=%v, want ErrEntitlementDenied", err)
	}
	current, err := service.GetAsset(t.Context(), identities.tenantOwner, asset.ID)
	if err != nil || current.Status != StatusFinalizing {
		t.Fatalf("denied status=%s err=%v", current.Status, err)
	}
	var successes int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events
		WHERE action='error_page.asset.reconcile' AND resource_id=$1 AND result='success'`, asset.ID.String()).
		Scan(&successes); err != nil {
		t.Fatal(err)
	}
	if successes != 0 {
		t.Fatalf("success audit count after denied reconcile=%d", successes)
	}
	checks := limits.reconcileChecks()
	if len(checks) != 1 || checks[0].ScopeID != asset.ScopeID || checks[0].ResourceID != asset.ID {
		t.Fatalf("reconcile entitlement checks=%+v", checks)
	}

	limits.setDenied(false)
	completed, err := service.ReconcileAssets(t.Context(), 100)
	if err != nil || completed != 1 {
		t.Fatalf("retry completed=%d err=%v", completed, err)
	}
	current, err = service.GetAsset(t.Context(), identities.tenantOwner, asset.ID)
	if err != nil || current.Status != StatusReady {
		t.Fatalf("retry status=%s err=%v", current.Status, err)
	}
}

type followupRuleSetup struct {
	fixture    integrationFixture
	identities seededIdentities
	service    *Service
	asset      Asset
	rule       WriteResult[Rule]
}

func newFollowupRuleSetup(t *testing.T, enabled bool, key string) followupRuleSetup {
	t.Helper()
	fixture := openErrorPageDatabase(t)
	identities := seedErrorPageIdentities(t, fixture.pool)
	service := newReviewService(t, fixture.pool, newMemoryContentStore(), staticLimits{
		quota: AssetQuota{MaxAssetBytes: MaxEdgeResourceBytes, MaxAssets: 100, MaxTotalBytes: 8 << 20},
	}, testTxAuthorizer{})
	asset := readyAsset(t, service, identities.tenantOwner, identities.tenantScope,
		key+"-asset", []byte(key), "text/plain")
	rule, err := service.CreateRule(t.Context(), identities.tenantOwner, CreateRuleRequest{
		Target: RuleTarget{Kind: ScopeSite, ScopeID: identities.tenantScope, SiteID: &identities.siteID},
		Fields: RuleFields{Category: CategoryOriginResponse,
			Match: StatusSelector{Kind: MatchExact, From: 518}, AssetID: asset.ID, Enabled: enabled},
		WriteMetadata: writeMetadata(key + "-create"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return followupRuleSetup{fixture: fixture, identities: identities, service: service, asset: asset, rule: rule}
}

func softDeleteFollowupSite(t *testing.T, pool *pgxpool.Pool, siteID uuid.UUID) {
	t.Helper()
	now := storeTime(time.Now())
	command, err := pool.Exec(t.Context(), `UPDATE sites SET deleted_at=$2,updated_at=$2 WHERE id=$1`, siteID, now)
	if err != nil {
		t.Fatal(err)
	}
	if command.RowsAffected() != 1 {
		t.Fatalf("soft delete site rows=%d", command.RowsAffected())
	}
}

func TestReviewFollowupEnabledRuleRequiresActiveSite(t *testing.T) {
	t.Run("update", func(t *testing.T) {
		setup := newFollowupRuleSetup(t, true, "followup-site-update")
		softDeleteFollowupSite(t, setup.fixture.pool, setup.identities.siteID)
		fields := setup.rule.Value.Fields
		fields.Match = StatusSelector{Kind: MatchExact, From: 519}
		_, err := setup.service.UpdateRule(t.Context(), setup.identities.tenantOwner, UpdateRuleRequest{
			RuleID: setup.rule.Value.ID, ExpectedRevision: setup.rule.Value.Revision,
			Fields: fields, WriteMetadata: writeMetadata("followup-site-update-write"),
		})
		if !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrConflict) {
			t.Fatalf("update deleted-site error=%v", err)
		}
	})

	t.Run("enable", func(t *testing.T) {
		setup := newFollowupRuleSetup(t, false, "followup-site-enable")
		softDeleteFollowupSite(t, setup.fixture.pool, setup.identities.siteID)
		_, err := setup.service.EnableRule(t.Context(), setup.identities.tenantOwner, ChangeRuleStateRequest{
			RuleID: setup.rule.Value.ID, ExpectedRevision: setup.rule.Value.Revision,
			WriteMetadata: writeMetadata("followup-site-enable-write"),
		})
		if !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrConflict) {
			t.Fatalf("enable deleted-site error=%v", err)
		}
	})

	t.Run("completed replay", func(t *testing.T) {
		setup := newFollowupRuleSetup(t, true, "followup-site-replay")
		fields := setup.rule.Value.Fields
		fields.Match = StatusSelector{Kind: MatchExact, From: 520}
		request := UpdateRuleRequest{
			RuleID: setup.rule.Value.ID, ExpectedRevision: setup.rule.Value.Revision,
			Fields: fields, WriteMetadata: writeMetadata("followup-site-replay-write"),
		}
		if _, err := setup.service.UpdateRule(t.Context(), setup.identities.tenantOwner, request); err != nil {
			t.Fatal(err)
		}
		softDeleteFollowupSite(t, setup.fixture.pool, setup.identities.siteID)
		_, err := setup.service.UpdateRule(t.Context(), setup.identities.tenantOwner, request)
		if !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrConflict) {
			t.Fatalf("replay deleted-site error=%v", err)
		}
	})

	t.Run("direct revision", func(t *testing.T) {
		setup := newFollowupRuleSetup(t, true, "followup-site-direct")
		softDeleteFollowupSite(t, setup.fixture.pool, setup.identities.siteID)
		_, err := setup.fixture.pool.Exec(t.Context(), `INSERT INTO error_page_rule_revisions (
			rule_id,revision,category,match_kind,code_from,code_to,asset_id,enabled,deleted,
			created_by_user_id,created_by_scope_id,request_id,trace_id,created_at
		) VALUES($1,2,$2,'exact',521,521,$3,true,false,$4,$5,$6,$6,$7)`,
			setup.rule.Value.ID, CategoryOriginResponse, setup.asset.ID,
			setup.identities.tenantOwner.UserID, setup.identities.tenantOwner.ScopeID,
			"followup-site-direct-revision", storeTime(time.Now()))
		if err == nil {
			t.Fatal("direct enabled revision succeeded for deleted site")
		}
	})

	t.Run("publication excludes deleted site", func(t *testing.T) {
		setup := newFollowupRuleSetup(t, true, "followup-site-publication")
		softDeleteFollowupSite(t, setup.fixture.pool, setup.identities.siteID)
		err := pgx.BeginFunc(t.Context(), setup.fixture.pool, func(tx pgx.Tx) error {
			snapshot, err := buildSnapshot(t.Context(), tx, 999, MaxPublicationSites, MaxEdgeRulesPerScope)
			if err != nil {
				return err
			}
			for _, site := range snapshot.Sites {
				if site.SiteKey == setup.identities.siteID.String() {
					return fmt.Errorf("deleted site remained in publication")
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("direct publication rejects deleted site", func(t *testing.T) {
		setup := newFollowupRuleSetup(t, true, "followup-site-direct-publication")
		softDeleteFollowupSite(t, setup.fixture.pool, setup.identities.siteID)
		var revision int64
		var previous []byte
		if err := setup.fixture.pool.QueryRow(t.Context(), `SELECT revision,snapshot_sha256
			FROM error_page_publications ORDER BY revision DESC LIMIT 1`).Scan(&revision, &previous); err != nil {
			t.Fatal(err)
		}
		canonical := followupPublicationSnapshot(revision+1, []SnapshotSite{{
			SiteKey: setup.identities.siteID.String(), Rules: []SnapshotRule{},
		}}, 0)
		if err := insertFollowupPublication(t.Context(), setup.fixture.pool, setup.identities,
			revision+1, previous, canonical); err == nil {
			t.Fatal("direct publication accepted deleted site")
		}
	})
}

func TestReviewFollowupCreateWaitsForSiteDeletion(t *testing.T) {
	setup := newFollowupRuleSetup(t, false, "followup-site-create-race")
	deletion, err := setup.fixture.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer deletion.Rollback(context.Background())
	if _, err := deletion.Exec(t.Context(), `UPDATE sites SET deleted_at=$2,updated_at=$2 WHERE id=$1`,
		setup.identities.siteID, storeTime(time.Now())); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	completed := make(chan error, 1)
	go func() {
		_, err := setup.service.CreateRule(ctx, setup.identities.tenantOwner, CreateRuleRequest{
			Target: RuleTarget{Kind: ScopeSite, ScopeID: setup.identities.tenantScope, SiteID: &setup.identities.siteID},
			Fields: RuleFields{Category: CategoryOriginResponse,
				Match: StatusSelector{Kind: MatchExact, From: 522}, AssetID: setup.asset.ID, Enabled: true},
			WriteMetadata: writeMetadata("followup-site-create-race-write"),
		})
		completed <- err
	}()
	early := false
	select {
	case <-completed:
		early = true
	case <-time.After(50 * time.Millisecond):
	}
	if err := deletion.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if early {
		t.Fatal("enabled create completed before concurrent site deletion committed")
	}
	select {
	case err := <-completed:
		if !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrConflict) {
			t.Fatalf("create after deletion error=%v", err)
		}
	case <-ctx.Done():
		t.Fatalf("create did not finish after deletion commit: %v", ctx.Err())
	}
}

func followupPublicationSnapshot(revision int64, sites []SnapshotSite, size int) []byte {
	prefix := fmt.Sprintf(`{"schema":"%s","version":"control-%d","revision":%d,"global":{"rules":[]},"sites":`,
		SchemaV1, revision, revision)
	encodedSites, _ := json.Marshal(sites)
	document := prefix + string(encodedSites)
	if size == 0 {
		return []byte(document + "}")
	}
	document += `,"padding":"`
	suffix := `"}`
	return []byte(document + strings.Repeat("x", size-len(document)-len(suffix)) + suffix)
}

func insertFollowupPublication(
	ctx context.Context,
	pool *pgxpool.Pool,
	identities seededIdentities,
	revision int64,
	previous []byte,
	canonical []byte,
) error {
	digest := sha256.Sum256(canonical)
	_, err := pool.Exec(ctx, `INSERT INTO error_page_publications (
		revision,platform_scope_id,schema,version,canonical_snapshot,snapshot_sha256,previous_sha256,
		created_by_user_id,created_by_scope_id,request_id,trace_id,created_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$10,$11)`, revision, identities.platformScope,
		SchemaV1, fmt.Sprintf("control-%d", revision), canonical, digest[:], previous,
		identities.platform.UserID, identities.platform.ScopeID,
		fmt.Sprintf("followup-publication-%d", revision), storeTime(time.Now()))
	return err
}

func TestReviewFollowupDirectPublicationBounds(t *testing.T) {
	t.Run("payload", func(t *testing.T) {
		fixture := openErrorPageDatabase(t)
		identities := seedErrorPageIdentities(t, fixture.pool)
		exact := followupPublicationSnapshot(1, []SnapshotSite{}, int(MaxEdgePolicyBytes))
		if len(exact) != int(MaxEdgePolicyBytes) {
			t.Fatalf("exact payload size=%d", len(exact))
		}
		if err := insertFollowupPublication(t.Context(), fixture.pool, identities, 1, nil, exact); err != nil {
			t.Fatalf("8 MiB publication rejected: %v", err)
		}
		exactDigest := sha256.Sum256(exact)
		tooLarge := followupPublicationSnapshot(2, []SnapshotSite{}, int(MaxEdgePolicyBytes)+1)
		if err := insertFollowupPublication(t.Context(), fixture.pool, identities, 2, exactDigest[:], tooLarge); err == nil {
			t.Fatal("8 MiB + 1 direct publication succeeded")
		}
	})

	t.Run("sites", func(t *testing.T) {
		fixture := openErrorPageDatabase(t)
		identities := seedErrorPageIdentities(t, fixture.pool)
		sites := make([]SnapshotSite, MaxPublicationSites)
		for index := range sites {
			sites[index] = SnapshotSite{SiteKey: identities.siteID.String(), Rules: []SnapshotRule{}}
		}
		exact := followupPublicationSnapshot(1, sites, 0)
		if err := insertFollowupPublication(t.Context(), fixture.pool, identities, 1, nil, exact); err != nil {
			t.Fatalf("256-site direct publication rejected: %v", err)
		}
		exactDigest := sha256.Sum256(exact)
		sites = append(sites, SnapshotSite{SiteKey: identities.siteID.String(), Rules: []SnapshotRule{}})
		tooMany := followupPublicationSnapshot(2, sites, 0)
		if err := insertFollowupPublication(t.Context(), fixture.pool, identities, 2, exactDigest[:], tooMany); err == nil {
			t.Fatal("257-site direct publication succeeded")
		}
	})
}

func insertFollowupAssetTx(ctx context.Context, tx pgx.Tx, identities seededIdentities, id uuid.UUID) error {
	var tenantID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT tenant_id FROM access_scopes WHERE id=$1`, identities.tenantScope).Scan(&tenantID); err != nil {
		return err
	}
	now := storeTime(time.Now())
	_, err := tx.Exec(ctx, `INSERT INTO error_page_assets (
		id,scope_id,tenant_id,mime_type,size_bytes,sha256,staging_object_key,storage_object_key,
		status,scan_status,object_state,revision,created_by_user_id,created_by_scope_id,
		created_request_id,created_trace_id,created_at,updated_at
	) VALUES($1,$2,$3,'text/plain',1,$4,$5,$6,'initiated','pending','none',1,$7,$8,$9,$9,$10,$10)`,
		id, identities.tenantScope, tenantID, decodeSHA256(digestBytes([]byte("x"))),
		"error-pages/staging/"+id.String(), "error-pages/objects/"+id.String(),
		identities.tenantOwner.UserID, identities.tenantOwner.ScopeID,
		"followup-asset-"+id.String(), now)
	return err
}

func TestReviewFollowupMigration054DownRejectsEachFactKind(t *testing.T) {
	cases := []struct {
		name  string
		table string
		seed  func(*testing.T, integrationFixture, seededIdentities)
	}{
		{name: "asset", table: "error_page_assets", seed: func(t *testing.T, fixture integrationFixture, identities seededIdentities) {
			err := pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
				return insertFollowupAssetTx(t.Context(), tx, identities, uuid.New())
			})
			if err != nil {
				t.Fatal(err)
			}
		}},
		{name: "write request", table: "error_page_write_requests", seed: func(t *testing.T, fixture integrationFixture, identities seededIdentities) {
			_, err := fixture.pool.Exec(t.Context(), `INSERT INTO error_page_write_requests (
				id,actor_user_id,actor_scope_id,target_scope_id,operation,idempotency_key,request_digest,
				request_id,trace_id,created_at
			) VALUES($1,$2,$3,$3,'error_page.asset.initiate',$4,$5,$4,$4,$6)`, uuid.New(),
				identities.tenantOwner.UserID, identities.tenantScope, "followup-down-write", make([]byte, 32), storeTime(time.Now()))
			if err != nil {
				t.Fatal(err)
			}
		}},
		{name: "publication", table: "error_page_publications", seed: func(t *testing.T, fixture integrationFixture, identities seededIdentities) {
			if err := insertFollowupPublication(t.Context(), fixture.pool, identities, 1, nil,
				followupPublicationSnapshot(1, []SnapshotSite{}, 0)); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "rule", table: "error_page_rules", seed: func(t *testing.T, fixture integrationFixture, identities seededIdentities) {
			insertDirectRuleIdentity(t, fixture.pool, directRuleSpec{
				Actor: identities.tenantOwner, ScopeID: identities.tenantScope, SiteID: identities.siteID,
			})
		}},
		{name: "scan fact", table: "error_page_asset_scan_facts", seed: func(t *testing.T, fixture integrationFixture, identities seededIdentities) {
			service := newReviewService(t, fixture.pool, newMemoryContentStore(), staticLimits{
				quota: AssetQuota{MaxAssetBytes: MaxEdgeResourceBytes, MaxAssets: 10, MaxTotalBytes: 8 << 20},
			}, testTxAuthorizer{})
			asset := initiateAsset(t, service, identities.tenantOwner, identities.tenantScope,
				"followup-down-scan", []byte("scan"), "text/plain")
			mustUpload(t, service, identities.tenantOwner, asset, "followup-down-scan-upload", []byte("scan"))
			staged, err := service.content.Stat(t.Context(), assetObjectRef(asset, asset.stagingObjectKey))
			if err != nil {
				t.Fatal(err)
			}
			if err := service.recordScan(t.Context(), identities.tenantOwner, writeMetadata("followup-down-scan-record"),
				asset.ID, "passed", "", StatusFinalizing, staged.ImmutableToken); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "rule revision", table: "error_page_rule_revisions", seed: func(t *testing.T, fixture integrationFixture, identities seededIdentities) {
			service := newReviewService(t, fixture.pool, newMemoryContentStore(), staticLimits{
				quota: AssetQuota{MaxAssetBytes: MaxEdgeResourceBytes, MaxAssets: 10, MaxTotalBytes: 8 << 20},
			}, testTxAuthorizer{})
			asset := readyAsset(t, service, identities.tenantOwner, identities.tenantScope,
				"followup-down-rule-revision", []byte("revision"), "text/plain")
			if _, err := service.CreateRule(t.Context(), identities.tenantOwner, CreateRuleRequest{
				Target: RuleTarget{Kind: ScopeSite, ScopeID: identities.tenantScope, SiteID: &identities.siteID},
				Fields: RuleFields{Category: CategoryOriginResponse,
					Match: StatusSelector{Kind: MatchExact, From: 523}, AssetID: asset.ID, Enabled: true},
				WriteMetadata: writeMetadata("followup-down-rule-revision-create"),
			}); err != nil {
				t.Fatal(err)
			}
		}},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			fixture := openErrorPageDatabase(t)
			identities := seedErrorPageIdentities(t, fixture.pool)
			test.seed(t, fixture, identities)
			var count int
			if err := fixture.pool.QueryRow(t.Context(), "SELECT count(*) FROM "+test.table).Scan(&count); err != nil || count == 0 {
				t.Fatalf("%s count=%d err=%v", test.table, count, err)
			}
			err := execMigration(t.Context(), fixture.pool, "054_error_page_control.down.sql")
			if sqlState(err) != "55000" {
				t.Fatalf("down error=%v state=%s, want 55000", err, sqlState(err))
			}
			assertErrorPageTables(t, fixture.pool, true)
		})
	}
}

func TestReviewFollowupMigration054DownSeesConcurrentInsert(t *testing.T) {
	script, err := controlmigrations.FS.ReadFile("054_error_page_control.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for round := 0; round < 3; round++ {
		t.Run(fmt.Sprintf("round-%d", round), func(t *testing.T) {
			fixture := openErrorPageDatabase(t)
			identities := seedErrorPageIdentities(t, fixture.pool)
			ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
			defer cancel()
			writer, err := fixture.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer writer.Rollback(context.Background())
			assetID := uuid.New()
			if err := insertFollowupAssetTx(ctx, writer, identities, assetID); err != nil {
				t.Fatal(err)
			}
			down, err := fixture.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer down.Rollback(context.Background())
			var downPID int
			if err := down.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&downPID); err != nil {
				t.Fatal(err)
			}
			completed := make(chan error, 1)
			go func() {
				_, err := down.Exec(ctx, string(script))
				completed <- err
			}()
			waitForFollowupRelationLock(t, ctx, fixture.pool, downPID, completed)
			if err := writer.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-completed:
				if sqlState(err) != "55000" {
					t.Fatalf("down error=%v state=%s, want 55000", err, sqlState(err))
				}
			case <-ctx.Done():
				t.Fatalf("down did not finish: %v", ctx.Err())
			}
			if err := down.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
				t.Fatal(err)
			}
			var count int
			if err := fixture.pool.QueryRow(ctx, `SELECT count(*) FROM error_page_assets WHERE id=$1`, assetID).Scan(&count); err != nil || count != 1 {
				t.Fatalf("asset count=%d err=%v", count, err)
			}
			assertErrorPageTables(t, fixture.pool, true)
		})
	}
}

func waitForFollowupRelationLock(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	pid int,
	completed <-chan error,
) {
	t.Helper()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err := <-completed:
			t.Fatalf("down completed before waiting for writer: %v", err)
		default:
		}
		var waitEventType string
		if err := pool.QueryRow(ctx, `SELECT COALESCE(wait_event_type,'') FROM pg_stat_activity WHERE pid=$1`, pid).
			Scan(&waitEventType); err != nil {
			t.Fatal(err)
		}
		if waitEventType == "Lock" {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("down did not wait on relation lock: %v", ctx.Err())
		case <-ticker.C:
		}
	}
}

func TestReviewFollowupCurrentHead068EmptyChain(t *testing.T) {
	fixture := openErrorPageDatabase(t)
	assertErrorPageTables(t, fixture.pool, true)
}
