package errorpagecontrol

import (
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestScopeOverridePostgreSQLCRUDRecoveryAndIsolation(t *testing.T) {
	fixture := openScopeOverrideDatabase(t)
	identities := seedScopeOverrideIdentities(t, fixture.pool)
	service := newScopeOverrideTestService(t, fixture.pool)
	seedScopeOverrideNode(t, fixture.pool, identities.platform, 41, "华东", "192.0.2.41")
	seedScopeOverrideNode(t, fixture.pool, identities.platform, 42, "华南", "192.0.2.42")
	seedScopeOverrideNode(t, fixture.pool, identities.tenantOwner, 9001, "租户区域", "198.51.100.41")

	firstBody := []byte(`<!doctype html><html><body>scope override first audit marker</body></html>`)
	secondBody := []byte(`<!doctype html><html><body>scope override second audit marker</body></html>`)
	firstAsset := readyAsset(t, service, identities.platform, identities.platformScope,
		"scope-override-first", firstBody, "text/html")
	secondAsset := readyAsset(t, service, identities.platform, identities.platformScope,
		"scope-override-second", secondBody, "text/html")
	tenantAsset := readyAsset(t, service, identities.tenantOwner, identities.tenantScope,
		"scope-override-tenant", []byte("tenant private page"), "text/plain")
	pendingBody := []byte("pending page")
	pendingAsset := initiateAsset(t, service, identities.platform, identities.platformScope,
		"scope-override-pending", pendingBody, "text/plain")

	createRequest := CreateScopeOverrideRequest{
		TargetKind: ScopeOverrideRegion,
		Region:     "华东",
		Items: []ScopeOverrideBinding{
			{Key: SlotHTTP403, AssetID: firstAsset.ID},
			{Key: SlotHTTP400, AssetID: firstAsset.ID},
		},
		WriteMetadata: writeMetadata("scope-override-create"),
	}
	created, err := service.CreateScopeOverride(t.Context(), identities.platform, createRequest)
	if err != nil || created.Replayed || created.Value.DisplayID == "" || created.Value.Revision != 1 ||
		created.Value.Target.Kind != ScopeOverrideRegion || created.Value.Target.Region != "华东" ||
		len(created.Value.Items) != 2 || created.Value.Items[0].Key != SlotHTTP400 ||
		created.Value.Items[1].Key != SlotHTTP403 {
		t.Fatalf("created=%#v err=%v", created, err)
	}
	displayID, err := strconv.ParseInt(created.Value.DisplayID, 10, 64)
	if err != nil || displayID < 1 {
		t.Fatalf("display id=%q err=%v", created.Value.DisplayID, err)
	}

	page, err := service.ListScopeOverrides(t.Context(), identities.platform)
	if err != nil || page.Total != 1 || len(page.Items) != 1 || page.Items[0].DisplayID != created.Value.DisplayID {
		t.Fatalf("page=%#v err=%v", page, err)
	}
	loaded, err := service.GetScopeOverride(t.Context(), identities.platform, displayID)
	if err != nil || loaded.Revision != 1 || len(loaded.Items) != 2 ||
		loaded.Items[0].Content != string(firstBody) || loaded.Items[1].Content != string(firstBody) {
		t.Fatalf("loaded=%#v err=%v", loaded, err)
	}

	replayedCreate, err := service.CreateScopeOverride(t.Context(), identities.platform, createRequest)
	if err != nil || !replayedCreate.Replayed || replayedCreate.Value.Revision != 1 ||
		replayedCreate.Value.DisplayID != created.Value.DisplayID {
		t.Fatalf("create replay=%#v err=%v", replayedCreate, err)
	}
	conflictingCreate := createRequest
	conflictingCreate.Items = []ScopeOverrideBinding{{Key: SlotHTTP400, AssetID: secondAsset.ID}}
	if _, err := service.CreateScopeOverride(t.Context(), identities.platform, conflictingCreate); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("conflicting create error=%v", err)
	}

	updateRequest := UpdateScopeOverrideRequest{
		DisplayID: displayID, ExpectedRevision: 1,
		Items:         []ScopeOverrideBinding{{Key: SlotHTTP400, AssetID: secondAsset.ID}},
		WriteMetadata: writeMetadata("scope-override-update"),
	}
	updated, err := service.UpdateScopeOverride(t.Context(), identities.platform, updateRequest)
	if err != nil || updated.Replayed || updated.Value.Revision != 2 || len(updated.Value.Items) != 1 ||
		updated.Value.Items[0].Key != SlotHTTP400 {
		t.Fatalf("updated=%#v err=%v", updated, err)
	}
	replayedUpdate, err := service.UpdateScopeOverride(t.Context(), identities.platform, updateRequest)
	if err != nil || !replayedUpdate.Replayed || replayedUpdate.Value.Revision != 2 {
		t.Fatalf("update replay=%#v err=%v", replayedUpdate, err)
	}
	conflictingUpdate := updateRequest
	conflictingUpdate.Items = []ScopeOverrideBinding{{Key: SlotHTTP400, AssetID: firstAsset.ID}}
	if _, err := service.UpdateScopeOverride(t.Context(), identities.platform, conflictingUpdate); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("conflicting update error=%v", err)
	}
	staleUpdate := updateRequest
	staleUpdate.WriteMetadata = writeMetadata("scope-override-stale-update")
	if _, err := service.UpdateScopeOverride(t.Context(), identities.platform, staleUpdate); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale update error=%v", err)
	}
	loaded, err = service.GetScopeOverride(t.Context(), identities.platform, displayID)
	if err != nil || loaded.Revision != 2 || len(loaded.Items) != 1 || loaded.Items[0].Content != string(secondBody) {
		t.Fatalf("updated document=%#v err=%v", loaded, err)
	}

	if _, err := service.CreateScopeOverride(t.Context(), identities.platform, CreateScopeOverrideRequest{
		TargetKind: ScopeOverrideRegion, Region: "华南",
		Items:         []ScopeOverrideBinding{{Key: SlotHTTP400, AssetID: pendingAsset.ID}},
		WriteMetadata: writeMetadata("scope-override-pending-asset"),
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("pending asset error=%v", err)
	}
	if _, err := service.CreateScopeOverride(t.Context(), identities.platform, CreateScopeOverrideRequest{
		TargetKind: ScopeOverrideRegion, Region: "华南",
		Items:         []ScopeOverrideBinding{{Key: SlotHTTP400, AssetID: tenantAsset.ID}},
		WriteMetadata: writeMetadata("scope-override-cross-scope-asset"),
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("cross-scope asset error=%v", err)
	}
	if _, err := service.CreateScopeOverride(t.Context(), identities.platform, CreateScopeOverrideRequest{
		TargetKind: ScopeOverrideNode, NodeDisplayID: 9001,
		Items:         []ScopeOverrideBinding{{Key: SlotHTTP400, AssetID: firstAsset.ID}},
		WriteMetadata: writeMetadata("scope-override-cross-scope-node"),
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-scope node error=%v", err)
	}

	if _, err := service.ListScopeOverrides(t.Context(), identities.tenantOwner); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("tenant list error=%v", err)
	}
	if _, err := service.GetScopeOverride(t.Context(), identities.tenantOwner, displayID); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("tenant get error=%v", err)
	}
	if _, err := service.CreateScopeOverride(t.Context(), identities.tenantOwner, CreateScopeOverrideRequest{
		TargetKind: ScopeOverrideRegion, Region: "租户区域",
		Items:         []ScopeOverrideBinding{{Key: SlotHTTP400, AssetID: tenantAsset.ID}},
		WriteMetadata: writeMetadata("scope-override-tenant-create"),
	}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("tenant create error=%v", err)
	}
	tenantUpdate := updateRequest
	tenantUpdate.WriteMetadata = writeMetadata("scope-override-tenant-update")
	if _, err := service.UpdateScopeOverride(t.Context(), identities.tenantOwner, tenantUpdate); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("tenant update error=%v", err)
	}
	if _, err := service.DeleteScopeOverride(t.Context(), identities.tenantOwner, DeleteScopeOverrideRequest{
		DisplayID: displayID, ExpectedRevision: 2, WriteMetadata: writeMetadata("scope-override-tenant-delete"),
	}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("tenant delete error=%v", err)
	}

	deleteRequest := DeleteScopeOverrideRequest{
		DisplayID: displayID, ExpectedRevision: 2, WriteMetadata: writeMetadata("scope-override-delete"),
	}
	deleted, err := service.DeleteScopeOverride(t.Context(), identities.platform, deleteRequest)
	if err != nil || deleted.Replayed || !deleted.Value.Deleted || deleted.Value.Revision != 3 ||
		len(deleted.Value.Items) != 0 {
		t.Fatalf("deleted=%#v err=%v", deleted, err)
	}
	replayedDelete, err := service.DeleteScopeOverride(t.Context(), identities.platform, deleteRequest)
	if err != nil || !replayedDelete.Replayed || replayedDelete.Value.Revision != 3 || !replayedDelete.Value.Deleted {
		t.Fatalf("delete replay=%#v err=%v", replayedDelete, err)
	}
	if _, err := service.GetScopeOverride(t.Context(), identities.platform, displayID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted get error=%v", err)
	}
	page, err = service.ListScopeOverrides(t.Context(), identities.platform)
	if err != nil || page.Total != 0 || len(page.Items) != 0 {
		t.Fatalf("deleted page=%#v err=%v", page, err)
	}

	restoredRequest := createRequest
	restoredRequest.Items = []ScopeOverrideBinding{{Key: SlotHTTP400, AssetID: firstAsset.ID}}
	restoredRequest.WriteMetadata = writeMetadata("scope-override-restore")
	restored, err := service.CreateScopeOverride(t.Context(), identities.platform, restoredRequest)
	if err != nil || restored.Replayed || restored.Value.Deleted || restored.Value.Revision != 4 ||
		restored.Value.DisplayID != created.Value.DisplayID {
		t.Fatalf("restored=%#v err=%v", restored, err)
	}
	loaded, err = service.GetScopeOverride(t.Context(), identities.platform, displayID)
	if err != nil || loaded.Revision != 4 || len(loaded.Items) != 1 || loaded.Items[0].Content != string(firstBody) {
		t.Fatalf("restored document=%#v err=%v", loaded, err)
	}

	var auditLog string
	if err := fixture.pool.QueryRow(t.Context(), `SELECT string_agg(action || ':' || payload::text, E'\n' ORDER BY stream_position)
		FROM audit_events WHERE scope_id=$1 AND action LIKE 'error_page.scope_override.%'`, identities.platformScope).
		Scan(&auditLog); err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{operationScopeOverrideCreate, operationScopeOverrideUpdate, operationScopeOverrideDelete} {
		if !strings.Contains(auditLog, operation) {
			t.Fatalf("audit missing %s: %s", operation, auditLog)
		}
	}
	if !strings.Contains(auditLog, `"item_keys": ["http_400"`) ||
		strings.Contains(auditLog, "scope override first audit marker") ||
		strings.Contains(auditLog, "scope override second audit marker") || strings.Contains(auditLog, "<!doctype") {
		t.Fatalf("unexpected scope override audit payload=%s", auditLog)
	}
}

func TestScopeOverrideResolutionPrecedencePostgreSQL(t *testing.T) {
	fixture := openScopeOverrideDatabase(t)
	identities := seedScopeOverrideIdentities(t, fixture.pool)
	service := newScopeOverrideTestService(t, fixture.pool)
	nodeID := seedScopeOverrideNode(t, fixture.pool, identities.platform, 51, "继承区域", "192.0.2.51")
	globalAsset := readyAsset(t, service, identities.platform, identities.platformScope,
		"scope-override-global", []byte("global"), "text/plain")
	regionAsset := readyAsset(t, service, identities.platform, identities.platformScope,
		"scope-override-region", []byte("region"), "text/plain")
	nodeAsset := readyAsset(t, service, identities.platform, identities.platformScope,
		"scope-override-node", []byte("node"), "text/plain")

	assertResolvedScopeOverrideSlot(t, service, identities.platform, nodeID, SlotHTTP400, "builtin", uuid.Nil)
	global, err := service.BindSlot(t.Context(), identities.platform, BindSlotRequest{
		Key: SlotHTTP400, AssetID: globalAsset.ID, ExpectedRevision: 0,
		WriteMetadata: writeMetadata("scope-override-global-bind"),
	})
	if err != nil || global.Value.Revision != 1 {
		t.Fatalf("global=%#v err=%v", global, err)
	}
	assertResolvedScopeOverrideSlot(t, service, identities.platform, nodeID, SlotHTTP400, "global", globalAsset.ID)

	region, err := service.CreateScopeOverride(t.Context(), identities.platform, CreateScopeOverrideRequest{
		TargetKind: ScopeOverrideRegion, Region: "继承区域",
		Items:         []ScopeOverrideBinding{{Key: SlotHTTP400, AssetID: regionAsset.ID}},
		WriteMetadata: writeMetadata("scope-override-region-create"),
	})
	if err != nil {
		t.Fatal(err)
	}
	regionDisplayID, err := strconv.ParseInt(region.Value.DisplayID, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	assertResolvedScopeOverrideSlot(t, service, identities.platform, nodeID, SlotHTTP400, "region", regionAsset.ID)

	node, err := service.CreateScopeOverride(t.Context(), identities.platform, CreateScopeOverrideRequest{
		TargetKind: ScopeOverrideNode, NodeDisplayID: 51,
		Items:         []ScopeOverrideBinding{{Key: SlotHTTP400, AssetID: nodeAsset.ID}},
		WriteMetadata: writeMetadata("scope-override-node-create"),
	})
	if err != nil {
		t.Fatal(err)
	}
	nodeDisplayID, err := strconv.ParseInt(node.Value.DisplayID, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	assertResolvedScopeOverrideSlot(t, service, identities.platform, nodeID, SlotHTTP400, "node", nodeAsset.ID)

	if _, err := service.DeleteScopeOverride(t.Context(), identities.platform, DeleteScopeOverrideRequest{
		DisplayID: nodeDisplayID, ExpectedRevision: 1, WriteMetadata: writeMetadata("scope-override-node-delete"),
	}); err != nil {
		t.Fatal(err)
	}
	assertResolvedScopeOverrideSlot(t, service, identities.platform, nodeID, SlotHTTP400, "region", regionAsset.ID)
	if _, err := service.DeleteScopeOverride(t.Context(), identities.platform, DeleteScopeOverrideRequest{
		DisplayID: regionDisplayID, ExpectedRevision: 1, WriteMetadata: writeMetadata("scope-override-region-delete"),
	}); err != nil {
		t.Fatal(err)
	}
	assertResolvedScopeOverrideSlot(t, service, identities.platform, nodeID, SlotHTTP400, "global", globalAsset.ID)
	if _, err := service.UnbindSlot(t.Context(), identities.platform, UnbindSlotRequest{
		Key: SlotHTTP400, ExpectedRevision: 1, WriteMetadata: writeMetadata("scope-override-global-unbind"),
	}); err != nil {
		t.Fatal(err)
	}
	assertResolvedScopeOverrideSlot(t, service, identities.platform, nodeID, SlotHTTP400, "builtin", uuid.Nil)
}

// TestScopeOverrideMigration220RoundTrip rolls 220 itself down and up on a
// schema migrated through 220 (Migrate down only rolls back the release head).
func TestScopeOverrideMigration220RoundTrip(t *testing.T) {
	const version = 220
	pool := databasetest.MigratedThroughPool(t, "scope_override_test", version)
	assertScopeOverrideTables(t, pool, true)
	if err := databasetest.MigrateThrough(t.Context(), pool, "down", version); err != nil {
		t.Fatal(err)
	}
	assertScopeOverrideTables(t, pool, false)
	if err := databasetest.MigrateThrough(t.Context(), pool, "up", version); err != nil {
		t.Fatal(err)
	}
	assertScopeOverrideTables(t, pool, true)
}

func openScopeOverrideDatabase(t *testing.T) integrationFixture {
	t.Helper()
	return integrationFixture{pool: databasetest.MigratedPool(t, nil)}
}

func seedScopeOverrideIdentities(t *testing.T, pool *pgxpool.Pool) seededIdentities {
	t.Helper()
	result := seededIdentities{}
	result.platform, result.platformScope = seedPlatformActor(t, pool)
	tenantID, scopeID := uuid.New(), uuid.New()
	userID, roleID, sessionID := uuid.New(), uuid.New(), uuid.New()
	now := time.Now().UTC()
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		statements := []struct {
			query string
			args  []any
		}{
			{`INSERT INTO tenants(id,display_name,created_at,updated_at) VALUES($1,$2,$3,$3)`,
				[]any{tenantID, "Scope override tenant", now}},
			{`INSERT INTO access_scopes(id,kind,tenant_id,created_at) VALUES($1,'tenant',$2,$3)`,
				[]any{scopeID, tenantID, now}},
			{`INSERT INTO users(id,username,display_name,password_hash,created_at,updated_at)
				VALUES($1,$2,'Scope override owner','hash',$3,$3)`,
				[]any{userID, "scope-override-owner-" + userID.String(), now}},
			{`INSERT INTO memberships(scope_id,user_id,created_at) VALUES($1,$2,$3)`,
				[]any{scopeID, userID, now}},
			{`INSERT INTO roles(id,scope_id,name,description,system_role,created_at)
				VALUES($1,$2,'tenant_owner','owner',true,$3)`,
				[]any{roleID, scopeID, now}},
			{`INSERT INTO role_assignments(scope_id,user_id,role_id,assigned_at) VALUES($1,$2,$3,$4)`,
				[]any{scopeID, userID, roleID, now}},
			{`INSERT INTO auth_sessions(id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at)
				VALUES($1,$1,$2,$3,$4,$5,$6)`,
				[]any{sessionID, userID, scopeID,
					decodeSHA256(digestBytes([]byte("session:" + sessionID.String()))), now, now.Add(24 * time.Hour)}},
		}
		for _, statement := range statements {
			if _, err := tx.Exec(t.Context(), statement.query, statement.args...); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	result.tenantOwner = Actor{
		UserID: userID, ScopeID: scopeID, ScopeKind: "tenant",
		Credential: CredentialReference{Kind: CredentialKindSession, ID: sessionID},
	}
	result.tenantScope = scopeID
	return result
}

func newScopeOverrideTestService(t *testing.T, pool *pgxpool.Pool) *Service {
	t.Helper()
	service, err := NewServiceWithDependencies(
		pool,
		newMemoryContentStore(),
		&testScanner{name: "scope-override-scanner"},
		staticLimits{quota: AssetQuota{
			MaxAssetBytes: MaxEdgeResourceBytes,
			MaxAssets:     100,
			MaxTotalBytes: 8 << 20,
		}},
		audit.New(pool),
		time.Now,
		testTxAuthorizer{},
	)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func seedScopeOverrideNode(
	t *testing.T,
	pool *pgxpool.Pool,
	actor Actor,
	displayID int64,
	region, ipv4 string,
) uuid.UUID {
	t.Helper()
	nodeID := uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO nodes (
		id,scope_id,display_id,name,region,ipv4,admin_state,created_by_user_id,created_at,updated_at
	) VALUES($1,$2,$3,$4,$5,$6,'active',$7,$8,$8)`, nodeID, actor.ScopeID, displayID,
		"scope-override-node-"+strconv.FormatInt(displayID, 10), region, ipv4, actor.UserID, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	return nodeID
}

func assertResolvedScopeOverrideSlot(
	t *testing.T,
	service *Service,
	actor Actor,
	nodeID uuid.UUID,
	key, source string,
	assetID uuid.UUID,
) {
	t.Helper()
	resolved, err := service.ResolveScopeOverrideSlot(t.Context(), actor, nodeID, key)
	if err != nil || resolved.Source != source {
		t.Fatalf("resolved=%#v err=%v want source=%s", resolved, err, source)
	}
	if assetID == uuid.Nil {
		if resolved.AssetID != nil {
			t.Fatalf("resolved asset=%s want nil", *resolved.AssetID)
		}
		return
	}
	if resolved.AssetID == nil || *resolved.AssetID != assetID {
		t.Fatalf("resolved asset=%v want=%s", resolved.AssetID, assetID)
	}
}

func assertScopeOverrideTables(t *testing.T, pool *pgxpool.Pool, expected bool) {
	t.Helper()
	for _, table := range []string{
		"error_page_scope_overrides",
		"error_page_scope_override_revisions",
		"error_page_scope_override_items",
	} {
		var exists bool
		if err := pool.QueryRow(t.Context(), `SELECT to_regclass($1) IS NOT NULL`, table).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if exists != expected {
			t.Fatalf("table %s exists=%t want=%t", table, exists, expected)
		}
	}
}
