//go:build integration

package theme_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/audit/audittest"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/errorpagecontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/theme"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func themePool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool := databasetest.ClonedMigratedPool(t, nil)
	if pool == nil {
		t.Skip("TEST_DATABASE_TEMPLATE is not set (run through scripts/control-api-integration-sharded.sh)")
	}
	return pool
}

func seedPlatformAdmin(t *testing.T, pool *pgxpool.Pool) theme.Actor {
	t.Helper()
	ctx := t.Context()
	var scopeID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform'`).Scan(&scopeID); errors.Is(err, pgx.ErrNoRows) {
		scopeID = uuid.New()
		if _, err := pool.Exec(ctx, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, scopeID); err != nil {
			t.Fatal(err)
		}
	} else if err != nil {
		t.Fatal(err)
	}
	userID := uuid.New()
	var roleID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM roles WHERE scope_id=$1 AND system_role AND name='platform_owner'`, scopeID).Scan(&roleID); errors.Is(err, pgx.ErrNoRows) {
		roleID = uuid.New()
		if _, err := pool.Exec(ctx, `INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$2,'platform_owner','owner',true)`, roleID, scopeID); err != nil {
			t.Fatal(err)
		}
	} else if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'Theme admin','hash')`, []any{userID, "theme-" + userID.String()}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{scopeID, userID}},
		{`INSERT INTO role_permissions(role_id,permission_name) VALUES($1,'system_configuration.read'),($1,'system_configuration.manage') ON CONFLICT DO NOTHING`, []any{roleID}},
		{`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, []any{scopeID, userID, roleID}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	return theme.Actor{UserID: userID, ScopeID: scopeID, ScopeKind: "platform", IP: "198.51.100.7", RequestID: "theme-req-1"}
}

type denyGuard struct{ calls int }

func (guard *denyGuard) CheckFeature(context.Context, pgx.Tx, entitlementguard.FeatureCheck) (entitlementguard.FeatureDecision, error) {
	guard.calls++
	return entitlementguard.FeatureDecision{}, entitlementguard.ErrFeatureDenied
}

type auditRow struct {
	Action, Result string
	Payload        map[string]any
	Changes        []audit.Change // the changes column
}

func auditEvents(t *testing.T, pool *pgxpool.Pool, action string) []auditRow {
	t.Helper()
	rows, err := pool.Query(t.Context(), `SELECT action,result,payload,changes FROM audit_events WHERE action=$1 ORDER BY occurred_at,stream_position`, action)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var result []auditRow
	for rows.Next() {
		var row auditRow
		var payload, changes []byte
		if err := rows.Scan(&row.Action, &row.Result, &payload, &changes); err != nil {
			t.Fatal(err)
		}
		row.Changes = audittest.DecodeChanges(t, changes)
		if err := json.Unmarshal(payload, &row.Payload); err != nil {
			t.Fatal(err)
		}
		result = append(result, row)
	}
	return result
}

// TestThemeLifecyclePostgreSQL: download and activation are separate, one
// theme is active at a time, switching writes an audited activation and a new
// error page publication pinned to the theme; unsafe uploads and paid themes
// without a license are refused and audited.
func TestThemeLifecyclePostgreSQL(t *testing.T) {
	pool := themePool(t)
	ctx := t.Context()
	actor := seedPlatformAdmin(t, pool)
	paidRaw := bytes.Replace(officialFixtureRaw(), []byte(`"official.slate"`), []byte(`"official.paid"`), 1)
	catalog := append(officialFixtureCatalog(), theme.CatalogEntry{ID: "official.paid", Raw: paidRaw, RequiresFeature: theme.FeatureCode("official.paid")})
	guard := &denyGuard{}
	service, err := theme.NewService(pool, audit.New(pool), guard, catalog, time.Now)
	if err != nil {
		t.Fatal(err)
	}

	current, err := service.Current(ctx, theme.CurrentRequest{})
	if err != nil || current.Revision != 0 || current.ThemeID != theme.DefaultThemeID {
		t.Fatalf("initial current = %+v, %v", current, err)
	}
	// Nothing uploaded: no slot is listed, so the page requests no
	// /v1/brand-assets/<slot>. An upload lists the slot with its revision.
	if len(current.BrandAssets) != 0 {
		t.Fatalf("brand assets before any upload = %v", current.BrandAssets)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO platform_brand_assets(platform_scope_id,slot,revision,reference,mime_type,size_bytes,sha256,object_key,immutable_token,updated_by_user_id,updated_at)
		VALUES($1,'logo',3,'asset://brand/logo/'||repeat('a',64),'image/png',1,decode(repeat('aa',32),'hex'),'brand/logo','token',$2,now())`, actor.ScopeID, actor.UserID); err != nil {
		t.Fatal(err)
	}
	if current, err := service.Current(ctx, theme.CurrentRequest{}); err != nil || len(current.BrandAssets) != 1 || current.BrandAssets["logo"] != 3 {
		t.Fatalf("brand assets after upload = %+v, %v", current, err)
	}
	if css, err := service.File(ctx, theme.FileStylesheet, strings.TrimSuffix(strings.TrimPrefix(current.StylesheetURL, "/v1/theme/theme."), ".css")); err != nil ||
		!bytes.Contains(css, []byte("--setting-primary: #2d8cf0")) {
		t.Fatalf("default stylesheet before any download: %v\n%s", err, css)
	}

	official, err := service.Download(ctx, actor, officialFixtureID)
	if err != nil || official.Active || official.Source != "builtin" {
		t.Fatalf("download = %+v, %v", official, err)
	}
	again, err := service.Download(ctx, actor, officialFixtureID)
	if err != nil || again.PackageSHA256 != official.PackageSHA256 {
		t.Fatalf("second download = %+v, %v", again, err)
	}
	// Downloaded but not active: the public pointer has not moved.
	if current, _ := service.Current(ctx, theme.CurrentRequest{}); current.ThemeID != theme.DefaultThemeID {
		t.Fatalf("download activated the theme: %+v", current)
	}

	activated, err := service.Activate(ctx, actor, official.PackageSHA256, 0)
	if err != nil || activated.Revision != 1 || activated.ErrorPagePublicationRevision < 1 {
		t.Fatalf("activate = %+v, %v", activated, err)
	}
	current, err = service.Current(ctx, theme.CurrentRequest{})
	if err != nil || current.Revision != 1 || current.ThemeID != officialFixtureID || current.PackageSHA256 != official.PackageSHA256 {
		t.Fatalf("current after activation = %+v, %v", current, err)
	}
	css, err := service.File(ctx, theme.FileStylesheet, strings.TrimSuffix(strings.TrimPrefix(current.StylesheetURL, "/v1/theme/theme."), ".css"))
	if err != nil || !bytes.Contains(css, []byte("--setting-primary: #0f766e")) {
		t.Fatalf("official stylesheet: %v\n%s", err, css)
	}
	var policy []byte
	if err := pool.QueryRow(ctx, `SELECT canonical_snapshot FROM error_page_publications WHERE revision=$1`, activated.ErrorPagePublicationRevision).Scan(&policy); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(policy, []byte(`"theme_package_sha256":"`+official.PackageSHA256+`"`)) {
		t.Fatalf("publication does not pin the theme: %s", policy)
	}

	// The active theme again (even with a stale revision): nothing changes, no
	// second activation or republication.
	if again, err := service.Activate(ctx, actor, official.PackageSHA256, 0); err != nil || !again.AlreadyActive ||
		again.Revision != 1 || again.ErrorPageRepublishScopes != 0 {
		t.Fatalf("re-activation = %+v, %v", again, err)
	}
	if err := service.Remove(ctx, actor, official.PackageSHA256); !errors.Is(err, theme.ErrActivePackage) {
		t.Fatalf("remove active: %v", err)
	}

	defaultView, err := service.Download(ctx, actor, theme.DefaultThemeID)
	if err != nil {
		t.Fatal(err)
	}
	if switched, err := service.Activate(ctx, actor, defaultView.PackageSHA256, 1); err != nil || switched.Revision != 2 {
		t.Fatalf("switch back = %+v, %v", switched, err)
	}
	if err := service.Remove(ctx, actor, official.PackageSHA256); err != nil {
		t.Fatalf("remove inactive: %v", err)
	}
	if _, err := service.Activate(ctx, actor, official.PackageSHA256, 2); !errors.Is(err, theme.ErrNotFound) {
		t.Fatalf("activate removed: %v", err)
	}
	slate, err := service.Download(ctx, actor, officialFixtureID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Activate(ctx, actor, slate.PackageSHA256, 1); !errors.Is(err, theme.ErrRevisionConflict) {
		t.Fatalf("stale activation: %v", err)
	}
	if err := service.Remove(ctx, actor, slate.PackageSHA256); err != nil {
		t.Fatal(err)
	}

	unsafe := bytes.Replace(officialFixtureRaw(), []byte(`"official.slate"`), []byte(`"custom.evil"`), 1)
	unsafe = bytes.Replace(unsafe, []byte(`"token:colorBgPage"`), []byte(`"url(https://evil.example/x.png)"`), 1)
	if _, err := service.Upload(ctx, actor, unsafe); !errors.Is(err, theme.ErrInvalidPackage) {
		t.Fatalf("unsafe upload: %v", err)
	}
	if _, err := service.Upload(ctx, actor, officialFixtureRaw()); !errors.Is(err, theme.ErrInvalidPackage) {
		t.Fatalf("upload under an official id: %v", err)
	}

	paid, err := service.Download(ctx, actor, "official.paid")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Activate(ctx, actor, paid.PackageSHA256, 2); !errors.Is(err, theme.ErrEntitlementDenied) || guard.calls != 1 {
		t.Fatalf("unlicensed paid theme: %v (guard calls %d)", err, guard.calls)
	}

	view, err := service.Catalog(ctx, actor)
	if err != nil || view.ActivationRevision != 2 || view.ActivePackage != defaultView.PackageSHA256 {
		t.Fatalf("catalog = %+v, %v", view, err)
	}

	// BATCH-PLUGIN §10: every state change is audited with ip and changes.
	activations := auditEvents(t, pool, theme.ActionActivate)
	if len(activations) != 5 {
		t.Fatalf("activation audits = %+v", activations)
	}
	first := activations[0]
	themeChange, _ := audittest.Find(first.Changes, "theme_id")
	if first.Result != "success" || first.Payload["ip"] != "198.51.100.7" || themeChange.Before != theme.DefaultThemeID ||
		themeChange.After != officialFixtureID {
		t.Fatalf("first activation audit = %+v", first)
	}
	if first.Payload["error_page_republish_scopes"] != float64(0) {
		t.Fatalf("first activation audit has no republish scope count: %+v", first)
	}
	// The re-activation of the active theme wrote nothing.
	for index, want := range []string{"success", "failure", "failure", "failure"} {
		if activations[index+1].Result != want {
			t.Fatalf("activation audit %d = %+v, want %s", index+1, activations[index+1], want)
		}
	}
	if activations[2].Payload["reason"] != "not_downloaded" || activations[3].Payload["reason"] != "revision_conflict" ||
		activations[4].Payload["reason"] != "entitlement_feature_denied" {
		t.Fatalf("failure audits = %+v", activations[2:])
	}
	// Every activation records the system republication event, scope count 0
	// here (no tenant has published error pages).
	if republish := auditEvents(t, pool, "site.error_page.republish"); len(republish) != 2 ||
		republish[0].Payload["scope_count"] != float64(0) || republish[0].Payload["theme_id"] != officialFixtureID {
		t.Fatalf("republish audits = %+v", republish)
	}
	uploads := auditEvents(t, pool, theme.ActionUpload)
	if len(uploads) != 2 || uploads[0].Result != "failure" || uploads[0].Payload["reason"] != "invalid_package.external_reference" {
		t.Fatalf("upload audits = %+v", uploads)
	}
	if removes := auditEvents(t, pool, theme.ActionRemove); len(removes) != 3 || removes[1].Result != "success" {
		t.Fatalf("remove audits = %+v", removes)
	}
	if downloads := auditEvents(t, pool, theme.ActionDownload); len(downloads) != 5 || downloads[0].Payload["ip"] != "198.51.100.7" {
		t.Fatalf("download audits = %+v", downloads)
	}
}

type emptyContentStore struct{}

func (emptyContentStore) Capabilities() errorpagecontrol.ObjectStoreCapabilities {
	return errorpagecontrol.ObjectStoreCapabilities{ImmutableStaging: true, ConditionalFinalize: true, TrustedMetadata: true, ImmutableReads: true, PreservesStagingAlias: true}
}
func (emptyContentStore) PutStaging(context.Context, errorpagecontrol.ObjectRef, []byte, string) (errorpagecontrol.ObjectInfo, error) {
	return errorpagecontrol.ObjectInfo{}, errorpagecontrol.ErrUnavailable
}
func (emptyContentStore) Open(context.Context, errorpagecontrol.ObjectRef, string) (io.ReadCloser, error) {
	return nil, errorpagecontrol.ErrObjectNotFound
}
func (emptyContentStore) Finalize(context.Context, errorpagecontrol.ObjectRef, errorpagecontrol.ObjectRef, errorpagecontrol.ObjectInfo) (errorpagecontrol.ObjectInfo, error) {
	return errorpagecontrol.ObjectInfo{}, errorpagecontrol.ErrUnavailable
}
func (emptyContentStore) Stat(context.Context, errorpagecontrol.ObjectRef) (errorpagecontrol.ObjectInfo, error) {
	return errorpagecontrol.ObjectInfo{}, errorpagecontrol.ErrObjectNotFound
}
func (emptyContentStore) Delete(context.Context, errorpagecontrol.ObjectRef) error { return nil }

type testSigner struct{ key ed25519.PrivateKey }

func (signer testSigner) SigningKeyID() string { return "theme-test" }
func (signer testSigner) SigningPublicKey() ed25519.PublicKey {
	return signer.key.Public().(ed25519.PublicKey)
}
func (signer testSigner) Sign(_ context.Context, body []byte) ([]byte, error) {
	return ed25519.Sign(signer.key, body), nil
}

// TestThemeDefaultErrorPagesReachTenantSnapshot: after activation, a tenant's
// error page snapshot carries the theme's default pages (the publication
// path nodes install), so node default error pages change with the theme.
func TestThemeDefaultErrorPagesReachTenantSnapshot(t *testing.T) {
	pool := themePool(t)
	ctx := t.Context()
	actor := seedPlatformAdmin(t, pool)
	tenantID, scopeID := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,display_name) VALUES($1,'Theme tenant')`, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, scopeID, tenantID); err != nil {
		t.Fatal(err)
	}
	service, err := theme.NewService(pool, audit.New(pool), nil, officialFixtureCatalog(), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	compiler, err := errorpagecontrol.NewProductionSnapshotCompiler(emptyContentStore{}, testSigner{key: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))})
	if err != nil {
		t.Fatal(err)
	}
	build := func() errorpagecontrol.ProductionSnapshotDocument {
		var document errorpagecontrol.ProductionSnapshotDocument
		err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			artifact, err := compiler.Build(ctx, tx, errorpagecontrol.ProductionSnapshotRequest{TenantID: tenantID, ScopeID: scopeID})
			if err != nil {
				return err
			}
			return json.Unmarshal(artifact.WireBytes, &document)
		})
		if err != nil {
			t.Fatalf("build snapshot: %v", err)
		}
		return document
	}
	pageFor := func(document errorpagecontrol.ProductionSnapshotDocument, id string) []byte {
		for _, rule := range document.Global.Rules {
			if rule.ID == id {
				return rule.Resource.Body
			}
		}
		t.Fatalf("snapshot has no rule %s: %+v", id, document.Global.Rules)
		return nil
	}
	revision := int64(0)
	var bodies [][]byte
	for _, id := range []string{officialFixtureID, theme.DefaultThemeID} {
		view, err := service.Download(ctx, actor, id)
		if err != nil {
			t.Fatal(err)
		}
		result, err := service.Activate(ctx, actor, view.PackageSHA256, revision)
		if err != nil {
			t.Fatal(err)
		}
		revision = result.Revision
		document := build()
		if document.Binding.PublicationRevision != uint64(result.ErrorPagePublicationRevision) || len(document.Global.Rules) != len(theme.DefaultErrorPages) {
			t.Fatalf("snapshot for %s = %+v", id, document)
		}
		body := pageFor(document, "theme.edge_connect.502")
		if err := errorpagecontrol.ValidateThemedHTML(body); err != nil {
			t.Fatal(err)
		}
		bodies = append(bodies, body)
	}
	if bytes.Equal(bodies[0], bodies[1]) || !bytes.Contains(bodies[0], []byte("#0f766e")) || !bytes.Contains(bodies[1], []byte("#2d8cf0")) {
		t.Fatalf("theme switch did not change the node default page:\n%s\n%s", bodies[0], bodies[1])
	}
}

// derivedCopy turns raw into a custom.* package edited from source.
func derivedCopy(t *testing.T, raw []byte, id, sourceID, version, sourceSHA string) []byte {
	t.Helper()
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	document["id"] = id
	document["tokens"] = map[string]any{"colorPrimary": "#123456"}
	document["derived_from"] = map[string]any{"id": sourceID, "version": version, "package_sha256": sourceSHA}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// TestThemeCustomizePostgreSQL: the management page reads a package's JSON,
// uploads an edited custom.* copy naming its source, and the copy keeps the
// source's license: a customized paid theme is still refused without it.
func TestThemeCustomizePostgreSQL(t *testing.T) {
	pool := themePool(t)
	ctx := t.Context()
	actor := seedPlatformAdmin(t, pool)
	paidRaw := bytes.Replace(officialFixtureRaw(), []byte(`"official.slate"`), []byte(`"official.paid"`), 1)
	catalog := append(officialFixtureCatalog(), theme.CatalogEntry{ID: "official.paid", Raw: paidRaw, RequiresFeature: theme.FeatureCode("official.paid")})
	guard := &denyGuard{}
	service, err := theme.NewService(pool, audit.New(pool), guard, catalog, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	slate, err := service.Download(ctx, actor, officialFixtureID)
	if err != nil {
		t.Fatal(err)
	}
	body, err := service.PackageBody(ctx, actor, slate.PackageSHA256)
	if err != nil || !bytes.Equal(body, officialFixtureRaw()) {
		t.Fatalf("package body = %v", err)
	}
	// A catalog theme not downloaded yet is readable too.
	paidSum := sha256.Sum256(paidRaw)
	paidSHA := hex.EncodeToString(paidSum[:])
	if body, err := service.PackageBody(ctx, actor, paidSHA); err != nil || !bytes.Equal(body, paidRaw) {
		t.Fatalf("catalog body = %v", err)
	}
	if _, err := service.PackageBody(ctx, actor, strings.Repeat("e", 64)); !errors.Is(err, theme.ErrNotFound) {
		t.Fatalf("unknown body: %v", err)
	}

	custom, err := service.Upload(ctx, actor, derivedCopy(t, body, "custom.slate", officialFixtureID, "1.0.0", slate.PackageSHA256))
	if err != nil || custom.Source != "upload" || custom.DerivedFrom == nil || custom.DerivedFrom.PackageSHA256 != slate.PackageSHA256 {
		t.Fatalf("upload derived = %+v, %v", custom, err)
	}
	if activated, err := service.Activate(ctx, actor, custom.PackageSHA256, 0); err != nil || activated.ThemeID != "custom.slate" {
		t.Fatalf("activate derived = %+v, %v", activated, err)
	}
	view, err := service.Catalog(ctx, actor)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range view.Packages {
		if item.ThemeID == "custom.slate" && (item.DerivedFrom == nil || item.DerivedFrom.ID != officialFixtureID || !item.Active) {
			t.Fatalf("catalog derived = %+v", item)
		}
	}

	// The source can be removed; its JSON stays readable for the upgrade merge.
	if err := service.Remove(ctx, actor, slate.PackageSHA256); err != nil {
		t.Fatal(err)
	}
	if again, err := service.PackageBody(ctx, actor, slate.PackageSHA256); err != nil || !bytes.Equal(again, body) {
		t.Fatalf("removed source body = %v", err)
	}

	// A wrong or unknown source is refused at upload.
	if _, err := service.Upload(ctx, actor, derivedCopy(t, body, "custom.forged", officialFixtureID, "9.9.9", slate.PackageSHA256)); !errors.Is(err, theme.ErrInvalidPackage) {
		t.Fatalf("forged version: %v", err)
	}
	if _, err := service.Upload(ctx, actor, derivedCopy(t, body, "custom.ghost", officialFixtureID, "1.0.0", strings.Repeat("e", 64))); !errors.Is(err, theme.ErrInvalidPackage) {
		t.Fatalf("unknown source: %v", err)
	}

	// Editing a paid theme does not free it: the copy needs the source's feature.
	paidCopy, err := service.Upload(ctx, actor, derivedCopy(t, paidRaw, "custom.paid", "official.paid", "1.0.0", paidSHA))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Activate(ctx, actor, paidCopy.PackageSHA256, 1); !errors.Is(err, theme.ErrEntitlementDenied) || guard.calls != 1 {
		t.Fatalf("customized paid theme: %v (guard calls %d)", err, guard.calls)
	}
}

// officialFixtureID / officialFixtureCatalog: the community edition ships only
// the default theme; these tests need a second downloadable theme, so they use
// the default package under an official id with its own primary color.
const officialFixtureID = "official.slate"

func officialFixtureRaw() []byte {
	var document map[string]any
	if err := json.Unmarshal(theme.BuiltinCatalog()[0].Raw, &document); err != nil {
		panic(err)
	}
	document["id"] = officialFixtureID
	document["tokens"] = map[string]any{"colorPrimary": "#0f766e"}
	raw, err := json.Marshal(document)
	if err != nil {
		panic(err)
	}
	return raw
}

func officialFixtureCatalog() []theme.CatalogEntry {
	return append(theme.BuiltinCatalog(), theme.CatalogEntry{ID: officialFixtureID, Raw: officialFixtureRaw()})
}
