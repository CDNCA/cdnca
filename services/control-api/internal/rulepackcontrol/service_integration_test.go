//go:build integration

package rulepackcontrol

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/rulepack"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var fixtures = filepath.Join("..", "..", "..", "..", "libs", "rulepack", "testdata")

// The differential fixture's user pack belongs to this tenant scope.
var fixtureTenant = uuid.MustParse("11111111-1111-4111-8111-111111111111")

type world struct {
	pool     *pgxpool.Pool
	service  *Service
	platform Actor
	tenantA  Actor
	tenantB  Actor
	siteA1   uuid.UUID
	siteA2   uuid.UUID
	siteB1   uuid.UUID
}

func newWorld(t *testing.T) world {
	pool := testPool(t)
	now := time.Date(2026, time.October, 17, 12, 0, 0, 0, time.UTC)
	w := world{pool: pool, service: NewService(pool, func() time.Time { return now })}
	w.platform = Actor{UserID: insertUser(t, pool, "rp-admin"), ScopeID: uuid.New(), ScopeKind: "platform"}
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, w.platform.ScopeID)
	w.tenantA = insertTenant(t, pool, fixtureTenant, "rp-a")
	w.tenantB = insertTenant(t, pool, uuid.New(), "rp-b")
	w.siteA1 = insertSite(t, pool, w.tenantA, "a1.example.test", 1)
	w.siteA2 = insertSite(t, pool, w.tenantA, "a2.example.test", 2)
	w.siteB1 = insertSite(t, pool, w.tenantB, "b1.example.test", 3)
	return w
}

func (w world) importFile(t *testing.T, actor Actor, name string) Pack {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(fixtures, "packs", name))
	if err != nil {
		t.Fatal(err)
	}
	pack, err := w.service.Import(t.Context(), actor, content)
	if err != nil {
		t.Fatalf("import %s: %v", name, err)
	}
	return pack
}

func (w world) put(t *testing.T, actor Actor, input OverrideInput) error {
	t.Helper()
	_, _, err := w.service.PutOverride(t.Context(), actor, input)
	return err
}

func platformLevel() (rulepack.Level, *uuid.UUID) { return rulepack.LevelPlatform, nil }

func ref(level rulepack.Level, id uuid.UUID) OverrideInput {
	return OverrideInput{Level: level, LevelObjectID: &id}
}

func with(base OverrideInput, packID string, state rulepack.State, allowLower bool) OverrideInput {
	base.PackID, base.State, base.AllowLower = packID, state, allowLower
	return base
}

func mountIDs(site SiteMounts) string {
	if site.Resolution.Security == nil {
		return "<conflict>"
	}
	ids := []string{}
	for _, mount := range site.Resolution.Security.Mounts {
		ids = append(ids, mount.PackID)
	}
	return strings.Join(ids, ",")
}

func TestDownloadEnableInheritanceAndPublication(t *testing.T) {
	w := newWorld(t)
	ctx := t.Context()
	if _, err := w.service.Import(ctx, w.tenantA, mustRead(t, "packs/system-sqli.json")); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("tenant imports a system pack: %v", err)
	}
	sqli := w.importFile(t, w.platform, "system-sqli.json")
	if sqli.CurrentVersion != "1.0.0" || sqli.Versions[0].State != "downloaded" {
		t.Fatalf("imported = %+v", sqli)
	}
	if _, err := w.service.Import(ctx, w.platform, mustRead(t, "packs/system-sqli.json")); !errors.Is(err, ErrExists) {
		t.Fatalf("re-import: %v", err)
	}

	// Downloaded but not enabled: no site mounts it.
	site, err := w.service.Site(ctx, w.tenantA, w.siteA1)
	if err != nil || mountIDs(site) != "" || !site.UpToDate {
		t.Fatalf("downloaded only: %q %+v %v", mountIDs(site), site.Published, err)
	}

	// A system pack nobody opened is locked to the platform.
	if err := w.put(t, w.tenantA, with(ref(rulepack.LevelTenant, w.tenantA.ScopeID), sqli.PackID, rulepack.StateEnabled, false)); !errors.Is(err, ErrLocked) {
		t.Fatalf("tenant enables a locked pack: %v", err)
	}
	// Platform enables and allows tenants; tenant A disables and allows its
	// sites; site A1 enables again -> only A1 (and tenant B) run it.
	level, object := platformLevel()
	if err := w.put(t, w.platform, with(OverrideInput{Level: level, LevelObjectID: object}, sqli.PackID, rulepack.StateEnabled, true)); err != nil {
		t.Fatal(err)
	}
	if err := w.put(t, w.tenantA, with(ref(rulepack.LevelTenant, w.tenantA.ScopeID), sqli.PackID, rulepack.StateDisabled, true)); err != nil {
		t.Fatal(err)
	}
	if err := w.put(t, w.tenantA, with(ref(rulepack.LevelSite, w.siteA1), sqli.PackID, rulepack.StateEnabled, false)); err != nil {
		t.Fatal(err)
	}
	if err := w.put(t, w.tenantB, with(ref(rulepack.LevelSite, w.siteA2), sqli.PackID, rulepack.StateEnabled, false)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("tenant B writes tenant A's site: %v", err)
	}
	for _, item := range []struct {
		actor Actor
		site  uuid.UUID
		want  string
	}{{w.tenantA, w.siteA1, sqli.PackID}, {w.tenantA, w.siteA2, ""}, {w.tenantB, w.siteB1, sqli.PackID}} {
		site, err := w.service.Site(ctx, item.actor, item.site)
		if err != nil || mountIDs(site) != item.want {
			t.Fatalf("site %s mounts %q, want %q (%v)", item.site, mountIDs(site), item.want, err)
		}
	}
	view, err := w.service.View(ctx, w.tenantA, LevelInput{Level: rulepack.LevelSite, ObjectID: &w.siteA1})
	if err != nil || len(view.Packs) != 1 || view.Packs[0].Effect.EnabledAt.Level != rulepack.LevelSite || len(view.Overrides) != 1 {
		t.Fatalf("site view = %+v %v", view, err)
	}

	// Rule-level and params at the site; publish; deleting is refused while in use.
	siteRef := ref(rulepack.LevelSite, w.siteA1)
	if err := w.put(t, w.tenantA, OverrideInput{Level: siteRef.Level, LevelObjectID: siteRef.LevelObjectID, PackID: sqli.PackID,
		RuleID: "r020", State: rulepack.StateDisabled}); err != nil {
		t.Fatal(err)
	}
	if err := w.put(t, w.tenantA, OverrideInput{Level: siteRef.Level, LevelObjectID: siteRef.LevelObjectID, PackID: sqli.PackID,
		RuleID: "nope", State: rulepack.StateDisabled}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("unknown export: %v", err)
	}
	bad := with(siteRef, sqli.PackID, rulepack.StateEnabled, false)
	bad.Params = json.RawMessage(`{"action":"allow"}`)
	if err := w.put(t, w.tenantA, bad); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("params outside schema: %v", err)
	}
	published, err := w.service.PublishSite(ctx, w.tenantA, w.siteA1)
	if err != nil || published.Published == nil || published.Published.Revision != 1 || !published.UpToDate {
		t.Fatalf("publish = %+v %v", published.Published, err)
	}
	if string(published.Published.Security.Mounts[0].Params[rulepack.ParamExclusions]) != `["r020"]` {
		t.Fatalf("exclusions = %s", published.Published.Security.Mounts[0].Params[rulepack.ParamExclusions])
	}
	again, err := w.service.PublishSite(ctx, w.tenantA, w.siteA1)
	if err != nil || again.Published.Revision != 1 {
		t.Fatalf("republish unchanged = %+v %v", again.Published, err)
	}
	if err := w.service.DeleteVersion(ctx, w.platform, sqli.PackID, "1.0.0"); !errors.Is(err, ErrInUse) {
		t.Fatalf("delete an enabled, mounted pack: %v", err)
	}

	// Disable everywhere, republish (empty mounts), then deleting works.
	if err := w.put(t, w.platform, with(OverrideInput{Level: level, LevelObjectID: object}, sqli.PackID, rulepack.StateDisabled, true)); err != nil {
		t.Fatal(err)
	}
	if err := w.put(t, w.tenantA, with(siteRef, sqli.PackID, rulepack.StateInherit, false)); err != nil {
		t.Fatal(err)
	}
	if published, err = w.service.PublishSite(ctx, w.tenantA, w.siteA1); err != nil || len(published.Published.Security.Mounts) != 0 ||
		published.Published.Revision != 2 {
		t.Fatalf("publish empty = %+v %v", published.Published, err)
	}
	if err := w.service.DeleteVersion(ctx, w.platform, sqli.PackID, "1.0.0"); err != nil {
		t.Fatalf("delete unused: %v", err)
	}
	if view, _ := w.service.View(ctx, w.platform, LevelInput{Level: rulepack.LevelPlatform}); len(view.Packs) != 0 {
		t.Fatalf("pack still listed: %+v", view.Packs)
	}
}

func TestConflictBlocksPublicationUntilOneSideIsDisabled(t *testing.T) {
	w := newWorld(t)
	ctx := t.Context()
	// base blocks /wp-admin (r020); opposite allows the same path at the
	// same layer and priority.
	base := w.importFile(t, w.platform, "system-sqli.json")
	opposite := mustImportModified(t, w, "system-sqli.json", func(d map[string]any) {
		d["pack_id"] = "system/sqli-strict"
		rules := d["rules"].([]any)
		rules[0].(map[string]any)["waf"].(map[string]any)["action"] = "allow"
	})
	level, object := platformLevel()
	for _, id := range []string{base.PackID, opposite.PackID} {
		if err := w.put(t, w.platform, with(OverrideInput{Level: level, LevelObjectID: object}, id, rulepack.StateEnabled, true)); err != nil {
			t.Fatal(err)
		}
	}
	_, err := w.service.PublishSite(ctx, w.tenantA, w.siteA1)
	var conflict *ConflictError
	if !errors.As(err, &conflict) || len(conflict.Resolution.Conflicts) == 0 {
		t.Fatalf("publish with conflict: %v", err)
	}
	first := conflict.Resolution.Conflicts[0]
	if first.Code != rulepack.ConflictOppositeAction || len(first.Sides) != 2 || first.Sides[0].EnabledAt.Level != rulepack.LevelPlatform {
		t.Fatalf("conflict = %+v", first)
	}
	// The tenant switches one side off at its own level -> publishable.
	if err := w.put(t, w.tenantA, with(ref(rulepack.LevelTenant, w.tenantA.ScopeID), opposite.PackID, rulepack.StateDisabled, true)); err != nil {
		t.Fatal(err)
	}
	if published, err := w.service.PublishSite(ctx, w.tenantA, w.siteA1); err != nil || mountIDs(published) != base.PackID {
		t.Fatalf("after disabling one side: %q %v", mountIDs(published), err)
	}
	// Tenant B still has both enabled: still refused there.
	if _, err := w.service.PublishSite(ctx, w.tenantB, w.siteB1); !errors.As(err, &conflict) {
		t.Fatalf("tenant B: %v", err)
	}
}

// TestControlMatchesDifferentialGolden: the control plane, from the
// authored packs and the same settings, publishes the security document
// libs/rulepack resolved (testdata/differential) and the edge agent precheck
// verifies (agents/edge-agent/internal/rulepackprecheck).
func TestControlMatchesDifferentialGolden(t *testing.T) {
	w := newWorld(t)
	ctx := t.Context()
	for _, name := range []string{"system-sqli.json", "system-cc.json"} {
		w.importFile(t, w.platform, name)
	}
	user := w.importFile(t, w.tenantA, "user-allow.json")
	level, object := platformLevel()
	sqli := with(OverrideInput{Level: level, LevelObjectID: object}, "system/sqli-basic", rulepack.StateEnabled, false)
	sqli.Params = json.RawMessage(`{"action":"log"}`)
	cc := with(OverrideInput{Level: level, LevelObjectID: object}, "system/cc-basic", rulepack.StateEnabled, false)
	priority := 200
	cc.Priority, cc.Params = &priority, json.RawMessage(`{"requests":300}`)
	for _, input := range []OverrideInput{sqli, cc,
		{Level: level, PackID: "system/sqli-basic", RuleID: "r020", State: rulepack.StateDisabled}} {
		if err := w.put(t, w.platform, input); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.put(t, w.tenantA, with(ref(rulepack.LevelTenant, w.tenantA.ScopeID), user.PackID, rulepack.StateEnabled, true)); err != nil {
		t.Fatal(err)
	}
	published, err := w.service.PublishSite(ctx, w.tenantA, w.siteA1)
	if err != nil {
		t.Fatal(err)
	}
	var golden rulepack.Security
	if err := json.Unmarshal(mustRead(t, "differential/security.json"), &golden); err != nil {
		t.Fatal(err)
	}
	if published.Published.Security.ResolvedSHA256 != golden.ResolvedSHA256 {
		t.Fatalf("control resolved %s, golden %s", published.Published.Security.ResolvedSHA256, golden.ResolvedSHA256)
	}
	// The stored artifacts are byte-identical to the golden objects.
	for _, mount := range published.Published.Security.Mounts {
		var stored []byte
		if err := w.pool.QueryRow(ctx, `SELECT content FROM rule_pack_artifacts WHERE sha256=$1`, mount.SHA256).Scan(&stored); err != nil {
			t.Fatal(err)
		}
		if string(stored) != string(mustRead(t, filepath.Join("differential", "objects", mount.SHA256))) {
			t.Fatalf("stored %s differs from the golden object", mount.PackID)
		}
	}
}

func mustImportModified(t *testing.T, w world, name string, change func(map[string]any)) Pack {
	t.Helper()
	var document map[string]any
	if err := json.Unmarshal(mustRead(t, filepath.Join("packs", name)), &document); err != nil {
		t.Fatal(err)
	}
	change(document)
	encoded, _ := json.Marshal(document)
	pack, err := w.service.Import(t.Context(), w.platform, encoded)
	if err != nil {
		t.Fatal(err)
	}
	return pack
}

func mustRead(t *testing.T, name string) []byte {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(fixtures, name))
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func insertUser(t *testing.T, pool *pgxpool.Pool, name string) uuid.UUID {
	id := uuid.New()
	mustExec(t, pool, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,$2,'test-only')`, id, name)
	return id
}

func insertTenant(t *testing.T, pool *pgxpool.Pool, scopeID uuid.UUID, name string) Actor {
	tenantID := uuid.New()
	mustExec(t, pool, `INSERT INTO tenants(id,display_name) VALUES($1,$2)`, tenantID, name)
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, scopeID, tenantID)
	user := insertUser(t, pool, name)
	mustExec(t, pool, `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, scopeID, user)
	return Actor{UserID: user, ScopeID: scopeID, ScopeKind: "tenant"}
}

func insertSite(t *testing.T, pool *pgxpool.Pool, owner Actor, domain string, displayID int) uuid.UUID {
	id := uuid.New()
	// A site needs its origin pool in the same transaction (deferred check).
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		for _, statement := range []struct {
			query string
			args  []any
		}{
			{`INSERT INTO sites(id,scope_id,owner_user_id,domain,origins,origin_hosts,created_by_user_id,updated_by_user_id,
				display_id) VALUES($1,$2,$3,$4,ARRAY['origin.example.test:80'],ARRAY['origin.example.test'],$3,$3,$5)`,
				[]any{id, owner.ScopeID, owner.UserID, domain, displayID}},
			{`INSERT INTO site_origin_pools(site_id) VALUES($1)`, []any{id}},
			{`INSERT INTO site_origins(site_id,position,host,port) VALUES($1,1,'origin.example.test',80)`, []any{id}},
		} {
			if _, err := tx.Exec(t.Context(), statement.query, statement.args...); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func mustExec(t *testing.T, pool *pgxpool.Pool, query string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), query, args...); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
}

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if pool := databasetest.ClonedMigratedPool(t, nil); pool != nil {
		return pool
	}
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
	defer cancel()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "rule_pack_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA IF EXISTS "+identifier+" CASCADE")
		admin.Close()
	})
	if err := database.Migrate(ctx, pool, "up"); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return pool
}

// 方案 A: a modsecurity pack only narrows the site's CRS profile; a site
// whose WAF library runs no managed WAF cannot publish one
// (crs_out_of_profile, with the disable remedies), and the live view shows
// the same conflict.
func TestModSecurityPackOutsideTheSiteProfileIsRefused(t *testing.T) {
	w := newWorld(t)
	pack := mustImportModified(t, w, "system-crs.json", func(d map[string]any) { d["pack_id"] = "system/sqli-narrow" })
	level, object := platformLevel()
	if err := w.put(t, w.platform, with(OverrideInput{Level: level, LevelObjectID: object}, pack.PackID, rulepack.StateEnabled, true)); err != nil {
		t.Fatal(err)
	}
	_, err := w.service.PublishSite(t.Context(), w.tenantA, w.siteA1)
	var conflict *ConflictError
	if !errors.As(err, &conflict) || len(conflict.Resolution.Conflicts) != 1 {
		t.Fatalf("publish: %v", err)
	}
	refused := conflict.Resolution.Conflicts[0]
	if refused.Code != rulepack.ConflictCRSOutOfProfile || len(refused.Sides) != 1 || refused.Sides[0].PackID != pack.PackID ||
		len(refused.Remedies) == 0 {
		t.Fatalf("conflict = %+v", refused)
	}
	view, err := w.service.Site(t.Context(), w.tenantA, w.siteA1)
	if err != nil || view.Resolution.Security != nil || view.UpToDate || len(view.Resolution.Conflicts) != 1 ||
		view.Resolution.Conflicts[0].Code != rulepack.ConflictCRSOutOfProfile {
		t.Fatalf("site view: %+v %v", view.Resolution.Conflicts, err)
	}
	var published bool
	if err := w.pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM site_security_mounts WHERE site_id=$1)`, w.siteA1).
		Scan(&published); err != nil || published {
		t.Fatalf("refused mounts were written: %v %v", published, err)
	}
}
