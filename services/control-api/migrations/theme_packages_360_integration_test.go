//go:build integration

package migrations_test

import (
	"crypto/sha256"
	"testing"

	"github.com/google/uuid"
)

// TestThemePackages360: brand slots grow by the theme slots; packages are
// immutable except for the removal mark, the active one cannot be removed,
// activations are gap-free and only name present packages; down refuses
// once an activation or a theme slot exists.
func TestThemePackages360(t *testing.T) {
	const version = 360
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	var platformScope uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform' AND tenant_id IS NULL`).Scan(&platformScope); err != nil {
		platformScope = uuid.New()
		mustExec(t, pool, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platformScope)
	}
	userID := uuid.New()
	mustExec(t, pool, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'theme-360','Theme 360','unused')`, userID)
	mustExec(t, pool, `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, platformScope, userID)
	brand := func(slot, mime string) error {
		digest := sha256.Sum256([]byte(slot))
		_, err := pool.Exec(ctx, `INSERT INTO platform_brand_assets(platform_scope_id,slot,revision,reference,mime_type,size_bytes,sha256,object_key,immutable_token,updated_by_user_id,updated_at)
			VALUES($1,$2,1,'asset://brand/'||$2||'/'||encode($3,'hex'),$4,10,$3,'k','t',$5,now())`, platformScope, slot, digest[:], mime, userID)
		return err
	}
	if err := brand("logo_dark", "image/png"); sqlState(err) != "23514" {
		t.Fatalf("359 logo_dark: %v, want 23514", err)
	}
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	if err := brand("logo_dark", "image/jpeg"); sqlState(err) != "23514" {
		t.Fatalf("logo_dark jpeg: %v, want 23514", err)
	}
	if err := brand("logo", "image/png"); err != nil {
		t.Fatalf("logo: %v", err)
	}

	pkg := func(id, source, body string) []byte {
		raw := []byte(body)
		digest := sha256.Sum256(raw)
		mustExec(t, pool, `INSERT INTO theme_packages(package_sha256,theme_id,version,source,package_body,css_sha256,css_body,json_sha256,json_body,downloaded_by_user_id,downloaded_at)
			VALUES($1,$2,'1.0.0',$3,$4,sha256('c'::bytea),'c'::bytea,sha256('j'::bytea),'j'::bytea,$5,now())`, digest[:], id, source, raw, userID)
		return digest[:]
	}
	first := pkg("default", "builtin", `{"a":1}`)
	second := pkg("custom.brand", "upload", `{"a":2}`)
	if _, err := pool.Exec(ctx, `INSERT INTO theme_packages(package_sha256,theme_id,version,source,package_body,css_sha256,css_body,json_sha256,json_body,downloaded_by_user_id,downloaded_at)
		VALUES(sha256('x'::bytea),'custom.x','1.0.0','builtin','x'::bytea,sha256('c'::bytea),'c'::bytea,sha256('j'::bytea),'j'::bytea,$1,now())`, userID); sqlState(err) != "23514" {
		t.Fatalf("custom theme as builtin: %v, want 23514", err)
	}
	activate := func(revision int64, digest []byte) error {
		_, err := pool.Exec(ctx, `INSERT INTO theme_activations(revision,platform_scope_id,package_sha256,activated_by_user_id,request_id,activated_at)
			VALUES($1,$2,$3,$4,'req-360',now())`, revision, platformScope, digest, userID)
		return err
	}
	if err := activate(2, first); sqlState(err) != "P3601" {
		t.Fatalf("gap activation: %v, want P3601", err)
	}
	if err := activate(1, first); err != nil {
		t.Fatalf("activate: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE theme_packages SET removed_at=now(),removed_by_user_id=$2 WHERE package_sha256=$1`, first, userID); sqlState(err) != "P3602" {
		t.Fatalf("remove active: %v, want P3602", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE theme_packages SET removed_at=now(),removed_by_user_id=$2 WHERE package_sha256=$1`, second, userID); err != nil {
		t.Fatalf("remove inactive: %v", err)
	}
	if err := activate(2, second); sqlState(err) != "P3601" {
		t.Fatalf("activate removed: %v, want P3601", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE theme_packages SET version='2.0.0' WHERE package_sha256=$1`, second); sqlState(err) != "P3603" {
		t.Fatalf("mutate package: %v, want P3603", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM theme_activations`); sqlState(err) != "P3603" {
		t.Fatalf("delete activation: %v, want P3603", err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); err == nil {
		t.Fatal("down dropped an activation")
	}
}
