//go:build integration

package migrations_test

import (
	"strconv"
	"testing"

	"github.com/google/uuid"
)

// TestRegionCatalogCode528 (fz-x12, 待出包前全量跑): every region gets a
// stable lower-case ASCII code: 默认 → default, an ASCII name its lower-cased
// self, a Chinese name region-<display_id>; a taken or region-<n> shaped
// name falls back too. The code is generated, never set, and survives a
// rename. Up, down and up again.
func TestRegionCatalogCode528(t *testing.T) {
	const version = 528
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	// 迁移模板是空库（无平台作用域），223 的"默认"种子行无处落；这里自建平台作用域与"默认"行。
	platform := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platform); err != nil {
		t.Fatal(err)
	}
	insert := func(name string) int64 {
		t.Helper()
		var displayID int64
		if err := pool.QueryRow(ctx, `INSERT INTO region_catalog(id,platform_scope_id,name) VALUES(gen_random_uuid(),$1,$2)
			RETURNING display_id`, platform, name).Scan(&displayID); err != nil {
			t.Fatalf("insert %s: %v", name, err)
		}
		return displayID
	}
	insert("默认")
	eastID := insert("华东") // before 528: backfilled
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	code := func(name string) string {
		t.Helper()
		var value string
		if err := pool.QueryRow(ctx, `SELECT code FROM region_catalog WHERE platform_scope_id=$1 AND name=$2`, platform, name).Scan(&value); err != nil {
			t.Fatalf("code of %s: %v", name, err)
		}
		return value
	}
	if got := code("默认"); got != "default" {
		t.Errorf("默认 code = %q", got)
	}
	if got, want := code("华东"), "region-"+itoa(eastID); got != want {
		t.Errorf("华东 code = %q, want %q", got, want)
	}
	insert("CN-West")
	if got := code("CN-West"); got != "cn-west" {
		t.Errorf("CN-West code = %q", got)
	}
	shaped := insert("region-1")
	if got, want := code("region-1"), "region-"+itoa(shaped); got != want {
		t.Errorf("region-1 code = %q, want %q (a region-<n> name never takes another's code)", got, want)
	}
	taken := insert("Cn-West") // another name whose code would be cn-west: taken, falls back
	var takenCode string
	if err := pool.QueryRow(ctx, `SELECT code FROM region_catalog WHERE display_id=$1`, taken).Scan(&takenCode); err != nil ||
		takenCode != "region-"+itoa(taken) {
		t.Errorf("taken code fallback = %q, %v", takenCode, err)
	}
	// generated, immutable, kept across a rename
	if _, err := pool.Exec(ctx, `INSERT INTO region_catalog(id,platform_scope_id,name,code) VALUES(gen_random_uuid(),$1,'x','x')`, platform); err == nil {
		t.Error("an explicit code was accepted")
	}
	if _, err := pool.Exec(ctx, `UPDATE region_catalog SET code='other',revision=revision+1 WHERE display_id=$1`, eastID); err == nil {
		t.Error("a code change was accepted")
	}
	if _, err := pool.Exec(ctx, `UPDATE region_catalog SET name='华东一区',revision=revision+1 WHERE display_id=$1`, eastID); err != nil {
		t.Fatal(err)
	}
	if got, want := code("华东一区"), "region-"+itoa(eastID); got != want {
		t.Errorf("renamed code = %q, want %q", got, want)
	}
	var sshColumn bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.columns
		WHERE table_name='node_ssh_install_jobs' AND column_name='node_region')`).Scan(&sshColumn); err != nil || sshColumn {
		t.Errorf("node_ssh_install_jobs.node_region still there (%v)", err)
	}
}

func itoa(value int64) string { return strconv.FormatInt(value, 10) }
