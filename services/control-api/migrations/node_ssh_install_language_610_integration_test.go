//go:build integration

package migrations_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

// TestNodeSSHInstallLanguage610: an existing job keeps language ” (no
// --lang), new rows take ” / 'zh' / 'en' only, the guard refuses a second
// apply and 609→610 goes up, down and up again.
func TestNodeSSHInstallLanguage610(t *testing.T) {
	const version = 610
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	scopeID, userID := uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, scopeID)
	mustExec(t, pool, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'ssh-610','SSH 610','test-only')`, userID)
	insert := func(columns, values string, args ...any) error {
		_, err := pool.Exec(ctx, `INSERT INTO node_ssh_install_jobs(id,scope_id,batch_id,host,port,username,auth_kind,
			control_plane,state,failure_code,created_by_user_id,created_at,finished_at,updated_at`+columns+`)
			VALUES($1,$2,$1,$3,22,'root','password','https://console.example.com','failed','ssh_unreachable',$4,now(),now(),now()`+values+`)`,
			args...)
		return err
	}
	oldJob := uuid.New()
	if err := insert("", "", oldJob, scopeID, "203.0.113.1", userID); err != nil {
		t.Fatal(err)
	}
	if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
		t.Fatalf("up %d: %v", version, err)
	}
	var language string
	if err := pool.QueryRow(ctx, `SELECT language FROM node_ssh_install_jobs WHERE id=$1`, oldJob).Scan(&language); err != nil || language != "" {
		t.Fatalf("existing job language %q %v, want ''", language, err)
	}
	for index, value := range []string{"", "zh", "en"} {
		if err := insert(",language", ",$5", uuid.New(), scopeID, fmt.Sprintf("203.0.113.%d", index+2), userID, value); err != nil {
			t.Fatalf("language %q refused: %v", value, err)
		}
	}
	for _, value := range []string{"zh-CN", "fr", "EN"} {
		if err := insert(",language", ",$5", uuid.New(), scopeID, "203.0.113.9", userID, value); err == nil ||
			!strings.Contains(err.Error(), "node_ssh_install_jobs_language_610_check") {
			t.Fatalf("language %q accepted: %v", value, err)
		}
	}
	up, err := controlmigrations.FS.ReadFile("610_node_ssh_install_language.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, string(up)); err == nil || !strings.Contains(err.Error(), "P6100") {
		t.Fatalf("610 re-applied on the head: %v", err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
		t.Fatalf("down %d: %v", version, err)
	}
	var columns int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_schema=current_schema()
		AND table_name='node_ssh_install_jobs' AND column_name='language'`).Scan(&columns); err != nil || columns != 0 {
		t.Fatalf("language column after down: %d %v", columns, err)
	}
	if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
		t.Fatalf("up again %d: %v", version, err)
	}
}
