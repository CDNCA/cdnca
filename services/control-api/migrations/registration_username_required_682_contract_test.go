package migrations

import (
	"strings"
	"testing"
)

// Migration 682: username_required false or absent becomes
// true on the exact verified 681 head; revision and updated_* are left alone;
// down writes nothing back.
func TestRegistrationUsernameRequired682Contract(t *testing.T) {
	up, err := FS.ReadFile("682_registration_username_required.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := FS.ReadFile("682_registration_username_required.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 681", "(SELECT max(version) FROM schema_migrations) <> 681",
		"migration_id='681_account_recovery_default_template'", "ERRCODE='P6820'",
		"jsonb_set(settings, '{username_required}', 'true'::jsonb, true)",
		"WHERE settings->'username_required' IS DISTINCT FROM 'true'::jsonb",
		"升级保持既有行为：用户名必填；管理员可在「系统配置 → 账号与安全 → 用户注册」关闭",
	} {
		if !strings.Contains(string(up), fragment) {
			t.Errorf("682 up missing %q", fragment)
		}
	}
	if strings.Contains(string(up), "revision=") || strings.Contains(string(up), "updated_at=") {
		t.Error("682 up must not touch revision or updated_at")
	}
	for _, fragment := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 682", "migration_id='682_registration_username_required'", "ERRCODE='P6821'",
	} {
		if !strings.Contains(string(down), fragment) {
			t.Errorf("682 down missing %q", fragment)
		}
	}
	if strings.Contains(string(down), "UPDATE") {
		t.Error("682 down must not write settings back")
	}
}
