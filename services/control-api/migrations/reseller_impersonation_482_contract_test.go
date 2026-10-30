package migrations_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

// (ADR 0018 RS-07): 482 follows 481_reseller_packages
// (pinned by checksum); renumbering moves the P48xx codes with the version.
const (
	resellerImpersonationVersion       = 482
	resellerImpersonationID            = "482_reseller_impersonation"
	resellerImpersonationPinnedID      = "481_reseller_packages"
	resellerImpersonationPinnedUpSHA   = "0090f42d63231589ad8eff70f4d230da7b38bd9cb2a1080eae5cd8507c68b2b7"
	resellerImpersonationPinnedDownSHA = "d23d1fa3bb822e9f2163be035e1406d4e4adc43723eec0453476467d9879e7ac"
	resellerImpersonationUpSHA         = "0dac3d102451e85c7a0c18be2f067d1efc3d57a9250d0e688383de2c3a93609f"
	resellerImpersonationDownSHA       = "59951ed53896a1e8a6646738ffcf7ac960b60bba75c222b9d011ac978b288d48"
)

func TestResellerImpersonation482Contract(t *testing.T) {
	previous := resellerImpersonationVersion - 1
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{resellerImpersonationID + ".up.sql", resellerImpersonationUpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", previous),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", previous),
			"migration_id='" + resellerImpersonationPinnedID + "'",
			"checksum_sha256='" + resellerImpersonationPinnedUpSHA + "'",
			"down_checksum_sha256='" + resellerImpersonationPinnedDownSHA + "'",
			fmt.Sprintf("ERRCODE='P%d0'", resellerImpersonationVersion),
			"CREATE FUNCTION impersonation_actor_may_target_482(actor_scope uuid, target_scope uuid)",
			"customer.parent_scope_id = actor.id AND reseller_scope_active_480(actor.id)",
			"'reseller.customers.manage'",
			"CREATE OR REPLACE FUNCTION assert_admin_impersonation_grant_principals()",
			"CREATE OR REPLACE FUNCTION assert_admin_impersonation_session_fact()",
			"CREATE OR REPLACE FUNCTION assert_admin_impersonation_revoker()",
			"NEW.original_actor_scope_id IS DISTINCT FROM NEW.revoked_by_scope_id",
		}},
		{resellerImpersonationID + ".down.sql", resellerImpersonationDownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", resellerImpersonationVersion),
			"migration_id='" + resellerImpersonationID + "'",
			fmt.Sprintf("ERRCODE='P%d1'", resellerImpersonationVersion),
			fmt.Sprintf("ERRCODE='P%d2'", resellerImpersonationVersion),
			"actor_kind IS DISTINCT FROM 'platform'",
			"DROP FUNCTION impersonation_actor_may_target_482(uuid, uuid)",
		}},
	} {
		raw, err := controlmigrations.FS.ReadFile(script.name)
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != script.sha {
			t.Fatalf("%s checksum drift: %s", script.name, got)
		}
		text := string(raw)
		for _, required := range script.required {
			if !strings.Contains(text, required) {
				t.Errorf("%s missing %q", script.name, required)
			}
		}
		guard, mutation := strings.Index(text, "RAISE EXCEPTION"), strings.Index(text, "CREATE ")
		if guard < 0 || mutation < guard {
			t.Errorf("%s guard must precede the first mutation", script.name)
		}
	}
	// The down script restores 038's functions verbatim.
	original, err := controlmigrations.FS.ReadFile("038_admin_impersonation.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := controlmigrations.FS.ReadFile(resellerImpersonationID + ".down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"assert_admin_impersonation_grant_principals", "assert_admin_impersonation_session_fact",
		"assert_admin_impersonation_revoker"} {
		header := "CREATE FUNCTION " + name + "()"
		start := strings.Index(string(original), header)
		if start < 0 {
			t.Fatalf("038 has no %s", name)
		}
		end := strings.Index(string(original)[start:], "\n$$;") + start
		body := strings.TrimPrefix(string(original)[start:end], "CREATE FUNCTION")
		if !strings.Contains(string(down), "CREATE OR REPLACE FUNCTION"+body) {
			t.Errorf("482 down does not restore %s from 038", name)
		}
	}
}
