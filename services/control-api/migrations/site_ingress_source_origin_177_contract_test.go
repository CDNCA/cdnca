package migrations_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

func TestSITE08IngressSourceOrigin177Contract(t *testing.T) {
	predecessorUp, err := controlmigrations.FS.ReadFile("176_site_ipv6_rollout_state.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	predecessorDown, err := controlmigrations.FS.ReadFile("176_site_ipv6_rollout_state.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	upBytes, err := controlmigrations.FS.ReadFile("177_site_ingress_source_origin.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	downBytes, err := controlmigrations.FS.ReadFile("177_site_ingress_source_origin.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down := string(upBytes), string(downBytes)
	for _, required := range []string{
		"migration 177 requires the exact verified 176 release head",
		fmt.Sprintf("%x", sha256.Sum256(predecessorUp)),
		fmt.Sprintf("%x", sha256.Sum256(predecessorDown)),
		"ADD COLUMN ingress_source_enabled boolean NOT NULL DEFAULT false",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("177 up missing %q", required)
		}
	}
	upSHA := fmt.Sprintf("%x", sha256.Sum256(upBytes))
	for _, required := range []string{
		"migration 177 rollback requires the exact verified 177 head", upSHA,
		"migration 177 rollback would discard enabled ingress-source origin facts",
		"WHERE ingress_source_enabled", "DROP COLUMN ingress_source_enabled",
	} {
		if !strings.Contains(down, required) {
			t.Errorf("177 down missing %q", required)
		}
	}
	if refusal, mutation := strings.Index(down, "migration 177 rollback would discard enabled ingress-source origin facts"),
		strings.Index(down, "DROP COLUMN ingress_source_enabled"); refusal < 0 || mutation < 0 || refusal > mutation {
		t.Fatal("177 fact refusal must precede destructive rollback")
	}
}
