package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

const (
	activeConfigIdentity232UpSHA   = "a034c7c7036d2af6be7fd99094d0ea938170339e0dc937db54a1c333973bfa0a"
	activeConfigIdentity232DownSHA = "0e36532308868afb1f7b81f3ca6a0eb720ef8c303f6fb6d728ce7c01d0b703fc"
)

func TestActiveConfigIdentityConfigurationScope232Contract(t *testing.T) {
	files := map[string]struct {
		name string
		sha  string
	}{
		"up":   {"232_active_config_identity_configuration_scope.up.sql", activeConfigIdentity232UpSHA},
		"down": {"232_active_config_identity_configuration_scope.down.sql", activeConfigIdentity232DownSHA},
	}
	contents := make(map[string]string, len(files))
	for label, file := range files {
		payload, err := FS.ReadFile(file.name)
		if err != nil {
			t.Fatalf("read migration 232 %s: %v", label, err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(payload)); got != file.sha {
			t.Fatalf("migration 232 %s checksum = %s, want %s", label, got, file.sha)
		}
		contents[label] = string(payload)
	}

	combined := contents["up"] + contents["down"]
	for _, required := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 231",
		"version = 231 AND migration_id = '231_edge_rollout_paused_retry'",
		"2df83085e830707c1a0e9056bdad2280352b574f6bf07afdcbf015069c2414ee",
		"f07f30d0f813039066de5b626a08a12b796c6f8345adb566505ba7732fc80a0a",
		"version.configuration_scope_id = config_state.configuration_scope_id",
		"config_state.configuration_scope_id IS NOT NULL",
		"deployment.action = 'apply'",
		"deployment.state IN ('activated', 'healthy')",
		"deployment.command_sha256 = sha256(deployment.command_bytes)",
		"binding.deployment_attempt = deployment.attempt",
		"binding.artifact_id = artifact.id",
		"rollout.configuration_scope_id = config_state.configuration_scope_id",
		"USING ERRCODE = 'P2320'",
		"USING ERRCODE = 'P2321'",
		"version = 232 AND migration_id = '232_active_config_identity_configuration_scope'",
		activeConfigIdentity232UpSHA,
		"version.configuration_scope_id = node.scope_id",
	} {
		if !strings.Contains(combined, required) {
			t.Errorf("migration 232 is missing %q", required)
		}
	}
	for _, forbidden := range []string{"REVOKE ALL", "DELETE FROM schema_migrations", " CASCADE", "__UP_SHA256__", "__DOWN_SHA256__"} {
		if strings.Contains(strings.ToUpper(combined), strings.ToUpper(forbidden)) {
			t.Errorf("migration 232 contains forbidden token %q", forbidden)
		}
	}
}
