package migrations

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

const (
	edgeRolloutPausedRetry230UpSHA   = "5a754062f0248ba9f8138cb3240f58a921968dc1526e551a78d5fcfc8e009551"
	edgeRolloutPausedRetry230DownSHA = "5a37942455d54cd6534b987eb5365e8eaddc21410797cfe0eb9bc6651bfad0e6"
	edgeRolloutPausedRetry231UpSHA   = "2df83085e830707c1a0e9056bdad2280352b574f6bf07afdcbf015069c2414ee"
	edgeRolloutPausedRetry231DownSHA = "f07f30d0f813039066de5b626a08a12b796c6f8345adb566505ba7732fc80a0a"
)

func TestEdgeRolloutPausedRetry231Contract(t *testing.T) {
	files := map[string]struct {
		name string
		sha  string
	}{
		"230 up":   {"230_security_policy_system_role_projection.up.sql", edgeRolloutPausedRetry230UpSHA},
		"230 down": {"230_security_policy_system_role_projection.down.sql", edgeRolloutPausedRetry230DownSHA},
		"231 up":   {"231_edge_rollout_paused_retry.up.sql", edgeRolloutPausedRetry231UpSHA},
		"231 down": {"231_edge_rollout_paused_retry.down.sql", edgeRolloutPausedRetry231DownSHA},
	}
	contents := make(map[string]string, len(files))
	for label, file := range files {
		payload, err := FS.ReadFile(file.name)
		if err != nil {
			t.Fatalf("read %s: %v", label, err)
		}
		if got := edgeRolloutPausedRetry231SHA(payload); got != file.sha {
			t.Fatalf("migration %s checksum = %s, want %s", label, got, file.sha)
		}
		contents[label] = string(payload)
	}

	up, down := contents["231 up"], contents["231 down"]
	for _, required := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 230",
		"(SELECT max(version) FROM schema_migrations) <> 230",
		"version = 230 AND migration_id = '230_security_policy_system_role_projection'",
		edgeRolloutPausedRetry230UpSHA,
		edgeRolloutPausedRetry230DownSHA,
		"OLD.status='paused' AND NEW.status='paused'",
		"request.operation='edge_rollout.retry'",
		"NEW.pause_reason IS NOT DISTINCT FROM OLD.pause_reason",
		"NEW.released_cohort=OLD.released_cohort",
		"USING ERRCODE = 'P2310'",
		"(SELECT count(*) FROM schema_migrations) <> 231",
		"(SELECT max(version) FROM schema_migrations) <> 231",
		"version = 231 AND migration_id = '231_edge_rollout_paused_retry'",
		edgeRolloutPausedRetry231UpSHA,
	} {
		if !strings.Contains(up+down, required) {
			t.Errorf("migration 231 is missing %q", required)
		}
	}
	if strings.Contains(up+down, "228_edge_rollout_paused_retry") {
		t.Fatal("migration 231 retains the obsolete duplicate version 228 identity")
	}
	for _, forbidden := range []string{" CASCADE", "\nTRUNCATE ", "DELETE FROM SCHEMA_MIGRATIONS", "__UP_SHA256__", "__DOWN_SHA256__"} {
		if strings.Contains(strings.ToUpper(up+down), forbidden) {
			t.Errorf("migration 231 contains forbidden token %q", forbidden)
		}
	}
}

func edgeRolloutPausedRetry231SHA(payload []byte) string {
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}
