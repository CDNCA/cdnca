package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
)

// Migration 399 (the 333 node artifact trigger accepts the
// v2 dynamic routing root) is a placeholder number (BATCH-PLUGIN 第 16 条):
// the merge renumbers it. Everything that changes with the renumbering is here.
const (
	migration399Version         = 399
	migration399ID              = "399_security_activation_v2_root"
	migration399PreviousVersion = 398
	migration399PreviousID      = "398_tenant_member_invitations"
	migration399PreviousUpSHA   = "a380fd93568e70d22bd9fb4f842686225b66d4ed2bd86a72a9b6d16a7e2c882e"
	migration399PreviousDownSHA = "ef525337ac937c5974d51c66e657f2d01223d40a028345c56a19d8cdb8a394dd"
	migration399UpSHA           = "10ed624dec56751600ff30cc869a5c2215845bb6b3e6770a7e8165e4a9d37b7e"
	migration399DownSHA         = "a8885fa8fb4679ce1dd62dfc0a414d48d6c64a0620471dda00f8e32b2fb9399f"
)

func TestSecurityActivationV2Root399Contract(t *testing.T) {
	// The v1 root media type (site runtime v8, deleted with dr-d13-c3b):
	// 399 still names it; 417 removes it.
	v1Root := "'" + migrationV1SiteObjectRootMediaType + "'"
	v2Root := "'" + siteobject.RootMediaTypeV2 + "'"
	for _, script := range []struct {
		name, sha         string
		required, refused []string
	}{
		{migration399ID + ".up.sql", migration399UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration399PreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration399PreviousVersion),
			"migration_id='" + migration399PreviousID + "'", migration399PreviousUpSHA, migration399PreviousDownSHA,
			"ERRCODE='P3990'", "CREATE OR REPLACE FUNCTION validate_security_policy_activation_node_artifact_333()",
			"root.media_type IN (" + v1Root, v2Root, "ERRCODE='P3332'",
		}, nil},
		{migration399ID + ".down.sql", migration399DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration399Version),
			"migration_id='" + migration399ID + "'", "ERRCODE='P3991'",
			"root.media_type=" + v1Root, "ERRCODE='P3332'",
		}, []string{v2Root}},
	} {
		raw, err := FS.ReadFile(script.name)
		if err != nil {
			t.Skipf("%s not embedded under this number (local renumbering): %v", script.name, err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != script.sha {
			t.Fatalf("%s checksum drift: %s", script.name, got)
		}
		for _, required := range script.required {
			if !strings.Contains(string(raw), required) {
				t.Errorf("%s missing %q", script.name, required)
			}
		}
		for _, refused := range script.refused {
			if strings.Contains(string(raw), refused) {
				t.Errorf("%s still names %q", script.name, refused)
			}
		}
	}
	// The down script restores exactly the 354 trigger body.
	up354, err := FS.ReadFile(edgeSiteObjectsID + ".up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := FS.ReadFile(migration399ID + ".down.sql")
	if err != nil {
		t.Fatal(err)
	}
	const marker = "CREATE OR REPLACE FUNCTION validate_security_policy_activation_node_artifact_333()"
	body354 := string(up354)[strings.Index(string(up354), marker):]
	body354 = body354[:strings.Index(body354, "$$;")+3]
	bodyDown := string(down)[strings.Index(string(down), marker):]
	if strings.TrimSpace(bodyDown) != body354 {
		t.Fatal("399 down does not restore the 354 trigger body")
	}
}
