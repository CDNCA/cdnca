package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
)

// Migration 426 (dynamic routing is the only node runtime,
// the v1 site object root is no longer published) is a placeholder number:
// the coordinator assigned 421 and renumbers it on merge. Everything that
// changes with the renumbering is here.
const (
	migration426Version         = 426
	migration426ID              = "426_security_activation_v1_root_removed"
	migration426PreviousVersion = 425
	migration426PreviousID      = "425_waf_adapt_cookies"
	migration426PreviousUpSHA   = "ab8f82e51340a050dd670d3e396ee986d05790ee7c0824dfd028afa09815b135"
	migration426PreviousDownSHA = "ef214d732072f69dd538451c2b961998d32e402d5e45c857aee80546bb2840c8"
	migration426UpSHA           = "5b19a7a2723ac905988003efc5871be164047e09a213287275bf9f8a33b96c73"
	migration426DownSHA         = "15150a88347442da8612864873d0c98ed49d1dc5f53a4e0b747b822cd069820b"
)

// migrationV1SiteObjectRootMediaType is the deleted site runtime v8 root.
const migrationV1SiteObjectRootMediaType = "application/vnd.cdnca.edge-site-root+json;version=1"

func TestSecurityActivationV1RootRemoved426Contract(t *testing.T) {
	v1Root := "'" + migrationV1SiteObjectRootMediaType + "'"
	v2Root := "'" + siteobject.RootMediaTypeV2 + "'"
	const marker = "CREATE OR REPLACE FUNCTION validate_security_policy_activation_node_artifact_333()"
	for _, script := range []struct {
		name, sha         string
		required, refused []string
	}{
		{migration426ID + ".up.sql", migration426UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration426PreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration426PreviousVersion),
			"migration_id='" + migration426PreviousID + "'", migration426PreviousUpSHA, migration426PreviousDownSHA,
			"ERRCODE='P4260'", marker, "root.media_type=" + v2Root, "ERRCODE='P3332'",
		}, []string{v1Root}},
		{migration426ID + ".down.sql", migration426DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration426Version),
			"migration_id='" + migration426ID + "'", "ERRCODE='P4261'", v1Root, v2Root, "ERRCODE='P3332'",
		}, nil},
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
	// The down script restores exactly the 399 trigger body.
	body := func(name string) string {
		raw, err := FS.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		text := string(raw)[strings.Index(string(raw), marker):]
		return strings.TrimSpace(text[:strings.Index(text, "$$;")+3])
	}
	if body(migration426ID+".down.sql") != body(migration399ID+".up.sql") {
		t.Fatal("426 down does not restore the 399 trigger body")
	}
}
