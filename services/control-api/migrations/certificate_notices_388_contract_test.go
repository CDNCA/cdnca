package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 388 (certificate notices) is a placeholder number
// after 387: the merge renumbers both.
const (
	migration388Version = 388
	migration388ID      = "388_certificate_notices"
	migration388UpSHA   = "6b3de6c8bf5d45920e60b609b090c0ea921ef94ac54fc3ec3c34e951541f38db"
	migration388DownSHA = "e10a84ecab7253cb5f21927776297985626537490b0423894afba8183fb46c4c"
)

func TestCertificateNotices388Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration388ID + ".up.sql", migration388UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration388Version-1),
			"migration_id='" + migration387ID + "'", migration387UpSHA, migration387DownSHA, "ERRCODE='P3880'",
			"'certificate.renew_failed'", "'certificate.renew_failed.zh-cn'",
		}},
		{migration388ID + ".down.sql", migration388DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration388Version),
			"migration_id='" + migration388ID + "'", "ERRCODE='P3881'", "ERRCODE='P3882'",
			"DISABLE TRIGGER notification_templates_immutable",
		}},
	} {
		raw, err := FS.ReadFile(script.name)
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != script.sha {
			t.Fatalf("%s checksum drift: %s", script.name, got)
		}
		for _, required := range script.required {
			if !strings.Contains(string(raw), required) {
				t.Errorf("%s missing %q", script.name, required)
			}
		}
	}
}
