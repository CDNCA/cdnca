package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 324 (FX57 系统重新发布触发 secondary_verification) placeholder
// number: on merge the coordinator renumbers it after the integration head.
// Every value that moves with the renumber is kept in this block.
const (
	sysRepubSecver324Version         = "324"
	sysRepubSecver324PreviousCount   = "323"
	sysRepubSecver324PreviousID      = "323_notification_subscription_defaults"
	sysRepubSecver324PreviousUpSHA   = "c4e690903f4c234a6c1c3bf67df3a5e932536e4c8b82ca3978561bc6361ec18a"
	sysRepubSecver324PreviousDownSHA = "84764d52a8d5963f6084d1dddaa718500452debff122b2b7c9a4df096d3808cb"
	sysRepubSecver324UpSHA           = "eac4de7e8d9d3300b841caacef1293550623edd4ae3834f6376912f57112412a"
	sysRepubSecver324DownSHA         = "82429290291a45689ebe035f9f3af3fb9f2dafc949b4a077e2c2587effbf143e"
)

func TestSystemRepublicationSecondaryVerification324Contract(t *testing.T) {
	name := sysRepubSecver324Version + "_system_republication_secondary_verification"
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{name + ".up.sql", sysRepubSecver324UpSHA, []string{
			"(SELECT count(*) FROM schema_migrations) <> " + sysRepubSecver324PreviousCount,
			"(SELECT max(version) FROM schema_migrations) <> " + sysRepubSecver324PreviousCount,
			sysRepubSecver324PreviousID, sysRepubSecver324PreviousUpSHA, sysRepubSecver324PreviousDownSHA, "ERRCODE='P3240'",
			"cardinality(triggers) BETWEEN 1 AND 6", "'domain_ownership',\n            'secondary_verification']::text[]",
			"'line_group', 'node_sync', 'domain_ownership', 'secondary_verification'));",
		}},
		{name + ".down.sql", sysRepubSecver324DownSHA, []string{
			"(SELECT count(*) FROM schema_migrations) <> " + sysRepubSecver324Version, name, "ERRCODE='P3241'",
			"WHERE source = 'secondary_verification'", "cardinality(triggers) BETWEEN 1 AND 5",
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
	for name, sha := range map[string]string{
		sysRepubSecver324PreviousID + ".up.sql":   sysRepubSecver324PreviousUpSHA,
		sysRepubSecver324PreviousID + ".down.sql": sysRepubSecver324PreviousDownSHA,
	} {
		raw, err := FS.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != sha {
			t.Fatalf("predecessor %s is not the pinned head: %s", name, got)
		}
	}
}
