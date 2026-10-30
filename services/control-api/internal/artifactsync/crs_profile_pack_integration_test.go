//go:build integration

package artifactsync_test

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/entitlement/artifactcatalog"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/jackc/pgx/v5"
)

// PA-12: CRS profile packs (crs_profile/crs-*) are downloaded and verified as
// rule packs, never materialized as system rules; the managed WAF reads the
// usable ones (securitypolicy.LoadCRSProfilesTx); a new revision republishes
// the scopes that selected the previous bytes; bytes that are not the pack
// the entry names are refused and the previous download stays.
func TestArtifactSyncCRSProfilePacks(t *testing.T) {
	f := newFixture(t)
	content, err := os.ReadFile("../../../../libs/rulepack/testdata/crs-profiles/crs-pl1.json")
	if err != nil {
		t.Fatal(err)
	}
	// The entry names the golden pack's own version (the download checks it).
	var golden struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(content, &golden); err != nil {
		t.Fatal(err)
	}
	entry, err := artifactcatalog.CRSProfilePackEntry("system/crs-pl1", golden.Version, 1, content, "")
	if err != nil {
		t.Fatal(err)
	}
	f.license.Publish(entry, content)
	f.sync()
	if f.local()[entry.ArtifactID] != 1 {
		t.Fatalf("local artifacts = %v", f.local())
	}
	if f.count(`SELECT count(*) FROM security_system_rules WHERE system_key LIKE '%crs-pl1%'`) != 0 {
		t.Fatal("a CRS profile pack was materialized as a system rule")
	}
	profiles := f.profiles()
	if profile, ok := profiles["system/crs-pl1"]; !ok || profile.Profile.Ref.SHA256 != entry.SHA256 || len(profile.Profile.Exports) != 82 {
		t.Fatalf("profiles = %v", profiles)
	}
	if f.count(`SELECT count(*) FROM local_artifacts WHERE artifact_id=$1 AND materialized_sha256=$2`, entry.ArtifactID, entry.SHA256) != 1 ||
		len(f.recorder.packs) != 0 {
		t.Fatalf("first download: materialized / republications %v", f.recorder.packs)
	}

	// Revision 2 with other bytes that are not this pack: refused, revision 1 stays.
	bad := append([]byte(nil), content...)
	bad = append(bad[:len(bad)-1], []byte(` }`)...)
	badEntry, _ := artifactcatalog.CRSProfilePackEntry("system/crs-pl1", "1.1.1", 2, bad, "")
	f.license.Publish(badEntry, bad)
	_ = f.syncer.SyncOnce(t.Context())
	if f.local()[entry.ArtifactID] != 1 || len(f.recorder.packs) != 0 {
		t.Fatalf("bad revision: local %v republications %v", f.local(), f.recorder.packs)
	}

	// A valid revision 2 (another profile's bytes renamed would not verify;
	// use the same pack at a new version): republishes the previous digest.
	pack := string(content)
	next := []byte(strings.Replace(pack, `"version":"`+golden.Version+`"`, `"version":"9.9.9"`, 1))
	nextEntry, _ := artifactcatalog.CRSProfilePackEntry("system/crs-pl1", "9.9.9", 3, next, "")
	f.license.Publish(nextEntry, next)
	f.sync()
	if f.local()[entry.ArtifactID] != 3 || len(f.recorder.packs) != 1 || !slices.Equal(f.recorder.packs[0], []string{entry.SHA256}) {
		t.Fatalf("next revision: local %v republications %v", f.local(), f.recorder.packs)
	}
	if profile := f.profiles()["system/crs-pl1"]; profile.Profile.Ref.Version != "9.9.9" {
		t.Fatalf("profile after update = %+v", profile.Profile.Ref)
	}

	// Withdrawn: no longer usable, its last digest republished.
	f.license.Withdraw(entry.ArtifactID)
	f.sync()
	if _, ok := f.profiles()["system/crs-pl1"]; ok || len(f.recorder.packs) != 2 || f.recorder.packs[1][0] != nextEntry.SHA256 {
		t.Fatalf("withdrawn: profiles %v republications %v", f.profiles(), f.recorder.packs)
	}
}

func (f *fixture) profiles() securitypolicy.CRSProfiles {
	f.t.Helper()
	var profiles securitypolicy.CRSProfiles
	if err := pgx.BeginFunc(f.t.Context(), f.pool, func(tx pgx.Tx) error {
		var err error
		profiles, err = securitypolicy.LoadCRSProfilesTx(f.t.Context(), tx, nil)
		return err
	}); err != nil {
		f.t.Fatal(err)
	}
	return profiles
}
