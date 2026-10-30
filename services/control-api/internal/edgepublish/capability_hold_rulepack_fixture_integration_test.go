//go:build integration

package edgepublish

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/artifactset"
	"github.com/cdnca/cdnca/libs/rulepack"
	"github.com/cdnca/cdnca/services/control-api/internal/rulepackcontrol"
	"github.com/google/uuid"
)

// MountRulePack mounts the system-sqli test pack on the scope's site and
// publishes the site's mounts (advances the scope's source revision). It
// returns the mounted pack's digest and its pack_id@version.
func (scope *SystemRepublishScope) MountRulePack(t *testing.T) (string, string) {
	t.Helper()
	fixture := scope.fixture
	packs := rulepackcontrol.NewService(fixture.pool, func() time.Time { return publishTestClock })
	platform := rulepackcontrol.Actor{UserID: fixture.platformUserID, ScopeID: fixture.platformScopeID, ScopeKind: "platform"}
	tenant := rulepackcontrol.Actor{UserID: fixture.userID, ScopeID: fixture.scopeID, ScopeKind: "tenant"}
	content, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "libs", "rulepack", "testdata", "packs", "system-sqli.json"))
	if err != nil {
		t.Fatal(err)
	}
	pack, err := packs.Import(t.Context(), platform, content)
	if err != nil {
		t.Fatalf("import pack: %v", err)
	}
	site := scope.SiteID
	for _, input := range []rulepackcontrol.OverrideInput{
		{Level: rulepack.LevelPlatform, PackID: pack.PackID, State: rulepack.StateDisabled, AllowLower: true},
		{Level: rulepack.LevelSite, LevelObjectID: &site, PackID: pack.PackID, State: rulepack.StateEnabled},
	} {
		if _, _, err := packs.PutOverride(t.Context(), platform, input); err != nil {
			t.Fatalf("override %+v: %v", input, err)
		}
	}
	published, err := packs.PublishSite(t.Context(), tenant, site)
	if err != nil || published.Published == nil || len(published.Published.Security.Mounts) != 1 {
		t.Fatalf("publish mounts: %+v %v", published.Published, err)
	}
	mount := published.Published.Security.Mounts[0]
	return mount.SHA256, mount.PackID + "@" + mount.Version
}

// ApplyRulePack records that nodeID applied the pack from its node artifact
// set, as edgestatus writes it from the node's receipt (announced_at unset:
// the distributor's announce has not run yet).
func (scope *SystemRepublishScope) ApplyRulePack(t *testing.T, nodeID uuid.UUID, digest string) {
	t.Helper()
	if _, err := scope.Pool.Exec(t.Context(), `INSERT INTO node_artifact_applied_items(
		node_id,artifact_id,version,item_revision,media_type,sha256,set_revision,applied_at)
		VALUES($1,$2,'1.0.0',1,$3,$4,1,now()) ON CONFLICT DO NOTHING`, nodeID, "rule_pack/"+digest,
		artifactset.MediaTypeRulePack, digest); err != nil {
		t.Fatal(err)
	}
}
