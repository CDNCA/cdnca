//go:build integration

package edgepublish

import (
	"encoding/hex"
	"errors"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/artifactset"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
	"github.com/cdnca/cdnca/libs/rulepack"
	"github.com/cdnca/cdnca/services/control-api/internal/rulepackcontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

// F1 (BACKLOG-1035): a site's published rule pack mounts
// (rulepackcontrol.PublishSite -> site_security_mounts) travel in its
// dynamic routing site object as security.mounts + resolved_sha256; a site
// without published mounts carries none, and a new mounts revision (which
// advances the scope's source revision) changes only the mounted site's
// object.
func TestDynamicRoutingSiteObjectsCarryPublishedRuleMounts(t *testing.T) {
	fixture := newPublishFixture(t)
	seedDynamicRoutingNode(t, fixture, fixture.nodeID)
	mounted := fixture.createSite(t, "mounted.example.test", 8080, false).Site.ID
	plain := fixture.createSite(t, "plain.example.test", 8081, false).Site.ID

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
	// Platform allows the pack below it; only the mounted site enables it.
	put := func(input rulepackcontrol.OverrideInput) {
		t.Helper()
		if _, _, err := packs.PutOverride(t.Context(), platform, input); err != nil {
			t.Fatalf("override %+v: %v", input, err)
		}
	}
	put(rulepackcontrol.OverrideInput{Level: rulepack.LevelPlatform, PackID: pack.PackID, State: rulepack.StateDisabled, AllowLower: true})
	put(rulepackcontrol.OverrideInput{Level: rulepack.LevelSite, LevelObjectID: &mounted, PackID: pack.PackID, State: rulepack.StateEnabled})
	publishMounts := func() rulepack.Security {
		t.Helper()
		published, err := packs.PublishSite(t.Context(), tenant, mounted)
		if err != nil || published.Published == nil || len(published.Published.Security.Mounts) != 1 {
			t.Fatalf("publish mounts: %+v %v", published.Published, err)
		}
		return published.Published.Security
	}

	first := publishMounts()
	// f2 gate: the node has not applied the pack from its node artifact set.
	_, err = fixture.service.Publish(t.Context(), siteRuntimeV2PublishRequest(fixture, "mounts-0", fixture.nodeID, siteRuntimeV2Schema))
	var refusal *RulePackUnavailableError
	if !errors.As(err, &refusal) || refusal.NodeID != fixture.nodeID || len(refusal.SHA256) != 1 ||
		refusal.SHA256[0] != first.Mounts[0].SHA256 {
		t.Fatalf("publish without the pack on the node: %v", err)
	}
	var held bool
	if err := fixture.pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM edge_capability_publication_holds
		WHERE scope_id=$1 AND refused_node_ids @> ARRAY[$2::uuid])`, fixture.scopeID, fixture.nodeID).Scan(&held); err != nil || !held {
		t.Fatalf("refused publication not held: %v %v", held, err)
	}
	applyRulePacks(t, fixture, first)
	result, err := fixture.service.Publish(t.Context(), siteRuntimeV2PublishRequest(fixture, "mounts-1", fixture.nodeID, siteRuntimeV2Schema))
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	sites := dynamicRoutingSiteObjects(t, fixture, result.ConfigVersionID)
	assertSiteMounts(t, sites[mounted.String()].security, first)
	if _, present := sites[plain.String()].security["mounts"]; present {
		t.Fatalf("site without published mounts carries security.mounts: %s", sites[plain.String()].raw)
	}

	// Rule r020 switched off at the site: new mounts revision (exclusions).
	put(rulepackcontrol.OverrideInput{Level: rulepack.LevelSite, LevelObjectID: &mounted, PackID: pack.PackID, RuleID: "r020",
		State: rulepack.StateDisabled})
	second := publishMounts()
	// The node took the first release (the next one is refused while it runs).
	(&SystemRepublishScope{Pool: fixture.pool, ScopeID: fixture.scopeID}).SettleDeployments(t)
	if second.ResolvedSHA256 == first.ResolvedSHA256 {
		t.Fatal("fixture: the second resolution has the same digest")
	}
	applyRulePacks(t, fixture, second)
	again, err := fixture.service.Publish(t.Context(), siteRuntimeV2PublishRequest(fixture, "mounts-2", fixture.nodeID, siteRuntimeV2Schema))
	if err != nil {
		t.Fatalf("republish: %v", err)
	}
	next := dynamicRoutingSiteObjects(t, fixture, again.ConfigVersionID)
	assertSiteMounts(t, next[mounted.String()].security, second)
	if next[mounted.String()].sha256 == sites[mounted.String()].sha256 {
		t.Fatal("mounted site object unchanged after a new mounts revision")
	}
	if next[plain.String()].sha256 != sites[plain.String()].sha256 {
		t.Fatal("site without mounts changed with another site's mounts")
	}
}

// applyRulePacks records that the fixture node applied security's packs from
// its node artifact set (what edgestatus writes from the node's receipt).
func applyRulePacks(t *testing.T, fixture *publishFixture, security rulepack.Security) {
	t.Helper()
	for _, mount := range security.Mounts {
		if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO node_artifact_applied_items(
			node_id,artifact_id,version,item_revision,media_type,sha256,set_revision,applied_at) VALUES($1,$2,$3,1,$4,$5,1,now())
			ON CONFLICT DO NOTHING`, fixture.nodeID, "rule_pack/"+mount.SHA256, mount.Version, artifactset.MediaTypeRulePack,
			mount.SHA256); err != nil {
			t.Fatal(err)
		}
	}
}

type publishedSiteObject struct {
	sha256   string
	raw      []byte
	security map[string]json.RawMessage
}

// dynamicRoutingSiteObjects opens every site object of a dynamic routing
// publication from the control store (content key of the scope) by site ID.
func dynamicRoutingSiteObjects(t *testing.T, fixture *publishFixture, configID uuid.UUID) map[string]publishedSiteObject {
	t.Helper()
	var rootWire []byte
	var mediaType string
	if err := fixture.pool.QueryRow(t.Context(), `SELECT wire_bytes,media_type FROM configuration_artifacts
		WHERE config_version_id=$1 AND encryption_algorithm='none'`, configID).Scan(&rootWire, &mediaType); err != nil {
		t.Fatal(err)
	}
	root, err := siteobject.ParseRootV2(rootWire)
	if mediaType != siteobject.RootMediaTypeV2 || err != nil {
		t.Fatalf("root %s: %v", mediaType, err)
	}
	var contentKey []byte
	if err := fixture.pool.QueryRow(t.Context(), `SELECT content_key FROM edge_site_object_keys
		WHERE configuration_scope_id=$1 AND key_epoch=$2`, fixture.scopeID, root.KeyEpoch).Scan(&contentKey); err != nil {
		t.Fatal(err)
	}
	open := func(digest string) []byte {
		raw, _ := hex.DecodeString(digest)
		var wire []byte
		if err := fixture.pool.QueryRow(t.Context(), `SELECT ciphertext FROM edge_site_objects
			WHERE configuration_scope_id=$1 AND key_epoch=$2 AND sha256=$3`, fixture.scopeID, root.KeyEpoch, raw).Scan(&wire); err != nil {
			t.Fatalf("object %s: %v", digest, err)
		}
		plaintext, err := siteobject.Open(contentKey, fixture.scopeID.String(), digest, wire)
		if err != nil {
			t.Fatalf("open %s: %v", digest, err)
		}
		return plaintext
	}
	result := map[string]publishedSiteObject{}
	for _, bucketDigest := range root.Buckets {
		bucket, err := siteobject.ParseBucketV2(open(bucketDigest))
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range bucket.Sites {
			plaintext := open(entry.SHA256)
			var site struct {
				Security map[string]json.RawMessage `json:"security"`
			}
			if err := json.Unmarshal(plaintext, &site); err != nil {
				t.Fatal(err)
			}
			result[entry.SiteID] = publishedSiteObject{sha256: entry.SHA256, raw: plaintext, security: site.Security}
		}
	}
	return result
}

func assertSiteMounts(t *testing.T, security map[string]json.RawMessage, want rulepack.Security) {
	t.Helper()
	var mounts []rulepack.Mount
	var resolved string
	if err := json.Unmarshal(security["mounts"], &mounts); err != nil {
		t.Fatalf("security.mounts: %v (%s)", err, security["mounts"])
	}
	if err := json.Unmarshal(security["resolved_sha256"], &resolved); err != nil || resolved != want.ResolvedSHA256 {
		t.Fatalf("security.resolved_sha256 = %s, want %s (%v)", security["resolved_sha256"], want.ResolvedSHA256, err)
	}
	// The node precheck (rulepack.Verify) needs the mounts exactly as resolved.
	got, _ := json.Marshal(mounts)
	expected, _ := json.Marshal(want.Mounts)
	if string(got) != string(expected) {
		t.Fatalf("security.mounts = %s, want %s", got, expected)
	}
}

// 方案 A: a site mounting a modsecurity pack that narrows its managed WAF
// (crs-pl1 down to crs_sqli) is published with the narrowing as
// managed_waf.exclusions, read from the stored pack; once the site's
// profile no longer covers the pack (paranoia above it) the publication is
// refused with CRSOutOfProfileError.
func TestDynamicRoutingSiteObjectsNarrowManagedWAFWithModSecurityPack(t *testing.T) {
	scope := NewSystemRepublishScope(t)
	scope.BindManagedWAF(t)
	packs := rulepackcontrol.NewService(scope.Pool, func() time.Time { return publishTestClock })
	platform := rulepackcontrol.Actor{UserID: scope.fixture.platformUserID, ScopeID: scope.fixture.platformScopeID, ScopeKind: "platform"}
	tenant := rulepackcontrol.Actor{UserID: scope.UserID, ScopeID: scope.ScopeID, ScopeKind: "tenant"}
	importPack := func(packID string, paranoia int) rulepackcontrol.Pack {
		t.Helper()
		content, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "libs", "rulepack", "testdata", "packs", "system-crs.json"))
		if err != nil {
			t.Fatal(err)
		}
		var document map[string]any
		_ = json.Unmarshal(content, &document)
		document["pack_id"] = packID
		rule := document["rules"].([]any)[0].(map[string]any)
		rule["id"] = "crs_sqli"
		rule["crs"].(map[string]any)["paranoia"] = paranoia
		encoded, _ := json.Marshal(document)
		pack, err := packs.Import(t.Context(), platform, encoded)
		if err != nil {
			t.Fatalf("import %s: %v", packID, err)
		}
		return pack
	}
	narrow := importPack("system/sqli-narrow", 1)
	if _, _, err := packs.PutOverride(t.Context(), platform, rulepackcontrol.OverrideInput{Level: rulepack.LevelPlatform,
		PackID: narrow.PackID, State: rulepack.StateDisabled, AllowLower: true}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := packs.PutOverride(t.Context(), platform, rulepackcontrol.OverrideInput{Level: rulepack.LevelSite,
		LevelObjectID: &scope.SiteID, PackID: narrow.PackID, State: rulepack.StateEnabled}); err != nil {
		t.Fatal(err)
	}
	if _, err := packs.PublishSite(t.Context(), tenant, scope.SiteID); err != nil {
		t.Fatalf("publish in-profile mounts: %v", err)
	}
	site := func() (edgesite.Site, error) {
		t.Helper()
		tx, err := scope.Pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(t.Context())
		facts, err := loadSiteRuleMounts(t.Context(), tx, scope.ScopeID, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := loadSiteModSecurityFacts(t.Context(), tx, facts); err != nil {
			t.Fatal(err)
		}
		profile := crsProfilesForEdgeTest(t)[securitypolicy.DefaultCRSProfile].Profile
		value := edgesite.Site{SiteID: scope.SiteID.String(), Security: edgesite.Security{
			ManagedWAF: &edgesite.ManagedWAF{CRSProfile: profile.Ref, Exclusions: []int{942100}}}}
		return value, applySiteModSecurity(&value, facts[scope.SiteID.String()].ModSecurity)
	}
	got, err := site()
	if err != nil {
		t.Fatal(err)
	}
	if excluded := got.Security.ManagedWAF.Exclusions; !slices.Contains(excluded, 942100) || !slices.Contains(excluded, 941100) ||
		slices.Contains(excluded, 942140) {
		t.Fatalf("exclusions = %v", excluded)
	}
	// The published mount now selects paranoia 2 (crs-pl1 is paranoia 1):
	// a stored mounts document the profile no longer covers.
	wide := importPack("system/sqli-wide", 2)
	if _, err := scope.Pool.Exec(t.Context(), `UPDATE site_security_mounts SET security=jsonb_set(jsonb_set(jsonb_set(security,
		'{mounts,0,pack_id}',to_jsonb($2::text)),'{mounts,0,sha256}',to_jsonb($3::text)),'{mounts,0,version}',to_jsonb($4::text))
		WHERE site_id=$1`, scope.SiteID, wide.PackID, wide.Versions[0].SHA256, wide.Versions[0].Version); err != nil {
		t.Fatal(err)
	}
	var refusal *CRSOutOfProfileError
	if _, err := site(); !errors.As(err, &refusal) || refusal.PackID != wide.PackID || !errors.Is(err, ErrUnsupportedSecurityPolicy) {
		t.Fatalf("out of profile: %v", err)
	}
}
