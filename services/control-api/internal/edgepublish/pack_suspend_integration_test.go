//go:build integration

package edgepublish

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/libs/rulepack"
	"github.com/cdnca/cdnca/services/control-api/internal/rulepackcontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// A site CRS profile change that no longer
// covers its modsecurity pack suspends the mount in the same transaction, so
// the publication carries the new profile instead of failing with
// CRSOutOfProfileError; changing the profile back restores the mount (same
// resolved_sha256). Enabling an out-of-profile pack by hand is still
// refused; a sealed modsecurity pack is checked by the crs_rule_ids the
// license service computed into its manifest and
// refused without them.
func TestSiteProfileChangeSuspendsAndRestoresModSecurityMount(t *testing.T) {
	scope := NewSystemRepublishScope(t)
	scope.BindManagedWAF(t) // crs-pl1, 942100 excluded
	packs := rulepackcontrol.NewService(scope.Pool, func() time.Time { return publishTestClock })
	platform := rulepackcontrol.Actor{UserID: scope.fixture.platformUserID, ScopeID: scope.fixture.platformScopeID, ScopeKind: "platform"}
	tenant := rulepackcontrol.Actor{UserID: scope.UserID, ScopeID: scope.ScopeID, ScopeKind: "tenant"}
	document := func(packID string, paranoia int) map[string]any {
		content, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "libs", "rulepack", "testdata", "packs", "system-crs.json"))
		if err != nil {
			t.Fatal(err)
		}
		var value map[string]any
		_ = json.Unmarshal(content, &value)
		value["pack_id"] = packID
		rule := value["rules"].([]any)[0].(map[string]any)
		rule["id"] = "crs_sqli"
		rule["crs"].(map[string]any)["paranoia"] = paranoia
		return value
	}
	importPack := func(value map[string]any) rulepackcontrol.Pack {
		t.Helper()
		encoded, _ := json.Marshal(value)
		pack, err := packs.Import(t.Context(), platform, encoded)
		if err != nil {
			t.Fatalf("import: %v", err)
		}
		return pack
	}
	enable := func(packID string, state rulepack.State) {
		t.Helper()
		// The platform keeps every pack off and lets the site decide.
		if _, _, err := packs.PutOverride(t.Context(), platform, rulepackcontrol.OverrideInput{Level: rulepack.LevelPlatform,
			PackID: packID, State: rulepack.StateDisabled, AllowLower: true}); err != nil {
			t.Fatal(err)
		}
		if _, _, err := packs.PutOverride(t.Context(), platform, rulepackcontrol.OverrideInput{Level: rulepack.LevelSite,
			LevelObjectID: &scope.SiteID, PackID: packID, State: state}); err != nil {
			t.Fatal(err)
		}
	}
	narrow := importPack(document("system/sqli-narrow", 1))
	enable(narrow.PackID, rulepack.StateEnabled)
	first, err := packs.PublishSite(t.Context(), tenant, scope.SiteID)
	if err != nil {
		t.Fatalf("publish in-profile mount: %v", err)
	}
	profiles := crsProfilesForEdgeTest(t)
	siteObject := func(profileID string) error {
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
		value := edgesite.Site{SiteID: scope.SiteID.String(), Security: edgesite.Security{
			ManagedWAF: &edgesite.ManagedWAF{CRSProfile: profiles[profileID].Profile.Ref, Exclusions: []int{942100}}}}
		return applySiteModSecurity(&value, facts[scope.SiteID.String()].ModSecurity)
	}
	changeProfile := func(profile *string) rulepackcontrol.ProfileChange {
		t.Helper()
		var change rulepackcontrol.ProfileChange
		if err := pgx.BeginFunc(t.Context(), scope.Pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(t.Context(), `DELETE FROM site_crs_overrides WHERE site_id=$1`, scope.SiteID); err != nil {
				return err
			}
			if profile != nil {
				if _, err := tx.Exec(t.Context(), `INSERT INTO site_crs_overrides(scope_id,site_id,override,updated_by_user_id,updated_at)
					VALUES($1,$2,$3,$4,now())`, scope.ScopeID, scope.SiteID, `{"profile":"`+*profile+`","exclusions":null}`,
					scope.UserID); err != nil {
					return err
				}
			}
			var err error
			change, err = rulepackcontrol.ApplySiteProfileChangeTx(t.Context(), tx, rulepackcontrol.ProfileChangeInput{
				ScopeID: scope.ScopeID, SiteID: scope.SiteID, ActorUserID: scope.UserID, ActorScopeKind: "tenant",
				SourceIP: "203.0.113.9", RequestID: "pack-suspend-" + uuid.NewString(), Now: publishTestClock})
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return change
	}
	count := func(query string, args ...any) int {
		t.Helper()
		var n int
		if err := scope.Pool.QueryRow(t.Context(), query, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	// The defect: with the mount still published, the record-only profile
	// (action log, the pack blocks) makes the publication refuse.
	var refusal *CRSOutOfProfileError
	if err := siteObject("system/crs-pl1-log"); !errors.As(err, &refusal) {
		t.Fatalf("published mount on crs-pl1-log: %v", err)
	}
	logProfile := "system/crs-pl1-log"
	suspended := changeProfile(&logProfile)
	if len(suspended.Suspended) != 1 || suspended.Suspended[0].PackID != narrow.PackID ||
		suspended.Suspended[0].Reason != rulepackcontrol.SuspensionOutOfProfile || suspended.Suspended[0].CRSProfile != logProfile {
		t.Fatalf("suspended = %+v", suspended)
	}
	if err := siteObject(logProfile); err != nil {
		t.Fatalf("publication after the suspension: %v", err)
	}
	if got := count(`SELECT jsonb_array_length(security->'mounts') FROM site_security_mounts WHERE site_id=$1`, scope.SiteID); got != 0 {
		t.Fatalf("published mounts after the suspension = %d", got)
	}
	// Publishing the site's mounts again keeps the suspension (no 422).
	view, err := packs.PublishSite(t.Context(), tenant, scope.SiteID)
	if err != nil || len(view.Suspended) != 1 || view.Resolution.Security == nil || len(view.Resolution.Security.Mounts) != 0 {
		t.Fatalf("republish with the suspension: %+v %v", view.Suspended, err)
	}
	// A pack enabled by hand that the profile does not cover is refused.
	// (narrow off meanwhile: two modsecurity packs would be engine_singleton).
	enable(narrow.PackID, rulepack.StateDisabled)
	wide := importPack(document("system/sqli-wide", 2))
	enable(wide.PackID, rulepack.StateEnabled)
	var conflict *rulepackcontrol.ConflictError
	if _, err := packs.PublishSite(t.Context(), tenant, scope.SiteID); !errors.As(err, &conflict) ||
		conflict.Resolution.Conflicts[0].Code != rulepack.ConflictCRSOutOfProfile {
		t.Fatalf("manual out-of-profile pack: %v", err)
	}
	enable(wide.PackID, rulepack.StateDisabled)
	enable(narrow.PackID, rulepack.StateEnabled)

	// Back to the library's profile: restored, the first resolved digest.
	restored := changeProfile(nil)
	if len(restored.Restored) != 1 || restored.Restored[0].PackID != narrow.PackID || len(restored.Suspended) != 0 {
		t.Fatalf("restored = %+v", restored)
	}
	var resolved string
	if err := scope.Pool.QueryRow(t.Context(), `SELECT resolved_sha256 FROM site_security_mounts WHERE site_id=$1`,
		scope.SiteID).Scan(&resolved); err != nil || resolved != first.Published.Security.ResolvedSHA256 {
		t.Fatalf("restored digest %s, want %s (%v)", resolved, first.Published.Security.ResolvedSHA256, err)
	}
	if err := siteObject("system/crs-pl1"); err != nil {
		t.Fatalf("restored mount: %v", err)
	}
	if got := count(`SELECT count(*) FROM rule_pack_mount_suspensions WHERE site_id=$1`, scope.SiteID); got != 0 {
		t.Fatalf("suspensions left = %d", got)
	}
	for action, want := range map[string]int{rulepackcontrol.AuditMountSuspend: 1, rulepackcontrol.AuditMountRestore: 1} {
		if got := count(`SELECT count(*) FROM audit_events WHERE action=$1 AND resource_id=$2 AND scope_id=$3
			AND payload->>'pack_id'=$4 AND payload->>'ip'='203.0.113.9'`, action, scope.SiteID.String(), scope.ScopeID,
			narrow.PackID); got != want {
			t.Fatalf("%s events = %d", action, got)
		}
	}

	// Editing the WAF library's profile has the same effect:
	// the mount is suspended in the edit's transaction, changing it back
	// restores it.
	editLibrary := func(profile string) {
		t.Helper()
		store := securitypolicy.NewStoreWithClock(scope.Pool, func() time.Time { return publishTestClock })
		owner := securitypolicy.Actor{UserID: scope.UserID, ScopeID: scope.ScopeID, ScopeKind: "tenant"}
		var policyID uuid.UUID
		if err := scope.Pool.QueryRow(t.Context(), `SELECT policy_id FROM security_policy_site_bindings WHERE site_id=$1
			AND policy_kind='waf'`, scope.SiteID).Scan(&policyID); err != nil {
			t.Fatal(err)
		}
		current, err := store.Get(t.Context(), owner, policyID)
		if err != nil {
			t.Fatal(err)
		}
		rules := slices.Clone(current.Rules)
		for index := range rules {
			if rules[index].ActionConfig.ManagedWAF != nil {
				config := *rules[index].ActionConfig.ManagedWAF
				config.Profile = profile
				rules[index].ActionConfig.ManagedWAF = &config
			}
		}
		request := securitypolicy.UpdateRequest{ID: policyID, ExpectedRevision: current.Revision, RequestID: "lib-" + uuid.NewString(),
			IdempotencyKey: "lib-" + uuid.NewString(), Fields: securitypolicy.PolicyFields{Kind: current.Kind, Name: current.Name,
				Description: current.Description, Enabled: current.Enabled, DefaultAction: current.DefaultAction, Rules: rules}}
		if _, err := store.Update(t.Context(), owner, request, sha256.Sum256([]byte(request.IdempotencyKey))); err != nil {
			t.Fatalf("edit WAF library profile to %s: %v", profile, err)
		}
	}
	editLibrary(logProfile)
	if got := count(`SELECT count(*) FROM rule_pack_mount_suspensions WHERE site_id=$1 AND pack_id=$2 AND crs_profile=$3`,
		scope.SiteID, narrow.PackID, logProfile); got != 1 {
		t.Fatalf("suspensions after the library edit = %d", got)
	}
	if err := siteObject(logProfile); err != nil {
		t.Fatalf("publication after the library edit: %v", err)
	}
	editLibrary(securitypolicy.DefaultCRSProfile)
	if got := count(`SELECT count(*) FROM rule_pack_mount_suspensions WHERE site_id=$1`, scope.SiteID); got != 0 {
		t.Fatalf("suspensions after the library edit back = %d", got)
	}
	if err := scope.Pool.QueryRow(t.Context(), `SELECT resolved_sha256 FROM site_security_mounts WHERE site_id=$1`,
		scope.SiteID).Scan(&resolved); err != nil || resolved != first.Published.Security.ResolvedSHA256 {
		t.Fatalf("restored by the library edit: digest %s, want %s (%v)", resolved, first.Published.Security.ResolvedSHA256, err)
	}

	// Sealed modsecurity packs: without the license service's crs_rule_ids
	// refused, with them (computed when it sealed) checked by the list alone.
	enable(narrow.PackID, rulepack.StateDisabled)
	sealedPack := func(packID string, listed bool) {
		t.Helper()
		value := document(packID, 1)
		encoded, _ := json.Marshal(value)
		compiled, err := rulepack.Compile(encoded)
		if err != nil {
			t.Fatal(err)
		}
		cek := make([]byte, rulepack.CEKSize)
		_, _ = rand.Read(cek)
		sealed, err := rulepack.SealWithCRSRuleIDs(compiled.Canonical, cek, nil)
		if listed {
			manifest, err := edgeconfig.DeriveCRSManifest(crsInputsForEdgeTest(t).RuleText)
			if err != nil {
				t.Fatal(err)
			}
			value["pack_id"] = packID + "-sealed"
			encoded, _ = json.Marshal(value)
			if compiled, err = rulepack.Compile(encoded); err != nil {
				t.Fatal(err)
			}
			packID += "-sealed"
			sealed, err = rulepack.Seal(compiled.Canonical, cek, manifest)
		}
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(sealed)
		if err := pgx.BeginFunc(t.Context(), scope.Pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(t.Context(), `INSERT INTO rule_packs(pack_id,layer,current_version,update_policy,created_at,updated_at)
				VALUES($1,'system','4.10.0','auto',now(),now())`, packID); err != nil {
				return err
			}
			_, err := tx.Exec(t.Context(), `INSERT INTO rule_pack_artifacts(pack_id,version,engine,engine_min_version,name,sha256,
				size_bytes,content,source,state,downloaded_at,created_at,sealed,wrapped_key) VALUES($1,'4.10.0','modsecurity',1,'sealed',
				$2,$3,$4,'catalog','downloaded',now(),now(),true,$5)`, packID, hex.EncodeToString(sum[:]), len(sealed), sealed,
				strings.Repeat("A", 107))
			return err
		}); err != nil {
			t.Fatal(err)
		}
		enable(packID, rulepack.StateEnabled)
	}
	sealedPack("system/sqli-unlisted", false)
	if _, err := packs.PublishSite(t.Context(), tenant, scope.SiteID); !errors.As(err, &conflict) ||
		conflict.Resolution.Conflicts[0].Code != rulepack.ConflictCRSOutOfProfile {
		t.Fatalf("sealed pack without the license service's crs_rule_ids: %v", err)
	}
	enable("system/sqli-unlisted", rulepack.StateDisabled)
	sealedPack("system/sqli-listed", true)
	if _, err := packs.PublishSite(t.Context(), tenant, scope.SiteID); err != nil {
		t.Fatalf("sealed pack with crs_rule_ids: %v", err)
	}
	if err := siteObject("system/crs-pl1"); err != nil {
		t.Fatalf("sealed listed mount on the site object: %v", err)
	}
}
