//go:build integration

package edgepublish_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig/artifactset"
	"github.com/cdnca/cdnca/libs/entitlement/artifactcatalog"
	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// stopping (or enabling again) a pack code on this controller asks
// the system channel to republish every scope whose sites mount a pack that
// needs it, at once (trigger module_entitlement); a code no mount needs
// republishes nothing.
func TestRepublishLocalPluginChangeQueuesMountingScopes(t *testing.T) {
	scope := edgepublish.NewSystemRepublishScope(t)
	_, mounted := scope.MountRulePack(t)
	packID, version, _ := strings.Cut(mounted, "@")
	var digest string
	if err := scope.Pool.QueryRow(t.Context(), `SELECT sha256 FROM rule_pack_artifacts WHERE pack_id=$1 AND version=$2`,
		packID, version).Scan(&digest); err != nil {
		t.Fatal(err)
	}
	if _, err := scope.Pool.Exec(t.Context(), `INSERT INTO artifact_catalog_entries(artifact_id,kind,version,revision,sha256,size,
		media_type,requires_feature,resident,encryption,status,delivery_id,first_seen_at,updated_at)
		VALUES($1,'rule_pack',$2,1,$3,1,$5,'pack.selfwaf',true,'none','active',$4,now(),now())`,
		artifactcatalog.RulePackArtifactID(packID), version, digest, uuid.New(), artifactset.MediaTypeRulePack); err != nil {
		t.Fatal(err)
	}
	republish := func(codes ...string) []uuid.UUID {
		t.Helper()
		var scopes []uuid.UUID
		if err := pgx.BeginFunc(t.Context(), scope.Pool, func(tx pgx.Tx) error {
			var err error
			scopes, err = edgeautopublish.RepublishLocalPluginChangeTx(t.Context(), tx, codes)
			return err
		}); err != nil {
			t.Fatalf("republish %v: %v", codes, err)
		}
		return scopes
	}
	if got := republish("module.probe.dnspup", "pack.crs"); len(got) != 0 {
		t.Fatalf("codes no mount needs republished %v", got)
	}
	if scope.Count(t, `SELECT count(*) FROM edge_system_republication_heads WHERE scope_id=$1`) != 0 {
		t.Fatal("unrelated code queued a republication")
	}
	if got := republish("pack.selfwaf"); !slices.Equal(got, []uuid.UUID{scope.ScopeID}) {
		t.Fatalf("republished scopes = %v, want %s", got, scope.ScopeID)
	}
	var triggers []string
	var state string
	if err := scope.Pool.QueryRow(t.Context(), `SELECT triggers,state FROM edge_system_republication_heads WHERE scope_id=$1`,
		scope.ScopeID).Scan(&triggers, &state); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(triggers, edgepublish.SystemTriggerModuleEntitlement) || state != "pending" {
		t.Fatalf("republication head = %v %s", triggers, state)
	}
}

// A plugin market rule pack withdrawn (or usable again) asks
// the system channel to republish every scope whose sites mount it, at once
// (trigger module_entitlement); a pack no site mounts republishes nothing.
func TestRepublishMarketRulePackChangeQueuesMountingScopes(t *testing.T) {
	scope := edgepublish.NewSystemRepublishScope(t)
	_, mounted := scope.MountRulePack(t)
	packID, _, _ := strings.Cut(mounted, "@")
	republish := func(packIDs ...string) []uuid.UUID {
		t.Helper()
		var scopes []uuid.UUID
		if err := pgx.BeginFunc(t.Context(), scope.Pool, func(tx pgx.Tx) error {
			var err error
			scopes, err = edgeautopublish.RuleCatalogPublisher{}.RepublishMarketRulePackChangeTx(t.Context(), tx, packIDs)
			return err
		}); err != nil {
			t.Fatalf("republish %v: %v", packIDs, err)
		}
		return scopes
	}
	if got := republish("dev/io.cdnca.examples/unmounted"); len(got) != 0 {
		t.Fatalf("pack no site mounts republished %v", got)
	}
	if scope.Count(t, `SELECT count(*) FROM edge_system_republication_heads WHERE scope_id=$1`) != 0 {
		t.Fatal("unmounted pack queued a republication")
	}
	if got := republish(packID); !slices.Equal(got, []uuid.UUID{scope.ScopeID}) {
		t.Fatalf("republished scopes = %v, want %s", got, scope.ScopeID)
	}
	var triggers []string
	var state string
	if err := scope.Pool.QueryRow(t.Context(), `SELECT triggers,state FROM edge_system_republication_heads WHERE scope_id=$1`,
		scope.ScopeID).Scan(&triggers, &state); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(triggers, edgepublish.SystemTriggerModuleEntitlement) || state != "pending" {
		t.Fatalf("republication head = %v %s", triggers, state)
	}
}
