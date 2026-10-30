//go:build integration

package rulepackcontrol

import (
	"testing"

	"github.com/cdnca/cdnca/libs/rulepack"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// F1: published mounts travel in the site object, so a new mounts revision
// advances the site scope's edge source revision (the scope can be
// published for it); an unchanged resolution and a refused publication do
// not.
func TestPublishSiteAdvancesEdgeSourceRevision(t *testing.T) {
	w := newWorld(t)
	ctx := t.Context()
	sqli := w.importFile(t, w.platform, "system-sqli.json")
	level, object := platformLevel()
	if err := w.put(t, w.platform, with(OverrideInput{Level: level, LevelObjectID: object}, sqli.PackID, rulepack.StateEnabled, true)); err != nil {
		t.Fatal(err)
	}
	before := edgeSourceRevision(t, w, w.tenantA.ScopeID)
	other := edgeSourceRevision(t, w, w.tenantB.ScopeID)
	if _, err := w.service.PublishSite(ctx, w.tenantA, w.siteA1); err != nil {
		t.Fatal(err)
	}
	after := edgeSourceRevision(t, w, w.tenantA.ScopeID)
	if after != before+1 {
		t.Fatalf("source revision %d -> %d after a new mounts revision", before, after)
	}
	if edgeSourceRevision(t, w, w.tenantB.ScopeID) != other {
		t.Fatal("another tenant's source revision moved")
	}
	if _, err := w.service.PublishSite(ctx, w.tenantA, w.siteA1); err != nil {
		t.Fatal(err)
	}
	if got := edgeSourceRevision(t, w, w.tenantA.ScopeID); got != after {
		t.Fatalf("unchanged mounts moved the source revision %d -> %d", after, got)
	}
}

func edgeSourceRevision(t *testing.T, w world, scopeID uuid.UUID) int64 {
	t.Helper()
	var revision int64
	err := w.pool.QueryRow(t.Context(), `SELECT source_revision FROM edge_configuration_scopes WHERE scope_id=$1`, scopeID).Scan(&revision)
	if err != nil && err != pgx.ErrNoRows {
		t.Fatal(err)
	}
	return revision
}
