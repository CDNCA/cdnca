//go:build integration

package nodeidentity

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// (fixed snapshot): the first apply
// of a scope ended rollback_failed while its generation kept serving, and the
// node holds access records of that version. A rollback_failed apply alone
// does not authorize its version for telemetry. Once the operator confirms
// the source deployment's own version (operator_confirmed with that
// observed_config_version_id), the Gateway's authorization carries it; with a
// null version it still does not.
func TestOperatorConfirmedSourceVersionEntersTelemetryAuthorization(t *testing.T) {
	pool := openIdentityTestDatabase(t, true)
	now := time.Date(2026, 11, 23, 1, 0, 0, 0, time.UTC)
	store, err := edgedeployment.NewStoreWithClock(pool, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name       string
		confirm    bool
		authorized bool
	}{
		{name: "source version confirmed", confirm: true, authorized: true},
		{name: "reconciled without a version", confirm: false, authorized: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := seedIdentityNode(t, pool, now, "active", "initial_enrollment")
			siteID := uuid.New()
			configID := seedTelemetryConfig(t, pool, fixture, siteID, now.Add(-2*time.Hour))
			deploymentID := seedTelemetryDeploymentFactWithPrevious(t, pool, fixture, configID, nil,
				"apply", "rollback_failed", "", now.Add(-time.Hour))
			seedRollbackFailedSource(t, pool, fixture, deploymentID, configID, now.Add(-time.Hour))

			if authorizesTelemetryVersion(t, pool, fixture, siteID, configID, now) {
				t.Fatal("a rollback_failed apply alone authorized its version")
			}
			request := edgedeployment.ReconcileNodeConfigRequest{
				RequestID: uuid.New(), NodeID: fixture.nodeID, ConfigurationScopeID: fixture.scopeID,
				SourceDeploymentID: deploymentID, SourceDeploymentAttempt: 1,
				Resolution: edgedeployment.ReconciliationOperatorConfirmed,
				Evidence:   "operator verified on the node that it still serves the source release",
			}
			if test.confirm {
				request.ObservedConfigVersionID = &configID
			}
			if _, err := store.ReconcileNodeConfig(context.Background(), request); err != nil {
				t.Fatalf("reconcile: %v", err)
			}
			if got := authorizesTelemetryVersion(t, pool, fixture, siteID, configID, now); got != test.authorized {
				t.Fatalf("telemetry authorization carries the source version = %v, want %v", got, test.authorized)
			}
		})
	}
}

// /
// reconciled without a version, the source version is not authorized; the
// automatic publication then reaches the node and becomes current. The
// supplemental confirmation of the source version still puts it in the
// Gateway's authorization, next to the later version, for this node and
// scope only. A rollback_failed version nobody confirmed stays out.
func TestSupplementalSourceConfirmationEntersTelemetryAuthorization(t *testing.T) {
	pool := openIdentityTestDatabase(t, true)
	now := time.Date(2026, 11, 23, 1, 0, 0, 0, time.UTC)
	store, err := edgedeployment.NewStoreWithClock(pool, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	fixture := seedIdentityNode(t, pool, now, "active", "initial_enrollment")
	siteID := uuid.New()
	// Another rollback_failed version of the scope on the node, never confirmed.
	unconfirmedID := seedTelemetryConfig(t, pool, fixture, siteID, now.Add(-3*time.Hour))
	seedTelemetryDeploymentFactWithPrevious(t, pool, fixture, unconfirmedID, nil, "apply", "rollback_failed", "", now.Add(-2*time.Hour))
	configID := seedTelemetryConfig(t, pool, fixture, siteID, now.Add(-2*time.Hour))
	deploymentID := seedTelemetryDeploymentFactWithPrevious(t, pool, fixture, configID, nil,
		"apply", "rollback_failed", "", now.Add(-time.Hour))
	seedRollbackFailedSource(t, pool, fixture, deploymentID, configID, now.Add(-time.Hour))
	// Another node of another tenant scope: it never sees this scope's versions.
	otherFixture := seedIdentityNode(t, pool, now, "active", "initial_enrollment")
	otherSiteID := uuid.New()
	seedTelemetryConfig(t, pool, otherFixture, otherSiteID, now.Add(-2*time.Hour))

	request := edgedeployment.ReconcileNodeConfigRequest{
		RequestID: uuid.New(), NodeID: fixture.nodeID, ConfigurationScopeID: fixture.scopeID,
		SourceDeploymentID: deploymentID, SourceDeploymentAttempt: 1,
		Resolution: edgedeployment.ReconciliationOperatorConfirmed,
		Evidence:   "operator confirmed; node state unconfirmed",
	}
	if _, err := store.ReconcileNodeConfig(context.Background(), request); err != nil {
		t.Fatalf("reconcile without a version: %v", err)
	}
	if authorizesTelemetryVersion(t, pool, fixture, siteID, configID, now) {
		t.Fatal("a reconciliation without a version authorized the source version")
	}
	// The automatic publication after the null reconciliation became current.
	laterID := seedTelemetryConfig(t, pool, fixture, siteID, now.Add(-time.Hour))
	seedTelemetryDeploymentFactWithPrevious(t, pool, fixture, laterID, nil, "apply", "healthy", "healthy", now.Add(-30*time.Minute))
	if _, err := pool.Exec(context.Background(), `UPDATE node_config_state SET current_config_version_id=$3,revision=revision+1
		WHERE node_id=$1 AND configuration_scope_id=$2`, fixture.nodeID, fixture.scopeID, laterID); err != nil {
		t.Fatal(err)
	}

	request.RequestID, request.ObservedConfigVersionID = uuid.New(), &configID
	request.Evidence = "operator verified on the node that the source release ran there after its rollback failed; current version unchanged"
	if _, err := store.ReconcileNodeConfig(context.Background(), request); err != nil {
		t.Fatalf("supplemental confirmation after the later deployment: %v", err)
	}
	var current *uuid.UUID
	if err := pool.QueryRow(context.Background(), `SELECT current_config_version_id FROM node_config_state
		WHERE node_id=$1 AND configuration_scope_id=$2`, fixture.nodeID, fixture.scopeID).Scan(&current); err != nil ||
		current == nil || *current != laterID {
		t.Fatalf("current version after the supplement = %v (%v), want the later deployment's %s", current, err, laterID)
	}
	if !authorizesTelemetryVersion(t, pool, fixture, siteID, configID, now) {
		t.Fatal("the supplemented source version is not in the telemetry authorization")
	}
	if !authorizesTelemetryVersion(t, pool, fixture, siteID, laterID, now) {
		t.Fatal("the later deployment's version left the telemetry authorization")
	}
	if authorizesTelemetryVersion(t, pool, fixture, siteID, unconfirmedID, now) {
		t.Fatal("an unconfirmed rollback_failed version entered the telemetry authorization")
	}
	if authorizesTelemetryVersion(t, pool, otherFixture, siteID, configID, now) {
		t.Fatal("another node's scope authorized the supplemented version")
	}
}

// seedRollbackFailedSource binds a configuration artifact to the source apply
// (a stored digest matching its bytes) and opens the scope's
// rollback_failed reconciliation, as on a node with no current version before).
func seedRollbackFailedSource(t *testing.T, pool *pgxpool.Pool, fixture identityFixture, deploymentID, configID uuid.UUID, at time.Time) {
	t.Helper()
	wire := []byte("node generation 1 configuration " + configID.String())
	digest := sha256.Sum256(wire)
	artifactID := uuid.New()
	err := pgx.BeginFunc(context.Background(), pool, func(tx pgx.Tx) error {
		// Fixture rows only: published artifacts are immutable, so the
		// triggers are off for this transaction.
		if _, err := tx.Exec(context.Background(), `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		if _, err := tx.Exec(context.Background(), `INSERT INTO configuration_artifacts (
			id,config_version_id,ordinal,kind,wire_bytes,size_bytes,sha256,signature,signing_key_id,
			signature_algorithm,compression,media_type,encryption_algorithm,recipient_key_id,created_at)
			VALUES($1,$2,1,'configuration',$3,$4,$5,$6,'telemetry-test-key','ed25519','none',
			'application/vnd.cdnca.site-runtime+json','none',NULL,$7)`,
			artifactID, configID, wire, len(wire), digest[:], bytesOf(64, 9), at); err != nil {
			return err
		}
		if _, err := tx.Exec(context.Background(), `INSERT INTO node_deployment_artifacts (
			deployment_id,deployment_attempt,config_version_id,artifact_id,ordinal) VALUES($1,1,$2,$3,1)`,
			deploymentID, configID, artifactID); err != nil {
			return err
		}
		_, err := tx.Exec(context.Background(), `INSERT INTO node_config_state (
			node_id,configuration_scope_id,current_config_version_id,revision,updated_at,
			reconciliation_required,reconciliation_reason,reconciliation_deployment_id,
			reconciliation_deployment_attempt,reconciliation_requested_at)
			VALUES($1,$2,NULL,1,$3,true,'rollback_failed',$4,1,$3)`, fixture.nodeID, fixture.scopeID, at, deploymentID)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func authorizesTelemetryVersion(t *testing.T, pool *pgxpool.Pool, fixture identityFixture, siteID, configID uuid.UUID, now time.Time) bool {
	t.Helper()
	sites, err := TelemetrySiteScopesForTest(context.Background(), pool, fixture.nodeID, fixture.scopeID, fixture.tenantID, now)
	if err != nil {
		t.Fatalf("telemetry site scopes: %v", err)
	}
	for _, site := range sites {
		if site.SiteID == siteID && site.ConfigVersionID == configID && site.ConfigurationScopeID == fixture.scopeID &&
			site.TenantID == fixture.tenantID {
			return true
		}
	}
	return false
}
