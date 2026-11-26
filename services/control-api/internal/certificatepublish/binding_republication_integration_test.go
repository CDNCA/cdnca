//go:build integration

package certificatepublish

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/certificateasset"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/cdnca/cdnca/services/control-api/internal/edgestatus"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// control 1129 rev3: the tenant rebound a site to another certificate, its
// publication reached the node, and the node kept serving the old one: the
// site object names the version and nothing republished it. Now the
// transaction that settles the publication succeeded queues the scope's
// system republication (certificate_renewal, the renewal's channel) once the
// material is on every node, and only for the site's latest binding; a
// failing republication request rolls the settlement back (retried).
func TestBindingPublicationSucceededQueuesSiteRepublication(t *testing.T) {
	pool := openPublicationIntegrationDatabase(t)
	ctx := t.Context()
	certificates, err := certificateasset.NewStoreWithDependencies(
		pool, integrationCertificateEnveloper{}, audit.New(pool), func() time.Time { return publicationIntegrationNow },
	)
	if err != nil {
		t.Fatal(err)
	}
	tenant := seedPublicationTenant(t, pool)
	if _, err := pool.Exec(ctx, `INSERT INTO edge_configuration_scopes(scope_id,source_revision,updated_at)
		VALUES($1,1,now()) ON CONFLICT (scope_id) DO NOTHING`, tenant.scopeID); err != nil {
		t.Fatal(err)
	}
	importActive := func(name string) certificateasset.ImportResult {
		t.Helper()
		certificatePEM, privateKeyPEM := issuePublicationCertificate(t, tenant.domain)
		imported, err := certificates.Import(ctx, tenant.certificateActor, certificateasset.ImportRequest{
			TenantScopeID: tenant.scopeID, Name: name, Source: certificateasset.SourceUploaded,
			CertificatePEM: certificatePEM, PrivateKeyPEM: privateKeyPEM, IdempotencyKey: name + "-import", RequestID: uuid.NewString(),
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := certificates.Activate(ctx, tenant.certificateActor, certificateasset.ActivateRequest{
			TenantScopeID: tenant.scopeID, AssetID: imported.Asset.ID, VersionID: imported.Version.ID,
			ExpectedRevision: imported.Asset.Revision, IdempotencyKey: name + "-activate", RequestID: uuid.NewString(),
		}); err != nil {
			t.Fatal(err)
		}
		return imported
	}
	first, second := importActive("binding-a"), importActive("binding-b")
	bind := func(asset certificateasset.ImportResult, expected int64, key string) certificateasset.Binding {
		t.Helper()
		bound, err := certificates.Bind(ctx, tenant.certificateActor, certificateasset.BindRequest{
			TenantScopeID: tenant.scopeID, SiteID: tenant.siteID, AssetID: asset.Asset.ID, VersionID: asset.Version.ID,
			ExpectedRevision: expected, Default: true, IdempotencyKey: key, RequestID: uuid.NewString(),
		})
		if err != nil {
			t.Fatal(err)
		}
		return bound
	}
	boundA := bind(first, 0, "binding-bind-a")

	actor, deploymentStore := seedPublicationDeploymentActor(t, pool)
	statusStore, err := edgestatus.NewStoreWithClock(pool, func() time.Time { return publicationIntegrationNow })
	if err != nil {
		t.Fatal(err)
	}
	nodes := []publicationNode{seedPublicationNode(t, pool, tenant.scopeID, tenant.userID)}
	service := newRecoverPublicationService(t, pool, certificates, deploymentStore)
	deliver := func(binding certificateasset.Binding, key string) certificateasset.PublicationResult {
		t.Helper()
		published, err := service.Publish(ctx, publicationIntegrationRequest(t, pool, actor, tenant, nodes, binding, key))
		if err != nil {
			t.Fatal(err)
		}
		for _, deployment := range published.Rollout.Deployments {
			projectPublicationSuccess(t, statusStore, deployment)
		}
		return certificateasset.PublicationResult{
			Outcome: certificateasset.PublicationAck, PublicationID: uuid.New(), PublicationRevision: published.Rollout.Revision,
			ConfigVersionID: published.Rollout.ConfigVersionID, RolloutID: published.Rollout.ID, RolloutRevision: published.Rollout.Revision,
		}
	}
	type hookCall struct {
		site     uuid.UUID
		revision int64
	}
	var calls []hookCall
	var failHook error
	config := certificateasset.DefaultPublicationIntentStoreConfig()
	config.Published = func(ctx context.Context, tx pgx.Tx, scopeID, siteID uuid.UUID, revision int64) error {
		if failHook != nil {
			return failHook
		}
		calls = append(calls, hookCall{siteID, revision})
		return RequestBindingRepublicationTx(ctx, tx, scopeID, siteID, revision)
	}
	intents, err := certificateasset.NewPublicationIntentStore(pool, config)
	if err != nil {
		t.Fatal(err)
	}
	claim := func(want int64) certificateasset.PublicationIntentLease {
		t.Helper()
		lease, found, err := intents.ClaimPublicationIntent(ctx, "binding-worker")
		if err != nil || !found || lease.BindingRevision != want {
			t.Fatalf("claim = %+v found=%t err=%v, want revision %d", lease, found, err, want)
		}
		return lease
	}
	queued := func() (pending bool, triggers []string, segments int) {
		t.Helper()
		if err := pool.QueryRow(ctx, `SELECT COALESCE((SELECT state='pending' FROM edge_system_republication_heads WHERE scope_id=$1),false),
			COALESCE((SELECT triggers FROM edge_system_republication_heads WHERE scope_id=$1),'{}'),
			(SELECT count(*) FROM edge_system_revision_segments WHERE scope_id=$1 AND source='certificate_renewal')`,
			tenant.scopeID).Scan(&pending, &triggers, &segments); err != nil {
			t.Fatal(err)
		}
		return pending, triggers, segments
	}

	// The first binding's publication settles: one republication, attributed
	// to the system (the tenant's chain stays clean).
	resultA := deliver(boundA, "binding-publish-a")
	if err := intents.CompletePublicationIntent(ctx, claim(boundA.Revision), resultA); err != nil {
		t.Fatal(err)
	}
	if pending, triggers, segments := queued(); !pending || len(triggers) != 1 ||
		triggers[0] != edgepublish.SystemTriggerCertificateRenewal || segments != 1 || len(calls) != 1 {
		t.Fatalf("BUG bound certificate not republished: pending=%t triggers=%v segments=%d calls=%v", pending, triggers, segments, calls)
	}
	if _, err := pool.Exec(ctx, `UPDATE edge_system_republication_heads SET state='idle',triggers=ARRAY['node_sync']
		WHERE scope_id=$1`, tenant.scopeID); err != nil {
		t.Fatal(err)
	}

	// Rebind to B. A failing republication request leaves the intent leased
	// (the lease expires and the worker settles it again).
	boundB := bind(second, boundA.Revision, "binding-bind-b")
	resultB := deliver(boundB, "binding-publish-b")
	leaseB := claim(boundB.Revision)
	failHook = errors.New("republication unavailable")
	if err := intents.CompletePublicationIntent(ctx, leaseB, resultB); !errors.Is(err, failHook) {
		t.Fatalf("settle with a failing republication = %v", err)
	}
	var state string
	if err := pool.QueryRow(ctx, `SELECT state FROM certificate_publication_intent_state_facts
		WHERE tenant_scope_id=$1 AND site_id=$2 AND binding_revision=$3 ORDER BY sequence DESC LIMIT 1`,
		tenant.scopeID, tenant.siteID, boundB.Revision).Scan(&state); err != nil || state != "leased" {
		t.Fatalf("intent after a failed republication request: state=%s err=%v", state, err)
	}
	failHook = nil
	if err := intents.CompletePublicationIntent(ctx, leaseB, resultB); err != nil {
		t.Fatal(err)
	}
	if pending, triggers, _ := queued(); !pending || len(triggers) != 1 || triggers[0] != edgepublish.SystemTriggerCertificateRenewal {
		t.Fatalf("BUG rebound certificate not republished: pending=%t triggers=%v", pending, triggers)
	}

	// A binding that is no longer the site's latest leaves it to the latest.
	var before int64
	if err := pool.QueryRow(ctx, `SELECT source_revision FROM edge_configuration_scopes WHERE scope_id=$1`, tenant.scopeID).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		return RequestBindingRepublicationTx(ctx, tx, tenant.scopeID, tenant.siteID, boundA.Revision)
	}); err != nil {
		t.Fatal(err)
	}
	var after int64
	if err := pool.QueryRow(ctx, `SELECT source_revision FROM edge_configuration_scopes WHERE scope_id=$1`, tenant.scopeID).Scan(&after); err != nil || after != before {
		t.Fatalf("an older binding republished the scope: revision %d -> %d (%v)", before, after, err)
	}

	// An HTTPS site cannot lose its certificate: the unbind is refused (its
	// configuration could not be published, its nodes would keep serving it).
	if _, err := pool.Exec(ctx, `UPDATE sites SET https_enabled=true,https_ports=ARRAY['443'] WHERE id=$1`, tenant.siteID); err != nil {
		t.Fatal(err)
	}
	if _, err := certificates.Unbind(ctx, tenant.certificateActor, certificateasset.UnbindRequest{
		TenantScopeID: tenant.scopeID, SiteID: tenant.siteID, ExpectedRevision: boundB.Revision,
		IdempotencyKey: "binding-unbind-https", RequestID: uuid.NewString(),
	}); !errors.Is(err, certificateasset.ErrSiteHTTPSEnabled) {
		t.Fatalf("unbind of an HTTPS site = %v, want ErrSiteHTTPSEnabled", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE sites SET https_enabled=false,https_ports=ARRAY[]::text[] WHERE id=$1`, tenant.siteID); err != nil {
		t.Fatal(err)
	}
	if _, err := certificates.Unbind(ctx, tenant.certificateActor, certificateasset.UnbindRequest{
		TenantScopeID: tenant.scopeID, SiteID: tenant.siteID, ExpectedRevision: boundB.Revision,
		IdempotencyKey: "binding-unbind-http", RequestID: uuid.NewString(),
	}); err != nil {
		t.Fatalf("unbind of an HTTP site: %v", err)
	}
}
