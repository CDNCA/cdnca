//go:build integration

package edgeautopublish_test

import (
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/cnameallocation"
	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/site"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// fix-autopub (73, 10-27): a site update enqueued revision N, then the CNAME
// projection wrote the site row twice (335 trigger: N+1, N+2) without
// enqueueing. The worker's claim superseded the N request because a newer
// revision existed, and nothing ever published N+2: the nodes kept the old
// configuration. The claim must carry the superseded request on to the
// scope's current revision when no request covers it.
func TestClaimContinuesSupersededRequestAtUnrequestedCurrentRevision(t *testing.T) {
	pool := openAutomaticDatabase(t)
	identity := seedAutomaticIntegrationIdentity(t, pool)
	trust := installAutomaticSiteEntitlement(t, pool)
	service := site.NewService(site.NewStoreWithClock(pool, func() time.Time { return automaticIntegrationNow }, trust))
	actor := site.Actor{UserID: identity.tenantUser, ScopeID: identity.tenantScope, ScopeKind: "tenant"}
	insertPolicy(t, pool, identity, 1, edgeautopublish.ModeAutomatic)
	created, err := service.Create(t.Context(), actor, newSiteRequest("continue.example.test", "continue-site"))
	if err != nil {
		t.Fatal(err)
	}
	enqueued := scopeRevision(t, pool, identity.tenantScope)

	// Two site row writes nobody enqueues (the CNAME regenerate and settle).
	for _, cname := range []string{"regenerated.cname.test", "settled.cname.test"} {
		if _, err := pool.Exec(t.Context(), `UPDATE sites SET cname=$2 WHERE id=$1`, created.Site.ID, cname); err != nil {
			t.Fatal(err)
		}
	}
	current := scopeRevision(t, pool, identity.tenantScope)
	if current != enqueued+2 {
		t.Fatalf("site row writes advanced revision %d -> %d, want +2", enqueued, current)
	}

	repository := edgeautopublish.NewStore(pool)
	var claim edgeautopublish.Claim
	found := false
	for attempt := 0; attempt < 3 && !found; attempt++ {
		claim, found, err = repository.Claim(t.Context(), "continue-worker", time.Minute)
		if err != nil {
			t.Fatal(err)
		}
	}
	if !found {
		t.Fatalf("no request was claimable at current revision %d: the site change is never published", current)
	}
	if claim.Request.SourceRevision != current || claim.Request.SourceKind != edgeautopublish.SourceSite ||
		claim.Request.Operation != "site.create" || claim.Request.SourceResourceID != created.Site.ID ||
		claim.Request.ActorUserID != identity.tenantUser || claim.Request.SourceRequestID == "" {
		t.Fatalf("continuation request=%+v, want site.create of %s at %d", claim.Request, created.Site.ID, current)
	}
	var supersededCode string
	if err := pool.QueryRow(t.Context(), `SELECT state.terminal_code
		FROM edge_automatic_publication_requests request_row
		JOIN LATERAL (SELECT state,terminal_code FROM edge_automatic_publication_request_state_facts
			WHERE request_id=request_row.id ORDER BY sequence DESC LIMIT 1) state ON true
		WHERE request_row.source_revision=$1 AND state.state='superseded'`, enqueued).Scan(&supersededCode); err != nil {
		t.Fatalf("original request at %d not superseded: %v", enqueued, err)
	}
	assertRequestCount(t, pool, 2)

	// A newer revision that already has its own request gets no continuation.
	fields := siteFields("continue.example.test")
	fields.CNAME = "continue-newer.example.test"
	current2, err := service.Get(t.Context(), actor, created.Site.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Update(t.Context(), actor, site.UpdateRequest{
		ID: created.Site.ID, ExpectedRevision: current2.Revision, Fields: fields,
		IdempotencyKey: "continue-site-newer", RequestID: "continue-site-newer",
	}); err != nil {
		t.Fatal(err)
	}
	// The update supersedes the leased continuation; its own request is the
	// one claimed, without another continuation.
	next, found, err := repository.Claim(t.Context(), "continue-worker", time.Minute)
	if err != nil || !found || next.Request.Operation != "site.update" ||
		next.Request.SourceRevision != scopeRevision(t, pool, identity.tenantScope) {
		t.Fatalf("next Claim()=%+v, %t, %v", next.Request, found, err)
	}
	assertRequestCount(t, pool, 3)
}

// fix-autopub B: the site's request was already settled when the CNAME job
// ended and failed the site (cname_state, 335 trigger advances the revision).
// Nothing requested that revision, so no claim could ever publish it.
func TestCNAMEProjectionAfterSettledRequestEnqueuesCurrentRevision(t *testing.T) {
	pool := openAutomaticDatabase(t)
	identity := seedAutomaticIntegrationIdentity(t, pool)
	if _, err := pool.Exec(t.Context(), `INSERT INTO role_permissions(role_id,permission_name) VALUES($1,'dns.manage')`,
		identity.tenantRole); err != nil {
		t.Fatal(err)
	}
	trust := installAutomaticSiteEntitlement(t, pool)
	service := site.NewService(site.NewStoreWithClock(pool, func() time.Time { return automaticIntegrationNow }, trust))
	actor := site.Actor{UserID: identity.tenantUser, ScopeID: identity.tenantScope, ScopeKind: "tenant"}
	insertPolicy(t, pool, identity, 1, edgeautopublish.ModeAutomatic)
	created, err := service.Create(t.Context(), actor, newSiteRequest("projection.example.test", "projection-site"))
	if err != nil {
		t.Fatal(err)
	}
	var tenantID, jobID uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT job.tenant_id,job.id FROM sites site
		JOIN background_jobs job ON job.id=site.cname_task_id AND job.kind='dns.cname.intent'
		WHERE site.id=$1 AND site.cname_state='pending'`, created.Site.ID).Scan(&tenantID, &jobID); err != nil {
		t.Fatalf("site create queued no CNAME intent: %v", err)
	}
	// The save's request is published (terminal) before the CNAME job ends.
	var requestID uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT id FROM edge_automatic_publication_requests WHERE source_resource_id=$1`,
		created.Site.ID).Scan(&requestID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO edge_automatic_publication_request_state_facts(
		request_id,sequence,state,attempt,terminal_code,occurred_at) VALUES($1,2,'superseded',0,'test_settled',clock_timestamp())`,
		requestID); err != nil {
		t.Fatal(err)
	}
	before := scopeRevision(t, pool, identity.tenantScope)
	// The job ended (cancelled; jobstate's own receipts are out of scope
	// here), then its CNAME terminal hook fails the pending site.
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `UPDATE background_jobs SET state='cancelled',claimable_at=NULL,completed_at=updated_at WHERE tenant_id=$1 AND id=$2`,
			tenantID, jobID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		return cnameallocation.TerminalHook()(t.Context(), tx, tenantID, jobID, "cancelled", time.Now().UTC())
	}); err != nil {
		t.Fatal(err)
	}
	current := scopeRevision(t, pool, identity.tenantScope)
	if current <= before {
		t.Fatalf("CNAME job end did not write the site: revision %d -> %d", before, current)
	}
	var operation string
	var resourceID uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT operation,source_resource_id FROM edge_automatic_publication_requests
		WHERE target_scope_id=$1 AND source_revision=$2`, identity.tenantScope, current).Scan(&operation, &resourceID); err != nil {
		t.Fatalf("no automatic request at revision %d after the CNAME projection: %v", current, err)
	}
	if operation != "site.update" || resourceID != created.Site.ID {
		t.Fatalf("projection request=%s/%s", operation, resourceID)
	}
}

func scopeRevision(t *testing.T, pool *pgxpool.Pool, scopeID uuid.UUID) int64 {
	t.Helper()
	var revision int64
	if err := pool.QueryRow(t.Context(), `SELECT source_revision FROM edge_configuration_scopes WHERE scope_id=$1`,
		scopeID).Scan(&revision); err != nil {
		t.Fatal(err)
	}
	return revision
}
