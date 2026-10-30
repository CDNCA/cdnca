//go:build integration

package edgeautopublish_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/entitlement"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish/capabilitytest"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/l4forward"
	"github.com/cdnca/cdnca/services/control-api/internal/site"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var automaticIntegrationNow = time.Now().UTC().Truncate(time.Minute)

type automaticIntegrationIdentity struct {
	tenantScope, tenantUser, tenantRole       uuid.UUID
	platformScope, platformUser, platformRole uuid.UUID
}

func TestSiteAndL4MutationsEnqueueAtomically(t *testing.T) {
	pool := openAutomaticDatabase(t)
	identity := seedAutomaticIntegrationIdentity(t, pool)
	trust := installAutomaticSiteEntitlement(t, pool)
	siteService := site.NewService(site.NewStoreWithClock(pool, func() time.Time { return automaticIntegrationNow }, trust))
	l4Service := l4forward.NewService(l4forward.NewStoreWithClock(pool, func() time.Time { return automaticIntegrationNow }))
	tenantSiteActor := site.Actor{UserID: identity.tenantUser, ScopeID: identity.tenantScope, ScopeKind: "tenant"}
	tenantL4Actor := l4forward.Actor{UserID: identity.tenantUser, ScopeID: identity.tenantScope, ScopeKind: "tenant"}
	l4Binding := insertAutomaticL4Binding(t, pool, identity)

	insertPolicy(t, pool, identity, 1, edgeautopublish.ModeManual)
	manualSite, err := siteService.Create(t.Context(), tenantSiteActor, newSiteRequest("manual.example.test", "manual-site"))
	if err != nil {
		t.Fatalf("manual site create: %v", err)
	}
	assertRequestCount(t, pool, 0)

	insertPolicy(t, pool, identity, 2, edgeautopublish.ModeAutomatic)
	automaticSite, err := siteService.Create(t.Context(), tenantSiteActor, newSiteRequest("automatic.example.test", "automatic-site"))
	if err != nil {
		t.Fatalf("automatic site create: %v", err)
	}
	assertLatestOperation(t, pool, "site.create")

	fields := siteFields("automatic.example.test")
	fields.CNAME = "cname.example.test"
	automaticSite, err = siteService.Update(t.Context(), tenantSiteActor, site.UpdateRequest{
		ID: automaticSite.Site.ID, ExpectedRevision: automaticSite.Site.Revision, Fields: fields,
		IdempotencyKey: "automatic-site-update", RequestID: "automatic-site-update",
	})
	if err != nil {
		t.Fatalf("site update: %v", err)
	}
	assertLatestOperation(t, pool, "site.update")

	poolUpdate := automaticSite.Site.OriginPool
	poolUpdate.Origins[0].Weight = 2
	automaticSite, err = siteService.UpdateOrigin(t.Context(), tenantSiteActor, site.UpdateOriginRequest{
		ID: automaticSite.Site.ID, ExpectedRevision: automaticSite.Site.Revision, Pool: poolUpdate,
		IdempotencyKey: "automatic-site-origin", RequestID: "automatic-site-origin",
	})
	if err != nil {
		t.Fatalf("site origin update: %v", err)
	}
	assertLatestOperation(t, pool, "site.origin.update")

	batch, err := siteService.BatchAction(t.Context(), tenantSiteActor, site.BatchActionRequest{
		Action:         site.BatchActionDisable,
		Items:          []site.BatchActionItem{{ID: automaticSite.Site.ID, ExpectedRevision: automaticSite.Site.Revision}},
		IdempotencyKey: "automatic-site-batch", RequestID: "automatic-site-batch",
	})
	if err != nil || len(batch.Items) != 1 || batch.Items[0].Error != nil {
		t.Fatalf("site batch: %+v, %v", batch, err)
	}
	assertLatestOperation(t, pool, "site.batch.disable")
	if _, err := siteService.Delete(t.Context(), tenantSiteActor, site.DeleteRequest{
		ID: automaticSite.Site.ID, ExpectedRevision: automaticSite.Site.Revision + 1,
		IdempotencyKey: "automatic-site-delete", RequestID: "automatic-site-delete",
	}); err != nil {
		t.Fatalf("site delete: %v", err)
	}
	assertLatestOperation(t, pool, "site.delete")

	forward, err := l4Service.Create(t.Context(), tenantL4Actor, newL4Request(l4Binding, "automatic-stream", 18086, "automatic-stream"))
	if err != nil {
		t.Fatalf("l4 create: %v", err)
	}
	assertLatestOperation(t, pool, "stream.create")
	updatedFields := l4Fields(l4Binding, "automatic-stream-updated", 18086)
	forward, err = l4Service.Update(t.Context(), tenantL4Actor, l4forward.UpdateRequest{
		ID: forward.Forward.ID, ExpectedRevision: forward.Forward.Revision, Fields: updatedFields,
		IdempotencyKey: "automatic-stream-update", RequestID: "automatic-stream-update",
	})
	if err != nil {
		t.Fatalf("l4 update: %v", err)
	}
	assertLatestOperation(t, pool, "stream.update")
	if _, err := l4Service.Delete(t.Context(), tenantL4Actor, l4forward.DeleteRequest{
		ID: forward.Forward.ID, ExpectedRevision: forward.Forward.Revision,
		IdempotencyKey: "automatic-stream-delete", RequestID: "automatic-stream-delete",
	}); err != nil {
		t.Fatalf("l4 delete: %v", err)
	}
	assertLatestOperation(t, pool, "stream.delete")

	insertPolicy(t, pool, identity, 3, edgeautopublish.ModeManual)
	before := requestCount(t, pool)
	if _, err := l4Service.Create(t.Context(), tenantL4Actor, newL4Request(l4Binding, "manual-stream", 18087, "manual-stream")); err != nil {
		t.Fatalf("manual l4 create: %v", err)
	}
	if after := requestCount(t, pool); after != before {
		t.Fatalf("manual policy enqueued request: before=%d after=%d", before, after)
	}

	insertPolicy(t, pool, identity, 4, edgeautopublish.ModeAutomatic)
	assertAutomaticAuditPayloads(t, pool, identity.tenantScope)
	assertPlatformActorTargeting(t, pool, siteService, identity)
	assertRBACRevocationRollsBack(t, pool, siteService, tenantSiteActor, manualSite.Site)
	assertEnqueueFailureRollsBackBusinessFact(t, pool, siteService, tenantSiteActor)
}

func TestWorkerClaimIsShortAndSupersededWorkerLosesCAS(t *testing.T) {
	pool := openAutomaticDatabase(t)
	identity := seedAutomaticIntegrationIdentity(t, pool)
	trust := installAutomaticSiteEntitlement(t, pool)
	service := site.NewService(site.NewStoreWithClock(pool, func() time.Time { return automaticIntegrationNow }, trust))
	actor := site.Actor{UserID: identity.tenantUser, ScopeID: identity.tenantScope, ScopeKind: "tenant"}
	insertPolicy(t, pool, identity, 1, edgeautopublish.ModeAutomatic)
	created, err := service.Create(t.Context(), actor, newSiteRequest("worker.example.test", "worker-site"))
	if err != nil {
		t.Fatal(err)
	}

	repository := edgeautopublish.NewStore(pool)
	claim, found, err := repository.Claim(t.Context(), "worker-claim", time.Minute)
	if err != nil || !found {
		t.Fatalf("Claim() = %+v, %t, %v", claim, found, err)
	}
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRow(t.Context(), `SELECT id FROM edge_automatic_publication_requests WHERE id=$1 FOR UPDATE NOWAIT`, claim.Request.ID).Scan(new(uuid.UUID)); err != nil {
		_ = tx.Rollback(t.Context())
		t.Fatalf("claim retained request row lock outside short transaction: %v", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}

	fields := siteFields("worker.example.test")
	fields.CNAME = "new-worker.example.test"
	if _, err := service.Update(t.Context(), actor, site.UpdateRequest{
		ID: created.Site.ID, ExpectedRevision: created.Site.Revision, Fields: fields,
		IdempotencyKey: "worker-site-newer", RequestID: "worker-site-newer",
	}); err != nil {
		t.Fatal(err)
	}
	staleResult := edgepublish.PublishResult{
		PublicationID: uuid.New(), ConfigurationScopeID: identity.tenantScope,
		SourceRevision: claim.Request.SourceRevision, RolloutID: uuid.New(),
	}
	if err := repository.RecordPublication(t.Context(), claim, staleResult); !edgeautopublish.IsStaleClaim(err) {
		t.Fatalf("stale RecordPublication error=%v", err)
	}
	assertLatestOperation(t, pool, "site.update")
}

func TestPrepareAutomaticPublicationRejectsInexactExpiredAndRevokedClaims(t *testing.T) {
	t.Run("exact reference and database clock", func(t *testing.T) {
		pool, identity, repository, reference := prepareAutomaticReference(t, "prepare-exact.example.test", time.Second)
		tx, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		prepared, err := repository.PrepareAutomaticPublication(t.Context(), tx, reference)
		_ = tx.Rollback(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if prepared.DatabaseNow.IsZero() || !prepared.Request.Deadline.After(prepared.DatabaseNow) ||
			prepared.Request.Actor.UserID != identity.tenantUser ||
			prepared.Request.Actor.ScopeID != identity.tenantScope ||
			prepared.Request.Actor.ScopeKind != edgepublish.ScopeKindTenant {
			t.Fatalf("prepared automatic publication=%+v", prepared)
		}

		for _, inexact := range []edgepublish.AutomaticClaimReference{
			{RequestID: reference.RequestID, LeaseToken: uuid.New(), StateSequence: reference.StateSequence},
			{RequestID: reference.RequestID, LeaseToken: reference.LeaseToken, StateSequence: reference.StateSequence + 1},
		} {
			tx, err := pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			_, prepareErr := repository.PrepareAutomaticPublication(t.Context(), tx, inexact)
			_ = tx.Rollback(t.Context())
			if !edgeautopublish.IsStaleClaim(prepareErr) {
				t.Fatalf("inexact reference error=%v", prepareErr)
			}
		}

		var leaseExpiresAt, databaseNow time.Time
		if err := pool.QueryRow(t.Context(), `SELECT lease_expires_at,clock_timestamp()
			FROM edge_automatic_publication_request_state_facts
			WHERE request_id=$1 AND sequence=$2`, reference.RequestID, reference.StateSequence).
			Scan(&leaseExpiresAt, &databaseNow); err != nil {
			t.Fatal(err)
		}
		if wait := leaseExpiresAt.Sub(databaseNow) + 25*time.Millisecond; wait > 0 {
			time.Sleep(wait)
		}
		tx, err = pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		_, prepareErr := repository.PrepareAutomaticPublication(t.Context(), tx, reference)
		_ = tx.Rollback(t.Context())
		if !edgeautopublish.IsStaleClaim(prepareErr) {
			t.Fatalf("expired lease error=%v", prepareErr)
		}
	})

	t.Run("revocation commits before prepare", func(t *testing.T) {
		pool, identity, repository, reference := prepareAutomaticReference(t, "prepare-revoked.example.test", time.Minute)
		if _, err := pool.Exec(t.Context(), `DELETE FROM role_assignments WHERE scope_id=$1 AND user_id=$2`,
			identity.tenantScope, identity.tenantUser); err != nil {
			t.Fatal(err)
		}
		tx, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		_, prepareErr := repository.PrepareAutomaticPublication(t.Context(), tx, reference)
		_ = tx.Rollback(t.Context())
		if !errors.Is(prepareErr, edgeautopublish.ErrPermissionDenied) {
			t.Fatalf("revoked prepare error=%v", prepareErr)
		}
	})
}

func TestExpiredAutomaticRequestBecomesTerminalAcrossLeaseWindows(t *testing.T) {
	pool := openAutomaticDatabase(t)
	identity := seedAutomaticIntegrationIdentity(t, pool)
	trust := installAutomaticSiteEntitlement(t, pool)
	service := site.NewService(site.NewStoreWithClock(pool, func() time.Time { return automaticIntegrationNow }, trust))
	// 086 的 CHECK 要求 deadline_window_seconds 在 30..86400；请求行不可改，只能等满最短窗口。
	insertExpiringPublishablePolicy(t, pool, identity, 1, 30*time.Second)
	actor := site.Actor{UserID: identity.tenantUser, ScopeID: identity.tenantScope, ScopeKind: "tenant"}
	if _, err := service.Create(t.Context(), actor,
		newSiteRequest("expired-automatic-request.example.test", "expired-automatic-request")); err != nil {
		t.Fatal(err)
	}
	var requestID uuid.UUID
	var deadline, databaseNow time.Time
	if err := pool.QueryRow(t.Context(), `SELECT id,created_at + interval '30 seconds',clock_timestamp()
		FROM edge_automatic_publication_requests WHERE source_request_id='expired-automatic-request'`).
		Scan(&requestID, &deadline, &databaseNow); err != nil {
		t.Fatal(err)
	}
	if wait := deadline.Sub(databaseNow) + 25*time.Millisecond; wait > 0 {
		time.Sleep(wait)
	}

	repository := edgeautopublish.NewStore(pool)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	deployments, err := edgedeployment.NewStoreWithClock(pool, func() time.Time { return automaticIntegrationNow })
	if err != nil {
		t.Fatal(err)
	}
	config := edgepublish.DefaultConfig()
	config.Clock = func() time.Time { panic("automatic publication used application clock") }
	config.EntitlementAuthorizer = automaticAllowAuthorizer{}
	publisher, err := edgepublish.NewAutomaticService(pool, deployments, automaticEntitlementSigner{
		id: "expired-automatic-artifact", public: publicKey, private: privateKey,
	}, config, repository)
	if err != nil {
		t.Fatal(err)
	}
	newWorker := func(id string) *edgeautopublish.Worker {
		worker, err := edgeautopublish.NewWorker(repository, publisher, edgeautopublish.WorkerConfig{
			WorkerID: id, LeaseDuration: time.Second, RetryDelay: time.Millisecond,
		})
		if err != nil {
			t.Fatal(err)
		}
		return worker
	}
	if worked, err := newWorker("expired-request-worker-one").RunOnce(t.Context()); err != nil || !worked {
		t.Fatalf("first RunOnce() = %t, %v", worked, err)
	}
	var state, terminalCode string
	var facts, terminalAudits, publications, rollouts, deploymentsCount int
	var leaseExpiresAt time.Time
	if err := pool.QueryRow(t.Context(), `SELECT state,terminal_code
		FROM edge_automatic_publication_request_state_facts
		WHERE request_id=$1 ORDER BY sequence DESC LIMIT 1`, requestID).Scan(&state, &terminalCode); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(t.Context(), `SELECT lease_expires_at
		FROM edge_automatic_publication_request_state_facts WHERE request_id=$1 AND sequence=2`, requestID).
		Scan(&leaseExpiresAt); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM edge_automatic_publication_request_state_facts WHERE request_id=$1),
		(SELECT count(*) FROM audit_events WHERE action='edge_automatic_publication.failed' AND resource_id=$1::text),
		(SELECT count(*) FROM edge_config_publications),
		(SELECT count(*) FROM rollouts),
		(SELECT count(*) FROM node_deployments)`, requestID).
		Scan(&facts, &terminalAudits, &publications, &rollouts, &deploymentsCount); err != nil {
		t.Fatal(err)
	}
	if state != edgeautopublish.StateFailed || terminalCode != "request_deadline_expired" ||
		facts != 3 || terminalAudits != 1 || publications != 0 || rollouts != 0 || deploymentsCount != 0 {
		t.Fatalf("terminal state/code/facts/audits/publications/rollouts/deployments=%s/%s/%d/%d/%d/%d/%d",
			state, terminalCode, facts, terminalAudits, publications, rollouts, deploymentsCount)
	}
	if err := pool.QueryRow(t.Context(), `SELECT clock_timestamp()`).Scan(&databaseNow); err != nil {
		t.Fatal(err)
	}
	if wait := leaseExpiresAt.Sub(databaseNow) + 25*time.Millisecond; wait > 0 {
		time.Sleep(wait)
	}
	if worked, err := newWorker("expired-request-worker-two").RunOnce(t.Context()); err != nil || worked {
		t.Fatalf("second RunOnce() = %t, %v", worked, err)
	}
	var finalFacts, finalAudits int
	if err := pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM edge_automatic_publication_request_state_facts WHERE request_id=$1),
		(SELECT count(*) FROM audit_events WHERE action='edge_automatic_publication.failed' AND resource_id=$1::text)`, requestID).
		Scan(&finalFacts, &finalAudits); err != nil {
		t.Fatal(err)
	}
	if finalFacts != facts || finalAudits != terminalAudits {
		t.Fatalf("post-lease facts/audits=%d/%d want=%d/%d", finalFacts, finalAudits, facts, terminalAudits)
	}
}

func TestAcceptedEntitlementRevocationLeavesAutomaticPublicationWithoutReceipts(t *testing.T) {
	pool := openAutomaticDatabase(t)
	identity := seedAutomaticIntegrationIdentity(t, pool)
	entitlementFixture := installAutomaticSiteEntitlementFixture(t, pool)
	service := site.NewService(site.NewStoreWithClock(
		pool, func() time.Time { return automaticIntegrationNow }, entitlementFixture.trust,
	))
	insertPublishablePolicy(t, pool, identity, 1)
	actor := site.Actor{UserID: identity.tenantUser, ScopeID: identity.tenantScope, ScopeKind: "tenant"}
	if _, err := service.Create(t.Context(), actor,
		newSiteRequest("revoked-automatic-publication.example.test", "revoked-automatic-publication")); err != nil {
		t.Fatal(err)
	}
	revokeAutomaticSiteEntitlement(t, pool, entitlementFixture)

	repository := edgeautopublish.NewStore(pool)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	deployments, err := edgedeployment.NewStoreWithClock(pool, func() time.Time { return automaticIntegrationNow })
	if err != nil {
		t.Fatal(err)
	}
	config := edgepublish.DefaultConfig()
	config.Clock = func() time.Time { panic("automatic publication used application clock") }
	config.EntitlementAuthorizer = automaticRevocationAwareAuthorizer{
		pool: pool, trust: entitlementFixture.trust,
	}
	publisher, err := edgepublish.NewAutomaticService(pool, deployments, automaticEntitlementSigner{
		id: "revoked-automatic-artifact", public: publicKey, private: privateKey,
	}, config, repository)
	if err != nil {
		t.Fatal(err)
	}
	worker, err := edgeautopublish.NewWorker(repository, publisher, edgeautopublish.WorkerConfig{
		WorkerID: "revoked-entitlement-worker", LeaseDuration: time.Minute, RetryDelay: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if worked, err := worker.RunOnce(t.Context()); err != nil || !worked {
		t.Fatalf("RunOnce() = %t, %v", worked, err)
	}
	var latestState string
	var publications, rollouts, deploymentsCount, reconcilingFacts, entitlementDenials int
	if err := pool.QueryRow(t.Context(), `SELECT
		(SELECT state FROM edge_automatic_publication_request_state_facts ORDER BY sequence DESC LIMIT 1),
		(SELECT count(*) FROM edge_config_publications),
		(SELECT count(*) FROM rollouts),
		(SELECT count(*) FROM node_deployments),
		(SELECT count(*) FROM edge_automatic_publication_request_state_facts WHERE state='reconciling'),
		(SELECT count(*) FROM audit_events WHERE action='edge_publication.entitlement_check' AND result='denied')`).
		Scan(&latestState, &publications, &rollouts, &deploymentsCount, &reconcilingFacts, &entitlementDenials); err != nil {
		t.Fatal(err)
	}
	if latestState != edgeautopublish.StateRetryWait || publications != 0 || rollouts != 0 || deploymentsCount != 0 ||
		reconcilingFacts != 0 || entitlementDenials != 1 {
		t.Fatalf("state/publications/rollouts/deployments/receipts/denials=%s/%d/%d/%d/%d/%d",
			latestState, publications, rollouts, deploymentsCount, reconcilingFacts, entitlementDenials)
	}
}

func TestAutomaticPublicationHoldsIAMAuthorityThroughRecordCommit(t *testing.T) {
	pool := openAutomaticDatabase(t)
	identity := seedAutomaticIntegrationIdentity(t, pool)
	// Publishing reads the installed control entitlement (telemetry installation identity).
	installAutomaticSiteEntitlement(t, pool)
	nodes := insertPublishablePolicy(t, pool, identity, 1)
	l4Service := l4forward.NewService(l4forward.NewStoreWithClock(pool, func() time.Time { return automaticIntegrationNow }))
	actor := l4forward.Actor{UserID: identity.tenantUser, ScopeID: identity.tenantScope, ScopeKind: "tenant"}
	if _, err := l4Service.Create(t.Context(), actor, newL4Request(insertAutomaticL4Binding(t, pool, identity),
		"atomic-lock-stream", 18091, "atomic-lock-stream")); err != nil {
		t.Fatal(err)
	}
	repository := edgeautopublish.NewStore(pool)
	signer := newBlockingAutomaticArtifactSigner(t)
	deployments, err := edgedeployment.NewStoreWithClock(pool, func() time.Time { return automaticIntegrationNow })
	if err != nil {
		t.Fatal(err)
	}
	config := edgepublish.DefaultConfig()
	config.Clock = func() time.Time { panic("automatic publication used application clock") }
	config.EntitlementAuthorizer = automaticAllowAuthorizer{}
	publisher, err := edgepublish.NewAutomaticService(pool, deployments, signer, config, repository)
	if err != nil {
		t.Fatal(err)
	}
	worker, err := edgeautopublish.NewWorker(repository, publisher, edgeautopublish.WorkerConfig{
		WorkerID: "atomic-lock-worker", LeaseDuration: time.Minute, RetryDelay: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	workerDone := make(chan error, 1)
	go func() {
		worked, runErr := worker.RunOnce(t.Context())
		if runErr == nil && !worked {
			runErr = errors.New("worker did not claim automatic publication")
		}
		workerDone <- runErr
	}()
	select {
	case <-signer.entered:
	case err := <-workerDone:
		t.Fatalf("automatic publication did not reach signer: worker returned %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("automatic publication did not reach signer")
	}

	revokerStarted := make(chan struct{})
	revokerDone := make(chan error, 1)
	go func() {
		close(revokerStarted)
		revokerDone <- pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
			if err := iamlock.AcquireExclusive(t.Context(), tx); err != nil {
				return err
			}
			if _, err := iamlock.AcquireScopes(t.Context(), tx, []uuid.UUID{identity.tenantScope}); err != nil {
				return err
			}
			_, err := tx.Exec(t.Context(), `DELETE FROM role_assignments WHERE scope_id=$1 AND user_id=$2`,
				identity.tenantScope, identity.tenantUser)
			return err
		})
	}()
	<-revokerStarted
	select {
	case err := <-revokerDone:
		t.Fatalf("revoker completed before publication Record commit: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	close(signer.release)
	if err := <-workerDone; err != nil {
		t.Fatal(err)
	}
	if err := <-revokerDone; err != nil {
		t.Fatal(err)
	}
	var state string
	if err := pool.QueryRow(t.Context(), `SELECT state FROM edge_automatic_publication_request_state_facts
		ORDER BY occurred_at DESC,sequence DESC LIMIT 1`).Scan(&state); err != nil {
		t.Fatal(err)
	}
	var publications int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM edge_config_publications`).Scan(&publications); err != nil {
		t.Fatal(err)
	}
	if state != edgeautopublish.StateReconciling || publications != 1 || len(nodes) != 2 {
		t.Fatalf("state/publications/nodes=%s/%d/%d", state, publications, len(nodes))
	}
	// An automatic publication never chooses a site runtime: it is the
	// default, v2 (an L4-only scope here).
	var schema string
	if err := pool.QueryRow(t.Context(), `SELECT convert_from(config.canonical_snapshot,'UTF8')::jsonb->>'schema'
		FROM edge_config_publications publication JOIN config_versions config ON config.id=publication.config_version_id`).
		Scan(&schema); err != nil || schema != edgepublish.SiteRuntimeV2Schema {
		t.Fatalf("automatic publication schema=%q err=%v, want site runtime v2", schema, err)
	}
}

func TestTwoWorkersDoNotPublishOneClaimConcurrently(t *testing.T) {
	pool := openAutomaticDatabase(t)
	identity := seedAutomaticIntegrationIdentity(t, pool)
	trust := installAutomaticSiteEntitlement(t, pool)
	service := site.NewService(site.NewStoreWithClock(pool, func() time.Time { return automaticIntegrationNow }, trust))
	actor := site.Actor{UserID: identity.tenantUser, ScopeID: identity.tenantScope, ScopeKind: "tenant"}
	insertPolicy(t, pool, identity, 1, edgeautopublish.ModeAutomatic)
	if _, err := service.Create(t.Context(), actor, newSiteRequest("two-workers.example.test", "two-workers")); err != nil {
		t.Fatal(err)
	}

	publisher := &blockingPublisher{entered: make(chan struct{}), release: make(chan struct{})}
	repository := edgeautopublish.NewStore(pool)
	workerOne, err := edgeautopublish.NewWorker(repository, publisher,
		edgeautopublish.WorkerConfig{WorkerID: "worker-one", LeaseDuration: time.Minute, RetryDelay: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	workerTwo, err := edgeautopublish.NewWorker(repository, publisher,
		edgeautopublish.WorkerConfig{WorkerID: "worker-two", LeaseDuration: time.Minute, RetryDelay: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, runErr := workerOne.RunOnce(t.Context())
		done <- runErr
	}()
	select {
	case <-publisher.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("first worker did not reach publisher")
	}
	if worked, err := workerTwo.RunOnce(t.Context()); err != nil || worked {
		t.Fatalf("second worker RunOnce() = %t, %v", worked, err)
	}
	close(publisher.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if publisher.calls.Load() != 1 {
		t.Fatalf("publisher calls=%d", publisher.calls.Load())
	}
}

type blockingPublisher struct {
	entered chan struct{}
	release chan struct{}
	calls   atomic.Int64
}

type automaticAllowAuthorizer struct{}

func (automaticAllowAuthorizer) AuthorizePublication(
	_ context.Context,
	_ pgx.Tx,
	request edgepublish.EntitlementRequest,
) (edgepublish.EntitlementDecision, error) {
	return edgepublish.EntitlementDecision{
		Allowed: true, LocallyVerified: true, Status: edgepublish.EntitlementStatusValid,
		LeaseSerial: 1, EvaluatedAt: request.EvaluatedAt,
	}, nil
}

type automaticRevocationAwareAuthorizer struct {
	pool  *pgxpool.Pool
	trust *entitlementguard.TrustStore
}

func (authorizer automaticRevocationAwareAuthorizer) AuthorizePublication(
	ctx context.Context,
	tx pgx.Tx,
	request edgepublish.EntitlementRequest,
) (edgepublish.EntitlementDecision, error) {
	evaluatedAt := request.EvaluatedAt.UTC()
	decision, err := entitlementguard.NewGuard(
		authorizer.pool, func() time.Time { return evaluatedAt }, authorizer.trust,
	).CheckFeature(ctx, tx, entitlementguard.FeatureCheck{
		TargetScopeID: request.ConfigurationScopeID, ActorScopeID: request.Actor.ScopeID,
		ActorUserID: request.Actor.UserID, ResourceType: "edge_configuration_scope",
		ResourceID: request.ConfigurationScopeID, RequestID: request.ConfigurationScopeID.String(),
		Operation: "edge_publication.publish", Feature: entitlementguard.FeatureSitesManage,
	})
	if err != nil {
		return edgepublish.EntitlementDecision{}, err
	}
	return edgepublish.EntitlementDecision{
		Allowed: true, LocallyVerified: true, Status: edgepublish.EntitlementStatusValid,
		LeaseSerial: decision.LeaseSerial, EvaluatedAt: decision.EvaluatedAt,
	}, nil
}

type blockingAutomaticArtifactSigner struct {
	public  ed25519.PublicKey
	private ed25519.PrivateKey
	entered chan struct{}
	release chan struct{}
	calls   atomic.Int64
}

func newBlockingAutomaticArtifactSigner(t *testing.T) *blockingAutomaticArtifactSigner {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &blockingAutomaticArtifactSigner{
		public: publicKey, private: privateKey, entered: make(chan struct{}), release: make(chan struct{}),
	}
}

func (*blockingAutomaticArtifactSigner) KeyID() string { return "automatic-artifact-key" }

func (signer *blockingAutomaticArtifactSigner) PublicKey() ed25519.PublicKey {
	return append(ed25519.PublicKey(nil), signer.public...)
}

func (signer *blockingAutomaticArtifactSigner) Sign(_ context.Context, payload []byte) ([]byte, error) {
	if signer.calls.Add(1) == 1 {
		close(signer.entered)
	}
	<-signer.release
	return ed25519.Sign(signer.private, payload), nil
}

func (publisher *blockingPublisher) PublishAutomatic(
	context.Context,
	edgepublish.AutomaticClaimReference,
) (edgepublish.PublishResult, error) {
	if publisher.calls.Add(1) == 1 {
		close(publisher.entered)
	}
	<-publisher.release
	return edgepublish.PublishResult{}, edgepublish.ErrPersistence
}

func assertPlatformActorTargeting(t *testing.T, pool *pgxpool.Pool, service *site.Service, identity automaticIntegrationIdentity) {
	t.Helper()
	// 533: a platform operator creating a site allocates its CNAME, which
	// needs a live session of the operator.
	sessionID := uuid.New()
	digest := sha256.Sum256(sessionID[:])
	if _, err := pool.Exec(t.Context(), `INSERT INTO auth_sessions(id,family_id,user_id,scope_id,refresh_token_hash,
		created_at,expires_at) VALUES($1,$2,$3,$4,$5,clock_timestamp(),clock_timestamp()+interval '1 hour')`,
		sessionID, uuid.New(), identity.platformUser, identity.platformScope, digest[:]); err != nil {
		t.Fatal(err)
	}
	actor := site.Actor{UserID: identity.platformUser, ScopeID: identity.platformScope, ScopeKind: "platform",
		SessionID: sessionID}
	request := newSiteRequest("platform-target.example.test", "platform-target")
	request.TargetScopeID, request.OwnerUserID = identity.tenantScope, identity.tenantUser
	if _, err := service.Create(t.Context(), actor, request); err != nil {
		t.Fatalf("platform targeted create: %v", err)
	}
	var actorScope, targetScope uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT actor_scope_id,target_scope_id FROM edge_automatic_publication_requests
		WHERE operation='site.create' AND source_request_id='platform-target'`).Scan(&actorScope, &targetScope); err != nil {
		t.Fatal(err)
	}
	if actorScope != identity.platformScope || targetScope != identity.tenantScope {
		t.Fatalf("platform/target scopes=%s/%s", actorScope, targetScope)
	}
	var forged bool
	if err := pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM memberships WHERE scope_id=$1 AND user_id=$2)`,
		identity.tenantScope, identity.platformUser).Scan(&forged); err != nil || forged {
		t.Fatalf("forged tenant membership=%t err=%v", forged, err)
	}
}

func assertRBACRevocationRollsBack(t *testing.T, pool *pgxpool.Pool, service *site.Service, actor site.Actor, current site.Site) {
	t.Helper()
	before := requestCount(t, pool)
	if _, err := pool.Exec(t.Context(), `DELETE FROM role_assignments WHERE scope_id=$1 AND user_id=$2`, actor.ScopeID, actor.UserID); err != nil {
		t.Fatal(err)
	}
	fields := siteFields(current.Domain)
	fields.CNAME = "revoked.example.test"
	if _, err := service.Update(t.Context(), actor, site.UpdateRequest{
		ID: current.ID, ExpectedRevision: current.Revision, Fields: fields,
		IdempotencyKey: "rbac-revoked", RequestID: "rbac-revoked",
	}); err == nil {
		t.Fatal("revoked actor updated site")
	}
	var revision int64
	if err := pool.QueryRow(t.Context(), `SELECT revision FROM sites WHERE id=$1`, current.ID).Scan(&revision); err != nil || revision != current.Revision {
		t.Fatalf("revision=%d want=%d err=%v", revision, current.Revision, err)
	}
	if requestCount(t, pool) != before {
		t.Fatal("revoked mutation enqueued request")
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`,
		actor.ScopeID, actor.UserID, automaticTenantRole(t, pool, actor.ScopeID)); err != nil {
		t.Fatal(err)
	}
}

func assertEnqueueFailureRollsBackBusinessFact(t *testing.T, pool *pgxpool.Pool, service *site.Service, actor site.Actor) {
	t.Helper()
	_, err := pool.Exec(t.Context(), `CREATE FUNCTION fail_edge_auto_enqueue_test() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN RAISE EXCEPTION 'forced automatic enqueue failure'; END $$;
		CREATE TRIGGER fail_edge_auto_enqueue_test BEFORE INSERT ON edge_automatic_publication_requests
		FOR EACH ROW EXECUTE FUNCTION fail_edge_auto_enqueue_test()`)
	if err != nil {
		t.Fatal(err)
	}
	_, createErr := service.Create(t.Context(), actor, newSiteRequest("atomic-failure.example.test", "atomic-failure"))
	if createErr == nil {
		t.Fatal("site create succeeded despite enqueue failure")
	}
	if _, err := pool.Exec(t.Context(), `DROP TRIGGER fail_edge_auto_enqueue_test ON edge_automatic_publication_requests;
		DROP FUNCTION fail_edge_auto_enqueue_test()`); err != nil {
		t.Fatal(err)
	}
	var sites int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM sites WHERE domain='atomic-failure.example.test'`).Scan(&sites); err != nil || sites != 0 {
		t.Fatalf("rolled-back site count=%d err=%v", sites, err)
	}
}

func assertAutomaticAuditPayloads(t *testing.T, pool *pgxpool.Pool, scopeID uuid.UUID) {
	t.Helper()
	var invalid int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events
		WHERE scope_id=$1 AND (action LIKE 'site.%' OR action LIKE 'stream.%') AND result='success'
		  AND (payload->>'actor_scope_id' IS NULL OR payload->>'target_scope_id' IS DISTINCT FROM $1::text
		    OR payload->>'operation' IS DISTINCT FROM action OR COALESCE(payload->>'reason','')='')`, scopeID).Scan(&invalid); err != nil || invalid != 0 {
		t.Fatalf("invalid automatic audit payloads=%d err=%v", invalid, err)
	}
}

func newSiteRequest(domain, key string) site.CreateRequest {
	return site.CreateRequest{Fields: siteFields(domain), IdempotencyKey: key, RequestID: key}
}

func siteFields(domain string) site.SiteFields {
	return site.SiteFields{
		Domain: domain, HTTPPorts: []string{"80"}, Origins: []string{"192.0.2.86"},
		Enabled: true, Status: site.StatusActive,
	}
}

func newL4Request(binding automaticL4Binding, name string, port uint16, key string) l4forward.CreateRequest {
	return l4forward.CreateRequest{Fields: l4Fields(binding, name, port), IdempotencyKey: key, RequestID: key}
}

func l4Fields(binding automaticL4Binding, name string, port uint16) l4forward.Fields {
	return l4forward.Fields{
		PackageSubscriptionID: new(binding.subscriptionID),
		Name:                  name, Protocol: l4forward.ProtocolTCP, ListenAddress: "*", ListenPort: port,
		UpstreamAddress: "192.0.2.87", UpstreamPort: 8080, ConnectTimeoutMS: 1000,
		ResponseTimeoutMS: 30000, MaxConnectionsPerClient: 100, Enabled: true,
	}
}

// automaticL4Binding is the package subscription and owning site every stream
// requires (l4forward normalizeFields rejects a nil PackageSubscriptionID/SiteID
// and MaxConnectionsPerClient < 1).
type automaticL4Binding struct {
	subscriptionID, siteID uuid.UUID
}

func automaticL4CatalogAudit(platformScopeID, actorUserID uuid.UUID, action, resourceType string, resourceID uuid.UUID, payload string) struct {
	query string
	args  []any
} {
	return struct {
		query string
		args  []any
	}{`WITH previous AS (
		SELECT stream_position,event_hash FROM audit_events WHERE scope_id=$2 ORDER BY stream_position DESC LIMIT 1
	) INSERT INTO audit_events(id,scope_id,stream_position,actor_user_id,action,resource_type,resource_id,
		request_id,result,payload,previous_hash,event_hash,occurred_at)
	SELECT $1,$2,COALESCE(previous.stream_position,0)+1,$3,$4,$5,$6,$7,'success',$8::jsonb,previous.event_hash,$9,clock_timestamp()
	FROM (SELECT true) seed LEFT JOIN previous ON true`, []any{uuid.New(), platformScopeID, actorUserID, action, resourceType,
		resourceID.String(), "automatic-l4-catalog-" + uuid.NewString(), payload, make([]byte, sha256.Size)}}
}

func insertAutomaticL4Binding(t *testing.T, pool *pgxpool.Pool, identity automaticIntegrationIdentity) automaticL4Binding {
	t.Helper()
	binding := automaticL4Binding{subscriptionID: uuid.New(), siteID: uuid.New()}
	groupID, productID := uuid.New(), uuid.New()
	spec := `{"name":"automatic L4 product","description":"integration","group_ids":["` + groupID.String() + `"],` +
		`"region_id":"11111111-1111-4111-8111-111111111111","node_group_id":"22222222-2222-4222-8222-222222222222","backup_node_group_id":null,` +
		`"limits":{"monthly_traffic_bytes":1024,"bandwidth_bps":1024,"connections":100,"stream_ports":10,"domains":10,"root_domains":10,"http_ports":10,"custom_cc":false,"websocket":true,"http3":true,"l2_origin":false},` +
		`"protection":{"cc":"","ddos":""},"prices":{"currency":"CNY","monthly_minor":100,"quarterly_minor":270,"yearly_minor":1000},` +
		`"cname":{"hostname":"","domain":"cdn.example.com","mode":"per_site"},"purchase":{"per_user_limit":-1,"sale_expires_at":null,"require_real_name":false,"restrict_source_ips":false,"renew_before_days":-1},` +
		`"commercial_terms":{"timezone":"UTC","cycle_kind":"monthly","custom_cycle_days":0,"site_limit":10,"node_limit":10,"tcp_factor_numerator":1,"tcp_factor_denominator":1},"sort_order":1,"enabled":true}`
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		for _, statement := range []struct {
			query string
			args  []any
		}{
			{`INSERT INTO package_groups(id,name,visible,sort_order,revision,created_by_user_id,updated_by_user_id,created_at,updated_at)
				VALUES($1,$2,true,1,1,$3,$3,clock_timestamp(),clock_timestamp())`, []any{groupID, "automatic L4 " + groupID.String(), identity.platformUser}},
			automaticL4CatalogAudit(identity.platformScope, identity.platformUser, "package.group.create", "package_group", groupID, `{"revision":1,"visible":true}`),
			{`INSERT INTO package_products(id,name,enabled,sort_order,spec,revision,created_by_user_id,updated_by_user_id,created_at,updated_at)
				VALUES($1,$2,true,1,$3::jsonb,1,$4,$4,clock_timestamp(),clock_timestamp())`, []any{productID, "automatic L4 " + productID.String(), spec, identity.platformUser}},
			{`INSERT INTO package_product_versions(product_id,revision,name,enabled,sort_order,spec,deleted,created_by_user_id,created_at)
				VALUES($1,1,$2,true,1,$3::jsonb,false,$4,clock_timestamp())`, []any{productID, "automatic L4 " + productID.String(), spec, identity.platformUser}},
			automaticL4CatalogAudit(identity.platformScope, identity.platformUser, "package.product.create", "package_product", productID, `{"revision":1,"enabled":true}`),
			{`WITH moment AS (SELECT clock_timestamp() AS now)
				INSERT INTO package_subscriptions(id,tenant_scope_id,product_id,product_revision,product_snapshot,
				site_limit,domain_limit,node_limit,traffic_limit_bytes,starts_at,ends_at,timezone,cycle_kind,
				custom_cycle_days,tcp_factor_numerator,tcp_factor_denominator,lifecycle_status,revision,
				created_by_user_id,updated_by_user_id,created_at,updated_at)
				SELECT $1,$2,p.product_id,p.revision,jsonb_build_object('id',p.product_id::text,'revision',p.revision,'name',p.name,'spec',p.spec),
				10,10,10,-1,moment.now-interval '1 hour',moment.now+interval '1 day','UTC','monthly',0,1,1,'active',1,$3,$3,moment.now,moment.now
				FROM package_product_versions p CROSS JOIN moment WHERE p.product_id=$4 AND p.revision=1`,
				[]any{binding.subscriptionID, identity.tenantScope, identity.tenantUser, productID}},
			{`INSERT INTO package_subscription_entitlement_versions(
				subscription_id,revision,supersedes_subscription_id,supersedes_revision,
				tenant_scope_id,effective_at,effective_until,product_id,product_revision,product_snapshot,
				site_limit,domain_limit,node_limit,traffic_limit_bytes,timezone,cycle_kind,custom_cycle_days,
				tcp_factor_numerator,tcp_factor_denominator,package_period,period_price_minor,currency,
				entitlement_status,source_order_id,operation,created_by_user_id,created_at)
				SELECT subscription.id,1,NULL,NULL,subscription.tenant_scope_id,subscription.starts_at,NULL,
				subscription.product_id,subscription.product_revision,subscription.product_snapshot,
				subscription.site_limit,subscription.domain_limit,subscription.node_limit,subscription.traffic_limit_bytes,
				subscription.timezone,subscription.cycle_kind,subscription.custom_cycle_days,
				subscription.tcp_factor_numerator,subscription.tcp_factor_denominator,NULL,NULL,'CNY',
				'active',NULL,'migration_backfill',$2,clock_timestamp()
				FROM package_subscriptions AS subscription WHERE subscription.id=$1`, []any{binding.subscriptionID, identity.tenantUser}},
			{`WITH allocated AS (
				INSERT INTO site_display_id_sequences(scope_id,next_value,updated_at) VALUES($1,2,now())
				ON CONFLICT(scope_id) DO UPDATE SET next_value=site_display_id_sequences.next_value+1,updated_at=EXCLUDED.updated_at
				RETURNING next_value-1 AS display_id
			) INSERT INTO sites(id,display_id,scope_id,owner_user_id,domain,http_ports,origins,origin_hosts,created_by_user_id,updated_by_user_id)
				SELECT $2,allocated.display_id,$1,$3,$4,ARRAY['80'],ARRAY['192.0.2.10'],ARRAY['192.0.2.10'],$3,$3 FROM allocated`,
				[]any{identity.tenantScope, binding.siteID, identity.tenantUser, "l4-owner-" + binding.siteID.String() + ".example.test"}},
			{`INSERT INTO site_origin_pools(site_id) VALUES($1)`, []any{binding.siteID}},
			{`INSERT INTO site_origins(site_id,position,host,port) VALUES($1,1,'192.0.2.10',80)`, []any{binding.siteID}},
		} {
			if _, err := tx.Exec(t.Context(), statement.query, statement.args...); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("insert automatic L4 binding: %v", err)
	}
	return binding
}

func insertPolicy(t *testing.T, pool *pgxpool.Pool, identity automaticIntegrationIdentity, revision int64, mode string) {
	t.Helper()
	nodes := []uuid.UUID{uuid.New(), uuid.New()}
	if nodes[0].String() > nodes[1].String() {
		nodes[0], nodes[1] = nodes[1], nodes[0]
	}
	if mode == edgeautopublish.ModeManual {
		nodes = []uuid.UUID{}
	}
	_, err := pool.Exec(t.Context(), `INSERT INTO edge_automatic_publication_policy_facts(
		target_scope_id,revision,mode,node_ids,activation_timeout_ms,observation_window_ms,
		required_consecutive_successes,max_attempts,deadline_window_seconds,
		actor_scope_id,actor_user_id,reason,created_at
	) VALUES($1,$2,$3,$4,30000,15000,2,3,600,$1,$5,'integration_policy',clock_timestamp())`,
		identity.tenantScope, revision, mode, nodes, identity.tenantUser)
	if err != nil {
		t.Fatal(err)
	}
}

func insertPublishablePolicy(
	t *testing.T,
	pool *pgxpool.Pool,
	identity automaticIntegrationIdentity,
	revision int64,
) []uuid.UUID {
	t.Helper()
	nodes := []uuid.UUID{uuid.New(), uuid.New()}
	if nodes[0].String() > nodes[1].String() {
		nodes[0], nodes[1] = nodes[1], nodes[0]
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO edge_automatic_publication_policy_facts(
		target_scope_id,revision,mode,node_ids,activation_timeout_ms,observation_window_ms,
		required_consecutive_successes,max_attempts,deadline_window_seconds,
		actor_scope_id,actor_user_id,reason,created_at
	) VALUES($1,$2,'automatic',$3,30000,15000,2,3,600,$1,$4,'publishable_policy',clock_timestamp())`,
		identity.tenantScope, revision, nodes, identity.tenantUser); err != nil {
		t.Fatal(err)
	}
	for _, nodeID := range nodes {
		insertAutomaticNode(t, pool, identity, nodeID, "automatic")
	}
	return nodes
}

func insertExpiringPublishablePolicy(
	t *testing.T,
	pool *pgxpool.Pool,
	identity automaticIntegrationIdentity,
	revision int64,
	deadline time.Duration,
) []uuid.UUID {
	t.Helper()
	nodes := []uuid.UUID{uuid.New(), uuid.New()}
	if nodes[0].String() > nodes[1].String() {
		nodes[0], nodes[1] = nodes[1], nodes[0]
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO edge_automatic_publication_policy_facts(
		target_scope_id,revision,mode,node_ids,activation_timeout_ms,observation_window_ms,
		required_consecutive_successes,max_attempts,deadline_window_seconds,
		actor_scope_id,actor_user_id,reason,created_at
	) VALUES($1,$2,'automatic',$3,30000,15000,2,3,$4,$1,$5,'expiring_policy',clock_timestamp())`,
		identity.tenantScope, revision, nodes, int64(deadline/time.Second), identity.tenantUser); err != nil {
		t.Fatal(err)
	}
	for _, nodeID := range nodes {
		insertAutomaticNode(t, pool, identity, nodeID, "expiring")
	}
	return nodes
}

// insertAutomaticNode adds an active node of the tenant scope enrolled as a
// 1.0.35 agent: automatic publications use the default site runtime (v2),
// which needs the node's issued identity and capabilities.
func insertAutomaticNode(t *testing.T, pool *pgxpool.Pool, identity automaticIntegrationIdentity, nodeID uuid.UUID, prefix string) {
	t.Helper()
	// nodes.display_id 为 NOT NULL，按节点存储的做法从本 scope 的序列取号。
	if _, err := pool.Exec(t.Context(), `WITH allocated AS (
		INSERT INTO node_display_id_sequences(scope_id,next_value,updated_at) VALUES($2,2,clock_timestamp())
		ON CONFLICT(scope_id) DO UPDATE SET next_value=node_display_id_sequences.next_value+1,
			updated_at=EXCLUDED.updated_at
		RETURNING next_value-1 AS display_id)
		INSERT INTO nodes(id,display_id,scope_id,name,admin_state,created_by_user_id,created_at,updated_at)
		SELECT $1,allocated.display_id,$2,$3,'active',$4,$5,$5 FROM allocated`, nodeID, identity.tenantScope,
		prefix+"-node-"+strings.ReplaceAll(nodeID.String(), "-", "")[:12], identity.tenantUser,
		automaticIntegrationNow.Add(-20*time.Minute)); err != nil {
		t.Fatal(err)
	}
	capabilitytest.SeedNodePublicationIdentityForTest(t, pool, identity.tenantScope, identity.tenantUser, nodeID,
		&agentv1.AgentCapabilities{AgentVersion: "1.0.35", BuildId: "automatic-publication", OperatingSystem: "linux",
			Architecture: "amd64", Features: automaticNodeFeatures()}, automaticIntegrationNow.Add(-10*time.Minute), true)
}

// automaticNodeFeatures is what a 1.0.35 edge agent declares.
func automaticNodeFeatures() []*agentv1.Capability {
	features := []*agentv1.Capability{}
	for name, version := range map[agentv1.CapabilityName]uint32{
		agentv1.CapabilityName_CAPABILITY_NAME_HTTP_1_1: 1, agentv1.CapabilityName_CAPABILITY_NAME_HTTP_2: 1,
		agentv1.CapabilityName_CAPABILITY_NAME_SITE_QUIC: 1, agentv1.CapabilityName_CAPABILITY_NAME_WEBSOCKET: 1,
		agentv1.CapabilityName_CAPABILITY_NAME_IPV4: 1, agentv1.CapabilityName_CAPABILITY_NAME_IPV6: 1,
		agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME: edgeconfig.MaxSiteRuntimeVersion,
		// 1.0.35 L4 forwards belong to no website: tcp/udp v12, and a forward
		// on a package needs the node to attribute its traffic (7eb99f04d).
		agentv1.CapabilityName_CAPABILITY_NAME_TCP_PROXY: 12, agentv1.CapabilityName_CAPABILITY_NAME_UDP_PROXY: 12,
		agentv1.CapabilityName_CAPABILITY_NAME_L4_PACKAGE_ATTRIBUTION: edgeconfig.L4PackageAttributionAPIVersion,
		agentv1.CapabilityName_CAPABILITY_NAME_PROXY_PROTOCOL:         1, agentv1.CapabilityName_CAPABILITY_NAME_CC: 4,
		agentv1.CapabilityName_CAPABILITY_NAME_WAF: 1, agentv1.CapabilityName_CAPABILITY_NAME_ATOMIC_RELEASE: 1,
		agentv1.CapabilityName_CAPABILITY_NAME_CONFIG_PRECHECK: 1,
	} {
		features = append(features, &agentv1.Capability{Name: name, ApiVersion: version})
	}
	return features
}

func prepareAutomaticReference(
	t *testing.T,
	domain string,
	leaseDuration time.Duration,
) (*pgxpool.Pool, automaticIntegrationIdentity, *edgeautopublish.Store, edgepublish.AutomaticClaimReference) {
	t.Helper()
	pool := openAutomaticDatabase(t)
	identity := seedAutomaticIntegrationIdentity(t, pool)
	trust := installAutomaticSiteEntitlement(t, pool)
	service := site.NewService(site.NewStoreWithClock(pool, func() time.Time { return automaticIntegrationNow }, trust))
	insertPolicy(t, pool, identity, 1, edgeautopublish.ModeAutomatic)
	actor := site.Actor{UserID: identity.tenantUser, ScopeID: identity.tenantScope, ScopeKind: "tenant"}
	if _, err := service.Create(t.Context(), actor, newSiteRequest(domain, "prepare-"+uuid.NewString())); err != nil {
		t.Fatal(err)
	}
	repository := edgeautopublish.NewStore(pool)
	reference, found, err := repository.ClaimAutomaticPublication(t.Context(), "prepare-worker", leaseDuration)
	if err != nil || !found {
		t.Fatalf("ClaimAutomaticPublication() = %+v, %t, %v", reference, found, err)
	}
	return pool, identity, repository, reference
}

func assertLatestOperation(t *testing.T, pool *pgxpool.Pool, want string) {
	t.Helper()
	var operation string
	var sourceRevision, currentRevision int64
	if err := pool.QueryRow(t.Context(), `SELECT operation,source_revision FROM edge_automatic_publication_requests
		ORDER BY created_at DESC,id DESC LIMIT 1`).Scan(&operation, &sourceRevision); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(t.Context(), `SELECT max(source_revision) FROM edge_configuration_scopes`).Scan(&currentRevision); err != nil {
		t.Fatal(err)
	}
	if operation != want || sourceRevision != currentRevision || sourceRevision < 1 {
		t.Fatalf("latest operation/revision=%s/%d current=%d want=%s", operation, sourceRevision, currentRevision, want)
	}
}

func assertRequestCount(t *testing.T, pool *pgxpool.Pool, want int) {
	t.Helper()
	if got := requestCount(t, pool); got != want {
		t.Fatalf("request count=%d want=%d", got, want)
	}
}

func requestCount(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()
	var count int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM edge_automatic_publication_requests`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func automaticTenantRole(t *testing.T, pool *pgxpool.Pool, scopeID uuid.UUID) uuid.UUID {
	t.Helper()
	var roleID uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT id FROM roles WHERE scope_id=$1 AND name='tenant_owner'`, scopeID).Scan(&roleID); err != nil {
		t.Fatal(err)
	}
	return roleID
}

func seedAutomaticIntegrationIdentity(t *testing.T, pool *pgxpool.Pool) automaticIntegrationIdentity {
	t.Helper()
	identity := automaticIntegrationIdentity{
		tenantScope: uuid.New(), tenantUser: uuid.New(), tenantRole: uuid.New(),
		platformScope: uuid.New(), platformUser: uuid.New(), platformRole: uuid.New(),
	}
	tenantID := uuid.New()
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		statements := []struct {
			query string
			args  []any
		}{
			{`INSERT INTO tenants(id,display_name) VALUES($1,'automatic integration')`, []any{tenantID}},
			{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2),($3,'platform',NULL)`, []any{identity.tenantScope, tenantID, identity.platformScope}},
			{`INSERT INTO users(id,username,display_name,password_hash) VALUES
				($1,$2,'tenant actor','hash'),($3,$4,'platform actor','hash')`, []any{
				identity.tenantUser, "automatic-tenant-" + identity.tenantUser.String(),
				identity.platformUser, "automatic-platform-" + identity.platformUser.String(),
			}},
			{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2),($3,$4)`, []any{identity.tenantScope, identity.tenantUser, identity.platformScope, identity.platformUser}},
			{`INSERT INTO roles(id,scope_id,name,system_role) VALUES
				($1,$2,'tenant_owner',true),($3,$4,'platform_owner',true)`, []any{identity.tenantRole, identity.tenantScope, identity.platformRole, identity.platformScope}},
			{`INSERT INTO role_permissions(role_id,permission_name) VALUES
				($1,'sites.manage'),($1,'streams.manage'),($2,'platform.admin') ON CONFLICT DO NOTHING`, []any{identity.tenantRole, identity.platformRole}},
			{`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3),($4,$5,$6)`, []any{identity.tenantScope, identity.tenantUser, identity.tenantRole, identity.platformScope, identity.platformUser, identity.platformRole}},
		}
		for _, statement := range statements {
			if _, err := tx.Exec(t.Context(), statement.query, statement.args...); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

type automaticEntitlementSigner struct {
	id      string
	public  ed25519.PublicKey
	private ed25519.PrivateKey
}

type automaticSiteEntitlementFixture struct {
	trust      *entitlementguard.TrustStore
	signer     automaticEntitlementSigner
	keyWindow  entitlement.RevocationKeyWindow
	customerID string
	installID  string
	licenseID  string
}

func (signer automaticEntitlementSigner) KeyID() string { return signer.id }
func (signer automaticEntitlementSigner) PublicKey() ed25519.PublicKey {
	return append(ed25519.PublicKey(nil), signer.public...)
}
func (signer automaticEntitlementSigner) Sign(_ context.Context, payload []byte) ([]byte, error) {
	return ed25519.Sign(signer.private, payload), nil
}

func installAutomaticSiteEntitlement(t *testing.T, pool *pgxpool.Pool) *entitlementguard.TrustStore {
	t.Helper()
	return installAutomaticSiteEntitlementFixture(t, pool).trust
}

func installAutomaticSiteEntitlementFixture(
	t *testing.T,
	pool *pgxpool.Pool,
) automaticSiteEntitlementFixture {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer := automaticEntitlementSigner{id: "automatic-entitlement-key", public: publicKey, private: privateKey}
	verifyUntil := automaticIntegrationNow.Add(24 * time.Hour)
	notBefore := automaticIntegrationNow.Add(-time.Hour)
	trust, err := entitlementguard.NewTrustStore([]entitlementguard.VerificationKey{{
		KeyID: signer.id, PublicKey: signer.public, NotBefore: notBefore,
		SignUntil: &verifyUntil, VerifyUntil: &verifyUntil,
	}})
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := sha256.Sum256(signer.public)
	payload := []byte(fmt.Sprintf(`{"schema":"cdnca.signing-keyset/v2","active_key_id":%q,"keys":[{"key_id":%q,"algorithm":"Ed25519","public_key":%q,"fingerprint":%q,"status":"active","not_before":%q,"sign_until":%q,"verify_until":%q}],"rotations":[]}`,
		signer.id, signer.id, base64.RawURLEncoding.EncodeToString(signer.public),
		base64.RawURLEncoding.EncodeToString(fingerprint[:]), notBefore.Format(time.RFC3339Nano),
		verifyUntil.Format(time.RFC3339Nano), verifyUntil.Format(time.RFC3339Nano)))
	payloadDigest := sha256.Sum256(payload)
	if _, err := pool.Exec(t.Context(), `INSERT INTO entitlement_signing_keyset_lkg(
		singleton,schema_version,etag,active_key_id,chain_depth,payload,payload_sha256,accepted_at,updated_at
	) VALUES(true,'cdnca.signing-keyset/v2',$1,$2,1,$3,$4,$5,$5)`,
		`"`+base64.RawURLEncoding.EncodeToString(payloadDigest[:])+`"`, signer.id, payload, payloadDigest[:], automaticIntegrationNow); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO entitlement_signing_keyset_current_keys(
		key_id,public_key,status,not_before,sign_until,verify_until,keyset_payload_sha256,accepted_at
	) VALUES($1,$2,'active',$3,$4,$4,$5,$6)`, signer.id, signer.public, notBefore,
		verifyUntil, payloadDigest[:], automaticIntegrationNow); err != nil {
		t.Fatal(err)
	}
	const customerID = "11111111-1111-4111-8111-111111111111"
	const installationID = "22222222-2222-4222-8222-222222222222"
	const licenseID = "33333333-3333-4333-8333-333333333333"
	issuedAt := automaticIntegrationNow.Add(-time.Minute)
	revocation, err := entitlement.SignRevocationSet(t.Context(), entitlement.RevocationSet{
		Schema: entitlement.RevocationSetSchemaV2, Audience: entitlement.RevocationSetAudience,
		CustomerID: customerID, InstallationID: installationID, LicenseID: licenseID,
		Revision: 1, IssuedAt: issuedAt.Unix(), ExpiresAt: issuedAt.Add(entitlement.RevocationSetWindow).Unix(),
		RevokedSerials: []uint64{},
	}, signer, entitlement.RevocationKeyWindow{NotBefore: notBefore, SignUntil: &verifyUntil, VerifyUntil: &verifyUntil})
	if err != nil {
		t.Fatal(err)
	}
	revocationBytes, err := revocation.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entitlementguard.NewRevocationService(pool, trust).Accept(t.Context(), revocationBytes, automaticIntegrationNow); err != nil {
		t.Fatal(err)
	}
	lease := entitlement.Lease{
		Schema: entitlement.SchemaV1, Audience: entitlement.ControlAudience,
		CustomerID: customerID, InstallationID: installationID, LicenseID: licenseID, Serial: 1,
		NotBefore: notBefore.Unix(), ExpiresAt: automaticIntegrationNow.Add(time.Hour).Unix(),
		GraceUntil: automaticIntegrationNow.Add(2 * time.Hour).Unix(),
		Version:    entitlement.VersionRange{Channel: "stable", Min: "0.1.0", Max: "1.0.0"},
		Features:   []entitlement.Feature{{Code: entitlementguard.FeatureSitesManage}},
		Quotas:     []entitlement.Quota{{Code: entitlementguard.QuotaDomainsCount, Limit: 100}},
	}
	signed, err := entitlement.Sign(t.Context(), lease, signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entitlementguard.NewService(pool, trust).Install(t.Context(), entitlementguard.InstallBundle{
		InstallationID: installationID, SignedLease: signed,
	}, automaticIntegrationNow); err != nil {
		t.Fatal(err)
	}
	return automaticSiteEntitlementFixture{
		trust: trust, signer: signer,
		keyWindow: entitlement.RevocationKeyWindow{
			NotBefore: notBefore, SignUntil: &verifyUntil, VerifyUntil: &verifyUntil,
		},
		customerID: customerID, installID: installationID, licenseID: licenseID,
	}
}

func revokeAutomaticSiteEntitlement(
	t *testing.T,
	pool *pgxpool.Pool,
	fixture automaticSiteEntitlementFixture,
) {
	t.Helper()
	issuedAt := automaticIntegrationNow.Add(-30 * time.Second)
	revocation, err := entitlement.SignRevocationSet(t.Context(), entitlement.RevocationSet{
		Schema: entitlement.RevocationSetSchemaV2, Audience: entitlement.RevocationSetAudience,
		CustomerID: fixture.customerID, InstallationID: fixture.installID, LicenseID: fixture.licenseID,
		Revision: 2, IssuedAt: issuedAt.Unix(), ExpiresAt: issuedAt.Add(entitlement.RevocationSetWindow).Unix(),
		RevokedSerials: []uint64{1},
	}, fixture.signer, fixture.keyWindow)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := revocation.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entitlementguard.NewRevocationService(pool, fixture.trust).Accept(
		t.Context(), artifact, automaticIntegrationNow,
	); err != nil {
		t.Fatal(err)
	}
}

func automaticPublicationActor(t *testing.T) edgepublish.Actor {
	t.Helper()
	actor, err := edgepublish.NewSessionActor(uuid.New(), uuid.New(), edgepublish.ScopeKindPlatform,
		uuid.New(), "automatic-publication-integration-session")
	if err != nil {
		t.Fatal(err)
	}
	return actor
}

func openAutomaticDatabase(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "edge_auto_086_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^edge_auto_086_test_[a-f0-9]{32}$`).MatchString(schema) {
		admin.Close()
		t.Fatalf("unsafe schema %q", schema)
	}
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		cleanupCtx, cleanupCancel := databasetest.CleanupContext()
		defer cleanupCancel()
		if _, err := admin.Exec(cleanupCtx, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop automatic publication schema: %v", err)
		}
		admin.Close()
	})
	if err := database.Migrate(ctx, pool, "up"); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	return pool
}

// adm-fix-a (73, 10-25): automatic publications create non-v2 rollouts, whose
// rollouts.status never leaves queued; the reconciler must finish a request
// once its deployments are all healthy. Before the fix every request stayed
// reconciling forever (the CRS republication banner never cleared).
func TestReconcileFinishesQueuedNonV2Rollout(t *testing.T) {
	pool := openAutomaticDatabase(t)
	identity := seedAutomaticIntegrationIdentity(t, pool)
	installAutomaticSiteEntitlement(t, pool)
	insertPublishablePolicy(t, pool, identity, 1)
	l4Service := l4forward.NewService(l4forward.NewStoreWithClock(pool, func() time.Time { return automaticIntegrationNow }))
	actor := l4forward.Actor{UserID: identity.tenantUser, ScopeID: identity.tenantScope, ScopeKind: "tenant"}
	binding := insertAutomaticL4Binding(t, pool, identity)
	repository := edgeautopublish.NewStore(pool)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	deployments, err := edgedeployment.NewStoreWithClock(pool, func() time.Time { return automaticIntegrationNow })
	if err != nil {
		t.Fatal(err)
	}
	config := edgepublish.DefaultConfig()
	config.Clock = func() time.Time { panic("automatic publication used application clock") }
	config.EntitlementAuthorizer = automaticAllowAuthorizer{}
	publisher, err := edgepublish.NewAutomaticService(pool, deployments, automaticEntitlementSigner{
		id: "reconcile-v1-artifact", public: publicKey, private: privateKey,
	}, config, repository)
	if err != nil {
		t.Fatal(err)
	}
	worker, err := edgeautopublish.NewWorker(repository, publisher, edgeautopublish.WorkerConfig{
		WorkerID: "reconcile-v1-worker", LeaseDuration: time.Minute, RetryDelay: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	rolloutOf := func(requestID uuid.UUID) (uuid.UUID, int16, string) {
		var rolloutID uuid.UUID
		var contractVersion int16
		var status string
		if err := pool.QueryRow(t.Context(), `SELECT rollout.id,rollout.contract_version,rollout.status
			FROM edge_automatic_publication_request_state_facts fact JOIN rollouts rollout ON rollout.id=fact.rollout_id
			WHERE fact.request_id=$1 AND fact.state='reconciling'`, requestID).Scan(&rolloutID, &contractVersion, &status); err != nil {
			t.Fatal(err)
		}
		return rolloutID, contractVersion, status
	}
	// advance walks a rollout's deployments along the agent status chain,
	// each step with its matching status event (348/477 guards).
	advance := func(rolloutID uuid.UUID, target string) {
		rows, err := pool.Query(t.Context(), `SELECT id,attempt FROM node_deployments WHERE rollout_id=$1`, rolloutID)
		if err != nil {
			t.Fatal(err)
		}
		type deployment struct {
			id      uuid.UUID
			attempt int
		}
		items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (deployment, error) {
			var item deployment
			return item, row.Scan(&item.id, &item.attempt)
		})
		if err != nil {
			t.Fatal(err)
		}
		for _, item := range items {
			for index, state := range []string{"delivered", "staged", "prechecked", "activated", "healthy"} {
				payload := []byte("reconcile-v1-status-" + state)
				digest := sha256.Sum256(payload)
				if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
					if _, err := tx.Exec(t.Context(), `INSERT INTO deployment_status_events(
						id,deployment_id,event_id,attempt,transition_sequence,state,payload,payload_sha256,occurred_at,received_at)
						SELECT $1,$2,$3,$4,$5,$6,$7,$8,
						  GREATEST(deployment.created_at,deployment.updated_at)+interval '1 millisecond',
						  GREATEST(deployment.created_at,deployment.updated_at)+interval '1 millisecond'
						FROM node_deployments deployment WHERE deployment.id=$2 AND deployment.attempt=$4`,
						uuid.New(), item.id, uuid.New(), item.attempt, index+1, state, payload, digest[:]); err != nil {
						return err
					}
					_, err := tx.Exec(t.Context(), `UPDATE node_deployments SET state=$3,
						updated_at=GREATEST(created_at,updated_at)+interval '1 millisecond' WHERE id=$1 AND attempt=$2`,
						item.id, item.attempt, state)
					return err
				}); err != nil {
					t.Fatalf("advance %s to %s: %v", item.id, state, err)
				}
				if state == target {
					break
				}
			}
		}
	}
	requests := make([]uuid.UUID, 0, 2)
	for index, name := range []string{"reconcile-v1-first", "reconcile-v1-second"} {
		if _, err := l4Service.Create(t.Context(), actor, newL4Request(binding, name, uint16(18101+index), name)); err != nil {
			t.Fatal(err)
		}
		if worked, err := worker.RunOnce(t.Context()); err != nil || !worked {
			t.Fatalf("%s RunOnce() = %t, %v", name, worked, err)
		}
		var requestID uuid.UUID
		if err := pool.QueryRow(t.Context(), `SELECT request_id FROM edge_automatic_publication_request_state_facts
			WHERE state='reconciling' AND request_id <> ALL($1) ORDER BY occurred_at DESC LIMIT 1`, requests).
			Scan(&requestID); err != nil {
			t.Fatalf("%s reconciling request: %v", name, err)
		}
		requests = append(requests, requestID)
		// A node takes the next publication once the previous one landed.
		rollout, _, _ := rolloutOf(requestID)
		advance(rollout, "healthy")
	}
	_, contractVersion, status := rolloutOf(requests[1])
	if contractVersion == 2 || status != "queued" {
		t.Fatalf("automatic rollout contract/status=%d/%s, want non-v2 queued", contractVersion, status)
	}
	for range requests {
		if worked, err := repository.ReconcileOne(t.Context()); err != nil || !worked {
			t.Fatalf("ReconcileOne() = %t, %v, want a healthy request settled", worked, err)
		}
	}
	latest := func(requestID uuid.UUID) (string, string) {
		var state string
		var code *string
		if err := pool.QueryRow(t.Context(), `SELECT state,terminal_code FROM edge_automatic_publication_request_state_facts
			WHERE request_id=$1 ORDER BY sequence DESC LIMIT 1`, requestID).Scan(&state, &code); err != nil {
			t.Fatal(err)
		}
		if code == nil {
			return state, ""
		}
		return state, *code
	}
	for _, requestID := range requests {
		if state, code := latest(requestID); state != edgeautopublish.StateSucceeded || code != edgeautopublish.SuccessApplyHealthy {
			t.Fatalf("request %s state/code=%s/%s, want succeeded/%s", requestID, state, code, edgeautopublish.SuccessApplyHealthy)
		}
	}
	// Nothing is left reconciling: a further pass does no work.
	if worked, err := repository.ReconcileOne(t.Context()); err != nil || worked {
		t.Fatalf("second ReconcileOne() = %t, %v, want no work", worked, err)
	}
}
