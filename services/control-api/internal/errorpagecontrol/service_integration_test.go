package errorpagecontrol

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestErrorPageControlPostgreSQL(t *testing.T) {
	fixture := openErrorPageDatabase(t)
	identities := seedErrorPageIdentities(t, fixture.pool)
	store := newMemoryContentStore()
	scanner := &testScanner{name: "test-scanner"}
	clock := &testClock{now: time.Date(2026, 7, 23, 8, 0, 0, 0, time.UTC)}
	limits := staticLimits{quota: AssetQuota{MaxAssetBytes: MaxEdgeResourceBytes, MaxAssets: 1000, MaxTotalBytes: 8 << 20}}
	service, err := NewServiceWithDependencies(fixture.pool, store, scanner, limits, audit.New(fixture.pool), clock.Now, testTxAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("RBAC tenant isolation and site ownership", func(t *testing.T) {
		asset := initiateAsset(t, service, identities.tenantOwner, identities.tenantScope, "rbac", []byte("safe"), "text/plain")
		if _, err := service.InitiateAsset(t.Context(), identities.tenantViewer, initiateRequest(
			identities.tenantScope, "viewer", []byte("viewer"), "text/plain")); !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("viewer write error=%v", err)
		}
		if _, err := service.InitiateAsset(t.Context(), identities.tenantOwner, initiateRequest(
			identities.otherTenantScope, "other", []byte("other"), "text/plain")); !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("cross-tenant write error=%v", err)
		}
		if _, err := service.GetAsset(t.Context(), identities.otherTenantOwner, asset.ID); !errors.Is(err, ErrNotFound) {
			t.Fatalf("cross-tenant get error=%v", err)
		}
		if _, err := service.GetAsset(t.Context(), identities.tenantViewer, asset.ID); err != nil {
			t.Fatalf("viewer read: %v", err)
		}
		var otherSiteID uuid.UUID
		if err := fixture.pool.QueryRow(t.Context(), `SELECT id FROM sites WHERE scope_id=$1`,
			identities.otherTenantScope).Scan(&otherSiteID); err != nil {
			t.Fatal(err)
		}
		if _, err := service.CreateRule(t.Context(), identities.tenantOwner, CreateRuleRequest{
			Target: RuleTarget{Kind: ScopeSite, ScopeID: identities.tenantScope, SiteID: &otherSiteID},
			Fields: RuleFields{
				Category: CategoryEdgeRoute, Match: StatusSelector{Kind: MatchExact, From: 404},
				AssetID: asset.ID, Enabled: false,
			},
			WriteMetadata: writeMetadata("foreign-site"),
		}); !errors.Is(err, ErrNotFound) {
			t.Fatalf("foreign site error=%v", err)
		}
	})

	t.Run("upload validation scanner allow reject timeout and replay", func(t *testing.T) {
		body := []byte(`<!doctype html><html><body><h1>Unavailable</h1></body></html>`)
		asset := initiateAsset(t, service, identities.tenantOwner, identities.tenantScope, "scan-pass", body, "text/html")
		upload := uploadRequest(asset.ID, "upload-pass", body, "text/html")
		first, err := service.UploadAsset(t.Context(), identities.tenantOwner, upload)
		if err != nil || first.Value.Status != StatusStaged || first.Replayed {
			t.Fatalf("first upload=%#v err=%v", first, err)
		}
		second, err := service.UploadAsset(t.Context(), identities.tenantOwner, uploadRequest(asset.ID, "upload-pass", body, "text/html"))
		if err != nil || !second.Replayed {
			t.Fatalf("replayed upload=%#v err=%v", second, err)
		}
		changed := uploadRequest(asset.ID, "upload-pass", append(body, '!'), "text/html")
		if _, err := service.UploadAsset(t.Context(), identities.tenantOwner, changed); !errors.Is(err, ErrIdempotencyConflict) {
			t.Fatalf("changed upload error=%v", err)
		}
		finalized, err := service.FinalizeAsset(t.Context(), identities.tenantOwner, finalizeRequest(asset.ID, "finalize-pass"))
		if err != nil || finalized.Value.Status != StatusReady || finalized.Value.ScanStatus != "passed" {
			t.Fatalf("finalize=%#v err=%v", finalized, err)
		}
		replayed, err := service.FinalizeAsset(t.Context(), identities.tenantOwner, finalizeRequest(asset.ID, "finalize-pass"))
		if err != nil || !replayed.Replayed {
			t.Fatalf("finalize replay=%#v err=%v", replayed, err)
		}

		rejectedBody := []byte("scanner rejects this")
		rejectedAsset := initiateAsset(t, service, identities.tenantOwner, identities.tenantScope, "scan-reject", rejectedBody, "text/plain")
		mustUpload(t, service, identities.tenantOwner, rejectedAsset, "reject-upload", rejectedBody)
		rejectScanner := &testScanner{name: "reject-scanner", err: ErrScanRejected}
		rejectService, _ := NewServiceWithDependencies(fixture.pool, store, rejectScanner, limits, audit.New(fixture.pool), clock.Now, testTxAuthorizer{})
		if _, err := rejectService.FinalizeAsset(t.Context(), identities.tenantOwner,
			finalizeRequest(rejectedAsset.ID, "reject-finalize")); !errors.Is(err, ErrScanRejected) {
			t.Fatalf("reject finalize error=%v", err)
		}
		rejected, _ := service.GetAsset(t.Context(), identities.tenantOwner, rejectedAsset.ID)
		if rejected.Status != StatusRejected || rejected.ScanStatus != "rejected" {
			t.Fatalf("rejected asset=%#v", rejected)
		}

		timeoutBody := []byte("scanner times out")
		timeoutAsset := initiateAsset(t, service, identities.tenantOwner, identities.tenantScope, "scan-timeout", timeoutBody, "text/plain")
		mustUpload(t, service, identities.tenantOwner, timeoutAsset, "timeout-upload", timeoutBody)
		timeoutScanner := &testScanner{name: "timeout-scanner", err: context.DeadlineExceeded}
		timeoutService, _ := NewServiceWithDependencies(fixture.pool, store, timeoutScanner, limits, audit.New(fixture.pool), clock.Now, testTxAuthorizer{})
		if _, err := timeoutService.FinalizeAsset(t.Context(), identities.tenantOwner,
			finalizeRequest(timeoutAsset.ID, "timeout-finalize")); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("timeout finalize error=%v", err)
		}
		timedOut, _ := service.GetAsset(t.Context(), identities.tenantOwner, timeoutAsset.ID)
		if timedOut.Status != StatusScanFailed || timedOut.ScanStatus != "error" {
			t.Fatalf("timed out asset=%#v", timedOut)
		}
	})

	t.Run("staging and finalize crash windows reconcile", func(t *testing.T) {
		body := []byte("recover upload")
		asset := initiateAsset(t, service, identities.tenantOwner, identities.tenantScope, "recover-upload", body, "text/plain")
		if _, err := store.PutStaging(t.Context(), assetObjectRef(asset, asset.stagingObjectKey), body, asset.MIMEType); err != nil {
			t.Fatal(err)
		}
		count, err := service.ReconcileAssets(t.Context(), 100)
		if err != nil || count < 1 {
			t.Fatalf("staging reconcile count=%d err=%v", count, err)
		}
		recovered, _ := service.GetAsset(t.Context(), identities.tenantOwner, asset.ID)
		if recovered.Status != StatusStaged {
			t.Fatalf("recovered status=%s", recovered.Status)
		}

		stagedInfo, err := store.Stat(t.Context(), assetObjectRef(asset, asset.stagingObjectKey))
		if err != nil {
			t.Fatal(err)
		}
		if err := service.recordScan(t.Context(), identities.tenantOwner, writeMetadata("recover-scan"),
			asset.ID, "passed", "", StatusFinalizing, stagedInfo.ImmutableToken); err != nil {
			t.Fatal(err)
		}
		finalizing, _ := service.GetAsset(t.Context(), identities.tenantOwner, asset.ID)
		stagedInfo, err = store.Stat(t.Context(), assetObjectRef(finalizing, finalizing.stagingObjectKey))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.Finalize(t.Context(), assetObjectRef(finalizing, finalizing.stagingObjectKey),
			assetObjectRef(finalizing, finalizing.storageObjectKey), stagedInfo); err != nil {
			t.Fatal(err)
		}
		count, err = service.ReconcileAssets(t.Context(), 100)
		if err != nil || count < 1 {
			t.Fatalf("finalize reconcile count=%d err=%v", count, err)
		}
		ready, _ := service.GetAsset(t.Context(), identities.tenantOwner, asset.ID)
		if ready.Status != StatusReady {
			t.Fatalf("ready status=%s", ready.Status)
		}
		deleted, err := service.DeleteAsset(t.Context(), identities.tenantOwner, DeleteAssetRequest{
			AssetID: ready.ID, ExpectedRevision: ready.Revision, WriteMetadata: writeMetadata("recover-delete"),
		})
		if err != nil || deleted.Value.Status != StatusDeletePending {
			t.Fatalf("delete=%#v err=%v", deleted, err)
		}
		if _, err := service.ReconcileAssets(t.Context(), 100); err != nil {
			t.Fatal(err)
		}
		deletedAsset, _ := service.GetAsset(t.Context(), identities.tenantOwner, asset.ID)
		if deletedAsset.Status != StatusDeleted || store.exists(ready.storageObjectKey) {
			t.Fatalf("deleted asset=%#v object_exists=%t", deletedAsset, store.exists(ready.storageObjectKey))
		}
	})

	t.Run("cancellation and object storage failure stay fail closed", func(t *testing.T) {
		body := []byte("storage unavailable")
		asset := initiateAsset(t, service, identities.tenantOwner, identities.tenantScope, "store-failure", body, "text/plain")
		store.setStatError(errors.New("backend unavailable"))
		if _, err := service.UploadAsset(t.Context(), identities.tenantOwner,
			uploadRequest(asset.ID, "store-failure-upload", body, "text/plain")); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("storage failure error=%v", err)
		}
		store.setStatError(nil)

		cancelBody := []byte("cancel scan")
		cancelAsset := initiateAsset(t, service, identities.tenantOwner, identities.tenantScope, "cancel-scan", cancelBody, "text/plain")
		mustUpload(t, service, identities.tenantOwner, cancelAsset, "cancel-upload", cancelBody)
		cancelScanner := &testScanner{name: "cancel-scanner", waitForCancel: true}
		cancelService, _ := NewServiceWithDependencies(fixture.pool, store, cancelScanner, limits, audit.New(fixture.pool), clock.Now, testTxAuthorizer{})
		ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
		defer cancel()
		if _, err := cancelService.FinalizeAsset(ctx, identities.tenantOwner,
			finalizeRequest(cancelAsset.ID, "cancel-finalize")); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("cancelled scan error=%v", err)
		}
		cancelled, err := service.GetAsset(t.Context(), identities.tenantOwner, cancelAsset.ID)
		if err != nil || cancelled.Status != StatusScanFailed {
			t.Fatalf("cancelled asset=%#v err=%v", cancelled, err)
		}
	})

	t.Run("asset pagination uses a stable cursor", func(t *testing.T) {
		page1, err := service.ListAssets(t.Context(), identities.tenantOwner, AssetPageRequest{
			TargetScopeID: identities.tenantScope, Limit: 1,
		})
		if err != nil || len(page1.Items) != 1 || page1.NextCursor == "" {
			t.Fatalf("asset page1=%#v err=%v", page1, err)
		}
		page2, err := service.ListAssets(t.Context(), identities.tenantOwner, AssetPageRequest{
			TargetScopeID: identities.tenantScope, Limit: 1, Cursor: page1.NextCursor,
		})
		if err != nil || len(page2.Items) != 1 || page2.Items[0].ID == page1.Items[0].ID {
			t.Fatalf("asset page2=%#v err=%v", page2, err)
		}
	})

	t.Run("rules priority CAS idempotency publication and pagination", func(t *testing.T) {
		tenantAsset := readyAsset(t, service, identities.tenantOwner, identities.tenantScope, "tenant-rule", []byte("tenant error"), "text/plain")
		globalAsset := readyAsset(t, service, identities.platform, identities.platformScope, "global-rule", []byte(`{"error":"global"}`), "application/json")
		create := CreateRuleRequest{
			Target:        RuleTarget{Kind: ScopeSite, ScopeID: identities.tenantScope, SiteID: &identities.siteID},
			Fields:        RuleFields{Category: CategoryEdgeRoute, Match: StatusSelector{Kind: MatchExact, From: 404}, AssetID: tenantAsset.ID, Enabled: true},
			WriteMetadata: writeMetadata("rule-create"),
		}
		ruleResult, err := service.CreateRule(t.Context(), identities.tenantOwner, create)
		if err != nil || ruleResult.Value.Priority != 1 || ruleResult.Value.Revision != 1 {
			t.Fatalf("create rule=%#v err=%v", ruleResult, err)
		}
		replay, err := service.CreateRule(t.Context(), identities.tenantOwner, create)
		if err != nil || !replay.Replayed || replay.Value.ID != ruleResult.Value.ID {
			t.Fatalf("rule replay=%#v err=%v", replay, err)
		}
		changed := create
		changed.Fields.Match.From = 403
		if _, err := service.CreateRule(t.Context(), identities.tenantOwner, changed); !errors.Is(err, ErrIdempotencyConflict) {
			t.Fatalf("rule changed payload error=%v", err)
		}
		conflict := create
		conflict.WriteMetadata = writeMetadata("rule-conflict")
		if _, err := service.CreateRule(t.Context(), identities.tenantOwner, conflict); !errors.Is(err, ErrConflict) {
			t.Fatalf("equal priority conflict error=%v", err)
		}
		broad := create
		broad.WriteMetadata = writeMetadata("rule-broad")
		broad.Fields.Match = StatusSelector{Kind: MatchRange, From: 400, To: 499}
		broadResult, err := service.CreateRule(t.Context(), identities.tenantOwner, broad)
		if err != nil || broadResult.Value.Priority != 100 {
			t.Fatalf("broad rule=%#v err=%v", broadResult, err)
		}
		if _, err := service.UpdateRule(t.Context(), identities.tenantOwner, UpdateRuleRequest{
			RuleID: ruleResult.Value.ID, ExpectedRevision: 99, Fields: ruleResult.Value.Fields,
			WriteMetadata: writeMetadata("bad-cas"),
		}); !errors.Is(err, ErrRevisionConflict) {
			t.Fatalf("CAS error=%v", err)
		}

		globalResult, err := service.CreateRule(t.Context(), identities.platform, CreateRuleRequest{
			Target:        RuleTarget{Kind: ScopeGlobal, ScopeID: identities.platformScope},
			Fields:        RuleFields{Category: CategoryNoHost, Match: StatusSelector{Kind: MatchExact, From: 400}, AssetID: globalAsset.ID, Enabled: true},
			WriteMetadata: writeMetadata("global-rule-create"),
		})
		if err != nil || globalResult.Value.Target.Kind != ScopeGlobal {
			t.Fatalf("global rule=%#v err=%v", globalResult, err)
		}
		if _, err := service.CreateRule(t.Context(), identities.tenantOwner, CreateRuleRequest{
			Target:        RuleTarget{Kind: ScopeGlobal, ScopeID: identities.tenantScope},
			Fields:        RuleFields{Category: CategoryNoHost, Match: StatusSelector{Kind: MatchExact, From: 400}, AssetID: tenantAsset.ID, Enabled: true},
			WriteMetadata: writeMetadata("tenant-global"),
		}); !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("tenant global error=%v", err)
		}
		if _, err := service.CreateRule(t.Context(), identities.tenantOwner, CreateRuleRequest{
			Target:        create.Target,
			Fields:        RuleFields{Category: CategoryOriginResponse, Match: StatusSelector{Kind: MatchExact, From: 500}, AssetID: globalAsset.ID, Enabled: true},
			WriteMetadata: writeMetadata("cross-scope-asset"),
		}); !errors.Is(err, ErrNotFound) {
			t.Fatalf("cross-scope asset error=%v", err)
		}

		firstSnapshot, err := service.PublicationSnapshot(t.Context(), identities.platform)
		if err != nil || len(firstSnapshot.Policy.Global.Rules) != 1 || len(firstSnapshot.Policy.Sites) != 1 {
			t.Fatalf("snapshot=%#v err=%v", firstSnapshot, err)
		}
		secondSnapshot, err := service.PublicationSnapshot(t.Context(), identities.platform)
		if err != nil || firstSnapshot.SHA256 != secondSnapshot.SHA256 ||
			firstSnapshot.Policy.Revision != secondSnapshot.Policy.Revision {
			t.Fatalf("unstable snapshots first=%#v second=%#v err=%v", firstSnapshot, secondSnapshot, err)
		}
		if _, err := service.PublicationSnapshot(t.Context(), identities.tenantOwner); !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("tenant snapshot error=%v", err)
		}
		page1, err := service.ListRules(t.Context(), identities.tenantOwner, RulePageRequest{
			TargetScopeID: identities.tenantScope, Limit: 1,
		})
		if err != nil || len(page1.Items) != 1 || page1.NextCursor == "" {
			t.Fatalf("page1=%#v err=%v", page1, err)
		}
		page2, err := service.ListRules(t.Context(), identities.tenantOwner, RulePageRequest{
			TargetScopeID: identities.tenantScope, Limit: 1, Cursor: page1.NextCursor,
		})
		if err != nil || len(page2.Items) != 1 || page2.Items[0].ID == page1.Items[0].ID {
			t.Fatalf("page2=%#v err=%v", page2, err)
		}
	})

	t.Run("concurrent rule precedence is serializable", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()
		asset := readyAsset(t, service, identities.tenantOwner, identities.tenantScope,
			"precedence-asset", []byte("precedence"), "text/plain")
		target := RuleTarget{Kind: ScopeSite, ScopeID: identities.tenantScope, SiteID: &identities.siteID}

		for round := 0; round < 20; round++ {
			statusCode := 520 + round
			start := make(chan struct{})
			results := make(chan error, 2)
			for contender := 0; contender < 2; contender++ {
				request := CreateRuleRequest{
					Target: target,
					Fields: RuleFields{
						Category: CategoryOriginResponse,
						Match:    StatusSelector{Kind: MatchExact, From: statusCode},
						AssetID:  asset.ID,
						Enabled:  true,
					},
					WriteMetadata: writeMetadata(fmt.Sprintf("precedence-create-%d-%d", round, contender)),
				}
				go func() {
					<-start
					_, err := service.CreateRule(ctx, identities.tenantOwner, request)
					results <- err
				}()
			}
			close(start)
			successes, conflicts := 0, 0
			for range 2 {
				err := <-results
				switch {
				case err == nil:
					successes++
				case errors.Is(err, ErrConflict):
					conflicts++
				default:
					t.Fatalf("round %d unexpected create result: %v", round, err)
				}
			}
			if successes != 1 || conflicts != 1 {
				t.Fatalf("round %d successes=%d conflicts=%d", round, successes, conflicts)
			}
		}

		for round := 0; round < 20; round++ {
			statusCode := 560 + round
			active, err := service.CreateRule(ctx, identities.tenantOwner, CreateRuleRequest{
				Target: target,
				Fields: RuleFields{
					Category: CategoryOriginResponse,
					Match:    StatusSelector{Kind: MatchExact, From: statusCode},
					AssetID:  asset.ID,
					Enabled:  true,
				},
				WriteMetadata: writeMetadata(fmt.Sprintf("precedence-active-%d", round)),
			})
			if err != nil {
				t.Fatal(err)
			}
			standby, err := service.CreateRule(ctx, identities.tenantOwner, CreateRuleRequest{
				Target: target,
				Fields: RuleFields{
					Category: CategoryOriginResponse,
					Match:    StatusSelector{Kind: MatchExact, From: statusCode},
					AssetID:  asset.ID,
					Enabled:  false,
				},
				WriteMetadata: writeMetadata(fmt.Sprintf("precedence-standby-%d", round)),
			})
			if err != nil {
				t.Fatal(err)
			}
			start := make(chan struct{})
			disableResult := make(chan error, 1)
			enableResult := make(chan error, 1)
			go func() {
				<-start
				_, err := service.DisableRule(ctx, identities.tenantOwner, ChangeRuleStateRequest{
					RuleID: active.Value.ID, ExpectedRevision: active.Value.Revision,
					WriteMetadata: writeMetadata(fmt.Sprintf("precedence-disable-%d", round)),
				})
				disableResult <- err
			}()
			go func() {
				<-start
				_, err := service.EnableRule(ctx, identities.tenantOwner, ChangeRuleStateRequest{
					RuleID: standby.Value.ID, ExpectedRevision: standby.Value.Revision,
					WriteMetadata: writeMetadata(fmt.Sprintf("precedence-enable-%d", round)),
				})
				enableResult <- err
			}()
			close(start)
			if err := <-disableResult; err != nil {
				t.Fatalf("round %d disable error=%v", round, err)
			}
			enableErr := <-enableResult
			if enableErr != nil && !errors.Is(enableErr, ErrConflict) {
				t.Fatalf("round %d enable error=%v", round, enableErr)
			}
			activeRule, err := service.GetRule(ctx, identities.tenantOwner, active.Value.ID)
			if err != nil || activeRule.Fields.Enabled {
				t.Fatalf("round %d active rule=%#v err=%v", round, activeRule, err)
			}
			standbyRule, err := service.GetRule(ctx, identities.tenantOwner, standby.Value.ID)
			if err != nil || standbyRule.Fields.Enabled != (enableErr == nil) {
				t.Fatalf("round %d standby rule=%#v enable_err=%v get_err=%v", round, standbyRule, enableErr, err)
			}
		}

		for round := 0; round < 20; round++ {
			assertDirectRuleConflictOneWinner(t, fixture.pool, directRuleSpec{
				Actor: identities.tenantOwner, ScopeID: identities.tenantScope, SiteID: identities.siteID,
				AssetID: asset.ID, Category: CategoryOriginResponse, From: 580 + round, To: 580 + round,
			}, round)
		}

		extraSiteID := seedAdditionalSite(t, fixture.pool, identities.tenantOwner, identities.tenantScope,
			"precedence-extra")
		otherSiteID := siteIDForScope(t, fixture.pool, identities.otherTenantScope)
		otherAsset := readyAsset(t, service, identities.otherTenantOwner, identities.otherTenantScope,
			"precedence-other-asset", []byte("other precedence"), "text/plain")
		base := directRuleSpec{
			Actor: identities.tenantOwner, ScopeID: identities.tenantScope, SiteID: identities.siteID,
			AssetID: asset.ID, Category: CategoryEdgeRoute, From: 540, To: 540,
		}
		t.Run("different scope", func(t *testing.T) {
			other := base
			other.Actor, other.ScopeID, other.SiteID, other.AssetID = identities.otherTenantOwner,
				identities.otherTenantScope, otherSiteID, otherAsset.ID
			assertDirectRuleDomainsIndependent(t, fixture.pool, base, other)
		})
		t.Run("different site", func(t *testing.T) {
			left := base
			left.From, left.To = 541, 541
			other := left
			other.SiteID = extraSiteID
			assertDirectRuleDomainsIndependent(t, fixture.pool, left, other)
		})
		t.Run("different category", func(t *testing.T) {
			left := base
			left.From, left.To = 542, 542
			other := left
			other.Category = CategoryOriginResponse
			assertDirectRuleDomainsIndependent(t, fixture.pool, left, other)
		})
		t.Run("different priority", func(t *testing.T) {
			left := base
			left.From, left.To = 543, 543
			other := left
			other.To = other.From + 1
			assertDirectRuleDomainsIndependent(t, fixture.pool, left, other)
		})
	})

	t.Run("quota concurrency has one winner", func(t *testing.T) {
		concurrent := seedAdditionalTenant(t, fixture.pool, "quota")
		oneLimit := staticLimits{quota: AssetQuota{MaxAssetBytes: MaxEdgeResourceBytes, MaxAssets: 1, MaxTotalBytes: 1024}}
		quotaService, _ := NewServiceWithDependencies(fixture.pool, store, scanner, oneLimit, audit.New(fixture.pool), clock.Now, testTxAuthorizer{})
		start := make(chan struct{})
		errorsFound := make(chan error, 2)
		for index := 0; index < 2; index++ {
			index := index
			go func() {
				<-start
				_, err := quotaService.InitiateAsset(context.Background(), concurrent.actor,
					initiateRequest(concurrent.scopeID, fmt.Sprintf("quota-%d", index), []byte(fmt.Sprintf("q-%d", index)), "text/plain"))
				errorsFound <- err
			}()
		}
		close(start)
		successes, quotaFailures := 0, 0
		for range 2 {
			err := <-errorsFound
			if err == nil {
				successes++
			} else if errors.Is(err, ErrQuotaExceeded) {
				quotaFailures++
			} else {
				t.Fatalf("unexpected quota result: %v", err)
			}
		}
		if successes != 1 || quotaFailures != 1 {
			t.Fatalf("successes=%d quota_failures=%d", successes, quotaFailures)
		}
	})

	t.Run("audit failure rolls back mutation", func(t *testing.T) {
		failedService, _ := NewServiceWithDependencies(fixture.pool, store, scanner, limits,
			failingAudit{err: errors.New("audit unavailable")}, clock.Now, testTxAuthorizer{})
		body := []byte("audit rollback")
		request := initiateRequest(identities.tenantScope, "audit-rollback", body, "text/plain")
		if _, err := failedService.InitiateAsset(t.Context(), identities.tenantOwner, request); err == nil {
			t.Fatal("expected audit failure")
		}
		var count int
		if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM error_page_assets
			WHERE scope_id=$1 AND sha256=$2`, identities.tenantScope, decodeSHA256(request.SHA256)).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("rolled back asset count=%d", count)
		}
	})

	t.Run("direct SQL tampering and down with facts fail closed", func(t *testing.T) {
		var assetID uuid.UUID
		if err := fixture.pool.QueryRow(t.Context(), `SELECT id FROM error_page_assets WHERE status='initiated' LIMIT 1`).Scan(&assetID); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.pool.Exec(t.Context(), `UPDATE error_page_assets SET
			status='ready',scan_status='passed',object_state='final',revision=revision+1,updated_at=updated_at
			WHERE id=$1`, assetID); err == nil {
			t.Fatal("direct asset ready tamper succeeded")
		}
		if _, err := fixture.pool.Exec(t.Context(), `UPDATE error_page_rule_revisions SET enabled=false`); err == nil {
			t.Fatal("rule revision tamper succeeded")
		}
		if _, err := fixture.pool.Exec(t.Context(), `UPDATE error_page_publications SET version='tampered'`); err == nil {
			t.Fatal("publication tamper succeeded")
		}
		var publicationRevision int64
		var previousSHA []byte
		if err := fixture.pool.QueryRow(t.Context(), `SELECT revision,snapshot_sha256
			FROM error_page_publications ORDER BY revision DESC LIMIT 1`).Scan(&publicationRevision, &previousSHA); err != nil {
			t.Fatal(err)
		}
		nextRevision := publicationRevision + 1
		forgedSnapshot := []byte(fmt.Sprintf(
			`{"schema":"%s","version":"control-%d","revision":%d,"global":{"rules":[]},"sites":[]}`,
			SchemaV1, nextRevision, nextRevision,
		))
		if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO error_page_publications (
			revision,platform_scope_id,schema,version,canonical_snapshot,snapshot_sha256,previous_sha256,
			created_by_user_id,created_by_scope_id,request_id,trace_id,created_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, nextRevision, identities.platformScope,
			SchemaV1, fmt.Sprintf("control-%d", nextRevision), forgedSnapshot, make([]byte, 32), previousSHA,
			identities.platform.UserID, identities.platform.ScopeID, "forged-publication", "forged-publication", clock.Now()); err == nil {
			t.Fatal("publication with forged snapshot hash succeeded")
		}
		if err := execMigration(t.Context(), fixture.pool, "054_error_page_control.down.sql"); err == nil {
			t.Fatal("054 down succeeded with facts")
		}
		var exists bool
		if err := fixture.pool.QueryRow(t.Context(), `SELECT to_regclass('error_page_assets') IS NOT NULL`).Scan(&exists); err != nil || !exists {
			t.Fatalf("schema disappeared after failed down: exists=%t err=%v", exists, err)
		}
	})

	if err := audit.New(fixture.pool).VerifyScope(t.Context(), identities.tenantScope); err != nil {
		t.Fatalf("tenant audit chain: %v", err)
	}
}

func TestIdempotencyReplayBindsRequestIDPostgreSQL(t *testing.T) {
	fixture := openErrorPageDatabase(t)
	identities := seedErrorPageIdentities(t, fixture.pool)
	store := newRuntimeContentStore()
	scanner := &runtimeScanner{}
	limits := staticLimits{quota: AssetQuota{
		MaxAssetBytes: MaxEdgeResourceBytes, MaxAssets: 100, MaxTotalBytes: 8 << 20,
	}}
	service, err := NewServiceWithDependencies(fixture.pool, store, scanner, limits,
		audit.New(fixture.pool), time.Now, testTxAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("request id replay binding")
	asset := initiateAsset(t, service, identities.tenantOwner, identities.tenantScope,
		"request-id-initiate", body, "text/plain")
	request := uploadRequest(asset.ID, "request-id-upload", body, "text/plain")
	if _, err := service.UploadAsset(t.Context(), identities.tenantOwner, request); err != nil {
		t.Fatal(err)
	}
	beforeStore := store.snapshot()
	beforeScans := scanner.calls()
	beforeFacts := reviewFactCounts(t, fixture.pool)

	replay := uploadRequest(asset.ID, "request-id-upload", body, "text/plain")
	replay.RequestID = "different-request-id"
	if _, err := service.UploadAsset(t.Context(), identities.tenantOwner, replay); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("different request-id replay error=%v, want ErrIdempotencyConflict", err)
	}
	if afterStore := store.snapshot(); afterStore != beforeStore {
		t.Fatalf("object side effects before=%+v after=%+v", beforeStore, afterStore)
	}
	if afterScans := scanner.calls(); afterScans != beforeScans {
		t.Fatalf("scanner side effects before=%d after=%d", beforeScans, afterScans)
	}
	if afterFacts := reviewFactCounts(t, fixture.pool); afterFacts != beforeFacts {
		t.Fatalf("database side effects before=%+v after=%+v", beforeFacts, afterFacts)
	}
	findErr := pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
		_, err := findWrite(t.Context(), tx, identities.tenantOwner, operationAssetUpload,
			request.IdempotencyKey, replay.RequestID)
		return err
	})
	if !errors.Is(findErr, ErrIdempotencyConflict) {
		t.Fatalf("findWrite different request-id error=%v, want ErrIdempotencyConflict", findErr)
	}
}

func TestErrorPageMigration054RoundTrip(t *testing.T) {
	fixture := openErrorPageDatabaseThrough(t, 53)
	if err := execMigration(t.Context(), fixture.pool, "054_error_page_control.up.sql"); err != nil {
		t.Fatal(err)
	}
	assertErrorPageTables(t, fixture.pool, true)
	if err := execMigration(t.Context(), fixture.pool, "054_error_page_control.down.sql"); err != nil {
		t.Fatal(err)
	}
	assertErrorPageTables(t, fixture.pool, false)
	if err := execMigration(t.Context(), fixture.pool, "054_error_page_control.up.sql"); err != nil {
		t.Fatal(err)
	}
	assertErrorPageTables(t, fixture.pool, true)
}

type integrationFixture struct {
	pool *pgxpool.Pool
}

// openErrorPageDatabase opens a schema at the release migration head (a
// template clone when TEST_DATABASE_TEMPLATE is set). Every test that runs the
// error page service, stores or audit log needs the head schema.
func openErrorPageDatabase(t *testing.T) integrationFixture {
	t.Helper()
	return integrationFixture{pool: databasetest.MigratedPool(t, nil)}
}

// openErrorPageDatabaseThrough opens a fresh schema migrated through version
// only, for a test of one migration's own up/down round trip.
func openErrorPageDatabaseThrough(t *testing.T, version int64) integrationFixture {
	t.Helper()
	return integrationFixture{pool: databasetest.MigratedThroughPool(t, "errorpage_test", version)}
}

func execMigration(ctx context.Context, pool *pgxpool.Pool, name string) error {
	script, err := controlmigrations.FS.ReadFile(name)
	if err != nil {
		return err
	}
	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, string(script))
		return err
	})
}

func assertErrorPageTables(t *testing.T, pool *pgxpool.Pool, expected bool) {
	t.Helper()
	for _, table := range []string{
		"error_page_assets", "error_page_asset_scan_facts", "error_page_rules",
		"error_page_rule_revisions", "error_page_publications", "error_page_write_requests",
	} {
		var exists bool
		if err := pool.QueryRow(t.Context(), `SELECT to_regclass($1) IS NOT NULL`, table).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if exists != expected {
			t.Fatalf("table %s exists=%t, want %t", table, exists, expected)
		}
	}
}

type seededIdentities struct {
	platform         Actor
	platformScope    uuid.UUID
	tenantOwner      Actor
	tenantViewer     Actor
	tenantScope      uuid.UUID
	otherTenantOwner Actor
	otherTenantScope uuid.UUID
	siteID           uuid.UUID
}

func seedErrorPageIdentities(t *testing.T, pool *pgxpool.Pool) seededIdentities {
	t.Helper()
	result := seededIdentities{}
	result.platform, result.platformScope = seedPlatformActor(t, pool)
	first := seedAdditionalTenant(t, pool, "first")
	second := seedAdditionalTenant(t, pool, "second")
	result.tenantOwner, result.tenantViewer, result.tenantScope, result.siteID = first.actor, first.viewer, first.scopeID, first.siteID
	result.otherTenantOwner, result.otherTenantScope = second.actor, second.scopeID
	return result
}

func seedPlatformActor(t *testing.T, pool *pgxpool.Pool) (Actor, uuid.UUID) {
	t.Helper()
	scopeID, userID, roleID, sessionID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	now := time.Now().UTC()
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		statements := []struct {
			query string
			args  []any
		}{
			{`INSERT INTO access_scopes(id,kind,created_at) VALUES($1,'platform',$2)`, []any{scopeID, now}},
			{`INSERT INTO users(id,username,display_name,password_hash,created_at,updated_at) VALUES($1,$2,$3,'hash',$4,$4)`, []any{userID, "platform-" + userID.String(), "Platform", now}},
			{`INSERT INTO memberships(scope_id,user_id,created_at) VALUES($1,$2,$3)`, []any{scopeID, userID, now}},
			{`INSERT INTO roles(id,scope_id,name,description,system_role,created_at) VALUES($1,$2,'platform_owner','owner',true,$3)`, []any{roleID, scopeID, now}},
			{`INSERT INTO role_assignments(scope_id,user_id,role_id,assigned_at) VALUES($1,$2,$3,$4)`, []any{scopeID, userID, roleID, now}},
			{`INSERT INTO auth_sessions(id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at)
				VALUES($1,$1,$2,$3,$4,$5,$6)`, []any{sessionID, userID, scopeID,
				decodeSHA256(digestBytes([]byte("session:" + sessionID.String()))), now, now.Add(24 * time.Hour)}},
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
	return Actor{UserID: userID, ScopeID: scopeID, ScopeKind: "platform",
		Credential: CredentialReference{Kind: CredentialKindSession, ID: sessionID}}, scopeID
}

type tenantSeed struct {
	actor   Actor
	viewer  Actor
	scopeID uuid.UUID
	siteID  uuid.UUID
}

func seedAdditionalTenant(t *testing.T, pool *pgxpool.Pool, label string) tenantSeed {
	t.Helper()
	tenantID, scopeID := uuid.New(), uuid.New()
	ownerID, viewerID := uuid.New(), uuid.New()
	ownerSessionID, viewerSessionID := uuid.New(), uuid.New()
	ownerRoleID, viewerRoleID, siteID := uuid.New(), uuid.New(), uuid.New()
	now := time.Now().UTC()
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		statements := []struct {
			query string
			args  []any
		}{
			{`INSERT INTO tenants(id,display_name,created_at,updated_at) VALUES($1,$2,$3,$3)`, []any{tenantID, "Tenant " + label, now}},
			{`INSERT INTO access_scopes(id,kind,tenant_id,created_at) VALUES($1,'tenant',$2,$3)`, []any{scopeID, tenantID, now}},
			{`INSERT INTO users(id,username,display_name,password_hash,created_at,updated_at) VALUES
				($1,$2,'Owner','hash',$3,$3),($4,$5,'Viewer','hash',$3,$3)`, []any{ownerID, label + "-owner-" + ownerID.String(), now, viewerID, label + "-viewer-" + viewerID.String()}},
			{`INSERT INTO memberships(scope_id,user_id,created_at) VALUES($1,$2,$4),($1,$3,$4)`, []any{scopeID, ownerID, viewerID, now}},
			{`INSERT INTO roles(id,scope_id,name,description,system_role,created_at) VALUES
				($1,$3,'tenant_owner','owner',true,$4),($2,$3,'tenant_viewer','viewer',true,$4)`, []any{ownerRoleID, viewerRoleID, scopeID, now}},
			{`INSERT INTO role_assignments(scope_id,user_id,role_id,assigned_at) VALUES
				($1,$2,$4,$6),($1,$3,$5,$6)`, []any{scopeID, ownerID, viewerID, ownerRoleID, viewerRoleID, now}},
			{`INSERT INTO auth_sessions(id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at) VALUES
				($1,$1,$2,$5,$6,$7,$8),($3,$3,$4,$5,$9,$7,$8)`, []any{
				ownerSessionID, ownerID, viewerSessionID, viewerID, scopeID,
				decodeSHA256(digestBytes([]byte("session:" + ownerSessionID.String()))), now, now.Add(24 * time.Hour),
				decodeSHA256(digestBytes([]byte("session:" + viewerSessionID.String()))),
			}},
			{seedSiteInsertSQL, []any{siteID, scopeID, ownerID, label + ".example.test", now}},
			{`INSERT INTO site_origin_pools(site_id,updated_at) VALUES($1,$2)`, []any{siteID, now}},
			{`INSERT INTO site_origins(site_id,position,host,port,weight,enabled)
				VALUES($1,1,'192.0.2.1',80,1,true)`, []any{siteID}},
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
	return tenantSeed{
		actor: Actor{UserID: ownerID, ScopeID: scopeID, ScopeKind: "tenant",
			Credential: CredentialReference{Kind: CredentialKindSession, ID: ownerSessionID}},
		viewer: Actor{UserID: viewerID, ScopeID: scopeID, ScopeKind: "tenant",
			Credential: CredentialReference{Kind: CredentialKindSession, ID: viewerSessionID}},
		scopeID: scopeID, siteID: siteID,
	}
}

func initiateRequest(scopeID uuid.UUID, key string, body []byte, mime string) InitiateAssetRequest {
	return InitiateAssetRequest{
		Target: AssetTarget{ScopeID: scopeID}, MIME: mime, Size: int64(len(body)), SHA256: digestBytes(body),
		WriteMetadata: writeMetadata(key),
	}
}

func initiateAsset(t *testing.T, service *Service, actor Actor, scopeID uuid.UUID, key string, body []byte, mime string) Asset {
	t.Helper()
	result, err := service.InitiateAsset(t.Context(), actor, initiateRequest(scopeID, key, body, mime))
	if err != nil {
		t.Fatal(err)
	}
	return result.Value
}

func uploadRequest(id uuid.UUID, key string, body []byte, mime string) UploadAssetRequest {
	return UploadAssetRequest{
		AssetID: id, MIMEType: mime, ContentLength: int64(len(body)), Body: bytes.NewReader(body),
		WriteMetadata: writeMetadata(key),
	}
}

func mustUpload(t *testing.T, service *Service, actor Actor, asset Asset, key string, body []byte) {
	t.Helper()
	if _, err := service.UploadAsset(t.Context(), actor, uploadRequest(asset.ID, key, body, asset.MIMEType)); err != nil {
		t.Fatal(err)
	}
}

func readyAsset(t *testing.T, service *Service, actor Actor, scopeID uuid.UUID, key string, body []byte, mime string) Asset {
	t.Helper()
	asset := initiateAsset(t, service, actor, scopeID, key+"-init", body, mime)
	mustUpload(t, service, actor, asset, key+"-upload", body)
	result, err := service.FinalizeAsset(t.Context(), actor, finalizeRequest(asset.ID, key+"-finalize"))
	if err != nil {
		t.Fatal(err)
	}
	return result.Value
}

func finalizeRequest(id uuid.UUID, key string) FinalizeAssetRequest {
	return FinalizeAssetRequest{AssetID: id, WriteMetadata: writeMetadata(key)}
}

func writeMetadata(key string) WriteMetadata {
	return WriteMetadata{IdempotencyKey: key, RequestID: key + "-request", TraceID: key + "-trace"}
}

type directRuleSpec struct {
	Actor    Actor
	ScopeID  uuid.UUID
	SiteID   uuid.UUID
	AssetID  uuid.UUID
	Category string
	From     int
	To       int
}

func insertDirectRuleIdentity(t *testing.T, pool *pgxpool.Pool, spec directRuleSpec) uuid.UUID {
	t.Helper()
	var tenantID uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT tenant_id FROM access_scopes WHERE id=$1`, spec.ScopeID).Scan(&tenantID); err != nil {
		t.Fatal(err)
	}
	ruleID := uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO error_page_rules (
		id,scope_kind,scope_id,tenant_id,site_id,created_by_user_id,created_by_scope_id,created_at
	) VALUES($1,'site',$2,$3,$4,$5,$6,$7)`, ruleID, spec.ScopeID, tenantID, spec.SiteID,
		spec.Actor.UserID, spec.Actor.ScopeID, storeTime(time.Now())); err != nil {
		t.Fatal(err)
	}
	return ruleID
}

func insertDirectRuleRevision(
	ctx context.Context,
	tx pgx.Tx,
	spec directRuleSpec,
	ruleID uuid.UUID,
	key string,
) error {
	matchKind := MatchExact
	if spec.From != spec.To {
		matchKind = MatchRange
	}
	_, err := tx.Exec(ctx, `INSERT INTO error_page_rule_revisions (
		rule_id,revision,category,match_kind,code_from,code_to,asset_id,enabled,deleted,
		created_by_user_id,created_by_scope_id,request_id,trace_id,created_at
	) VALUES($1,1,$2,$3,$4,$5,$6,true,false,$7,$8,$9,$9,$10)`, ruleID, spec.Category,
		matchKind, spec.From, spec.To, spec.AssetID, spec.Actor.UserID, spec.Actor.ScopeID, key,
		storeTime(time.Now()))
	return err
}

func assertDirectRuleConflictOneWinner(t *testing.T, pool *pgxpool.Pool, spec directRuleSpec, round int) {
	t.Helper()
	leftRuleID := insertDirectRuleIdentity(t, pool, spec)
	rightRuleID := insertDirectRuleIdentity(t, pool, spec)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	left, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer left.Rollback(context.Background())
	if err := insertDirectRuleRevision(ctx, left, spec, leftRuleID, fmt.Sprintf("direct-left-%d", round)); err != nil {
		t.Fatal(err)
	}
	right, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer right.Rollback(context.Background())
	if _, err := right.Exec(ctx, `SET LOCAL lock_timeout='4s'`); err != nil {
		t.Fatal(err)
	}
	var rightPID int
	if err := right.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&rightPID); err != nil {
		t.Fatal(err)
	}
	completed := make(chan error, 1)
	go func() {
		completed <- insertDirectRuleRevision(ctx, right, spec, rightRuleID, fmt.Sprintf("direct-right-%d", round))
	}()
	waitForAdvisoryLock(t, ctx, pool, rightPID, completed)
	if err := left.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-completed:
		if sqlState(err) != "P0001" {
			t.Fatalf("round %d direct conflict error=%v state=%s", round, err, sqlState(err))
		}
	case <-ctx.Done():
		t.Fatalf("round %d direct conflict did not finish: %v", round, ctx.Err())
	}
	if err := right.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		t.Fatal(err)
	}
	var revisionCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM error_page_rule_revisions
		WHERE rule_id IN ($1,$2)`, leftRuleID, rightRuleID).Scan(&revisionCount); err != nil {
		t.Fatal(err)
	}
	if revisionCount != 1 {
		t.Fatalf("round %d direct revision count=%d", round, revisionCount)
	}
}

func waitForAdvisoryLock(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	pid int,
	completed <-chan error,
) {
	t.Helper()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err := <-completed:
			t.Fatalf("direct conflicting insert completed before advisory wait: %v", err)
		default:
		}
		var waitEvent string
		err := pool.QueryRow(ctx, `SELECT COALESCE(wait_event,'') FROM pg_stat_activity WHERE pid=$1`, pid).Scan(&waitEvent)
		if err != nil {
			t.Fatal(err)
		}
		if strings.EqualFold(waitEvent, "advisory") {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("direct conflicting insert did not wait on advisory lock: %v", ctx.Err())
		case <-ticker.C:
		}
	}
}

func assertDirectRuleDomainsIndependent(t *testing.T, pool *pgxpool.Pool, leftSpec, rightSpec directRuleSpec) {
	t.Helper()
	leftRuleID := insertDirectRuleIdentity(t, pool, leftSpec)
	rightRuleID := insertDirectRuleIdentity(t, pool, rightSpec)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	left, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer left.Rollback(context.Background())
	if err := insertDirectRuleRevision(ctx, left, leftSpec, leftRuleID, "direct-independent-left-"+uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	right, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer right.Rollback(context.Background())
	var rightPID int
	if err := right.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&rightPID); err != nil {
		t.Fatal(err)
	}
	completed := make(chan error, 1)
	go func() {
		completed <- insertDirectRuleRevision(ctx, right, rightSpec, rightRuleID,
			"direct-independent-right-"+uuid.NewString())
	}()
	waitForAdvisoryLock(t, ctx, pool, rightPID, completed)
	if err := left.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-completed:
		if err != nil {
			t.Fatalf("independent rule domain rejected after publication serialization: %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("independent rule domain did not finish after publication lock release: %v", ctx.Err())
	}
	if err := right.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func siteIDForScope(t *testing.T, pool *pgxpool.Pool, scopeID uuid.UUID) uuid.UUID {
	t.Helper()
	var siteID uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT id FROM sites WHERE scope_id=$1 ORDER BY id LIMIT 1`, scopeID).Scan(&siteID); err != nil {
		t.Fatal(err)
	}
	return siteID
}

// seedSiteInsertSQL inserts an active site ($1 id, $2 scope, $3 owner,
// $4 domain, $5 time) with a display ID allocated from the per-scope sequence,
// as site.Store does (sites.display_id is NOT NULL since migration 210).
const seedSiteInsertSQL = `WITH display AS (
		INSERT INTO site_display_id_sequences(scope_id,next_value,updated_at) VALUES($2,2,$5)
		ON CONFLICT(scope_id) DO UPDATE SET next_value=site_display_id_sequences.next_value+1,
			updated_at=EXCLUDED.updated_at
		RETURNING next_value-1 AS display_id
	)
	INSERT INTO sites(id,display_id,scope_id,owner_user_id,domain,http_ports,https_ports,origins,origin_hosts,
		cname,https_enabled,enabled,status,is_default,revision,created_by_user_id,
		updated_by_user_id,created_at,updated_at)
	SELECT $1,display.display_id,$2,$3,$4,ARRAY['80'],ARRAY[]::text[],ARRAY['192.0.2.1:80'],ARRAY['192.0.2.1'],
		'',false,true,'active',false,1,$3,$3,$5,$5 FROM display`

func seedAdditionalSite(t *testing.T, pool *pgxpool.Pool, actor Actor, scopeID uuid.UUID, label string) uuid.UUID {
	t.Helper()
	siteID := uuid.New()
	now := storeTime(time.Now())
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), seedSiteInsertSQL, siteID, scopeID, actor.UserID,
			label+".example.test", now); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO site_origin_pools(site_id,updated_at) VALUES($1,$2)`,
			siteID, now); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO site_origins(site_id,position,host,port,weight,enabled)
			VALUES($1,1,'192.0.2.1',80,1,true)`, siteID)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return siteID
}

type staticLimits struct {
	quota  AssetQuota
	denied bool
}

func (limits staticLimits) Limits(context.Context, pgx.Tx, EntitlementCheck) (EntitlementLimits, error) {
	if limits.denied {
		return EntitlementLimits{}, ErrEntitlementDenied
	}
	return EntitlementLimits{
		FeatureEnabled: true, AssetQuota: limits.quota, MaxRulesPerScope: MaxEdgeRulesPerScope,
		MaxPublicationSites: MaxPublicationSites, MaxPublicationBytes: MaxEdgePolicyBytes,
	}, nil
}

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (clock *testClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

type testScanner struct {
	name          string
	err           error
	waitForCancel bool
}

func (scanner *testScanner) Name() string { return scanner.name }

func (scanner *testScanner) Scan(ctx context.Context, input ScanInput) error {
	if scanner.waitForCancel {
		<-ctx.Done()
		return ctx.Err()
	}
	if _, err := io.ReadAll(input.Body); err != nil {
		return err
	}
	return scanner.err
}

type memoryContentStore struct {
	mu      sync.Mutex
	objects map[string]memoryObject
	statErr error
}

type memoryObject struct {
	body  []byte
	mime  string
	token string
}

func newMemoryContentStore() *memoryContentStore {
	return &memoryContentStore{objects: make(map[string]memoryObject)}
}

func (store *memoryContentStore) Capabilities() ObjectStoreCapabilities {
	return ObjectStoreCapabilities{
		ImmutableStaging: true, ConditionalFinalize: true, TrustedMetadata: true,
		ImmutableReads: true, PreservesStagingAlias: true,
	}
}

func (store *memoryContentStore) PutStaging(
	ctx context.Context,
	ref ObjectRef,
	body []byte,
	mime string,
) (ObjectInfo, error) {
	if err := ctx.Err(); err != nil {
		return ObjectInfo{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	key := ref.LogicalKey
	if existing, found := store.objects[key]; found {
		if !bytes.Equal(existing.body, body) || existing.mime != mime {
			return ObjectInfo{}, ErrConflict
		}
		return memoryObjectInfo(existing), nil
	}
	object := memoryObject{body: append([]byte(nil), body...), mime: mime, token: "memory-" + uuid.NewString()}
	store.objects[key] = object
	return memoryObjectInfo(object), nil
}

func (store *memoryContentStore) Open(ctx context.Context, ref ObjectRef, immutableToken string) (io.ReadCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	key := ref.LogicalKey
	object, found := store.objects[key]
	if !found {
		return nil, ErrObjectNotFound
	}
	if object.token != immutableToken {
		return nil, ErrConflict
	}
	return io.NopCloser(bytes.NewReader(append([]byte(nil), object.body...))), nil
}

func (store *memoryContentStore) Finalize(
	ctx context.Context,
	stagingRef, objectRef ObjectRef,
	expected ObjectInfo,
) (ObjectInfo, error) {
	if err := ctx.Err(); err != nil {
		return ObjectInfo{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	stagingKey, objectKey := stagingRef.LogicalKey, objectRef.LogicalKey
	staged, found := store.objects[stagingKey]
	if !found {
		return ObjectInfo{}, ErrObjectNotFound
	}
	if memoryObjectInfo(staged) != expected {
		return ObjectInfo{}, ErrConflict
	}
	if final, found := store.objects[objectKey]; found {
		if memoryObjectInfo(final) != expected {
			return ObjectInfo{}, ErrConflict
		}
		return memoryObjectInfo(final), nil
	}
	store.objects[objectKey] = staged
	return memoryObjectInfo(staged), nil
}

func (store *memoryContentStore) Stat(ctx context.Context, ref ObjectRef) (ObjectInfo, error) {
	if err := ctx.Err(); err != nil {
		return ObjectInfo{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	key := ref.LogicalKey
	if store.statErr != nil {
		return ObjectInfo{}, store.statErr
	}
	object, found := store.objects[key]
	if !found {
		return ObjectInfo{}, ErrObjectNotFound
	}
	return memoryObjectInfo(object), nil
}

func memoryObjectInfo(object memoryObject) ObjectInfo {
	return ObjectInfo{
		Size: int64(len(object.body)), SHA256: digestBytes(object.body), MIMEType: object.mime,
		ImmutableToken: object.token,
	}
}

func (store *memoryContentStore) setStatError(err error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.statErr = err
}

func (store *memoryContentStore) Delete(ctx context.Context, ref ObjectRef) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	key := ref.LogicalKey
	if _, found := store.objects[key]; !found {
		return ErrObjectNotFound
	}
	delete(store.objects, key)
	return nil
}

func (store *memoryContentStore) exists(key string) bool {
	store.mu.Lock()
	defer store.mu.Unlock()
	_, found := store.objects[key]
	return found
}

type failingAudit struct{ err error }

func (failure failingAudit) Append(context.Context, pgx.Tx, audit.Event) error { return failure.err }

type publicationAtomicityState struct {
	facts               runtimeDomainFactCounts
	asset               Asset
	rule                Rule
	publicationRevision int64
	canonicalSnapshot   string
	snapshotSHA256      string
	previousSHA256      string
}

type publicationAfterWriteFailingAudit struct {
	err                 error
	ruleID              uuid.UUID
	ruleRevision        int64
	publicationRevision int64
	actor               Actor
	idempotencyKey      string
}

func (failure publicationAfterWriteFailingAudit) Append(
	ctx context.Context,
	tx pgx.Tx,
	event audit.Event,
) error {
	if event.Action != operationRuleUpdate || event.ResourceID != failure.ruleID.String() {
		return fmt.Errorf("audit reached for unexpected event %s/%s", event.Action, event.ResourceID)
	}
	var ruleRevision int64
	if err := tx.QueryRow(ctx, `SELECT revision FROM error_page_rule_revisions
		WHERE rule_id=$1 ORDER BY revision DESC LIMIT 1`, failure.ruleID).Scan(&ruleRevision); err != nil {
		return fmt.Errorf("audit reached before rule revision: %w", err)
	}
	if ruleRevision != failure.ruleRevision {
		return fmt.Errorf("audit saw rule revision %d, want %d", ruleRevision, failure.ruleRevision)
	}
	var publicationRevision int64
	var canonical []byte
	if err := tx.QueryRow(ctx, `SELECT revision,canonical_snapshot FROM error_page_publications
		ORDER BY revision DESC LIMIT 1`).Scan(&publicationRevision, &canonical); err != nil {
		return fmt.Errorf("audit reached before publication: %w", err)
	}
	if publicationRevision != failure.publicationRevision ||
		!bytes.Contains(canonical, []byte(failure.ruleID.String())) ||
		!bytes.Contains(canonical, []byte(`"codes":[503]`)) {
		return fmt.Errorf("audit saw publication revision=%d canonical=%s",
			publicationRevision, string(canonical))
	}
	var completed bool
	if err := tx.QueryRow(ctx, `SELECT completed_at IS NOT NULL FROM error_page_write_requests
		WHERE actor_scope_id=$1 AND actor_user_id=$2 AND operation=$3 AND idempotency_key=$4`,
		failure.actor.ScopeID, failure.actor.UserID, operationRuleUpdate, failure.idempotencyKey).Scan(&completed); err != nil {
		return fmt.Errorf("audit reached before idempotency claim: %w", err)
	}
	if completed {
		return errors.New("audit reached after idempotency completion")
	}
	return failure.err
}

func TestRulePublicationAndWriteFactsRollbackAfterAuditFailure(t *testing.T) {
	fixture := openErrorPageDatabase(t)
	identities := seedErrorPageIdentities(t, fixture.pool)
	store := newMemoryContentStore()
	scanner := &testScanner{name: "publication-atomicity-scanner"}
	clock := &testClock{now: time.Date(2026, 7, 25, 2, 0, 0, 0, time.UTC)}
	limits := staticLimits{quota: AssetQuota{
		MaxAssetBytes: MaxEdgeResourceBytes, MaxAssets: 1000, MaxTotalBytes: 64 << 20,
	}}
	healthy, err := NewServiceWithDependencies(fixture.pool, store, scanner, limits,
		audit.New(fixture.pool), clock.Now, testTxAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	asset := readyAsset(t, healthy, identities.tenantOwner, identities.tenantScope,
		"publication-atomicity-asset", []byte("publication atomicity body"), "text/plain")
	created, err := healthy.CreateRule(t.Context(), identities.tenantOwner, CreateRuleRequest{
		Target: RuleTarget{Kind: ScopeSite, ScopeID: identities.tenantScope, SiteID: &identities.siteID},
		Fields: RuleFields{
			Category: CategoryOriginResponse, Match: StatusSelector{Kind: MatchExact, From: 502},
			AssetID: asset.ID, Enabled: true,
		},
		WriteMetadata: writeMetadata("publication-atomicity-create"),
	})
	if err != nil {
		t.Fatal(err)
	}
	before := readPublicationAtomicityState(t, fixture.pool, healthy, identities.tenantOwner,
		asset.ID, created.Value.ID)
	if before.publicationRevision < 1 || before.canonicalSnapshot == "" || before.snapshotSHA256 == "" ||
		!strings.Contains(before.canonicalSnapshot, created.Value.ID.String()) ||
		!strings.Contains(before.canonicalSnapshot, identities.siteID.String()) ||
		!strings.Contains(before.canonicalSnapshot, asset.SHA256) {
		t.Fatalf("baseline publication is incomplete: %+v", before)
	}

	auditFailure := errors.New("publication atomicity audit failure")
	failing, err := NewServiceWithDependencies(fixture.pool, store, scanner, limits,
		publicationAfterWriteFailingAudit{
			err: auditFailure, ruleID: created.Value.ID, ruleRevision: created.Value.Revision + 1,
			publicationRevision: before.publicationRevision + 1, actor: identities.tenantOwner,
			idempotencyKey: "publication-atomicity-update",
		}, clock.Now, testTxAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	fields := created.Value.Fields
	fields.Match = StatusSelector{Kind: MatchExact, From: 503}
	_, err = failing.UpdateRule(t.Context(), identities.tenantOwner, UpdateRuleRequest{
		RuleID: created.Value.ID, ExpectedRevision: created.Value.Revision, Fields: fields,
		WriteMetadata: writeMetadata("publication-atomicity-update"),
	})
	if !errors.Is(err, auditFailure) {
		t.Fatalf("update error=%v, want injected audit failure", err)
	}

	after := readPublicationAtomicityState(t, fixture.pool, healthy, identities.tenantOwner,
		asset.ID, created.Value.ID)
	if after.facts != before.facts {
		t.Fatalf("failed update changed domain facts: before=%+v after=%+v", before.facts, after.facts)
	}
	if !reflect.DeepEqual(after.asset, before.asset) {
		t.Fatalf("failed update changed asset: before=%#v after=%#v", before.asset, after.asset)
	}
	if !reflect.DeepEqual(after.rule, before.rule) {
		t.Fatalf("failed update changed rule: before=%#v after=%#v", before.rule, after.rule)
	}
	if after.publicationRevision != before.publicationRevision ||
		after.canonicalSnapshot != before.canonicalSnapshot ||
		after.snapshotSHA256 != before.snapshotSHA256 || after.previousSHA256 != before.previousSHA256 {
		t.Fatalf("failed update changed publication: before=%+v after=%+v", before, after)
	}
	var failedWriteFacts int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM error_page_write_requests
		WHERE actor_scope_id=$1 AND actor_user_id=$2 AND operation=$3 AND idempotency_key=$4`,
		identities.tenantOwner.ScopeID, identities.tenantOwner.UserID, operationRuleUpdate,
		"publication-atomicity-update").Scan(&failedWriteFacts); err != nil {
		t.Fatal(err)
	}
	if failedWriteFacts != 0 {
		t.Fatalf("failed update retained %d idempotency facts", failedWriteFacts)
	}
}

func readPublicationAtomicityState(
	t *testing.T,
	pool *pgxpool.Pool,
	service *Service,
	actor Actor,
	assetID, ruleID uuid.UUID,
) publicationAtomicityState {
	t.Helper()
	asset, err := service.GetAsset(t.Context(), actor, assetID)
	if err != nil {
		t.Fatal(err)
	}
	rule, err := service.GetRule(t.Context(), actor, ruleID)
	if err != nil {
		t.Fatal(err)
	}
	state := publicationAtomicityState{facts: readRuntimeDomainFacts(t, pool), asset: asset, rule: rule}
	var canonical, snapshotSHA, previousSHA []byte
	if err := pool.QueryRow(t.Context(), `SELECT revision,canonical_snapshot,snapshot_sha256,previous_sha256
		FROM error_page_publications ORDER BY revision DESC LIMIT 1`).Scan(
		&state.publicationRevision, &canonical, &snapshotSHA, &previousSHA,
	); err != nil {
		t.Fatal(err)
	}
	state.canonicalSnapshot = string(canonical)
	state.snapshotSHA256 = string(snapshotSHA)
	state.previousSHA256 = string(previousSHA)
	return state
}
