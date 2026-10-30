package errorpagecontrol

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/rbacmanager"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type reviewStepUp struct{ now time.Time }

func (step reviewStepUp) VerifyAndConsume(
	context.Context,
	pgx.Tx,
	rbacmanager.StepUpProof,
	rbacmanager.StepUpCheck,
) (rbacmanager.StepUpEvidence, error) {
	return rbacmanager.StepUpEvidence{ProofID: uuid.New(), Method: "totp", VerifiedAt: step.now}, nil
}

func TestReviewTenantSessionAndCustomRBACRevocation(t *testing.T) {
	fixture := openErrorPageDatabase(t)
	identities := seedErrorPageIdentities(t, fixture.pool)
	now := storeTime(time.Now())
	rbac, err := rbacmanager.NewServiceWithDependencies(
		fixture.pool, audit.New(fixture.pool), reviewStepUp{now: now}, func() time.Time { return now },
	)
	if err != nil {
		t.Fatal(err)
	}
	authorizer, err := NewTenantSessionTxAuthorizer(rbac)
	if err != nil {
		t.Fatal(err)
	}
	service := newReviewService(t, fixture.pool, newMemoryContentStore(), staticLimits{
		quota: AssetQuota{MaxAssetBytes: MaxEdgeResourceBytes, MaxAssets: 100, MaxTotalBytes: 8 << 20},
	}, authorizer)

	t.Run("completed fresh and in-progress replay reject revoked session without side effects", func(t *testing.T) {
		completed := initiateRequest(identities.tenantScope, "session-completed", []byte("completed"), "text/plain")
		if _, err := service.InitiateAsset(t.Context(), identities.tenantOwner, completed); err != nil {
			t.Fatal(err)
		}
		inProgress := initiateRequest(identities.tenantScope, "session-in-progress", []byte("pending"), "text/plain")
		insertIncompleteInitiate(t, fixture.pool, identities.tenantOwner, inProgress)
		if _, err := fixture.pool.Exec(t.Context(), `UPDATE auth_sessions SET revoked_at=$2,revocation_reason='review'
			WHERE id=$1`, identities.tenantOwner.Credential.ID, now); err != nil {
			t.Fatal(err)
		}
		before := reviewFactCounts(t, fixture.pool)
		for name, request := range map[string]InitiateAssetRequest{
			"completed":   completed,
			"in_progress": inProgress,
			"fresh":       initiateRequest(identities.tenantScope, "session-fresh", []byte("fresh"), "text/plain"),
		} {
			t.Run(name, func(t *testing.T) {
				if _, err := service.InitiateAsset(t.Context(), identities.tenantOwner, request); !errors.Is(err, ErrPermissionDenied) {
					t.Fatalf("error=%v, want ErrPermissionDenied", err)
				}
			})
		}
		if after := reviewFactCounts(t, fixture.pool); after != before {
			t.Fatalf("facts changed on denied session replay: before=%v after=%v", before, after)
		}
		if _, err := fixture.pool.Exec(t.Context(), `UPDATE auth_sessions SET revoked_at=NULL,revocation_reason=NULL
			WHERE id=$1`, identities.tenantOwner.Credential.ID); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("membership revocation gates completed replay", func(t *testing.T) {
		request := initiateRequest(identities.tenantScope, "membership-replay", []byte("membership"), "text/plain")
		if _, err := service.InitiateAsset(t.Context(), identities.tenantOwner, request); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.pool.Exec(t.Context(), `UPDATE memberships SET status='suspended'
			WHERE scope_id=$1 AND user_id=$2`, identities.tenantScope, identities.tenantOwner.UserID); err != nil {
			t.Fatal(err)
		}
		before := reviewFactCounts(t, fixture.pool)
		if _, err := service.InitiateAsset(t.Context(), identities.tenantOwner, request); !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("error=%v, want ErrPermissionDenied", err)
		}
		if after := reviewFactCounts(t, fixture.pool); after != before {
			t.Fatalf("facts changed on revoked membership: before=%v after=%v", before, after)
		}
		if _, err := fixture.pool.Exec(t.Context(), `UPDATE memberships SET status='active'
			WHERE scope_id=$1 AND user_id=$2`, identities.tenantScope, identities.tenantOwner.UserID); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("custom grant revocation gates completed replay", func(t *testing.T) {
		actor := rbacmanager.Actor{
			UserID: identities.tenantOwner.UserID, ScopeID: identities.tenantScope,
			SessionID: identities.tenantOwner.Credential.ID, ScopeKind: "tenant",
			IdentityDomain: rbacmanager.CustomerControlIdentityDomain,
		}
		role, err := rbac.CreateRole(t.Context(), actor, rbacmanager.CreateRoleRequest{
			Name: "error_page_review", Permissions: []string{permissionManage},
			Mutation: reviewRBACMutation("custom-create"),
		})
		if err != nil {
			t.Fatal(err)
		}
		grant, err := rbac.AssignRole(t.Context(), actor, rbacmanager.AssignRoleRequest{
			RoleID: role.ID, ExpectedRoleRevision: role.CurrentRevision,
			SubjectUserID: identities.tenantViewer.UserID, Mutation: reviewRBACMutation("custom-assign"),
		})
		if err != nil {
			t.Fatal(err)
		}
		request := initiateRequest(identities.tenantScope, "custom-rbac-replay", []byte("custom"), "text/plain")
		if _, err := service.InitiateAsset(t.Context(), identities.tenantViewer, request); err != nil {
			t.Fatal(err)
		}
		if _, err := rbac.RevokeGrant(t.Context(), actor, rbacmanager.RevokeGrantRequest{
			GrantID: grant.ID, Mutation: reviewRBACMutation("custom-revoke"),
		}); err != nil {
			t.Fatal(err)
		}
		before := reviewFactCounts(t, fixture.pool)
		if _, err := service.InitiateAsset(t.Context(), identities.tenantViewer, request); !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("error=%v, want ErrPermissionDenied", err)
		}
		if after := reviewFactCounts(t, fixture.pool); after != before {
			t.Fatalf("facts changed on custom grant revoke: before=%v after=%v", before, after)
		}
	})
}

func reviewRBACMutation(key string) rbacmanager.MutationContext {
	return rbacmanager.MutationContext{
		IdempotencyKey: key, RequestID: key + "-request", TraceID: key + "-trace",
		StepUp: rbacmanager.StepUpProof{Token: key + "-proof"},
	}
}

type reviewSessionHooks struct {
	delegate   TenantSessionAuthorizer
	entered    chan<- struct{}
	authorized chan<- struct{}
	release    <-chan struct{}
}

func (authorizer reviewSessionHooks) AuthorizeTenantSessionTx(
	ctx context.Context,
	tx pgx.Tx,
	session rbacmanager.AuthenticatedSessionReference,
	permission string,
) (uuid.UUID, error) {
	if authorizer.entered != nil {
		authorizer.entered <- struct{}{}
	}
	tenantID, err := authorizer.delegate.AuthorizeTenantSessionTx(ctx, tx, session, permission)
	if err != nil {
		return uuid.Nil, err
	}
	if authorizer.authorized != nil {
		authorizer.authorized <- struct{}{}
	}
	if authorizer.release != nil {
		select {
		case <-ctx.Done():
			return uuid.Nil, ctx.Err()
		case <-authorizer.release:
		}
	}
	return tenantID, nil
}

func TestReviewTenantSessionRevocationCommitOrder(t *testing.T) {
	fixture := openErrorPageDatabase(t)
	identities := seedErrorPageIdentities(t, fixture.pool)
	now := storeTime(time.Now())
	rbac, err := rbacmanager.NewServiceWithDependencies(
		fixture.pool, audit.New(fixture.pool), reviewStepUp{now: now}, time.Now,
	)
	if err != nil {
		t.Fatal(err)
	}
	limits := staticLimits{quota: AssetQuota{MaxAssetBytes: MaxEdgeResourceBytes, MaxAssets: 100, MaxTotalBytes: 8 << 20}}
	store := newMemoryContentStore()

	t.Run("business first", func(t *testing.T) {
		authorized := make(chan struct{}, 1)
		release := make(chan struct{})
		authorizer, err := NewTenantSessionTxAuthorizer(reviewSessionHooks{
			delegate: rbac, authorized: authorized, release: release,
		})
		if err != nil {
			t.Fatal(err)
		}
		service := newReviewService(t, fixture.pool, store, limits, authorizer)
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		request := initiateRequest(identities.tenantScope, "session-business-first", []byte("business"), "text/plain")
		business := make(chan error, 1)
		go func() { _, err := service.InitiateAsset(ctx, identities.tenantOwner, request); business <- err }()
		waitSignal(t, ctx, authorized, "session authorization")
		revoked := make(chan error, 1)
		go func() {
			_, err := fixture.pool.Exec(ctx, `UPDATE auth_sessions SET revoked_at=$2,revocation_reason='review'
				WHERE id=$1`, identities.tenantOwner.Credential.ID, storeTime(time.Now()))
			revoked <- err
		}()
		select {
		case err := <-revoked:
			t.Fatalf("session revocation bypassed authorization lock: %v", err)
		case <-time.After(25 * time.Millisecond):
		}
		close(release)
		if err := waitError(t, ctx, business, "session business"); err != nil {
			t.Fatal(err)
		}
		if err := waitError(t, ctx, revoked, "session revocation"); err != nil {
			t.Fatal(err)
		}
		if _, err := service.InitiateAsset(t.Context(), identities.tenantOwner, request); !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("post-revocation replay error=%v", err)
		}
		if _, err := fixture.pool.Exec(t.Context(), `UPDATE auth_sessions SET revoked_at=NULL,revocation_reason=NULL
			WHERE id=$1`, identities.tenantOwner.Credential.ID); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("revocation first", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		revocation, err := fixture.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer revocation.Rollback(context.Background())
		if _, err := revocation.Exec(ctx, `UPDATE auth_sessions SET revoked_at=$2,revocation_reason='review'
			WHERE id=$1`, identities.tenantOwner.Credential.ID, storeTime(time.Now())); err != nil {
			t.Fatal(err)
		}
		entered := make(chan struct{}, 1)
		authorizer, err := NewTenantSessionTxAuthorizer(reviewSessionHooks{delegate: rbac, entered: entered})
		if err != nil {
			t.Fatal(err)
		}
		service := newReviewService(t, fixture.pool, store, limits, authorizer)
		request := initiateRequest(identities.tenantScope, "session-revocation-first", []byte("revoked"), "text/plain")
		business := make(chan error, 1)
		go func() { _, err := service.InitiateAsset(ctx, identities.tenantOwner, request); business <- err }()
		waitSignal(t, ctx, entered, "session authorization entry")
		select {
		case err := <-business:
			t.Fatalf("business bypassed session revocation transaction: %v", err)
		case <-time.After(25 * time.Millisecond):
		}
		if err := revocation.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if err := waitError(t, ctx, business, "revoked session business"); !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("error=%v, want ErrPermissionDenied", err)
		}
	})
}

type reviewEntitlementHooks struct {
	entered    chan<- struct{}
	authorized chan<- struct{}
	release    <-chan struct{}
}

type postgresReviewLimits struct {
	hooks *reviewEntitlementHooks
}

func (provider postgresReviewLimits) Limits(
	ctx context.Context,
	tx pgx.Tx,
	check EntitlementCheck,
) (EntitlementLimits, error) {
	if provider.hooks != nil && provider.hooks.entered != nil {
		provider.hooks.entered <- struct{}{}
	}
	var enabled bool
	var limits EntitlementLimits
	err := tx.QueryRow(ctx, `SELECT enabled,max_asset_bytes,max_assets,max_total_bytes,max_rules,
		max_sites,max_publication_bytes FROM error_page_test_entitlements WHERE scope_id=$1 FOR SHARE`, check.ScopeID).
		Scan(&enabled, &limits.AssetQuota.MaxAssetBytes, &limits.AssetQuota.MaxAssets,
			&limits.AssetQuota.MaxTotalBytes, &limits.MaxRulesPerScope,
			&limits.MaxPublicationSites, &limits.MaxPublicationBytes)
	if errors.Is(err, pgx.ErrNoRows) {
		return EntitlementLimits{}, ErrEntitlementDenied
	}
	if err != nil {
		return EntitlementLimits{}, err
	}
	if !enabled {
		return EntitlementLimits{}, ErrEntitlementDenied
	}
	limits.FeatureEnabled = true
	if provider.hooks != nil && provider.hooks.authorized != nil {
		provider.hooks.authorized <- struct{}{}
	}
	if provider.hooks != nil && provider.hooks.release != nil {
		select {
		case <-ctx.Done():
			return EntitlementLimits{}, ctx.Err()
		case <-provider.hooks.release:
		}
	}
	return limits, nil
}

func TestReviewEntitlementRevocationReplayAndCommitOrder(t *testing.T) {
	fixture := openErrorPageDatabase(t)
	identities := seedErrorPageIdentities(t, fixture.pool)
	if _, err := fixture.pool.Exec(t.Context(), `CREATE TABLE error_page_test_entitlements(
		scope_id uuid PRIMARY KEY,enabled boolean NOT NULL,max_asset_bytes bigint NOT NULL,
		max_assets bigint NOT NULL,max_total_bytes bigint NOT NULL,max_rules integer NOT NULL,
		max_sites integer NOT NULL,max_publication_bytes bigint NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO error_page_test_entitlements VALUES
		($1,true,$2,100,8388608,$3,$4,$5)`, identities.tenantScope, MaxEdgeResourceBytes,
		MaxEdgeRulesPerScope, MaxPublicationSites, MaxEdgePolicyBytes); err != nil {
		t.Fatal(err)
	}
	store := newMemoryContentStore()
	service := newReviewService(t, fixture.pool, store, postgresReviewLimits{}, testTxAuthorizer{})
	completed := initiateRequest(identities.tenantScope, "entitlement-completed", []byte("completed"), "text/plain")
	if _, err := service.InitiateAsset(t.Context(), identities.tenantOwner, completed); err != nil {
		t.Fatal(err)
	}
	activeAsset := readyAsset(t, service, identities.tenantOwner, identities.tenantScope,
		"entitlement-active", []byte("active"), "text/plain")
	activeRule, err := service.CreateRule(t.Context(), identities.tenantOwner, CreateRuleRequest{
		Target: RuleTarget{Kind: ScopeSite, ScopeID: identities.tenantScope, SiteID: &identities.siteID},
		Fields: RuleFields{Category: CategoryOriginResponse,
			Match: StatusSelector{Kind: MatchExact, From: 519}, AssetID: activeAsset.ID, Enabled: true},
		WriteMetadata: writeMetadata("entitlement-active-rule"),
	})
	if err != nil {
		t.Fatal(err)
	}
	inProgress := initiateRequest(identities.tenantScope, "entitlement-in-progress", []byte("pending"), "text/plain")
	insertIncompleteInitiate(t, fixture.pool, identities.tenantOwner, inProgress)
	if _, err := fixture.pool.Exec(t.Context(), `UPDATE error_page_test_entitlements SET enabled=false WHERE scope_id=$1`,
		identities.tenantScope); err != nil {
		t.Fatal(err)
	}
	before := reviewFactCounts(t, fixture.pool)
	for name, request := range map[string]InitiateAssetRequest{
		"completed": completed, "in_progress": inProgress,
		"fresh": initiateRequest(identities.tenantScope, "entitlement-fresh", []byte("fresh"), "text/plain"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := service.InitiateAsset(t.Context(), identities.tenantOwner, request); !errors.Is(err, ErrEntitlementDenied) {
				t.Fatalf("error=%v, want ErrEntitlementDenied", err)
			}
		})
	}
	if after := reviewFactCounts(t, fixture.pool); after != before {
		t.Fatalf("facts changed on entitlement denial: before=%v after=%v", before, after)
	}
	snapshot, err := service.PublicationSnapshot(t.Context(), identities.platform)
	if err != nil {
		t.Fatal(err)
	}
	published := false
	for _, site := range snapshot.Policy.Sites {
		for _, rule := range site.Rules {
			published = published || rule.ID == activeRule.Value.ID.String()
		}
	}
	if !published {
		t.Fatal("lease revocation interrupted the already-active publication")
	}
	disabled, err := service.DisableRule(t.Context(), identities.tenantOwner, ChangeRuleStateRequest{
		RuleID: activeRule.Value.ID, ExpectedRevision: activeRule.Value.Revision,
		WriteMetadata: writeMetadata("entitlement-disable"),
	})
	if err != nil {
		t.Fatalf("disable under revoked entitlement: %v", err)
	}
	if _, err := service.DeleteRule(t.Context(), identities.tenantOwner, ChangeRuleStateRequest{
		RuleID: disabled.Value.ID, ExpectedRevision: disabled.Value.Revision,
		WriteMetadata: writeMetadata("entitlement-delete-rule"),
	}); err != nil {
		t.Fatalf("delete rule under revoked entitlement: %v", err)
	}
	if _, err := service.DeleteAsset(t.Context(), identities.tenantOwner, DeleteAssetRequest{
		AssetID: activeAsset.ID, ExpectedRevision: activeAsset.Revision,
		WriteMetadata: writeMetadata("entitlement-delete-asset"),
	}); err != nil {
		t.Fatalf("delete asset under revoked entitlement: %v", err)
	}
	if _, err := fixture.pool.Exec(t.Context(), `UPDATE error_page_test_entitlements SET enabled=true WHERE scope_id=$1`,
		identities.tenantScope); err != nil {
		t.Fatal(err)
	}

	t.Run("business first", func(t *testing.T) {
		authorized := make(chan struct{}, 1)
		release := make(chan struct{})
		blocked := newReviewService(t, fixture.pool, store, postgresReviewLimits{hooks: &reviewEntitlementHooks{
			authorized: authorized, release: release,
		}}, testTxAuthorizer{})
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		request := initiateRequest(identities.tenantScope, "entitlement-business-first", []byte("business"), "text/plain")
		business := make(chan error, 1)
		go func() { _, err := blocked.InitiateAsset(ctx, identities.tenantOwner, request); business <- err }()
		waitSignal(t, ctx, authorized, "entitlement authorization")
		revoked := make(chan error, 1)
		go func() {
			_, err := fixture.pool.Exec(ctx, `UPDATE error_page_test_entitlements SET enabled=false WHERE scope_id=$1`,
				identities.tenantScope)
			revoked <- err
		}()
		select {
		case err := <-revoked:
			t.Fatalf("revocation bypassed entitlement lock: %v", err)
		case <-time.After(25 * time.Millisecond):
		}
		close(release)
		if err := waitError(t, ctx, business, "entitlement business"); err != nil {
			t.Fatal(err)
		}
		if err := waitError(t, ctx, revoked, "entitlement revocation"); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("revocation first", func(t *testing.T) {
		if _, err := fixture.pool.Exec(t.Context(), `UPDATE error_page_test_entitlements SET enabled=true WHERE scope_id=$1`,
			identities.tenantScope); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		revocation, err := fixture.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer revocation.Rollback(context.Background())
		if _, err := revocation.Exec(ctx, `UPDATE error_page_test_entitlements SET enabled=false WHERE scope_id=$1`,
			identities.tenantScope); err != nil {
			t.Fatal(err)
		}
		entered := make(chan struct{}, 1)
		blocked := newReviewService(t, fixture.pool, store, postgresReviewLimits{hooks: &reviewEntitlementHooks{
			entered: entered,
		}}, testTxAuthorizer{})
		request := initiateRequest(identities.tenantScope, "entitlement-revocation-first", []byte("revoked"), "text/plain")
		business := make(chan error, 1)
		go func() { _, err := blocked.InitiateAsset(ctx, identities.tenantOwner, request); business <- err }()
		waitSignal(t, ctx, entered, "entitlement entry")
		select {
		case err := <-business:
			t.Fatalf("business bypassed revocation transaction: %v", err)
		case <-time.After(25 * time.Millisecond):
		}
		if err := revocation.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if err := waitError(t, ctx, business, "revoked entitlement business"); !errors.Is(err, ErrEntitlementDenied) {
			t.Fatalf("error=%v, want ErrEntitlementDenied", err)
		}
	})
}

func newReviewService(
	t *testing.T,
	pool *pgxpool.Pool,
	store ContentStore,
	limits LimitProvider,
	authorizer TxAuthorizer,
) *Service {
	t.Helper()
	service, err := NewServiceWithDependencies(
		pool, store, &testScanner{name: "review-scanner"}, limits, audit.New(pool), time.Now, authorizer,
	)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func insertIncompleteInitiate(
	t *testing.T,
	pool *pgxpool.Pool,
	actor Actor,
	request InitiateAssetRequest,
) {
	t.Helper()
	digest, err := digestRequest(struct {
		Target AssetTarget `json:"target"`
		MIME   string      `json:"mime"`
		Size   int64       `json:"size"`
		SHA256 string      `json:"sha256"`
	}{request.Target, request.MIME, request.Size, request.SHA256})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO error_page_write_requests(
		id,actor_user_id,actor_scope_id,target_scope_id,operation,idempotency_key,request_digest,
		request_id,trace_id,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		uuid.New(), actor.UserID, actor.ScopeID, request.Target.ScopeID, operationAssetInitiate,
		request.IdempotencyKey, digest[:], request.RequestID, request.TraceID, storeTime(time.Now())); err != nil {
		t.Fatal(err)
	}
}

type reviewCounts struct {
	assets int
	writes int
	audits int
}

func reviewFactCounts(t *testing.T, pool *pgxpool.Pool) reviewCounts {
	t.Helper()
	var counts reviewCounts
	if err := pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM error_page_assets),
		(SELECT count(*) FROM error_page_write_requests),
		(SELECT count(*) FROM audit_events WHERE action LIKE 'error_page.%')`).
		Scan(&counts.assets, &counts.writes, &counts.audits); err != nil {
		t.Fatal(err)
	}
	return counts
}

type mutatingReviewScanner struct {
	store *memoryContentStore
}

func (scanner mutatingReviewScanner) Name() string { return "mutating-review-scanner" }

func (scanner mutatingReviewScanner) Scan(ctx context.Context, input ScanInput) error {
	if _, err := io.ReadAll(input.Body); err != nil {
		return err
	}
	key := "error-pages/staging/" + input.AssetID.String()
	scanner.store.mu.Lock()
	object := scanner.store.objects[key]
	object.token = "replacement-" + uuid.NewString()
	scanner.store.objects[key] = object
	scanner.store.mu.Unlock()
	return ctx.Err()
}

type mismatchingFinalizeStore struct{ ContentStore }

func (store mismatchingFinalizeStore) Finalize(
	ctx context.Context,
	stagingRef, objectRef ObjectRef,
	expected ObjectInfo,
) (ObjectInfo, error) {
	info, err := store.ContentStore.Finalize(ctx, stagingRef, objectRef, expected)
	info.MIMEType = "application/json"
	return info, err
}

func TestReviewFinalObjectIntegrityFailuresStayNonReady(t *testing.T) {
	fixture := openErrorPageDatabase(t)
	identities := seedErrorPageIdentities(t, fixture.pool)
	limits := staticLimits{quota: AssetQuota{MaxAssetBytes: MaxEdgeResourceBytes, MaxAssets: 100, MaxTotalBytes: 8 << 20}}

	t.Run("staging replacement after scan", func(t *testing.T) {
		store := newMemoryContentStore()
		service, err := NewServiceWithDependencies(
			fixture.pool, store, mutatingReviewScanner{store: store}, limits,
			audit.New(fixture.pool), time.Now, testTxAuthorizer{},
		)
		if err != nil {
			t.Fatal(err)
		}
		body := []byte("replacement")
		asset := initiateAsset(t, service, identities.tenantOwner, identities.tenantScope, "replace", body, "text/plain")
		mustUpload(t, service, identities.tenantOwner, asset, "replace-upload", body)
		if _, err := service.FinalizeAsset(t.Context(), identities.tenantOwner,
			finalizeRequest(asset.ID, "replace-finalize")); !errors.Is(err, ErrConflict) {
			t.Fatalf("error=%v, want ErrConflict", err)
		}
		current, err := service.GetAsset(t.Context(), identities.tenantOwner, asset.ID)
		if err != nil {
			t.Fatal(err)
		}
		if current.Status != StatusFinalizing || store.exists(asset.storageObjectKey) {
			t.Fatalf("status=%s final_exists=%t", current.Status, store.exists(asset.storageObjectKey))
		}
	})

	t.Run("finalize returned metadata mismatch", func(t *testing.T) {
		base := newMemoryContentStore()
		store := mismatchingFinalizeStore{ContentStore: base}
		service := newReviewService(t, fixture.pool, store, limits, testTxAuthorizer{})
		body := []byte("metadata")
		asset := initiateAsset(t, service, identities.tenantOwner, identities.tenantScope, "metadata", body, "text/plain")
		mustUpload(t, service, identities.tenantOwner, asset, "metadata-upload", body)
		if _, err := service.FinalizeAsset(t.Context(), identities.tenantOwner,
			finalizeRequest(asset.ID, "metadata-finalize")); !errors.Is(err, ErrConflict) {
			t.Fatalf("error=%v, want ErrConflict", err)
		}
		current, err := service.GetAsset(t.Context(), identities.tenantOwner, asset.ID)
		if err != nil || current.Status != StatusFinalizing {
			t.Fatalf("status=%s err=%v", current.Status, err)
		}
	})
}

type reviewFinalStatStore struct {
	ContentStore
	finalKey string
	err      error
	mismatch bool
}

func (store reviewFinalStatStore) Stat(ctx context.Context, ref ObjectRef) (ObjectInfo, error) {
	if ref.LogicalKey == store.finalKey && store.err != nil {
		return ObjectInfo{}, store.err
	}
	info, err := store.ContentStore.Stat(ctx, ref)
	if ref.LogicalKey == store.finalKey && err == nil && store.mismatch {
		info.SHA256 = digestBytes([]byte("different final bytes"))
	}
	return info, err
}

type incapableReviewStore struct{ ContentStore }

func (incapableReviewStore) Capabilities() ObjectStoreCapabilities {
	return ObjectStoreCapabilities{}
}

func TestReviewReconcileFinalIntegrityFailures(t *testing.T) {
	for _, test := range []struct {
		name     string
		key      string
		headErr  error
		mismatch bool
		want     error
	}{
		{name: "final metadata mismatch", key: "metadata", mismatch: true, want: ErrConflict},
		{name: "final head failure", key: "head", headErr: errors.New("head unavailable"), want: ErrUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := openErrorPageDatabase(t)
			identities := seedErrorPageIdentities(t, fixture.pool)
			base := newMemoryContentStore()
			limits := staticLimits{quota: AssetQuota{
				MaxAssetBytes: MaxEdgeResourceBytes, MaxAssets: 100, MaxTotalBytes: 8 << 20,
			}}
			setup := newReviewService(t, fixture.pool, base, limits, testTxAuthorizer{})
			body := []byte("reconcile-final")
			asset := initiateAsset(t, setup, identities.tenantOwner, identities.tenantScope,
				"reconcile-"+test.key, body, "text/plain")
			mustUpload(t, setup, identities.tenantOwner, asset, "reconcile-upload-"+test.key, body)
			staged, err := base.Stat(t.Context(), assetObjectRef(asset, asset.stagingObjectKey))
			if err != nil {
				t.Fatal(err)
			}
			if err := setup.recordScan(t.Context(), identities.tenantOwner,
				writeMetadata("reconcile-scan-"+test.key), asset.ID, "passed", "",
				StatusFinalizing, staged.ImmutableToken); err != nil {
				t.Fatal(err)
			}
			store := reviewFinalStatStore{
				ContentStore: base, finalKey: asset.storageObjectKey, err: test.headErr, mismatch: test.mismatch,
			}
			service := newReviewService(t, fixture.pool, store, limits, testTxAuthorizer{})
			if _, err := service.ReconcileAssets(t.Context(), 100); !errors.Is(err, test.want) {
				t.Fatalf("error=%v, want %v", err, test.want)
			}
			current, err := setup.GetAsset(t.Context(), identities.tenantOwner, asset.ID)
			if err != nil || current.Status != StatusFinalizing {
				t.Fatalf("status=%s err=%v", current.Status, err)
			}
			var failures int
			if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events
				WHERE action='error_page.asset.reconcile' AND resource_id=$1 AND result='failure'`, asset.ID.String()).
				Scan(&failures); err != nil {
				t.Fatal(err)
			}
			if failures != 1 {
				t.Fatalf("failure audit count=%d", failures)
			}
		})
	}
}

func TestReviewReconcileBacklogFairnessAndFailureAuditDeduplication(t *testing.T) {
	t.Run("poison row does not starve later work", func(t *testing.T) {
		fixture := openErrorPageDatabase(t)
		identities := seedErrorPageIdentities(t, fixture.pool)
		base := newMemoryContentStore()
		limits := staticLimits{quota: AssetQuota{
			MaxAssetBytes: MaxEdgeResourceBytes, MaxAssets: 100, MaxTotalBytes: 8 << 20,
		}}
		setup := newReviewService(t, fixture.pool, base, limits, testTxAuthorizer{})
		poisonBody := []byte("poison-final")
		poison := initiateAsset(t, setup, identities.tenantOwner, identities.tenantScope,
			"reconcile-poison", poisonBody, "text/plain")
		mustUpload(t, setup, identities.tenantOwner, poison, "reconcile-poison-upload", poisonBody)
		staged, err := base.Stat(t.Context(), assetObjectRef(poison, poison.stagingObjectKey))
		if err != nil {
			t.Fatal(err)
		}
		if err := setup.recordScan(t.Context(), identities.tenantOwner,
			writeMetadata("reconcile-poison-scan"), poison.ID, "passed", "",
			StatusFinalizing, staged.ImmutableToken); err != nil {
			t.Fatal(err)
		}
		poison, err = setup.GetAsset(t.Context(), identities.tenantOwner, poison.ID)
		if err != nil {
			t.Fatal(err)
		}

		healthyBody := []byte("healthy-staging")
		healthy := initiateAsset(t, setup, identities.tenantOwner, identities.tenantScope,
			"reconcile-healthy", healthyBody, "text/plain")
		if _, err := base.PutStaging(t.Context(), assetObjectRef(healthy, healthy.stagingObjectKey),
			healthyBody, healthy.MIMEType); err != nil {
			t.Fatal(err)
		}
		worker := newReviewService(t, fixture.pool, reviewFinalStatStore{
			ContentStore: base, finalKey: poison.storageObjectKey, mismatch: true,
		}, limits, testTxAuthorizer{})

		if count, err := worker.ReconcileAssets(t.Context(), 1); count != 0 || !errors.Is(err, ErrConflict) {
			t.Fatalf("first reconcile count=%d error=%v, want 0 ErrConflict", count, err)
		}
		if count, err := worker.ReconcileAssets(t.Context(), 1); count != 1 || err != nil {
			t.Fatalf("second reconcile count=%d error=%v, want 1 nil", count, err)
		}
		healthy, err = setup.GetAsset(t.Context(), identities.tenantOwner, healthy.ID)
		if err != nil || healthy.Status != StatusStaged {
			t.Fatalf("healthy status=%s error=%v, want staged", healthy.Status, err)
		}
		newerBody := []byte("newer-staging")
		newer := initiateAsset(t, setup, identities.tenantOwner, identities.tenantScope,
			"reconcile-newer", newerBody, "text/plain")
		if _, err := base.PutStaging(t.Context(), assetObjectRef(newer, newer.stagingObjectKey),
			newerBody, newer.MIMEType); err != nil {
			t.Fatal(err)
		}
		if count, err := worker.ReconcileAssets(t.Context(), 1); count != 0 || !errors.Is(err, ErrConflict) {
			t.Fatalf("third reconcile count=%d error=%v, want 0 ErrConflict", count, err)
		}
		if count, err := worker.ReconcileAssets(t.Context(), 1); count != 1 || err != nil {
			t.Fatalf("fourth reconcile count=%d error=%v, want 1 nil", count, err)
		}
		var failures int
		if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events
			WHERE action='error_page.asset.reconcile' AND resource_id=$1 AND result='failure'`,
			poison.ID.String()).Scan(&failures); err != nil {
			t.Fatal(err)
		}
		if failures != 1 {
			t.Fatalf("failure audit count=%d, want 1", failures)
		}
	})

	t.Run("cleaned rejection does not occupy batch", func(t *testing.T) {
		fixture := openErrorPageDatabase(t)
		identities := seedErrorPageIdentities(t, fixture.pool)
		store := newMemoryContentStore()
		limits := staticLimits{quota: AssetQuota{
			MaxAssetBytes: MaxEdgeResourceBytes, MaxAssets: 100, MaxTotalBytes: 8 << 20,
		}}
		rejecting, err := NewServiceWithDependencies(
			fixture.pool, store, &testScanner{name: "reconcile-reject", err: ErrScanRejected}, limits,
			audit.New(fixture.pool), time.Now, testTxAuthorizer{},
		)
		if err != nil {
			t.Fatal(err)
		}
		rejectedBody := []byte("rejected-terminal")
		rejected := initiateAsset(t, rejecting, identities.tenantOwner, identities.tenantScope,
			"reconcile-rejected", rejectedBody, "text/plain")
		mustUpload(t, rejecting, identities.tenantOwner, rejected, "reconcile-rejected-upload", rejectedBody)
		if _, err := rejecting.FinalizeAsset(t.Context(), identities.tenantOwner,
			finalizeRequest(rejected.ID, "reconcile-rejected-finalize")); !errors.Is(err, ErrScanRejected) {
			t.Fatalf("finalize rejected error=%v, want ErrScanRejected", err)
		}
		rejected, err = rejecting.GetAsset(t.Context(), identities.tenantOwner, rejected.ID)
		if err != nil {
			t.Fatal(err)
		}
		if changed, err := rejecting.reconcileAsset(t.Context(), rejected); !changed || err != nil {
			t.Fatalf("cleanup changed=%t error=%v, want true nil", changed, err)
		}
		rejected, err = rejecting.GetAsset(t.Context(), identities.tenantOwner, rejected.ID)
		if err != nil || rejected.Status != StatusRejected || rejected.objectState != "absent" {
			t.Fatalf("rejected status=%s object_state=%s error=%v", rejected.Status, rejected.objectState, err)
		}

		healthyBody := []byte("healthy-after-rejected")
		healthy := initiateAsset(t, rejecting, identities.tenantOwner, identities.tenantScope,
			"reconcile-after-rejected", healthyBody, "text/plain")
		if _, err := store.PutStaging(t.Context(), assetObjectRef(healthy, healthy.stagingObjectKey),
			healthyBody, healthy.MIMEType); err != nil {
			t.Fatal(err)
		}
		worker := newReviewService(t, fixture.pool, store, limits, testTxAuthorizer{})
		if count, err := worker.ReconcileAssets(t.Context(), 1); count != 1 || err != nil {
			t.Fatalf("reconcile count=%d error=%v, want 1 nil", count, err)
		}
		healthy, err = worker.GetAsset(t.Context(), identities.tenantOwner, healthy.ID)
		if err != nil || healthy.Status != StatusStaged {
			t.Fatalf("healthy status=%s error=%v, want staged", healthy.Status, err)
		}
	})
}

type reviewScopeLimits struct {
	restrictedScope uuid.UUID
}

func (provider reviewScopeLimits) Limits(
	_ context.Context,
	_ pgx.Tx,
	check EntitlementCheck,
) (EntitlementLimits, error) {
	limits := EntitlementLimits{
		FeatureEnabled: true,
		AssetQuota: AssetQuota{
			MaxAssetBytes: MaxEdgeResourceBytes, MaxAssets: 100, MaxTotalBytes: 8 << 20,
		},
		MaxRulesPerScope: MaxEdgeRulesPerScope, MaxPublicationSites: MaxPublicationSites,
		MaxPublicationBytes: MaxEdgePolicyBytes,
	}
	if check.ScopeID == provider.restrictedScope {
		limits.MaxRulesPerScope = 1
		limits.MaxPublicationSites = 1
	}
	return limits, nil
}

func TestReviewScopedPublicationLimitsDoNotCrossTenants(t *testing.T) {
	fixture := openErrorPageDatabase(t)
	identities := seedErrorPageIdentities(t, fixture.pool)
	store := newMemoryContentStore()
	service := newReviewService(t, fixture.pool, store,
		reviewScopeLimits{restrictedScope: identities.tenantScope}, testTxAuthorizer{})

	otherFirstSite := siteIDForScope(t, fixture.pool, identities.otherTenantScope)
	otherSecondSite := seedAdditionalSite(t, fixture.pool, identities.otherTenantOwner,
		identities.otherTenantScope, "publication-other-second")
	otherAsset := readyAsset(t, service, identities.otherTenantOwner, identities.otherTenantScope,
		"publication-other", []byte("other tenant publication"), "text/plain")
	for index, siteID := range []uuid.UUID{otherFirstSite, otherSecondSite} {
		if _, err := service.CreateRule(t.Context(), identities.otherTenantOwner, CreateRuleRequest{
			Target: RuleTarget{Kind: ScopeSite, ScopeID: identities.otherTenantScope, SiteID: &siteID},
			Fields: RuleFields{
				Category: CategoryEdgeRoute,
				Match:    StatusSelector{Kind: MatchExact, From: 501 + index},
				AssetID:  otherAsset.ID,
				Enabled:  true,
			},
			WriteMetadata: writeMetadata(fmt.Sprintf("publication-other-rule-%d", index)),
		}); err != nil {
			t.Fatalf("create other tenant rule %d: %v", index, err)
		}
	}

	restrictedAsset := readyAsset(t, service, identities.tenantOwner, identities.tenantScope,
		"publication-restricted", []byte("restricted tenant publication"), "text/plain")
	result, err := service.CreateRule(t.Context(), identities.tenantOwner, CreateRuleRequest{
		Target: RuleTarget{Kind: ScopeSite, ScopeID: identities.tenantScope, SiteID: &identities.siteID},
		Fields: RuleFields{
			Category: CategoryEdgeRoute, Match: StatusSelector{Kind: MatchExact, From: 503},
			AssetID: restrictedAsset.ID, Enabled: true,
		},
		WriteMetadata: writeMetadata("publication-restricted-rule"),
	})
	if err != nil {
		t.Fatalf("restricted tenant first rule: %v", err)
	}
	if result.Value.Target.ScopeID != identities.tenantScope {
		t.Fatalf("restricted tenant rule scope=%s, want %s",
			result.Value.Target.ScopeID, identities.tenantScope)
	}
	snapshot, err := service.PublicationSnapshot(t.Context(), identities.platform)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Policy.Sites) != 3 {
		t.Fatalf("publication sites=%d, want 3", len(snapshot.Policy.Sites))
	}
}

func TestReviewFactoryRejectsObjectStoreWithoutRequiredCapabilities(t *testing.T) {
	fixture := openErrorPageDatabase(t)
	_, err := NewServiceWithDependencies(
		fixture.pool, incapableReviewStore{ContentStore: newMemoryContentStore()},
		&testScanner{name: "incapable-review-scanner"},
		staticLimits{quota: AssetQuota{MaxAssetBytes: 1, MaxAssets: 1, MaxTotalBytes: 1}},
		audit.New(fixture.pool), time.Now, testTxAuthorizer{},
	)
	if !errors.Is(err, ErrInvalidStore) {
		t.Fatalf("error=%v, want ErrInvalidStore", err)
	}
}

func TestReviewCurrentHeadMigrationPackageSmoke(t *testing.T) {
	fixture := openErrorPageDatabase(t)
	identities := seedErrorPageIdentities(t, fixture.pool)
	service := newReviewService(t, fixture.pool, newMemoryContentStore(), staticLimits{
		quota: AssetQuota{MaxAssetBytes: MaxEdgeResourceBytes, MaxAssets: 10, MaxTotalBytes: 8 << 20},
	}, testTxAuthorizer{})
	request := initiateRequest(identities.tenantScope, "current-head-smoke", []byte("current-head"), "text/plain")
	result, err := service.InitiateAsset(t.Context(), identities.tenantOwner, request)
	if err != nil || result.Value.Status != StatusInitiated {
		t.Fatalf("status=%s err=%v", result.Value.Status, err)
	}
}

type pidReviewAuthorizer struct {
	delegate TxAuthorizer
	pid      chan<- int
}

func (authorizer pidReviewAuthorizer) Authorize(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	permission string,
) error {
	if err := authorizer.delegate.Authorize(ctx, tx, actor, permission); err != nil {
		return err
	}
	var pid int
	if err := tx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		return err
	}
	select {
	case authorizer.pid <- pid:
	default:
	}
	return nil
}

func TestReviewAssetDeleteAndRuleEnableSharePublicationLock(t *testing.T) {
	fixture := openErrorPageDatabase(t)
	identities := seedErrorPageIdentities(t, fixture.pool)
	store := newMemoryContentStore()
	limits := staticLimits{quota: AssetQuota{MaxAssetBytes: MaxEdgeResourceBytes, MaxAssets: 1000, MaxTotalBytes: 64 << 20}}
	setup := newReviewService(t, fixture.pool, store, limits, testTxAuthorizer{})
	for _, first := range []string{"enable", "delete"} {
		t.Run(first+"-first", func(t *testing.T) {
			body := []byte("lock-" + first)
			asset := readyAsset(t, setup, identities.tenantOwner, identities.tenantScope, "lock-"+first, body, "text/plain")
			created, err := setup.CreateRule(t.Context(), identities.tenantOwner, CreateRuleRequest{
				Target: RuleTarget{Kind: ScopeSite, ScopeID: identities.tenantScope, SiteID: &identities.siteID},
				Fields: RuleFields{Category: CategoryOriginResponse,
					Match: StatusSelector{Kind: MatchExact, From: 520}, AssetID: asset.ID},
				WriteMetadata: writeMetadata("lock-rule-" + first),
			})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
			defer cancel()
			gate, err := fixture.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer gate.Rollback(context.Background())
			if err := lockPublication(ctx, gate); err != nil {
				t.Fatal(err)
			}
			type contender struct {
				name string
				pid  chan int
				run  func(*Service) error
			}
			enable := contender{name: "enable", pid: make(chan int, 1), run: func(service *Service) error {
				_, err := service.EnableRule(ctx, identities.tenantOwner, ChangeRuleStateRequest{
					RuleID: created.Value.ID, ExpectedRevision: created.Value.Revision,
					WriteMetadata: writeMetadata("lock-enable-" + first),
				})
				return err
			}}
			remove := contender{name: "delete", pid: make(chan int, 1), run: func(service *Service) error {
				_, err := service.DeleteAsset(ctx, identities.tenantOwner, DeleteAssetRequest{
					AssetID: asset.ID, ExpectedRevision: asset.Revision,
					WriteMetadata: writeMetadata("lock-delete-" + first),
				})
				return err
			}}
			ordered := []contender{enable, remove}
			if first == "delete" {
				ordered = []contender{remove, enable}
			}
			results := make(chan struct {
				name string
				err  error
			}, 2)
			for _, candidate := range ordered {
				candidate := candidate
				service := newReviewService(t, fixture.pool, store, limits, pidReviewAuthorizer{
					delegate: testTxAuthorizer{}, pid: candidate.pid,
				})
				go func() {
					results <- struct {
						name string
						err  error
					}{candidate.name, candidate.run(service)}
				}()
				pid := <-candidate.pid
				waitForReviewAdvisoryLock(t, ctx, fixture.pool, pid)
			}
			if err := gate.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			outcomes := map[string]error{}
			for range 2 {
				outcome := <-results
				outcomes[outcome.name] = outcome.err
			}
			if outcomes[first] != nil || !errors.Is(outcomes[ordered[1].name], ErrConflict) {
				t.Fatalf("first=%s outcomes=%v", first, outcomes)
			}
			currentAsset, err := setup.GetAsset(t.Context(), identities.tenantOwner, asset.ID)
			if err != nil {
				t.Fatal(err)
			}
			currentRule, err := setup.GetRule(t.Context(), identities.tenantOwner, created.Value.ID)
			if err != nil {
				t.Fatal(err)
			}
			if currentRule.Fields.Enabled && currentAsset.Status == StatusDeletePending {
				t.Fatalf("enabled rule references delete-pending asset: rule=%#v asset=%#v", currentRule, currentAsset)
			}
			snapshot, err := setup.PublicationSnapshot(t.Context(), identities.platform)
			if err != nil {
				t.Fatal(err)
			}
			published := false
			for _, site := range snapshot.Policy.Sites {
				for _, rule := range site.Rules {
					published = published || rule.ID == currentRule.ID.String()
				}
			}
			if published != currentRule.Fields.Enabled || published && currentAsset.Status != StatusReady {
				t.Fatalf("snapshot published=%t rule_enabled=%t asset_status=%s",
					published, currentRule.Fields.Enabled, currentAsset.Status)
			}
		})
	}
}

func waitForReviewAdvisoryLock(t *testing.T, ctx context.Context, pool *pgxpool.Pool, pid int) {
	t.Helper()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		var waitEvent string
		if err := pool.QueryRow(ctx, `SELECT COALESCE(wait_event,'') FROM pg_stat_activity WHERE pid=$1`, pid).
			Scan(&waitEvent); err != nil {
			t.Fatal(err)
		}
		if waitEvent == "advisory" || waitEvent == "AdvisoryLock" {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("pid %d did not wait for publication lock: %v", pid, ctx.Err())
		case <-ticker.C:
		}
	}
}

func TestReviewAssetRulePublicationDeadlockStress(t *testing.T) {
	fixture := openErrorPageDatabase(t)
	identities := seedErrorPageIdentities(t, fixture.pool)
	store := newMemoryContentStore()
	limits := staticLimits{quota: AssetQuota{MaxAssetBytes: MaxEdgeResourceBytes, MaxAssets: 1000, MaxTotalBytes: 64 << 20}}
	service := newReviewService(t, fixture.pool, store, limits, testTxAuthorizer{})
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	for round := 0; round < 16; round++ {
		body := []byte(fmt.Sprintf("stress-%d", round))
		asset := readyAsset(t, service, identities.tenantOwner, identities.tenantScope,
			fmt.Sprintf("stress-%d", round), body, "text/plain")
		created, err := service.CreateRule(ctx, identities.tenantOwner, CreateRuleRequest{
			Target: RuleTarget{Kind: ScopeSite, ScopeID: identities.tenantScope, SiteID: &identities.siteID},
			Fields: RuleFields{Category: CategoryOriginResponse,
				Match: StatusSelector{Kind: MatchExact, From: 530 + round%10}, AssetID: asset.ID},
			WriteMetadata: writeMetadata(fmt.Sprintf("stress-rule-%d", round)),
		})
		if err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		results := make(chan error, 2)
		var ready sync.WaitGroup
		ready.Add(2)
		go func() {
			ready.Done()
			<-start
			_, err := service.EnableRule(ctx, identities.tenantOwner, ChangeRuleStateRequest{
				RuleID: created.Value.ID, ExpectedRevision: created.Value.Revision,
				WriteMetadata: writeMetadata(fmt.Sprintf("stress-enable-%d", round)),
			})
			results <- err
		}()
		go func() {
			ready.Done()
			<-start
			_, err := service.DeleteAsset(ctx, identities.tenantOwner, DeleteAssetRequest{
				AssetID: asset.ID, ExpectedRevision: asset.Revision,
				WriteMetadata: writeMetadata(fmt.Sprintf("stress-delete-%d", round)),
			})
			results <- err
		}()
		ready.Wait()
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
				t.Fatalf("round %d error=%v", round, err)
			}
		}
		if successes != 1 || conflicts != 1 {
			t.Fatalf("round %d successes=%d conflicts=%d", round, successes, conflicts)
		}
	}
}
