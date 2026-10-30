package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/site"
	"github.com/google/uuid"
)

func TestSiteBatchActionHTTPFlow(t *testing.T) {
	pool := isolatedTestPool(t)
	baseTime := time.Now().UTC().Truncate(time.Second)
	clockUnix := &atomic.Int64{}
	clockUnix.Store(baseTime.Unix())
	key := newSiteTestKey(t, "control-site-batch-key")
	trust := newSiteTestTrust(t, key)
	installSiteTestEntitlement(t, pool, trust, baseTime, siteTestLeaseOptions{serial: 1, limit: 100, key: key})
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	identityStore := identity.NewStore(pool)
	bootstrap, err := identityStore.BootstrapPlatformUser(
		context.Background(), "sitebatchadmin", "Site Batch Administrator", passwordHash, "site-batch-bootstrap",
	)
	if err != nil {
		t.Fatalf("BootstrapPlatformUser() error = %v", err)
	}
	insertTestUser(t, pool, bootstrap.ScopeID, "sitebatchviewer", "Site Batch Viewer", passwordHash, "active")
	tenantA := insertSiteTenant(t, pool, "tenant-site-batch-a", "tenant-batch-a", "Tenant Batch A", passwordHash)
	tenantB := insertSiteTenant(t, pool, "tenant-site-batch-b", "tenant-batch-b", "Tenant Batch B", passwordHash)
	tokens, err := identity.NewTokenManager("site-batch-secret-at-least-thirty-two-bytes", 5*time.Minute)
	if err != nil {
		t.Fatalf("NewTokenManager() error = %v", err)
	}
	identityService, err := identity.NewService(identityStore, tokens, 24*time.Hour)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	server := httptest.NewServer(New(pool, identityService, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32),
		CookieSecure:     false,
		EntitlementTrust: trust,
		Now: func() time.Time {
			return time.Unix(clockUnix.Load(), 0).UTC()
		},
	}).Handler())
	t.Cleanup(server.Close)
	client := server.Client()
	platformAuth, _ := loginOK(t, client, server.URL, "sitebatchadmin")
	viewerAuth, _ := loginOK(t, client, server.URL, "sitebatchviewer")
	tenantAAuth := loginForScope(t, client, server.URL, tenantA.username, tenantA.scopeID)
	tenantBAuth := loginForScope(t, client, server.URL, tenantB.username, tenantB.scopeID)
	sameUserTenantBRoleID := uuid.New()
	// Non-system roles may only be created through custom RBAC facts (042);
	// a fixture role is inserted as a system role, as in the node fixtures.
	if _, err := pool.Exec(context.Background(), `INSERT INTO memberships (scope_id, user_id) VALUES ($1, $2)`,
		tenantB.scopeID, tenantA.userID); err != nil {
		t.Fatalf("grant same user second site batch membership: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `INSERT INTO roles (id, scope_id, name, system_role) VALUES ($1, $2, 'site-batch-cross-scope', true)`,
		sameUserTenantBRoleID, tenantB.scopeID); err != nil {
		t.Fatalf("create same user second site batch role: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `INSERT INTO role_assignments (scope_id, user_id, role_id) VALUES ($1, $2, $3)`,
		tenantB.scopeID, tenantA.userID, sameUserTenantBRoleID); err != nil {
		t.Fatalf("assign same user second site batch role: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO role_permissions (role_id, permission_name)
		VALUES ($1, 'sites.read'), ($1, 'sites.manage')`, sameUserTenantBRoleID); err != nil {
		t.Fatalf("grant same user access to second site batch scope: %v", err)
	}
	sameUserTenantBAuth := loginForScope(t, client, server.URL, tenantA.username, tenantB.scopeID)

	t.Run("authentication and request validation", func(t *testing.T) {
		valid := batchSiteActionRequest{Action: site.BatchActionEnable, Items: []site.BatchActionItem{{ID: uuid.New(), ExpectedRevision: 1}}}
		response := siteRequest(t, client, http.MethodPost, server.URL+"/v1/sites/batch-action", valid, "", "batch-unauthenticated", "")
		assertError(t, response, http.StatusUnauthorized, "invalid_session", "")
		response.Body.Close()
		response = siteRequest(t, client, http.MethodPost, server.URL+"/v1/sites/batch-action", valid, viewerAuth.AccessToken, "batch-viewer", "")
		assertError(t, response, http.StatusForbidden, "permission_denied", "")
		response.Body.Close()
		response = siteRequest(t, client, http.MethodPost, server.URL+"/v1/sites/batch-action", valid, tenantAAuth.AccessToken, "", "")
		assertError(t, response, http.StatusBadRequest, "validation_error", "")
		response.Body.Close()

		duplicateID := uuid.New()
		invalidBodies := []batchSiteActionRequest{
			{Action: "start", Items: valid.Items},
			{Action: site.BatchActionEnable},
			{Action: site.BatchActionEnable, Items: []site.BatchActionItem{
				{ID: duplicateID, ExpectedRevision: 1}, {ID: duplicateID, ExpectedRevision: 2},
			}},
		}
		tooMany := batchSiteActionRequest{Action: site.BatchActionDelete, Items: make([]site.BatchActionItem, 101)}
		for index := range tooMany.Items {
			tooMany.Items[index] = site.BatchActionItem{ID: uuid.New(), ExpectedRevision: 1}
		}
		invalidBodies = append(invalidBodies, tooMany)
		for index, body := range invalidBodies {
			response = siteRequest(t, client, http.MethodPost, server.URL+"/v1/sites/batch-action", body,
				tenantAAuth.AccessToken, fmt.Sprintf("batch-invalid-%d", index), "")
			assertError(t, response, http.StatusBadRequest, "validation_error", "")
			response.Body.Close()
		}
	})

	tenantAFirst := createSite(t, client, server.URL, tenantAAuth.AccessToken, "batch-create-a-first", createSiteRequest{
		Basic: disabledSiteBasic("batch-a-first.example", "192.0.2.101"),
	})
	tenantALocked := createSite(t, client, server.URL, tenantAAuth.AccessToken, "batch-create-a-locked", createSiteRequest{
		Basic: disabledSiteBasic("batch-a-locked.example", "192.0.2.102"),
	})
	tenantBFirst := createSite(t, client, server.URL, tenantBAuth.AccessToken, "batch-create-b-first", createSiteRequest{
		Basic: disabledSiteBasic("batch-b-first.example", "192.0.2.103"),
	})
	lockResponse := siteRequest(t, client, http.MethodPost, server.URL+"/v1/sites/"+tenantALocked.ID.String()+"/lock",
		lockSiteRequest{ExpectedVersion: 1, Reason: "Batch lock test"}, platformAuth.AccessToken, "batch-lock-a", "")
	var locked siteDetailResponse
	decodeResponse(t, lockResponse, http.StatusOK, &locked)
	lockResponse.Body.Close()

	t.Run("same user idempotency is isolated across scopes", func(t *testing.T) {
		body := batchSiteActionRequest{
			Action: site.BatchActionEnable,
			Items:  []site.BatchActionItem{{ID: tenantALocked.ID, ExpectedRevision: locked.Version}},
		}
		const key = "batch-same-user-cross-scope"

		tenantAResult := batchSiteActionOK(t, client, server.URL, tenantAAuth.AccessToken, key, body)
		if len(tenantAResult.Items) != 1 {
			t.Fatalf("tenant A cross-scope result = %#v", tenantAResult)
		}
		assertBatchFailure(t, tenantAResult.Items[0], "site_locked")

		tenantBResult := batchSiteActionOK(t, client, server.URL, sameUserTenantBAuth.AccessToken, key, body)
		if len(tenantBResult.Items) != 1 {
			t.Fatalf("tenant B cross-scope result = %#v", tenantBResult)
		}
		assertBatchFailure(t, tenantBResult.Items[0], "site_not_found")

		tenantBReplay := batchSiteActionOK(t, client, server.URL, sameUserTenantBAuth.AccessToken, key, body)
		if encoded, _ := json.Marshal(tenantBReplay); string(encoded) != mustJSON(t, tenantBResult) {
			t.Fatalf("tenant B replay = %s, want %s", encoded, mustJSON(t, tenantBResult))
		}

		rows, err := pool.Query(context.Background(), `
			SELECT actor_scope_id
			FROM site_batch_write_requests
			WHERE actor_user_id = $1 AND idempotency_key = $2
			ORDER BY actor_scope_id`, tenantA.userID, key)
		if err != nil {
			t.Fatalf("query cross-scope batch writes: %v", err)
		}
		defer rows.Close()
		var scopes []uuid.UUID
		for rows.Next() {
			var scopeID uuid.UUID
			if err := rows.Scan(&scopeID); err != nil {
				t.Fatalf("scan cross-scope batch write: %v", err)
			}
			scopes = append(scopes, scopeID)
		}
		if err := rows.Err(); err != nil {
			t.Fatalf("iterate cross-scope batch writes: %v", err)
		}
		sort.Slice(scopes, func(i, j int) bool { return scopes[i].String() < scopes[j].String() })
		wantScopes := []uuid.UUID{tenantA.scopeID, tenantB.scopeID}
		sort.Slice(wantScopes, func(i, j int) bool { return wantScopes[i].String() < wantScopes[j].String() })
		if len(scopes) != 2 || scopes[0] != wantScopes[0] || scopes[1] != wantScopes[1] {
			t.Fatalf("cross-scope batch write scopes = %v, want %v", scopes, wantScopes)
		}
	})

	t.Run("ordered partial success isolation lock and replay", func(t *testing.T) {
		listSnapshot := listSites(t, client, server.URL+"/v1/sites?page=1&limit=100", tenantAAuth.AccessToken)
		body := batchSiteActionRequest{Action: site.BatchActionEnable, Items: []site.BatchActionItem{
			{ID: tenantBFirst.ID, ExpectedRevision: 1},
			{ID: tenantAFirst.ID, ExpectedRevision: siteListVersion(t, listSnapshot, tenantAFirst.ID)},
			{ID: tenantALocked.ID, ExpectedRevision: siteListVersion(t, listSnapshot, tenantALocked.ID)},
		}}
		response := siteRequest(t, client, http.MethodPost, server.URL+"/v1/sites/batch-action", body,
			tenantAAuth.AccessToken, "batch-partial", "", "batch-partial-request")
		var result batchSiteActionResponse
		decodeResponse(t, response, http.StatusOK, &result)
		response.Body.Close()
		if len(result.Items) != 3 || result.Items[0].ID != tenantBFirst.ID || result.Items[1].ID != tenantAFirst.ID || result.Items[2].ID != tenantALocked.ID {
			t.Fatalf("batch result order = %#v", result.Items)
		}
		assertBatchFailure(t, result.Items[0], "site_not_found")
		if result.Items[1].Status != "updated" || result.Items[1].Site == nil || result.Items[1].Site.Version != 2 ||
			!result.Items[1].Site.Basic.Enabled || result.Items[1].Site.Owner != nil {
			t.Fatalf("batch updated item = %#v", result.Items[1])
		}
		assertBatchFailure(t, result.Items[2], "site_locked")
		if detail := getSite(t, client, server.URL, tenantBFirst.ID, tenantBAuth.AccessToken); detail.Version != 1 || detail.Basic.Enabled {
			t.Fatalf("cross-tenant site changed = %#v", detail)
		}

		var auditCount int
		if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE request_id = $1`, "batch-partial-request").Scan(&auditCount); err != nil {
			t.Fatalf("count batch audits: %v", err)
		}
		if auditCount != 3 {
			t.Fatalf("batch audit count = %d, want 3", auditCount)
		}
		response = siteRequest(t, client, http.MethodPost, server.URL+"/v1/sites/batch-action", body,
			tenantAAuth.AccessToken, "batch-partial", "", "batch-partial-replay-request")
		var replayed batchSiteActionResponse
		decodeResponse(t, response, http.StatusOK, &replayed)
		response.Body.Close()
		if encoded, _ := json.Marshal(replayed); string(encoded) != mustJSON(t, result) {
			t.Fatalf("batch replay = %s, want %s", encoded, mustJSON(t, result))
		}
		if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE request_id = $1`, "batch-partial-replay-request").Scan(&auditCount); err != nil {
			t.Fatalf("count replay audits: %v", err)
		}
		if auditCount != 0 {
			t.Fatalf("batch replay audit count = %d, want 0", auditCount)
		}
		changed := body
		changed.Action = site.BatchActionDisable
		response = siteRequest(t, client, http.MethodPost, server.URL+"/v1/sites/batch-action", changed,
			tenantAAuth.AccessToken, "batch-partial", "")
		assertError(t, response, http.StatusConflict, "idempotency_conflict", "")
		response.Body.Close()
	})

	t.Run("same state increments version", func(t *testing.T) {
		disable := func(key string, version int64) batchSiteActionResponse {
			return batchSiteActionOK(t, client, server.URL, tenantAAuth.AccessToken, key, batchSiteActionRequest{
				Action: site.BatchActionDisable,
				Items:  []site.BatchActionItem{{ID: tenantAFirst.ID, ExpectedRevision: version}},
			})
		}
		first := disable("batch-disable-first", 2)
		if first.Items[0].Site == nil || first.Items[0].Site.Version != 3 || first.Items[0].Site.Basic.Enabled {
			t.Fatalf("first disable = %#v", first)
		}
		second := disable("batch-disable-same-state", 3)
		if second.Items[0].Site == nil || second.Items[0].Site.Version != 4 || second.Items[0].Site.Basic.Enabled {
			t.Fatalf("same-state disable = %#v", second)
		}
	})

	t.Run("entitlement quota and grace contraction", func(t *testing.T) {
		quotaOne := createSite(t, client, server.URL, tenantAAuth.AccessToken, "batch-quota-create-one", createSiteRequest{
			Basic: disabledSiteBasic("batch-quota-one.example", "198.51.100.111"),
		})
		quotaTwo := createSite(t, client, server.URL, tenantAAuth.AccessToken, "batch-quota-create-two", createSiteRequest{
			Basic: disabledSiteBasic("batch-quota-two.example", "198.51.100.112"),
		})
		installSiteTestEntitlement(t, pool, trust, baseTime, siteTestLeaseOptions{serial: 2, limit: 1, key: key})
		quota := batchSiteActionOK(t, client, server.URL, tenantAAuth.AccessToken, "batch-quota-enable", batchSiteActionRequest{
			Action: site.BatchActionEnable,
			Items: []site.BatchActionItem{
				{ID: quotaTwo.ID, ExpectedRevision: 1},
				{ID: quotaOne.ID, ExpectedRevision: 1},
			},
		})
		var updated, denied int
		var enabledID, disabledID uuid.UUID
		disabledDomain := "batch-quota-two.example"
		for _, item := range quota.Items {
			switch item.Status {
			case "updated":
				updated++
				enabledID = item.ID
			case "failed":
				if item.Error == nil || item.Error.Code != "entitlement_quota_exceeded" {
					t.Fatalf("quota failure = %#v", item)
				}
				denied++
				disabledID = item.ID
			}
		}
		if updated != 1 || denied != 1 {
			t.Fatalf("quota batch = %#v", quota)
		}
		if disabledID == quotaOne.ID {
			disabledDomain = "batch-quota-one.example"
		}
		clockUnix.Store(baseTime.Add(90 * time.Minute).Unix())
		graceEnable := batchSiteActionOK(t, client, server.URL, tenantAAuth.AccessToken, "batch-grace-enable", batchSiteActionRequest{
			Action: site.BatchActionEnable,
			Items:  []site.BatchActionItem{{ID: disabledID, ExpectedRevision: 1}},
		})
		// A lease in grace stays usable (entitlementguard leaseUsable, user
		// decision 2026-10-21); enabling is still bounded by the quota.
		assertBatchFailure(t, graceEnable.Items[0], "entitlement_quota_exceeded")
		disableEnabled := batchSiteActionOK(t, client, server.URL, tenantAAuth.AccessToken, "batch-grace-disable", batchSiteActionRequest{
			Action: site.BatchActionDisable,
			Items:  []site.BatchActionItem{{ID: enabledID, ExpectedRevision: 2}},
		})
		if disableEnabled.Items[0].Site == nil || disableEnabled.Items[0].Site.Basic.Enabled || disableEnabled.Items[0].Site.Version != 3 {
			t.Fatalf("grace disable = %#v", disableEnabled)
		}
		deleted := batchSiteActionOK(t, client, server.URL, tenantAAuth.AccessToken, "batch-grace-delete", batchSiteActionRequest{
			Action: site.BatchActionDelete,
			Items:  []site.BatchActionItem{{ID: disabledID, ExpectedRevision: 1}},
		})
		if deleted.Items[0].Status != "deleted" || deleted.Items[0].Site != nil || deleted.Items[0].Error != nil {
			t.Fatalf("grace delete = %#v", deleted)
		}
		deleteReplay := batchSiteActionOK(t, client, server.URL, tenantAAuth.AccessToken, "batch-grace-delete", batchSiteActionRequest{
			Action: site.BatchActionDelete,
			Items:  []site.BatchActionItem{{ID: disabledID, ExpectedRevision: 1}},
		})
		if mustJSON(t, deleteReplay) != mustJSON(t, deleted) {
			t.Fatalf("delete replay = %s, want %s", mustJSON(t, deleteReplay), mustJSON(t, deleted))
		}
		clockUnix.Store(baseTime.Unix())
		recreated := createSite(t, client, server.URL, tenantAAuth.AccessToken, "batch-recreate-domain", createSiteRequest{
			Basic: disabledSiteBasic(disabledDomain, "198.51.100.113"),
		})
		if recreated.ID == disabledID {
			t.Fatal("soft-delete domain recreation reused the deleted site ID")
		}
	})

	t.Run("platform can maintain a locked site", func(t *testing.T) {
		installSiteTestEntitlement(t, pool, trust, baseTime, siteTestLeaseOptions{serial: 3, limit: 100, key: key})
		listSnapshot := listSites(t, client, server.URL+"/v1/sites?page=1&limit=100", platformAuth.AccessToken)
		result := batchSiteActionOK(t, client, server.URL, platformAuth.AccessToken, "batch-platform-locked-enable", batchSiteActionRequest{
			Action: site.BatchActionEnable,
			Items: []site.BatchActionItem{
				{ID: tenantBFirst.ID, ExpectedRevision: siteListVersion(t, listSnapshot, tenantBFirst.ID)},
				{ID: tenantALocked.ID, ExpectedRevision: siteListVersion(t, listSnapshot, tenantALocked.ID)},
			},
		})
		if len(result.Items) != 2 || result.Items[0].ID != tenantBFirst.ID || result.Items[0].Site == nil ||
			!result.Items[0].Site.Basic.Enabled || result.Items[0].Site.Owner == nil || result.Items[1].ID != tenantALocked.ID ||
			result.Items[1].Site == nil || !result.Items[1].Site.Basic.Enabled || !result.Items[1].Site.Lock.Locked || result.Items[1].Site.Owner == nil {
			t.Fatalf("platform locked maintenance = %#v", result)
		}
	})

	t.Run("concurrent CAS winner and reverse-order locking", func(t *testing.T) {
		installSiteTestEntitlement(t, pool, trust, baseTime, siteTestLeaseOptions{serial: 4, limit: 100, key: key})
		first := createSite(t, client, server.URL, tenantAAuth.AccessToken, "batch-race-create-first", createSiteRequest{
			Basic: disabledSiteBasic("batch-race-first.example", "203.0.113.121"),
		})
		second := createSite(t, client, server.URL, tenantAAuth.AccessToken, "batch-race-create-second", createSiteRequest{
			Basic: disabledSiteBasic("batch-race-second.example", "203.0.113.122"),
		})
		for round := 0; round < 12; round++ {
			firstDetail := getSite(t, client, server.URL, first.ID, tenantAAuth.AccessToken)
			secondDetail := getSite(t, client, server.URL, second.ID, tenantAAuth.AccessToken)
			action := site.BatchActionEnable
			if firstDetail.Basic.Enabled {
				action = site.BatchActionDisable
			}
			forward := batchSiteActionRequest{Action: action, Items: []site.BatchActionItem{
				{ID: first.ID, ExpectedRevision: firstDetail.Version}, {ID: second.ID, ExpectedRevision: secondDetail.Version},
			}}
			reverse := batchSiteActionRequest{Action: action, Items: []site.BatchActionItem{
				{ID: second.ID, ExpectedRevision: secondDetail.Version}, {ID: first.ID, ExpectedRevision: firstDetail.Version},
			}}
			type raceOutcome struct {
				status int
				result batchSiteActionResponse
				err    error
			}
			outcomes := concurrentSiteRequests(2, func(index int) raceOutcome {
				body := forward
				if index == 1 {
					body = reverse
				}
				response, err := performSiteRequest(client, http.MethodPost, server.URL+"/v1/sites/batch-action", body,
					tenantAAuth.AccessToken, fmt.Sprintf("batch-race-%d-%d", round, index), "")
				if err != nil {
					return raceOutcome{err: err}
				}
				defer response.Body.Close()
				outcome := raceOutcome{status: response.StatusCode}
				outcome.err = decodeSiteResponseBody(response.Body, &outcome.result)
				return outcome
			})
			statuses := make([]string, 0, 4)
			for _, outcome := range outcomes {
				if outcome.err != nil || outcome.status != http.StatusOK {
					t.Fatalf("race round %d outcome = %#v", round, outcome)
				}
				for _, item := range outcome.result.Items {
					if item.Status == "failed" && (item.Error == nil || item.Error.Code != "version_conflict") {
						t.Fatalf("race round %d unexpected failure = %#v", round, item)
					}
					statuses = append(statuses, item.Status)
				}
			}
			sort.Strings(statuses)
			if fmt.Sprint(statuses) != "[failed failed updated updated]" {
				t.Fatalf("race round %d statuses = %v", round, statuses)
			}
		}
	})

	t.Run("audit failure rolls back all state and idempotency", func(t *testing.T) {
		first := createSite(t, client, server.URL, tenantAAuth.AccessToken, "batch-rollback-create-first", createSiteRequest{
			Basic: validSiteBasic("batch-rollback-first.example", "203.0.113.131"),
		})
		second := createSite(t, client, server.URL, tenantAAuth.AccessToken, "batch-rollback-create-second", createSiteRequest{
			Basic: validSiteBasic("batch-rollback-second.example", "203.0.113.132"),
		})
		if _, err := pool.Exec(context.Background(), `
			CREATE FUNCTION fail_site_batch_audit() RETURNS trigger LANGUAGE plpgsql AS $$
			BEGIN
				IF NEW.request_id = 'batch-audit-fail-request' THEN
					RAISE EXCEPTION 'injected site batch audit failure';
				END IF;
				RETURN NEW;
			END $$;
			CREATE TRIGGER fail_site_batch_audit_trigger BEFORE INSERT ON audit_events
			FOR EACH ROW EXECUTE FUNCTION fail_site_batch_audit()`); err != nil {
			t.Fatalf("install audit failure trigger: %v", err)
		}
		body := batchSiteActionRequest{Action: site.BatchActionDisable, Items: []site.BatchActionItem{
			{ID: first.ID, ExpectedRevision: 1}, {ID: second.ID, ExpectedRevision: 1},
		}}
		response := siteRequest(t, client, http.MethodPost, server.URL+"/v1/sites/batch-action", body,
			tenantAAuth.AccessToken, "batch-audit-fail", "", "batch-audit-fail-request")
		assertError(t, response, http.StatusInternalServerError, "internal_error", "batch-audit-fail-request")
		response.Body.Close()
		if _, err := pool.Exec(context.Background(), `DROP TRIGGER fail_site_batch_audit_trigger ON audit_events; DROP FUNCTION fail_site_batch_audit()`); err != nil {
			t.Fatalf("remove audit failure trigger: %v", err)
		}
		for _, id := range []uuid.UUID{first.ID, second.ID} {
			detail := getSite(t, client, server.URL, id, tenantAAuth.AccessToken)
			if detail.Version != 1 || !detail.Basic.Enabled {
				t.Fatalf("site %s changed despite audit rollback: %#v", id, detail)
			}
		}
		var writeCount int
		if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM site_batch_write_requests WHERE idempotency_key = $1`, "batch-audit-fail").Scan(&writeCount); err != nil {
			t.Fatalf("count rolled back batch write: %v", err)
		}
		if writeCount != 0 {
			t.Fatalf("rolled back batch write count = %d, want 0", writeCount)
		}
	})

	for _, scopeID := range []uuid.UUID{bootstrap.ScopeID, tenantA.scopeID, tenantB.scopeID} {
		if err := audit.New(pool).VerifyScope(context.Background(), scopeID); err != nil {
			t.Fatalf("VerifyScope(%s) error = %v", scopeID, err)
		}
	}
}

func TestSiteBatchMigrationRollbackAndReapply(t *testing.T) {
	pool := migrationRoundTripPool(t, 12)
	ctx := context.Background()
	if err := database.Migrate(ctx, pool, "down"); err != nil {
		t.Fatalf("Migrate(down 012) error = %v", err)
	}
	var relation *string
	if err := pool.QueryRow(ctx, `SELECT to_regclass('site_batch_write_requests')::text`).Scan(&relation); err != nil {
		t.Fatalf("inspect site batch write table after rollback: %v", err)
	}
	if relation != nil {
		t.Fatalf("site_batch_write_requests still exists after rollback: %s", *relation)
	}
	if err := database.Migrate(ctx, pool, "up"); err != nil {
		t.Fatalf("Migrate(up 012) error = %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT to_regclass('site_batch_write_requests')::text`).Scan(&relation); err != nil {
		t.Fatalf("inspect site batch write table after reapply: %v", err)
	}
	if relation == nil {
		t.Fatal("site_batch_write_requests is missing after reapply")
	}
}

func batchSiteActionOK(
	t *testing.T,
	client *http.Client,
	baseURL string,
	accessToken string,
	key string,
	body batchSiteActionRequest,
) batchSiteActionResponse {
	t.Helper()
	response := siteRequest(t, client, http.MethodPost, baseURL+"/v1/sites/batch-action", body, accessToken, key, "")
	var result batchSiteActionResponse
	decodeResponse(t, response, http.StatusOK, &result)
	response.Body.Close()
	return result
}

func assertBatchFailure(t *testing.T, item batchSiteActionItemResponse, code string) {
	t.Helper()
	if item.Status != "failed" || item.Error == nil || item.Error.Code != code || item.Site != nil {
		t.Fatalf("batch item = %#v, want failed/%s", item, code)
	}
}

func siteListVersion(t *testing.T, snapshot site.ListResult, id uuid.UUID) int64 {
	t.Helper()
	for _, item := range snapshot.Items {
		if item.ID == id {
			if item.Revision < 1 {
				t.Fatalf("site %s list version = %d", id, item.Revision)
			}
			return item.Revision
		}
	}
	t.Fatalf("site %s missing from list snapshot", id)
	return 0
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	return string(encoded)
}
