package httpapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/site"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestSiteHTTPFlow(t *testing.T) {
	pool := isolatedTestPool(t)
	key := newSiteTestKey(t, "control-site-test-key")
	trust := newSiteTestTrust(t, key)
	installSiteTestEntitlement(t, pool, trust, time.Now(), siteTestLeaseOptions{serial: 1, limit: 100, key: key})
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	identityStore := identity.NewStore(pool)
	bootstrap, err := identityStore.BootstrapPlatformUser(
		context.Background(),
		"siteadmin",
		"Site Administrator",
		passwordHash,
		"site-test-bootstrap",
	)
	if err != nil {
		t.Fatalf("BootstrapPlatformUser() error = %v", err)
	}
	insertTestUser(t, pool, bootstrap.ScopeID, "siteviewer", "Platform Viewer", passwordHash, "active")
	tenantA := insertSiteTenant(t, pool, "tenant-site-a", "tenant-a-user", "Tenant A User", passwordHash)
	tenantB := insertSiteTenant(t, pool, "tenant-site-b", "tenant-b-user", "Tenant B User", passwordHash)
	readOnlyUserID := insertSiteScopeUser(t, pool, tenantA.scopeID, "tenant-a-reader", "Tenant A Reader", passwordHash, []string{"sites.read"})
	if readOnlyUserID == uuid.Nil {
		t.Fatal("read-only site user was not created")
	}

	tokens, err := identity.NewTokenManager("site-integration-secret-at-least-thirty-two-bytes", 5*time.Minute)
	if err != nil {
		t.Fatalf("NewTokenManager() error = %v", err)
	}
	identityService, err := identity.NewService(identityStore, tokens, 24*time.Hour)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	server := httptest.NewServer(New(pool, identityService, Config{
		CookieSecure:     false,
		EntitlementTrust: trust,
		APIKeyPepper:     bytes.Repeat([]byte{0x52}, 32),
	}).Handler())
	t.Cleanup(server.Close)
	client := server.Client()
	platformAuth, _ := loginOK(t, client, server.URL, "siteadmin")
	viewerAuth, _ := loginOK(t, client, server.URL, "siteviewer")
	tenantAAuth := loginForScope(t, client, server.URL, tenantA.username, tenantA.scopeID)
	tenantBAuth := loginForScope(t, client, server.URL, tenantB.username, tenantB.scopeID)
	tenantReaderAuth := loginForScope(t, client, server.URL, "tenant-a-reader", tenantA.scopeID)

	t.Run("authentication and RBAC", func(t *testing.T) {
		unauthenticated := siteRequest(t, client, http.MethodGet, server.URL+"/v1/sites", nil, "", "", "")
		assertError(t, unauthenticated, http.StatusUnauthorized, "invalid_session", "")
		unauthenticated.Body.Close()

		for name, token := range map[string]string{
			"platform without permission": viewerAuth.AccessToken,
		} {
			t.Run(name, func(t *testing.T) {
				response := siteRequest(t, client, http.MethodGet, server.URL+"/v1/sites", nil, token, "", "")
				assertError(t, response, http.StatusForbidden, "permission_denied", "")
				response.Body.Close()
			})
		}
	})

	// 带 package_id 建站要求属主有该产品的有效订阅（含 owner 投影），group_id 要求真实站点分组。
	packageID, groupID := insertSiteFlowPackageAndGroup(t, pool, tenantA)
	packageName := "Business"
	groupName := "Production"
	platformCreateBody := createSiteRequest{
		TargetScopeID: tenantA.scopeID.String(),
		OwnerID:       tenantA.userID.String(),
		Basic:         validSiteBasic("www.alpha.example", "192.0.2.10:8080"),
		OriginPool: &site.OriginPool{
			Origins:          []site.Origin{{Host: "192.0.2.10", Port: 8080, Weight: 75, Enabled: true}},
			BalanceMethod:    site.BalanceURLHash,
			FailoverTries:    1,
			ConnectTimeoutMS: 500,
			ReadTimeoutMS:    5000,
		},
	}
	platformCreateBody.Basic.CNAME = "alpha.edge.example"
	platformCreateBody.Basic.PackageID = &packageID
	platformCreateBody.Basic.PackageName = &packageName
	platformCreateBody.Basic.GroupID = &groupID
	platformCreateBody.Basic.GroupName = &groupName

	createdA := createSite(t, client, server.URL, platformAuth.AccessToken, "create-alpha", platformCreateBody)
	if createdA.DisplayID != "1" || createdA.Version != 1 || createdA.Owner == nil || createdA.Owner.ID != tenantA.userID {
		t.Fatalf("created platform site = %#v", createdA)
	}
	if createdA.OriginPool.BalanceMethod != site.BalanceURLHash || createdA.OriginPool.Origins[0].Weight != 75 ||
		createdA.OriginPool.ConnectTimeoutMS != 500 || createdA.OriginPool.ReadTimeoutMS != 5000 {
		t.Fatalf("created platform origin pool = %#v", createdA.OriginPool)
	}

	t.Run("create idempotency and validation", func(t *testing.T) {
		replayed := createSite(t, client, server.URL, platformAuth.AccessToken, "create-alpha", platformCreateBody)
		if replayed.ID != createdA.ID || replayed.DisplayID != createdA.DisplayID || replayed.Version != createdA.Version {
			t.Fatalf("create replay = %#v, want site %s version %d", replayed, createdA.ID, createdA.Version)
		}

		conflictingBody := platformCreateBody
		conflictingBody.Basic = validSiteBasic("changed.alpha.example", "192.0.2.11")
		conflictingBody.OriginPool = nil // 源站池须与 Basic.Origins 一致，否则先被 400 拒，测不到幂等冲突
		conflict := siteRequest(t, client, http.MethodPost, server.URL+"/v1/sites", conflictingBody, platformAuth.AccessToken, "create-alpha", "")
		assertError(t, conflict, http.StatusConflict, "idempotency_conflict", "")
		conflict.Body.Close()

		poolConflictBody := platformCreateBody
		changedPool := *platformCreateBody.OriginPool
		changedPool.BalanceMethod = site.BalanceLeastConn
		poolConflictBody.OriginPool = &changedPool
		poolConflict := siteRequest(t, client, http.MethodPost, server.URL+"/v1/sites", poolConflictBody, platformAuth.AccessToken, "create-alpha", "")
		assertError(t, poolConflict, http.StatusConflict, "idempotency_conflict", "")
		poolConflict.Body.Close()

		missingKey := siteRequest(t, client, http.MethodPost, server.URL+"/v1/sites", platformCreateBody, platformAuth.AccessToken, "", "")
		assertError(t, missingKey, http.StatusBadRequest, "validation_error", "")
		missingKey.Body.Close()

		invalid := platformCreateBody
		invalid.Basic = validSiteBasic("https://not-a-domain.example/path", "not an origin")
		invalidResponse := siteRequest(t, client, http.MethodPost, server.URL+"/v1/sites", invalid, platformAuth.AccessToken, "invalid-create", "")
		assertError(t, invalidResponse, http.StatusBadRequest, "validation_error", "")
		invalidResponse.Body.Close()

		spoofed := createSiteRequest{
			TargetScopeID: tenantB.scopeID.String(),
			OwnerID:       tenantB.userID.String(),
			Basic:         validSiteBasic("spoofed.example", "192.0.2.12"),
		}
		spoofedResponse := siteRequest(t, client, http.MethodPost, server.URL+"/v1/sites", spoofed, tenantAAuth.AccessToken, "tenant-spoof", "")
		assertError(t, spoofedResponse, http.StatusForbidden, "permission_denied", "")
		spoofedResponse.Body.Close()
	})

	createdB := createSite(t, client, server.URL, tenantBAuth.AccessToken, "create-beta", createSiteRequest{
		Basic: validSiteBasic("www.beta.example", "198.51.100.20"),
	})
	if createdB.DisplayID != "1" || createdB.Owner != nil {
		t.Fatalf("tenant create owner = %#v, want redacted", createdB.Owner)
	}

	t.Run("platform and tenant list scopes", func(t *testing.T) {
		platformPage := listSites(t, client, server.URL+"/v1/sites?page=1&limit=20", platformAuth.AccessToken)
		if platformPage.Total != 2 || len(platformPage.Items) != 2 {
			t.Fatalf("platform page = %#v", platformPage)
		}
		for _, item := range platformPage.Items {
			if item.Owner == nil || item.Revision < 1 {
				t.Fatalf("platform list owner/version for site %s = %#v", item.ID, item)
			}
		}

		tenantPage := listSites(t, client, server.URL+"/v1/sites?page=1&limit=20", tenantAAuth.AccessToken)
		if tenantPage.Total != 1 || len(tenantPage.Items) != 1 || tenantPage.Items[0].ID != createdA.ID ||
			tenantPage.Items[0].DisplayID != createdA.DisplayID ||
			tenantPage.Items[0].Revision != createdA.Version {
			t.Fatalf("tenant A page = %#v", tenantPage)
		}
		if tenantPage.Items[0].Owner != nil || tenantPage.Items[0].Region != nil {
			t.Fatalf("tenant-only fields were not redacted: %#v", tenantPage.Items[0])
		}
		for _, privilegedFilter := range []string{"owner=Tenant", "region_id=" + uuid.NewString(), "node_group_id=" + uuid.NewString()} {
			response := siteRequest(t, client, http.MethodGet, server.URL+"/v1/sites?page=1&limit=20&"+privilegedFilter, nil, tenantAAuth.AccessToken, "", "")
			assertError(t, response, http.StatusForbidden, "permission_denied", "")
			response.Body.Close()
		}

		pageOne := listSites(t, client, server.URL+"/v1/sites?page=1&limit=1", platformAuth.AccessToken)
		pageTwo := listSites(t, client, server.URL+"/v1/sites?page=2&limit=1", platformAuth.AccessToken)
		if pageOne.Total != 2 || pageTwo.Total != 2 || len(pageOne.Items) != 1 || len(pageTwo.Items) != 1 ||
			pageOne.Items[0].ID == pageTwo.Items[0].ID {
			t.Fatalf("site pagination is not stable: first=%#v second=%#v", pageOne, pageTwo)
		}
	})

	t.Run("all list filters and invalid query", func(t *testing.T) {
		query := url.Values{
			"page":           {"1"},
			"limit":          {"20"},
			"domain":         {"alpha"},
			"domains":        {"www.alpha.example,www.unknown.example"},
			"origin_ip":      {"192.0.2.10"},
			"site_ids":       {createdA.ID.String()},
			"owner":          {"Tenant A"},
			"package_id":     {packageID},
			"group_id":       {groupID},
			"http_port":      {"80"},
			"https_port":     {"443"},
			"https_enabled":  {"true"},
			"enabled":        {"true"},
			"status":         {"active"},
			"is_default":     {"false"},
			"sync_status":    {"synced"},
		}
		filtered := listSites(t, client, server.URL+"/v1/sites?"+query.Encode(), platformAuth.AccessToken)
		if filtered.Total != 1 || len(filtered.Items) != 1 || filtered.Items[0].ID != createdA.ID {
			t.Fatalf("filtered page = %#v", filtered)
		}
		// 带套餐的站点 CNAME 由系统分配（请求里的 CNAME 不落库），CNAME 筛选用自填 CNAME 的站点 B。
		cnameFiltered := listSites(t, client, server.URL+"/v1/sites?page=1&limit=20&cname_domain=edge.example&cname_hostname=www", platformAuth.AccessToken)
		if cnameFiltered.Total != 1 || len(cnameFiltered.Items) != 1 || cnameFiltered.Items[0].ID != createdB.ID {
			t.Fatalf("CNAME filtered page = %#v", cnameFiltered)
		}
		for _, rawQuery := range []string{
			"page=0", "limit=101", "enabled=1", "status=unknown", "site_ids=not-a-uuid", "unknown=value", "page=1&page=2",
		} {
			response := siteRequest(t, client, http.MethodGet, server.URL+"/v1/sites?"+rawQuery, nil, platformAuth.AccessToken, "", "")
			assertError(t, response, http.StatusBadRequest, "validation_error", "")
			response.Body.Close()
		}
	})

	t.Run("detail isolation and read-only role", func(t *testing.T) {
		detail := getSite(t, client, server.URL, createdA.ID, tenantAAuth.AccessToken)
		if detail.DisplayID != createdA.DisplayID || detail.Owner != nil || detail.Basic.Domains[0] != "www.alpha.example" {
			t.Fatalf("tenant detail = %#v", detail)
		}
		crossTenant := siteRequest(t, client, http.MethodGet, server.URL+"/v1/sites/"+createdB.ID.String(), nil, tenantAAuth.AccessToken, "", "")
		assertError(t, crossTenant, http.StatusNotFound, "site_not_found", "")
		crossTenant.Body.Close()

		readOnlyUpdate := updateSiteRequest{ExpectedVersion: 1, Section: "basic", Changes: validSiteBasic("readonly.example", "192.0.2.30")}
		response := siteRequest(t, client, http.MethodPatch, server.URL+"/v1/sites/"+createdA.ID.String(), readOnlyUpdate, tenantReaderAuth.AccessToken, "reader-update", "")
		assertError(t, response, http.StatusForbidden, "permission_denied", "")
		response.Body.Close()
	})

	// 站点 A 的源站池非默认（URL hash、权重 75），basic 段不能改源站（origin_section_conflict）。
	updatedBasic := validSiteBasic("cdn.alpha.example", "192.0.2.10:8080")
	updatedBasic.CNAME = "alpha2.edge.example"
	updateBody := updateSiteRequest{ExpectedVersion: 1, Section: "basic", Changes: updatedBasic}
	updated := updateSite(t, client, server.URL, createdA.ID, tenantAAuth.AccessToken, "update-alpha", updateBody)
	if updated.Version != 2 || updated.Basic.Domains[0] != "cdn.alpha.example" || updated.Owner != nil {
		t.Fatalf("updated site = %#v", updated)
	}

	t.Run("update idempotency and optimistic concurrency", func(t *testing.T) {
		replayed := updateSite(t, client, server.URL, createdA.ID, tenantAAuth.AccessToken, "update-alpha", updateBody)
		if replayed.Version != 2 || replayed.ID != updated.ID {
			t.Fatalf("update replay = %#v", replayed)
		}

		stale := siteRequest(t, client, http.MethodPatch, server.URL+"/v1/sites/"+createdA.ID.String(), updateBody, tenantAAuth.AccessToken, "stale-update", "")
		assertError(t, stale, http.StatusConflict, "version_conflict", "")
		stale.Body.Close()

		changed := updateBody
		changed.Changes.CNAME = "different.edge.example"
		idempotencyConflict := siteRequest(t, client, http.MethodPatch, server.URL+"/v1/sites/"+createdA.ID.String(), changed, tenantAAuth.AccessToken, "update-alpha", "")
		assertError(t, idempotencyConflict, http.StatusConflict, "idempotency_conflict", "")
		idempotencyConflict.Body.Close()

		unsupported := updateBody
		unsupported.ExpectedVersion = 2
		unsupported.Section = "cache"
		unsupportedResponse := siteRequest(t, client, http.MethodPatch, server.URL+"/v1/sites/"+createdA.ID.String(), unsupported, tenantAAuth.AccessToken, "unsupported-update", "")
		assertError(t, unsupportedResponse, http.StatusBadRequest, "validation_error", "")
		unsupportedResponse.Body.Close()
	})

	lockTarget := createSite(t, client, server.URL, tenantAAuth.AccessToken, "create-lock-target", createSiteRequest{
		Basic: validSiteBasic("lock-target.example", "203.0.113.40"),
	})
	t.Run("platform lock lifecycle and tenant write protection", func(t *testing.T) {
		lockBody := lockSiteRequest{ExpectedVersion: 1, Reason: "Account ownership review"}
		for name, testCase := range map[string]struct {
			target string
			token  string
			key    string
		}{
			"tenant lock":         {"lock", tenantAAuth.AccessToken, "tenant-lock-denied"},
			"cross-tenant lock":   {"lock", tenantBAuth.AccessToken, "cross-tenant-lock-denied"},
			"tenant unlock":       {"unlock", tenantAAuth.AccessToken, "tenant-unlock-denied"},
			"cross-tenant unlock": {"unlock", tenantBAuth.AccessToken, "cross-tenant-unlock-denied"},
		} {
			t.Run(name, func(t *testing.T) {
				body := any(lockBody)
				if testCase.target == "unlock" {
					body = unlockSiteRequest{ExpectedVersion: 1}
				}
				response := siteRequest(t, client, http.MethodPost,
					server.URL+"/v1/sites/"+lockTarget.ID.String()+"/"+testCase.target,
					body, testCase.token, testCase.key, "")
				assertError(t, response, http.StatusForbidden, "permission_denied", "")
				response.Body.Close()
			})
		}

		invalid := siteRequest(t, client, http.MethodPost,
			server.URL+"/v1/sites/"+lockTarget.ID.String()+"/lock",
			lockSiteRequest{ExpectedVersion: 1, Reason: " \n\t "}, platformAuth.AccessToken, "invalid-lock", "")
		assertError(t, invalid, http.StatusBadRequest, "validation_error", "")
		invalid.Body.Close()

		magicStatus := updateSiteRequest{ExpectedVersion: 1, Section: "basic", Changes: validSiteBasic("lock-target.example", "203.0.113.40")}
		magicStatus.Changes.Status = site.StatusLocked
		invalid = siteRequest(t, client, http.MethodPatch, server.URL+"/v1/sites/"+lockTarget.ID.String(),
			magicStatus, tenantAAuth.AccessToken, "tenant-magic-lock", "")
		assertError(t, invalid, http.StatusBadRequest, "validation_error", "")
		invalid.Body.Close()

		type lockOutcome struct {
			status int
			code   string
			detail siteDetailResponse
			err    error
		}
		lockResults := concurrentSiteRequests(2, func(index int) lockOutcome {
			response, err := performSiteRequest(client, http.MethodPost,
				server.URL+"/v1/sites/"+lockTarget.ID.String()+"/lock", lockBody,
				platformAuth.AccessToken, fmt.Sprintf("concurrent-lock-%d", index), "")
			if err != nil {
				return lockOutcome{err: err}
			}
			defer response.Body.Close()
			outcome := lockOutcome{status: response.StatusCode}
			if response.StatusCode == http.StatusOK {
				outcome.err = decodeSiteResponseBody(response.Body, &outcome.detail)
				return outcome
			}
			var envelope testErrorEnvelope
			outcome.err = json.NewDecoder(response.Body).Decode(&envelope)
			outcome.code = envelope.Error.Code
			return outcome
		})
		winner := -1
		for index, result := range lockResults {
			if result.err != nil {
				t.Fatalf("concurrent lock result %d error = %v", index, result.err)
			}
			switch result.status {
			case http.StatusOK:
				if winner != -1 {
					t.Fatalf("multiple concurrent lock winners: %#v", lockResults)
				}
				winner = index
			case http.StatusConflict:
				if result.code != "version_conflict" {
					t.Fatalf("concurrent lock conflict code = %q", result.code)
				}
			default:
				t.Fatalf("concurrent lock status = %d", result.status)
			}
		}
		if winner == -1 {
			t.Fatalf("concurrent lock had no winner: %#v", lockResults)
		}
		locked := lockResults[winner].detail
		if locked.Version != 2 || !locked.Lock.Locked || locked.Lock.Reason == nil ||
			*locked.Lock.Reason != lockBody.Reason || locked.Lock.LockedAt == nil || locked.Lock.Operator == nil ||
			locked.Lock.Operator.DisplayName != "Site Administrator" || locked.Basic.Status != site.StatusActive {
			t.Fatalf("locked site = %#v", locked)
		}

		replay := siteRequest(t, client, http.MethodPost,
			server.URL+"/v1/sites/"+lockTarget.ID.String()+"/lock", lockBody,
			platformAuth.AccessToken, fmt.Sprintf("concurrent-lock-%d", winner), "")
		var replayed siteDetailResponse
		decodeResponse(t, replay, http.StatusOK, &replayed)
		replay.Body.Close()
		if replayed.Version != locked.Version || replayed.Lock.LockedAt == nil || !replayed.Lock.LockedAt.Equal(*locked.Lock.LockedAt) {
			t.Fatalf("lock replay = %#v", replayed)
		}

		idempotencyConflict := lockBody
		idempotencyConflict.Reason = "Changed reason"
		response := siteRequest(t, client, http.MethodPost,
			server.URL+"/v1/sites/"+lockTarget.ID.String()+"/lock", idempotencyConflict,
			platformAuth.AccessToken, fmt.Sprintf("concurrent-lock-%d", winner), "")
		assertError(t, response, http.StatusConflict, "idempotency_conflict", "")
		response.Body.Close()

		response = siteRequest(t, client, http.MethodPost,
			server.URL+"/v1/sites/"+lockTarget.ID.String()+"/lock",
			lockSiteRequest{ExpectedVersion: 2, Reason: "Another reason"}, platformAuth.AccessToken, "already-locked", "")
		assertError(t, response, http.StatusConflict, "site_lock_state_conflict", "")
		response.Body.Close()

		tenantDetail := getSite(t, client, server.URL, lockTarget.ID, tenantAAuth.AccessToken)
		if !tenantDetail.Lock.Locked || tenantDetail.Lock.Operator == nil || tenantDetail.Lock.Operator.DisplayName != "Site Administrator" {
			t.Fatalf("tenant locked detail = %#v", tenantDetail)
		}
		tenantList := listSites(t, client, server.URL+"/v1/sites?page=1&limit=20", tenantAAuth.AccessToken)
		lockListed := false
		for _, item := range tenantList.Items {
			if item.ID == lockTarget.ID {
				lockListed = item.Revision == 2 && item.Lock.Locked && item.Lock.Reason != nil && item.Lock.Operator != nil
			}
		}
		if !lockListed {
			t.Fatalf("locked site missing typed lock state in list: %#v", tenantList)
		}
		lockedOnly := listSites(t, client, server.URL+"/v1/sites?page=1&limit=20&status=locked", tenantAAuth.AccessToken)
		if lockedOnly.Total != 1 || len(lockedOnly.Items) != 1 || lockedOnly.Items[0].ID != lockTarget.ID ||
			lockedOnly.Items[0].Revision != 2 || !lockedOnly.Items[0].Lock.Locked {
			t.Fatalf("locked status filter = %#v", lockedOnly)
		}

		replayTarget := createSite(t, client, server.URL, tenantAAuth.AccessToken, "create-lock-replay-target", createSiteRequest{
			Basic: validSiteBasic("lock-replay-target.example", "203.0.113.44"),
		})
		preLockUpdate := updateSiteRequest{
			ExpectedVersion: 1,
			Section:         "basic",
			Changes:         validSiteBasic("lock-replay-target.example", "203.0.113.45"),
		}
		preLockResult := updateSite(t, client, server.URL, replayTarget.ID, tenantAAuth.AccessToken, "pre-lock-update", preLockUpdate)
		if preLockResult.Version != 2 {
			t.Fatalf("pre-lock update version = %d", preLockResult.Version)
		}
		response = siteRequest(t, client, http.MethodPost,
			server.URL+"/v1/sites/"+replayTarget.ID.String()+"/lock",
			lockSiteRequest{ExpectedVersion: 2, Reason: "Idempotency review"}, platformAuth.AccessToken, "lock-replay-target", "")
		var replayTargetLocked siteDetailResponse
		decodeResponse(t, response, http.StatusOK, &replayTargetLocked)
		response.Body.Close()
		if replayTargetLocked.Version != 3 || !replayTargetLocked.Lock.Locked {
			t.Fatalf("replay target lock = %#v", replayTargetLocked)
		}
		response = siteRequest(t, client, http.MethodPatch,
			server.URL+"/v1/sites/"+replayTarget.ID.String(), preLockUpdate,
			tenantAAuth.AccessToken, "pre-lock-update", "")
		var resolvedUnknownWrite siteDetailResponse
		decodeResponse(t, response, http.StatusOK, &resolvedUnknownWrite)
		response.Body.Close()
		if resolvedUnknownWrite.Version != 2 || resolvedUnknownWrite.Basic.Origins[0] != "203.0.113.45" {
			t.Fatalf("pre-lock update replay = %#v", resolvedUnknownWrite)
		}
		response = siteRequest(t, client, http.MethodPatch,
			server.URL+"/v1/sites/"+replayTarget.ID.String(),
			updateSiteRequest{ExpectedVersion: 3, Section: "basic", Changes: validSiteBasic("lock-replay-target.example", "203.0.113.46")},
			tenantAAuth.AccessToken, "new-locked-update", "")
		assertError(t, response, http.StatusConflict, "site_locked", "")
		response.Body.Close()

		blockedChanges := validSiteBasic("lock-target-edited.example", "203.0.113.41")
		blockedRequests := []struct {
			method  string
			key     string
			body    any
			ifMatch string
		}{
			{http.MethodPatch, "locked-edit", updateSiteRequest{ExpectedVersion: 2, Section: "basic", Changes: blockedChanges}, ""},
			{http.MethodPatch, "locked-disable", updateSiteRequest{ExpectedVersion: 2, Section: "basic", Changes: disabledSiteBasic("lock-target.example", "203.0.113.40")}, ""},
			{http.MethodDelete, "locked-delete", nil, `"2"`},
		}
		for _, blocked := range blockedRequests {
			response = siteRequest(t, client, blocked.method, server.URL+"/v1/sites/"+lockTarget.ID.String(),
				blocked.body, tenantAAuth.AccessToken, blocked.key, blocked.ifMatch, blocked.key+"-request")
			assertError(t, response, http.StatusConflict, "site_locked", blocked.key+"-request")
			response.Body.Close()
		}
		crossTenant := siteRequest(t, client, http.MethodPatch, server.URL+"/v1/sites/"+lockTarget.ID.String(),
			updateSiteRequest{ExpectedVersion: 2, Section: "basic", Changes: blockedChanges},
			tenantBAuth.AccessToken, "cross-tenant-locked-edit", "")
		assertError(t, crossTenant, http.StatusNotFound, "site_not_found", "")
		crossTenant.Body.Close()

		var rejectedWrites, rejectedAudits int
		if err := pool.QueryRow(context.Background(), `
			SELECT count(*) FROM site_write_requests
			WHERE idempotency_key = ANY($1::text[])`,
			[]string{
				"tenant-lock-denied", "cross-tenant-lock-denied", "tenant-unlock-denied", "cross-tenant-unlock-denied",
				"invalid-lock", "tenant-magic-lock", "already-locked", "locked-edit", "locked-disable", "locked-delete",
				"cross-tenant-locked-edit",
			},
		).Scan(&rejectedWrites); err != nil {
			t.Fatalf("count rejected site writes: %v", err)
		}
		if err := pool.QueryRow(context.Background(), `
			SELECT count(*) FROM audit_events
			WHERE request_id = ANY($1::text[])`,
			[]string{"locked-edit-request", "locked-disable-request", "locked-delete-request"},
		).Scan(&rejectedAudits); err != nil {
			t.Fatalf("count rejected site audits: %v", err)
		}
		if rejectedWrites != 0 || rejectedAudits != 0 {
			t.Fatalf("rejected lock writes/audits = %d/%d, want 0/0", rejectedWrites, rejectedAudits)
		}

		maintenance := updateSiteRequest{
			ExpectedVersion: 2,
			Section:         "basic",
			Changes:         validSiteBasic("lock-target.example", "203.0.113.42"),
		}
		maintained := updateSite(t, client, server.URL, lockTarget.ID, platformAuth.AccessToken, "locked-platform-maintenance", maintenance)
		if maintained.Version != 3 || !maintained.Lock.Locked || maintained.Lock.Reason == nil {
			t.Fatalf("platform maintenance result = %#v", maintained)
		}

		// SITE-14: unlock only queues a durable site.status_recovery task; the
		// recovery worker clears the lock once the edge is healthy. The site
		// stays locked (version 3) until then.
		unlockBody := unlockSiteRequest{ExpectedVersion: 3}
		response = siteRequest(t, client, http.MethodPost,
			server.URL+"/v1/sites/"+lockTarget.ID.String()+"/unlock", unlockBody,
			platformAuth.AccessToken, "unlock-site", "")
		var unlocked siteDetailResponse
		decodeResponse(t, response, http.StatusOK, &unlocked)
		response.Body.Close()
		if unlocked.Version != 3 || !unlocked.Lock.Locked || unlocked.StatusRecovery == nil ||
			unlocked.StatusRecovery.Trigger != site.RecoveryTriggerUnlock || unlocked.StatusRecovery.SiteRevision != 3 {
			t.Fatalf("unlock did not queue status recovery: %#v", unlocked)
		}
		response = siteRequest(t, client, http.MethodPost,
			server.URL+"/v1/sites/"+lockTarget.ID.String()+"/unlock", unlockBody,
			platformAuth.AccessToken, "unlock-site", "")
		decodeResponse(t, response, http.StatusOK, &replayed)
		response.Body.Close()
		if replayed.Version != 3 || replayed.StatusRecovery == nil || replayed.StatusRecovery.TaskID != unlocked.StatusRecovery.TaskID {
			t.Fatalf("unlock replay = %#v", replayed)
		}

		pendingTenantUpdate := updateSiteRequest{
			ExpectedVersion: 3,
			Section:         "basic",
			Changes:         validSiteBasic("lock-target.example", "203.0.113.43"),
		}
		response = siteRequest(t, client, http.MethodPatch, server.URL+"/v1/sites/"+lockTarget.ID.String(),
			pendingTenantUpdate, tenantAAuth.AccessToken, "pending-unlock-update", "")
		assertError(t, response, http.StatusConflict, "site_locked", "")
		response.Body.Close()

		var lockAudits, lockWrites int
		if err := pool.QueryRow(context.Background(), `
			SELECT count(*) FROM audit_events
			WHERE resource_id = $1 AND action IN ('site.lock', 'site.status_recovery.unlock')`, lockTarget.ID.String(),
		).Scan(&lockAudits); err != nil {
			t.Fatalf("count lock audits: %v", err)
		}
		if lockAudits != 2 {
			t.Fatalf("lock audit count = %d, want 2", lockAudits)
		}
		if err := pool.QueryRow(context.Background(), `
			SELECT count(*) FROM site_write_requests
			WHERE resource_id = $1 AND operation IN ('site.lock', 'site.status_recovery.unlock') AND completed_at IS NOT NULL`, lockTarget.ID,
		).Scan(&lockWrites); err != nil {
			t.Fatalf("count completed lock writes: %v", err)
		}
		if lockWrites != 2 {
			t.Fatalf("completed lock write count = %d, want 2", lockWrites)
		}
		if err := audit.New(pool).VerifyScope(context.Background(), tenantA.scopeID); err != nil {
			t.Fatalf("VerifyScope(tenant A) after lock lifecycle error = %v", err)
		}
	})

	t.Run("concurrent idempotent create and domain uniqueness", func(t *testing.T) {
		body := createSiteRequest{Basic: validSiteBasic("concurrent.example", "203.0.113.10")}
		type outcome struct {
			status    int
			id        uuid.UUID
			displayID string
			code      string
			err       error
		}
		run := func(key string) outcome {
			response, err := performSiteRequest(client, http.MethodPost, server.URL+"/v1/sites", body, tenantAAuth.AccessToken, key, "")
			if err != nil {
				return outcome{err: err}
			}
			defer response.Body.Close()
			result := outcome{status: response.StatusCode}
			if response.StatusCode == http.StatusCreated {
				var detail siteDetailResponse
				err = decodeSiteResponseBody(response.Body, &detail)
				result.id, result.displayID, result.err = detail.ID, detail.DisplayID, err
				return result
			}
			var envelope testErrorEnvelope
			err = json.NewDecoder(response.Body).Decode(&envelope)
			result.code, result.err = envelope.Error.Code, err
			return result
		}

		results := concurrentSiteRequests(2, func(_ int) outcome { return run("concurrent-same-key") })
		if results[0].err != nil || results[1].err != nil || results[0].status != http.StatusCreated ||
			results[1].status != http.StatusCreated || results[0].id != results[1].id ||
			results[0].displayID == "" || results[0].displayID != results[1].displayID {
			t.Fatalf("concurrent idempotent outcomes = %#v", results)
		}

		body = createSiteRequest{Basic: validSiteBasic("race-domain.example", "203.0.113.11")}
		uniqueResults := concurrentSiteRequests(2, func(index int) outcome {
			return run(fmt.Sprintf("concurrent-domain-%d", index))
		})
		statuses := []int{uniqueResults[0].status, uniqueResults[1].status}
		sort.Ints(statuses)
		if statuses[0] != http.StatusCreated || statuses[1] != http.StatusConflict {
			t.Fatalf("concurrent domain outcomes = %#v", uniqueResults)
		}
		for _, result := range uniqueResults {
			if result.status == http.StatusConflict && result.code != "site_domain_conflict" {
				t.Fatalf("concurrent domain conflict code = %q", result.code)
			}
		}
		var tenantSiteCount, tenantDisplayCount, minimumDisplayID, maximumDisplayID int64
		if err := pool.QueryRow(context.Background(), `
			SELECT count(*),count(DISTINCT display_id),min(display_id),max(display_id)
			FROM sites WHERE scope_id=$1`, tenantA.scopeID,
		).Scan(&tenantSiteCount, &tenantDisplayCount, &minimumDisplayID, &maximumDisplayID); err != nil {
			t.Fatalf("read tenant site display IDs: %v", err)
		}
		if tenantSiteCount != tenantDisplayCount || minimumDisplayID != 1 || maximumDisplayID != tenantSiteCount {
			t.Fatalf("tenant site display IDs are not unique and dense: count=%d distinct=%d range=%d..%d",
				tenantSiteCount, tenantDisplayCount, minimumDisplayID, maximumDisplayID)
		}
	})

	t.Run("delete version, replay, isolation, and audit", func(t *testing.T) {
		stale := siteRequest(t, client, http.MethodDelete, server.URL+"/v1/sites/"+createdA.ID.String(), nil, tenantAAuth.AccessToken, "delete-alpha-stale", `"1"`)
		assertError(t, stale, http.StatusConflict, "version_conflict", "")
		stale.Body.Close()

		deleted := siteRequest(t, client, http.MethodDelete, server.URL+"/v1/sites/"+createdA.ID.String(), nil, tenantAAuth.AccessToken, "delete-alpha", `"2"`)
		if deleted.StatusCode != http.StatusNoContent {
			t.Fatalf("delete status = %d, want 204, body = %s", deleted.StatusCode, readBody(deleted.Body))
		}
		deleted.Body.Close()
		replay := siteRequest(t, client, http.MethodDelete, server.URL+"/v1/sites/"+createdA.ID.String(), nil, tenantAAuth.AccessToken, "delete-alpha", `"2"`)
		if replay.StatusCode != http.StatusNoContent {
			t.Fatalf("delete replay status = %d, want 204, body = %s", replay.StatusCode, readBody(replay.Body))
		}
		replay.Body.Close()

		missing := siteRequest(t, client, http.MethodGet, server.URL+"/v1/sites/"+createdA.ID.String(), nil, platformAuth.AccessToken, "", "")
		assertError(t, missing, http.StatusNotFound, "site_not_found", "")
		missing.Body.Close()

		if err := audit.New(pool).VerifyScope(context.Background(), tenantA.scopeID); err != nil {
			t.Fatalf("VerifyScope(tenant A) error = %v", err)
		}
		var actions int
		if err := pool.QueryRow(context.Background(), `
			SELECT count(*) FROM audit_events
			WHERE scope_id = $1 AND action IN ('site.create', 'site.update', 'site.delete')`, tenantA.scopeID,
		).Scan(&actions); err != nil {
			t.Fatalf("count site audit events: %v", err)
		}
		if actions < 3 {
			t.Fatalf("site audit action count = %d, want at least 3", actions)
		}
	})
}

func TestSiteLockMigrationRollbackAndReapply(t *testing.T) {
	pool := migrationRoundTripPool(t, 10)
	ctx := context.Background()
	if err := database.Migrate(ctx, pool, "down"); err != nil {
		t.Fatalf("Migrate(down 010) error = %v", err)
	}
	for _, column := range []string{"lock_reason", "locked_at", "locked_by_user_id"} {
		var exists bool
		if err := pool.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM information_schema.columns
				WHERE table_schema = current_schema() AND table_name = 'sites' AND column_name = $1
			)`, column).Scan(&exists); err != nil {
			t.Fatalf("inspect site lock column %s: %v", column, err)
		}
		if exists {
			t.Fatalf("site lock column %s still exists after rollback", column)
		}
	}
	if err := database.Migrate(ctx, pool, "up"); err != nil {
		t.Fatalf("Migrate(up 010) error = %v", err)
	}
	var columnCount int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM information_schema.columns
		WHERE table_schema = current_schema() AND table_name = 'sites'
		  AND column_name IN ('lock_reason', 'locked_at', 'locked_by_user_id')`,
	).Scan(&columnCount); err != nil {
		t.Fatalf("inspect reapplied site lock columns: %v", err)
	}
	if columnCount != 3 {
		t.Fatalf("reapplied site lock column count = %d, want 3", columnCount)
	}
}

func TestSiteEntitlementHTTPFlow(t *testing.T) {
	pool := isolatedTestPool(t)
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	identityStore := identity.NewStore(pool)
	_, err = identityStore.BootstrapPlatformUser(
		context.Background(), "entitlementadmin", "Entitlement Admin", passwordHash, "entitlement-bootstrap",
	)
	if err != nil {
		t.Fatalf("BootstrapPlatformUser() error = %v", err)
	}
	tenantA := insertSiteTenant(t, pool, "entitlement-tenant-a", "entitlement-user-a", "Entitlement User A", passwordHash)
	tenantB := insertSiteTenant(t, pool, "entitlement-tenant-b", "entitlement-user-b", "Entitlement User B", passwordHash)

	tokens, err := identity.NewTokenManager("entitlement-test-secret-at-least-thirty-two-bytes", 5*time.Minute)
	if err != nil {
		t.Fatalf("NewTokenManager() error = %v", err)
	}
	identityService, err := identity.NewService(identityStore, tokens, 24*time.Hour)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	var baseTime time.Time
	if err := pool.QueryRow(t.Context(), `SELECT date_trunc('second',clock_timestamp())`).Scan(&baseTime); err != nil {
		t.Fatalf("read entitlement test clock: %v", err)
	}
	key := newSiteTestKey(t, "control-test-key-1")
	trust := newSiteTestTrust(t, key)
	var clockUnix atomic.Int64
	clockUnix.Store(baseTime.Unix())
	server := httptest.NewServer(New(pool, identityService, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32),
		CookieSecure:     false,
		Now:              func() time.Time { return time.Unix(clockUnix.Load(), 0).UTC() },
		EntitlementTrust: trust,
	}).Handler())
	t.Cleanup(server.Close)
	client := server.Client()
	platformAuth, _ := loginOK(t, client, server.URL, "entitlementadmin")
	tenantAAuth := loginForScope(t, client, server.URL, tenantA.username, tenantA.scopeID)
	tenantBAuth := loginForScope(t, client, server.URL, tenantB.username, tenantB.scopeID)

	platformBody := createSiteRequest{
		TargetScopeID: tenantA.scopeID.String(),
		OwnerID:       tenantA.userID.String(),
		Basic:         validSiteBasic("entitlement-replay.example", "192.0.2.50"),
	}
	response := siteRequest(t, client, http.MethodPost, server.URL+"/v1/sites", platformBody, platformAuth.AccessToken, "entitlement-no-lease", "", "entitlement-no-lease-request")
	assertError(t, response, http.StatusForbidden, "entitlement_unavailable", "entitlement-no-lease-request")
	response.Body.Close()
	assertEntitlementAudit(t, pool, "entitlement-no-lease-request", "uninstalled", 0, -1)

	validLease := installSiteTestEntitlement(t, pool, trust, baseTime, siteTestLeaseOptions{
		serial: 1, limit: 10, key: key,
	})
	databaseOnlyServer := httptest.NewServer(New(pool, identityService, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32),
		CookieSecure: false,
		Now:          func() time.Time { return baseTime },
	}).Handler())
	response = siteRequest(t, databaseOnlyServer.Client(), http.MethodPost, databaseOnlyServer.URL+"/v1/sites", platformBody, platformAuth.AccessToken, "database-only-trust", "", "database-only-trust-request")
	assertError(t, response, http.StatusForbidden, "entitlement_unavailable", "database-only-trust-request")
	response.Body.Close()
	databaseOnlyServer.Close()
	created := createSite(t, client, server.URL, platformAuth.AccessToken, "entitlement-replay", platformBody)
	if _, err := entitlementguard.NewService(pool, trust).Install(context.Background(), entitlementguard.InstallBundle{
		InstallationID: validLease.Lease.InstallationID,
		RevokedSerials: []uint64{validLease.Lease.Serial},
		SignedLease:    validLease,
	}, baseTime); !errors.Is(err, entitlementguard.ErrUntrustedRevocations) {
		t.Fatalf("Install(forged revocation) error = %v", err)
	}
	replayed := createSite(t, client, server.URL, platformAuth.AccessToken, "entitlement-replay", platformBody)
	if replayed.ID != created.ID {
		t.Fatalf("replayed site ID = %s, want %s", replayed.ID, created.ID)
	}
	validDelete := siteRequest(t, client, http.MethodDelete, server.URL+"/v1/sites/"+created.ID.String(), nil, platformAuth.AccessToken, "valid-delete", `"1"`)
	if validDelete.StatusCode != http.StatusNoContent {
		t.Fatalf("delete in valid state = %d, body = %s", validDelete.StatusCode, readBody(validDelete.Body))
	}
	validDelete.Body.Close()

	installSiteTestEntitlement(t, pool, trust, baseTime, siteTestLeaseOptions{
		serial: 2, limit: 10, key: key, omitFeature: true,
	})
	response = siteRequest(t, client, http.MethodPost, server.URL+"/v1/sites", createSiteRequest{
		Basic: disabledSiteBasic("feature-create.example", "192.0.2.52"),
	}, tenantAAuth.AccessToken, "feature-create", "", "feature-create-request")
	assertError(t, response, http.StatusForbidden, "entitlement_feature_denied", "feature-create-request")
	response.Body.Close()

	installSiteTestEntitlement(t, pool, trust, baseTime, siteTestLeaseOptions{
		serial: 3, limit: 10, key: key, omitQuota: true,
	})
	response = siteRequest(t, client, http.MethodPost, server.URL+"/v1/sites", createSiteRequest{
		Basic: disabledSiteBasic("quota-create.example", "192.0.2.53"),
	}, tenantAAuth.AccessToken, "quota-create", "", "quota-create-request")
	assertError(t, response, http.StatusForbidden, "entitlement_quota_denied", "quota-create-request")
	response.Body.Close()

	installSiteTestEntitlement(t, pool, trust, baseTime, siteTestLeaseOptions{
		serial: 4, limit: 1, key: key,
	})
	type quotaOutcome struct {
		status int
		code   string
		err    error
	}
	quotaResults := concurrentSiteRequests(2, func(index int) quotaOutcome {
		auth := tenantAAuth.AccessToken
		if index == 1 {
			auth = tenantBAuth.AccessToken
		}
		request, requestErr := performSiteRequest(client, http.MethodPost, server.URL+"/v1/sites", createSiteRequest{
			Basic: validSiteBasic(fmt.Sprintf("quota-race-%d.example", index), fmt.Sprintf("198.51.100.%d", index+10)),
		}, auth, fmt.Sprintf("quota-race-%d", index), "", fmt.Sprintf("quota-race-request-%d", index))
		if requestErr != nil {
			return quotaOutcome{err: requestErr}
		}
		defer request.Body.Close()
		outcome := quotaOutcome{status: request.StatusCode}
		if request.StatusCode != http.StatusCreated {
			var envelope testErrorEnvelope
			outcome.err = json.NewDecoder(request.Body).Decode(&envelope)
			outcome.code = envelope.Error.Code
		}
		return outcome
	})
	statuses := []int{quotaResults[0].status, quotaResults[1].status}
	sort.Ints(statuses)
	if quotaResults[0].err != nil || quotaResults[1].err != nil ||
		statuses[0] != http.StatusCreated || statuses[1] != http.StatusConflict {
		t.Fatalf("concurrent entitlement quota outcomes = %#v", quotaResults)
	}
	for _, outcome := range quotaResults {
		if outcome.status == http.StatusConflict && outcome.code != "entitlement_quota_exceeded" {
			t.Fatalf("quota rejection code = %q", outcome.code)
		}
	}
	var enabledCount int64
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM sites WHERE enabled AND deleted_at IS NULL`).Scan(&enabledCount); err != nil {
		t.Fatalf("count enabled sites: %v", err)
	}
	if enabledCount != 1 {
		t.Fatalf("enabled site count = %d, want quota limit 1", enabledCount)
	}

	installSiteTestEntitlement(t, pool, trust, baseTime, siteTestLeaseOptions{
		serial: 5, limit: 10, key: key,
	})
	clockSite := createSite(t, client, server.URL, tenantAAuth.AccessToken, "clock-site", createSiteRequest{
		Basic: validSiteBasic("clock-state.example", "203.0.113.60"),
	})
	clockUnix.Store(baseTime.Add(90 * time.Minute).Unix())
	graceUpdate := updateSiteRequest{
		ExpectedVersion: 1,
		Section:         "basic",
		Changes:         validSiteBasic("clock-state.example", "203.0.113.61"),
	}
	// Grace keeps publishing allowed while the license service is unreachable;
	// disable and re-enable work too.
	published := updateSite(t, client, server.URL, clockSite.ID, tenantAAuth.AccessToken, "grace-publish", graceUpdate)
	if !published.Basic.Enabled || published.Version != 2 {
		t.Fatalf("grace published site = %#v", published)
	}

	disableUpdate := graceUpdate
	disableUpdate.ExpectedVersion = 2
	disableUpdate.Changes = disabledSiteBasic("clock-state.example", "203.0.113.61")
	disabled := updateSite(t, client, server.URL, clockSite.ID, tenantAAuth.AccessToken, "grace-disable", disableUpdate)
	if disabled.Basic.Enabled || disabled.Version != 3 {
		t.Fatalf("disabled site = %#v", disabled)
	}
	reenable := graceUpdate
	reenable.ExpectedVersion = 3
	reenabled := updateSite(t, client, server.URL, clockSite.ID, tenantAAuth.AccessToken, "grace-reenable", reenable)
	if !reenabled.Basic.Enabled || reenabled.Version != 4 {
		t.Fatalf("grace re-enabled site = %#v", reenabled)
	}

	deleted := siteRequest(t, client, http.MethodDelete, server.URL+"/v1/sites/"+clockSite.ID.String(), nil, tenantAAuth.AccessToken, "grace-delete", `"4"`)
	if deleted.StatusCode != http.StatusNoContent {
		t.Fatalf("delete in grace status = %d, body = %s", deleted.StatusCode, readBody(deleted.Body))
	}
	deleted.Body.Close()

	clockUnix.Store(baseTime.Add(3 * time.Hour).Unix())
	response = siteRequest(t, client, http.MethodPost, server.URL+"/v1/sites", createSiteRequest{
		Basic: disabledSiteBasic("expired-create.example", "203.0.113.62"),
	}, tenantAAuth.AccessToken, "expired-create", "", "expired-create-request")
	assertError(t, response, http.StatusForbidden, "entitlement_state_denied", "expired-create-request")
	response.Body.Close()
	for _, scopeID := range []uuid.UUID{tenantA.scopeID, tenantB.scopeID} {
		if err := audit.New(pool).VerifyScope(context.Background(), scopeID); err != nil {
			t.Fatalf("VerifyScope(%s) error = %v", scopeID, err)
		}
	}
}

type siteTestKey struct {
	id      string
	public  ed25519.PublicKey
	private ed25519.PrivateKey
}

func (key siteTestKey) KeyID() string { return key.id }

func (key siteTestKey) Sign(_ context.Context, payload []byte) ([]byte, error) {
	return ed25519.Sign(key.private, payload), nil
}

type siteTestLeaseOptions struct {
	serial      uint64
	limit       int64
	key         siteTestKey
	omitFeature bool
	omitQuota   bool
	// extraFeatures are granted in addition to sites.manage.
	extraFeatures []string
}

func newSiteTestKey(t *testing.T, id string) siteTestKey {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	return siteTestKey{id: id, public: publicKey, private: privateKey}
}

func newSiteTestTrust(t *testing.T, keys ...siteTestKey) *entitlementguard.TrustStore {
	t.Helper()
	notBefore := time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC)
	verifyUntil := time.Date(2100, time.January, 1, 0, 0, 0, 0, time.UTC)
	verificationKeys := make([]entitlementguard.VerificationKey, 0, len(keys))
	for _, key := range keys {
		verificationKeys = append(verificationKeys, entitlementguard.VerificationKey{
			KeyID: key.id, PublicKey: key.public, NotBefore: notBefore,
			SignUntil: &verifyUntil, VerifyUntil: &verifyUntil,
		})
	}
	trust, err := entitlementguard.NewTrustStore(verificationKeys)
	if err != nil {
		t.Fatalf("NewTrustStore() error = %v", err)
	}
	return trust
}

func installSiteTestEntitlement(
	t *testing.T,
	pool *pgxpool.Pool,
	trust *entitlementguard.TrustStore,
	now time.Time,
	options siteTestLeaseOptions,
) entitlement.SignedLease {
	t.Helper()
	features := []entitlement.Feature{{Code: entitlementguard.FeatureSitesManage}}
	if options.omitFeature {
		features = nil
	}
	for _, code := range options.extraFeatures {
		features = append(features, entitlement.Feature{Code: code})
	}
	// Lease features must be strictly ordered by code.
	sort.Slice(features, func(i, j int) bool { return features[i].Code < features[j].Code })
	quotas := []entitlement.Quota{{Code: entitlementguard.QuotaDomainsCount, Limit: options.limit}}
	if options.omitQuota {
		quotas = nil
	}
	lease := entitlement.Lease{
		Schema:         entitlement.SchemaV1,
		Audience:       entitlement.ControlAudience,
		CustomerID:     "11111111-1111-4111-8111-111111111111",
		InstallationID: "22222222-2222-4222-8222-222222222222",
		LicenseID:      "33333333-3333-4333-8333-333333333333",
		Serial:         options.serial,
		NotBefore:      now.Add(-time.Hour).Unix(),
		ExpiresAt:      now.Add(time.Hour).Unix(),
		GraceUntil:     now.Add(2 * time.Hour).Unix(),
		Version:        entitlement.VersionRange{Channel: "stable", Min: "0.1.0", Max: "1.0.0"},
		Features:       features,
		Quotas:         quotas,
	}
	ensureHTTPTestRevocation(t, pool, trust, options.key, now, lease)
	signed, err := entitlement.Sign(context.Background(), lease, options.key)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if _, err := entitlementguard.NewService(pool, trust).Install(context.Background(), entitlementguard.InstallBundle{
		InstallationID: lease.InstallationID,
		SignedLease:    signed,
	}, now); err != nil {
		t.Fatalf("Install() error = %v", err)
	}
	return signed
}

func ensureHTTPTestRevocation(
	t *testing.T,
	pool *pgxpool.Pool,
	trust *entitlementguard.TrustStore,
	key siteTestKey,
	now time.Time,
	lease entitlement.Lease,
) {
	t.Helper()
	var revision int64
	var expiresAt *time.Time
	if err := pool.QueryRow(t.Context(), `SELECT COALESCE(max(revision),0),max(expires_at)
		FROM control_entitlement_revocation_lkg
		WHERE customer_id=$1 AND installation_id=$2 AND license_id=$3`,
		lease.CustomerID, lease.InstallationID, lease.LicenseID).Scan(&revision, &expiresAt); err != nil {
		t.Fatalf("inspect HTTP test revocation: %v", err)
	}
	if expiresAt != nil && now.UTC().Before(*expiresAt) {
		return
	}
	issuedAt := now.UTC().Truncate(time.Second).Add(-time.Minute)
	notBefore := issuedAt.Add(-24 * time.Hour)
	verifyUntil := issuedAt.Add(24 * time.Hour)
	fingerprint := sha256.Sum256(key.public)
	keysetPayload := []byte(fmt.Sprintf(
		`{"schema":"cdnca.signing-keyset/v2","active_key_id":%q,"keys":[`+
			`{"key_id":%q,"algorithm":"Ed25519","public_key":%q,"fingerprint":%q,`+
			`"status":"active","not_before":%q,"sign_until":%q,"verify_until":%q}],"rotations":[]}`,
		key.id, key.id, base64.RawURLEncoding.EncodeToString(key.public),
		base64.RawURLEncoding.EncodeToString(fingerprint[:]), notBefore.Format(time.RFC3339Nano),
		verifyUntil.Format(time.RFC3339Nano), verifyUntil.Format(time.RFC3339Nano)))
	keysetDigest := sha256.Sum256(keysetPayload)
	if revision == 0 {
		if _, err := pool.Exec(t.Context(), `INSERT INTO entitlement_signing_keyset_lkg(
			singleton,schema_version,etag,active_key_id,chain_depth,payload,payload_sha256,accepted_at,updated_at)
			VALUES(true,'cdnca.signing-keyset/v2',$1,$2,1,$3,$4,$5,$5)`,
			`"`+base64.RawURLEncoding.EncodeToString(keysetDigest[:])+`"`, key.id,
			keysetPayload, keysetDigest[:], now.UTC()); err != nil {
			t.Fatalf("seed HTTP test signing keyset: %v", err)
		}
		if _, err := pool.Exec(t.Context(), `INSERT INTO entitlement_signing_keyset_current_keys(
			key_id,public_key,status,not_before,sign_until,verify_until,keyset_payload_sha256,accepted_at)
			VALUES($1,$2,'active',$3,$4,$4,$5,$6)`, key.id, key.public, notBefore,
			verifyUntil, keysetDigest[:], now.UTC()); err != nil {
			t.Fatalf("seed HTTP test signing key: %v", err)
		}
	}
	signed, err := entitlement.SignRevocationSet(t.Context(), entitlement.RevocationSet{
		Schema: entitlement.RevocationSetSchemaV2, Audience: entitlement.RevocationSetAudience,
		CustomerID: lease.CustomerID, InstallationID: lease.InstallationID,
		LicenseID: lease.LicenseID, Revision: uint64(revision + 1), IssuedAt: issuedAt.Unix(),
		ExpiresAt: issuedAt.Add(entitlement.RevocationSetWindow).Unix(), RevokedSerials: []uint64{},
	}, key, entitlement.RevocationKeyWindow{NotBefore: notBefore,
		SignUntil: &verifyUntil, VerifyUntil: &verifyUntil})
	if err != nil {
		t.Fatalf("sign HTTP test revocation: %v", err)
	}
	artifact, err := signed.Encode()
	if err != nil {
		t.Fatalf("encode HTTP test revocation: %v", err)
	}
	if _, err := entitlementguard.NewRevocationService(pool, trust).Accept(t.Context(), artifact, now.UTC()); err != nil {
		t.Fatalf("accept HTTP test revocation: %v", err)
	}
}

func disabledSiteBasic(domain, origin string) siteBasicPayload {
	basic := validSiteBasic(domain, origin)
	basic.Enabled = false
	basic.Status = site.StatusDisabled
	return basic
}

func assertEntitlementAudit(t *testing.T, pool *pgxpool.Pool, expectedRequestID, expectedState string, current, limit int64) {
	t.Helper()
	var requestID string
	var payload []byte
	if err := pool.QueryRow(context.Background(), `
		SELECT request_id, payload FROM audit_events
		WHERE action = 'entitlement.guard.reject'
		ORDER BY occurred_at DESC, id DESC LIMIT 1`,
	).Scan(&requestID, &payload); err != nil {
		t.Fatalf("read entitlement audit event: %v", err)
	}
	var fields map[string]any
	if err := json.Unmarshal(payload, &fields); err != nil {
		t.Fatalf("decode entitlement audit payload: %v", err)
	}
	for _, name := range []string{"lease_serial", "state", "feature", "quota", "current", "limit", "request_id"} {
		if _, found := fields[name]; !found {
			t.Fatalf("entitlement audit payload is missing %q: %s", name, payload)
		}
	}
	if requestID != expectedRequestID || fields["request_id"] != expectedRequestID ||
		fields["state"] != expectedState || int64(fields["current"].(float64)) != current || int64(fields["limit"].(float64)) != limit {
		t.Fatalf("entitlement audit = request_id %q payload %s", requestID, payload)
	}
	if bytes.Contains(payload, []byte("signature")) {
		t.Fatalf("entitlement audit leaked a signed envelope: %s", payload)
	}
}

type siteTenantFixture struct {
	scopeID  uuid.UUID
	userID   uuid.UUID
	username string
}

func insertSiteTenant(
	t *testing.T,
	pool *pgxpool.Pool,
	displayName string,
	username string,
	userDisplayName string,
	passwordHash string,
) siteTenantFixture {
	t.Helper()
	tenantID := uuid.New()
	scopeID := uuid.New()
	ownerRoleID := uuid.New()
	viewerRoleID := uuid.New()
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants (id, display_name) VALUES ($1, $2)`, tenantID, displayName); err != nil {
		t.Fatalf("insert site tenant: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO access_scopes (id, kind, tenant_id) VALUES ($1, 'tenant', $2)`, scopeID, tenantID); err != nil {
		t.Fatalf("insert site tenant scope: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO roles(id,scope_id,name,system_role) VALUES
		($1,$3,'tenant_owner',true),($2,$3,'tenant_viewer',true)`, ownerRoleID, viewerRoleID, scopeID); err != nil {
		t.Fatalf("insert site tenant system roles: %v", err)
	}
	if _, err := pool.Exec(ctx, `WITH additions AS (
		INSERT INTO role_permissions(role_id,permission_name) VALUES
			($1,'sites.read'),($1,'sites.manage'),($2,'sites.read')
		ON CONFLICT DO NOTHING RETURNING role_id,permission_name
	)
	INSERT INTO custom_rbac_system_role_permission_additions(role_id,permission_name)
	SELECT role_id,permission_name FROM additions ON CONFLICT DO NOTHING`, ownerRoleID, viewerRoleID); err != nil {
		t.Fatalf("project site tenant system role permissions: %v", err)
	}
	userID := insertSiteScopeUser(t, pool, scopeID, username, userDisplayName, passwordHash, []string{"sites.read", "sites.manage"})
	return siteTenantFixture{scopeID: scopeID, userID: userID, username: username}
}

func insertSiteScopeUser(
	t *testing.T,
	pool *pgxpool.Pool,
	scopeID uuid.UUID,
	username string,
	displayName string,
	passwordHash string,
	permissions []string,
) uuid.UUID {
	t.Helper()
	roleName := ""
	switch {
	case permissions == nil:
	case len(permissions) == 1 && permissions[0] == "sites.read":
		roleName = "tenant_viewer"
	case len(permissions) == 2 && permissions[0] == "sites.read" && permissions[1] == "sites.manage":
		roleName = "tenant_owner"
	case len(permissions) == 1 && permissions[0] == "security_policies.read":
		roleName = "tenant_viewer"
	case len(permissions) == 2 && permissions[0] == "security_policies.read" && permissions[1] == "security_policies.manage":
		roleName = "tenant_owner"
	case len(permissions) == 1 && permissions[0] == "url_auth_policies.read":
		roleName = "tenant_viewer"
	case len(permissions) == 2 && permissions[0] == "url_auth_policies.read" && permissions[1] == "url_auth_policies.manage":
		roleName = "tenant_owner"
	default:
		t.Fatalf("unsupported site fixture permissions for %q: %#v", username, permissions)
	}
	userID := uuid.New()
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, username, display_name, password_hash) VALUES ($1, $2, $3, $4)`,
		userID, username, displayName, passwordHash); err != nil {
		t.Fatalf("insert site scope user %q: %v", username, err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO memberships (scope_id, user_id) VALUES ($1, $2)`, scopeID, userID); err != nil {
		t.Fatalf("insert site membership %q: %v", username, err)
	}
	if roleName == "" {
		return userID
	}
	var roleID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM roles WHERE scope_id=$1 AND name=$2 AND system_role`,
		scopeID, roleName).Scan(&roleID); err != nil {
		t.Fatalf("load site system role %q for %q: %v", roleName, username, err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO role_assignments (scope_id, user_id, role_id) VALUES ($1, $2, $3)`, scopeID, userID, roleID); err != nil {
		t.Fatalf("assign site system role %q to %q: %v", roleName, username, err)
	}
	return userID
}

func validSiteBasic(domain, origin string) siteBasicPayload {
	return siteBasicPayload{
		Domains:          []string{domain},
		HTTPEnabled:      true,
		HTTPListenPorts:  []string{"80"},
		HTTPSListenPorts: []string{"443"},
		Origins:          []string{origin},
		CNAME:            stringsFromDomain(domain) + ".edge.example",
		HTTPSEnabled:     true,
		Enabled:          true,
		Status:           site.StatusActive,
	}
}

func stringsFromDomain(domain string) string {
	for index, character := range domain {
		if character == '.' {
			return domain[:index]
		}
	}
	return domain
}

func createSite(
	t *testing.T,
	client *http.Client,
	baseURL string,
	accessToken string,
	key string,
	body createSiteRequest,
) siteDetailResponse {
	t.Helper()
	response := siteRequest(t, client, http.MethodPost, baseURL+"/v1/sites", body, accessToken, key, "")
	var detail siteDetailResponse
	decodeResponse(t, response, http.StatusCreated, &detail)
	response.Body.Close()
	return detail
}

func updateSite(
	t *testing.T,
	client *http.Client,
	baseURL string,
	id uuid.UUID,
	accessToken string,
	key string,
	body updateSiteRequest,
) siteDetailResponse {
	t.Helper()
	response := siteRequest(t, client, http.MethodPatch, baseURL+"/v1/sites/"+id.String(), body, accessToken, key, "")
	var detail siteDetailResponse
	decodeResponse(t, response, http.StatusOK, &detail)
	response.Body.Close()
	return detail
}

func getSite(t *testing.T, client *http.Client, baseURL string, id uuid.UUID, accessToken string) siteDetailResponse {
	t.Helper()
	response := siteRequest(t, client, http.MethodGet, baseURL+"/v1/sites/"+id.String(), nil, accessToken, "", "")
	var detail siteDetailResponse
	decodeResponse(t, response, http.StatusOK, &detail)
	response.Body.Close()
	return detail
}

func listSites(t *testing.T, client *http.Client, rawURL, accessToken string) site.ListResult {
	t.Helper()
	response := siteRequest(t, client, http.MethodGet, rawURL, nil, accessToken, "", "")
	var result site.ListResult
	decodeResponse(t, response, http.StatusOK, &result)
	response.Body.Close()
	return result
}

func siteRequest(
	t *testing.T,
	client *http.Client,
	method string,
	rawURL string,
	body any,
	accessToken string,
	idempotencyKey string,
	ifMatch string,
	requestIDs ...string,
) *http.Response {
	t.Helper()
	response, err := performSiteRequest(client, method, rawURL, body, accessToken, idempotencyKey, ifMatch, requestIDs...)
	if err != nil {
		t.Fatalf("perform site request: %v", err)
	}
	return response
}

func performSiteRequest(
	client *http.Client,
	method string,
	rawURL string,
	body any,
	accessToken string,
	idempotencyKey string,
	ifMatch string,
	requestIDs ...string,
) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequest(method, rawURL, reader)
	if err != nil {
		return nil, err
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if accessToken != "" {
		request.Header.Set("Authorization", "Bearer "+accessToken)
	}
	if idempotencyKey != "" {
		request.Header.Set("Idempotency-Key", idempotencyKey)
	}
	if ifMatch != "" {
		request.Header.Set("If-Match", ifMatch)
	}
	if len(requestIDs) > 0 && requestIDs[0] != "" {
		request.Header.Set("X-Request-ID", requestIDs[0])
	}
	return client.Do(request)
}

func concurrentSiteRequests[T any](count int, operation func(int) T) []T {
	results := make([]T, count)
	var wait sync.WaitGroup
	for index := 0; index < count; index++ {
		index := index
		wait.Add(1)
		go func() {
			defer wait.Done()
			results[index] = operation(index)
		}()
	}
	wait.Wait()
	return results
}

// insertSiteFlowPackageAndGroup gives tenant an active per-site CNAME package
// (product ID returned) and a site group named "Production".
func insertSiteFlowPackageAndGroup(t *testing.T, pool *pgxpool.Pool, tenant siteTenantFixture) (string, string) {
	t.Helper()
	subscriptionID := insertPackageSubscriptionWithSpec(t, pool, tenant.scopeID, tenant.userID, func(groupID uuid.UUID) string {
		return strings.Replace(validL4HTTPPackageSpec(groupID), `"domain":"cdn.example.com"`, `"domain":"edge.example"`, 1)
	})
	ctx := context.Background()
	var productID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT product_id FROM package_subscriptions WHERE id=$1`, subscriptionID).Scan(&productID); err != nil {
		t.Fatalf("load site flow package product: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO package_monitor_subscription_owners(subscription_id,state_revision,tenant_scope_id,
		owner_user_id,source_kind,created_at) VALUES($1,1,$2,$3,'subscription_state',clock_timestamp())`,
		subscriptionID, tenant.scopeID, tenant.userID); err != nil {
		t.Fatalf("project site flow package owner: %v", err)
	}
	groupID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO site_groups(id,scope_id,name) VALUES($1,$2,'Production')`, groupID, tenant.scopeID); err != nil {
		t.Fatalf("insert site flow group: %v", err)
	}
	return productID.String(), groupID.String()
}
