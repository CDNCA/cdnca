package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/artifactsync/artifactsynctest"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestSecurityPolicyHTTPFlow(t *testing.T) {
	pool := isolatedTestPool(t)
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	identityStore := identity.NewStore(pool)
	platform, err := identityStore.BootstrapPlatformUser(context.Background(), "securityadmin", "Security Admin", passwordHash, "security-bootstrap")
	if err != nil {
		t.Fatalf("BootstrapPlatformUser: %v", err)
	}
	tenantA := insertSecurityTenant(t, pool, "Security Tenant A", "security-a", passwordHash)
	tenantB := insertSecurityTenant(t, pool, "Security Tenant B", "security-b", passwordHash)
	// 创建 CC 策略要求属主持有含 custom_cc 的有效套餐（6ada1749f 起）。
	insertPackageSubscriptionWithSpec(t, pool, tenantA.scopeID, tenantA.userID, func(groupID uuid.UUID) string {
		return strings.Replace(validL4HTTPPackageSpec(groupID), `"custom_cc":false`, `"custom_cc":true`, 1)
	})
	readerID := insertSiteScopeUser(t, pool, tenantA.scopeID, "security-reader", "Security Reader", passwordHash, []string{"security_policies.read"})
	if readerID == uuid.Nil {
		t.Fatal("reader was not created")
	}

	tokens, err := identity.NewTokenManager("security-policy-integration-secret-32bytes", 5*time.Minute)
	if err != nil {
		t.Fatalf("NewTokenManager: %v", err)
	}
	identityService, err := identity.NewService(identityStore, tokens, 24*time.Hour)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	serverConfig := Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32)}
	server := httptest.NewServer(New(pool, identityService, serverConfig).Handler())
	t.Cleanup(server.Close)
	client := server.Client()
	platformAuth, _ := loginOK(t, client, server.URL, "securityadmin")
	tenantAAuth := loginForScope(t, client, server.URL, tenantA.username, tenantA.scopeID)
	tenantBAuth := loginForScope(t, client, server.URL, tenantB.username, tenantB.scopeID)
	readerAuth := loginForScope(t, client, server.URL, "security-reader", tenantA.scopeID)

	createBody := createSecurityPolicyRequest{
		TargetScopeID: tenantA.scopeID.String(), OwnerID: tenantA.userID.String(),
		PolicyFields: validSecurityPolicyFields("API CC", securitypolicy.KindCC),
	}
	created := createSecurityPolicy(t, client, server.URL, platformAuth.AccessToken, "security-create", createBody)
	if created.Revision != 1 || created.Owner == nil || created.Owner.ID != tenantA.userID || created.Rules[0].ID == uuid.Nil {
		t.Fatalf("created policy = %#v", created)
	}

	t.Run("ACL import line errors and durable replay", func(t *testing.T) {
		invalidBody := createSecurityPolicyRequest{PolicyFields: securitypolicy.PolicyFields{
			Kind: securitypolicy.KindACL, Name: "Imported ACL", Enabled: true, DefaultAction: securitypolicy.ActionAllow,
			ACLImport: "deny 192.0.2.1\nblock 2001:db8::/129",
		}}
		response := siteRequest(t, client, http.MethodPost, server.URL+"/v1/security-policies", invalidBody, tenantAAuth.AccessToken, "acl-import-invalid", "")
		var invalid struct {
			Error struct {
				Code       string                              `json:"code"`
				LineErrors []securitypolicy.ACLImportLineError `json:"line_errors"`
			} `json:"error"`
		}
		decodeResponse(t, response, http.StatusUnprocessableEntity, &invalid)
		response.Body.Close()
		if invalid.Error.Code != "acl_import_invalid" || !reflect.DeepEqual(invalid.Error.LineErrors, []securitypolicy.ACLImportLineError{
			{Line: 1, Code: "invalid_action"}, {Line: 2, Code: "invalid_cidr"},
		}) {
			t.Fatalf("invalid import=%#v", invalid)
		}

		validBody := invalidBody
		validBody.ACLImport = "block 192.0.2.0/24 expires=2030-01-02T03:04:05Z # deny office\nallow 192.0.2.42 # operator"
		imported := createSecurityPolicy(t, client, server.URL, tenantAAuth.AccessToken, "acl-import-valid", validBody)
		replayed := createSecurityPolicy(t, client, server.URL, tenantAAuth.AccessToken, "acl-import-valid", validBody)
		if replayed.ID != imported.ID || len(imported.Rules) != 2 || imported.Rules[0].Action != securitypolicy.ActionAllow ||
			imported.Rules[0].Comment != "operator" || imported.Rules[1].ExpiresAt != "2030-01-02T03:04:05Z" {
			t.Fatalf("imported=%#v replayed=%#v", imported, replayed)
		}
		crossTenant := siteRequest(t, client, http.MethodGet, server.URL+"/v1/security-policies/"+imported.ID.String(), nil, tenantBAuth.AccessToken, "", "")
		assertError(t, crossTenant, http.StatusNotFound, "security_policy_not_found", "")
		crossTenant.Body.Close()
		var audits int
		if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE resource_id=$1 AND action='security_policy.create'`, imported.ID.String()).Scan(&audits); err != nil {
			t.Fatalf("count ACL audit: %v", err)
		}
		if audits != 1 {
			t.Fatalf("ACL audit count=%d", audits)
		}
	})

	t.Run("idempotency and validation", func(t *testing.T) {
		replayed := createSecurityPolicy(t, client, server.URL, platformAuth.AccessToken, "security-create", createBody)
		if replayed.ID != created.ID || replayed.Rules[0].ID != created.Rules[0].ID {
			t.Fatalf("create replay changed generated IDs: %#v", replayed)
		}
		conflicting := createBody
		conflicting.Name = "Different"
		response := siteRequest(t, client, http.MethodPost, server.URL+"/v1/security-policies", conflicting, platformAuth.AccessToken, "security-create", "")
		assertError(t, response, http.StatusConflict, "idempotency_conflict", "")
		response.Body.Close()

		invalid := createBody
		invalid.Name = "Unsafe"
		invalid.Rules = []securitypolicy.Rule{{
			Name: "unsafe", Priority: 1, Enabled: true,
			Conditions: []securitypolicy.Condition{{Field: "path", Operator: "regex", Values: []string{".*"}}},
			Action:     securitypolicy.ActionBlock, Flow: securitypolicy.FlowStop,
		}}
		response = siteRequest(t, client, http.MethodPost, server.URL+"/v1/security-policies", invalid, platformAuth.AccessToken, "security-invalid", "")
		assertError(t, response, http.StatusBadRequest, "validation_error", "")
		response.Body.Close()
	})

	t.Run("tenant isolation redaction and reader RBAC", func(t *testing.T) {
		page := listSecurityPolicies(t, client, server.URL+"/v1/security-policies?page=1&limit=20", tenantAAuth.AccessToken)
		if page.Total != 2 || len(page.Items) != 2 {
			t.Fatalf("tenant A page = %#v", page)
		}
		foundCreated := false
		for _, item := range page.Items {
			if item.ID == created.ID {
				foundCreated = true
				if item.Owner != nil {
					t.Fatalf("tenant policy owner was not redacted: %#v", item)
				}
			}
		}
		if !foundCreated {
			t.Fatalf("tenant policy page did not contain created policy: %#v", page)
		}
		other := siteRequest(t, client, http.MethodGet, server.URL+"/v1/security-policies/"+created.ID.String(), nil, tenantBAuth.AccessToken, "", "")
		assertError(t, other, http.StatusNotFound, "security_policy_not_found", "")
		other.Body.Close()
		ownerFilter := siteRequest(t, client, http.MethodGet, server.URL+"/v1/security-policies?owner=Security", nil, tenantAAuth.AccessToken, "", "")
		assertError(t, ownerFilter, http.StatusForbidden, "permission_denied", "")
		ownerFilter.Body.Close()
		write := siteRequest(t, client, http.MethodPatch, server.URL+"/v1/security-policies/"+created.ID.String(), createdFields(created), readerAuth.AccessToken, "reader-write", `"1"`)
		assertError(t, write, http.StatusForbidden, "permission_denied", "")
		write.Body.Close()
	})

	t.Run("matcher and filter projections keep scope and validation", func(t *testing.T) {
		response := siteRequest(t, client, http.MethodGet, server.URL+"/v1/security-policies/matchers?page=1&limit=10&name=block", nil, tenantAAuth.AccessToken, "", "")
		var matchers ccReferenceList
		decodeResponse(t, response, http.StatusOK, &matchers)
		response.Body.Close()
		if matchers.Total != 0 || len(matchers.Items) != 0 {
			t.Fatalf("tenant matcher projection = %#v", matchers)
		}
		response = siteRequest(t, client, http.MethodGet, server.URL+"/v1/security-policies/filters", nil, tenantAAuth.AccessToken, "", "")
		var filters ccReferenceList
		decodeResponse(t, response, http.StatusOK, &filters)
		response.Body.Close()
		if filters.Total != 0 || len(filters.Items) != 0 {
			t.Fatalf("block-only filter projection = %#v", filters)
		}
		response = siteRequest(t, client, http.MethodGet, server.URL+"/v1/security-policies/matchers", nil, tenantBAuth.AccessToken, "", "")
		var other ccReferenceList
		decodeResponse(t, response, http.StatusOK, &other)
		response.Body.Close()
		if other.Total != 0 || len(other.Items) != 0 {
			t.Fatalf("cross-tenant matcher projection = %#v", other)
		}
		insertSystemCCReferenceFixtures(t, pool, tenantA, tenantB)
		response = siteRequest(t, client, http.MethodGet, server.URL+"/v1/security-policies/matchers?page=1&limit=10", nil, platformAuth.AccessToken, "", "")
		var allPlatformMatchers ccReferenceList
		decodeResponse(t, response, http.StatusOK, &allPlatformMatchers)
		response.Body.Close()
		legacyFound := false
		for _, item := range allPlatformMatchers.Items {
			legacyFound = legacyFound || item.SystemRuleID == "legacy-300"
		}
		if allPlatformMatchers.Total != 2 || len(allPlatformMatchers.Items) != 2 || !legacyFound {
			t.Fatalf("platform key and legacy ID aggregation = %#v", allPlatformMatchers)
		}
		response = siteRequest(t, client, http.MethodGet, server.URL+"/v1/security-policies/matchers?page=1&limit=10&status=disabled", nil, platformAuth.AccessToken, "", "")
		var platformMatchers ccReferenceList
		decodeResponse(t, response, http.StatusOK, &platformMatchers)
		response.Body.Close()
		if platformMatchers.Total != 1 || len(platformMatchers.Items) != 1 || platformMatchers.Items[0].SystemRuleKey != "cc.challenge.5s.60-5" || platformMatchers.Items[0].Status != "disabled" {
			t.Fatalf("platform system matcher aggregation = %#v", platformMatchers)
		}
		response = siteRequest(t, client, http.MethodGet, server.URL+"/v1/security-policies/filters?page=1&limit=10&status=disabled", nil, platformAuth.AccessToken, "", "")
		var platformFilters ccReferenceList
		decodeResponse(t, response, http.StatusOK, &platformFilters)
		response.Body.Close()
		if platformFilters.Total != 1 || len(platformFilters.Items) != 1 || platformFilters.Items[0].SystemRuleKey != "cc.challenge.5s.60-5" || platformFilters.Items[0].Status != "disabled" {
			t.Fatalf("platform system filter aggregation = %#v", platformFilters)
		}
		response = siteRequest(t, client, http.MethodGet, server.URL+"/v1/security-policies/filters?page=1&limit=10", nil, tenantAAuth.AccessToken, "", "")
		var tenantFilters ccReferenceList
		decodeResponse(t, response, http.StatusOK, &tenantFilters)
		response.Body.Close()
		if tenantFilters.Total != 1 || len(tenantFilters.Items) != 1 || tenantFilters.Items[0].SystemRuleKey != "cc.challenge.5s.60-5" {
			t.Fatalf("tenant system filter projection = %#v", tenantFilters)
		}
		response = siteRequest(t, client, http.MethodGet, server.URL+"/v1/security-policies/matchers?status=unknown", nil, tenantAAuth.AccessToken, "", "")
		assertError(t, response, http.StatusBadRequest, "validation_error", "")
		response.Body.Close()
	})

	t.Run("matcher and filter CRUD keeps RBAC idempotency and revisions", func(t *testing.T) {
		matcherBody := map[string]any{
			"name":        "手工匹配器",
			"description": "独立匹配器",
			"enabled":     true,
			"field":       "path",
			"operator":    "prefix",
			"values":      []string{"/admin"},
		}
		createdResponse := siteRequest(t, client, http.MethodPost, server.URL+"/v1/security-policies/matchers", matcherBody, tenantAAuth.AccessToken, "cc-matcher-create", "")
		var matcher ccReference
		decodeResponse(t, createdResponse, http.StatusCreated, &matcher)
		if matcher.Name != "手工匹配器" || matcher.Version != 1 || matcher.Owner != nil || matcher.Field != "path" {
			t.Fatalf("created matcher = %#v", matcher)
		}
		createdResponse.Body.Close()

		replayedResponse := siteRequest(t, client, http.MethodPost, server.URL+"/v1/security-policies/matchers", matcherBody, tenantAAuth.AccessToken, "cc-matcher-create", "")
		var replayedMatcher ccReference
		decodeResponse(t, replayedResponse, http.StatusCreated, &replayedMatcher)
		replayedResponse.Body.Close()
		if replayedMatcher.ID != matcher.ID || replayedMatcher.Version != matcher.Version {
			t.Fatalf("matcher replay = %#v, original = %#v", replayedMatcher, matcher)
		}

		changedBody := map[string]any{"name": "重放冲突", "description": "", "enabled": true, "field": "path", "operator": "prefix", "values": []string{"/other"}}
		conflictingResponse := siteRequest(t, client, http.MethodPost, server.URL+"/v1/security-policies/matchers", changedBody, tenantAAuth.AccessToken, "cc-matcher-create", "")
		assertError(t, conflictingResponse, http.StatusConflict, "idempotency_conflict", "")
		conflictingResponse.Body.Close()

		readResponse := siteRequest(t, client, http.MethodGet, server.URL+"/v1/security-policies/matchers/"+matcher.ID.String(), nil, tenantAAuth.AccessToken, "", "")
		var readMatcher ccReference
		decodeResponse(t, readResponse, http.StatusOK, &readMatcher)
		readResponse.Body.Close()
		if readMatcher.Owner != nil || readMatcher.Version != 1 {
			t.Fatalf("tenant matcher detail = %#v", readMatcher)
		}

		updatedBody := map[string]any{"name": "手工匹配器已更新", "description": "更新", "enabled": true, "field": "path", "operator": "prefix", "values": []string{"/admin", "/ops"}}
		updatedResponse := siteRequest(t, client, http.MethodPatch, server.URL+"/v1/security-policies/matchers/"+matcher.ID.String(), updatedBody, tenantAAuth.AccessToken, "cc-matcher-update", `"1"`)
		var updatedMatcher ccReference
		decodeResponse(t, updatedResponse, http.StatusOK, &updatedMatcher)
		updatedResponse.Body.Close()
		if updatedMatcher.Version != 2 || updatedMatcher.Name != "手工匹配器已更新" || len(updatedMatcher.Values) != 2 {
			t.Fatalf("updated matcher = %#v", updatedMatcher)
		}
		staleResponse := siteRequest(t, client, http.MethodPatch, server.URL+"/v1/security-policies/matchers/"+matcher.ID.String(), updatedBody, tenantAAuth.AccessToken, "cc-matcher-stale", `"1"`)
		assertError(t, staleResponse, http.StatusConflict, "version_conflict", "")
		staleResponse.Body.Close()

		readerWrite := siteRequest(t, client, http.MethodPost, server.URL+"/v1/security-policies/matchers", map[string]any{
			"name": "读者不能创建", "description": "", "enabled": true, "field": "path", "operator": "equals", "values": []string{"/"},
		}, readerAuth.AccessToken, "cc-reader-create", "")
		assertError(t, readerWrite, http.StatusForbidden, "permission_denied", "")
		readerWrite.Body.Close()
		crossTenant := siteRequest(t, client, http.MethodGet, server.URL+"/v1/security-policies/matchers/"+matcher.ID.String(), nil, tenantBAuth.AccessToken, "", "")
		assertError(t, crossTenant, http.StatusNotFound, "cc_reference_not_found", "")
		crossTenant.Body.Close()

		filterBody := map[string]any{
			"name": "手工过滤器", "description": "独立过滤器", "enabled": true, "type": "req_rate",
			"parameters": map[string]any{"window_seconds": 10, "max_requests": 2},
		}
		filterResponse := siteRequest(t, client, http.MethodPost, server.URL+"/v1/security-policies/filters", filterBody, tenantAAuth.AccessToken, "cc-filter-create", "")
		var filter ccReference
		decodeResponse(t, filterResponse, http.StatusCreated, &filter)
		filterResponse.Body.Close()
		if filter.Name != "手工过滤器" || filter.Type != "req_rate" || filter.Version != 1 || filter.Owner != nil {
			t.Fatalf("created filter = %#v", filter)
		}

		platformList := siteRequest(t, client, http.MethodGet, server.URL+"/v1/security-policies/matchers?name=%E6%89%8B%E5%B7%A5%E5%8C%B9%E9%85%8D%E5%99%A8%E5%B7%B2%E6%9B%B4%E6%96%B0&owner=Security%20Tenant%20A", nil, platformAuth.AccessToken, "", "")
		var platformMatchers ccReferenceList
		decodeResponse(t, platformList, http.StatusOK, &platformMatchers)
		platformList.Body.Close()
		if platformMatchers.Total != 1 || len(platformMatchers.Items) != 1 || platformMatchers.Items[0].Owner == nil || platformMatchers.Items[0].Owner.ID != tenantA.userID {
			t.Fatalf("platform matcher owner projection = %#v", platformMatchers)
		}

		disableResponse := siteRequest(t, client, http.MethodPost, server.URL+"/v1/security-policies/matchers/"+matcher.ID.String()+"/disable", nil, tenantAAuth.AccessToken, "cc-matcher-disable", `"2"`)
		var disabledMatcher ccReference
		decodeResponse(t, disableResponse, http.StatusOK, &disabledMatcher)
		disableResponse.Body.Close()
		if disabledMatcher.Status != "disabled" || disabledMatcher.Version != 3 {
			t.Fatalf("disabled matcher = %#v", disabledMatcher)
		}

		deleteResponse := siteRequest(t, client, http.MethodDelete, server.URL+"/v1/security-policies/matchers/"+matcher.ID.String(), nil, tenantAAuth.AccessToken, "cc-matcher-delete", `"3"`)
		if deleteResponse.StatusCode != http.StatusNoContent {
			t.Fatalf("delete status = %d, body=%s", deleteResponse.StatusCode, readBody(deleteResponse.Body))
		}
		deleteResponse.Body.Close()
		goneResponse := siteRequest(t, client, http.MethodGet, server.URL+"/v1/security-policies/matchers/"+matcher.ID.String(), nil, tenantAAuth.AccessToken, "", "")
		assertError(t, goneResponse, http.StatusNotFound, "cc_reference_not_found", "")
		goneResponse.Body.Close()
	})

	t.Run("evaluate preview", func(t *testing.T) {
		response := siteRequest(t, client, http.MethodPost, server.URL+"/v1/security-policies/"+created.ID.String()+"/evaluate", securitypolicy.RequestFacts{
			ClientIP: "2001:db8::ffff", Host: "API.EXAMPLE", Path: "/login", Method: "get", Country: "cn", Port: 443,
			Headers: securitypolicy.HeaderValues{},
		}, tenantAAuth.AccessToken, "", `"1"`)
		var evaluation securitypolicy.Evaluation
		decodeResponse(t, response, http.StatusOK, &evaluation)
		response.Body.Close()
		if evaluation.Action != securitypolicy.ActionBlock || evaluation.TerminalRuleID == nil || evaluation.UsedDefault {
			t.Fatalf("evaluation = %#v", evaluation)
		}
	})

	t.Run("concurrent revision has one winner", func(t *testing.T) {
		bodies := []securitypolicy.PolicyFields{createdFields(created), createdFields(created)}
		bodies[0].Description = "winner-a"
		bodies[1].Description = "winner-b"
		statuses := make([]int, 2)
		codes := make([]string, 2)
		var updated [2]securitypolicy.Policy
		var group sync.WaitGroup
		for index := range bodies {
			group.Add(1)
			go func(index int) {
				defer group.Done()
				response, requestErr := performSiteRequest(client, http.MethodPatch,
					server.URL+"/v1/security-policies/"+created.ID.String(), bodies[index],
					platformAuth.AccessToken, fmt.Sprintf("security-race-%d", index), `"1"`)
				if requestErr != nil {
					codes[index] = requestErr.Error()
					return
				}
				statuses[index] = response.StatusCode
				if response.StatusCode == http.StatusOK {
					_ = decodeJSONResponse(response, &updated[index])
				} else {
					var envelope testErrorEnvelope
					_ = decodeJSONResponse(response, &envelope)
					codes[index] = envelope.Error.Code
				}
				response.Body.Close()
			}(index)
		}
		group.Wait()
		sort.Ints(statuses)
		if statuses[0] != http.StatusOK || statuses[1] != http.StatusConflict {
			t.Fatalf("race statuses = %v codes=%v", statuses, codes)
		}
		var winner securitypolicy.Policy
		for _, item := range updated {
			if item.ID != uuid.Nil {
				winner = item
			}
		}
		if winner.Revision != 2 {
			t.Fatalf("winner = %#v", winner)
		}
		created = winner
	})

	t.Run("audit failure rolls back resource and idempotency claim", func(t *testing.T) {
		ctx := context.Background()
		if _, err := pool.Exec(ctx, `CREATE FUNCTION fail_security_policy_audit() RETURNS trigger LANGUAGE plpgsql AS $$
			BEGIN IF NEW.action='security_policy.create' AND NEW.request_id='security-audit-fail' THEN
				RAISE EXCEPTION 'injected audit failure'; END IF; RETURN NEW; END $$`); err != nil {
			t.Fatalf("create failure function: %v", err)
		}
		if _, err := pool.Exec(ctx, `CREATE TRIGGER fail_security_policy_audit
			BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION fail_security_policy_audit()`); err != nil {
			t.Fatalf("create failure trigger: %v", err)
		}
		body := createBody
		body.Name = "Must Roll Back"
		response := siteRequest(t, client, http.MethodPost, server.URL+"/v1/security-policies", body,
			platformAuth.AccessToken, "security-audit-rollback", "", "security-audit-fail")
		assertError(t, response, http.StatusInternalServerError, "internal_error", "security-audit-fail")
		response.Body.Close()
		if _, err := pool.Exec(ctx, `DROP TRIGGER fail_security_policy_audit ON audit_events; DROP FUNCTION fail_security_policy_audit()`); err != nil {
			t.Fatalf("drop failure trigger: %v", err)
		}
		var policies, writes int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM security_policies WHERE name='Must Roll Back'`).Scan(&policies); err != nil {
			t.Fatalf("count rolled back policies: %v", err)
		}
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM security_policy_write_requests WHERE idempotency_key='security-audit-rollback'`).Scan(&writes); err != nil {
			t.Fatalf("count rolled back writes: %v", err)
		}
		if policies != 0 || writes != 0 {
			t.Fatalf("audit rollback policies=%d writes=%d", policies, writes)
		}
	})

	var versions int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM security_policy_versions WHERE policy_id=$1`, created.ID).Scan(&versions); err != nil {
		t.Fatalf("count versions: %v", err)
	}
	if versions != 2 {
		t.Fatalf("version snapshots = %d, want 2", versions)
	}
	response := siteRequest(t, client, http.MethodDelete, server.URL+"/v1/security-policies/"+created.ID.String(), nil,
		platformAuth.AccessToken, "security-delete", quoteVersion(created.Revision))
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("delete status = %d", response.StatusCode)
	}
	response.Body.Close()
	response = siteRequest(t, client, http.MethodDelete, server.URL+"/v1/security-policies/"+created.ID.String(), nil,
		platformAuth.AccessToken, "security-delete", quoteVersion(created.Revision))
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("delete replay status = %d", response.StatusCode)
	}
	response.Body.Close()
	if err := audit.New(pool).VerifyScope(context.Background(), platform.ScopeID); err != nil {
		t.Fatalf("VerifyScope platform: %v", err)
	}
	if err := audit.New(pool).VerifyScope(context.Background(), tenantA.scopeID); err != nil {
		t.Fatalf("VerifyScope tenant: %v", err)
	}
}

func TestSecurityPolicyMigrationDownUp(t *testing.T) {
	// Only 1..026: rolling the release head back crosses migration 268's
	// one-way down gate (P2682).
	pool := migrationRoundTripPool(t, 26)
	if migrationVersion(t, pool) != 26 {
		t.Fatalf("migration version = %d, want 26", migrationVersion(t, pool))
	}
	if err := database.Migrate(context.Background(), pool, "down"); err != nil {
		t.Fatalf("migrate 026 down: %v", err)
	}
	if migrationVersion(t, pool) != 25 || relationExists(t, pool, "security_policies") {
		t.Fatalf("migration 026 rollback did not remove security policy schema")
	}
	if err := databasetest.MigrateThrough(context.Background(), pool, "up", 26); err != nil {
		t.Fatalf("migrate 026 up: %v", err)
	}
	if migrationVersion(t, pool) != 26 || !relationExists(t, pool, "security_policies") {
		t.Fatalf("migration 026 reapply did not restore security policy schema")
	}
}

type securityTenantFixture struct {
	scopeID  uuid.UUID
	userID   uuid.UUID
	username string
}

func insertSecurityTenant(t *testing.T, pool *pgxpool.Pool, displayName, username, passwordHash string) securityTenantFixture {
	t.Helper()
	tenantID, scopeID := uuid.New(), uuid.New()
	ownerRoleID, viewerRoleID := uuid.New(), uuid.New()
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,display_name) VALUES($1,$2)`, tenantID, displayName); err != nil {
		t.Fatalf("insert security tenant: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, scopeID, tenantID); err != nil {
		t.Fatalf("insert security scope: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO roles(id,scope_id,name,system_role) VALUES
		($1,$3,'tenant_owner',true),($2,$3,'tenant_viewer',true)`, ownerRoleID, viewerRoleID, scopeID); err != nil {
		t.Fatalf("insert security tenant roles: %v", err)
	}
	if _, err := pool.Exec(ctx, `WITH additions AS (
		INSERT INTO role_permissions(role_id,permission_name) VALUES
			($1,'security_policies.read'),($1,'security_policies.manage'),($2,'security_policies.read')
		ON CONFLICT DO NOTHING RETURNING role_id,permission_name
	)
	INSERT INTO custom_rbac_system_role_permission_additions(role_id,permission_name)
	SELECT role_id,permission_name FROM additions ON CONFLICT DO NOTHING`, ownerRoleID, viewerRoleID); err != nil {
		t.Fatalf("project security tenant role permissions: %v", err)
	}
	userID := insertSiteScopeUser(t, pool, scopeID, username, displayName+" Owner", passwordHash,
		[]string{"security_policies.read", "security_policies.manage"})
	return securityTenantFixture{scopeID: scopeID, userID: userID, username: username}
}

func insertSystemCCReferenceFixtures(t *testing.T, pool *pgxpool.Pool, tenants ...securityTenantFixture) {
	t.Helper()
	ctx := context.Background()
	key := "cc.challenge.5s.60-5"
	for index, tenant := range tenants {
		now := time.Now().UTC()
		enabled := index == 0
		if _, err := pool.Exec(ctx, `INSERT INTO cc_reference_matchers(
			id,scope_id,tenant_id,owner_user_id,name,description,field,operator,condition_key,values,
			enabled,revision,created_by_user_id,updated_by_user_id,created_at,updated_at,system_rule,system_rule_id,system_rule_sort,system_rule_key)
			VALUES($1,$2,(SELECT tenant_id FROM access_scopes WHERE id=$2),$3,$4,'','path','prefix','',$5,$8,1,$3,$3,$6,$6,true,'challenge-5s',1,$7)`,
			uuid.New(), tenant.scopeID, tenant.userID, "5秒盾60-5", []byte(`[]`), now, key, enabled); err != nil {
			t.Fatalf("insert system matcher fixture: %v", err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO cc_reference_filters(
			id,scope_id,tenant_id,owner_user_id,name,description,filter_type,parameters,
			enabled,revision,created_by_user_id,updated_by_user_id,created_at,updated_at,system_rule,system_rule_id,system_rule_sort,system_rule_key)
			VALUES($1,$2,(SELECT tenant_id FROM access_scopes WHERE id=$2),$3,$4,'','challenge_5s',$5,$8,1,$3,$3,$6,$6,true,'challenge-5s',1,$7)`,
			uuid.New(), tenant.scopeID, tenant.userID, "5秒盾60-5", []byte(`{}`), now, key, enabled); err != nil {
			t.Fatalf("insert system filter fixture: %v", err)
		}
	}
	_, err := pool.Exec(ctx, `INSERT INTO cc_reference_filters(
		id,scope_id,tenant_id,owner_user_id,name,description,filter_type,parameters,
		enabled,revision,created_by_user_id,updated_by_user_id,created_at,updated_at,system_rule,system_rule_id,system_rule_sort,system_rule_key)
		VALUES($1,$2,(SELECT tenant_id FROM access_scopes WHERE id=$2),$3,'重复键探针','','challenge_5s','{}'::jsonb,true,1,$3,$3,$4,$4,true,'challenge-5s',1,$5)`,
		uuid.New(), tenants[0].scopeID, tenants[0].userID, time.Now().UTC(), key)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
		t.Fatalf("duplicate system projection error = %v", err)
	}
	tenant := tenants[0]
	_, err = pool.Exec(ctx, `INSERT INTO cc_reference_matchers(
		id,scope_id,tenant_id,owner_user_id,name,description,field,operator,condition_key,values,
		enabled,revision,created_by_user_id,updated_by_user_id,created_at,updated_at,
		system_rule,system_rule_id,system_rule_sort,system_rule_key)
		VALUES($1,$2,(SELECT tenant_id FROM access_scopes WHERE id=$2),$3,'旧版系统规则','','path','prefix','', '[]'::jsonb,
		true,1,$3,$3,$4,$4,true,'legacy-300',2,'')`, uuid.New(), tenant.scopeID, tenant.userID, time.Now().UTC())
	if err != nil {
		t.Fatalf("insert legacy system projection: %v", err)
	}
}

func validSecurityPolicyFields(name, kind string) securitypolicy.PolicyFields {
	return securitypolicy.PolicyFields{
		Kind: kind, Name: name, Description: "Security policy", Enabled: true, DefaultAction: securitypolicy.ActionAllow,
		Rules: []securitypolicy.Rule{{
			Name: "block login", Priority: 100, Enabled: true,
			Conditions: []securitypolicy.Condition{
				{Field: "path", Operator: "prefix", Values: []string{"/login"}},
				{Field: "method", Operator: "equals", Values: []string{"GET"}},
				{Field: "client_ip", Operator: "ip_in_cidr", Values: []string{"2001:db8::/32"}},
			},
			Action: securitypolicy.ActionBlock, Flow: securitypolicy.FlowStop,
		}},
	}
}

func createdFields(item securitypolicy.Policy) securitypolicy.PolicyFields {
	return securitypolicy.PolicyFields{
		Kind: item.Kind, Name: item.Name, Description: item.Description, Enabled: item.Enabled,
		DefaultAction: item.DefaultAction, Rules: item.Rules,
	}
}

func createSecurityPolicy(t *testing.T, client *http.Client, baseURL, token, key string, body createSecurityPolicyRequest) securitypolicy.Policy {
	t.Helper()
	response := siteRequest(t, client, http.MethodPost, baseURL+"/v1/security-policies", body, token, key, "")
	var item securitypolicy.Policy
	decodeResponse(t, response, http.StatusCreated, &item)
	response.Body.Close()
	return item
}

func listSecurityPolicies(t *testing.T, client *http.Client, rawURL, token string) securitypolicy.ListResult {
	t.Helper()
	response := siteRequest(t, client, http.MethodGet, rawURL, nil, token, "", "")
	var result securitypolicy.ListResult
	decodeResponse(t, response, http.StatusOK, &result)
	response.Body.Close()
	return result
}

func decodeJSONResponse(response *http.Response, destination any) error {
	return json.NewDecoder(response.Body).Decode(destination)
}

func migrationVersion(t *testing.T, pool *pgxpool.Pool) int64 {
	t.Helper()
	var version int64
	if err := pool.QueryRow(context.Background(), `SELECT COALESCE(max(version),0) FROM schema_migrations`).Scan(&version); err != nil {
		t.Fatalf("read migration version: %v", err)
	}
	return version
}

func relationExists(t *testing.T, pool *pgxpool.Pool, name string) bool {
	t.Helper()
	var exists bool
	if err := pool.QueryRow(context.Background(), `SELECT to_regclass($1) IS NOT NULL`, name).Scan(&exists); err != nil {
		t.Fatalf("check relation %s: %v", name, err)
	}
	return exists
}

// TestSecurityPolicyQuickBlockHTTP: PUT .../quick-block and
// GET .../ip-intel-status over HTTP with RBAC, the library gate and the
// stable 422 codes.
func TestSecurityPolicyQuickBlockHTTP(t *testing.T) {
	pool := isolatedTestPool(t)
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	identityStore := identity.NewStore(pool)
	tenantA := insertSecurityTenant(t, pool, "Quick Block Tenant", "quick-block-a", passwordHash)
	insertSiteScopeUser(t, pool, tenantA.scopeID, "quick-block-reader", "Quick Block Reader", passwordHash, []string{"security_policies.read"})
	tokens, err := identity.NewTokenManager("security-policy-quick-block-secret-32bytes", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(identityStore, tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(New(pool, identityService, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32)}).Handler())
	t.Cleanup(server.Close)
	client := server.Client()
	tenantAAuth := loginForScope(t, client, server.URL, tenantA.username, tenantA.scopeID)
	readerAuth := loginForScope(t, client, server.URL, "quick-block-reader", tenantA.scopeID)

	waf := createSecurityPolicy(t, client, server.URL, tenantAAuth.AccessToken, "quick-block-waf", createSecurityPolicyRequest{
		PolicyFields: validSecurityPolicyFields("Quick block WAF", securitypolicy.KindWAF)})
	url := server.URL + "/v1/security-policies/" + waf.ID.String() + "/quick-block"
	body := securitypolicy.QuickBlock{BlockIDCCN: true, Carriers: []string{}, AllowedCrawlers: nil}
	var status struct {
		Ready    bool   `json:"ready"`
		Revision uint64 `json:"revision"`
	}
	response := siteRequest(t, client, http.MethodGet, server.URL+"/v1/security-policies/ip-intel-status", nil, readerAuth.AccessToken, "", "")
	decodeResponse(t, response, http.StatusOK, &status)
	response.Body.Close()
	if status.Ready || status.Revision != 0 {
		t.Fatalf("status without library = %+v", status)
	}
	response = siteRequest(t, client, http.MethodPut, url, body, tenantAAuth.AccessToken, "quick-block-no-lib", `"1"`)
	assertError(t, response, http.StatusUnprocessableEntity, "quick_block_ip_intel_unavailable", "")
	response = siteRequest(t, client, http.MethodPut, url, body, readerAuth.AccessToken, "quick-block-reader", `"1"`)
	assertError(t, response, http.StatusForbidden, "permission_denied", "")
	artifactsynctest.SeedDownloaded(t, pool, artifactsynctest.IPIntelBase(3, "ipx-test", strings.Repeat("0", 64), 2),
		bytes.Repeat([]byte{1}, 65))
	response = siteRequest(t, client, http.MethodPut, url, body, tenantAAuth.AccessToken, "quick-block-on", `"1"`)
	var updated securitypolicy.Policy
	decodeResponse(t, response, http.StatusOK, &updated)
	if response.Header.Get("ETag") != `"2"` || updated.QuickBlock == nil || !updated.QuickBlock.BlockIDCCN ||
		len(updated.Rules) != 2 || !securitypolicy.IsQuickBlockRuleID(updated.Rules[0].ID) {
		t.Fatalf("quick block response = %+v etag %s", updated, response.Header.Get("ETag"))
	}
	response.Body.Close()
	blockDefault := validSecurityPolicyFields("Whitelist WAF", securitypolicy.KindWAF)
	blockDefault.DefaultAction = securitypolicy.ActionBlock
	whitelist := createSecurityPolicy(t, client, server.URL, tenantAAuth.AccessToken, "quick-block-whitelist",
		createSecurityPolicyRequest{PolicyFields: blockDefault})
	response = siteRequest(t, client, http.MethodPut, server.URL+"/v1/security-policies/"+whitelist.ID.String()+"/quick-block",
		body, tenantAAuth.AccessToken, "quick-block-whitelist-on", quoteVersion(whitelist.Revision))
	assertError(t, response, http.StatusUnprocessableEntity, "quick_block_unsupported_policy", "")
	response = siteRequest(t, client, http.MethodPut, url, map[string]any{"block_idc_cn": true, "unknown": 1},
		tenantAAuth.AccessToken, "quick-block-unknown", `"2"`)
	assertError(t, response, http.StatusBadRequest, "invalid_request", "")
}
