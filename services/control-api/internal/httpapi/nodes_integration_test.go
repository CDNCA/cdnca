package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	nodedomain "github.com/cdnca/cdnca/services/control-api/internal/node"
	"github.com/cdnca/cdnca/services/control-api/internal/nodepresence"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestNodeInventoryAndEnrollmentFlow(t *testing.T) {
	pool := isolatedTestPool(t)
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	identityStore := identity.NewStore(pool)
	bootstrap, err := identityStore.BootstrapPlatformUser(
		context.Background(),
		"nodeadmin",
		"Node Admin",
		passwordHash,
		"node-test-bootstrap",
	)
	if err != nil {
		t.Fatalf("BootstrapPlatformUser() error = %v", err)
	}
	insertTestUser(t, pool, bootstrap.ScopeID, "nodeviewer", "Node Viewer", passwordHash, "active")
	readerID := insertTestUser(t, pool, bootstrap.ScopeID, "nodereader", "Node Reader", passwordHash, "active")
	managerID := insertTestUser(t, pool, bootstrap.ScopeID, "nodemanager", "Node Manager", passwordHash, "active")
	grantNodePermissions(t, pool, bootstrap.ScopeID, readerID, "nodes.read")
	grantNodePermissions(t, pool, bootstrap.ScopeID, managerID, "nodes.manage")
	tenantUsername, tenantScopeID := insertTenantAdmin(t, pool, passwordHash)

	tokens, err := identity.NewTokenManager("node-integration-secret-at-least-thirty-two-bytes", 5*time.Minute)
	if err != nil {
		t.Fatalf("NewTokenManager() error = %v", err)
	}
	identityService, err := identity.NewService(identityStore, tokens, 24*time.Hour)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	fixedNow := time.Now().UTC().Truncate(time.Second)
	key := newSiteTestKey(t, "node-inventory-key")
	trust := newSiteTestTrust(t, key)
	installNodeTestEntitlement(t, pool, trust, fixedNow, nodeTestLeaseOptions{
		serial: 1, limit: 100, key: key,
	})
	server := httptest.NewServer(New(pool, identityService, Config{
		CookieSecure: false, APIKeyPepper: bytes.Repeat([]byte{0x52}, 32),
		Now: func() time.Time { return fixedNow }, EntitlementTrust: trust,
	}).Handler())
	t.Cleanup(server.Close)
	client := server.Client()
	adminAuth, _ := loginOK(t, client, server.URL, "nodeadmin")
	viewerAuth, _ := loginOK(t, client, server.URL, "nodeviewer")
	readerAuth, _ := loginOK(t, client, server.URL, "nodereader")
	managerAuth, _ := loginOK(t, client, server.URL, "nodemanager")
	tenantAuth := loginForScope(t, client, server.URL, tenantUsername, tenantScopeID)

	t.Run("authentication and platform RBAC", func(t *testing.T) {
		unauthenticated := doRequest(t, client, http.MethodGet, server.URL+"/v1/nodes", nil, nil, "")
		assertError(t, unauthenticated, http.StatusUnauthorized, "invalid_session", "")
		unauthenticated.Body.Close()

		for name, accessToken := range map[string]string{
			"platform without role": viewerAuth.AccessToken,
			"tenant owner":          tenantAuth.AccessToken,
		} {
			t.Run(name, func(t *testing.T) {
				response := doRequest(t, client, http.MethodGet, server.URL+"/v1/nodes", nil, nil, accessToken)
				assertError(t, response, http.StatusForbidden, "permission_denied", "")
				response.Body.Close()
			})
		}

		readAllowed := doRequest(t, client, http.MethodGet, server.URL+"/v1/nodes", nil, nil, readerAuth.AccessToken)
		if readAllowed.StatusCode != http.StatusOK {
			t.Fatalf("nodes.read list status = %d, want 200", readAllowed.StatusCode)
		}
		readAllowed.Body.Close()
		readDenied := doRequest(t, client, http.MethodGet, server.URL+"/v1/nodes", nil, nil, managerAuth.AccessToken)
		assertError(t, readDenied, http.StatusForbidden, "permission_denied", "")
		readDenied.Body.Close()
		manageDenied := doRequest(t, client, http.MethodPost, server.URL+"/v1/nodes", map[string]any{"name": "Reader Denied"}, nil, readerAuth.AccessToken)
		assertError(t, manageDenied, http.StatusForbidden, "permission_denied", "")
		manageDenied.Body.Close()
		manageAllowed := nodeWriteRequest(t, client, http.MethodPost, server.URL+"/v1/nodes",
			map[string]any{"name": "Manager Allowed"}, managerAuth.AccessToken, "manager-create", "", "")
		if manageAllowed.StatusCode != http.StatusCreated {
			t.Fatalf("nodes.manage create status = %d, want 201, body = %s", manageAllowed.StatusCode, readBody(manageAllowed.Body))
		}
		manageAllowed.Body.Close()
	})

	t.Run("input limits and unknown JSON", func(t *testing.T) {
		cases := []struct {
			name string
			body map[string]any
		}{
			{name: "unknown field", body: map[string]any{"name": "node", "secret": "not-allowed"}},
			{name: "long name", body: map[string]any{"name": strings.Repeat("n", 129)}},
			{name: "invalid IPv4", body: map[string]any{"name": "node", "ipv4": "2001:db8::1"}},
			{name: "oversized TTL", body: map[string]any{"name": "node", "issue_enrollment_token": true, "enrollment_token_ttl_seconds": 86401}},
		}
		for _, test := range cases {
			t.Run(test.name, func(t *testing.T) {
				response := doRequest(t, client, http.MethodPost, server.URL+"/v1/nodes", test.body, nil, adminAuth.AccessToken)
				if response.StatusCode != http.StatusBadRequest {
					t.Fatalf("status = %d, want 400, body = %s", response.StatusCode, readBody(response.Body))
				}
				response.Body.Close()
			})
		}
	})

	created := createNodeWithToken(t, client, server.URL, adminAuth.AccessToken, "Edge Shanghai")
	if created.Node.AdminState != nodedomain.StatePending {
		t.Fatalf("created node state = %q, want pending", created.Node.AdminState)
	}
	if created.EnrollmentToken == nil || len(created.EnrollmentToken.Token) != 43 {
		t.Fatalf("created enrollment token = %#v", created.EnrollmentToken)
	}

	t.Run("raw token is returned once and never persisted or audited", func(t *testing.T) {
		var storedHash []byte
		if err := pool.QueryRow(context.Background(), `
			SELECT token_hash FROM node_enrollment_tokens WHERE id = $1`,
			created.EnrollmentToken.ID,
		).Scan(&storedHash); err != nil {
			t.Fatalf("read stored token hash: %v", err)
		}
		if len(storedHash) != sha256.Size || string(storedHash) == created.EnrollmentToken.Token {
			t.Fatalf("stored enrollment token is not a SHA-256 digest")
		}
		var leaked bool
		if err := pool.QueryRow(context.Background(), `
			SELECT EXISTS (
				SELECT 1 FROM audit_events WHERE payload::text LIKE '%' || $1 || '%'
			)`, created.EnrollmentToken.Token).Scan(&leaked); err != nil {
			t.Fatalf("scan audit payloads: %v", err)
		}
		if leaked {
			t.Fatal("raw enrollment token leaked into audit payload")
		}
	})

	t.Run("duplicate names are case insensitive", func(t *testing.T) {
		response := nodeWriteRequest(t, client, http.MethodPost, server.URL+"/v1/nodes", map[string]any{
			"name": "edge shanghai",
		}, adminAuth.AccessToken, "duplicate-edge-shanghai", "", "")
		assertError(t, response, http.StatusConflict, "node_name_conflict", "")
		response.Body.Close()
	})

	second := createNodeWithToken(t, client, server.URL, adminAuth.AccessToken, "Edge Beijing")
	t.Run("get and stable pagination", func(t *testing.T) {
		invalid := doRequest(t, client, http.MethodGet, server.URL+"/v1/nodes/not-a-uuid", nil, nil, adminAuth.AccessToken)
		assertError(t, invalid, http.StatusBadRequest, "validation_error", "")
		invalid.Body.Close()
		missing := doRequest(t, client, http.MethodGet, server.URL+"/v1/nodes/"+uuid.NewString(), nil, nil, adminAuth.AccessToken)
		assertError(t, missing, http.StatusNotFound, "node_not_found", "")
		missing.Body.Close()

		response := doRequest(t, client, http.MethodGet, server.URL+"/v1/nodes/"+created.Node.ID.String(), nil, nil, adminAuth.AccessToken)
		var fetched nodedomain.Node
		decodeResponse(t, response, http.StatusOK, &fetched)
		response.Body.Close()
		if fetched.ID != created.Node.ID {
			t.Fatalf("fetched node ID = %s, want %s", fetched.ID, created.Node.ID)
		}

		pageOne := getNodePage(t, client, server.URL+"/v1/nodes?status=pending&limit=1", adminAuth.AccessToken)
		if len(pageOne.Items) != 1 || pageOne.NextCursor == nil {
			t.Fatalf("first node page = %#v", pageOne)
		}
		pageTwo := getNodePage(t, client, server.URL+"/v1/nodes?status=pending&limit=1&cursor="+pageOne.NextCursor.String(), adminAuth.AccessToken)
		if len(pageTwo.Items) != 1 || pageTwo.Items[0].ID == pageOne.Items[0].ID {
			t.Fatalf("second node page = %#v", pageTwo)
		}
		pageMax := getNodePage(t, client, server.URL+"/v1/nodes?limit=300", adminAuth.AccessToken)
		if len(pageMax.Items) < 2 {
			t.Fatalf("maximum node page = %#v, want all seeded nodes", pageMax)
		}

		for _, query := range []string{"?status=unknown", "?limit=301", "?cursor=bad"} {
			bad := doRequest(t, client, http.MethodGet, server.URL+"/v1/nodes"+query, nil, nil, adminAuth.AccessToken)
			assertError(t, bad, http.StatusBadRequest, "validation_error", "")
			bad.Body.Close()
		}
	})

	t.Run("server-side search matches node identity and keeps stable pagination", func(t *testing.T) {
		name := getNodePage(t, client, server.URL+"/v1/nodes?search=SHANGHAI", adminAuth.AccessToken)
		if len(name.Items) != 1 || name.Items[0].ID != created.Node.ID {
			t.Fatalf("name search = %#v, want node %s", name, created.Node.ID)
		}
		region := getNodePage(t, client, server.URL+"/v1/nodes?search=cn-east", adminAuth.AccessToken)
		if len(region.Items) < 2 {
			t.Fatalf("region search = %#v, want both CN-East nodes", region)
		}
		byUUID := getNodePage(t, client, server.URL+"/v1/nodes?search="+created.Node.ID.String(), adminAuth.AccessToken)
		if len(byUUID.Items) != 1 || byUUID.Items[0].ID != created.Node.ID {
			t.Fatalf("UUID search = %#v, want node %s", byUUID, created.Node.ID)
		}
		byDisplayID := getNodePage(t, client, server.URL+"/v1/nodes?search="+created.Node.DisplayID, adminAuth.AccessToken)
		if len(byDisplayID.Items) == 0 || byDisplayID.Items[0].DisplayID != created.Node.DisplayID {
			t.Fatalf("display ID search = %#v, want prefix %s", byDisplayID, created.Node.DisplayID)
		}
		for _, address := range []string{"192.0.2.10", "2001:0db8:0:0:0:0:0:10"} {
			byIP := getNodePage(t, client, server.URL+"/v1/nodes?search="+address, adminAuth.AccessToken)
			if len(byIP.Items) < 2 {
				t.Fatalf("IP search %q = %#v, want both matching nodes", address, byIP)
			}
		}

		pageOne := getNodePage(t, client, server.URL+"/v1/nodes?search=edge&limit=1", adminAuth.AccessToken)
		if len(pageOne.Items) != 1 || pageOne.NextCursor == nil {
			t.Fatalf("first searched page = %#v", pageOne)
		}
		pageTwo := getNodePage(t, client, server.URL+"/v1/nodes?search=edge&limit=1&cursor="+pageOne.NextCursor.String(), adminAuth.AccessToken)
		if len(pageTwo.Items) != 1 || pageTwo.Items[0].ID.String() <= pageOne.Items[0].ID.String() {
			t.Fatalf("second searched page = %#v after %#v", pageTwo, pageOne)
		}
		unfiltered := getNodePage(t, client, server.URL+"/v1/nodes?limit=100", adminAuth.AccessToken)
		blank := getNodePage(t, client, server.URL+"/v1/nodes?search=+++&limit=100", adminAuth.AccessToken)
		if len(blank.Items) != len(unfiltered.Items) || (blank.NextCursor == nil) != (unfiltered.NextCursor == nil) {
			t.Fatalf("blank search changed the unfiltered page: blank=%#v unfiltered=%#v", blank, unfiltered)
		}
		for index := range blank.Items {
			if blank.Items[index].ID != unfiltered.Items[index].ID {
				t.Fatalf("blank search order changed at %d: blank=%#v unfiltered=%#v", index, blank, unfiltered)
			}
		}
		if blank.NextCursor != nil && *blank.NextCursor != *unfiltered.NextCursor {
			t.Fatalf("blank search cursor changed: blank=%#v unfiltered=%#v", blank, unfiltered)
		}

		for _, query := range []string{"?search=%0A", "?search=" + strings.Repeat("n", nodepresence.MaxInventorySearchRunes+1)} {
			bad := doRequest(t, client, http.MethodGet, server.URL+"/v1/nodes"+query, nil, nil, adminAuth.AccessToken)
			assertError(t, bad, http.StatusBadRequest, "validation_error", "")
			bad.Body.Close()
		}
	})

	t.Run("metadata update, IP clearing, ETag, validation, and idempotency", func(t *testing.T) {
		item := createNodeWithToken(t, client, server.URL, adminAuth.AccessToken, "Lifecycle Metadata")
		body := map[string]any{
			"name": "Lifecycle Metadata Updated", "description": "updated", "region": "CN-North",
			"ipv4": "", "ipv6": "2001:db8::22",
		}
		response := nodeWriteRequest(t, client, http.MethodPatch, server.URL+"/v1/nodes/"+item.Node.ID.String(), body,
			adminAuth.AccessToken, "node-metadata-update", `"1"`, "node-metadata-request")
		var updated nodedomain.Node
		decodeResponse(t, response, http.StatusOK, &updated)
		if response.Header.Get("ETag") != `"2"` {
			t.Fatalf("update ETag = %q, want quoted revision 2", response.Header.Get("ETag"))
		}
		response.Body.Close()
		if updated.Revision != 2 || updated.Name != "Lifecycle Metadata Updated" || updated.IPv4 != nil || updated.IPv6 == nil || *updated.IPv6 != "2001:db8::22" {
			t.Fatalf("updated node = %#v", updated)
		}

		replay := nodeWriteRequest(t, client, http.MethodPatch, server.URL+"/v1/nodes/"+item.Node.ID.String(), body,
			adminAuth.AccessToken, "node-metadata-update", `"1"`, "node-metadata-replay")
		var replayed nodedomain.Node
		decodeResponse(t, replay, http.StatusOK, &replayed)
		replay.Body.Close()
		if replayed.Revision != updated.Revision || replayed.UpdatedAt != updated.UpdatedAt {
			t.Fatalf("idempotent replay = %#v, want original %#v", replayed, updated)
		}

		conflictBody := map[string]any{"description": "different"}
		conflict := nodeWriteRequest(t, client, http.MethodPatch, server.URL+"/v1/nodes/"+item.Node.ID.String(), conflictBody,
			adminAuth.AccessToken, "node-metadata-update", `"2"`, "node-metadata-conflict")
		assertError(t, conflict, http.StatusConflict, "idempotency_conflict", "")
		conflict.Body.Close()

		cases := []struct {
			name string
			body map[string]any
		}{
			{name: "empty patch", body: map[string]any{}},
			{name: "unknown field", body: map[string]any{"secret": "hidden"}},
			{name: "invalid IP", body: map[string]any{"ipv4": "2001:db8::1"}},
		}
		for index, test := range cases {
			response := nodeWriteRequest(t, client, http.MethodPatch, server.URL+"/v1/nodes/"+item.Node.ID.String(), test.body,
				adminAuth.AccessToken, fmt.Sprintf("node-invalid-%d", index), `"2"`, "")
			if response.StatusCode != http.StatusBadRequest {
				t.Fatalf("%s status = %d, want 400, body = %s", test.name, response.StatusCode, readBody(response.Body))
			}
			response.Body.Close()
		}

		permissionDenied := nodeWriteRequest(t, client, http.MethodPatch, server.URL+"/v1/nodes/"+item.Node.ID.String(),
			map[string]any{"description": "denied"}, readerAuth.AccessToken, "node-reader-denied", `"2"`, "")
		assertError(t, permissionDenied, http.StatusForbidden, "permission_denied", "")
		permissionDenied.Body.Close()
		tenantDenied := nodeWriteRequest(t, client, http.MethodPatch, server.URL+"/v1/nodes/"+item.Node.ID.String(),
			map[string]any{"description": "denied"}, tenantAuth.AccessToken, "node-tenant-denied", `"2"`, "")
		assertError(t, tenantDenied, http.StatusForbidden, "permission_denied", "")
		tenantDenied.Body.Close()
	})

	t.Run("scope isolation returns not found", func(t *testing.T) {
		foreignID := uuid.New()
		if _, err := pool.Exec(context.Background(), `
			INSERT INTO nodes (id, display_id, scope_id, name, created_by_user_id)
			VALUES ($1, 1, $2, 'Tenant Scoped Node', $3)`, foreignID, tenantScopeID, bootstrap.UserID); err != nil {
			t.Fatalf("insert cross-scope node fixture: %v", err)
		}
		response := doRequest(t, client, http.MethodGet, server.URL+"/v1/nodes/"+foreignID.String(), nil, nil, adminAuth.AccessToken)
		assertError(t, response, http.StatusNotFound, "node_not_found", "")
		response.Body.Close()
		for _, search := range []string{foreignID.String(), "Tenant+Scoped+Node"} {
			page := getNodePage(t, client, server.URL+"/v1/nodes?search="+search, adminAuth.AccessToken)
			if len(page.Items) != 0 || page.NextCursor != nil {
				t.Fatalf("cross-scope search %q leaked nodes: %#v", search, page)
			}
		}
	})

	t.Run("concurrent revision update has one winner", func(t *testing.T) {
		item := createNodeWithToken(t, client, server.URL, adminAuth.AccessToken, "Lifecycle Concurrent")
		type outcome struct {
			status int
			code   string
			err    error
		}
		outcomes := make(chan outcome, 2)
		for index := 0; index < 2; index++ {
			index := index
			go func() {
				response, err := performSiteRequest(client, http.MethodPatch, server.URL+"/v1/nodes/"+item.Node.ID.String(),
					map[string]any{"description": fmt.Sprintf("winner-%d", index)}, adminAuth.AccessToken,
					fmt.Sprintf("node-concurrent-%d", index), `"1"`, fmt.Sprintf("node-concurrent-request-%d", index))
				if err != nil {
					outcomes <- outcome{err: err}
					return
				}
				defer response.Body.Close()
				result := outcome{status: response.StatusCode}
				if response.StatusCode != http.StatusOK {
					var envelope errorEnvelope
					if err := json.NewDecoder(response.Body).Decode(&envelope); err != nil {
						result.err = err
					} else {
						result.code = envelope.Error.Code
					}
				}
				outcomes <- result
			}()
		}
		succeeded, conflicted := 0, 0
		for index := 0; index < 2; index++ {
			result := <-outcomes
			if result.err != nil {
				t.Fatalf("concurrent request error = %v", result.err)
			}
			switch {
			case result.status == http.StatusOK:
				succeeded++
			case result.status == http.StatusConflict && result.code == "version_conflict":
				conflicted++
			default:
				t.Fatalf("concurrent outcome = %#v", result)
			}
		}
		if succeeded != 1 || conflicted != 1 {
			t.Fatalf("concurrent outcomes succeeded=%d conflicted=%d", succeeded, conflicted)
		}
	})

	t.Run("pending activation bypass is denied and retire purges the node", func(t *testing.T) {
		item := createNodeWithToken(t, client, server.URL, adminAuth.AccessToken, "Lifecycle Pending")
		// Initializing (pending -> active) needs a completed enrollment with a
		// live certificate; other pending transitions stay denied.
		for index, state := range []string{nodedomain.StateActive, nodedomain.StateDisabled} {
			response := nodeWriteRequest(t, client, http.MethodPatch, server.URL+"/v1/nodes/"+item.Node.ID.String(),
				map[string]any{"admin_state": state}, adminAuth.AccessToken, fmt.Sprintf("pending-denied-%d", index), `"1"`, "")
			code := "node_state_transition_denied"
			if state == nodedomain.StateActive {
				code = "node_identity_required"
			}
			assertError(t, response, http.StatusConflict, code, "")
			response.Body.Close()
		}
		retire := nodeWriteRequest(t, client, http.MethodPatch, server.URL+"/v1/nodes/"+item.Node.ID.String(),
			map[string]any{"admin_state": nodedomain.StateRetired}, adminAuth.AccessToken, "pending-retire", `"1"`, "")
		var retired nodedomain.Node
		decodeResponse(t, retire, http.StatusOK, &retired)
		retire.Body.Close()
		metadata := nodeWriteRequest(t, client, http.MethodPatch, server.URL+"/v1/nodes/"+item.Node.ID.String(),
			map[string]any{"description": "immutable"}, adminAuth.AccessToken, "retired-metadata", quoteVersion(retired.Revision), "")
		// 9a2e5feae 起"退役"即物理删除，之后的写入找不到节点。
		assertError(t, metadata, http.StatusNotFound, "node_not_found", "")
		metadata.Body.Close()
	})

	t.Run("identity authorization gates node restoration", func(t *testing.T) {
		withoutIdentity := createNodeWithToken(t, client, server.URL, adminAuth.AccessToken, "Lifecycle No Identity")
		setGatewayActivatedNode(t, pool, withoutIdentity.Node.ID)
		disable := nodeWriteRequest(t, client, http.MethodPatch, server.URL+"/v1/nodes/"+withoutIdentity.Node.ID.String(),
			map[string]any{"admin_state": nodedomain.StateDisabled}, adminAuth.AccessToken, "no-identity-disable", `"2"`, "")
		var disabled nodedomain.Node
		decodeResponse(t, disable, http.StatusOK, &disabled)
		disable.Body.Close()
		restore := nodeWriteRequest(t, client, http.MethodPatch, server.URL+"/v1/nodes/"+withoutIdentity.Node.ID.String(),
			map[string]any{"admin_state": nodedomain.StateActive}, adminAuth.AccessToken, "no-identity-restore", quoteVersion(disabled.Revision), "")
		assertError(t, restore, http.StatusConflict, "node_identity_required", "")
		restore.Body.Close()

		withIdentity := createNodeWithToken(t, client, server.URL, adminAuth.AccessToken, "Lifecycle With Identity")
		digest := sha256.Sum256([]byte("gateway-enrollment"))
		if _, err := nodedomain.NewService(nodedomain.NewStore(pool)).ConsumeEnrollmentToken(context.Background(), nodedomain.ConsumeRequest{
			Token: withIdentity.EnrollmentToken.Token, Purpose: withIdentity.EnrollmentToken.Purpose,
			RequestID: "gateway-enrollment", RequestDigest: digest,
		}); err != nil {
			t.Fatalf("consume enrollment token: %v", err)
		}
		setGatewayActivatedNode(t, pool, withIdentity.Node.ID)
		disable = nodeWriteRequest(t, client, http.MethodPatch, server.URL+"/v1/nodes/"+withIdentity.Node.ID.String(),
			map[string]any{"admin_state": nodedomain.StateDisabled}, adminAuth.AccessToken, "identity-disable", `"2"`, "")
		decodeResponse(t, disable, http.StatusOK, &disabled)
		disable.Body.Close()
		restore = nodeWriteRequest(t, client, http.MethodPatch, server.URL+"/v1/nodes/"+withIdentity.Node.ID.String(),
			map[string]any{"admin_state": nodedomain.StateActive}, adminAuth.AccessToken, "identity-restore", quoteVersion(disabled.Revision), "")
		var restored nodedomain.Node
		decodeResponse(t, restore, http.StatusOK, &restored)
		restore.Body.Close()
		if restored.AdminState != nodedomain.StateActive {
			t.Fatalf("restored state = %q, want active", restored.AdminState)
		}
	})

	t.Run("batch state update is ordered, partial, bounded, and idempotent", func(t *testing.T) {
		success := createNodeWithToken(t, client, server.URL, adminAuth.AccessToken, "Batch Active")
		setGatewayActivatedNode(t, pool, success.Node.ID)
		pending := createNodeWithToken(t, client, server.URL, adminAuth.AccessToken, "Batch Pending")
		stale := createNodeWithToken(t, client, server.URL, adminAuth.AccessToken, "Batch Stale")
		setGatewayActivatedNode(t, pool, stale.Node.ID)
		missingID := uuid.New()
		body := map[string]any{
			"admin_state": nodedomain.StateDisabled,
			"items": []map[string]any{
				{"id": pending.Node.ID, "expected_revision": 1},
				{"id": success.Node.ID, "expected_revision": 2},
				{"id": stale.Node.ID, "expected_revision": 1},
				{"id": missingID, "expected_revision": 1},
			},
		}
		response := nodeWriteRequest(t, client, http.MethodPost, server.URL+"/v1/nodes/batch-admin-state", body,
			adminAuth.AccessToken, "node-batch-partial", "", "node-batch-partial-request")
		var result nodedomain.BatchAdminStateResult
		decodeResponse(t, response, http.StatusOK, &result)
		response.Body.Close()
		if len(result.Items) != 4 || result.Items[0].ID != pending.Node.ID || result.Items[0].Error == nil ||
			result.Items[0].Error.Code != "node_state_transition_denied" || result.Items[1].ID != success.Node.ID ||
			result.Items[1].Node == nil || result.Items[1].Node.AdminState != nodedomain.StateDisabled ||
			result.Items[2].ID != stale.Node.ID || result.Items[2].Error == nil || result.Items[2].Error.Code != "version_conflict" ||
			result.Items[3].ID != missingID || result.Items[3].Error == nil || result.Items[3].Error.Code != "node_not_found" {
			t.Fatalf("batch result = %#v", result)
		}
		var auditCount int
		if err := pool.QueryRow(context.Background(), `
			SELECT count(*) FROM audit_events
			WHERE action = 'node.batch_admin_state' AND request_id = 'node-batch-partial-request'`).Scan(&auditCount); err != nil {
			t.Fatalf("count batch audits: %v", err)
		}
		if auditCount != 1 {
			t.Fatalf("batch audit count = %d, want 1", auditCount)
		}

		replay := nodeWriteRequest(t, client, http.MethodPost, server.URL+"/v1/nodes/batch-admin-state", body,
			adminAuth.AccessToken, "node-batch-partial", "", "node-batch-replay")
		var replayed nodedomain.BatchAdminStateResult
		decodeResponse(t, replay, http.StatusOK, &replayed)
		replay.Body.Close()
		if replayed.Items[1].Node == nil || replayed.Items[1].Node.Revision != result.Items[1].Node.Revision {
			t.Fatalf("batch replay = %#v, want original revision", replayed)
		}
		if err := pool.QueryRow(context.Background(), `
			SELECT count(*) FROM audit_events WHERE action = 'node.batch_admin_state'`).Scan(&auditCount); err != nil {
			t.Fatalf("count all batch audits: %v", err)
		}
		if auditCount != 1 {
			t.Fatalf("batch audit count after replay = %d, want 1", auditCount)
		}
		idempotencyConflict := nodeWriteRequest(t, client, http.MethodPost, server.URL+"/v1/nodes/batch-admin-state",
			map[string]any{"admin_state": nodedomain.StateRetired, "items": body["items"]},
			adminAuth.AccessToken, "node-batch-partial", "", "node-batch-conflict")
		assertError(t, idempotencyConflict, http.StatusConflict, "idempotency_conflict", "")
		idempotencyConflict.Body.Close()

		sameState := nodeWriteRequest(t, client, http.MethodPost, server.URL+"/v1/nodes/batch-admin-state",
			map[string]any{"admin_state": nodedomain.StateDisabled, "items": []map[string]any{{
				"id": success.Node.ID, "expected_revision": result.Items[1].Node.Revision,
			}}}, adminAuth.AccessToken, "node-batch-same-state", "", "node-batch-same-state-request")
		var sameStateResult nodedomain.BatchAdminStateResult
		decodeResponse(t, sameState, http.StatusOK, &sameStateResult)
		sameState.Body.Close()
		if len(sameStateResult.Items) != 1 || sameStateResult.Items[0].Node == nil ||
			sameStateResult.Items[0].Node.Revision != result.Items[1].Node.Revision+1 ||
			sameStateResult.Items[0].Node.AdminState != nodedomain.StateDisabled {
			t.Fatalf("same-state batch result = %#v", sameStateResult)
		}

		duplicate := map[string]any{"admin_state": nodedomain.StateRetired, "items": []map[string]any{
			{"id": pending.Node.ID, "expected_revision": 1}, {"id": pending.Node.ID, "expected_revision": 1},
		}}
		bad := nodeWriteRequest(t, client, http.MethodPost, server.URL+"/v1/nodes/batch-admin-state", duplicate,
			adminAuth.AccessToken, "node-batch-duplicate", "", "")
		assertError(t, bad, http.StatusBadRequest, "validation_error", "")
		bad.Body.Close()

		tooMany := make([]map[string]any, 101)
		for index := range tooMany {
			tooMany[index] = map[string]any{"id": uuid.New(), "expected_revision": 1}
		}
		bad = nodeWriteRequest(t, client, http.MethodPost, server.URL+"/v1/nodes/batch-admin-state",
			map[string]any{"admin_state": nodedomain.StateRetired, "items": tooMany},
			adminAuth.AccessToken, "node-batch-too-many", "", "")
		assertError(t, bad, http.StatusBadRequest, "validation_error", "")
		bad.Body.Close()
	})

	domain := nodedomain.NewService(nodedomain.NewStore(pool))
	t.Run("restoration rejects an IP already used by a serving node", func(t *testing.T) {
		first := createNodeWithToken(t, client, server.URL, adminAuth.AccessToken, "Duplicate IP First")
		setGatewayActivatedNode(t, pool, first.Node.ID)
		firstUpdate := nodeWriteRequest(t, client, http.MethodPatch, server.URL+"/v1/nodes/"+first.Node.ID.String(), map[string]any{
			"ipv4": "198.51.100.220", "ipv6": "2001:db8::220",
		}, adminAuth.AccessToken, "duplicate-ip-first-update", `"2"`, "duplicate-ip-first-request")
		var updatedFirst nodedomain.Node
		decodeResponse(t, firstUpdate, http.StatusOK, &updatedFirst)
		firstUpdate.Body.Close()

		second := createNodeWithToken(t, client, server.URL, adminAuth.AccessToken, "Duplicate IP Second")
		digest := sha256.Sum256([]byte("duplicate-ip-enrollment"))
		if _, err := domain.ConsumeEnrollmentToken(context.Background(), nodedomain.ConsumeRequest{
			Token: second.EnrollmentToken.Token, Purpose: second.EnrollmentToken.Purpose,
			RequestID: "duplicate-ip-enrollment", RequestDigest: digest,
		}); err != nil {
			t.Fatalf("consume duplicate-IP enrollment token: %v", err)
		}
		setGatewayActivatedNode(t, pool, second.Node.ID)
		disable := nodeWriteRequest(t, client, http.MethodPatch, server.URL+"/v1/nodes/"+second.Node.ID.String(), map[string]any{
			"admin_state": nodedomain.StateDisabled,
		}, adminAuth.AccessToken, "duplicate-ip-disable", `"2"`, "duplicate-ip-disable-request")
		var disabledSecond nodedomain.Node
		decodeResponse(t, disable, http.StatusOK, &disabledSecond)
		disable.Body.Close()
		secondUpdate := nodeWriteRequest(t, client, http.MethodPatch, server.URL+"/v1/nodes/"+second.Node.ID.String(), map[string]any{
			"ipv4": "198.51.100.220", "ipv6": "2001:db8::220",
		}, adminAuth.AccessToken, "duplicate-ip-second-update", quoteVersion(disabledSecond.Revision), "duplicate-ip-second-request")
		var updatedSecond nodedomain.Node
		decodeResponse(t, secondUpdate, http.StatusOK, &updatedSecond)
		secondUpdate.Body.Close()
		activation := nodeWriteRequest(t, client, http.MethodPatch, server.URL+"/v1/nodes/"+second.Node.ID.String(), map[string]any{
			"admin_state": nodedomain.StateActive,
		}, adminAuth.AccessToken, "duplicate-ip-activation", quoteVersion(updatedSecond.Revision), "duplicate-ip-activation-request")
		assertError(t, activation, http.StatusConflict, "node_ip_conflict", "")
		activation.Body.Close()
	})
	t.Run("idempotent token consumption and conflict", func(t *testing.T) {
		issued := issueToken(t, client, server.URL, adminAuth.AccessToken, created.Node.ID)
		digest := sha256.Sum256([]byte("csr-request-one"))
		request := nodedomain.ConsumeRequest{
			Token: issued.Token, Purpose: issued.Purpose, RequestID: "consume-idempotent", RequestDigest: digest,
		}
		first, err := domain.ConsumeEnrollmentToken(context.Background(), request)
		if err != nil {
			t.Fatalf("first ConsumeEnrollmentToken() error = %v", err)
		}
		secondAuthorization, err := domain.ConsumeEnrollmentToken(context.Background(), request)
		if err != nil || secondAuthorization.ID != first.ID {
			t.Fatalf("idempotent ConsumeEnrollmentToken() = (%#v, %v), want authorization %s", secondAuthorization, err, first.ID)
		}
		request.RequestDigest = sha256.Sum256([]byte("different-csr"))
		if _, err := domain.ConsumeEnrollmentToken(context.Background(), request); !errors.Is(err, nodedomain.ErrIdempotencyConflict) {
			t.Fatalf("different digest error = %v, want ErrIdempotencyConflict", err)
		}
		request.RequestID = "consume-second-request"
		if _, err := domain.ConsumeEnrollmentToken(context.Background(), request); !errors.Is(err, nodedomain.ErrTokenConsumed) {
			t.Fatalf("second request error = %v, want ErrTokenConsumed", err)
		}
	})

	t.Run("invalid purpose and expired token are denied", func(t *testing.T) {
		issued := issueToken(t, client, server.URL, adminAuth.AccessToken, created.Node.ID)
		digest := sha256.Sum256([]byte("purpose-mismatch"))
		if _, err := domain.ConsumeEnrollmentToken(context.Background(), nodedomain.ConsumeRequest{
			Token: issued.Token, Purpose: nodedomain.PurposeReEnrollment, RequestID: "purpose-mismatch", RequestDigest: digest,
		}); !errors.Is(err, nodedomain.ErrInvalidToken) {
			t.Fatalf("purpose mismatch error = %v, want ErrInvalidToken", err)
		}

		expired := issueToken(t, client, server.URL, adminAuth.AccessToken, created.Node.ID)
		if _, err := pool.Exec(context.Background(), `
			UPDATE node_enrollment_tokens
			SET created_at = now() - interval '2 hours', expires_at = now() - interval '1 hour'
			WHERE id = $1`, expired.ID); err != nil {
			t.Fatalf("expire enrollment token: %v", err)
		}
		digest = sha256.Sum256([]byte("expired"))
		if _, err := domain.ConsumeEnrollmentToken(context.Background(), nodedomain.ConsumeRequest{
			Token: expired.Token, Purpose: expired.Purpose, RequestID: "expired-token", RequestDigest: digest,
		}); !errors.Is(err, nodedomain.ErrTokenExpired) {
			t.Fatalf("expired token error = %v, want ErrTokenExpired", err)
		}
	})

	t.Run("disabled and retired nodes are denied", func(t *testing.T) {
		for stateIndex, state := range []string{nodedomain.StateDisabled, nodedomain.StateRetired} {
			nodeResult := createNodeWithToken(t, client, server.URL, adminAuth.AccessToken, fmt.Sprintf("State Node %d", stateIndex))
			if _, err := pool.Exec(context.Background(), `UPDATE nodes SET admin_state = $2 WHERE id = $1`, nodeResult.Node.ID, state); err != nil {
				t.Fatalf("set node state %s: %v", state, err)
			}
			digest := sha256.Sum256([]byte(state))
			if _, err := domain.ConsumeEnrollmentToken(context.Background(), nodedomain.ConsumeRequest{
				Token: nodeResult.EnrollmentToken.Token, Purpose: nodeResult.EnrollmentToken.Purpose,
				RequestID: "consume-" + state, RequestDigest: digest,
			}); !errors.Is(err, nodedomain.ErrEnrollmentDenied) {
				t.Fatalf("consume on %s node error = %v, want ErrEnrollmentDenied", state, err)
			}
			issuedResponse := doRequest(t, client, http.MethodPost,
				server.URL+"/v1/nodes/"+nodeResult.Node.ID.String()+"/enrollment-tokens",
				map[string]any{}, nil, adminAuth.AccessToken)
			assertError(t, issuedResponse, http.StatusConflict, "enrollment_denied", "")
			issuedResponse.Body.Close()
		}
	})

	t.Run("concurrent consumption creates one authorization", func(t *testing.T) {
		issued := issueToken(t, client, server.URL, adminAuth.AccessToken, second.Node.ID)
		type outcome struct {
			authorization nodedomain.Authorization
			err           error
		}
		outcomes := make(chan outcome, 2)
		var wait sync.WaitGroup
		for index := 0; index < 2; index++ {
			index := index
			wait.Add(1)
			go func() {
				defer wait.Done()
				digest := sha256.Sum256([]byte(fmt.Sprintf("concurrent-%d", index)))
				authorization, err := domain.ConsumeEnrollmentToken(context.Background(), nodedomain.ConsumeRequest{
					Token: issued.Token, Purpose: issued.Purpose,
					RequestID: fmt.Sprintf("concurrent-%d", index), RequestDigest: digest,
				})
				outcomes <- outcome{authorization: authorization, err: err}
			}()
		}
		wait.Wait()
		close(outcomes)
		succeeded := 0
		consumed := 0
		for result := range outcomes {
			switch {
			case result.err == nil:
				succeeded++
			case errors.Is(result.err, nodedomain.ErrTokenConsumed):
				consumed++
			default:
				t.Fatalf("unexpected concurrent consume error = %v", result.err)
			}
		}
		if succeeded != 1 || consumed != 1 {
			t.Fatalf("concurrent outcomes: succeeded=%d consumed=%d", succeeded, consumed)
		}
		var authorizationCount int
		if err := pool.QueryRow(context.Background(), `
			SELECT count(*) FROM node_enrollment_authorizations WHERE token_id = $1`, issued.ID,
		).Scan(&authorizationCount); err != nil {
			t.Fatalf("count enrollment authorizations: %v", err)
		}
		if authorizationCount != 1 {
			t.Fatalf("authorization count = %d, want 1", authorizationCount)
		}
	})

	t.Run("unknown token denial and audit chain verification", func(t *testing.T) {
		digest := sha256.Sum256([]byte("unknown-token"))
		if _, err := domain.ConsumeEnrollmentToken(context.Background(), nodedomain.ConsumeRequest{
			Token: strings.Repeat("A", 43), Purpose: nodedomain.PurposeInitial,
			RequestID: "unknown-token", RequestDigest: digest,
		}); !errors.Is(err, nodedomain.ErrInvalidToken) {
			t.Fatalf("unknown token error = %v, want ErrInvalidToken", err)
		}
		if err := audit.New(pool).VerifyScope(context.Background(), bootstrap.ScopeID); err != nil {
			t.Fatalf("VerifyScope() error = %v", err)
		}
		var deniedCount int
		if err := pool.QueryRow(context.Background(), `
			SELECT count(*) FROM audit_events
			WHERE action = 'node.enrollment_token.reject' AND result = 'denied'`,
		).Scan(&deniedCount); err != nil {
			t.Fatalf("count enrollment denial audits: %v", err)
		}
		if deniedCount < 1 {
			t.Fatal("enrollment denials were not audited")
		}
	})
}

func TestNodeCreateEntitlementLifecycle(t *testing.T) {
	pool := isolatedTestPool(t)
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	identityStore := identity.NewStore(pool)
	bootstrap, err := identityStore.BootstrapPlatformUser(
		context.Background(), "node-entitlement-admin", "Node Entitlement Admin", passwordHash, "node-entitlement-bootstrap",
	)
	if err != nil {
		t.Fatalf("BootstrapPlatformUser() error = %v", err)
	}
	tokens, err := identity.NewTokenManager("node-entitlement-secret-at-least-thirty-two-bytes", 5*time.Minute)
	if err != nil {
		t.Fatalf("NewTokenManager() error = %v", err)
	}
	identityService, err := identity.NewService(identityStore, tokens, 24*time.Hour)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	baseTime := time.Now().UTC().Truncate(time.Second)
	var clockUnix atomic.Int64
	clockUnix.Store(baseTime.Unix())
	now := func() time.Time { return time.Unix(clockUnix.Load(), 0).UTC() }
	key := newSiteTestKey(t, "node-entitlement-key")
	trust := newSiteTestTrust(t, key)
	server := httptest.NewServer(New(pool, identityService, Config{
		CookieSecure: false, APIKeyPepper: bytes.Repeat([]byte{0x52}, 32),
		Now: now, EntitlementTrust: trust,
	}).Handler())
	t.Cleanup(server.Close)
	client := server.Client()
	auth, _ := loginOK(t, client, server.URL, "node-entitlement-admin")

	createBody := func(name string) map[string]any {
		return map[string]any{
			"name": name, "description": "Entitlement test node", "region": "CN-East",
			"ipv4": "192.0.2.20", "issue_enrollment_token": true,
			"enrollment_purpose": nodedomain.PurposeInitial, "enrollment_token_ttl_seconds": 600,
		}
	}
	post := func(idempotencyKey, requestID, name string) *http.Response {
		return nodeWriteRequest(t, client, http.MethodPost, server.URL+"/v1/nodes",
			createBody(name), auth.AccessToken, idempotencyKey, "", requestID)
	}

	response := post("node-no-lease", "node-no-lease-request", "No Lease")
	assertError(t, response, http.StatusForbidden, "entitlement_unavailable", "node-no-lease-request")
	response.Body.Close()
	assertNodeCreateResidue(t, pool, 0, 0, 0)
	assertNodeEntitlementAudit(t, pool, "node-no-lease-request", "uninstalled", 0, -1)

	installNodeTestEntitlement(t, pool, trust, baseTime, nodeTestLeaseOptions{
		serial: 1, limit: 2, key: key, omitFeature: true,
	})
	response = post("node-feature-missing", "node-feature-missing-request", "Feature Missing")
	assertError(t, response, http.StatusForbidden, "entitlement_feature_denied", "node-feature-missing-request")
	response.Body.Close()
	assertNodeCreateResidue(t, pool, 0, 0, 0)

	installNodeTestEntitlement(t, pool, trust, baseTime, nodeTestLeaseOptions{
		serial: 2, limit: 2, key: key, omitQuota: true,
	})
	response = post("node-quota-missing", "node-quota-missing-request", "Quota Missing")
	assertError(t, response, http.StatusForbidden, "entitlement_quota_denied", "node-quota-missing-request")
	response.Body.Close()
	assertNodeCreateResidue(t, pool, 0, 0, 0)

	installNodeTestEntitlement(t, pool, trust, baseTime, nodeTestLeaseOptions{
		serial: 3, limit: 2, key: key,
	})
	firstBody := createBody("First Licensed Node")
	response = nodeWriteRequest(t, client, http.MethodPost, server.URL+"/v1/nodes",
		firstBody, auth.AccessToken, "node-first", "", "node-first-request")
	var first createNodeResponse
	decodeResponse(t, response, http.StatusCreated, &first)
	response.Body.Close()
	if first.EnrollmentToken == nil || first.EnrollmentToken.Token == "" {
		t.Fatalf("first enrollment token = %#v", first.EnrollmentToken)
	}

	response = nodeWriteRequest(t, client, http.MethodPost, server.URL+"/v1/nodes",
		firstBody, auth.AccessToken, "node-first", "", "node-first-replay-request")
	var replay createNodeResponse
	decodeResponse(t, response, http.StatusCreated, &replay)
	response.Body.Close()
	if replay.Node.ID != first.Node.ID || replay.EnrollmentToken != nil {
		t.Fatalf("create replay = %#v, want node %s without token", replay, first.Node.ID)
	}
	var storedResponse string
	if err := pool.QueryRow(context.Background(), `
		SELECT response_body::text FROM node_write_requests
		WHERE actor_user_id = $1 AND operation = 'node.create' AND idempotency_key = 'node-first'`,
		bootstrap.UserID).Scan(&storedResponse); err != nil {
		t.Fatalf("read stored create response: %v", err)
	}
	if strings.Contains(storedResponse, "enrollment_token") || strings.Contains(storedResponse, first.EnrollmentToken.Token) {
		t.Fatalf("stored create response contains enrollment token: %s", storedResponse)
	}

	response = nodeWriteRequest(t, client, http.MethodPost, server.URL+"/v1/nodes",
		createBody("Different Payload"), auth.AccessToken, "node-first", "", "node-first-conflict-request")
	assertError(t, response, http.StatusConflict, "idempotency_conflict", "node-first-conflict-request")
	response.Body.Close()

	type createOutcome struct {
		status int
		code   string
		nodeID uuid.UUID
	}
	outcomes := make(chan createOutcome, 2)
	var wait sync.WaitGroup
	for index := 0; index < 2; index++ {
		index := index
		wait.Add(1)
		go func() {
			defer wait.Done()
			response := post(fmt.Sprintf("node-concurrent-%d", index), fmt.Sprintf("node-concurrent-request-%d", index), fmt.Sprintf("Concurrent Node %d", index))
			defer response.Body.Close()
			outcome := createOutcome{status: response.StatusCode}
			if response.StatusCode == http.StatusCreated {
				var created createNodeResponse
				_ = json.NewDecoder(response.Body).Decode(&created)
				outcome.nodeID = created.Node.ID
			} else {
				var envelope errorEnvelope
				_ = json.NewDecoder(response.Body).Decode(&envelope)
				outcome.code = envelope.Error.Code
			}
			outcomes <- outcome
		}()
	}
	wait.Wait()
	close(outcomes)
	var quotaWinner uuid.UUID
	var succeeded, exhausted int
	for outcome := range outcomes {
		switch {
		case outcome.status == http.StatusCreated:
			succeeded++
			quotaWinner = outcome.nodeID
		case outcome.status == http.StatusConflict && outcome.code == "entitlement_quota_exceeded":
			exhausted++
		default:
			t.Fatalf("unexpected concurrent node create outcome = %#v", outcome)
		}
	}
	if succeeded != 1 || exhausted != 1 {
		t.Fatalf("concurrent outcomes: succeeded=%d exhausted=%d", succeeded, exhausted)
	}

	if _, err := pool.Exec(context.Background(), `UPDATE nodes SET admin_state = 'disabled' WHERE id = $1`, first.Node.ID); err != nil {
		t.Fatalf("disable first node: %v", err)
	}
	response = post("node-disabled-still-counts", "node-disabled-still-counts-request", "Disabled Still Counts")
	assertError(t, response, http.StatusConflict, "entitlement_quota_exceeded", "node-disabled-still-counts-request")
	response.Body.Close()
	if _, err := pool.Exec(context.Background(), `UPDATE nodes SET admin_state = 'retired' WHERE id = $1`, quotaWinner); err != nil {
		t.Fatalf("retire quota winner: %v", err)
	}
	response = post("node-after-retire", "node-after-retire-request", "Replacement Node")
	var replacement createNodeResponse
	decodeResponse(t, response, http.StatusCreated, &replacement)
	response.Body.Close()

	clockUnix.Store(baseTime.Add(90 * time.Minute).Unix())
	// Grace keeps node creation allowed: it reaches
	// the quota check (still full here) instead of a state denial.
	response = post("node-grace-full", "node-grace-full-request", "Grace Full")
	assertError(t, response, http.StatusConflict, "entitlement_quota_exceeded", "node-grace-full-request")
	response.Body.Close()
	response = nodeWriteRequest(t, client, http.MethodPost, server.URL+"/v1/nodes",
		firstBody, auth.AccessToken, "node-first", "", "node-first-grace-replay")
	decodeResponse(t, response, http.StatusCreated, &replay)
	response.Body.Close()
	if replay.Node.ID != first.Node.ID || replay.EnrollmentToken != nil {
		t.Fatalf("grace replay = %#v", replay)
	}
	list := doRequest(t, client, http.MethodGet, server.URL+"/v1/nodes", nil, nil, auth.AccessToken)
	if list.StatusCode != http.StatusOK {
		t.Fatalf("grace list status = %d, body = %s", list.StatusCode, readBody(list.Body))
	}
	list.Body.Close()
	retire := nodeWriteRequest(t, client, http.MethodPatch, server.URL+"/v1/nodes/"+replacement.Node.ID.String(),
		map[string]any{"admin_state": nodedomain.StateRetired}, auth.AccessToken, "node-grace-retire", `"1"`, "node-grace-retire-request")
	var retired nodedomain.Node
	decodeResponse(t, retire, http.StatusOK, &retired)
	retire.Body.Close()
	response = post("node-grace-allowed", "node-grace-allowed-request", "Grace Allowed")
	var graceNode createNodeResponse
	decodeResponse(t, response, http.StatusCreated, &graceNode)
	response.Body.Close()

	clockUnix.Store(baseTime.Add(3 * time.Hour).Unix())
	response = post("node-expired-denied", "node-expired-denied-request", "Expired Denied")
	assertError(t, response, http.StatusForbidden, "entitlement_state_denied", "node-expired-denied-request")
	response.Body.Close()

	clockUnix.Store(baseTime.Unix())
	installNodeTestEntitlement(t, pool, trust, now(), nodeTestLeaseOptions{
		serial: 4, limit: 10, key: key,
	})
	if _, err := pool.Exec(context.Background(), `
		CREATE FUNCTION reject_node_create_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.action = 'node.enrollment_token.issue' AND NEW.request_id = 'node-audit-failure-request' THEN
				RAISE EXCEPTION 'injected node token audit failure';
			END IF;
			RETURN NEW;
		END $$;
		CREATE TRIGGER reject_node_create_audit_trigger
		BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION reject_node_create_audit()`); err != nil {
		t.Fatalf("install audit failure trigger: %v", err)
	}
	var beforeNodes, beforeTokens, beforeWrites int
	if err := pool.QueryRow(context.Background(), `
		SELECT (SELECT count(*) FROM nodes),
		       (SELECT count(*) FROM node_enrollment_tokens),
		       (SELECT count(*) FROM node_write_requests)`).Scan(&beforeNodes, &beforeTokens, &beforeWrites); err != nil {
		t.Fatalf("count before injected failure: %v", err)
	}
	response = post("node-audit-failure", "node-audit-failure-request", "Audit Failure")
	assertError(t, response, http.StatusInternalServerError, "internal_error", "node-audit-failure-request")
	response.Body.Close()
	assertNodeCreateResidue(t, pool, beforeNodes, beforeTokens, beforeWrites)
	if _, err := pool.Exec(context.Background(), `
		DROP TRIGGER reject_node_create_audit_trigger ON audit_events;
		DROP FUNCTION reject_node_create_audit()`); err != nil {
		t.Fatalf("remove audit failure trigger: %v", err)
	}
	if err := audit.New(pool).VerifyScope(context.Background(), bootstrap.ScopeID); err != nil {
		t.Fatalf("VerifyScope() error = %v", err)
	}
}

func TestNodeLifecycleMigrationRollbackAndReapply(t *testing.T) {
	// Migration 268's down is a deliberate one-way gate (P2682): seed and
	// round-trip 013/011 with only 1..013 loaded.
	pool := migrationRoundTripPool(t, 13)
	ctx := context.Background()
	// The 013 schema predates the current bootstrap path; seed the platform
	// actor the write requests reference directly.
	bootstrap := struct{ UserID, ScopeID uuid.UUID }{ScopeID: uuid.New()}
	if _, err := pool.Exec(ctx, `INSERT INTO access_scopes (id, kind) VALUES ($1, 'platform')`, bootstrap.ScopeID); err != nil {
		t.Fatalf("insert platform scope: %v", err)
	}
	bootstrap.UserID = insertTestUser(t, pool, bootstrap.ScopeID, "node-migration-owner",
		"Node Migration Owner", "unused", "active")
	// Migration 011 grants node permissions to the platform_owner system role.
	if _, err := pool.Exec(ctx, `INSERT INTO roles (id, scope_id, name, description, system_role)
		VALUES ($1, $2, 'platform_owner', 'Node migration platform owner', true)`, uuid.New(), bootstrap.ScopeID); err != nil {
		t.Fatalf("insert platform owner role: %v", err)
	}
	if err := database.Migrate(ctx, pool, "down"); err != nil {
		t.Fatalf("Migrate(down 013) error = %v", err)
	}
	var currentVersion int64
	if err := pool.QueryRow(ctx, `SELECT max(version) FROM schema_migrations`).Scan(&currentVersion); err != nil {
		t.Fatalf("inspect migration version after 013 rollback: %v", err)
	}
	if currentVersion != 12 {
		t.Fatalf("migration version after 013 rollback = %d, want 12", currentVersion)
	}
	legacyDigest := sha256.Sum256([]byte("legacy node.create rejection"))
	if _, err := pool.Exec(ctx, `
		INSERT INTO node_write_requests (
			id, actor_user_id, actor_scope_id, operation, idempotency_key, request_digest, created_at
		) VALUES ($1, $2, $3, 'node.create', 'legacy-node-create', $4, now())`,
		uuid.New(), bootstrap.UserID, bootstrap.ScopeID, legacyDigest[:]); err == nil {
		t.Fatal("migration 012 schema unexpectedly accepted node.create")
	}
	if err := databasetest.MigrateThrough(ctx, pool, "up", 13); err != nil {
		t.Fatalf("Migrate(up 013 from applied 012) error = %v", err)
	}
	upgradeDigest := sha256.Sum256([]byte("upgraded node.create acceptance"))
	if _, err := pool.Exec(ctx, `
		INSERT INTO node_write_requests (
			id, actor_user_id, actor_scope_id, operation, idempotency_key, request_digest, created_at
		) VALUES ($1, $2, $3, 'node.create', 'upgraded-node-create', $4, now())`,
		uuid.New(), bootstrap.UserID, bootstrap.ScopeID, upgradeDigest[:]); err != nil {
		t.Fatalf("migration 013 did not accept node.create: %v", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM node_write_requests WHERE idempotency_key = 'upgraded-node-create'`); err != nil {
		t.Fatalf("remove migration 013 probe: %v", err)
	}
	rollbackToMigration(t, pool, 11)
	if err := database.Migrate(ctx, pool, "down"); err != nil {
		t.Fatalf("Migrate(down 011) error = %v", err)
	}
	var writeTable *string
	if err := pool.QueryRow(ctx, "SELECT to_regclass('node_write_requests')::text").Scan(&writeTable); err != nil {
		t.Fatalf("inspect node write table after rollback: %v", err)
	}
	if writeTable != nil {
		t.Fatalf("node_write_requests still exists after migration rollback: %s", *writeTable)
	}
	var permissionCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM permissions WHERE name IN ('nodes.read', 'nodes.manage')`).Scan(&permissionCount); err != nil {
		t.Fatalf("inspect node permissions after rollback: %v", err)
	}
	if permissionCount != 0 {
		t.Fatalf("node permission count after rollback = %d, want 0", permissionCount)
	}
	if err := databasetest.MigrateThrough(ctx, pool, "up", 13); err != nil {
		t.Fatalf("Migrate(up 011) error = %v", err)
	}
	if err := pool.QueryRow(ctx, "SELECT to_regclass('node_write_requests')::text").Scan(&writeTable); err != nil {
		t.Fatalf("inspect node write table after reapply: %v", err)
	}
	if writeTable == nil {
		t.Fatal("node_write_requests is missing after migration reapply")
	}
	digest := sha256.Sum256([]byte("node.create migration check"))
	if _, err := pool.Exec(ctx, `
		INSERT INTO node_write_requests (
			id, actor_user_id, actor_scope_id, operation, idempotency_key, request_digest, created_at
		) VALUES ($1, $2, $3, 'node.create', 'migration-node-create', $4, now())`,
		uuid.New(), bootstrap.UserID, bootstrap.ScopeID, digest[:]); err != nil {
		t.Fatalf("insert node.create write request after reapply: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM permissions WHERE name IN ('nodes.read', 'nodes.manage')`).Scan(&permissionCount); err != nil {
		t.Fatalf("inspect node permissions after reapply: %v", err)
	}
	if permissionCount != 2 {
		t.Fatalf("node permission count after reapply = %d, want 2", permissionCount)
	}
	var ownerGrantCount int
	if err := pool.QueryRow(ctx, `
		SELECT count(*)
		FROM role_permissions rp
		JOIN roles r ON r.id = rp.role_id
		WHERE r.system_role AND r.name = 'platform_owner'
		  AND rp.permission_name IN ('nodes.read', 'nodes.manage')`).Scan(&ownerGrantCount); err != nil {
		t.Fatalf("inspect platform owner node grants after reapply: %v", err)
	}
	if ownerGrantCount != 2 {
		t.Fatalf("platform owner node grant count = %d, want 2", ownerGrantCount)
	}
}

func createNodeWithToken(
	t *testing.T,
	client *http.Client,
	baseURL string,
	accessToken string,
	name string,
) createNodeResponse {
	t.Helper()
	response := nodeWriteRequest(t, client, http.MethodPost, baseURL+"/v1/nodes", map[string]any{
		"name":                         name,
		"description":                  "Integration node",
		"region":                       "CN-East",
		"ipv4":                         "192.0.2.10",
		"ipv6":                         "2001:db8::10",
		"issue_enrollment_token":       true,
		"enrollment_purpose":           nodedomain.PurposeInitial,
		"enrollment_token_ttl_seconds": 600,
	}, accessToken, uuid.NewString(), "", uuid.NewString())
	var result createNodeResponse
	decodeResponse(t, response, http.StatusCreated, &result)
	response.Body.Close()
	return result
}

func issueToken(
	t *testing.T,
	client *http.Client,
	baseURL string,
	accessToken string,
	nodeID uuid.UUID,
) nodedomain.IssuedToken {
	t.Helper()
	response := doRequest(t, client, http.MethodPost,
		baseURL+"/v1/nodes/"+nodeID.String()+"/enrollment-tokens",
		map[string]any{"purpose": nodedomain.PurposeInitial, "ttl_seconds": 600},
		nil,
		accessToken,
	)
	var issued nodedomain.IssuedToken
	decodeResponse(t, response, http.StatusCreated, &issued)
	response.Body.Close()
	return issued
}

func getNodePage(t *testing.T, client *http.Client, url string, accessToken string) nodeListResponse {
	t.Helper()
	response := doRequest(t, client, http.MethodGet, url, nil, nil, accessToken)
	var page nodeListResponse
	decodeResponse(t, response, http.StatusOK, &page)
	response.Body.Close()
	return page
}

func nodeWriteRequest(
	t *testing.T,
	client *http.Client,
	method string,
	rawURL string,
	body any,
	accessToken string,
	idempotencyKey string,
	ifMatch string,
	requestID string,
) *http.Response {
	t.Helper()
	return siteRequest(t, client, method, rawURL, body, accessToken, idempotencyKey, ifMatch, requestID)
}

func setGatewayActivatedNode(t *testing.T, pool *pgxpool.Pool, nodeID uuid.UUID) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `
		UPDATE nodes
		SET admin_state = 'active', revision = revision + 1, updated_at = now()
		WHERE id = $1`, nodeID); err != nil {
		t.Fatalf("simulate completed gateway enrollment: %v", err)
	}
}

func grantNodePermissions(t *testing.T, pool *pgxpool.Pool, scopeID, userID uuid.UUID, permissions ...string) {
	t.Helper()
	roleID := uuid.New()
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO roles (id, scope_id, name, system_role) VALUES ($1, $2, $3, true)`, roleID, scopeID, "node-test-"+roleID.String()); err != nil {
		t.Fatalf("insert node test role: %v", err)
	}
	for _, permission := range permissions {
		if _, err := pool.Exec(context.Background(), `
			INSERT INTO role_permissions (role_id, permission_name) VALUES ($1, $2)`, roleID, permission); err != nil {
			t.Fatalf("grant node permission %s: %v", permission, err)
		}
	}
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO role_assignments (scope_id, user_id, role_id) VALUES ($1, $2, $3)`, scopeID, userID, roleID); err != nil {
		t.Fatalf("assign node test role: %v", err)
	}
}

type nodeTestLeaseOptions struct {
	serial      uint64
	limit       int64
	key         siteTestKey
	omitFeature bool
	omitQuota   bool
	expiresAt   time.Time
	graceUntil  time.Time
}

func installNodeTestEntitlement(
	t *testing.T,
	pool *pgxpool.Pool,
	trust *entitlementguard.TrustStore,
	now time.Time,
	options nodeTestLeaseOptions,
) entitlement.SignedLease {
	t.Helper()
	features := []entitlement.Feature{{Code: entitlementguard.FeatureNodesManage}}
	if options.omitFeature {
		features = nil
	}
	quotas := []entitlement.Quota{{Code: entitlementguard.QuotaNodesCount, Limit: options.limit}}
	if options.omitQuota {
		quotas = nil
	}
	expiresAt := options.expiresAt
	if expiresAt.IsZero() {
		expiresAt = now.Add(time.Hour)
	}
	graceUntil := options.graceUntil
	if graceUntil.IsZero() {
		graceUntil = expiresAt.Add(time.Hour)
	}
	lease := entitlement.Lease{
		Schema:         entitlement.SchemaV1,
		Audience:       entitlement.ControlAudience,
		CustomerID:     "44444444-4444-4444-8444-444444444444",
		InstallationID: "55555555-5555-4555-8555-555555555555",
		LicenseID:      "66666666-6666-4666-8666-666666666666",
		Serial:         options.serial,
		NotBefore:      now.Add(-time.Hour).Unix(),
		ExpiresAt:      expiresAt.Unix(),
		GraceUntil:     graceUntil.Unix(),
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

func assertNodeCreateResidue(t *testing.T, pool *pgxpool.Pool, nodes, tokens, writes int) {
	t.Helper()
	var gotNodes, gotTokens, gotWrites int
	if err := pool.QueryRow(context.Background(), `
		SELECT (SELECT count(*) FROM nodes),
		       (SELECT count(*) FROM node_enrollment_tokens),
		       (SELECT count(*) FROM node_write_requests)`).Scan(&gotNodes, &gotTokens, &gotWrites); err != nil {
		t.Fatalf("count node create residue: %v", err)
	}
	if gotNodes != nodes || gotTokens != tokens || gotWrites != writes {
		t.Fatalf("node create residue = nodes:%d tokens:%d writes:%d, want %d/%d/%d",
			gotNodes, gotTokens, gotWrites, nodes, tokens, writes)
	}
}

func assertNodeEntitlementAudit(
	t *testing.T,
	pool *pgxpool.Pool,
	requestID string,
	state string,
	current int64,
	limit int64,
) {
	t.Helper()
	var resourceType, gotState, feature, quota string
	var gotCurrent, gotLimit int64
	if err := pool.QueryRow(context.Background(), `
		SELECT resource_type, payload->>'state', payload->>'feature', payload->>'quota',
		       (payload->>'current')::bigint, (payload->>'limit')::bigint
		FROM audit_events
		WHERE action = 'entitlement.guard.reject' AND request_id = $1`, requestID,
	).Scan(&resourceType, &gotState, &feature, &quota, &gotCurrent, &gotLimit); err != nil {
		t.Fatalf("read node entitlement audit: %v", err)
	}
	if resourceType != "node" || gotState != state || feature != entitlementguard.FeatureNodesManage ||
		quota != entitlementguard.QuotaNodesCount || gotCurrent != current || gotLimit != limit {
		t.Fatalf("node entitlement audit = resource:%s state:%s feature:%s quota:%s current:%d limit:%d",
			resourceType, gotState, feature, quota, gotCurrent, gotLimit)
	}
}

func insertTenantAdmin(t *testing.T, pool *pgxpool.Pool, passwordHash string) (string, uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	tenantID := uuid.New()
	scopeID := uuid.New()
	userID := uuid.New()
	roleID := uuid.New()
	username := "tenantnodeadmin"
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO tenants (id, display_name) VALUES ($1, 'Tenant Test')`, []any{tenantID}},
		{`INSERT INTO access_scopes (id, kind, tenant_id) VALUES ($1, 'tenant', $2)`, []any{scopeID, tenantID}},
		{`INSERT INTO users (id, username, display_name, password_hash) VALUES ($1, $2, 'Tenant Node Admin', $3)`, []any{userID, username, passwordHash}},
		{`INSERT INTO memberships (scope_id, user_id) VALUES ($1, $2)`, []any{scopeID, userID}},
		{`INSERT INTO roles (id, scope_id, name, system_role) VALUES ($1, $2, 'tenant_owner', true)`, []any{roleID, scopeID}},
		{`INSERT INTO role_assignments (scope_id, user_id, role_id) VALUES ($1, $2, $3)`, []any{scopeID, userID, roleID}},
	}
	for _, statement := range statements {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatalf("insert tenant admin fixture: %v", err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO role_permissions (role_id, permission_name) VALUES ($1, 'nodes.manage')`, roleID); err == nil {
		t.Fatal("tenant role must not receive platform node permissions")
	}
	return username, scopeID
}

func loginForScope(
	t *testing.T,
	client *http.Client,
	baseURL string,
	username string,
	scopeID uuid.UUID,
) testAuthResponse {
	t.Helper()
	response := postLogin(t, client, baseURL, map[string]any{
		"username": username,
		"password": testPassword,
		"scope_id": scopeID.String(),
	}, "")
	var result testAuthResponse
	decodeResponse(t, response, http.StatusOK, &result)
	response.Body.Close()
	return result
}
