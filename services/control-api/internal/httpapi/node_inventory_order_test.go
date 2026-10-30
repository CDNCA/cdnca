package httpapi

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/nodepresence"
	"github.com/google/uuid"
)

func TestNodeInventoryOrder(t *testing.T) {
	pool := isolatedTestPool(t)
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	store := identity.NewStore(pool)
	admin, err := store.BootstrapPlatformUser(t.Context(), "orderadmin", "Order Admin", passwordHash, "node-order-test")
	if err != nil {
		t.Fatal(err)
	}
	reader := insertTestUser(t, pool, admin.ScopeID, "orderreader", "Reader", passwordHash, "active")
	grantNodePermissions(t, pool, admin.ScopeID, reader, "nodes.read")
	insertTestUser(t, pool, admin.ScopeID, "orderviewer", "Viewer", passwordHash, "active")
	tenantName, tenantScope := insertTenantAdmin(t, pool, passwordHash)
	tokens, err := identity.NewTokenManager("node-order-test-key-at-least-thirty-two-bytes", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := identity.NewService(store, tokens, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	api := New(pool, auth, Config{APIKeyPepper: bytes.Repeat([]byte{0x53}, 32)})
	server := httptest.NewServer(api.Handler())
	t.Cleanup(server.Close)
	readerAuth, _ := loginOK(t, server.Client(), server.URL, "orderreader")
	viewerAuth, _ := loginOK(t, server.Client(), server.URL, "orderviewer")
	tenantAuth := loginForScope(t, server.Client(), server.URL, tenantName, tenantScope)
	ids := make([]uuid.UUID, 6)
	for index := range ids {
		ids[index] = uuid.MustParse(fmt.Sprintf("018f0000-0000-7000-8000-%012d", index+1))
		scope := admin.ScopeID
		if index == 5 {
			scope = tenantScope
		}
		if _, err := pool.Exec(t.Context(), `INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id)
			VALUES($1,$2,$3,'active',$4,$5)`, ids[index], scope, fmt.Sprintf("order-edge-%d", index), admin.UserID, []int64{1, 9007199254740992, 9007199254740993, 4, 5, 1}[index]); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(t.Context(), `UPDATE nodes SET management_settings=jsonb_set(management_settings,'{sort}',to_jsonb($2::int)) WHERE id=$1`,
			ids[index], []int{0, 100, 100, 999999, 100, 999999}[index]); err != nil {
			t.Fatal(err)
		}
	}
	var page struct {
		Order      string                       `json:"order"`
		Items      []nodepresence.InventoryItem `json:"items"`
		NextCursor string                       `json:"next_cursor"`
	}
	response := doRequest(t, server.Client(), http.MethodGet, server.URL+"/v1/nodes?order=management_sort_desc&limit=2", nil, nil, readerAuth.AccessToken)
	decodeResponse(t, response, http.StatusOK, &page)
	response.Body.Close()
	if page.Order != "management_sort_desc" || len(page.Items) != 2 || page.Items[0].ID != ids[3] || page.Items[1].ID != ids[2] || page.NextCursor == "" {
		t.Fatalf("descending sort/numeric ID first page: %+v", page)
	}
	firstCursor := page.NextCursor
	// Changing the boundary row does not reinterpret the saved boundary. This
	// is live keyset pagination, not a cross-request snapshot of concurrent edits.
	if _, err := pool.Exec(t.Context(), `UPDATE nodes SET management_settings=jsonb_set(management_settings,'{sort}','999999') WHERE id=$1`, ids[2]); err != nil {
		t.Fatal(err)
	}
	response = doRequest(t, server.Client(), http.MethodGet, server.URL+"/v1/nodes?order=management_sort_desc&limit=2&cursor="+url.QueryEscape(firstCursor), nil, nil, readerAuth.AccessToken)
	decodeResponse(t, response, http.StatusOK, &page)
	response.Body.Close()
	if len(page.Items) != 2 || page.Items[0].ID != ids[1] || page.Items[1].ID != ids[4] || page.NextCursor == "" {
		t.Fatalf("second page: %+v", page)
	}
	secondCursor := page.NextCursor
	page.NextCursor = ""
	response = doRequest(t, server.Client(), http.MethodGet, server.URL+"/v1/nodes?order=management_sort_desc&limit=300&cursor="+url.QueryEscape(secondCursor), nil, nil, readerAuth.AccessToken)
	decodeResponse(t, response, http.StatusOK, &page)
	response.Body.Close()
	if len(page.Items) != 1 || page.Items[0].ID != ids[0] || page.Items[0].ManagementSettings.Sort != 0 || page.NextCursor != "" {
		t.Fatalf("last page: %+v", page)
	}
	for _, query := range []string{
		"order=", "order=management_sort_asc", "order=management_sort_desc&order=management_sort_desc",
		"order=management_sort_desc&extra=1", "order=management_sort_desc&limit=0", "order=management_sort_desc&limit=301",
		"order=management_sort_desc&limit=01", "order=management_sort_desc&limit=1&limit=2",
		"order=management_sort_desc&status=invalid", "order=management_sort_desc&presence=invalid",
		"order=management_sort_desc&search=%0A", "order=management_sort_desc&search=" + strings.Repeat("x", 129),
		"order=management_sort_desc&cursor=", "order=management_sort_desc&cursor=" + ids[0].String(),
		"order=management_sort_desc&cursor=nso1.?", "order=management_sort_desc&cursor=" + firstCursor + "=",
		"order=management_sort_desc&status=active&cursor=" + firstCursor,
		"order=management_sort_desc&presence=unknown&cursor=" + firstCursor,
		"order=management_sort_desc&search=edge&cursor=" + firstCursor,
		"order=management_sort_desc&status=active;ignored=1",
	} {
		response := doRequest(t, server.Client(), http.MethodGet, server.URL+"/v1/nodes?"+query, nil, nil, readerAuth.AccessToken)
		assertError(t, response, http.StatusBadRequest, "validation_error", "")
		response.Body.Close()
	}
	filtered := "order=management_sort_desc&status=active&presence=unknown&search=order-edge&limit=2"
	response = doRequest(t, server.Client(), http.MethodGet, server.URL+"/v1/nodes?"+filtered, nil, nil, readerAuth.AccessToken)
	decodeResponse(t, response, http.StatusOK, &page)
	response.Body.Close()
	if len(page.Items) != 2 || page.NextCursor == "" {
		t.Fatal("filter first page missing")
	}
	response = doRequest(t, server.Client(), http.MethodGet, server.URL+"/v1/nodes?"+filtered+"&cursor="+page.NextCursor, nil, nil, readerAuth.AccessToken)
	decodeResponse(t, response, http.StatusOK, &page)
	response.Body.Close()
	if len(page.Items) != 2 || page.Items[0].ID != ids[1] {
		t.Fatalf("filter second page: %+v", page)
	}
	response = doRequest(t, server.Client(), http.MethodGet, server.URL+"/v1/nodes?order=management_sort_desc&status=disabled", nil, nil, readerAuth.AccessToken)
	var empty map[string]any
	decodeResponse(t, response, http.StatusOK, &empty)
	response.Body.Close()
	if len(empty) != 2 || empty["order"] != "management_sort_desc" || len(empty["items"].([]any)) != 0 {
		t.Fatalf("empty sorted shape: %+v", empty)
	}
	response = doRequest(t, server.Client(), http.MethodGet, server.URL+"/v1/nodes?limit=2", nil, nil, readerAuth.AccessToken)
	var legacyPage nodeListResponse
	decodeResponse(t, response, http.StatusOK, &legacyPage)
	response.Body.Close()
	if len(legacyPage.Items) != 2 || legacyPage.Items[0].ID != ids[0] || legacyPage.Items[1].ID != ids[1] || legacyPage.NextCursor == nil || *legacyPage.NextCursor != ids[1] {
		t.Fatalf("legacy order changed: %+v", legacyPage)
	}
	_, err = api.nodeInventory.List(t.Context(), nodepresence.InventoryListRequest{ScopeID: tenantScope, Order: "management_sort_desc", OrderedAfter: firstCursor, Limit: 2})
	if err == nil {
		t.Fatal("foreign scope cursor was accepted")
	}
	for _, test := range []struct {
		token  string
		status int
		code   string
	}{
		{"", http.StatusUnauthorized, "invalid_session"},
		{viewerAuth.AccessToken, http.StatusForbidden, "permission_denied"},
		{tenantAuth.AccessToken, http.StatusForbidden, "permission_denied"},
	} {
		response := doRequest(t, server.Client(), http.MethodGet, server.URL+"/v1/nodes?order=management_sort_desc", nil, nil, test.token)
		assertError(t, response, test.status, test.code, "")
		response.Body.Close()
	}
}
