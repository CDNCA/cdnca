//go:build integration

package cachecontrolhttp

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/cachecontrol"
)

// tp-b4b: 重新提交 (same nodes and targets, idempotent per batch, audited),
// the list's first target / auto_nodes, multi-state filter and per-state
// counts, each bound to the caller's tenant.
func TestCacheOperationResubmitAndStateCounts(t *testing.T) {
	pool := openHTTPIntegrationDatabase(t)
	fixture := seedHTTPFixture(t, pool)
	store, err := cachecontrol.NewStore(pool, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := NewPostgresReader(pool)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(store, reader, bytes.Repeat([]byte{0x5b}, 32))
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(service, fixture.authenticate)
	if err != nil {
		t.Fatal(err)
	}

	secret := "resubmit-query-secret"
	body := integrationOperationBody(fixture.siteA, fixture.nodeA, "http://a.cache.example/r/app.js?sig="+secret, 2)
	body["targets"] = []string{"http://a.cache.example/r/app.js?sig=" + secret, "http://a.cache.example/r/second.css"}
	response := serve(t, handler, http.MethodPost, "/v1/cache-operations", body, "tenant-a", "resubmit-source")
	if response.Code != http.StatusAccepted {
		t.Fatalf("create: %d %s", response.Code, response.Body.String())
	}
	source := decodeOperation(t, response)
	if source.AutoNodes {
		t.Fatalf("explicit-node operation reported auto_nodes")
	}
	// Tenant B has one operation of its own; it never shows up in A's counts.
	response = serve(t, handler, http.MethodPost, "/v1/cache-operations",
		integrationOperationBody(fixture.siteB, fixture.nodeB, "http://b.cache.example/b", 0), "tenant-b", "tenant-b-op")
	if response.Code != http.StatusAccepted {
		t.Fatalf("tenant b create: %d %s", response.Code, response.Body.String())
	}
	other := decodeOperation(t, response)

	resubmitPath := "/v1/cache-operations/" + source.ID.String() + "/resubmit"
	response = serve(t, handler, http.MethodPost, resubmitPath, map[string]any{}, "tenant-a", "batch-1")
	if response.Code != http.StatusAccepted || response.Header().Get("Idempotency-Replayed") != "" {
		t.Fatalf("resubmit: %d %v %s", response.Code, response.Header(), response.Body.String())
	}
	if strings.Contains(response.Body.String(), secret) {
		t.Fatalf("resubmit response leaked the query: %s", response.Body.String())
	}
	first := decodeOperation(t, response)
	if first.ID == source.ID || response.Header().Get("Location") != "/v1/cache-operations/"+first.ID.String() ||
		first.Action != source.Action || first.TargetType != source.TargetType || first.MaxAttempts != 3 ||
		first.AutoNodes || len(first.Nodes) != 1 || first.Nodes[0].NodeID != fixture.nodeA ||
		len(first.Targets) != 2 || first.Targets[0].TargetSHA256 != source.Targets[0].TargetSHA256 ||
		first.Targets[1].TargetSHA256 != source.Targets[1].TargetSHA256 {
		t.Fatalf("resubmitted operation = %+v (source %+v)", first, source)
	}
	// The same batch replays; another batch makes another operation.
	response = serve(t, handler, http.MethodPost, resubmitPath, map[string]any{}, "tenant-a", "batch-1")
	if response.Code != http.StatusAccepted || response.Header().Get("Idempotency-Replayed") != "true" ||
		decodeOperation(t, response).ID != first.ID {
		t.Fatalf("resubmit replay: %d %s", response.Code, response.Body.String())
	}
	response = serve(t, handler, http.MethodPost, resubmitPath, map[string]any{}, "tenant-a", "batch-2")
	second := decodeOperation(t, response)
	if response.Code != http.StatusAccepted || second.ID == first.ID || second.ID == source.ID {
		t.Fatalf("second batch: %d %s", response.Code, response.Body.String())
	}
	var audits int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE scope_id=$1
		AND action='cache.operation.resubmit' AND resource_id=$2`, fixture.scopeA, source.ID.String()).Scan(&audits); err != nil || audits != 2 {
		t.Fatalf("resubmit audits = %d, %v", audits, err)
	}
	// Another tenant cannot re-submit (or see) A's operation.
	response = serve(t, handler, http.MethodPost, resubmitPath, map[string]any{}, "tenant-b", "batch-b")
	assertAPIError(t, response, http.StatusNotFound, "not_found")
	response = serve(t, handler, http.MethodPost, "/v1/cache-operations/"+other.ID.String()+"/resubmit", map[string]any{}, "tenant-a", "batch-cross")
	assertAPIError(t, response, http.StatusNotFound, "not_found")

	// Cancel the second one: A has 2 queued + 1 cancelled.
	response = serve(t, handler, http.MethodPost, "/v1/cache-operations/"+second.ID.String()+"/cancel", map[string]any{}, "tenant-a", "cancel-second")
	if response.Code != http.StatusOK {
		t.Fatalf("cancel: %d %s", response.Code, response.Body.String())
	}
	response = serve(t, handler, http.MethodGet, "/v1/cache-operations?limit=1&state=queued,cancelled", nil, "tenant-a", "")
	page := decodeOperationPage(t, response)
	want := StateCounts{cachecontrol.StateQueued: 2, cachecontrol.StateCancelled: 1, cachecontrol.StateRunning: 0,
		cachecontrol.StateSucceeded: 0, cachecontrol.StatePartialFailed: 0, cachecontrol.StateFailed: 0}
	if len(page.Items) != 1 || page.NextCursor == "" || len(page.StateCounts) != len(want) {
		t.Fatalf("first page = %+v", page)
	}
	for state, count := range want {
		if page.StateCounts[state] != count {
			t.Fatalf("state counts = %v, want %v", page.StateCounts, want)
		}
	}
	// Counts follow the other filters (here a search) but not the state one.
	response = serve(t, handler, http.MethodGet, "/v1/cache-operations?state=running&search=second.css", nil, "tenant-a", "")
	searched := decodeOperationPage(t, response)
	if len(searched.Items) != 0 || searched.StateCounts[cachecontrol.StateQueued] != 2 ||
		searched.StateCounts[cachecontrol.StateCancelled] != 1 {
		t.Fatalf("searched page = %+v", searched)
	}
	// Later pages carry no counts; the multi-state filter covers all three.
	response = serve(t, handler, http.MethodGet, "/v1/cache-operations?limit=1&state=queued,cancelled&cursor="+page.NextCursor, nil, "tenant-a", "")
	next := decodeOperationPage(t, response)
	if len(next.Items) != 1 || next.StateCounts != nil {
		t.Fatalf("second page = %+v", next)
	}
	response = serve(t, handler, http.MethodGet, "/v1/cache-operations?state=cancelled", nil, "tenant-a", "")
	cancelled := decodeOperationPage(t, response)
	if len(cancelled.Items) != 1 || cancelled.Items[0].ID != second.ID {
		t.Fatalf("cancelled page = %+v", cancelled)
	}
	// The summary carries the first target as the detail shows it.
	response = serve(t, handler, http.MethodGet, "/v1/cache-operations?state=queued", nil, "tenant-a", "")
	queued := decodeOperationPage(t, response)
	for _, item := range queued.Items {
		if item.FirstTarget.Ordinal != 1 || item.FirstTarget.TargetSHA256 != source.Targets[0].TargetSHA256 ||
			!item.FirstTarget.QueryRedacted || strings.Contains(item.FirstTarget.DisplayURL, secret) ||
			item.TargetCount != 2 || item.AutoNodes {
			t.Fatalf("summary = %+v", item)
		}
	}
	// Tenant B sees only its own operation.
	response = serve(t, handler, http.MethodGet, "/v1/cache-operations", nil, "tenant-b", "")
	mine := decodeOperationPage(t, response)
	if len(mine.Items) != 1 || mine.Items[0].ID != other.ID || mine.StateCounts[cachecontrol.StateQueued] != 1 ||
		mine.StateCounts[cachecontrol.StateCancelled] != 0 {
		t.Fatalf("tenant b page = %+v", mine)
	}
	// Unknown or duplicate-only states are rejected; the platform route needs a scope.
	for _, path := range []string{"/v1/cache-operations?state=queued,bogus", "/v1/cache-operations?state=queued,"} {
		assertAPIError(t, serve(t, handler, http.MethodGet, path, nil, "tenant-a", ""), http.StatusBadRequest, "invalid_request")
	}
	response = serve(t, handler, http.MethodGet, "/v1/admin/cache-operations?scope_id="+fixture.scopeA.String(), nil, "platform", "")
	admin := decodeOperationPage(t, response)
	if admin.StateCounts[cachecontrol.StateQueued] != 2 || admin.StateCounts[cachecontrol.StateCancelled] != 1 {
		t.Fatalf("admin counts = %+v", admin.StateCounts)
	}
}
