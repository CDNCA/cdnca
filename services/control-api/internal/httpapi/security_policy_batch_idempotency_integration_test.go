package httpapi

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

// POST /v1/security-policies/batch binds its Idempotency-Key to
// the whole request (migration 637). Same key and body replays the stored
// results; the same key with other items or another action is a 409 before
// any item is written.
func TestSecurityPolicyBatchIdempotencyHTTP(t *testing.T) {
	pool := isolatedTestPool(t)
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	identityStore := identity.NewStore(pool)
	tenant := insertSecurityTenant(t, pool, "Batch Tenant", "batch-idem-a", passwordHash)
	tokens, err := identity.NewTokenManager("security-policy-batch-idempotency-32bytes", 5*time.Minute)
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
	auth := loginForScope(t, client, server.URL, tenant.username, tenant.scopeID)
	first := createSecurityPolicy(t, client, server.URL, auth.AccessToken, "batch-waf-1", createSecurityPolicyRequest{
		PolicyFields: validSecurityPolicyFields("Batch WAF 1", securitypolicy.KindWAF)})
	second := createSecurityPolicy(t, client, server.URL, auth.AccessToken, "batch-waf-2", createSecurityPolicyRequest{
		PolicyFields: validSecurityPolicyFields("Batch WAF 2", securitypolicy.KindWAF)})

	type batchBody struct {
		Action string                     `json:"action"`
		Items  []securitypolicy.BatchItem `json:"items"`
	}
	type batchResult struct {
		Items []securitypolicy.BatchItemResult `json:"items"`
	}
	post := func(key string, body batchBody) *http.Response {
		return siteRequest(t, client, http.MethodPost, server.URL+"/v1/security-policies/batch", body, auth.AccessToken, key, "")
	}
	enabled := func(id uuid.UUID) bool {
		var value bool
		if err := pool.QueryRow(context.Background(), `SELECT enabled FROM security_policies WHERE id=$1`, id).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}

	disableFirst := batchBody{Action: securitypolicy.BatchDisable, Items: []securitypolicy.BatchItem{{ID: first.ID, Version: first.Revision}}}
	var original batchResult
	response := post("batch-key-1", disableFirst)
	decodeResponse(t, response, http.StatusOK, &original)
	response.Body.Close()
	if len(original.Items) != 1 || original.Items[0].Status != "ok" || enabled(first.ID) {
		t.Fatalf("first batch = %+v enabled=%v", original, enabled(first.ID))
	}

	var replay batchResult
	response = post("batch-key-1", disableFirst)
	decodeResponse(t, response, http.StatusOK, &replay)
	response.Body.Close()
	if !reflect.DeepEqual(replay, original) {
		t.Fatalf("replay = %+v want the stored %+v", replay, original)
	}

	moreItems := disableFirst
	moreItems.Items = append(append([]securitypolicy.BatchItem(nil), disableFirst.Items...),
		securitypolicy.BatchItem{ID: second.ID, Version: second.Revision})
	response = post("batch-key-1", moreItems)
	assertError(t, response, http.StatusConflict, "idempotency_conflict", "")
	response.Body.Close()
	if !enabled(second.ID) {
		t.Fatal("a conflicting batch wrote a new item")
	}

	otherAction := disableFirst
	otherAction.Action = securitypolicy.BatchEnable
	response = post("batch-key-1", otherAction)
	assertError(t, response, http.StatusConflict, "idempotency_conflict", "")
	response.Body.Close()
	if enabled(first.ID) {
		t.Fatal("a conflicting batch changed an item")
	}

	var fresh batchResult
	response = post("batch-key-2", moreItems)
	decodeResponse(t, response, http.StatusOK, &fresh)
	response.Body.Close()
	if len(fresh.Items) != 2 || fresh.Items[0].Status != "version_conflict" || fresh.Items[1].Status != "ok" || enabled(second.ID) {
		t.Fatalf("new key batch = %+v", fresh)
	}
}
