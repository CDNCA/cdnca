package analyticsconnectionshttp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticsconnections"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

const (
	dlqTenantID = "11111111-1111-4111-8111-111111111111"
	dlqOtherID  = "33333333-3333-4333-8333-333333333333"
)

type dlqStoreStub30 struct {
	rows      []analyticsconnections.DeadLetterReceiptView
	item      analyticsconnections.DeadLetterReceiptView
	listQuery []analyticsconnections.DeadLetterQuery
	getIDs    []string
	err       error
}

func (store *dlqStoreStub30) ListDeadLetters(_ context.Context, query analyticsconnections.DeadLetterQuery) ([]analyticsconnections.DeadLetterReceiptView, error) {
	store.listQuery = append(store.listQuery, query)
	if store.err != nil {
		return nil, store.err
	}
	return append([]analyticsconnections.DeadLetterReceiptView(nil), store.rows...), nil
}

func (store *dlqStoreStub30) GetDeadLetter(_ context.Context, deadLetterID string) (analyticsconnections.DeadLetterReceiptView, error) {
	store.getIDs = append(store.getIDs, deadLetterID)
	if store.err != nil {
		return analyticsconnections.DeadLetterReceiptView{}, store.err
	}
	return store.item, nil
}

func (store *dlqStoreStub30) GetDeadLetterBySequence(_ context.Context, _ uint64) (analyticsconnections.DeadLetterReceiptView, error) {
	if store.err != nil {
		return analyticsconnections.DeadLetterReceiptView{}, store.err
	}
	return store.item, nil
}

func TestDLQHTTPListDetailScopesAndDigestOnly(t *testing.T) {
	first := dlqReceiptFixture(100, dlqTenantID)
	second := dlqReceiptFixture(101, dlqTenantID)
	store := &dlqStoreStub30{rows: []analyticsconnections.DeadLetterReceiptView{first, second}, item: first}
	platform := identity.AuthenticatedSession{
		SessionID: uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
		Principal: identity.Principal{
			UserID: uuid.MustParse("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"), ScopeID: uuid.MustParse("cccccccc-cccc-4ccc-8ccc-cccccccccccc"),
			ScopeKind: "platform", Permissions: []string{"sites.read", "platform.admin"},
		},
	}
	tenant := identity.AuthenticatedSession{
		SessionID: uuid.MustParse("dddddddd-dddd-4ddd-8ddd-dddddddddddd"),
		Principal: identity.Principal{
			UserID: uuid.MustParse("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"), ScopeID: uuid.MustParse("ffffffff-ffff-4fff-8fff-ffffffffffff"),
			ScopeKind: "tenant", TenantID: ptrUUID(uuid.MustParse(dlqTenantID)), Permissions: []string{"sites.read"},
		},
	}
	auth := func(request *http.Request) (identity.AuthenticatedSession, error) {
		if request.Header.Get("X-Test-Principal") == "platform" {
			return platform, nil
		}
		return tenant, nil
	}
	handler, err := NewDLQHandler(store, auth, DLQHandlerConfig{})
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "/v1/analytics/connections/dead-letters?limit=1", nil)
	request.Header.Set("Authorization", "Bearer tenant-token")
	request.Header.Set("X-Request-ID", "dlq-list-1")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"next_after_sequence":100`) ||
		strings.Contains(response.Body.String(), "canonical_event_sha256") || strings.Contains(response.Body.String(), "secret_payload") {
		t.Fatalf("tenant list response = %d %s", response.Code, response.Body.String())
	}
	if len(store.listQuery) != 1 || store.listQuery[0].TenantID != dlqTenantID || store.listQuery[0].Limit != 2 {
		t.Fatalf("list query = %#v", store.listQuery)
	}

	detail := httptest.NewRequest(http.MethodGet, "/v1/analytics/connections/dead-letters/"+first.DeadLetterID, nil)
	detail.Header.Set("Authorization", "Bearer tenant-token")
	detailResponse := httptest.NewRecorder()
	handler.ServeHTTP(detailResponse, detail)
	if detailResponse.Code != http.StatusOK || !strings.Contains(detailResponse.Body.String(), `"payload_digest":"`+first.PayloadSHA256+`"`) ||
		strings.Contains(detailResponse.Body.String(), "payload_bytes") {
		t.Fatalf("tenant detail response = %d %s", detailResponse.Code, detailResponse.Body.String())
	}

	adminList := httptest.NewRequest(http.MethodGet, "/v1/admin/analytics/connections/dead-letters?tenant_id="+dlqTenantID+"&limit=1", nil)
	adminList.Header.Set("Authorization", "Bearer platform-token")
	adminList.Header.Set("X-Test-Principal", "platform")
	adminResponse := httptest.NewRecorder()
	handler.ServeHTTP(adminResponse, adminList)
	if adminResponse.Code != http.StatusOK || len(store.listQuery) != 2 || store.listQuery[1].TenantID != dlqTenantID {
		t.Fatalf("admin list response = %d queries=%#v body=%s", adminResponse.Code, store.listQuery, adminResponse.Body.String())
	}
}

func TestDLQHTTPRequiresBearerAndRejectsTenantSpoof(t *testing.T) {
	store := &dlqStoreStub30{}
	calls := 0
	handler, err := NewDLQHandler(store, func(*http.Request) (identity.AuthenticatedSession, error) {
		calls++
		return identity.AuthenticatedSession{}, nil
	}, DLQHandlerConfig{})
	if err != nil {
		t.Fatal(err)
	}
	missing := httptest.NewRequest(http.MethodGet, "/v1/analytics/connections/dead-letters", nil)
	missingResponse := httptest.NewRecorder()
	handler.ServeHTTP(missingResponse, missing)
	assertDLQError(t, missingResponse, http.StatusUnauthorized, "connections_dead_letter_authentication_required")
	if calls != 0 {
		t.Fatal("missing bearer reached session authenticator")
	}

	spoof := httptest.NewRequest(http.MethodGet, "/v1/analytics/connections/dead-letters", nil)
	spoof.Header.Set("Authorization", "Bearer token")
	spoof.Header.Set("X-Tenant-ID", dlqOtherID)
	spoofResponse := httptest.NewRecorder()
	handler.ServeHTTP(spoofResponse, spoof)
	assertDLQError(t, spoofResponse, http.StatusUnauthorized, "connections_dead_letter_authentication_required")
}

func TestDLQHTTPRejectsMalformedFactsAndDoesNotLeakStoreErrors(t *testing.T) {
	malformed := dlqReceiptFixture(100, dlqTenantID)
	malformed.PayloadSHA256 = strings.Repeat("0", 64)
	store := &dlqStoreStub30{rows: []analyticsconnections.DeadLetterReceiptView{malformed}}
	session := dlqTenantSession()
	handler, err := NewDLQHandler(store, func(*http.Request) (identity.AuthenticatedSession, error) { return session, nil }, DLQHandlerConfig{})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/analytics/connections/dead-letters", nil)
	request.Header.Set("Authorization", "Bearer token")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	assertDLQError(t, response, http.StatusBadGateway, "connections_dead_letter_invalid_response")

	store.err = errors.New("SELECT secret_payload from durable_dead_letters")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	assertDLQError(t, response, http.StatusServiceUnavailable, "connections_dead_letter_unavailable")
	if strings.Contains(response.Body.String(), "secret_payload") || strings.Contains(response.Body.String(), "SELECT") {
		t.Fatalf("store error leaked: %s", response.Body.String())
	}
}

func TestDLQHTTPDeniesCrossTenantDetail(t *testing.T) {
	store := &dlqStoreStub30{item: dlqReceiptFixture(100, dlqOtherID)}
	handler, err := NewDLQHandler(store, func(*http.Request) (identity.AuthenticatedSession, error) {
		return dlqTenantSession(), nil
	}, DLQHandlerConfig{})
	if err != nil {
		t.Fatal(err)
	}
	item := dlqReceiptFixture(100, dlqTenantID)
	request := httptest.NewRequest(http.MethodGet, "/v1/analytics/connections/dead-letters/"+item.DeadLetterID, nil)
	request.Header.Set("Authorization", "Bearer token")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	assertDLQError(t, response, http.StatusForbidden, "connections_dead_letter_permission_denied")
}

func dlqReceiptFixture(sequence uint64, tenantID string) analyticsconnections.DeadLetterReceiptView {
	digest := strings.Repeat("ab", 32)
	created := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	settled := created.Add(time.Second)
	return analyticsconnections.DeadLetterReceiptView{
		MetadataVersion: analyticsconnections.DeliveryMetadataVersion, DeadLetterID: digest, EnvelopeSHA256: digest,
		BatchID: "batch-30-" + string(rune('a'+sequence-100)), ReceiptID: "receipt-30-" + string(rune('a'+sequence-100)),
		EventID: "event-30-" + string(rune('a'+sequence-100)), TenantID: tenantID, InstallationID: "installation-30", SiteID: "site-30", PackageSubscriptionID: "subscription-30",
		SourceStream: "CONNECTIONS_INGEST_V1", Durable: "control_api_connections", SourceStreamSequence: sequence, ConsumerSequence: sequence + 10,
		Attempt: 8, MaxDeliver: 8, FailureReason: analyticsconnections.DeliveryFailureMaxDeliver,
		PayloadSHA256: digest, CanonicalEventSHA256: digest, EvidenceSHA256: digest,
		DeadLetterStream: "CONNECTIONS_DEAD_V1", DeadLetterSequence: sequence, CreatedAt: created, SettledAt: settled,
	}
}

func dlqTenantSession() identity.AuthenticatedSession {
	return identity.AuthenticatedSession{
		SessionID: uuid.MustParse("dddddddd-dddd-4ddd-8ddd-dddddddddddd"),
		Principal: identity.Principal{
			UserID: uuid.MustParse("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"), ScopeID: uuid.MustParse("ffffffff-ffff-4fff-8fff-ffffffffffff"),
			ScopeKind: "tenant", TenantID: ptrUUID(uuid.MustParse(dlqTenantID)), Permissions: []string{"sites.read"},
		},
	}
}

func ptrUUID(value uuid.UUID) *uuid.UUID { return &value }

func assertDLQError(t *testing.T, response *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if response.Code != status || !strings.Contains(response.Body.String(), `"code":"`+code+`"`) ||
		strings.Contains(response.Body.String(), "secret") || response.Header().Get("Cache-Control") != "no-store" ||
		response.Header().Get("X-Request-ID") == "" {
		t.Fatalf("response = %d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
}
