package certificateassethttp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/certificateasset"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

func TestPublicationStatusHandlerListsWithOpaqueSnapshotCursor46(t *testing.T) {
	fixture := newPublicationStatusHTTPFixture46(t)
	filter := certificateasset.PublicationStatusFilter{
		State: "succeeded", Operation: "publish", SiteID: fixture.filterSiteID,
	}
	pageCursor := certificateasset.PublicationStatusCursor{
		SnapshotAt: fixture.now, LastOccurredAt: fixture.now.Add(-time.Second),
		LastSiteID: fixture.siteID, LastBindingRevision: 7,
	}
	fixture.reader.listPage = certificateasset.PublicationStatusPage{
		Items:      []certificateasset.PublicationStatus{fixture.status},
		SnapshotAt: fixture.now, NextCursor: &pageCursor,
	}
	handler := fixture.handler(t, fixture.tenantSession("certificates.read"))
	path := "/v1/certificate-publications?state=succeeded&operation=publish&site_id=" +
		fixture.filterSiteID.String() + "&limit=25"
	response := fixture.serve(handler, http.MethodGet, path, "", nil)
	assertPublicationStatusResponse46(t, response, http.StatusOK, "")
	var body struct {
		Items      []certificateasset.PublicationStatus `json:"items"`
		SnapshotAt time.Time                            `json:"snapshot_at"`
		NextCursor string                               `json:"next_cursor"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(body.Items, fixture.reader.listPage.Items) || !body.SnapshotAt.Equal(fixture.now) ||
		body.NextCursor == "" || strings.Contains(body.NextCursor, "{") || strings.Contains(body.NextCursor, fixture.siteID.String()) {
		t.Fatalf("list response = %+v", body)
	}
	if fixture.reader.listCalls != 1 || fixture.reader.actor.UserID != fixture.userID ||
		fixture.reader.tenantScopeID != fixture.tenantScopeID || fixture.reader.filter != filter ||
		fixture.reader.cursor != (certificateasset.PublicationStatusCursor{}) || fixture.reader.limit != 25 {
		t.Fatalf("list request = %+v", fixture.reader)
	}

	fixture.reader.listPage.NextCursor = nil
	second := fixture.serve(handler, http.MethodGet, path+"&cursor="+body.NextCursor, "", nil)
	assertPublicationStatusResponse46(t, second, http.StatusOK, "")
	if fixture.reader.listCalls != 2 || fixture.reader.cursor != pageCursor {
		t.Fatalf("decoded cursor = %+v calls=%d", fixture.reader.cursor, fixture.reader.listCalls)
	}
	var secondBody map[string]any
	if err := json.Unmarshal(second.Body.Bytes(), &secondBody); err != nil {
		t.Fatal(err)
	}
	if _, exists := secondBody["next_cursor"]; exists {
		t.Fatalf("terminal page exposed next_cursor: %s", second.Body.String())
	}
}

func TestPublicationStatusHandlerGetsExactRevisionHistory46(t *testing.T) {
	fixture := newPublicationStatusHTTPFixture46(t)
	fixture.reader.detail = certificateasset.PublicationStatusDetail{
		Current: fixture.status,
		History: []certificateasset.PublicationStatusEvent{
			{Sequence: 1, State: "pending", NextAttemptAt: pointerTime46(fixture.now), OccurredAt: fixture.now.Add(-time.Minute)},
			{Sequence: 2, State: "succeeded", Attempt: 1, OccurredAt: fixture.now},
		},
	}
	handler := fixture.handler(t, fixture.tenantSession("certificates.read"))
	path := "/v1/certificate-publications/" + fixture.siteID.String() + "/revisions/7"
	response := fixture.serve(handler, http.MethodGet, path, "", nil)
	assertPublicationStatusResponse46(t, response, http.StatusOK, "")
	var detail certificateasset.PublicationStatusDetail
	if err := json.Unmarshal(response.Body.Bytes(), &detail); err != nil || !reflect.DeepEqual(detail, fixture.reader.detail) {
		t.Fatalf("detail = %+v decode=%v body=%s", detail, err, response.Body.String())
	}
	if fixture.reader.getCalls != 1 || fixture.reader.siteID != fixture.siteID || fixture.reader.revision != 7 ||
		fixture.reader.tenantScopeID != fixture.tenantScopeID || fixture.reader.actor.UserID != fixture.userID {
		t.Fatalf("get request = %+v", fixture.reader)
	}
}

func TestPublicationStatusHandlerAuthenticatesScopeAndPermissionBeforeStore46(t *testing.T) {
	fixture := newPublicationStatusHTTPFixture46(t)
	path := "/v1/certificate-publications"

	for name, mutate := range map[string]func(*http.Request){
		"missing bearer": func(request *http.Request) { request.Header.Del("Authorization") },
		"duplicate bearer": func(request *http.Request) {
			request.Header.Add("Authorization", "Bearer second")
		},
		"spoofed identity": func(request *http.Request) { request.Header.Set("X-Scope-ID", uuid.NewString()) },
	} {
		t.Run(name, func(t *testing.T) {
			handler := fixture.handler(t, fixture.tenantSession("certificates.read"))
			response := fixture.serve(handler, http.MethodGet, path, "", mutate)
			assertPublicationStatusResponse46(t, response, http.StatusUnauthorized, "authentication_required")
		})
	}

	noPermission := fixture.handler(t, fixture.tenantSession())
	assertPublicationStatusResponse46(t, fixture.serve(noPermission, http.MethodGet, path, "", nil),
		http.StatusForbidden, "certificate_publication_permission_denied")
	crossTenant := fixture.handler(t, fixture.tenantSession("certificates.read"))
	assertPublicationStatusResponse46(t, fixture.serve(crossTenant, http.MethodGet,
		path+"?target_scope_id="+uuid.NewString(), "", nil),
		http.StatusForbidden, "certificate_publication_permission_denied")

	platform := fixture.handler(t, fixture.platformSession("certificates.read"))
	assertPublicationStatusResponse46(t, fixture.serve(platform, http.MethodGet, path, "", nil),
		http.StatusBadRequest, "certificate_publication_invalid_request")
	response := fixture.serve(platform, http.MethodGet,
		path+"?target_scope_id="+fixture.tenantScopeID.String(), "", nil)
	assertPublicationStatusResponse46(t, response, http.StatusOK, "")
	if fixture.reader.actor.ScopeKind != certificateasset.ScopePlatform ||
		fixture.reader.tenantScopeID != fixture.tenantScopeID {
		t.Fatalf("platform request = %+v", fixture.reader)
	}

	invalidSession := fixture.handler(t, identity.AuthenticatedSession{})
	assertPublicationStatusResponse46(t, fixture.serve(invalidSession, http.MethodGet, path, "", nil),
		http.StatusUnauthorized, "authentication_required")
	if fixture.reader.listCalls != 1 {
		t.Fatalf("unauthorized request reached store, list calls=%d", fixture.reader.listCalls)
	}
}

func TestPublicationStatusHandlerRejectsMalformedRoutesQueriesBodiesAndCursors46(t *testing.T) {
	fixture := newPublicationStatusHTTPFixture46(t)
	handler := fixture.handler(t, fixture.tenantSession("certificates.read"))
	validList := "/v1/certificate-publications"
	validDetail := validList + "/" + fixture.siteID.String() + "/revisions/7"

	for name, request := range map[string]*http.Request{
		"trailing slash":   httptest.NewRequest(http.MethodGet, validList+"/", nil),
		"bad site":         httptest.NewRequest(http.MethodGet, validList+"/not-a-uuid/revisions/7", nil),
		"uppercase site":   httptest.NewRequest(http.MethodGet, validList+"/"+strings.ToUpper(fixture.siteID.String())+"/revisions/7", nil),
		"zero revision":    httptest.NewRequest(http.MethodGet, validList+"/"+fixture.siteID.String()+"/revisions/0", nil),
		"leading revision": httptest.NewRequest(http.MethodGet, validList+"/"+fixture.siteID.String()+"/revisions/07", nil),
	} {
		t.Run(name, func(t *testing.T) {
			request.Header.Set("Authorization", "Bearer session")
			request.Header.Set("X-Request-ID", "certificate-publication-test")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			assertPublicationStatusResponse46(t, response, http.StatusNotFound, "certificate_publication_not_found")
		})
	}
	method := fixture.serve(handler, http.MethodPost, validList, "", nil)
	assertPublicationStatusResponse46(t, method, http.StatusMethodNotAllowed, "certificate_publication_method_not_allowed")
	if method.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("Allow=%q", method.Header().Get("Allow"))
	}
	detailQuery := fixture.serve(handler, http.MethodGet, validDetail+"?state=pending", "", nil)
	assertPublicationStatusResponse46(t, detailQuery, http.StatusBadRequest, "certificate_publication_invalid_request")

	invalidQueries := []string{
		"unknown=1", "state=pending&state=succeeded", "state=failed", "state=", "operation=delete",
		"site_id=bad", "site_id=" + strings.ToUpper(fixture.siteID.String()), "limit=0", "limit=201",
		"limit=01", "cursor=", "target_scope_id=", "target_scope_id=" + strings.ToUpper(fixture.tenantScopeID.String()),
	}
	for _, query := range invalidQueries {
		response := fixture.serve(handler, http.MethodGet, validList+"?"+query, "", nil)
		assertPublicationStatusResponse46(t, response, http.StatusBadRequest, "certificate_publication_invalid_request")
	}
	body := fixture.serve(handler, http.MethodGet, validList, `{}`, nil)
	assertPublicationStatusResponse46(t, body, http.StatusBadRequest, "certificate_publication_invalid_request")

	filter := certificateasset.PublicationStatusFilter{State: "succeeded"}
	cursor := certificateasset.PublicationStatusCursor{
		SnapshotAt: fixture.now, LastOccurredAt: fixture.now.Add(-time.Second),
		LastSiteID: fixture.siteID, LastBindingRevision: 7,
	}
	token, err := fixture.codec.Encode(
		certificateasset.Actor{UserID: fixture.userID, ScopeID: fixture.tenantScopeID, ScopeKind: certificateasset.ScopeTenant},
		fixture.tenantScopeID, filter, cursor,
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		validList + "?state=pending&cursor=" + token,
		validList + "?state=succeeded&cursor=" + tamperPublicationStatusToken46(t, token),
		validList + "?state=succeeded&cursor=" + token + "=",
	} {
		response := fixture.serve(handler, http.MethodGet, path, "", nil)
		assertPublicationStatusResponse46(t, response, http.StatusBadRequest, "certificate_publication_invalid_cursor")
	}
	if fixture.reader.listCalls != 0 || fixture.reader.getCalls != 0 {
		t.Fatalf("invalid requests reached store: list=%d get=%d", fixture.reader.listCalls, fixture.reader.getCalls)
	}
}

func TestPublicationStatusHandlerMapsStableErrorsWithoutDetails46(t *testing.T) {
	fixture := newPublicationStatusHTTPFixture46(t)
	handler := fixture.handler(t, fixture.tenantSession("certificates.read"))
	privateError := errors.New("private postgres publication failure")
	for _, test := range []struct {
		err    error
		status int
		code   string
	}{
		{certificateasset.ErrInvalidInput, http.StatusBadRequest, "certificate_publication_invalid_request"},
		{certificateasset.ErrInvalidPublicationCursor, http.StatusBadRequest, "certificate_publication_invalid_cursor"},
		{certificateasset.ErrPermissionDenied, http.StatusForbidden, "certificate_publication_permission_denied"},
		{certificateasset.ErrNotFound, http.StatusNotFound, "certificate_publication_not_found"},
		{privateError, http.StatusInternalServerError, "certificate_publication_internal_error"},
	} {
		fixture.reader.listErr = test.err
		response := fixture.serve(handler, http.MethodGet, "/v1/certificate-publications", "", nil)
		assertPublicationStatusResponse46(t, response, test.status, test.code)
		if strings.Contains(response.Body.String(), test.err.Error()) || strings.Contains(response.Body.String(), "postgres") {
			t.Fatalf("response leaked service error: %s", response.Body.String())
		}
	}

	fixture.reader.listErr = nil
	fixture.reader.listPage = certificateasset.PublicationStatusPage{SnapshotAt: fixture.now}
	empty := fixture.serve(handler, http.MethodGet, "/v1/certificate-publications", "", nil)
	assertPublicationStatusResponse46(t, empty, http.StatusOK, "")
	if !strings.Contains(empty.Body.String(), `"items":[]`) || strings.Contains(empty.Body.String(), `"next_cursor"`) {
		t.Fatalf("empty response = %s", empty.Body.String())
	}
}

func TestPublicationStatusHandlerRejectsInvalidDependencies46(t *testing.T) {
	fixture := newPublicationStatusHTTPFixture46(t)
	valid := PublicationStatusHTTPDependencies{
		Reader: fixture.reader, CursorCodec: fixture.codec,
		AuthenticateSession: func(context.Context, string) (identity.AuthenticatedSession, error) {
			return fixture.tenantSession("certificates.read"), nil
		},
	}
	for _, mutate := range []func(*PublicationStatusHTTPDependencies){
		func(value *PublicationStatusHTTPDependencies) { value.Reader = nil },
		func(value *PublicationStatusHTTPDependencies) { value.CursorCodec = nil },
		func(value *PublicationStatusHTTPDependencies) { value.AuthenticateSession = nil },
	} {
		candidate := valid
		mutate(&candidate)
		if _, err := NewPublicationStatusHandler(candidate); !errors.Is(err, errInvalidDependencies) {
			t.Fatalf("constructor error = %v", err)
		}
	}
}

type publicationStatusReaderStub46 struct {
	listPage certificateasset.PublicationStatusPage
	detail   certificateasset.PublicationStatusDetail
	listErr  error
	getErr   error

	listCalls     int
	getCalls      int
	actor         certificateasset.Actor
	tenantScopeID uuid.UUID
	filter        certificateasset.PublicationStatusFilter
	cursor        certificateasset.PublicationStatusCursor
	limit         int
	siteID        uuid.UUID
	revision      int64
}

func (reader *publicationStatusReaderStub46) List(
	_ context.Context,
	actor certificateasset.Actor,
	tenantScopeID uuid.UUID,
	filter certificateasset.PublicationStatusFilter,
	cursor certificateasset.PublicationStatusCursor,
	limit int,
) (certificateasset.PublicationStatusPage, error) {
	reader.listCalls++
	reader.actor, reader.tenantScopeID = actor, tenantScopeID
	reader.filter, reader.cursor, reader.limit = filter, cursor, limit
	return reader.listPage, reader.listErr
}

func (reader *publicationStatusReaderStub46) Get(
	_ context.Context,
	actor certificateasset.Actor,
	tenantScopeID, siteID uuid.UUID,
	bindingRevision int64,
) (certificateasset.PublicationStatusDetail, error) {
	reader.getCalls++
	reader.actor, reader.tenantScopeID = actor, tenantScopeID
	reader.siteID, reader.revision = siteID, bindingRevision
	return reader.detail, reader.getErr
}

type publicationStatusHTTPFixture46 struct {
	tenantScopeID uuid.UUID
	userID        uuid.UUID
	filterSiteID  uuid.UUID
	siteID        uuid.UUID
	now           time.Time
	status        certificateasset.PublicationStatus
	reader        *publicationStatusReaderStub46
	codec         *certificateasset.PublicationCursorCodec
}

func newPublicationStatusHTTPFixture46(t *testing.T) publicationStatusHTTPFixture46 {
	t.Helper()
	tenantScopeID, userID := uuid.New(), uuid.New()
	filterSiteID, siteID, assetID, versionID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	now := time.Date(2026, 8, 7, 11, 12, 13, 123456000, time.UTC)
	codec, err := certificateasset.NewPublicationCursorCodec(certificateasset.PublicationCursorKeyring{
		ActiveKID: "current", Keys: map[string][]byte{"current": bytes.Repeat([]byte{0x21}, 32)},
	})
	if err != nil {
		t.Fatal(err)
	}
	status := certificateasset.PublicationStatus{
		TenantScopeID: tenantScopeID, SiteID: siteID, AssetID: assetID, VersionID: versionID,
		BindingRevision: 7, Operation: "publish", Default: true, StateSequence: 2,
		State: "succeeded", Attempt: 1, OccurredAt: now,
	}
	return publicationStatusHTTPFixture46{
		tenantScopeID: tenantScopeID, userID: userID, filterSiteID: filterSiteID, siteID: siteID,
		now: now, status: status, reader: &publicationStatusReaderStub46{}, codec: codec,
	}
}

func (fixture publicationStatusHTTPFixture46) handler(
	t *testing.T,
	session identity.AuthenticatedSession,
) http.Handler {
	t.Helper()
	handler, err := NewPublicationStatusHandler(PublicationStatusHTTPDependencies{
		Reader: fixture.reader, CursorCodec: fixture.codec,
		AuthenticateSession: func(_ context.Context, raw string) (identity.AuthenticatedSession, error) {
			if raw != "session" {
				return identity.AuthenticatedSession{}, identity.ErrInvalidSession
			}
			return session, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func (fixture publicationStatusHTTPFixture46) tenantSession(permissions ...string) identity.AuthenticatedSession {
	tenantID := uuid.New()
	return identity.AuthenticatedSession{SessionID: uuid.New(), Principal: identity.Principal{
		UserID: fixture.userID, ScopeID: fixture.tenantScopeID, ScopeKind: certificateasset.ScopeTenant,
		TenantID: &tenantID, Permissions: permissions,
	}}
}

func (fixture publicationStatusHTTPFixture46) platformSession(permissions ...string) identity.AuthenticatedSession {
	return identity.AuthenticatedSession{SessionID: uuid.New(), Principal: identity.Principal{
		UserID: fixture.userID, ScopeID: uuid.New(), ScopeKind: certificateasset.ScopePlatform,
		Permissions: permissions,
	}}
}

func (fixture publicationStatusHTTPFixture46) serve(
	handler http.Handler,
	method, path, body string,
	mutate func(*http.Request),
) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer session")
	request.Header.Set("X-Request-ID", "certificate-publication-test")
	if mutate != nil {
		mutate(request)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func assertPublicationStatusResponse46(
	t *testing.T,
	response *httptest.ResponseRecorder,
	status int,
	code string,
) {
	t.Helper()
	if response.Code != status {
		t.Fatalf("status=%d body=%s, want %d", response.Code, response.Body.String(), status)
	}
	if code != "" {
		var body errorEnvelope
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || body.Error.Code != code {
			t.Fatalf("code=%q decode=%v body=%s, want %q", body.Error.Code, err, response.Body.String(), code)
		}
	}
	if response.Header().Get("Cache-Control") != "no-store" ||
		response.Header().Get("X-Content-Type-Options") != "nosniff" ||
		response.Header().Get("X-Request-ID") != "certificate-publication-test" {
		t.Fatalf("security headers = %v", response.Header())
	}
}

func pointerTime46(value time.Time) *time.Time { return &value }

func tamperPublicationStatusToken46(t *testing.T, token string) string {
	t.Helper()
	packet, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(packet) < 2 {
		t.Fatal(err)
	}
	packet[len(packet)/2] ^= 1
	return base64.RawURLEncoding.EncodeToString(packet)
}
