package errorpagecontrol

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

type fakeScopeOverrideHTTPDomain struct {
	fakeHTTPDomain
	page          ScopeOverridePage
	record        ScopeOverride
	write         WriteResult[ScopeOverride]
	err           error
	listCalls     int
	getCalls      int
	createCalls   int
	updateCalls   int
	deleteCalls   int
	displayID     int64
	createRequest CreateScopeOverrideRequest
	updateRequest UpdateScopeOverrideRequest
	deleteRequest DeleteScopeOverrideRequest
}

func (domain *fakeScopeOverrideHTTPDomain) ListScopeOverrides(context.Context, Actor) (ScopeOverridePage, error) {
	domain.listCalls++
	return domain.page, domain.err
}

func (domain *fakeScopeOverrideHTTPDomain) GetScopeOverride(_ context.Context, _ Actor, displayID int64) (ScopeOverride, error) {
	domain.getCalls++
	domain.displayID = displayID
	return domain.record, domain.err
}

func (domain *fakeScopeOverrideHTTPDomain) CreateScopeOverride(
	_ context.Context,
	_ Actor,
	request CreateScopeOverrideRequest,
) (WriteResult[ScopeOverride], error) {
	domain.createCalls++
	domain.createRequest = request
	return domain.write, domain.err
}

func (domain *fakeScopeOverrideHTTPDomain) UpdateScopeOverride(
	_ context.Context,
	_ Actor,
	request UpdateScopeOverrideRequest,
) (WriteResult[ScopeOverride], error) {
	domain.updateCalls++
	domain.updateRequest = request
	return domain.write, domain.err
}

func (domain *fakeScopeOverrideHTTPDomain) DeleteScopeOverride(
	_ context.Context,
	_ Actor,
	request DeleteScopeOverrideRequest,
) (WriteResult[ScopeOverride], error) {
	domain.deleteCalls++
	domain.deleteRequest = request
	return domain.write, domain.err
}

func TestScopeOverrideHandlerCRUD(t *testing.T) {
	t.Parallel()
	actor := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform"}
	firstAssetID, secondAssetID := uuid.New(), uuid.New()
	domain := &fakeScopeOverrideHTTPDomain{
		page: ScopeOverridePage{Items: []ScopeOverride{{DisplayID: "17", Revision: 3}}, Total: 1},
		record: ScopeOverride{
			DisplayID: "17", Target: ScopeOverrideTarget{Kind: ScopeOverrideNode, NodeDisplayID: "42"},
			Items: []ScopeOverrideItem{{Key: SlotHTTP400, Content: "<h1>400</h1>"}}, Revision: 3,
		},
	}
	handler, err := NewHandler(domain, fixedAuthenticator{actor: actor})
	if err != nil {
		t.Fatal(err)
	}

	response := serveScopeOverrideHTTP(t, handler, http.MethodGet, apiPrefix+"/scope-overrides", "", nil)
	if response.Code != http.StatusOK || domain.listCalls != 1 {
		t.Fatalf("list status=%d calls=%d body=%s", response.Code, domain.listCalls, response.Body.String())
	}
	var page ScopeOverridePage
	if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil || page.Total != 1 || page.Items[0].DisplayID != "17" {
		t.Fatalf("list page=%#v err=%v", page, err)
	}

	domain.write = WriteResult[ScopeOverride]{Value: ScopeOverride{
		DisplayID: "17", Target: ScopeOverrideTarget{Kind: ScopeOverrideNode, NodeDisplayID: "42"},
		Items: []ScopeOverrideItem{{Key: SlotHTTP400}, {Key: SlotConnectionLimit}}, Revision: 1,
	}}
	createBody := `{"target":{"kind":"node","node_display_id":"42","region":""},"items":[` +
		`{"key":"connection_limit","asset_id":"` + secondAssetID.String() + `"},` +
		`{"key":"http_400","asset_id":"` + firstAssetID.String() + `"}]}`
	response = serveScopeOverrideHTTP(t, handler, http.MethodPost, apiPrefix+"/scope-overrides", createBody, func(request *http.Request) {
		request.Header.Set("Content-Type", "application/json")
		setWriteHeaders(request)
	})
	if response.Code != http.StatusCreated || domain.createCalls != 1 ||
		domain.createRequest.TargetKind != ScopeOverrideNode || domain.createRequest.NodeDisplayID != 42 ||
		domain.createRequest.Region != "" || len(domain.createRequest.Items) != 2 ||
		domain.createRequest.Items[0].Key != SlotHTTP400 || domain.createRequest.Items[0].AssetID != firstAssetID ||
		domain.createRequest.Items[1].Key != SlotConnectionLimit || domain.createRequest.Items[1].AssetID != secondAssetID ||
		domain.createRequest.IdempotencyKey != "idem" {
		t.Fatalf("create status=%d calls=%d request=%#v body=%s", response.Code, domain.createCalls,
			domain.createRequest, response.Body.String())
	}

	response = serveScopeOverrideHTTP(t, handler, http.MethodGet, apiPrefix+"/scope-overrides/17", "", nil)
	var loaded ScopeOverride
	if err := json.Unmarshal(response.Body.Bytes(), &loaded); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK || domain.getCalls != 1 || domain.displayID != 17 ||
		len(loaded.Items) != 1 || loaded.Items[0].Content != "<h1>400</h1>" {
		t.Fatalf("get status=%d calls=%d id=%d body=%s", response.Code, domain.getCalls, domain.displayID,
			response.Body.String())
	}

	domain.write = WriteResult[ScopeOverride]{Value: ScopeOverride{DisplayID: "17", Revision: 4}}
	updateBody := `{"items":[{"key":"http_403","asset_id":"` + secondAssetID.String() + `"}]}`
	response = serveScopeOverrideHTTP(t, handler, http.MethodPatch, apiPrefix+"/scope-overrides/17", updateBody, func(request *http.Request) {
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("If-Match", `"3"`)
		setWriteHeaders(request)
	})
	if response.Code != http.StatusOK || domain.updateCalls != 1 || domain.updateRequest.DisplayID != 17 ||
		domain.updateRequest.ExpectedRevision != 3 || len(domain.updateRequest.Items) != 1 ||
		domain.updateRequest.Items[0].Key != SlotHTTP403 || domain.updateRequest.TraceID != "trace" {
		t.Fatalf("update status=%d calls=%d request=%#v body=%s", response.Code, domain.updateCalls,
			domain.updateRequest, response.Body.String())
	}

	domain.write = WriteResult[ScopeOverride]{Value: ScopeOverride{DisplayID: "17", Revision: 5, Deleted: true}}
	response = serveScopeOverrideHTTP(t, handler, http.MethodDelete, apiPrefix+"/scope-overrides/17", "", func(request *http.Request) {
		request.Header.Set("If-Match", `"4"`)
		setWriteHeaders(request)
	})
	if response.Code != http.StatusAccepted || domain.deleteCalls != 1 || domain.deleteRequest.DisplayID != 17 ||
		domain.deleteRequest.ExpectedRevision != 4 || domain.deleteRequest.RequestID != "request" {
		t.Fatalf("delete status=%d calls=%d request=%#v body=%s", response.Code, domain.deleteCalls,
			domain.deleteRequest, response.Body.String())
	}
}

func TestScopeOverrideHandlerRejectsInvalidInputBeforeDomain(t *testing.T) {
	t.Parallel()
	actor := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform"}
	assetID := uuid.NewString()
	domain := &fakeScopeOverrideHTTPDomain{}
	handler, err := NewHandler(domain, fixedAuthenticator{actor: actor})
	if err != nil {
		t.Fatal(err)
	}
	writeJSON := func(request *http.Request) {
		request.Header.Set("Content-Type", "application/json")
		setWriteHeaders(request)
	}
	tests := []struct {
		name    string
		method  string
		path    string
		body    string
		headers func(*http.Request)
		status  int
	}{
		{name: "unknown query", method: http.MethodGet, path: "/v1/error-pages/scope-overrides?limit=10", status: http.StatusBadRequest},
		{name: "get body", method: http.MethodGet, path: "/v1/error-pages/scope-overrides", body: `{}`, status: http.StatusBadRequest},
		{name: "leading zero display id", method: http.MethodGet, path: "/v1/error-pages/scope-overrides/01", status: http.StatusNotFound},
		{name: "unknown json", method: http.MethodPost, path: "/v1/error-pages/scope-overrides",
			body:    `{"target":{"kind":"region","node_display_id":"","region":"华东"},"items":[{"key":"http_400","asset_id":"` + assetID + `"}],"unknown":true}`,
			headers: writeJSON, status: http.StatusBadRequest},
		{name: "node target with region", method: http.MethodPost, path: "/v1/error-pages/scope-overrides",
			body:    `{"target":{"kind":"node","node_display_id":"3","region":"华东"},"items":[{"key":"http_400","asset_id":"` + assetID + `"}]}`,
			headers: writeJSON, status: http.StatusBadRequest},
		{name: "region target without region", method: http.MethodPost, path: "/v1/error-pages/scope-overrides",
			body:    `{"target":{"kind":"region","node_display_id":"","region":""},"items":[{"key":"http_400","asset_id":"` + assetID + `"}]}`,
			headers: writeJSON, status: http.StatusBadRequest},
		{name: "duplicate item key", method: http.MethodPost, path: "/v1/error-pages/scope-overrides",
			body:    `{"target":{"kind":"region","node_display_id":"","region":"华东"},"items":[{"key":"http_400","asset_id":"` + assetID + `"},{"key":"http_400","asset_id":"` + uuid.NewString() + `"}]}`,
			headers: writeJSON, status: http.StatusBadRequest},
		{name: "missing write headers", method: http.MethodPost, path: "/v1/error-pages/scope-overrides",
			body:    `{"target":{"kind":"region","node_display_id":"","region":"华东"},"items":[{"key":"http_400","asset_id":"` + assetID + `"}]}`,
			headers: func(request *http.Request) { request.Header.Set("Content-Type", "application/json") }, status: http.StatusBadRequest},
		{name: "missing if match", method: http.MethodPatch, path: "/v1/error-pages/scope-overrides/3",
			body: `{"items":[{"key":"http_400","asset_id":"` + assetID + `"}]}`, headers: writeJSON, status: http.StatusBadRequest},
		{name: "delete body", method: http.MethodDelete, path: "/v1/error-pages/scope-overrides/3", body: `{}`,
			headers: func(request *http.Request) { request.Header.Set("If-Match", `"1"`); setWriteHeaders(request) }, status: http.StatusBadRequest},
		{name: "method not allowed", method: http.MethodPut, path: "/v1/error-pages/scope-overrides", status: http.StatusMethodNotAllowed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := serveScopeOverrideHTTP(t, handler, test.method, test.path, test.body, test.headers)
			if response.Code != test.status {
				t.Fatalf("status=%d want=%d body=%s", response.Code, test.status, response.Body.String())
			}
		})
	}
	if domain.listCalls != 0 || domain.getCalls != 0 || domain.createCalls != 0 || domain.updateCalls != 0 ||
		domain.deleteCalls != 0 {
		t.Fatalf("unexpected domain calls: %#v", domain)
	}
}

func TestScopeOverrideHandlerStableDomainErrors(t *testing.T) {
	t.Parallel()
	actor := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform"}
	assetID := uuid.NewString()
	tests := []struct {
		name    string
		err     error
		method  string
		path    string
		body    string
		headers func(*http.Request)
		status  int
		code    string
	}{
		{name: "permission", err: ErrPermissionDenied, method: http.MethodGet,
			path: "/v1/error-pages/scope-overrides", status: http.StatusForbidden, code: "permission_denied"},
		{name: "not found", err: ErrNotFound, method: http.MethodGet,
			path: "/v1/error-pages/scope-overrides/9", status: http.StatusNotFound, code: "not_found"},
		{name: "idempotency conflict", err: ErrIdempotencyConflict, method: http.MethodPost,
			path: "/v1/error-pages/scope-overrides",
			body: `{"target":{"kind":"region","node_display_id":"","region":"华东"},"items":[{"key":"http_400","asset_id":"` + assetID + `"}]}`,
			headers: func(request *http.Request) {
				request.Header.Set("Content-Type", "application/json")
				setWriteHeaders(request)
			},
			status: http.StatusConflict, code: "conflict"},
		{name: "revision conflict", err: ErrRevisionConflict, method: http.MethodPatch,
			path: "/v1/error-pages/scope-overrides/9",
			body: `{"items":[{"key":"http_400","asset_id":"` + assetID + `"}]}`,
			headers: func(request *http.Request) {
				request.Header.Set("Content-Type", "application/json")
				request.Header.Set("If-Match", `"2"`)
				setWriteHeaders(request)
			}, status: http.StatusPreconditionFailed, code: "revision_conflict"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			domain := &fakeScopeOverrideHTTPDomain{err: test.err}
			handler, err := NewHandler(domain, fixedAuthenticator{actor: actor})
			if err != nil {
				t.Fatal(err)
			}
			response := serveScopeOverrideHTTP(t, handler, test.method, test.path, test.body, test.headers)
			var body struct {
				Error struct {
					Code string `json:"code"`
				} `json:"error"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if response.Code != test.status || body.Error.Code != test.code {
				t.Fatalf("error=%v status=%d body=%s", test.err, response.Code, response.Body.String())
			}
		})
	}
}

func TestScopeOverrideValidationLimits(t *testing.T) {
	t.Parallel()
	items := make([]ScopeOverrideBinding, len(ErrorPageScopeOverrideSlotKeys)+1)
	for index := range items {
		items[index] = ScopeOverrideBinding{Key: SlotHTTP400, AssetID: uuid.New()}
	}
	if _, err := normalizeScopeOverrideBindings(items); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("eleven items error=%v", err)
	}
	if validScopeOverrideTarget(ScopeOverrideNode, 1, "华东") ||
		validScopeOverrideTarget(ScopeOverrideRegion, 1, "华东") ||
		validScopeOverrideTarget(ScopeOverrideRegion, 0, " 华东") {
		t.Fatal("invalid target was accepted")
	}
}

func serveScopeOverrideHTTP(
	t *testing.T,
	handler http.Handler,
	method, path, body string,
	headers func(*http.Request),
) *httptest.ResponseRecorder {
	t.Helper()
	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	request := httptest.NewRequest(method, "http://control.test"+path, reader)
	if headers != nil {
		headers(request)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}
