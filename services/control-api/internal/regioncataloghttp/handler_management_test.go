package regioncataloghttp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/regioncatalog"
)

type managementCatalogStub struct {
	getID         string
	createRequest regioncatalog.CreateRequest
	updateRequest regioncatalog.UpdateRequest
	deleteRequest regioncatalog.DeleteRequest
	region        regioncatalog.Region
	replayed      bool
	err           error
}

func (stub *managementCatalogStub) List(context.Context, regioncatalog.Actor, regioncatalog.ListRequest) (regioncatalog.Page, error) {
	return regioncatalog.Page{}, stub.err
}

func (stub *managementCatalogStub) Get(_ context.Context, _ regioncatalog.Actor, id string) (regioncatalog.Region, error) {
	stub.getID = id
	return stub.region, stub.err
}

func (stub *managementCatalogStub) Create(_ context.Context, _ regioncatalog.Actor, request regioncatalog.CreateRequest) (regioncatalog.Region, bool, error) {
	stub.createRequest = request
	return stub.region, stub.replayed, stub.err
}

func (stub *managementCatalogStub) Update(_ context.Context, _ regioncatalog.Actor, request regioncatalog.UpdateRequest) (regioncatalog.Region, bool, error) {
	stub.updateRequest = request
	return stub.region, stub.replayed, stub.err
}

func (stub *managementCatalogStub) Delete(_ context.Context, _ regioncatalog.Actor, request regioncatalog.DeleteRequest) (bool, error) {
	stub.deleteRequest = request
	return stub.replayed, stub.err
}

func managementHandler(t *testing.T, stub *managementCatalogStub, permissions ...string) *Handler {
	t.Helper()
	handler, err := NewHandler(stub, func(context.Context, string) (identity.AuthenticatedSession, error) {
		return platformSession(permissions...), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func managementRequest(method, path, body string) *http.Request {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer live-session")
	request.Header.Set("X-Request-ID", "region-request-1")
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	return request
}

func TestHandlerCreatesAndReplaysPlatformRegions(t *testing.T) {
	stub := &managementCatalogStub{region: regionFixture("7", "华南"), replayed: true}
	request := managementRequest(http.MethodPost, Route, `{"name":" 华南 ","description":" 主区域 ","l2_check_port":8080,"sort":9}`)
	request.Header.Set("Idempotency-Key", "region-create-1")
	response := httptest.NewRecorder()

	managementHandler(t, stub, regioncatalog.PermissionManage).ServeHTTP(response, request)

	if response.Code != http.StatusCreated || response.Header().Get("Location") != Route+"/7" ||
		response.Header().Get("ETag") != `"1"` || response.Header().Get("Idempotent-Replay") != "true" {
		t.Fatalf("status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
	if stub.createRequest.Name != " 华南 " || stub.createRequest.Description != " 主区域 " ||
		stub.createRequest.L2CheckPort != 8080 || stub.createRequest.Sort != 9 ||
		stub.createRequest.IdempotencyKey != "region-create-1" || stub.createRequest.RequestID != "region-request-1" {
		t.Fatalf("create request=%+v", stub.createRequest)
	}
}

func TestHandlerGetsAndUpdatesRegionWithStrongRevision(t *testing.T) {
	region := regionFixture("7", "华南")
	region.Revision = 4
	stub := &managementCatalogStub{region: region}
	handler := managementHandler(t, stub, regioncatalog.PermissionRead, regioncatalog.PermissionManage)

	getRequest := managementRequest(http.MethodGet, Route+"/7", "")
	getResponse := httptest.NewRecorder()
	handler.ServeHTTP(getResponse, getRequest)
	if getResponse.Code != http.StatusOK || stub.getID != "7" || getResponse.Header().Get("ETag") != `"4"` {
		t.Fatalf("get status=%d id=%q headers=%v", getResponse.Code, stub.getID, getResponse.Header())
	}

	updateRequest := managementRequest(http.MethodPatch, Route+"/7", `{"name":"华南二","country_code":"CN","province_code":"440000","description":"备注","l2_check_port":443,"sort":8}`)
	updateRequest.Header.Set("Idempotency-Key", "region-update-1")
	updateRequest.Header.Set("If-Match", `"3"`)
	updateResponse := httptest.NewRecorder()
	handler.ServeHTTP(updateResponse, updateRequest)
	if updateResponse.Code != http.StatusOK || stub.updateRequest.ID != "7" ||
		stub.updateRequest.ExpectedRevision != 3 || stub.updateRequest.Name != "华南二" ||
		stub.updateRequest.L2CheckPort != 443 || stub.updateRequest.Sort != 8 ||
		stub.updateRequest.CountryCode != "CN" || stub.updateRequest.ProvinceCode != "440000" {
		t.Fatalf("update status=%d request=%+v body=%s", updateResponse.Code, stub.updateRequest, updateResponse.Body.String())
	}
}

func TestHandlerRequiresManagePermissionIdempotencyAndIfMatch(t *testing.T) {
	body := `{"name":"华南","description":"","l2_check_port":80,"sort":100}`
	for _, test := range []struct {
		name        string
		permissions []string
		mutate      func(*http.Request)
		status      int
		code        string
	}{
		{name: "read only", permissions: []string{regioncatalog.PermissionRead}, mutate: func(request *http.Request) {
			request.Header.Set("Idempotency-Key", "region-update-1")
			request.Header.Set("If-Match", `"1"`)
		}, status: http.StatusForbidden, code: "regions_permission_denied"},
		{name: "missing idempotency", permissions: []string{regioncatalog.PermissionManage}, mutate: func(request *http.Request) {
			request.Header.Set("If-Match", `"1"`)
		}, status: http.StatusBadRequest, code: "regions_validation_error"},
		{name: "missing if match", permissions: []string{regioncatalog.PermissionManage}, mutate: func(request *http.Request) {
			request.Header.Set("Idempotency-Key", "region-update-1")
		}, status: http.StatusPreconditionRequired, code: "regions_precondition_required"},
		{name: "weak if match", permissions: []string{regioncatalog.PermissionManage}, mutate: func(request *http.Request) {
			request.Header.Set("Idempotency-Key", "region-update-1")
			request.Header.Set("If-Match", "1")
		}, status: http.StatusBadRequest, code: "regions_validation_error"},
		{name: "unknown field", permissions: []string{regioncatalog.PermissionManage}, mutate: func(request *http.Request) {
			request.Header.Set("Idempotency-Key", "region-update-1")
			request.Header.Set("If-Match", `"1"`)
			request.Body = ioNopCloser(`{"name":"华南","description":"","l2_check_port":80,"sort":100,"tenant_id":"x"}`)
		}, status: http.StatusBadRequest, code: "regions_validation_error"},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := managementRequest(http.MethodPatch, Route+"/7", body)
			test.mutate(request)
			response := httptest.NewRecorder()
			managementHandler(t, &managementCatalogStub{}, test.permissions...).ServeHTTP(response, request)
			if response.Code != test.status || !containsErrorCode(response.Body.String(), test.code) {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func TestHandlerDeletesAndMapsRegionManagementConflicts(t *testing.T) {
	request := managementRequest(http.MethodDelete, Route+"/9", "")
	request.Header.Set("Idempotency-Key", "region-delete-1")
	request.Header.Set("If-Match", `"6"`)
	response := httptest.NewRecorder()
	stub := &managementCatalogStub{replayed: true}
	managementHandler(t, stub, regioncatalog.PermissionManage).ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || response.Header().Get("Idempotent-Replay") != "true" ||
		stub.deleteRequest.ID != "9" || stub.deleteRequest.ExpectedRevision != 6 {
		t.Fatalf("status=%d request=%+v headers=%v", response.Code, stub.deleteRequest, response.Header())
	}

	for _, test := range []struct {
		err    error
		status int
		code   string
	}{
		{regioncatalog.ErrNotFound, 404, "regions_not_found"},
		{regioncatalog.ErrNameConflict, 409, "regions_name_conflict"},
		{regioncatalog.ErrIdempotencyConflict, 409, "regions_idempotency_conflict"},
		{regioncatalog.ErrInUse, 409, "regions_in_use"},
		{regioncatalog.ErrRevisionConflict, 412, "regions_revision_conflict"},
		{regioncatalog.ErrUnavailable, 503, "regions_unavailable"},
	} {
		request := managementRequest(http.MethodDelete, Route+"/9", "")
		request.Header.Set("Idempotency-Key", "region-delete-1")
		request.Header.Set("If-Match", `"6"`)
		response := httptest.NewRecorder()
		managementHandler(t, &managementCatalogStub{err: test.err}, regioncatalog.PermissionManage).ServeHTTP(response, request)
		if response.Code != test.status || !containsErrorCode(response.Body.String(), test.code) {
			t.Fatalf("error=%v status=%d body=%s", test.err, response.Code, response.Body.String())
		}
	}
}

func TestHandlerPaginatesRegionsAndRejectsMixedLegacyLimits(t *testing.T) {
	stub := &managementCatalogStub{}
	request := managementRequest(http.MethodGet, Route+"?page=2&page_size=30&search=%E5%8D%8E", "")
	response := httptest.NewRecorder()
	managementHandler(t, stub, regioncatalog.PermissionRead).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}

	mixed := managementRequest(http.MethodGet, Route+"?limit=0&page=1", "")
	mixedResponse := httptest.NewRecorder()
	managementHandler(t, stub, regioncatalog.PermissionRead).ServeHTTP(mixedResponse, mixed)
	if mixedResponse.Code != http.StatusBadRequest {
		t.Fatalf("mixed status=%d body=%s", mixedResponse.Code, mixedResponse.Body.String())
	}
}

func ioNopCloser(value string) *readCloser {
	return &readCloser{Reader: strings.NewReader(value)}
}

type readCloser struct{ *strings.Reader }

func (reader *readCloser) Close() error { return nil }

var _ = errors.Is
