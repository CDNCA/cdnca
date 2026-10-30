package errorpagecontrol

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

type fakeSlotHTTPDomain struct {
	fakeHTTPDomain
	page        SlotPage
	document    SlotDocument
	write       WriteResult[SlotBinding]
	err         error
	listCalls   int
	getCalls    int
	bindCalls   int
	unbindCalls int
	key         string
	bindRequest BindSlotRequest
	unbind      UnbindSlotRequest
}

func (domain *fakeSlotHTTPDomain) ListSlots(context.Context, Actor) (SlotPage, error) {
	domain.listCalls++
	return domain.page, domain.err
}

func (domain *fakeSlotHTTPDomain) GetSlot(_ context.Context, _ Actor, key string) (SlotDocument, error) {
	domain.getCalls++
	domain.key = key
	return domain.document, domain.err
}

func (domain *fakeSlotHTTPDomain) BindSlot(_ context.Context, _ Actor, request BindSlotRequest) (WriteResult[SlotBinding], error) {
	domain.bindCalls++
	domain.bindRequest = request
	return domain.write, domain.err
}

func (domain *fakeSlotHTTPDomain) UnbindSlot(_ context.Context, _ Actor, request UnbindSlotRequest) (WriteResult[SlotBinding], error) {
	domain.unbindCalls++
	domain.unbind = request
	return domain.write, domain.err
}

func TestSlotHandlerListAndGet(t *testing.T) {
	t.Parallel()
	actor := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform"}
	domain := &fakeSlotHTTPDomain{
		page: SlotPage{Items: []SlotBinding{{Key: SlotBlacklist}, {Key: SlotHTTP400}}},
		document: SlotDocument{
			Binding: SlotBinding{Key: SlotHTTP400, Revision: 2},
			Content: "<!doctype html><title>400</title>",
		},
	}
	handler, err := NewHandler(domain, fixedAuthenticator{actor: actor})
	if err != nil {
		t.Fatal(err)
	}

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://control.test/v1/error-pages/slots", nil))
	if response.Code != http.StatusOK || domain.listCalls != 1 ||
		!strings.Contains(response.Body.String(), `"key":"blacklist"`) {
		t.Fatalf("list code=%d calls=%d body=%s", response.Code, domain.listCalls, response.Body.String())
	}

	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet,
		"http://control.test/v1/error-pages/slots/http_400", nil))
	var document SlotDocument
	if err := json.Unmarshal(response.Body.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK || domain.getCalls != 1 || domain.key != SlotHTTP400 ||
		document.Content != "<!doctype html><title>400</title>" {
		t.Fatalf("get code=%d calls=%d key=%q body=%s", response.Code, domain.getCalls, domain.key, response.Body.String())
	}
}

func TestSlotHandlerBindAndUnbind(t *testing.T) {
	t.Parallel()
	actor := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform"}
	assetID := uuid.New()
	domain := &fakeSlotHTTPDomain{write: WriteResult[SlotBinding]{
		Value: SlotBinding{Key: SlotWAFBlock, AssetID: &assetID, Revision: 4},
	}}
	handler, _ := NewHandler(domain, fixedAuthenticator{actor: actor})

	request := httptest.NewRequest(http.MethodPut, "http://control.test/v1/error-pages/slots/waf_block",
		strings.NewReader(`{"asset_id":"`+assetID.String()+`"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("If-Match", `"3"`)
	setWriteHeaders(request)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || domain.bindCalls != 1 || domain.bindRequest.Key != SlotWAFBlock ||
		domain.bindRequest.AssetID != assetID || domain.bindRequest.ExpectedRevision != 3 ||
		domain.bindRequest.IdempotencyKey != "idem" {
		t.Fatalf("bind code=%d calls=%d request=%#v body=%s", response.Code, domain.bindCalls,
			domain.bindRequest, response.Body.String())
	}

	request = httptest.NewRequest(http.MethodDelete, "http://control.test/v1/error-pages/slots/waf_block", nil)
	request.Header.Set("If-Match", `"4"`)
	setWriteHeaders(request)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || domain.unbindCalls != 1 || domain.unbind.Key != SlotWAFBlock ||
		domain.unbind.ExpectedRevision != 4 || domain.unbind.RequestID != "request" {
		t.Fatalf("unbind code=%d calls=%d request=%#v body=%s", response.Code, domain.unbindCalls,
			domain.unbind, response.Body.String())
	}
}

func TestSlotHandlerRejectsUnknownInputBeforeDomain(t *testing.T) {
	t.Parallel()
	actor := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform"}
	domain := &fakeSlotHTTPDomain{}
	handler, _ := NewHandler(domain, fixedAuthenticator{actor: actor})

	tests := []struct {
		name    string
		method  string
		path    string
		body    string
		headers func(*http.Request)
		status  int
	}{
		{name: "unknown key", method: http.MethodGet, path: "/v1/error-pages/slots/unknown", status: http.StatusNotFound},
		{name: "unknown json", method: http.MethodPut, path: "/v1/error-pages/slots/http_403",
			body: `{"asset_id":"` + uuid.NewString() + `","unknown":true}`, headers: func(request *http.Request) {
				request.Header.Set("Content-Type", "application/json")
				request.Header.Set("If-Match", `"0"`)
				setWriteHeaders(request)
			}, status: http.StatusBadRequest},
		{name: "missing if match", method: http.MethodDelete, path: "/v1/error-pages/slots/http_403",
			headers: setWriteHeaders, status: http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, "http://control.test"+test.path, strings.NewReader(test.body))
			if test.headers != nil {
				test.headers(request)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("code=%d want=%d body=%s", response.Code, test.status, response.Body.String())
			}
		})
	}
	if domain.listCalls != 0 || domain.getCalls != 0 || domain.bindCalls != 0 || domain.unbindCalls != 0 {
		t.Fatalf("unexpected domain calls: %#v", domain)
	}
}

func TestSlotHandlerStableDomainErrors(t *testing.T) {
	t.Parallel()
	actor := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform"}
	tests := []struct {
		err    error
		status int
		code   string
	}{
		{ErrPermissionDenied, http.StatusForbidden, "permission_denied"},
		{ErrRevisionConflict, http.StatusPreconditionFailed, "revision_conflict"},
		{ErrIdempotencyConflict, http.StatusConflict, "conflict"},
	}
	for _, test := range tests {
		domain := &fakeSlotHTTPDomain{err: test.err}
		handler, _ := NewHandler(domain, fixedAuthenticator{actor: actor})
		request := httptest.NewRequest(http.MethodPut, "http://control.test/v1/error-pages/slots/http_504",
			strings.NewReader(`{"asset_id":"`+uuid.NewString()+`"}`))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("If-Match", `"0"`)
		setWriteHeaders(request)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		var body struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if response.Code != test.status || body.Error.Code != test.code {
			t.Fatalf("error=%v code=%d body=%s", test.err, response.Code, response.Body.String())
		}
	}
}
