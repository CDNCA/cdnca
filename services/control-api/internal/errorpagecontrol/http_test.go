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

func TestHandlerRejectsUnknownJSONAndRequiresWriteCorrelation(t *testing.T) {
	t.Parallel()
	actor := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform"}
	domain := &fakeHTTPDomain{}
	handler, err := NewHandler(domain, fixedAuthenticator{actor: actor})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "http://control.test/v1/error-pages/assets/initiate",
		strings.NewReader(`{"scope_id":"`+actor.ScopeID.String()+`","mime_type":"text/plain","size_bytes":4,"sha256":"`+strings.Repeat("a", 64)+`","unknown":true}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "idem-1")
	request.Header.Set("X-Request-ID", "request-1")
	request.Header.Set("X-Trace-ID", "trace-1")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || domain.initiateCalls != 0 ||
		!strings.Contains(response.Body.String(), `"code":"invalid_request"`) {
		t.Fatalf("code=%d calls=%d body=%s", response.Code, domain.initiateCalls, response.Body.String())
	}

	request = httptest.NewRequest(http.MethodPost, "http://control.test/v1/error-pages/assets/initiate",
		strings.NewReader(`{"scope_id":"`+actor.ScopeID.String()+`","mime_type":"text/plain","size_bytes":4,"sha256":"`+strings.Repeat("a", 64)+`"}`))
	request.Header.Set("Content-Type", "application/json")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || domain.initiateCalls != 0 {
		t.Fatalf("missing metadata code=%d calls=%d", response.Code, domain.initiateCalls)
	}

	oversized := `{"scope_id":"` + actor.ScopeID.String() + `","mime_type":"text/plain","size_bytes":4,"sha256":"` +
		strings.Repeat("a", 64) + `"}` + strings.Repeat(" ", maxJSONBody)
	request = httptest.NewRequest(http.MethodPost, "http://control.test/v1/error-pages/assets/initiate", strings.NewReader(oversized))
	request.ContentLength = -1
	request.Header.Set("Content-Type", "application/json")
	setWriteHeaders(request)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || domain.initiateCalls != 0 {
		t.Fatalf("unknown-length oversized body code=%d calls=%d", response.Code, domain.initiateCalls)
	}
}

func TestHandlerReturnsPublicAssetMetadataWithoutObjectKeys(t *testing.T) {
	t.Parallel()
	actor := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform"}
	assetID := uuid.New()
	domain := &fakeHTTPDomain{asset: Asset{
		ID: assetID, ScopeID: actor.ScopeID, MIMEType: "text/plain", SizeBytes: 4,
		SHA256: strings.Repeat("a", 64), Status: StatusInitiated, ScanStatus: "pending",
		stagingObjectKey: "secret/staging", storageObjectKey: "secret/final",
	}}
	handler, _ := NewHandler(domain, fixedAuthenticator{actor: actor})
	request := httptest.NewRequest(http.MethodGet, "http://control.test/v1/error-pages/assets/"+assetID.String(), nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("code=%d body=%s", response.Code, response.Body.String())
	}
	for _, secret := range []string{"secret/staging", "secret/final", "storage_object_key", "staging_object_key"} {
		if strings.Contains(response.Body.String(), secret) {
			t.Fatalf("response leaked %q: %s", secret, response.Body.String())
		}
	}
}

func TestHandlerStableErrorMapping(t *testing.T) {
	t.Parallel()
	tests := []struct {
		err    error
		status int
		code   string
	}{
		{ErrInvalidInput, 400, "invalid_request"},
		{ErrUnauthenticated, 401, "authentication_required"},
		{ErrPermissionDenied, 403, "permission_denied"},
		{ErrNotFound, 404, "not_found"},
		{ErrConflict, 409, "conflict"},
		{ErrRevisionConflict, 412, "revision_conflict"},
		{ErrUnsafeContent, 422, "unsafe_content"},
		{ErrScanRejected, 422, "scan_rejected"},
		{errors.New("sql details must not escape"), 503, "service_unavailable"},
	}
	for _, test := range tests {
		response := httptest.NewRecorder()
		writeHTTPError(response, test.err)
		if response.Code != test.status || !strings.Contains(response.Body.String(), `"code":"`+test.code+`"`) ||
			strings.Contains(response.Body.String(), "sql details") {
			t.Fatalf("error=%v code=%d body=%s", test.err, response.Code, response.Body.String())
		}
	}
}

func TestHTTPErrorMappingsIncludeStableRequestID(t *testing.T) {
	t.Parallel()
	tests := []struct {
		err    error
		status int
		code   string
	}{
		{ErrInvalidInput, http.StatusBadRequest, "invalid_request"},
		{ErrInvalidCredential, http.StatusUnauthorized, "authentication_required"},
		{ErrUnauthenticated, http.StatusUnauthorized, "authentication_required"},
		{ErrPermissionDenied, http.StatusForbidden, "permission_denied"},
		{ErrNotFound, http.StatusNotFound, "not_found"},
		{ErrConflict, http.StatusConflict, "conflict"},
		{ErrIdempotencyConflict, http.StatusConflict, "conflict"},
		{ErrRevisionConflict, http.StatusPreconditionFailed, "revision_conflict"},
		{ErrQuotaExceeded, http.StatusUnprocessableEntity, "quota_exceeded"},
		{ErrEntitlementDenied, http.StatusUnprocessableEntity, "quota_exceeded"},
		{ErrUnsafeContent, http.StatusUnprocessableEntity, "unsafe_content"},
		{ErrScanRejected, http.StatusUnprocessableEntity, "scan_rejected"},
		{errMethodNotAllowed, http.StatusMethodNotAllowed, "method_not_allowed"},
		{errors.New("SQLSTATE 57P01 bucket=/secret/path"), http.StatusServiceUnavailable, "service_unavailable"},
	}
	for _, test := range tests {
		response := httptest.NewRecorder()
		response.Header().Set("X-Request-ID", "mapping-request")
		writeHTTPError(response, test.err)
		var body struct {
			Error struct {
				Code      string         `json:"code"`
				Params    map[string]any `json:"params"`
				RequestID string         `json:"request_id"`
			} `json:"error"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if response.Code != test.status || body.Error.Code != test.code || body.Error.Params == nil ||
			len(body.Error.Params) != 0 || body.Error.RequestID != "mapping-request" ||
			response.Header().Get("X-Request-ID") != body.Error.RequestID ||
			strings.Contains(response.Body.String(), "SQLSTATE") || strings.Contains(response.Body.String(), "/secret/path") {
			t.Fatalf("error=%v status=%d body=%s", test.err, response.Code, response.Body.String())
		}
	}
}

func TestHandlerRejectsMIMEParametersAndOversizedResponse(t *testing.T) {
	t.Parallel()
	actor := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant"}
	domain := &fakeHTTPDomain{}
	handler, _ := NewHandler(domain, fixedAuthenticator{actor: actor})
	request := httptest.NewRequest(http.MethodPut, "http://control.test/v1/error-pages/assets/"+uuid.NewString()+"/content",
		strings.NewReader("body"))
	request.Header.Set("Content-Type", "text/plain; charset=utf-8")
	setWriteHeaders(request)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || domain.uploadCalls != 0 {
		t.Fatalf("code=%d calls=%d", response.Code, domain.uploadCalls)
	}

	response = httptest.NewRecorder()
	writeDomainResponse(response, http.StatusOK, strings.Repeat("x", maxResponseBody+1), nil)
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "service_unavailable") {
		t.Fatalf("oversized response code=%d body=%s", response.Code, response.Body.String())
	}
}

func TestHandlerHasNoExecutablePreviewAndSetsRestrictiveCSP(t *testing.T) {
	t.Parallel()
	actor := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant"}
	handler, err := NewHandler(&fakeHTTPDomain{}, fixedAuthenticator{actor: actor})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet,
		"http://control.test/v1/error-pages/assets/"+uuid.NewString()+"/preview", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("preview code=%d body=%s", response.Code, response.Body.String())
	}
	if got := response.Header().Get("Content-Security-Policy"); got != "default-src 'none'; frame-ancestors 'none'; sandbox" {
		t.Fatalf("Content-Security-Policy=%q", got)
	}
}

func setWriteHeaders(request *http.Request) {
	request.Header.Set("Idempotency-Key", "idem")
	request.Header.Set("X-Request-ID", "request")
	request.Header.Set("X-Trace-ID", "trace")
}

type fixedAuthenticator struct {
	actor Actor
	err   error
}

func (auth fixedAuthenticator) Authenticate(*http.Request) (Actor, error) {
	if auth.actor.Credential.ID == uuid.Nil {
		auth.actor.Credential = CredentialReference{Kind: CredentialKindSession, ID: uuid.New()}
	}
	return auth.actor, auth.err
}

type fakeHTTPDomain struct {
	asset         Asset
	initiateCalls int
	uploadCalls   int
}

func (domain *fakeHTTPDomain) InitiateAsset(_ context.Context, _ Actor, _ InitiateAssetRequest) (WriteResult[Asset], error) {
	domain.initiateCalls++
	return WriteResult[Asset]{Value: domain.asset}, nil
}

func (domain *fakeHTTPDomain) UploadAsset(_ context.Context, _ Actor, _ UploadAssetRequest) (WriteResult[Asset], error) {
	domain.uploadCalls++
	return WriteResult[Asset]{Value: domain.asset}, nil
}

func (domain *fakeHTTPDomain) FinalizeAsset(context.Context, Actor, FinalizeAssetRequest) (WriteResult[Asset], error) {
	return WriteResult[Asset]{Value: domain.asset}, nil
}

func (domain *fakeHTTPDomain) DeleteAsset(context.Context, Actor, DeleteAssetRequest) (WriteResult[Asset], error) {
	return WriteResult[Asset]{Value: domain.asset}, nil
}

func (domain *fakeHTTPDomain) GetAsset(context.Context, Actor, uuid.UUID) (Asset, error) {
	return domain.asset, nil
}

func (domain *fakeHTTPDomain) GetAssetContent(context.Context, Actor, uuid.UUID) (AssetContent, error) {
	return AssetContent{Asset: domain.asset, Content: "<h1>x</h1>"}, nil
}

func (domain *fakeHTTPDomain) ListAssets(context.Context, Actor, AssetPageRequest) (AssetPage, error) {
	return AssetPage{Items: []Asset{}}, nil
}

func (domain *fakeHTTPDomain) CreateRule(context.Context, Actor, CreateRuleRequest) (WriteResult[Rule], error) {
	return WriteResult[Rule]{}, nil
}

func (domain *fakeHTTPDomain) UpdateRule(context.Context, Actor, UpdateRuleRequest) (WriteResult[Rule], error) {
	return WriteResult[Rule]{}, nil
}

func (domain *fakeHTTPDomain) EnableRule(context.Context, Actor, ChangeRuleStateRequest) (WriteResult[Rule], error) {
	return WriteResult[Rule]{}, nil
}

func (domain *fakeHTTPDomain) DisableRule(context.Context, Actor, ChangeRuleStateRequest) (WriteResult[Rule], error) {
	return WriteResult[Rule]{}, nil
}

func (domain *fakeHTTPDomain) DeleteRule(context.Context, Actor, ChangeRuleStateRequest) (WriteResult[Rule], error) {
	return WriteResult[Rule]{}, nil
}

func (domain *fakeHTTPDomain) GetRule(context.Context, Actor, uuid.UUID) (Rule, error) {
	return Rule{}, nil
}

func (domain *fakeHTTPDomain) ListRules(context.Context, Actor, RulePageRequest) (RulePage, error) {
	return RulePage{Items: []Rule{}}, nil
}

func (domain *fakeHTTPDomain) PublicationSnapshot(context.Context, Actor) (PublicationSnapshot, error) {
	return PublicationSnapshot{}, nil
}
