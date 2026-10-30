package errorpagecontrol

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestHandlerNeighborRouteDoesNotAuthenticate(t *testing.T) {
	authenticator := &reviewAuthenticator{}
	handler, err := NewHandler(&fakeHTTPDomain{}, authenticator)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet,
		"http://control.test/v1/error-pages-neighbor/assets", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound || authenticator.calls != 0 {
		t.Fatalf("status=%d authentication_calls=%d, want 404 and zero calls",
			response.Code, authenticator.calls)
	}
}

func TestHandlerRejectsUndeclaredRoutesBeforeAuthentication(t *testing.T) {
	id := uuid.NewString()
	tests := []string{
		apiPrefix + "/unknown",
		apiPrefix + "/assets/not-a-uuid",
		apiPrefix + "/rules/not-a-uuid",
		apiPrefix + "/assets/" + id + "/unknown",
		apiPrefix + "/rules/" + id + "/unknown",
		apiPrefix + "/assets/" + id + "/finalize/extra",
		apiPrefix + "/rules/" + id + "/enable/extra",
		apiPrefix + "/assets//content",
		apiPrefix + "/rules/",
	}
	for _, path := range tests {
		t.Run(path, func(t *testing.T) {
			authenticator := &reviewAuthenticator{err: errors.New("identity unavailable")}
			domain := &reviewPublicationDomain{fakeHTTPDomain: &fakeHTTPDomain{}}
			handler, err := NewHandler(domain, authenticator)
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodGet, "http://control.test"+path, nil)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusNotFound || authenticator.calls != 0 ||
				domain.initiateCalls != 0 || domain.uploadCalls != 0 || domain.calls != 0 {
				t.Fatalf("status=%d auth_calls=%d initiate_calls=%d upload_calls=%d publication_calls=%d",
					response.Code, authenticator.calls, domain.initiateCalls, domain.uploadCalls, domain.calls)
			}
		})
	}
}

func TestHandlerPreservesDeclaredRouteMethodContract(t *testing.T) {
	id := uuid.NewString()
	tests := []struct {
		path  string
		allow string
	}{
		{apiPrefix + "/assets/initiate", "POST"},
		{apiPrefix + "/assets", "GET"},
		{apiPrefix + "/assets/" + id, "GET, DELETE"},
		{apiPrefix + "/assets/" + id + "/content", "GET, PUT"},
		{apiPrefix + "/assets/" + id + "/finalize", "POST"},
		{apiPrefix + "/rules", "GET, POST"},
		{apiPrefix + "/rules/" + id, "GET, PATCH, DELETE"},
		{apiPrefix + "/rules/" + id + "/enable", "POST"},
		{apiPrefix + "/rules/" + id + "/disable", "POST"},
		{apiPrefix + "/publication-snapshot", "GET"},
	}
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			authenticator := &reviewAuthenticator{actor: tenantRuntimeActor()}
			handler, err := NewHandler(&fakeHTTPDomain{}, authenticator)
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodOptions, "http://control.test"+test.path, nil)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusMethodNotAllowed || authenticator.calls != 1 ||
				response.Header().Get("Allow") != test.allow ||
				!strings.Contains(response.Body.String(), `"code":"method_not_allowed"`) {
				t.Fatalf("status=%d auth_calls=%d allow=%q body=%s", response.Code,
					authenticator.calls, response.Header().Get("Allow"), response.Body.String())
			}
		})
	}
}

func TestHTTPErrorContractIncludesStableParameters(t *testing.T) {
	response := httptest.NewRecorder()
	writeHTTPError(response, errors.New("SQLSTATE 57P01 bucket=/secret/path"))
	var body struct {
		Error struct {
			Code   string         `json:"code"`
			Params map[string]any `json:"params"`
		} `json:"error"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusServiceUnavailable || body.Error.Code != "service_unavailable" ||
		body.Error.Params == nil || len(body.Error.Params) != 0 {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestConstructorsRejectTypedNilDependencies(t *testing.T) {
	var domain *typedNilHTTPDomain
	var authenticator *typedNilAuthenticator
	if handler, err := NewHandler(domain, fixedAuthenticator{actor: tenantRuntimeActor()}); handler != nil || !errors.Is(err, ErrInvalidStore) {
		t.Fatalf("NewHandler(typed nil domain) = (%T,%v)", handler, err)
	}
	if handler, err := NewHandler(&fakeHTTPDomain{}, authenticator); handler != nil || !errors.Is(err, ErrInvalidStore) {
		t.Fatalf("NewHandler(typed nil authenticator) = (%T,%v)", handler, err)
	}

	var content *typedNilContentStore
	var scanner *typedNilScanner
	var limits *typedNilLimits
	var auditor *typedNilAuditor
	var authorizer *typedNilTxAuthorizer
	tests := []struct {
		name       string
		content    ContentStore
		scanner    Scanner
		limits     LimitProvider
		auditor    AuditAppender
		authorizer TxAuthorizer
	}{
		{name: "content", content: content, scanner: &testScanner{name: "typed-nil"}, limits: runtimeLimits(), auditor: typedNilAuditFallback{}, authorizer: testTxAuthorizer{}},
		{name: "scanner", content: newMemoryContentStore(), scanner: scanner, limits: runtimeLimits(), auditor: typedNilAuditFallback{}, authorizer: testTxAuthorizer{}},
		{name: "limits", content: newMemoryContentStore(), scanner: &testScanner{name: "typed-nil"}, limits: limits, auditor: typedNilAuditFallback{}, authorizer: testTxAuthorizer{}},
		{name: "auditor", content: newMemoryContentStore(), scanner: &testScanner{name: "typed-nil"}, limits: runtimeLimits(), auditor: auditor, authorizer: testTxAuthorizer{}},
		{name: "authorizer", content: newMemoryContentStore(), scanner: &testScanner{name: "typed-nil"}, limits: runtimeLimits(), auditor: typedNilAuditFallback{}, authorizer: authorizer},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service, err := NewServiceWithDependencies(new(pgxpool.Pool), test.content, test.scanner, test.limits,
				test.auditor, time.Now, test.authorizer)
			if service != nil || !errors.Is(err, ErrInvalidStore) {
				t.Fatalf("NewServiceWithDependencies() = (%T,%v)", service, err)
			}
		})
	}
}

type typedNilHTTPDomain struct{ *fakeHTTPDomain }
type typedNilAuthenticator struct{}
type typedNilContentStore struct{}
type typedNilScanner struct{}
type typedNilLimits struct{}
type typedNilAuditor struct{}
type typedNilTxAuthorizer struct{}

func (*typedNilAuthenticator) Authenticate(*http.Request) (Actor, error) { return Actor{}, nil }

func (*typedNilContentStore) Capabilities() ObjectStoreCapabilities {
	return ObjectStoreCapabilities{
		ImmutableStaging: true, ConditionalFinalize: true, TrustedMetadata: true,
		ImmutableReads: true, PreservesStagingAlias: true,
	}
}
func (*typedNilContentStore) PutStaging(context.Context, ObjectRef, []byte, string) (ObjectInfo, error) {
	return ObjectInfo{}, nil
}
func (*typedNilContentStore) Open(context.Context, ObjectRef, string) (io.ReadCloser, error) {
	return nil, nil
}
func (*typedNilContentStore) Finalize(context.Context, ObjectRef, ObjectRef, ObjectInfo) (ObjectInfo, error) {
	return ObjectInfo{}, nil
}
func (*typedNilContentStore) Stat(context.Context, ObjectRef) (ObjectInfo, error) {
	return ObjectInfo{}, nil
}
func (*typedNilContentStore) Delete(context.Context, ObjectRef) error { return nil }

func (*typedNilScanner) Name() string                          { return "typed-nil" }
func (*typedNilScanner) Scan(context.Context, ScanInput) error { return nil }
func (*typedNilLimits) Limits(context.Context, pgx.Tx, EntitlementCheck) (EntitlementLimits, error) {
	return EntitlementLimits{}, nil
}
func (*typedNilAuditor) Append(context.Context, pgx.Tx, audit.Event) error           { return nil }
func (*typedNilTxAuthorizer) Authorize(context.Context, pgx.Tx, Actor, string) error { return nil }

type typedNilAuditFallback struct{}

func (typedNilAuditFallback) Append(context.Context, pgx.Tx, audit.Event) error { return nil }

func tenantRuntimeActor() Actor {
	return Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant",
		Credential: CredentialReference{Kind: CredentialKindSession, ID: uuid.New()}}
}

func runtimeLimits() LimitProvider {
	return staticLimits{quota: AssetQuota{
		MaxAssetBytes: MaxEdgeResourceBytes, MaxAssets: 10, MaxTotalBytes: MaxEdgePolicyBytes,
	}}
}
