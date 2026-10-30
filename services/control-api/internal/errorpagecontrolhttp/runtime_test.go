package errorpagecontrolhttp

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/apikey"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/errorpagecontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestResolveAdaptersReusesInjectedInstances(t *testing.T) {
	store := &injectedContentStore{}
	scanner := &injectedScanner{}
	gotStore, gotScanner, err := resolveAdapters(t.Context(), Config{}, Dependencies{
		ContentStore: store,
		Scanner:      scanner,
	})
	if err != nil {
		t.Fatalf("resolveAdapters() error = %v", err)
	}
	if gotStore != store {
		t.Fatalf("resolveAdapters() content store = %p, want injected %p", gotStore, store)
	}
	if gotScanner != scanner {
		t.Fatalf("resolveAdapters() scanner = %p, want injected %p", gotScanner, scanner)
	}
}

type injectedContentStore struct{}

func (*injectedContentStore) Capabilities() errorpagecontrol.ObjectStoreCapabilities {
	return errorpagecontrol.ObjectStoreCapabilities{
		ImmutableStaging: true, ConditionalFinalize: true, TrustedMetadata: true,
		ImmutableReads: true, PreservesStagingAlias: true,
	}
}

func (*injectedContentStore) PutStaging(context.Context, errorpagecontrol.ObjectRef, []byte, string) (errorpagecontrol.ObjectInfo, error) {
	return errorpagecontrol.ObjectInfo{}, errors.New("unused injected store")
}

func (*injectedContentStore) Open(context.Context, errorpagecontrol.ObjectRef, string) (io.ReadCloser, error) {
	return nil, errors.New("unused injected store")
}

func (*injectedContentStore) Finalize(context.Context, errorpagecontrol.ObjectRef, errorpagecontrol.ObjectRef, errorpagecontrol.ObjectInfo) (errorpagecontrol.ObjectInfo, error) {
	return errorpagecontrol.ObjectInfo{}, errors.New("unused injected store")
}

func (*injectedContentStore) Stat(context.Context, errorpagecontrol.ObjectRef) (errorpagecontrol.ObjectInfo, error) {
	return errorpagecontrol.ObjectInfo{}, errors.New("unused injected store")
}

func (*injectedContentStore) Delete(context.Context, errorpagecontrol.ObjectRef) error {
	return errors.New("unused injected store")
}

type injectedScanner struct{}

func (*injectedScanner) Name() string { return "injected-scanner" }

func (*injectedScanner) Scan(context.Context, errorpagecontrol.ScanInput) error {
	return errors.New("unused injected scanner")
}

func TestNewRuntimeDisabledDoesNotRequireProductionDependencies(t *testing.T) {
	runtime, err := NewRuntime(t.Context(), Config{}, Dependencies{})
	if err != nil || runtime == nil {
		t.Fatalf("NewRuntime(disabled) = (%T,%v)", runtime, err)
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/error-pages/assets", nil)
	response := httptest.NewRecorder()
	runtime.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("disabled status = %d, want 404", response.Code)
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestNewRuntimeEnabledRejectsMissingDependenciesBeforeOutboundInitialization(t *testing.T) {
	valid := Dependencies{
		Pool: new(pgxpool.Pool), Identity: new(identity.Service), APIKeys: new(apikey.Service),
		IAM:              new(iamlock.Authorizer),
		EntitlementTrust: new(entitlementguard.TrustStore), Clock: time.Now,
	}
	tests := map[string]func(*Dependencies){
		"postgres":          func(value *Dependencies) { value.Pool = nil },
		"identity":          func(value *Dependencies) { value.Identity = nil },
		"api keys":          func(value *Dependencies) { value.APIKeys = nil },
		"iam":               func(value *Dependencies) { value.IAM = nil },
		"entitlement trust": func(value *Dependencies) { value.EntitlementTrust = nil },
		"clock":             func(value *Dependencies) { value.Clock = nil },
	}
	for name, remove := range tests {
		t.Run(name, func(t *testing.T) {
			dependencies := valid
			remove(&dependencies)
			runtime, err := NewRuntime(t.Context(), Config{Enabled: true}, dependencies)
			if runtime != nil || !errors.Is(err, errorpagecontrol.ErrInvalidStore) {
				t.Fatalf("NewRuntime() = (%T,%v), want nil ErrInvalidStore", runtime, err)
			}
		})
	}
}

func TestNewRuntimeEnabledRejectsNilContext(t *testing.T) {
	runtime, err := NewRuntime(nil, Config{Enabled: true}, Dependencies{})
	if runtime != nil || !errors.Is(err, errorpagecontrol.ErrInvalidStore) {
		t.Fatalf("NewRuntime(nil context) = (%T,%v), want nil ErrInvalidStore", runtime, err)
	}
}
