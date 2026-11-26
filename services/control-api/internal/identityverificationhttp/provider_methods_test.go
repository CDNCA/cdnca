package identityverificationhttp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/identityverification"
	"github.com/jackc/pgx/v5/pgxpool"
)

// GET /methods 只给出已配置的那一个认证服务的名称与已开通的认证类型，
// 不暴露端点或密钥；服务未配置、凭据未就绪或全部类型被关闭时 configured=false。
func TestProviderMethodsReportOnlyTheConfiguredServiceAndEnabledKinds(t *testing.T) {
	pool, err := pgxpool.New(t.Context(), "postgres://unused@127.0.0.1:1/unused?connect_timeout=1")
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	enabled := map[string]bool{"personal_initial": true, "personal_reverification": true, "enterprise": true}
	var policyErr error
	provider, objects := &reconfigurableProviderStub{}, &reconfigurableObjectsStub{}
	workflow, err := NewProviderWorkflow(pool, discardAudit{}, allowProviderWrites{}, objects, provider, ProviderWorkflowConfig{
		TokenKey: make([]byte, 32), ResolverName: "trusted-kyc",
		KindEnabled: func(context.Context, string) (bool, error) { return false, nil }})
	if err != nil {
		t.Fatal(err)
	}
	workflow.kindEnabled = func(_ context.Context, kind string) (bool, error) { return enabled[kind], policyErr }

	off := ProviderMethodsView{Kinds: []string{}}
	if view, err := workflow.methods(t.Context()); err != nil || !reflect.DeepEqual(view, off) {
		t.Fatalf("unconfigured service: view=%+v err=%v", view, err)
	}

	provider.name = "trusted-kyc"
	view, err := workflow.methods(t.Context())
	if err != nil || !reflect.DeepEqual(view, ProviderMethodsView{Configured: true, ProviderDisplayName: "trusted-kyc",
		Kinds: []string{"personal_initial", "personal_reverification", "enterprise"}}) {
		t.Fatalf("configured service: view=%+v err=%v", view, err)
	}

	enabled["enterprise"] = false
	if view, err := workflow.methods(t.Context()); err != nil || !reflect.DeepEqual(view.Kinds, []string{"personal_initial", "personal_reverification"}) {
		t.Fatalf("enterprise turned off: view=%+v err=%v", view, err)
	}

	enabled["personal_initial"], enabled["personal_reverification"] = false, false
	if view, err := workflow.methods(t.Context()); err != nil || !reflect.DeepEqual(view, off) {
		t.Fatalf("every kind turned off: view=%+v err=%v", view, err)
	}

	policyErr = errors.New("settings unavailable")
	if _, err := workflow.methods(t.Context()); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("policy read failure err=%v", err)
	}

	if _, err := workflow.Methods(t.Context(), identityverification.Actor{}); !errors.Is(err, ErrProviderInvalid) {
		t.Fatalf("invalid actor err=%v", err)
	}
}

func TestProviderMethodsRoute(t *testing.T) {
	route, ok := resolveProviderRoute(apiPrefix + "/methods")
	if !ok || route.kind != providerRouteMethods || route.method != http.MethodGet || route.callback {
		t.Fatalf("route=%+v ok=%v", route, ok)
	}
	if _, ok := resolveProviderRoute(apiPrefix + "/methods/x"); ok {
		t.Fatal("a sub path of /methods resolved")
	}
	var cases, provider int
	dispatch := providerDispatchHandler{
		cases:    http.HandlerFunc(func(http.ResponseWriter, *http.Request) { cases++ }),
		provider: http.HandlerFunc(func(http.ResponseWriter, *http.Request) { provider++ }),
	}
	dispatch.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, apiPrefix+"/methods", nil))
	dispatch.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, apiPrefix+"/status", nil))
	if provider != 1 || cases != 1 {
		t.Fatalf("provider=%d cases=%d", provider, cases)
	}
}
