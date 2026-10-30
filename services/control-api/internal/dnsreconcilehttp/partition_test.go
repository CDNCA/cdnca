package dnsreconcilehttp

import (
	"context"
	"net/http"
	"testing"
)

func TestTenantAndProviderHandlersHaveDisjointRouteSurfaces(t *testing.T) {
	handler, err := NewHandler(Dependencies{
		Sessions: sessionAuthenticatorFunc(func(_ context.Context, _ string) (Principal, error) { return Principal{}, ErrUnauthenticated }),
		IAM:      iamAuthorizerFunc(func(context.Context, AuthorizationRequest) error { return nil }),
		Domain:   &fakeDomain{},
		Workloads: workloadAuthenticatorFunc(func(*http.Request) (WorkloadPrincipal, error) {
			return WorkloadPrincipal{}, ErrWorkloadUnauthenticated
		}),
	}, Config{})
	if err != nil {
		t.Fatal(err)
	}
	tenant := NewTenantHandler(handler)
	provider := NewProviderReportHandler(handler)
	siteID := "11111111-1111-4111-8111-111111111111"
	taskID := "22222222-2222-4222-8222-222222222222"
	tenantPath := "/v1/sites/" + siteID + "/dns-reconcile/tasks/" + taskID
	providerPath := "/internal/v1/dns/reconcile/tasks/" + taskID + "/provider-reports"

	if response := serve(tenant, http.MethodPost, providerPath, "{}", nil, mutationHeaders()); response.Code != http.StatusNotFound {
		t.Fatalf("tenant handler exposed provider route: status=%d body=%s", response.Code, response.Body.String())
	}
	if response := serve(provider, http.MethodGet, tenantPath, "", nil, readHeaders()); response.Code != http.StatusNotFound {
		t.Fatalf("provider handler exposed tenant route: status=%d body=%s", response.Code, response.Body.String())
	}
}
