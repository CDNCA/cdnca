package certificateassethttp

import (
	"net/http"
	"testing"
)

func TestW3RootCertificateAssetHandlerAuthorizationMatrix(t *testing.T) {
	type routeContract struct {
		name       string
		method     string
		action     string
		methods    string
		permission string
		path       func(handlerFixture) string
		body       func(handlerFixture) string
		calls      func(*serviceStub) int
		status     int
	}
	routes := []routeContract{
		{name: "list", method: http.MethodGet, action: "list", methods: "GET, POST", permission: "certificates.read",
			path: func(handlerFixture) string { return "/v1/certificate-assets" }, calls: func(service *serviceStub) int { return service.listCalls }, status: http.StatusOK},
		{name: "upload", method: http.MethodPost, action: "upload", methods: "GET, POST", permission: "certificates.manage",
			path: func(handlerFixture) string { return "/v1/certificate-assets" },
			body: func(handlerFixture) string {
				return `{"name":"edge","certificate_pem":"PUBLIC-PEM","private_key_pem":"PRIVATE-PEM"}`
			},
			calls: func(service *serviceStub) int { return service.importCalls }, status: http.StatusCreated},
		{name: "get", method: http.MethodGet, action: "get", methods: "GET, DELETE", permission: "certificates.read",
			path: func(fixture handlerFixture) string { return "/v1/certificate-assets/" + fixture.assetID.String() }, calls: func(service *serviceStub) int { return service.getCalls }, status: http.StatusOK},
		{name: "get site binding", method: http.MethodGet, action: "get_site_binding", methods: "GET", permission: "certificates.read",
			path: func(fixture handlerFixture) string {
				return "/v1/sites/" + fixture.siteID.String() + "/certificate-binding"
			}, calls: func(service *serviceStub) int { return service.siteBindingCalls }, status: http.StatusOK},
		{name: "delete", method: http.MethodDelete, action: "delete", methods: "GET, DELETE", permission: "certificates.manage",
			path: func(fixture handlerFixture) string { return "/v1/certificate-assets/" + fixture.assetID.String() },
			body: func(handlerFixture) string { return `{"expected_revision":3}` }, calls: func(service *serviceStub) int { return service.deleteCalls }, status: http.StatusOK},
		{name: "activate", method: http.MethodPost, action: "activate", methods: "POST", permission: "certificates.manage",
			path: func(fixture handlerFixture) string {
				return "/v1/certificate-assets/" + fixture.assetID.String() + "/versions/" + fixture.versionID.String() + "/activate"
			}, body: func(handlerFixture) string { return `{"expected_revision":3}` }, calls: func(service *serviceStub) int { return service.activateCalls }, status: http.StatusOK},
		{name: "list bindings", method: http.MethodGet, action: "list_bindings", methods: "GET, POST", permission: "certificates.read",
			path: func(fixture handlerFixture) string {
				return "/v1/certificate-assets/" + fixture.assetID.String() + "/bindings"
			},
			calls: func(service *serviceStub) int { return service.bindingsCalls }, status: http.StatusOK},
		{name: "bind", method: http.MethodPost, action: "bind", methods: "GET, POST", permission: "certificates.manage",
			path: func(fixture handlerFixture) string {
				return "/v1/certificate-assets/" + fixture.assetID.String() + "/bindings"
			},
			body: func(fixture handlerFixture) string {
				return `{"site_id":"` + fixture.siteID.String() + `","version_id":"` + fixture.versionID.String() + `","expected_revision":0,"default":true}`
			}, calls: func(service *serviceStub) int { return service.bindCalls }, status: http.StatusOK},
		{name: "unbind", method: http.MethodDelete, action: "unbind", methods: "DELETE", permission: "certificates.manage",
			path: func(fixture handlerFixture) string {
				return "/v1/certificate-assets/" + fixture.assetID.String() + "/bindings/" + fixture.siteID.String()
			}, body: func(handlerFixture) string { return `{"expected_revision":1}` }, calls: func(service *serviceStub) int { return service.unbindCalls }, status: http.StatusOK},
	}

	for _, contract := range routes {
		t.Run(contract.name, func(t *testing.T) {
			fixture := newFixture()
			path := contract.path(fixture)
			matched, ok := matchRoute(path)
			if !ok || matched.methods != contract.methods || !methodAllowed(contract.method, matched.methods) ||
				matched.resolved(contract.method).action != contract.action {
				t.Fatalf("route=(%#v,%t) want action=%q methods=%q", matched, ok, contract.action, contract.methods)
			}

			wrongMethod := fixture.serve(fixture.handler(t, tenantSession(fixture.tenantID, contract.permission)),
				http.MethodPatch, path, "", nil)
			assertResponse(t, wrongMethod, http.StatusMethodNotAllowed, "certificate_asset_method_not_allowed")
			if wrongMethod.Header().Get("Allow") != contract.methods || certificateServiceCallCount(fixture.service) != 0 {
				t.Fatalf("wrong method allow/calls=%q/%d", wrongMethod.Header().Get("Allow"), certificateServiceCallCount(fixture.service))
			}

			oppositePermission := "certificates.read"
			if contract.permission == oppositePermission {
				oppositePermission = "certificates.manage"
			}
			denied := fixture.serve(fixture.handler(t, tenantSession(fixture.tenantID, oppositePermission)),
				contract.method, path, "", nil)
			assertResponse(t, denied, http.StatusForbidden, "certificate_asset_permission_denied")
			if certificateServiceCallCount(fixture.service) != 0 {
				t.Fatalf("permission denial reached service %d times", certificateServiceCallCount(fixture.service))
			}

			platformDenied := fixture.serve(fixture.handler(t, platformSession("platform.admin")), contract.method,
				path+"?target_scope_id="+fixture.tenantID.String(), "", nil)
			assertResponse(t, platformDenied, http.StatusForbidden, "certificate_asset_permission_denied")
			if certificateServiceCallCount(fixture.service) != 0 {
				t.Fatalf("platform.admin denial reached service %d times", certificateServiceCallCount(fixture.service))
			}

			body := ""
			headers := http.Header(nil)
			if contract.body != nil {
				body, headers = contract.body(fixture), writeHeaders()
			}
			allowed := fixture.serve(fixture.handler(t, tenantSession(fixture.tenantID, contract.permission)),
				contract.method, path, body, headers)
			assertResponse(t, allowed, contract.status, "")
			if contract.calls(fixture.service) != 1 || certificateServiceCallCount(fixture.service) != 1 {
				t.Fatalf("allowed action calls=%d total=%d", contract.calls(fixture.service), certificateServiceCallCount(fixture.service))
			}
		})
	}
}

func certificateServiceCallCount(service *serviceStub) int {
	return service.listCalls + service.getCalls + service.siteBindingCalls + service.importCalls + service.activateCalls +
		service.bindingsCalls + service.bindCalls + service.unbindCalls + service.deleteCalls
}
