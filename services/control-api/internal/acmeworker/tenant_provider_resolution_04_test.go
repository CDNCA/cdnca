package acmeworker

import (
	"reflect"
	"testing"

	"github.com/google/uuid"
)

func TestTenantProviderResolution04RequestDigestAndLegacyFailClosed(t *testing.T) {
	tenantID := uuid.MustParse("10000000-0000-4000-8000-000000000001")
	scopeID := uuid.MustParse("20000000-0000-4000-8000-000000000001")
	providerID := uuid.MustParse("30000000-0000-4000-8000-000000000001")
	zoneID := uuid.MustParse("40000000-0000-4000-8000-000000000001")
	orderID := uuid.MustParse("50000000-0000-4000-8000-000000000001")
	request := IssueRequest{
		TenantID: tenantID, OperationID: orderID.String(), CertificateOrderID: orderID,
		ActorUserID: uuid.MustParse("60000000-0000-4000-8000-000000000001"),
		ProviderRef: providerID.String(), DirectoryURL: "https://acme.example/directory",
		AccountKeyRef: "account", CertificateKeyRef: "certificate",
		Contacts: []string{"mailto:ops@example.test"}, AcceptTerms: true,
		Domains: []string{"example.test"}, ChallengeType: ChallengeDNS01,
	}
	setUUIDField04(t, &request, "ScopeID", scopeID)
	setUUIDField04(t, &request, "ProviderID", providerID)
	setUUIDField04(t, &request, "ZoneID", zoneID)
	if !validFrozenIssueRequest(request) {
		t.Fatal("complete tenant/scope/provider/zone request rejected")
	}
	digest := issueRequestDigest(request)
	for _, field := range []string{"TenantID", "ScopeID", "ProviderID", "ZoneID"} {
		changed := request
		setUUIDField04(t, &changed, field, uuid.New())
		if issueRequestDigest(changed) == digest {
			t.Fatalf("%s is not bound by issue request digest", field)
		}
	}
	legacy := request
	setUUIDField04(t, &legacy, "ScopeID", uuid.Nil)
	setUUIDField04(t, &legacy, "ProviderID", uuid.Nil)
	setUUIDField04(t, &legacy, "ZoneID", uuid.Nil)
	if validFrozenIssueRequest(legacy) {
		t.Fatal("legacy DNS snapshot without frozen quartet was accepted")
	}

	httpRequest := request
	httpRequest.ProviderRef = ""
	httpRequest.ChallengeType = ChallengeHTTP01
	setUUIDField04(t, &httpRequest, "ProviderID", uuid.Nil)
	setUUIDField04(t, &httpRequest, "ZoneID", uuid.Nil)
	if !validFrozenIssueRequest(httpRequest) {
		t.Fatal("HTTP-01 request with tenant/scope and nil provider/zone rejected")
	}

	challenge := ChallengeIdentity{TenantID: tenantID}
	setUUIDField04(t, &challenge, "ScopeID", scopeID)
	setUUIDField04(t, &challenge, "ProviderID", providerID)
	setUUIDField04(t, &challenge, "ZoneID", zoneID)
	lease := OperationLease{TenantID: tenantID, Request: request}
	setUUIDField04(t, &lease, "ScopeID", scopeID)
}

func setUUIDField04(t *testing.T, target any, name string, value uuid.UUID) {
	t.Helper()
	field := reflect.ValueOf(target).Elem().FieldByName(name)
	if !field.IsValid() || !field.CanSet() || field.Type() != reflect.TypeOf(uuid.UUID{}) {
		t.Fatalf("%T is missing explicit uuid.UUID field %s", target, name)
	}
	field.Set(reflect.ValueOf(value))
}
