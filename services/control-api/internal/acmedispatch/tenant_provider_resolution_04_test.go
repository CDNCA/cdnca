package acmedispatch

import (
	"reflect"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/acmeworker"
	"github.com/google/uuid"
)

func TestTenantProviderResolution04CertificateLeaseSeparatesTenantAndScope(t *testing.T) {
	tenantID := uuid.MustParse("10000000-0000-4000-8000-000000000001")
	scopeID := uuid.MustParse("20000000-0000-4000-8000-000000000001")
	lease := acmeworker.OperationLease{
		TenantID: tenantID,
		Request:  acmeworker.IssueRequest{TenantID: tenantID},
	}
	setDispatchUUIDField04(t, &lease, "ScopeID", scopeID)
	setDispatchUUIDField04(t, &lease.Request, "ScopeID", scopeID)
	same := lease
	if !sameLease(lease, same) {
		t.Fatal("identical tenant/scope lease rejected")
	}
	setDispatchUUIDField04(t, &same, "ScopeID", uuid.New())
	if sameLease(lease, same) {
		t.Fatal("certificate store lease fence ignores access scope")
	}
	same = lease
	setDispatchUUIDField04(t, &same.Request, "ScopeID", uuid.New())
	if sameLease(lease, same) {
		t.Fatal("certificate store request identity ignores access scope")
	}
}

func setDispatchUUIDField04(t *testing.T, target any, name string, value uuid.UUID) {
	t.Helper()
	field := reflect.ValueOf(target).Elem().FieldByName(name)
	if !field.IsValid() || !field.CanSet() || field.Type() != reflect.TypeOf(uuid.UUID{}) {
		t.Fatalf("%T is missing explicit uuid.UUID field %s", target, name)
	}
	field.Set(reflect.ValueOf(value))
}
