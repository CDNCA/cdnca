package dnsproviderremotesource

import (
	"os"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/google/uuid"
)

func TestTenantProviderResolution04SourceValidatesBeforeDecrypt(t *testing.T) {
	lookup := dnsproviderremote.ProviderLookup{}
	for _, field := range []string{"TenantID", "ScopeID", "ProviderID", "ZoneID"} {
		value := reflect.ValueOf(&lookup).Elem().FieldByName(field)
		if !value.IsValid() || !value.CanSet() || value.Type() != reflect.TypeOf(uuid.UUID{}) {
			t.Fatalf("ProviderLookup is missing explicit uuid.UUID field %s", field)
		}
		value.Set(reflect.ValueOf(uuid.New()))
	}

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	raw, err := os.ReadFile(strings.TrimSuffix(file, "tenant_provider_resolution_04_test.go") + "source.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	for _, required := range []string{
		"pgx.BeginFunc", "tenant.id", "lookup.TenantID", "lookup.ScopeID",
		"lookup.ZoneID", "credential_version", "credential_revoked", "FOR SHARE",
		"request_snapshot ->> 'TenantID'", "request_snapshot ->> 'ScopeID'",
		"request_snapshot ->> 'ProviderID'", "request_snapshot ->> 'ZoneID'",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("production Source lacks pre-decrypt authority check %q", required)
		}
	}
	validation := strings.Index(source, "tenantStatus != \"active\"")
	decrypt := strings.Index(source, ".Decrypt(")
	if validation < 0 || decrypt < 0 || validation > decrypt {
		t.Fatal("credential decrypt is not ordered after tenant/provider/zone validation")
	}
}
