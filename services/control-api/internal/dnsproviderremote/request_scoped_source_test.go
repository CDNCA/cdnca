package dnsproviderremote

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"testing"

	"github.com/google/uuid"
)

func TestSourceContractRequiresRequestScopedResolve(t *testing.T) {
	lookupType := reflect.TypeOf(ProviderLookup{})
	operationField, ok := lookupType.FieldByName("OperationID")
	if !ok || operationField.Type.Kind() != reflect.String {
		t.Fatal("ProviderLookup must bind the frozen ACME operation ID")
	}
	sourceType := reflect.TypeOf((*Source)(nil)).Elem()
	method, ok := sourceType.MethodByName("Resolve")
	if !ok {
		t.Fatal("Source must require request-scoped Resolve")
	}
	if method.Type.NumIn() != 2 || method.Type.In(1) != reflect.TypeOf(ProviderLookup{}) ||
		method.Type.NumOut() != 2 || method.Type.Out(0) != reflect.TypeOf(ProviderConfig{}) ||
		!method.Type.Out(1).Implements(reflect.TypeOf((*error)(nil)).Elem()) {
		t.Fatalf("Source.Resolve has unexpected signature %v", method.Type)
	}
}

func TestAdapterResolvesEveryRequestByFrozenAuthority(t *testing.T) {
	tenantA, tenantB := uuid.New(), uuid.New()
	scopeA, scopeB := uuid.New(), uuid.New()
	providerA, providerB := uuid.New(), uuid.New()
	zoneA, zoneB := uuid.New(), uuid.New()
	source := &requestScopedTestSource{configs: map[uuid.UUID]ProviderConfig{
		providerA: {
			TenantID: tenantA, ScopeID: scopeA, TenantScopeID: scopeA,
			ProviderID: providerA, ProviderType: providerCloudflare,
			ZoneID: zoneA, ZoneName: "a.example.test",
			Credentials: map[string]string{"api_token": "tenant-a-token"},
		},
		providerB: {
			TenantID: tenantB, ScopeID: scopeB, TenantScopeID: scopeB,
			ProviderID: providerB, ProviderType: providerCloudflare,
			ZoneID: zoneB, ZoneName: "b.example.test",
			Credentials: map[string]string{"api_token": "tenant-b-token"},
		},
	}}
	keyring, err := NewHandleKeyring(HandleKey{ID: "active", Secret: make([]byte, 32)})
	if err != nil {
		t.Fatal(err)
	}
	adapter := newAdapter(source, keyring, nil, productionEndpoints(), requestTimeout, nil, nil)
	lookups := []ProviderLookup{
		{
			OperationID: uuid.NewString(),
			TenantID:    tenantA, ScopeID: scopeA, TenantScopeID: scopeA,
			ProviderID: providerA, ZoneID: zoneA, OwnerName: "_acme-challenge.a.example.test.",
		},
		{
			OperationID: uuid.NewString(),
			TenantID:    tenantB, ScopeID: scopeB, TenantScopeID: scopeB,
			ProviderID: providerB, ZoneID: zoneB, OwnerName: "_acme-challenge.b.example.test.",
		},
	}
	for index, lookup := range lookups {
		config, _, resolveErr := adapter.resolve(t.Context(), lookup)
		if resolveErr != nil {
			t.Fatalf("resolve request %d: %v", index, resolveErr)
		}
		if config.TenantID != lookup.TenantID || config.ScopeID != lookup.ScopeID ||
			config.ProviderID != lookup.ProviderID || config.ZoneID != lookup.ZoneID {
			t.Fatalf("request %d resolved foreign authority: %+v", index, config)
		}
		clearProviderConfig(&config)
	}
	if len(source.lookups) != len(lookups) || source.lookups[0] != lookups[0] || source.lookups[1] != lookups[1] {
		t.Fatalf("Resolve lookups = %+v, want %+v", source.lookups, lookups)
	}

	malformed := lookups[1]
	malformed.ProviderID = uuid.New()
	malformedConfig := source.configs[providerB]
	malformedConfig.ProviderID = malformed.ProviderID
	malformedConfig.Credentials = map[string]string{
		"api_token": "tenant-b-token",
		"extra":     "must-not-reach-provider",
	}
	source.configs[malformed.ProviderID] = malformedConfig
	if _, _, err := adapter.resolve(t.Context(), malformed); ErrorCodeOf(err) != CodeInvalidInput {
		t.Fatalf("extra credential field error = %v, want %s", err, CodeInvalidInput)
	}
}

func TestEveryAdapterProviderLookupBindsRequestOperation(t *testing.T) {
	parsed, err := parser.ParseFile(token.NewFileSet(), "adapter.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	lookups := 0
	ast.Inspect(parsed, func(node ast.Node) bool {
		literal, ok := node.(*ast.CompositeLit)
		if !ok {
			return true
		}
		name, ok := literal.Type.(*ast.Ident)
		if !ok || name.Name != "ProviderLookup" {
			return true
		}
		lookups++
		for _, element := range literal.Elts {
			field, ok := element.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := field.Key.(*ast.Ident)
			if !ok || key.Name != "OperationID" {
				continue
			}
			requestSpecific := false
			ast.Inspect(field.Value, func(value ast.Node) bool {
				selector, ok := value.(*ast.SelectorExpr)
				if ok && selector.Sel.Name == "OperationID" {
					requestSpecific = true
				}
				return true
			})
			if requestSpecific {
				return true
			}
		}
		t.Errorf("ProviderLookup at adapter.go:%d does not bind the request OperationID", literal.Pos())
		return true
	})
	if lookups == 0 {
		t.Fatal("adapter.go contains no ProviderLookup construction")
	}
}

type requestScopedTestSource struct {
	configs map[uuid.UUID]ProviderConfig
	lookups []ProviderLookup
}

func (s *requestScopedTestSource) Resolve(_ context.Context, lookup ProviderLookup) (ProviderConfig, error) {
	s.lookups = append(s.lookups, lookup)
	config := s.configs[lookup.ProviderID]
	config.Credentials = cloneCredentialMap(config.Credentials)
	return config, nil
}

func cloneCredentialMap(source map[string]string) map[string]string {
	cloned := make(map[string]string, len(source))
	for key, value := range source {
		cloned[key] = value
	}
	return cloned
}
