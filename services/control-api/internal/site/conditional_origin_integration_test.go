package site

import (
	"errors"
	"reflect"
	"testing"
)

func TestNormalizeConditionalOriginDocumentDeterministicOrder(t *testing.T) {
	document := validConditionalOriginDocument()
	normalized, err := NormalizeConditionalOriginDocument(document)
	if err != nil {
		t.Fatalf("NormalizeConditionalOriginDocument() error = %v", err)
	}
	if got, want := []string{normalized.Pools[0].ID, normalized.Pools[1].ID}, []string{"backup", "primary"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("pool order = %v, want %v", got, want)
	}
	gotRoutes := make([]string, len(normalized.Routes))
	for index := range normalized.Routes {
		gotRoutes[index] = normalized.Routes[index].ID
	}
	if want := []string{"priority", "long-path", "region", "cidr-long", "id-a", "id-b"}; !reflect.DeepEqual(gotRoutes, want) {
		t.Fatalf("route order = %v, want %v", gotRoutes, want)
	}
	if want := []string{"GET", "HEAD"}; !reflect.DeepEqual(normalized.Retry.Methods, want) {
		t.Fatalf("retry methods = %v, want %v", normalized.Retry.Methods, want)
	}
	if !normalized.IngressSourceEnabled {
		t.Fatal("ingress-source origin setting was lost during normalization")
	}
}

func TestNormalizeConditionalOriginDocumentAcceptsCanonicalDNSOrigins(t *testing.T) {
	document := validConditionalOriginDocument()
	document.Pools[1].Endpoints[0].Host = "Origin.Example.COM."
	normalized, err := NormalizeConditionalOriginDocument(document)
	if err != nil {
		t.Fatalf("NormalizeConditionalOriginDocument() error = %v", err)
	}
	if got, want := normalized.Pools[0].Endpoints[0].Host, "origin.example.com"; got != want {
		t.Fatalf("normalized DNS origin = %q, want %q", got, want)
	}
}

func TestNormalizeConditionalOriginDocumentRejectsUnsafeContracts(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*ConditionalOriginDocument)
	}{
		{"wrong schema", func(value *ConditionalOriginDocument) { value.Schema = "cdnca.edge.origin-route/v2" }},
		{"no pools", func(value *ConditionalOriginDocument) { value.Pools = nil }},
		{"too many pools", func(value *ConditionalOriginDocument) {
			value.Pools = append(value.Pools, make([]ConditionalOriginPool, 63)...)
		}},
		{"no endpoints", func(value *ConditionalOriginDocument) { value.Pools[0].Endpoints = nil }},
		{"unknown default", func(value *ConditionalOriginDocument) { value.DefaultPoolID = "missing" }},
		{"conditionless route", func(value *ConditionalOriginDocument) { value.Routes[0].PathPrefix = "" }},
		{"unknown route pool", func(value *ConditionalOriginDocument) { value.Routes[0].PoolID = "missing" }},
		{"same fallback", func(value *ConditionalOriginDocument) { value.Routes[0].FallbackPoolID = value.Routes[0].PoolID }},
		{"unsafe cidr", func(value *ConditionalOriginDocument) { value.Routes[0].ClientCIDRs = []string{"224.0.0.0/4"} }},
		{"localhost origin", func(value *ConditionalOriginDocument) { value.Pools[0].Endpoints[0].Host = "localhost" }},
		{"reverse DNS origin", func(value *ConditionalOriginDocument) { value.Pools[0].Endpoints[0].Host = "10.in-addr.arpa" }},
		{"unqualified DNS origin", func(value *ConditionalOriginDocument) { value.Pools[0].Endpoints[0].Host = "origin" }},
		{"padded DNS origin", func(value *ConditionalOriginDocument) { value.Pools[0].Endpoints[0].Host = " origin.example.com" }},
		{"numeric DNS suffix", func(value *ConditionalOriginDocument) { value.Pools[0].Endpoints[0].Host = "origin.123" }},
		{"post retry", func(value *ConditionalOriginDocument) { value.Retry.Methods = []string{"POST"} }},
		{"attempt zero", func(value *ConditionalOriginDocument) { value.Retry.MaxAttempts = 0 }},
		{"attempt nine", func(value *ConditionalOriginDocument) { value.Retry.MaxAttempts = 9 }},
		{"budget too small", func(value *ConditionalOriginDocument) { value.Retry.TotalBudgetMS = 100 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := validConditionalOriginDocument()
			test.mutate(&value)
			if _, err := NormalizeConditionalOriginDocument(value); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("error = %v, want ErrInvalidInput", err)
			}
		})
	}
}

func validConditionalOriginDocument() ConditionalOriginDocument {
	return ConditionalOriginDocument{
		Schema:               ConditionalOriginSchemaV1,
		IngressSourceEnabled: true,
		Pools: []ConditionalOriginPool{
			{ID: "primary", Endpoints: []ConditionalOriginEndpoint{{ID: "p2", Host: "192.0.2.11", Port: 80, Weight: 20}, {ID: "p1", Host: "192.0.2.10", Port: 80, Weight: 10}}},
			{ID: "backup", Endpoints: []ConditionalOriginEndpoint{{ID: "b1", Host: "198.51.100.10", Port: 8080, Weight: 1}}},
		},
		DefaultPoolID: "primary",
		Routes: []ConditionalOriginRoute{
			{ID: "id-b", Priority: 0, PathPrefix: "/", PoolID: "primary"},
			{ID: "cidr-long", Priority: 0, ClientCIDRs: []string{"203.0.113.0/25"}, PoolID: "primary"},
			{ID: "long-path", Priority: 0, PathPrefix: "/assets/private", PoolID: "primary"},
			{ID: "priority", Priority: 1, PathPrefix: "/", PoolID: "primary"},
			{ID: "region", Priority: 0, NodeRegions: []string{"CN-EAST"}, PoolID: "backup", FallbackPoolID: "primary"},
			{ID: "id-a", Priority: 0, PathPrefix: "/", PoolID: "primary"},
		},
		Retry: ConditionalOriginRetry{Methods: []string{"head", "get"}, MaxAttempts: 3, ConnectTimeoutMS: 500, ReadTimeoutMS: 1500, TotalBudgetMS: 5000},
	}
}
