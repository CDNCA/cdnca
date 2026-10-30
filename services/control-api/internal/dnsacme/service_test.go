package dnsacme

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestNormalizeRecordByType(t *testing.T) {
	tests := []struct {
		name, recordType, content string
		valid                     bool
	}{
		{"www", "A", "192.0.2.10", true},
		{"www", "A", "2001:db8::1", false},
		{"www", "AAAA", "2001:db8::1", true},
		{"www", "CNAME", "TARGET.EXAMPLE.", true},
		{"_acme-challenge", "TXT", "proof-value", true},
		{"bad name", "TXT", "proof-value", false},
		{"www", "MX", "mail.example", false},
	}
	for _, test := range tests {
		name, recordType, content := test.name, test.recordType, test.content
		err := normalizeRecord(&name, &recordType, &content, 300)
		if (err == nil) != test.valid {
			t.Errorf("normalizeRecord(%q, %q, %q) error = %v", test.name, test.recordType, test.content, err)
		}
	}
}

func TestNormalizeProviderCredentialsDNSLAExactSchema(t *testing.T) {
	encoded, err := normalizeProviderCredentials("dns_la", map[string]string{
		"api_id": "dnsla-id", "api_secret": "dnsla-secret",
	})
	if err != nil || !bytes.Equal(encoded, []byte(`{"api_id":"dnsla-id","api_secret":"dnsla-secret"}`)) {
		t.Fatalf("normalizeProviderCredentials() = %s, %v", encoded, err)
	}
	invalid := []map[string]string{
		{"api_id": "dnsla-id"},
		{"api_secret": "dnsla-secret"},
		{"api_id": "dnsla-id", "api_secret": "dnsla-secret", "extra": "rejected"},
		{"api_id": "dnsla:id", "api_secret": "dnsla-secret"},
	}
	for _, credentials := range invalid {
		if _, err := normalizeProviderCredentials("dns_la", credentials); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("normalizeProviderCredentials(%v) error = %v", credentials, err)
		}
	}
	if _, err := normalizeProviderCredentials("cloudflare", map[string]string{
		"api_token": "stored-for-verification", "extra": "rejected",
	}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("non-DNS.LA credential normalization accepted an extra field: %v", err)
	}
}

func TestNormalizeDomainsAndChallengeRules(t *testing.T) {
	domains, wildcard, err := normalizeDomains([]string{"WWW.Example.COM.", "*.example.com"})
	if err != nil || !wildcard || len(domains) != 2 || domains[0] != "*.example.com" {
		t.Fatalf("normalizeDomains() = (%v, %t, %v)", domains, wildcard, err)
	}
	if _, _, err := normalizeDomains([]string{"example.com", "EXAMPLE.COM"}); err == nil {
		t.Fatal("normalizeDomains() accepted duplicates")
	}
	if _, _, err := normalizeDomains([]string{"https://example.com"}); err == nil {
		t.Fatal("normalizeDomains() accepted a URL")
	}
}

func TestNormalizeDomainsWildcardPublicSuffixAndCreateValidation(t *testing.T) {
	tests := []struct {
		name         string
		input        []string
		wantDomains  []string
		wantWildcard bool
		wantErr      bool
	}{
		{name: "reject com wildcard", input: []string{"*.com"}, wantErr: true},
		{name: "reject co uk public suffix wildcard", input: []string{"*.co.uk"}, wantErr: true},
		{name: "reject com apex", input: []string{"com"}, wantErr: true},
		{name: "reject co uk apex", input: []string{"co.uk"}, wantErr: true},
		{name: "accept com registered domain", input: []string{"example.com"}, wantDomains: []string{"example.com"}},
		{name: "accept co uk registered domain", input: []string{"example.co.uk"}, wantDomains: []string{"example.co.uk"}},
		{
			name:         "accept registered domain wildcard",
			input:        []string{"example.co.uk", "*.example.co.uk", "www.example.com"},
			wantDomains:  []string{"*.example.co.uk", "example.co.uk", "www.example.com"},
			wantWildcard: true,
		},
		{
			name:         "accept nested wildcard and apex",
			input:        []string{"*.foo.example.com", "example.com"},
			wantDomains:  []string{"*.foo.example.com", "example.com"},
			wantWildcard: true,
		},
		{name: "reject normalized duplicate", input: []string{"example.co.uk", "EXAMPLE.CO.UK."}, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			domains, wildcard, err := normalizeDomains(test.input)
			if test.wantErr {
				if err == nil {
					t.Fatalf("normalizeDomains(%v) accepted invalid input: domains=%v wildcard=%t", test.input, domains, wildcard)
				}
				return
			}
			if err != nil || wildcard != test.wantWildcard || !equalStrings(domains, test.wantDomains) {
				t.Fatalf("normalizeDomains(%v) = (%v, %t, %v), want (%v, %t, nil)", test.input, domains, wildcard, err, test.wantDomains, test.wantWildcard)
			}
		})
	}

	actor := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant"}
	providerID := uuid.New()
	for _, domain := range []string{"*.com", "*.co.uk", "com", "co.uk"} {
		t.Run("CreateOrder rejects "+domain, func(t *testing.T) {
			service := NewService(NewStore(nil), nil)
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("CreateOrder reached nil store for invalid domain %q: %v", domain, recovered)
				}
			}()
			if _, err := service.CreateOrder(context.Background(), actor, CreateOrderRequest{
				Domains:        []string{domain},
				DNSProviderID:  &providerID,
				ChallengeType:  "dns-01",
				IdempotencyKey: "public-suffix-validation-" + domain,
				RequestID:      "public-suffix-validation-request-" + domain,
			}); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("CreateOrder(%q) error = %v, want %v before store access", domain, err, ErrInvalidInput)
			}
		})
	}
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func TestLegacyOrderMutationEndpointsFailClosed(t *testing.T) {
	actor := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform"}
	service := NewService(NewStore(nil), nil)
	if _, err := service.TransitionOrder(context.Background(), actor, TransitionOrderRequest{}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("TransitionOrder() error = %v, want %v", err, ErrPermissionDenied)
	}
	if _, err := service.CreateRenewal(context.Background(), actor, CreateRenewalRequest{}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("CreateRenewal() error = %v, want %v", err, ErrPermissionDenied)
	}
	store := NewStore(nil)
	if _, err := store.TransitionOrder(context.Background(), actor, TransitionOrderRequest{}, [32]byte{}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("Store.TransitionOrder() error = %v, want %v", err, ErrPermissionDenied)
	}
	if _, err := store.CreateRenewal(context.Background(), actor, CreateRenewalRequest{}, [32]byte{}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("Store.CreateRenewal() error = %v, want %v", err, ErrPermissionDenied)
	}
}
