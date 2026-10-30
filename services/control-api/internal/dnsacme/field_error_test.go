package dnsacme

import (
	"errors"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
	"github.com/google/uuid"
)

func assertDNSField(t *testing.T, err error, field, reason string) {
	t.Helper()
	located, ok := fielderr.As(err)
	if !errors.Is(err, ErrInvalidInput) || !ok || located.Field != field || located.Reason != reason {
		t.Fatalf("error = %v, want %s/%s", err, field, reason)
	}
}

// fix-fielderr-be: DNS account, zone, record and certificate order refusals
// name the request field; checks before the store need no database.
func TestDNSACMERefusalsLocateField(t *testing.T) {
	service := &Service{}
	tenant := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant"}
	providerID := uuid.New()
	t.Run("provider", func(t *testing.T) {
		for name, check := range map[string]struct {
			request       CreateProviderRequest
			field, reason string
		}{
			"empty name":  {CreateProviderRequest{ProviderType: "cloudflare"}, "name", fielderr.Required},
			"long name":   {CreateProviderRequest{Name: strings.Repeat("x", 129), ProviderType: "cloudflare"}, "name", fielderr.TooLong},
			"long remark": {CreateProviderRequest{Name: "a", Remark: strings.Repeat("x", 257), ProviderType: "cloudflare"}, "remark", fielderr.TooLong},
			"bad type":    {CreateProviderRequest{Name: "a", ProviderType: "bogus"}, "provider_type", fielderr.Invalid},
			"credentials": {CreateProviderRequest{Name: "a", ProviderType: "cloudflare", Credentials: map[string]string{"x": "y"}}, "credentials", fielderr.Invalid},
		} {
			check.request.IdempotencyKey, check.request.RequestID = "k", "r"
			_, err := service.CreateProvider(t.Context(), tenant, check.request)
			if err == nil {
				t.Fatalf("%s accepted", name)
			}
			assertDNSField(t, err, check.field, check.reason)
		}
		_, err := service.UpdateProvider(t.Context(), tenant, UpdateProviderRequest{ID: uuid.New(), ExpectedRevision: 1,
			Name: "a", Status: "bogus", IdempotencyKey: "k", RequestID: "r"})
		assertDNSField(t, err, "status", fielderr.Invalid)
	})
	t.Run("zone", func(t *testing.T) {
		_, err := service.CreateZone(t.Context(), tenant, CreateZoneRequest{ProviderID: providerID, Name: "bad_name", IdempotencyKey: "k", RequestID: "r"})
		assertDNSField(t, err, "name", fielderr.InvalidFormat)
		_, err = service.CreateZone(t.Context(), tenant, CreateZoneRequest{Name: "example.com", IdempotencyKey: "k", RequestID: "r"})
		assertDNSField(t, err, "provider_id", fielderr.Required)
	})
	t.Run("record", func(t *testing.T) {
		for name, check := range map[string]struct {
			record        CreateRecordRequest
			field, reason string
		}{
			"ttl":       {CreateRecordRequest{Name: "www", Type: "A", Content: "198.51.100.1", TTL: 10}, "ttl", fielderr.OutOfRange},
			"name":      {CreateRecordRequest{Name: "a b", Type: "A", Content: "198.51.100.1", TTL: 600}, "name", fielderr.InvalidFormat},
			"type":      {CreateRecordRequest{Name: "www", Type: "MX", Content: "x", TTL: 600}, "type", fielderr.Invalid},
			"a content": {CreateRecordRequest{Name: "www", Type: "A", Content: "2001:db8::1", TTL: 600}, "content", fielderr.InvalidFormat},
			"cname":     {CreateRecordRequest{Name: "www", Type: "CNAME", Content: "bad_host", TTL: 600}, "content", fielderr.InvalidFormat},
			"txt empty": {CreateRecordRequest{Name: "www", Type: "TXT", Content: " ", TTL: 600}, "content", fielderr.Required},
		} {
			check.record.ZoneID, check.record.IdempotencyKey, check.record.RequestID = uuid.New(), "k", "r"
			_, err := service.CreateRecord(t.Context(), tenant, check.record)
			if err == nil {
				t.Fatalf("%s accepted", name)
			}
			assertDNSField(t, err, check.field, check.reason)
		}
	})
	t.Run("order", func(t *testing.T) {
		for name, check := range map[string]struct {
			order         CreateOrderRequest
			field, reason string
		}{
			"challenge":        {CreateOrderRequest{ChallengeType: "tls-alpn-01", Domains: []string{"a.example.com"}}, "challenge_type", fielderr.Invalid},
			"no domains":       {CreateOrderRequest{ChallengeType: "http-01"}, "domains", fielderr.Required},
			"bad domain":       {CreateOrderRequest{ChallengeType: "http-01", Domains: []string{"a.example.com", "bad_domain"}}, "domains[1]", fielderr.InvalidFormat},
			"duplicate domain": {CreateOrderRequest{ChallengeType: "http-01", Domains: []string{"a.example.com", "A.example.com"}}, "domains[1]", fielderr.Duplicate},
			"wildcard http":    {CreateOrderRequest{ChallengeType: "http-01", Domains: []string{"*.example.com"}}, "challenge_type", fielderr.Invalid},
			"dns no provider":  {CreateOrderRequest{ChallengeType: "dns-01", Domains: []string{"a.example.com"}}, "dns_provider_id", fielderr.Required},
			"issuer":           {CreateOrderRequest{ChallengeType: "http-01", Domains: []string{"a.example.com"}, Issuer: "bogus"}, "issuer", fielderr.Invalid},
			"long remark":      {CreateOrderRequest{ChallengeType: "http-01", Domains: []string{"a.example.com"}, Remark: strings.Repeat("x", 257)}, "remark", fielderr.TooLong},
		} {
			check.order.IdempotencyKey, check.order.RequestID = "k", "r"
			_, err := service.CreateOrder(t.Context(), tenant, check.order)
			if err == nil {
				t.Fatalf("%s accepted", name)
			}
			assertDNSField(t, err, check.field, check.reason)
		}
	})
}

// fix-fielderr-be3: 平台 DNS 配置 (PUT /v1/dns/platform-config) names
// provider_type, ttl and credentials.
func TestPlatformConfigRefusalsLocateField(t *testing.T) {
	service := &Service{}
	admin := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform"}
	valid := SavePlatformConfigRequest{ProviderType: "cloudflare", TTL: 600, ExpectedRevision: 1, IdempotencyKey: "key-1", RequestID: "r"}
	for name, check := range map[string]struct {
		change        func(*SavePlatformConfigRequest)
		field, reason string
	}{
		"provider":    {func(r *SavePlatformConfigRequest) { r.ProviderType = "nope" }, "provider_type", fielderr.Invalid},
		"ttl low":     {func(r *SavePlatformConfigRequest) { r.TTL = 1 }, "ttl", fielderr.OutOfRange},
		"ttl high":    {func(r *SavePlatformConfigRequest) { r.TTL = PlatformMaxTTL + 1 }, "ttl", fielderr.OutOfRange},
		"credentials": {func(r *SavePlatformConfigRequest) { r.Credentials = map[string]string{"x": "y"} }, "credentials", fielderr.Invalid},
	} {
		t.Run(name, func(t *testing.T) {
			request := valid
			check.change(&request)
			_, err := service.SavePlatformConfig(t.Context(), admin, request)
			assertDNSField(t, err, check.field, check.reason)
		})
	}
}
