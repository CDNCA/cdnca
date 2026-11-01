package dnsacme

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// DNS-SEC-20261027-01：平台 DNS 副本以 managed_by 为准，迁移 569 前同步的副本按确定 id 也算。
func TestIsPlatformManagedProvider(t *testing.T) {
	scope := uuid.New()
	copyID := PlatformProviderCopyID(scope)
	own := uuid.New()
	for name, test := range map[string]struct {
		managedBy string
		id        uuid.UUID
		want      bool
	}{
		"own account":            {ProviderManagedByTenant, own, false},
		"marked platform":        {ProviderManagedByPlatform, own, true},
		"copy id before 569":     {ProviderManagedByTenant, copyID, true},
		"copy id of other scope": {ProviderManagedByTenant, PlatformProviderCopyID(uuid.New()), false},
	} {
		if got := IsPlatformManagedProvider(test.managedBy, scope, test.id); got != test.want {
			t.Errorf("%s: got %v want %v", name, got, test.want)
		}
	}
}

// 租户能用平台副本的入口都必须在调用服务商/写库之前拒绝：新增解析区（查托管根域前）、
// 下单（权益检查、写订单前）、编辑/删除/验证（平台同步维护）。
func TestPlatformManagedProviderGuardsPrecedeUse(t *testing.T) {
	read := func(name string) string {
		body, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	block := func(text, start, end string) string {
		from := strings.Index(text, start)
		if from < 0 {
			t.Fatalf("%q not found", start)
		}
		to := strings.Index(text[from:], end)
		if to < 0 {
			t.Fatalf("%q not found after %q", end, start)
		}
		return text[from : from+to]
	}
	before := func(t *testing.T, text, guard, use string) {
		t.Helper()
		guardAt, useAt := strings.Index(text, guard), strings.Index(text, use)
		if guardAt < 0 || useAt < 0 || guardAt > useAt {
			t.Fatalf("%q must precede %q", guard, use)
		}
	}
	service, store := read("service.go"), read("store.go")
	zone := block(service, "func (s *Service) CreateZone(", "func (s *Service) ListZones(")
	before(t, zone, "refusePlatformManagedUse(", "s.store.zoneProviderCredentials(")
	order := block(store, "func (s *Store) CreateOrder(", "func refuseOrderInFlight(")
	before(t, order, "refusePlatformManagedUse(", "s.checkCreateOrderEntitlement(")
	before(t, order, "refusePlatformManagedUse(", "INSERT INTO certificate_orders")
	update := block(service, "func (s *Service) UpdateProvider(", "func (s *Service) ListProviders(")
	before(t, update, "platformManagedRefusal(", "EncryptCredential(")
	remove := block(service, "func (s *Service) DeleteProvider(", "func (s *Service) CreateZone(")
	before(t, remove, "platformManagedRefusal(", "s.store.DeleteProvider(")
	verify := block(store, "func (s *Store) PrepareProviderVerification(", "func (s *Store) CompleteProviderVerification(")
	before(t, verify, "platformManagedRefusal(", "return target, nil, nil")
}

// 租户看不到平台副本——对它的改/删/验证与不存在一致（404），
// 平台侧仍是 409 dns_provider_platform_managed。
func TestPlatformManagedRefusalHidesCopyFromTenant(t *testing.T) {
	if err := platformManagedRefusal(Actor{ScopeKind: "tenant"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("tenant: %v, want ErrNotFound", err)
	}
	if err := platformManagedRefusal(Actor{ScopeKind: "platform"}); !errors.Is(err, ErrPlatformManagedProvider) {
		t.Fatalf("platform: %v, want ErrPlatformManagedProvider", err)
	}
}

// 租户 DNS 账户列表在 SQL 里排除平台副本（managed_by 与 569 前的确定 id 两种标记），平台视图不过滤；
// 改/删/验证的平台副本拒绝都走 platformManagedRefusal。
func TestTenantProviderListExcludesPlatformCopy(t *testing.T) {
	body, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatal(err)
	}
	store := string(body)
	from := strings.Index(store, "func (s *Store) ListProviders(")
	to := strings.Index(store, "func (s *Store) PrepareProviderVerification(")
	if from < 0 || to < from {
		t.Fatal("ListProviders not found")
	}
	list := store[from:to]
	for _, want := range []string{"managed_by = 'tenant'", "id <> $6", "PlatformProviderCopyID(actor.ScopeID)"} {
		if !strings.Contains(list, want) {
			t.Fatalf("ListProviders lacks %q", want)
		}
	}
	service, err := os.ReadFile("service.go")
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(service), "return Provider{}, platformManagedRefusal(actor)") +
		strings.Count(string(service), "return platformManagedRefusal(actor)"); n != 2 {
		t.Fatalf("service platformManagedRefusal uses = %d, want 2 (update, delete)", n)
	}
	if !strings.Contains(list+store, "return providerVerificationTarget{}, nil, platformManagedRefusal(actor)") {
		t.Fatal("verification must refuse through platformManagedRefusal")
	}
}
