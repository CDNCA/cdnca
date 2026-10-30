package dnsacme

import (
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
	before(t, update, "ErrPlatformManagedProvider", "EncryptCredential(")
	remove := block(service, "func (s *Service) DeleteProvider(", "func (s *Service) CreateZone(")
	before(t, remove, "ErrPlatformManagedProvider", "s.store.DeleteProvider(")
	verify := block(store, "func (s *Store) PrepareProviderVerification(", "func (s *Store) CompleteProviderVerification(")
	before(t, verify, "ErrPlatformManagedProvider", "return target, nil, nil")
}
