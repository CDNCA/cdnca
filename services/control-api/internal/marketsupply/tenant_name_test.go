package marketsupply

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/cdnca/cdnca/libs/marketproto/grant"
	"github.com/google/uuid"
)

// the hidden tenant is named by the seller's own
// supply group and a short code both sides can read: the root subscription's
// first 8 hex (the buyer's subscription id, as on 订阅者 for a direct buyer),
// or the downstream ref the market gives a resold path (订阅者 shows the same).
func TestTenantDisplayName(t *testing.T) {
	root := uuid.MustParse("d5b9aae7-1111-2222-3333-444455556666")
	direct := grant.Grant{SubscriptionPath: []uuid.UUID{root}}
	if got := SubscriberCode(direct); got != "d5b9aae7" {
		t.Fatalf("direct code %q", got)
	}
	resold := grant.Grant{SubscriptionPath: []uuid.UUID{root, uuid.New()}, DownstreamRef: "d-0123456789abcdef"}
	if got := SubscriberCode(resold); got != "d-0123456789abcdef" {
		t.Fatalf("downstream code %q", got)
	}
	if got := tenantDisplayName("测试 · 3b08628a", direct); got != "市场订阅 · 测试 · 3b08628a · d5b9aae7" {
		t.Fatalf("name %q", got)
	}
	if got := tenantDisplayName("", direct); got != "市场订阅 · d5b9aae7" {
		t.Fatalf("no group name %q", got)
	}
	long := tenantDisplayName(strings.Repeat("长", 200), resold)
	if utf8.RuneCountInString(long) > 128 || !strings.HasSuffix(long, " · d-0123456789abcdef") || !strings.HasPrefix(long, "市场订阅 · 长") {
		t.Fatalf("long name %q (%d runes)", long, utf8.RuneCountInString(long))
	}
}
