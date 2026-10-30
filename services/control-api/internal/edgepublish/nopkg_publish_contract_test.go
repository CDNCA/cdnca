package edgepublish

import (
	"os"
	"strings"
	"testing"
)

// 绑定了套餐的网站与四层转发只有在套餐有效
// （admin_enabled 且未删除）时才进发布事实；停止覆盖的恢复路径同样。
// 社区版：没有绑定套餐的网站与转发照常下发（package_subscription_id IS NULL）。
func TestPublicationFactsRequireValidPackage(t *testing.T) {
	read := func(name string) string {
		content, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return string(content)
	}
	// Unbound resources publish: sites and streams in store.go, taken-out
	// sites, restored sites and restored streams in system_overlay.go.
	for name, want := range map[string]int{"store.go": 2, "system_overlay.go": 3} {
		if count := strings.Count(read(name), "package_subscription_id IS NULL") +
			strings.Count(read(name), "package_subscription_id IS NOT NULL AND NOT EXISTS"); count != want {
			t.Fatalf("%s unbound-resource predicates=%d want %d", name, count, want)
		}
	}
	const valid = "package_subscription.admin_enabled=true AND package_subscription.deleted_at IS NULL"
	if count := strings.Count(read("store.go"), valid); count != 2 {
		t.Fatalf("store.go valid package predicates=%d want 2 (sites, streams)", count)
	}
	// taken-out sites (lost package), restored sites, restored streams
	if count := strings.Count(read("system_overlay.go"), valid); count != 3 {
		t.Fatalf("system_overlay.go valid package predicates=%d want 3", count)
	}
}
