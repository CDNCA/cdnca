package edgepublish

import (
	"os"
	"strings"
	"testing"
)

// 绑定了套餐的网站与四层转发只有在套餐有效
// （packageInEffectSQL：启用、未删除、未取消、未暂停）时才进发布事实；停止覆盖的恢复路径同样。
// 社区版：没有绑定套餐的网站与转发照常下发（package_subscription_id IS NULL）。
func TestPublicationFactsRequireValidPackage(t *testing.T) {
	read := func(name string) string {
		content, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return string(content)
	}
	// Unbound resources publish: sites and streams in store.go, restored
	// sites and restored streams in system_overlay.go, taken-out sites and
	// streams in site_objects_serving.go.
	for name, want := range map[string]int{"store.go": 2, "system_overlay.go": 2, "site_objects_serving.go": 2} {
		if count := strings.Count(read(name), "package_subscription_id IS NULL") +
			strings.Count(read(name), "package_subscription_id IS NOT NULL AND NOT EXISTS"); count != want {
			t.Fatalf("%s unbound-resource predicates=%d want %d", name, count, want)
		}
	}
	const valid = `packageInEffectSQL("package_subscription")`
	for name, want := range map[string]int{"store.go": 2, "system_overlay.go": 2, "site_objects_serving.go": 2} {
		if count := strings.Count(read(name), valid); count != want {
			t.Fatalf("%s valid package predicates=%d want %d", name, count, want)
		}
	}
}
