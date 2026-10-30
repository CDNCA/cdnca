package marketsubscribe

import (
	"errors"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/cnameallocation"
	"github.com/google/uuid"
)

// 网站无有效套餐时，主控平台作用域的市场订阅不再
// 接受配置推送（手动推送、自动防御重推、site-apply 都经 run）；站点所有者自己的
// 订阅照常推送；判定与调度/DNS 同一条（cnameallocation.SupplyPausedWithoutPackageSQL）。
func TestTargetsQueryUsesPackageRule(t *testing.T) {
	if want := cnameallocation.SupplyPausedWithoutPackageSQL("supply", "site"); !strings.Contains(targetsQuery, want) {
		t.Fatalf("targets query lacks the package rule %q:\n%s", want, targetsQuery)
	}
	if !strings.Contains(targetsQuery, "JOIN sites site ON site.id=binding.site_id") {
		t.Fatalf("targets query does not join the site row:\n%s", targetsQuery)
	}
}

func TestPushableSupplies(t *testing.T) {
	platform, own := bound{id: uuid.New(), paused: true}, bound{id: uuid.New()}

	// Only the controller's subscriptions, package invalid: refused.
	if _, err := pushable([]bound{platform}); !errors.Is(err, ErrSitePackageUnavailable) {
		t.Fatalf("all paused: %v", err)
	}
	// The site owner's own subscription still takes the push; the paused
	// one is left as it is (drained, not deleted).
	got, err := pushable([]bound{platform, own})
	if err != nil || len(got) != 1 || got[0].id != own.id {
		t.Fatalf("mixed = %+v %v", got, err)
	}
	// Package valid again: nothing paused, everything is pushed.
	platform.paused = false
	if got, err := pushable([]bound{platform, own}); err != nil || len(got) != 2 {
		t.Fatalf("valid package = %+v %v", got, err)
	}
	if _, err := pushable(nil); !errors.Is(err, ErrNoMarketBinding) {
		t.Fatalf("no binding: %v", err)
	}
}
