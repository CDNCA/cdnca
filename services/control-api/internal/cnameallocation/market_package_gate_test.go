package cnameallocation

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type recordingQuerier struct{ query string }

func (querier *recordingQuerier) Query(_ context.Context, query string, _ ...any) (pgx.Rows, error) {
	querier.query = query
	return nil, errors.New("recorded")
}

// 网站无有效套餐时主控的第三方 CDN 与市场订阅供给
// 停用（站点所有者自己的不停），供给目标（MarketTarget/DNS 默认线路）不再选它。
func TestSupplyPausedWithoutPackageSQL(t *testing.T) {
	expression := SupplyPausedWithoutPackageSQL("supply", "site")
	for _, want := range []string{
		"supply.kind IN ('third_party_cdn','market_subscription')",
		"supply.platform_scope_id<>site.scope_id",
		"valid_package.admin_enabled",
		"valid_package.deleted_at IS NULL",
		"valid_package.id=site.package_subscription_id",
		"valid_package.tenant_scope_id=site.scope_id",
	} {
		if !strings.Contains(expression, want) {
			t.Fatalf("SupplyPausedWithoutPackageSQL lacks %q: %s", want, expression)
		}
	}
}

func TestSupplyTargetsLeavesOutPausedSupplies(t *testing.T) {
	querier := &recordingQuerier{}
	if _, err := SupplyTargets(t.Context(), querier, uuid.New(), uuid.New()); err == nil {
		t.Fatal("expected the recorded error")
	}
	if want := "NOT " + SupplyPausedWithoutPackageSQL("supply", "site"); !strings.Contains(querier.query, want) {
		t.Fatalf("SupplyTargets must leave out paused supplies (%s): %s", want, querier.query)
	}
}
