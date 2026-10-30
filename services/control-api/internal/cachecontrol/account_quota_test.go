package cachecontrol

import (
	"testing"

	"github.com/google/uuid"
)

// fix-cachequota2：租户主账号与成员（同一作用域）提交计入该租户额度；平台管理员
// 代租户提交（认证作用域不是目标租户）不计入、不受拦截。
func TestCountsTowardsDailyLimit(t *testing.T) {
	tenant, platform := uuid.New(), uuid.New()
	owner := Actor{UserID: uuid.New(), ScopeID: tenant, ActorScopeID: tenant}
	member := Actor{UserID: uuid.New(), ScopeID: tenant, ActorScopeID: tenant}
	onBehalf := Actor{UserID: uuid.New(), ScopeID: tenant, ActorScopeID: platform}
	if !countsTowardsDailyLimit(owner) || !countsTowardsDailyLimit(member) {
		t.Fatal("tenant owner and member submissions must count")
	}
	if countsTowardsDailyLimit(onBehalf) {
		t.Fatal("platform submission on behalf of the tenant must not count")
	}
}
