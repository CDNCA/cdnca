//go:build integration

package identity_test

import (
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
)

// 全新安装先 migrate 再 bootstrap_admin（scripts/install-control.sh），迁移 137 插默认
// TCP 计费系数时还没有平台成员，所以默认行必须由 bootstrap 补上，否则 TCP 计费页 404。
func TestIdentityBootstrapSeedsDefaultTCPBillingFactor(t *testing.T) {
	pool := newIdentityAuthorityPool(t)
	store := identity.NewStore(pool)
	result, err := store.BootstrapPlatformUserWithEmail(t.Context(),
		"bootstrap-tcp", "Bootstrap TCP", "tcp@example.test", "unused-hash", "bootstrap-tcp")
	if err != nil {
		t.Fatal(err)
	}
	var count int
	var factor, createdBy string
	if err := pool.QueryRow(t.Context(), `SELECT count(*) OVER (), factor, created_by_user_id::text
		FROM tcp_billing_factor_revisions WHERE platform_scope_id=$1 AND revision=1`, result.ScopeID).
		Scan(&count, &factor, &createdBy); err != nil {
		t.Fatalf("default TCP billing factor missing after bootstrap: %v", err)
	}
	if count != 1 || factor != "1.0" || createdBy != result.UserID.String() {
		t.Fatalf("default factor count=%d factor=%s created_by=%s", count, factor, createdBy)
	}
	if _, err := store.BootstrapPlatformUserWithEmail(t.Context(),
		"bootstrap-tcp-2", "Bootstrap TCP 2", "tcp2@example.test", "unused-hash", "bootstrap-tcp-2"); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM tcp_billing_factor_revisions
		WHERE platform_scope_id=$1`, result.ScopeID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("second bootstrap revisions=%d err=%v, want 1", count, err)
	}
}
