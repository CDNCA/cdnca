//go:build integration

package certificateasset

import (
	"context"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/tenantaccess/tenantaccesstest"
	"github.com/jackc/pgx/v5"
)

var _ = time.Now

// fix-adminall: a platform administrator acts on any tenant; a platform
// member without platform.admin is still refused.
func TestPlatformAdminActsForTenant(t *testing.T) {
	pool := databasetest.MigratedPool(t, nil)
	f := tenantaccesstest.Seed(t, pool)
	actor := func(p tenantaccesstest.Principal) Actor {
		return Actor{UserID: p.UserID, ScopeID: f.PlatformScope, ScopeKind: ScopePlatform, SessionID: p.SessionID}
	}
	tenantaccesstest.Check(t, pool, f, func(ctx context.Context, tx pgx.Tx, p tenantaccesstest.Principal) error {
		return authorizePlatformAssetList(ctx, tx, actor(p))
	})
	tenantaccesstest.Check(t, pool, f, func(ctx context.Context, tx pgx.Tx, p tenantaccesstest.Principal) error {
		return authorizeActorRead(ctx, tx, actor(p), f.TenantScope, "certificates.read")
	})
	tenantaccesstest.Check(t, pool, f, func(ctx context.Context, tx pgx.Tx, p tenantaccesstest.Principal) error {
		return authorizeActorInTx(ctx, tx, actor(p), f.TenantScope, "certificates.manage", true)
	})
}
