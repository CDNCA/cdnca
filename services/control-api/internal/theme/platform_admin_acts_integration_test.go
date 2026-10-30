//go:build integration

package theme

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
	tenantaccesstest.Check(t, pool, f, func(ctx context.Context, tx pgx.Tx, p tenantaccesstest.Principal) error {
		return authorize(ctx, tx, Actor{UserID: p.UserID, ScopeID: f.PlatformScope, ScopeKind: "platform"}, "themes.manage")
	})
}
