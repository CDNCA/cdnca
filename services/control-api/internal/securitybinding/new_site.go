package securitybinding

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// AttachNewSiteTx binds a new site to policyID (网站列表 > 默认设置 复制快照)
// inside the site create's tx: the binding row lockBinding
// would insert, never published (revision 0). The activation worker's
// rebind pass (securityactivation/rebind.go) starts it like any binding
// behind its library, onto the site's package line groups.
func AttachNewSiteTx(ctx context.Context, tx pgx.Tx, scopeID, siteID, policyID uuid.UUID, kind string, now time.Time) error {
	_, err := lockBinding(ctx, tx, scopeID, siteID, policyID, kind, now)
	return err
}
