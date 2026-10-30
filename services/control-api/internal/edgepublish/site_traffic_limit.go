package edgepublish

import (
	"context"
	"fmt"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// applySiteTrafficLimits marks the document's sites that are over their own
// traffic cap (site_traffic_limits.exceeded_period, decided by the traffic
// enforcement runtime): their nodes answer every request with the notice
// page. Sites within their caps carry nothing.
func applySiteTrafficLimits(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, document *siteRuntimeV2Document) error {
	rows, err := tx.Query(ctx, `SELECT site_id,exceeded_period,notice_html FROM site_traffic_limits
		WHERE scope_id=$1 AND enabled AND exceeded_period IS NOT NULL`, scopeID)
	if err != nil {
		return fmt.Errorf("%w: load site traffic limits", ErrPersistence)
	}
	defer rows.Close()
	exceeded := map[string]edgeconfig.SiteTrafficLimit{}
	for rows.Next() {
		var siteID uuid.UUID
		var limit edgeconfig.SiteTrafficLimit
		if err := rows.Scan(&siteID, &limit.Period, &limit.NoticeHTML); err != nil {
			return fmt.Errorf("%w: scan site traffic limits", ErrPersistence)
		}
		limit.Exceeded = true
		if limit.Validate() != nil {
			return ErrInvalidInput
		}
		exceeded[siteID.String()] = limit
	}
	if rows.Err() != nil {
		return fmt.Errorf("%w: iterate site traffic limits", ErrPersistence)
	}
	for index := range document.Sites {
		if limit, ok := exceeded[document.Sites[index].ID]; ok {
			document.Sites[index].TrafficLimit = &limit
		}
	}
	return nil
}
