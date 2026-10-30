package edgepublish

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// loadSiteAccessSettings is the scope's per-site request handling
// (site_access_settings written by internal/siteaccess); a site
// without a row has none.
func loadSiteAccessSettings(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID) (map[uuid.UUID]edgeconfig.SiteAccess, error) {
	rows, err := tx.Query(ctx, `SELECT site_id,settings FROM site_access_settings WHERE scope_id=$1`, scopeID)
	if err != nil {
		return nil, fmt.Errorf("%w: read site access settings", ErrPersistence)
	}
	defer rows.Close()
	result := make(map[uuid.UUID]edgeconfig.SiteAccess)
	for rows.Next() {
		var siteID uuid.UUID
		var raw []byte
		if err := rows.Scan(&siteID, &raw); err != nil {
			return nil, fmt.Errorf("%w: scan site access settings", ErrPersistence)
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		var value edgeconfig.SiteAccess
		if err := decoder.Decode(&value); err != nil || value.Empty() {
			return nil, fmt.Errorf("%w: decode site access settings", ErrPersistence)
		}
		result[siteID] = value
	}
	if rows.Err() != nil {
		return nil, fmt.Errorf("%w: iterate site access settings", ErrPersistence)
	}
	return result, nil
}
