// Package securityrulecatalog serves the CC/WAF system rules to the
// management UI: the rules artifactsync materialized into
// security_system_rules from the signed artifact catalog (ruleset /
// crs_profile artifacts), the local visibility overlay and the per-tenant
// switches. It no longer talks to the license service.
package securityrulecatalog

import (
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool *pgxpool.Pool
	now  func() time.Time
}

func NewStore(pool *pgxpool.Pool, now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{pool: pool, now: now}
}
