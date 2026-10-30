package dnsacme

import (
	"context"

	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// ZoneApexExecer is the database handle EnsureZoneApex writes back with
// (pgx.Tx or the pool).
type ZoneApexExecer interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

// EnsureZoneApex returns the zone's hosted domain (dns_zones.provider_zone_apex,
// migration 473). A zone saved before 473 has none: it is looked up from the
// provider's domain list once and written back, so later calls read it. A
// zone the account does not host fails with dnsproviderremote.CodeZoneNotHosted.
// The write does not touch name/status/revision (the 089 claim guard and
// digests), so it is allowed under an active mutation claim.
func EnsureZoneApex(ctx context.Context, db ZoneApexExecer, resolver dnsproviderremote.ZoneApexResolver,
	scopeID, zoneID uuid.UUID, providerType string, credentials map[string]string, zoneName, stored string) (string, error) {
	if stored != "" {
		return stored, nil
	}
	if resolver == nil || db == nil {
		return "", ErrProviderVerificationUnavailable
	}
	apex, err := resolver.ResolveZoneApex(ctx, providerType, credentials, zoneName)
	if err != nil {
		return "", err
	}
	if _, err := db.Exec(ctx, `UPDATE dns_zones SET provider_zone_apex=$3
		WHERE scope_id=$1 AND id=$2 AND provider_zone_apex IS NULL`, scopeID, zoneID, apex); err != nil {
		return "", err
	}
	return apex, nil
}
