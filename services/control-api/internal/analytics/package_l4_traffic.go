package analytics

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

const nilUUIDString = "00000000-0000-0000-0000-000000000000"

// L4 bytes are billed like HTTP bytes: up + down of every session. The facts
// are only the L4 session envelopes, a separate NATS stream and table from
// access_events, so no byte is in both. A fact names the package its forward
// had in the release that served the session (CH 027), so a
// forward moved to another package leaves its past bytes on the old one.
// A TCP session in progress is billed by its checkpoints at checkpoint_at
// (L4-USAGE-01, CH 029), its end fact only by what they did not bill.
var packageL4TrafficSQL = `SELECT toUInt64(coalesce(sum(up + down), 0)) AS traffic_bytes
FROM (` + packageL4RowsSQL + `)
FORMAT JSONEachRow`

var packageL4RowsSQL = l4UsageRowsSQL(l4FinalizedWindowSQL, "tenant_id={l4_tenant_id:UUID} AND package_subscription_id={subscription_id:UUID}")

// l4FinalizedWindowSQL is the [from, to) window on the end facts;
// l4UsageRowsSQL moves it to checkpoint_at for the checkpoints.
const l4FinalizedWindowSQL = "finalized_at>={from:DateTime64(3,'UTC')} AND finalized_at<{to:DateTime64(3,'UTC')}"

// l4UsageRowsSQL is the billed L4 usage (L4-USAGE-01) as rows (at, up,
// down): each end fact's bytes its checkpoints did not bill, at
// finalized_at, and each in-progress checkpoint's delta, at checkpoint_at.
// window names finalized_at; where (may be empty) holds conditions on
// columns both tables have (tenant_id, package_subscription_id, stream_id,
// listen_port). The two are disjoint shares of each session's bytes, so a
// session is counted once, across months by when its bytes moved.
func l4UsageRowsSQL(window, where string) string {
	if where != "" {
		where = " AND " + where
	}
	return "SELECT finalized_at AS at, toUInt64(bytes_up-least(bytes_up,checkpointed_bytes_up)) AS up, " +
		"toUInt64(bytes_down-least(bytes_down,checkpointed_bytes_down)) AS down FROM l4_session_facts_v1 FINAL WHERE " +
		window + where + " UNION ALL SELECT checkpoint_at AS at, bytes_up AS up, bytes_down AS down " +
		"FROM l4_usage_checkpoints_v1 FINAL WHERE " + strings.ReplaceAll(window, "finalized_at", "checkpoint_at") + where
}

type packageL4TrafficRow struct {
	TrafficBytes uint64 `json:"traffic_bytes"`
}

// validL4TenantID: "" (no L4 bytes) or a canonical non-nil tenants.id.
func validL4TenantID(value string) bool {
	return value == "" || validUUID(value) && !nilUUID(value)
}

func setPackageL4Parameters(parameters url.Values, l4TenantID string) {
	if l4TenantID == "" {
		l4TenantID = nilUUIDString // matches no fact
	}
	parameters.Set("param_l4_tenant_id", l4TenantID)
}

// LoadPackageL4TenantID reads the tenant (tenants.id) of a tenant access
// scope: L4 session facts carry it, not the access scope ID. "" when the
// scope is not a tenant scope.
func LoadPackageL4TenantID(ctx context.Context, query interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, tenantScopeID string) (string, error) {
	if ctx == nil || query == nil || !validUUID(tenantScopeID) {
		return "", ErrInvalidInput
	}
	var tenantID *string
	err := query.QueryRow(ctx, `SELECT tenant_id::text FROM access_scopes WHERE id=$1 AND kind='tenant'`, tenantScopeID).Scan(&tenantID)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && tenantID == nil {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if !validL4TenantID(*tenantID) {
		return "", ErrInvalidResponse
	}
	return *tenantID, nil
}

// PackageL4Traffic sums the L4 bytes attributed to a subscription in
// [from, to).
func (client *Client) PackageL4Traffic(ctx context.Context, l4TenantID, subscriptionID string, from, to time.Time) (uint64, error) {
	if client == nil || ctx == nil || !validL4TenantID(l4TenantID) || !validUUID(subscriptionID) || nilUUID(subscriptionID) ||
		from.IsZero() || !from.Before(to) || from.Location() != time.UTC || to.Location() != time.UTC ||
		to.Sub(from) > packageMetricFactRetention {
		return 0, ErrInvalidInput
	}
	if l4TenantID == "" {
		return 0, nil
	}
	parameters := url.Values{"param_from": {clickHouseTime(from)}, "param_to": {clickHouseTime(to)},
		"param_subscription_id": {subscriptionID}}
	setPackageL4Parameters(parameters, l4TenantID)
	rows, err := queryRows[packageL4TrafficRow](client, ctx, packageL4TrafficSQL, parameters, 1)
	if err != nil {
		return 0, err
	}
	if len(rows) != 1 {
		return 0, ErrInvalidResponse
	}
	return rows[0].TrafficBytes, nil
}
