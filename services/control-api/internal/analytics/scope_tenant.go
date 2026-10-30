package analytics

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
)

// ErrTenantUnresolved: a scope-keyed read has no scope → tenant resolver, so
// it fails instead of querying ClickHouse with the scope ID (which matches no
// row and reads as zero usage).
var ErrTenantUnresolved = errors.New("analytics tenant scope is not resolvable")

// TenantResolver maps a tenant access scope (access_scopes.id) to its tenant
// (tenants.id). ClickHouse facts carry tenants.id: the node's telemetry
// manifest (edgepublish/site_runtime_v2.go) and the gateway's authorization
// (nodeidentity/store.go) both take access_scopes.tenant_id, and the gateway
// rejects any other value. The two IDs are generated independently
// (identity/users.go), so a scope ID never matches a fact.
type TenantResolver interface {
	TenantOfScope(ctx context.Context, scopeID string) (string, error)
}

// WithTenantResolver sets the resolver the scope-keyed reads (package
// metrics, package usage, site traffic, package traffic buckets, package
// resource nodes, usage search targets) use. It returns client.
func (client *Client) WithTenantResolver(resolver TenantResolver) *Client {
	if client != nil {
		client.tenants = resolver
	}
	return client
}

// tenantOfScope is the tenants.id of the tenant scope scopeID.
func (client *Client) tenantOfScope(ctx context.Context, scopeID string) (string, error) {
	if client.tenants == nil {
		return "", ErrTenantUnresolved
	}
	tenantID, err := client.tenants.TenantOfScope(ctx, scopeID)
	if err != nil {
		return "", err
	}
	if !validUUID(tenantID) || nilUUID(tenantID) {
		return "", ErrInvalidResponse
	}
	return strings.ToLower(tenantID), nil
}

// PostgresTenants reads access_scopes. The mapping is 1:1 (UNIQUE tenant_id)
// and no code path updates a scope's tenant, so it is not cached; the lookup
// is a primary key read.
type PostgresTenants struct {
	Query interface {
		QueryRow(context.Context, string, ...any) pgx.Row
	}
}

func (tenants PostgresTenants) TenantOfScope(ctx context.Context, scopeID string) (string, error) {
	if tenants.Query == nil || ctx == nil || !validUUID(scopeID) || nilUUID(scopeID) {
		return "", ErrInvalidInput
	}
	var tenantID string
	err := tenants.Query.QueryRow(ctx, `SELECT tenant_id::text FROM access_scopes WHERE id=$1 AND kind='tenant'`,
		scopeID).Scan(&tenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrInvalidInput
	}
	if err != nil {
		return "", errors.Join(ErrTenantUnresolved, err)
	}
	return tenantID, nil
}
