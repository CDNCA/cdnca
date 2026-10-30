// Package marketmanaged answers whether a tenant, user or site on this
// controller is a node-market subscriber's restricted tenant (marketsupply
// "mkt-" tenants), and refuses stopping it locally (ADR 0012 §18.4: the
// supplier cannot stop supply it sold).
//
// A tenant is market managed while it has an mkt- member and a live market
// package subscription (product spec carries "market"). Only the market
// service account (marketsupply, acting for supply.delete_site and grant
// sync) may stop or delete it; once the grant runs out the subscription
// lapses and local cleanup is allowed again.
package marketmanaged

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	// ServiceUsername and TenantPrefix match marketsupply (tested there).
	ServiceUsername = "market-supply"
	TenantPrefix    = "mkt-"
)

// ErrManaged: the target belongs to a market subscriber; answer 409 market_managed.
var ErrManaged = errors.New("market managed: the target serves a node-market subscriber and cannot be stopped locally")

type querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

const liveScope = `EXISTS (SELECT 1 FROM memberships m JOIN users u ON u.id = m.user_id
		WHERE m.scope_id = SCOPE AND starts_with(u.username, 'mkt-'))
	AND EXISTS (SELECT 1 FROM package_subscriptions s JOIN package_products p ON p.id = s.product_id
		WHERE s.tenant_scope_id = SCOPE AND s.lifecycle_status = 'active' AND s.deleted_at IS NULL
		AND s.ends_at > now() AND p.spec ? 'market')`

// GuardScope returns ErrManaged when scope is a live market tenant and actor
// is not the market service account.
func GuardScope(ctx context.Context, q querier, actor, scope uuid.UUID) error {
	var managed, service bool
	err := q.QueryRow(ctx, `SELECT `+live("$1")+`,
		EXISTS (SELECT 1 FROM users WHERE id = $2 AND username = $3)`, scope, actor, ServiceUsername).Scan(&managed, &service)
	if err != nil {
		return err
	}
	if managed && !service {
		return ErrManaged
	}
	return nil
}

// GuardUser returns ErrManaged when user is the mkt- member of a live market
// tenant and actor is not the market service account.
func GuardUser(ctx context.Context, q querier, actor, user uuid.UUID) error {
	var managed, service bool
	err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM users u JOIN memberships mm ON mm.user_id = u.id
			WHERE u.id = $1 AND starts_with(u.username, 'mkt-') AND `+live("mm.scope_id")+`),
		EXISTS (SELECT 1 FROM users WHERE id = $2 AND username = $3)`, user, actor, ServiceUsername).Scan(&managed, &service)
	if err != nil {
		return err
	}
	if managed && !service {
		return ErrManaged
	}
	return nil
}

// live is liveScope for one scope expression.
func live(scope string) string { return strings.ReplaceAll(liveScope, "SCOPE", scope) }
