// Package entitlementusage collects the thirteen quota values the control
// installation reports to the license service (fix-usagereport).
package entitlementusage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementsync"
	"github.com/cdnca/cdnca/services/control-api/internal/errorpagecontrol"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrTrafficUnavailable: monthly_traffic_bytes cannot be read (analytics
// query disabled or ClickHouse failing). The v2 report has no "not counted"
// value, so the round is skipped rather than reporting 0.
var ErrTrafficUnavailable = errors.New("monthly traffic usage unavailable")

// TrafficReader sums package-attributed HTTP + L4 bytes of the installation
// in [from, to) (analytics.Client.InstallationTrafficBytes).
type TrafficReader interface {
	InstallationTrafficBytes(ctx context.Context, from, to time.Time, excludeBlocked bool) (uint64, error)
}

type Collector struct {
	Pool    *pgxpool.Pool
	Traffic TrafficReader // nil: analytics query disabled
	// ExcludeBlocked is the "block pages are not traffic" switch (FX60), as
	// for package traffic; nil counts every request.
	ExcludeBlocked func(context.Context) (bool, error)
	// ReleaseChannels is the number of release channels the platform policy
	// currently allows on this installation.
	ReleaseChannels func() int
	Now             func() time.Time
}

// MonthStart is the start of the UTC calendar month of at (the quota month,
// docs/adr/0012 monthly_traffic_bytes).
func MonthStart(at time.Time) time.Time {
	at = at.UTC()
	return time.Date(at.Year(), at.Month(), 1, 0, 0, 0, 0, time.UTC)
}

func (collector Collector) Collect(ctx context.Context) (time.Time, []entitlementsync.UsageValue, error) {
	if collector.Pool == nil || collector.ReleaseChannels == nil {
		return time.Time{}, nil, entitlementsync.ErrInvalidConfiguration
	}
	now := time.Now
	if collector.Now != nil {
		now = collector.Now
	}
	observedAt := time.Unix(now().UTC().Unix(), 0).UTC()
	used := make(map[string]int64, len(entitlementsync.UsageReportCodes))
	if collector.Traffic == nil {
		return time.Time{}, nil, ErrTrafficUnavailable
	}
	exclude := false
	if collector.ExcludeBlocked != nil {
		value, err := collector.ExcludeBlocked(ctx)
		if err != nil {
			return time.Time{}, nil, errors.Join(ErrTrafficUnavailable, err)
		}
		exclude = value
	}
	if start := MonthStart(observedAt); start.Before(observedAt) {
		traffic, err := collector.Traffic.InstallationTrafficBytes(ctx, start, observedAt, exclude)
		if err != nil {
			return time.Time{}, nil, errors.Join(ErrTrafficUnavailable, err)
		}
		used[entitlement.QuotaMonthlyTrafficBytes] = int64(min(traffic, uint64(entitlement.MaxQuotaLimit)))
	} else {
		used[entitlement.QuotaMonthlyTrafficBytes] = 0 // first second of the month
	}
	used[entitlement.QuotaReleaseChannelsCount] = int64(collector.ReleaseChannels())

	// One read-only snapshot, so the counts are of the same moment.
	err := pgx.BeginTxFunc(ctx, collector.Pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly},
		func(tx pgx.Tx) error { return countDatabase(ctx, tx, used) })
	if err != nil {
		return time.Time{}, nil, fmt.Errorf("count entitlement usage: %w", err)
	}
	values := make([]entitlementsync.UsageValue, 0, len(entitlementsync.UsageReportCodes))
	for _, code := range entitlementsync.UsageReportCodes {
		value, ok := used[code]
		if !ok || value < 0 {
			return time.Time{}, nil, fmt.Errorf("entitlement usage %s not counted", code)
		}
		values = append(values, entitlementsync.UsageValue{Code: code, Used: min(value, entitlement.MaxQuotaLimit)})
	}
	return observedAt, values, nil
}

func countDatabase(ctx context.Context, tx pgx.Tx, used map[string]int64) error {
	var err error
	if used[entitlement.QuotaDomainsCount], err = entitlementguard.ActiveDomainCount(ctx, tx); err != nil {
		return err
	}
	if used[entitlement.QuotaNodesCount], err = entitlementguard.AllocatedNodeCount(ctx, tx); err != nil {
		return err
	}
	var sites, packages, webhooks int64
	// sites.count: every site not deleted (enabled or not).
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM sites WHERE deleted_at IS NULL`).Scan(&sites); err != nil {
		return err
	}
	// packages.count: the publish guard (packagecatalog checkPublicationEntitlement)
	// counts published packages per owner scope; the fullest owner is reported.
	if err := tx.QueryRow(ctx, `SELECT COALESCE(max(published),0) FROM (
		SELECT count(*) AS published FROM package_offer_publication_heads head
		JOIN package_products product ON product.id=head.product_id
		WHERE head.state='published' GROUP BY product.owner_scope_id) per_owner`).Scan(&packages); err != nil {
		return err
	}
	// extensions.webhooks.count: the subscription guard (pluginwebhookcontrol)
	// counts active subscriptions per tenant; the fullest tenant is reported.
	if err := tx.QueryRow(ctx, `SELECT COALESCE(max(active),0) FROM (
		SELECT count(*) AS active FROM plugin_webhook_subscriptions
		WHERE status='active' GROUP BY tenant_scope_id) per_tenant`).Scan(&webhooks); err != nil {
		return err
	}
	used[entitlement.QuotaSitesCount] = sites
	used[entitlement.QuotaPackagesCount] = packages
	used[entitlement.QuotaExtensionsWebhooksCount] = webhooks
	pages, err := errorpagecontrol.CountUsage(ctx, tx)
	if err != nil {
		return err
	}
	used[entitlement.QuotaErrorPageAssetBytes] = pages.AssetBytes
	used[entitlement.QuotaErrorPageAssetsCount] = pages.AssetsCount
	used[entitlement.QuotaErrorPageTotalBytes] = pages.TotalBytes
	used[entitlement.QuotaErrorPageRulesPerScope] = pages.RulesPerScope
	used[entitlement.QuotaErrorPagePublicationSites] = pages.PublicationSites
	used[entitlement.QuotaErrorPagePublicationBytes] = pages.PublicationBytes
	return nil
}
