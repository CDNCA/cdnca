package cnamelines

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/cnameallocation"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremotesource"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Failure codes kept on the row (short, never vendor text).
const (
	ErrProvider    = "dns_provider_failed"
	ErrUnconfirmed = "dns_line_unconfirmed"
	ErrUnsupported = "dns_lines_unsupported"
	// ErrNotInPlan: the account's plan lacks the line; it answers with the
	// default line until the plan changes.
	ErrNotInPlan = "dns_line_not_in_plan"
)

const (
	batchSites       = 50
	retryAfter       = time.Minute
	unsupportedRetry = 10 * time.Minute
)

// Publisher writes one line's A/AAAA set (dnsproviderremotesource.LineRecords).
type Publisher interface {
	PublishAddresses(context.Context, dnsproviderremotesource.AddressPublication) error
}

type Worker struct {
	pool      *pgxpool.Pool
	publisher Publisher
	auditor   *audit.Log
	now       func() time.Time
	logger    *slog.Logger
}

func NewWorker(pool *pgxpool.Pool, publisher Publisher, now func() time.Time, logger *slog.Logger) (*Worker, error) {
	if pool == nil || publisher == nil {
		return nil, errors.New("cname lines worker requires a pool and a publisher")
	}
	if now == nil {
		now = time.Now
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Worker{pool: pool, publisher: publisher, auditor: audit.NewWithClock(pool, func() time.Time { return now().UTC() }),
		now: now, logger: logger}, nil
}

// Run ticks until ctx ends.
func (worker *Worker) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := worker.Tick(ctx); err != nil && ctx.Err() == nil {
			worker.logger.Warn("cname carrier line tick failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// site is one settled site-mode CNAME owner and where its records live.
type site struct {
	TenantID, ScopeID, SiteID, ZoneID uuid.UUID
	GroupScopeID, GroupID             uuid.UUID
	GroupRevision                     int64
	Owner, ProviderType               string
}

// Tick plans every site and publishes lines whose wanted set differs from
// what was last confirmed (or whose retry is due).
func (worker *Worker) Tick(ctx context.Context) error {
	rows, err := worker.pool.Query(ctx, `SELECT allocation.tenant_id,allocation.tenant_scope_id,binding.site_id,frozen.zone_id,
			line_group.tenant_scope_id,line_group.id,line_group.current_revision,frozen.owner_name,provider.provider_type
		FROM cname_site_bindings binding
		JOIN cname_allocations allocation ON allocation.tenant_scope_id=binding.tenant_scope_id
		 AND allocation.id=binding.current_allocation_id AND allocation.state='done' AND allocation.mode='site'
		JOIN cname_allocation_targets frozen ON frozen.tenant_id=allocation.tenant_id AND frozen.job_id=allocation.job_id
		JOIN node_line_groups line_group ON line_group.tenant_scope_id=frozen.node_group_scope_id
		 AND line_group.id=frozen.node_group_id AND line_group.deleted_at IS NULL
		JOIN dns_zones zone ON zone.scope_id=frozen.tenant_scope_id AND zone.id=frozen.zone_id AND zone.status<>'failed'
		JOIN dns_providers provider ON provider.scope_id=zone.scope_id AND provider.id=zone.provider_id
		JOIN sites ON sites.id=binding.site_id AND sites.deleted_at IS NULL
		WHERE provider.provider_type = ANY($1::text[])
		ORDER BY binding.site_id`, lineProviders())
	if err != nil {
		return err
	}
	sites, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (site, error) {
		var value site
		return value, row.Scan(&value.TenantID, &value.ScopeID, &value.SiteID, &value.ZoneID, &value.GroupScopeID,
			&value.GroupID, &value.GroupRevision, &value.Owner, &value.ProviderType)
	})
	if err != nil {
		return err
	}
	written := 0
	for _, item := range sites {
		if ctx.Err() != nil || written >= batchSites {
			break
		}
		changed, err := worker.site(ctx, item)
		if err != nil {
			return err
		}
		if changed {
			written++
		}
	}
	return nil
}

func lineProviders() []string {
	var providers []string
	for _, capability := range dnsproviderremote.ProviderCapabilityMatrix() {
		if capability.Line {
			providers = append(providers, capability.ProviderType)
		}
	}
	return providers
}

type lineRow struct {
	desired, published string
	due                bool
}

func (worker *Worker) site(ctx context.Context, item site) (bool, error) {
	endpoints, err := worker.endpoints(ctx, item)
	if err != nil {
		return false, err
	}
	settings, err := cnameallocation.LoadPublishSettings(ctx, worker.pool, item.ScopeID, item.ZoneID, item.GroupID,
		item.GroupRevision)
	if err != nil {
		return false, err
	}
	// Lines the aggregated edge schedules for this site are its own.
	rows, err := worker.pool.Query(ctx, `SELECT line_scope FROM aggregated_edge_line_targets WHERE site_id=$1 AND line_scope<>''`,
		item.SiteID)
	if err != nil {
		return false, err
	}
	scheduled, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return false, err
	}
	existing := map[string]lineRow{}
	rows, err = worker.pool.Query(ctx, `SELECT line_scope,desired_digest,COALESCE(published_digest,''),next_attempt_at<=$2
		FROM cname_carrier_line_records WHERE site_id=$1`, item.SiteID, worker.now().UTC())
	if err != nil {
		return false, err
	}
	for rows.Next() {
		var scope string
		var row lineRow
		if err := rows.Scan(&scope, &row.desired, &row.published, &row.due); err != nil {
			rows.Close()
			return false, err
		}
		existing[scope] = row
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return false, err
	}
	changed := false
	for scope, set := range Plan(endpoints) {
		row, tracked := existing[scope]
		if !Supported(item.ProviderType, scope) {
			continue
		}
		if containsScope(scheduled, scope) {
			// Handed over to the aggregated edge: forget our record of it.
			if tracked {
				if _, err := worker.pool.Exec(ctx, `DELETE FROM cname_carrier_line_records WHERE site_id=$1 AND line_scope=$2`,
					item.SiteID, scope); err != nil {
					return changed, err
				}
			}
			continue
		}
		weights := LineWeights(endpoints, scope, settings.Weights)
		digest := set.Digest(settings.TTL, weights)
		// Nothing wanted and nothing of ours on the line: never touch it.
		if set.Empty() && !tracked {
			continue
		}
		if tracked && row.published == digest && row.desired == digest {
			if set.Empty() {
				if _, err := worker.pool.Exec(ctx, `DELETE FROM cname_carrier_line_records WHERE site_id=$1 AND line_scope=$2`,
					item.SiteID, scope); err != nil {
					return changed, err
				}
			}
			continue
		}
		if tracked && row.desired == digest && !row.due {
			continue
		}
		changed = true
		if err := worker.publish(ctx, item, scope, set, settings.TTL, weights, digest); err != nil {
			return changed, err
		}
	}
	return changed, nil
}

func containsScope(scopes []string, scope string) bool {
	for _, value := range scopes {
		if value == scope {
			return true
		}
	}
	return false
}

// endpoints are the published endpoints of the site's line group, minus the
// nodes the ACME HTTP-01 serving gate keeps off the site (migration 342),
// with the region/carrier of the endpoint.
func (worker *Worker) endpoints(ctx context.Context, item site) ([]Endpoint, error) {
	rows, err := worker.pool.Query(ctx, `SELECT host(published.address),endpoint.region,endpoint.carrier
		FROM node_line_endpoint_published published
		JOIN node_line_endpoints endpoint ON endpoint.tenant_scope_id=published.tenant_scope_id
		 AND endpoint.line_group_id=published.line_group_id AND endpoint.config_revision=published.config_revision
		 AND endpoint.id=published.endpoint_id
		WHERE published.tenant_scope_id=$1 AND published.line_group_id=$2 AND published.config_revision=$3 AND published.published
		  AND (published.node_id IS NULL OR acme_http01_site_node_serving_blocked($4,$5,published.node_id) IS NULL)
		ORDER BY published.address`, item.GroupScopeID, item.GroupID, item.GroupRevision, item.ScopeID, item.SiteID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (Endpoint, error) {
		var value Endpoint
		return value, row.Scan(&value.Address, &value.Region, &value.Carrier)
	})
}

func (worker *Worker) publish(ctx context.Context, item site, scope string, set Set, ttl uint32, weights map[string]uint32,
	digest string) error {
	line, _ := DNSLine(scope)
	err := worker.publisher.PublishAddresses(ctx, dnsproviderremotesource.AddressPublication{TenantID: item.TenantID,
		SiteID: item.SiteID, ZoneID: item.ZoneID, Owner: item.Owner, Line: line, A: set.A, AAAA: set.AAAA,
		Weights: weights, TTL: ttl})
	now := worker.now().UTC()
	code, retry := "", time.Duration(0)
	switch {
	case err == nil:
	case errors.Is(err, dnsproviderremotesource.ErrLineUnconfirmed):
		code, retry = ErrUnconfirmed, retryAfter
	case dnsproviderremote.ErrorCodeOf(err) == dnsproviderremote.CodeUnsupported:
		code, retry = ErrUnsupported, unsupportedRetry
	case dnsproviderremote.ErrorCodeOf(err) == dnsproviderremote.CodeLineNotInPlan:
		code, retry = ErrNotInPlan, unsupportedRetry
	default:
		code, retry = ErrProvider, retryAfter
	}
	return pgx.BeginFunc(ctx, worker.pool, func(tx pgx.Tx) error {
		if code != "" {
			worker.logger.Warn("cname carrier line publication failed", "site_id", item.SiteID, "line", scope, "code", code)
			_, err := tx.Exec(ctx, `INSERT INTO cname_carrier_line_records(site_id,line_scope,desired_digest,publish_error,
				next_attempt_at,updated_at) VALUES($1,$2,$3,$4,$5,$6)
				ON CONFLICT (site_id,line_scope) DO UPDATE SET desired_digest=EXCLUDED.desired_digest,
				publish_error=EXCLUDED.publish_error,next_attempt_at=EXCLUDED.next_attempt_at,updated_at=EXCLUDED.updated_at`,
				item.SiteID, scope, digest, code, now.Add(retry), now)
			if err != nil {
				return err
			}
			return worker.audit(ctx, tx, item, scope, set, "failure", code)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO cname_carrier_line_records(site_id,line_scope,desired_digest,published_digest,
			published_a,published_aaaa,published_at,publish_error,next_attempt_at,updated_at)
			VALUES($1,$2,$3,$3,$4,$5,$6,'',$6,$6)
			ON CONFLICT (site_id,line_scope) DO UPDATE SET desired_digest=EXCLUDED.desired_digest,
			published_digest=EXCLUDED.published_digest,published_a=EXCLUDED.published_a,published_aaaa=EXCLUDED.published_aaaa,
			published_at=EXCLUDED.published_at,publish_error='',next_attempt_at=EXCLUDED.next_attempt_at,updated_at=EXCLUDED.updated_at`,
			item.SiteID, scope, digest, set.A, set.AAAA, now); err != nil {
			return err
		}
		return worker.audit(ctx, tx, item, scope, set, "success", "")
	})
}

func (worker *Worker) audit(ctx context.Context, tx pgx.Tx, item site, scope string, set Set, result, reason string) error {
	action := "dns.cname_line.publish"
	if set.Empty() {
		action = "dns.cname_line.retire"
	}
	return worker.auditor.Append(ctx, tx, audit.Event{ScopeID: item.ScopeID, Action: action, ResourceType: "site",
		ResourceID: item.SiteID.String(), Result: result, ActorKind: audit.ActorSystem, ActorRef: "job:cname_carrier_lines",
		RequestID:  "cname-carrier-lines/" + uuid.NewString(),
		ReasonCode: reason, Payload: map[string]any{"line": scope, "owner": item.Owner,
			"changes": map[string]any{"a": set.A, "aaaa": set.AAAA}}})
}
