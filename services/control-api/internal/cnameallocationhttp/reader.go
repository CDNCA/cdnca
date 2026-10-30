package cnameallocationhttp

import (
	"context"
	"errors"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresReader struct{ pool *pgxpool.Pool }

type nullableUUID struct {
	value uuid.UUID
	valid bool
}

type zoneFact struct {
	id       uuid.UUID
	provider uuid.UUID
	domain   string
	// providerUsable: the zone's own DNS provider is not disabled.
	providerUsable bool
}

type diagnosisSite struct {
	mode                  *string
	packageSubscriptionID *uuid.UUID
	configuredDomain      *string
	configuredHostname    *string
	bindingID             *uuid.UUID
	lkgID                 *uuid.UUID
	boundDomain           *string
}

func NewPostgresReader(pool *pgxpool.Pool) (*PostgresReader, error) {
	if pool == nil {
		return nil, ErrInvalidRequest
	}
	return &PostgresReader{pool: pool}, nil
}

func (reader *PostgresReader) List(ctx context.Context, scopeID uuid.UUID, query ListQuery) ([]AllocationView, error) {
	if ctx == nil || ctx.Err() != nil || scopeID == uuid.Nil || query.Limit < 1 || query.Limit > 101 ||
		(query.AfterID != nil && *query.AfterID == uuid.Nil) {
		return nil, ErrInvalidRequest
	}
	rows, err := reader.pool.Query(ctx, allocationSelect+`
		WHERE allocation.tenant_scope_id=$1
		  AND ($2::uuid IS NULL OR allocation.id>$2)
		ORDER BY allocation.id ASC LIMIT $3`, scopeID, query.AfterID, query.Limit)
	if err != nil {
		return nil, readerError(ctx, err)
	}
	defer rows.Close()
	items := make([]AllocationView, 0, query.Limit)
	for rows.Next() {
		item, err := scanAllocation(rows)
		if err != nil {
			return nil, readerError(ctx, err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, readerError(ctx, err)
	}
	return items, nil
}

func (reader *PostgresReader) Get(ctx context.Context, scopeID, allocationID uuid.UUID) (AllocationView, error) {
	if ctx == nil || ctx.Err() != nil || scopeID == uuid.Nil || allocationID == uuid.Nil {
		return AllocationView{}, ErrInvalidRequest
	}
	item, err := scanAllocation(reader.pool.QueryRow(ctx, allocationSelect+`
		WHERE allocation.tenant_scope_id=$1 AND allocation.id=$2`, scopeID, allocationID))
	if errors.Is(err, pgx.ErrNoRows) {
		return AllocationView{}, ErrNotFound
	}
	if err != nil {
		return AllocationView{}, readerError(ctx, err)
	}
	return item, nil
}

func (reader *PostgresReader) Diagnose(ctx context.Context, scopeID uuid.UUID, query DiagnoseQuery) (DiagnosisView, error) {
	if ctx == nil || ctx.Err() != nil || scopeID == uuid.Nil || query.SiteID == uuid.Nil ||
		!validOptionalName(query.Domain) || !validOptionalName(query.Hostname) {
		return DiagnosisView{}, ErrInvalidRequest
	}
	var result DiagnosisView
	err := pgx.BeginTxFunc(ctx, reader.pool, pgx.TxOptions{
		IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly,
	}, func(tx pgx.Tx) error {
		result.SiteID = query.SiteID
		site, err := readDiagnosisSite(ctx, tx, scopeID, query.SiteID)
		if err != nil {
			return err
		}
		codes := make([]string, 0, 8)
		blocking := false
		add := func(code string, blocks bool) {
			codes = append(codes, code)
			blocking = blocking || blocks
		}

		var ownerID uuid.UUID
		if site.mode == nil {
			add("mode_unconfigured", true)
		} else {
			result.Mode = *site.mode
			switch *site.mode {
			case "site":
				ownerID = query.SiteID
			case "package":
				if site.packageSubscriptionID == nil {
					add("package_binding_missing", true)
				} else {
					ownerID = *site.packageSubscriptionID
				}
			default:
				add("mode_invalid", true)
			}
		}
		result.OwnerID = ownerID
		result.BindingAllocationID, result.LKGAllocationID = site.bindingID, site.lkgID
		if site.bindingID == nil {
			add("current_binding_missing", true)
		}
		if site.lkgID != nil {
			add("lkg_available", false)
		} else {
			add("lkg_missing", false)
		}

		defaultZone, defaultFound, err := readZone(ctx, tx, scopeID, "", true)
		if err != nil {
			return err
		}
		if !defaultFound {
			add("default_zone_missing", true)
		}
		domain := query.Domain
		if domain == "" && site.configuredDomain != nil {
			domain = *site.configuredDomain
		}
		// cname_domain '' is a CNAME without a domain: the default zone or a
		// randomly drawn one (fix-cnamerand); the bound allocation says which.
		if domain == "" && site.boundDomain != nil {
			domain = *site.boundDomain
		}
		if domain == "" && defaultFound {
			domain = defaultZone.domain
		}
		result.Domain = domain
		hostname := query.Hostname
		if hostname == "" && site.configuredHostname != nil {
			hostname = *site.configuredHostname
		}
		result.Hostname = hostname

		var targetZone zoneFact
		zoneFound := false
		if domain != "" {
			targetZone, zoneFound, err = readZone(ctx, tx, scopeID, domain, false)
			if err != nil {
				return err
			}
		}
		if !zoneFound {
			add("zone_not_found", true)
		} else {
			result.ProviderID, result.ZoneID = &targetZone.provider, &targetZone.id
			// Any provider may host the zone; only its own must be enabled.
			if !targetZone.providerUsable {
				add("provider_mismatch", true)
			}
		}

		allocation, found, err := readOwnerAllocation(ctx, tx, scopeID, result.Mode, ownerID)
		if err != nil {
			return err
		}
		if !found {
			add("owner_allocation_missing", true)
		} else {
			result.AllocationID = &allocation.ID
			result.State = allocation.State
			switch allocation.State {
			case "pending":
				add("owner_allocation_pending", true)
			case "failed":
				add("owner_allocation_failed", true)
			case "done":
			default:
				add("owner_allocation_invalid", true)
			}
			if site.bindingID != nil && *site.bindingID != allocation.ID {
				add("current_binding_drift", true)
			}
			if zoneFound && (allocation.ProviderID != targetZone.provider || allocation.ZoneID != targetZone.id || allocation.Domain != domain) {
				add("allocation_zone_drift", true)
			}
			if hostname != "" && allocation.Hostname != hostname {
				add("allocation_hostname_drift", true)
			}
		}
		if hostname != "" {
			allocationID := uuid.Nil
			if result.AllocationID != nil {
				allocationID = *result.AllocationID
			}
			conflict, err := hostnameClaimConflict(ctx, tx, scopeID, hostname, allocationID)
			if err != nil {
				return err
			}
			if conflict {
				add("hostname_claim_conflict", true)
			}
		}
		if !blocking {
			codes = append(codes, "ready")
			result.Ready = true
		}
		sort.Strings(codes)
		result.ReasonCodes = codes
		return nil
	})
	if err != nil {
		return DiagnosisView{}, readerError(ctx, err)
	}
	return result, nil
}

const allocationSelect = `
	SELECT allocation.id,allocation.mode,
	       COALESCE(allocation.site_owner_id,allocation.package_subscription_id,allocation.stream_owner_id),
	       claim.provider_id,claim.zone_id,claim.domain,claim.hostname,claim.explicit_hostname,
	       allocation.state,allocation.failure_code,allocation.job_id,allocation.generation,
	       allocation.current_revision,allocation.lkg_revision,
	       allocation.created_at,allocation.updated_at
	FROM cname_allocations AS allocation
	JOIN cname_hostname_claims AS claim
	  ON claim.tenant_scope_id=allocation.tenant_scope_id
	 AND claim.allocation_id=allocation.id AND claim.id=allocation.current_claim_id`

type rowScanner interface{ Scan(...any) error }

func scanAllocation(row rowScanner) (AllocationView, error) {
	var item AllocationView
	var failureCode *string
	var lkgRevision *int64
	if err := row.Scan(&item.ID, &item.Mode, &item.OwnerID, &item.ProviderID, &item.ZoneID,
		&item.Domain, &item.Hostname, &item.ExplicitHostname, &item.State, &failureCode,
		&item.JobID, &item.Generation, &item.CurrentRevision, &lkgRevision,
		&item.CreatedAt, &item.UpdatedAt); err != nil {
		return AllocationView{}, err
	}
	if failureCode != nil {
		item.FailureCode = *failureCode
	}
	if lkgRevision != nil {
		item.LKGRevision = *lkgRevision
	}
	if !validAllocation(item) {
		return AllocationView{}, ErrUnavailable
	}
	item.CreatedAt, item.UpdatedAt = item.CreatedAt.UTC(), item.UpdatedAt.UTC()
	return item, nil
}

func readDiagnosisSite(ctx context.Context, tx pgx.Tx, scopeID, siteID uuid.UUID) (diagnosisSite, error) {
	var result diagnosisSite
	err := tx.QueryRow(ctx, `
		SELECT site.cname_mode,site.package_subscription_id,site.cname_domain,site.cname_hostname2,
		       binding.current_allocation_id,binding.lkg_allocation_id,claim.domain
		FROM sites AS site
		LEFT JOIN cname_site_bindings AS binding
		  ON binding.tenant_scope_id=site.scope_id AND binding.site_id=site.id
		LEFT JOIN cname_allocations AS allocation
		  ON allocation.tenant_scope_id=binding.tenant_scope_id AND allocation.id=binding.current_allocation_id
		LEFT JOIN cname_hostname_claims AS claim
		  ON claim.id=allocation.current_claim_id AND claim.allocation_id=allocation.id
		WHERE site.scope_id=$1 AND site.id=$2`, scopeID, siteID).Scan(
		&result.mode, &result.packageSubscriptionID, &result.configuredDomain, &result.configuredHostname,
		&result.bindingID, &result.lkgID, &result.boundDomain)
	if errors.Is(err, pgx.ErrNoRows) {
		return diagnosisSite{}, ErrNotFound
	}
	return result, err
}

func readZone(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, domain string, defaultOnly bool) (zoneFact, bool, error) {
	var result zoneFact
	err := tx.QueryRow(ctx, `
		SELECT zone.id,zone.provider_id,zone.name,COALESCE(provider.status<>'disabled',false) FROM dns_zones zone
		LEFT JOIN dns_providers provider ON provider.scope_id=zone.scope_id AND provider.id=zone.provider_id
		WHERE zone.scope_id=$1 AND (($2::boolean AND zone.is_default) OR (NOT $2 AND zone.name=$3))
		ORDER BY zone.id LIMIT 1`, scopeID, defaultOnly, domain).Scan(&result.id, &result.provider, &result.domain,
		&result.providerUsable)
	if errors.Is(err, pgx.ErrNoRows) {
		return zoneFact{}, false, nil
	}
	return result, err == nil, err
}

func readOwnerAllocation(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, mode string, ownerID uuid.UUID) (AllocationView, bool, error) {
	if (mode != "site" && mode != "package") || ownerID == uuid.Nil {
		return AllocationView{}, false, nil
	}
	item, err := scanAllocation(tx.QueryRow(ctx, allocationSelect+`
		WHERE allocation.tenant_scope_id=$1 AND allocation.mode=$2
		  AND (($2='site' AND allocation.site_owner_id=$3) OR
		       ($2='package' AND allocation.package_subscription_id=$3))`, scopeID, mode, ownerID))
	if errors.Is(err, pgx.ErrNoRows) {
		return AllocationView{}, false, nil
	}
	return item, err == nil, err
}

func hostnameClaimConflict(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, hostname string, allocationID uuid.UUID) (bool, error) {
	var found bool
	err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM cname_hostname_claims
			WHERE tenant_scope_id=$1 AND lower(hostname)=lower($2) AND allocation_id<>$3
		)`, scopeID, hostname, allocationID).Scan(&found)
	return found, err
}

func validAllocation(item AllocationView) bool {
	return item.ID != uuid.Nil && (item.Mode == "site" || item.Mode == "package") && item.OwnerID != uuid.Nil &&
		item.ProviderID != uuid.Nil && item.ZoneID != uuid.Nil && validOptionalName(item.Domain) && item.Domain != "" &&
		validOptionalName(item.Hostname) && item.Hostname != "" &&
		(item.State == "pending" || item.State == "failed" || item.State == "done") && item.JobID != uuid.Nil &&
		item.Generation > 0 && item.CurrentRevision > 0 && item.LKGRevision >= 0 && item.LKGRevision <= item.CurrentRevision &&
		!item.CreatedAt.IsZero() && !item.UpdatedAt.Before(item.CreatedAt)
}

func validOptionalName(value string) bool {
	return value == "" || (len(value) <= 253 && value == strings.TrimSpace(value) && value == strings.ToLower(value) &&
		!strings.ContainsAny(value, " \t\r\n") && !strings.HasPrefix(value, ".") && !strings.HasSuffix(value, "."))
}

func readerError(ctx context.Context, err error) error {
	if errors.Is(err, ErrInvalidRequest) || errors.Is(err, ErrNotFound) || errors.Is(err, ErrUnavailable) {
		return err
	}
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return ErrUnavailable
}
