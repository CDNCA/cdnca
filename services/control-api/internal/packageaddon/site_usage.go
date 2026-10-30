package packageaddon

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

type SiteUsageCounts struct {
	Domains, RootDomains, HTTPPorts int64
}

type siteAllocation struct {
	id      uuid.UUID
	domains []string
	ports   []int64
}

// SiteUsage reads configured resources, including disabled sites. Callers which
// admit or release capacity hold the subscription lock until their commit.
func SiteUsage(ctx context.Context, tx pgx.Tx, scopeID, subscriptionID uuid.UUID) (SiteUsageCounts, error) {
	sites, err := siteAllocations(ctx, tx, scopeID, subscriptionID)
	if err != nil {
		return SiteUsageCounts{}, err
	}
	return countSiteAllocations(sites)
}

// CheckSiteChange serializes admissions with allocation changes. Existing
// over-quota configurations can be reduced without interrupting edge traffic.
func CheckSiteChange(ctx context.Context, tx pgx.Tx, scopeID, subscriptionID, siteID uuid.UUID, domains []string, ports []int64, at time.Time) error {
	limits, err := LockRuntimeLimits(ctx, tx, scopeID, subscriptionID, at)
	if err != nil {
		return err
	}
	sites, err := siteAllocations(ctx, tx, scopeID, subscriptionID)
	if err != nil {
		return err
	}
	before, err := countSiteAllocations(sites)
	if err != nil {
		return err
	}
	replacement := siteAllocation{id: siteID, domains: domains, ports: ports}
	replaced := false
	for i := range sites {
		if sites[i].id == siteID {
			sites[i] = replacement
			replaced = true
			break
		}
	}
	if !replaced {
		sites = append(sites, replacement)
	}
	after, err := countSiteAllocations(sites)
	if err != nil {
		return err
	}
	for _, value := range [][3]int64{{before.Domains, after.Domains, limits.Domains}, {before.RootDomains, after.RootDomains, limits.RootDomains}, {before.HTTPPorts, after.HTTPPorts, limits.HTTPPorts}} {
		if value[2] >= 0 && value[1] > value[2] && value[1] > value[0] {
			return ErrQuotaExceeded
		}
	}
	return nil
}

func siteAllocations(ctx context.Context, tx pgx.Tx, scopeID, subscriptionID uuid.UUID) ([]siteAllocation, error) {
	rows, err := tx.Query(ctx, `SELECT s.id,
		COALESCE((SELECT array_agg(d.canonical_domain) FROM (
			SELECT DISTINCT ON (canonical_domain) canonical_domain,action
			FROM site_domain_facts WHERE scope_id=s.scope_id AND site_id=s.id
			ORDER BY canonical_domain,global_sequence DESC
		) d WHERE d.action='activate'),ARRAY[s.domain]::text[]),
		(s.http_ports || s.https_ports)::bigint[]
		FROM sites s WHERE s.scope_id=$1 AND s.package_subscription_id=$2 AND s.deleted_at IS NULL`, scopeID, subscriptionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var sites []siteAllocation
	for rows.Next() {
		var item siteAllocation
		if err := rows.Scan(&item.id, &item.domains, &item.ports); err != nil {
			return nil, err
		}
		sites = append(sites, item)
	}
	return sites, rows.Err()
}

func countSiteAllocations(sites []siteAllocation) (SiteUsageCounts, error) {
	var result SiteUsageCounts
	domains, roots := map[string]bool{}, map[string]bool{}
	for _, site := range sites {
		for _, raw := range site.domains {
			domain := strings.TrimSuffix(strings.TrimSpace(raw), ".")
			wildcard := strings.HasPrefix(domain, "*.")
			if wildcard {
				domain = strings.TrimPrefix(domain, "*.")
			}
			domain, err := idna.Lookup.ToASCII(domain)
			if err != nil {
				return result, ErrInvalid
			}
			domain = strings.ToLower(domain)
			if wildcard {
				domain = "*." + domain
			}
			root, err := publicsuffix.EffectiveTLDPlusOne(strings.TrimPrefix(domain, "*."))
			if err != nil {
				return result, ErrInvalid
			}
			domains[domain], roots[root] = true, true
		}
		ports := map[int64]bool{}
		for _, port := range site.ports {
			if port < 1 || port > 65535 {
				return result, ErrInvalid
			}
			if port != 80 && port != 443 {
				ports[port] = true
			}
		}
		result.HTTPPorts += int64(len(ports))
	}
	result.Domains, result.RootDomains = int64(len(domains)), int64(len(roots))
	return result, nil
}
