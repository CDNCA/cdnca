package acmehttp01

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// OrderReadiness is the accept-time check of an HTTP-01 certificate order
// (dnsacme.HTTP01Readiness): notServing is the first domain
// PublishChallenge would refuse with ErrNoTarget/ErrInvalidChallenge, i.e.
// not exactly one live site of scopeID (resolveChallengeSite) or a site
// without candidate nodes (acme_http01_site_candidate_nodes); "" when every
// domain has one. pointsElsewhere are the domains whose stored access check
// (site_dns_resolution_checks, migration 559) found DNS pointing elsewhere:
// the CA would not reach the nodes, but the owner may be about to fix it, so
// the order is only warned about.
func OrderReadiness(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, domains []string) (string, []string, error) {
	var elsewhere []string
	for _, domain := range domains {
		siteID, err := resolveChallengeSite(ctx, tx, scopeID, domain)
		if errors.Is(err, ErrInvalidChallenge) {
			return domain, nil, nil
		}
		if err != nil {
			return "", nil, err
		}
		var serving, pointsElsewhere bool
		if err := tx.QueryRow(ctx, `SELECT
			EXISTS(SELECT 1 FROM acme_http01_site_candidate_nodes($1,$2)),
			EXISTS(SELECT 1 FROM site_dns_resolution_checks check_row, jsonb_array_elements(check_row.results) result
				WHERE check_row.scope_id=$1 AND check_row.site_id=$2
				  AND lower(result->>'domain')=$3 AND result->>'code'='dns_points_elsewhere')`,
			scopeID, siteID, domain).Scan(&serving, &pointsElsewhere); err != nil {
			return "", nil, err
		}
		if !serving {
			return domain, nil, nil
		}
		if pointsElsewhere {
			elsewhere = append(elsewhere, domain)
		}
	}
	return "", elsewhere, nil
}
