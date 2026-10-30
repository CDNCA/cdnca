package dnsacme

import (
	"context"
	"errors"
	"math"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/acmeworker"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var errCAPolicyStore = errors.New("dns_acme_ca_policy_store_failed")

func (s *Store) LoadCAPolicyFacts(
	ctx context.Context,
	request acmeworker.IssueRequest,
	candidates []acmeworker.CAPolicyCandidate,
	asOf time.Time,
	accountWindow time.Duration,
	domainWindow time.Duration,
) (acmeworker.CAPolicyFacts, error) {
	if s == nil || s.pool == nil || ctx == nil || request.ScopeID == uuid.Nil || request.OperationID == "" ||
		len(request.Domains) == 0 || len(candidates) < 1 || len(candidates) > 4 || asOf.IsZero() ||
		accountWindow <= 0 || domainWindow <= 0 {
		return acmeworker.CAPolicyFacts{}, errCAPolicyStore
	}
	facts := acmeworker.CAPolicyFacts{Usage: make(map[string]acmeworker.CAPolicyUsage, len(candidates))}
	err := s.pool.QueryRow(ctx, `SELECT directory_url FROM acme_issuance_operations
		WHERE tenant_scope_id=$1 AND operation_id=$2`, request.ScopeID, request.OperationID,
	).Scan(&facts.PinnedDirectoryURL)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return acmeworker.CAPolicyFacts{}, errCAPolicyStore
	}
	for _, candidate := range candidates {
		if candidate.DirectoryURL == "" || candidate.AccountKeyRef == "" {
			return acmeworker.CAPolicyFacts{}, errCAPolicyStore
		}
		var accountAttempts, domainAttempts int64
		var accountAvailableAt, domainAvailableAt, retryAfterUntil *time.Time
		err := s.pool.QueryRow(ctx, `SELECT
			COUNT(*) FILTER (WHERE operation.account_key_ref=$5 AND operation.created_at >= $3),
			MIN(operation.created_at + ($6 * interval '1 microsecond'))
				FILTER (WHERE operation.account_key_ref=$5 AND operation.created_at >= $3),
			COUNT(*) FILTER (WHERE operation.created_at >= $4 AND EXISTS (
				SELECT 1 FROM jsonb_array_elements_text(operation.request_snapshot -> 'Domains') domain(value)
				WHERE domain.value=ANY($7)
			)),
			MIN(operation.created_at + ($8 * interval '1 microsecond'))
				FILTER (WHERE operation.created_at >= $4 AND EXISTS (
					SELECT 1 FROM jsonb_array_elements_text(operation.request_snapshot -> 'Domains') domain(value)
					WHERE domain.value=ANY($7)
				)),
			MAX(latest.next_reconcile_at) FILTER (WHERE latest.failure_code='acme_rate_limited')
			FROM acme_issuance_operations operation
			LEFT JOIN LATERAL (
				SELECT event.failure_code,event.next_reconcile_at
				FROM acme_issuance_operation_events event
				WHERE event.tenant_scope_id=operation.tenant_scope_id
				  AND event.operation_id=operation.operation_id
				ORDER BY revision DESC LIMIT 1
			) latest ON TRUE
			WHERE operation.tenant_scope_id=$1 AND operation.directory_url=$2`,
			request.ScopeID, candidate.DirectoryURL,
			asOf.UTC().Add(-accountWindow), asOf.UTC().Add(-domainWindow), candidate.AccountKeyRef,
			accountWindow.Microseconds(), request.Domains, domainWindow.Microseconds(),
		).Scan(&accountAttempts, &accountAvailableAt, &domainAttempts, &domainAvailableAt, &retryAfterUntil)
		if err != nil || accountAttempts > math.MaxInt || domainAttempts > math.MaxInt {
			return acmeworker.CAPolicyFacts{}, errCAPolicyStore
		}
		usage := acmeworker.CAPolicyUsage{
			AccountAttempts: int(accountAttempts), DomainAttempts: int(domainAttempts),
		}
		if accountAvailableAt != nil {
			usage.AccountAvailableAt = accountAvailableAt.UTC()
		}
		if domainAvailableAt != nil {
			usage.DomainAvailableAt = domainAvailableAt.UTC()
		}
		if retryAfterUntil != nil {
			usage.RetryAfterUntil = retryAfterUntil.UTC()
		}
		facts.Usage[candidate.DirectoryURL] = usage
	}
	return facts, nil
}
