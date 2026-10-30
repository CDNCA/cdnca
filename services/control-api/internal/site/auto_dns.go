package site

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// 建站「DNS API（自动添加记录）」(migration 490). The create
// transaction stores one site_auto_dns_tasks row; a worker writes a CNAME of
// every site domain to the site CNAME through that DNS account and is done
// once the provider lists the record back (written to the
// provider and read back = done; propagation is not waited for). A failure
// only marks the task and shows on the site; the site itself is untouched.

const (
	AutoDNSPending = "pending"
	AutoDNSDone    = "done"
	AutoDNSFailed  = "failed"

	// AutoDNSWaitingCNAME: the site has no CNAME yet (allocation pending).
	AutoDNSWaitingCNAME = "cname_pending"
	// AutoDNSRetriesExhausted ends a task whose temporary failures kept on.
	AutoDNSRetriesExhausted = "retries_exhausted"

	autoDNSMaxAttempts = 8
)

var ErrAutoDNSProvider = errors.New("dns provider is not a verified account of the site owner")

// ownAutoDNSProviderSQL ($3 = the scope's platform copy id): 建站「DNS API
// （自动添加记录）」only takes the tenant's own accounts, never the platform
// DNS copy (DNS-SEC-20261027-01; migration 569 managed_by).
const ownAutoDNSProviderSQL = `managed_by='tenant' AND id<>$3`

// AutoDNSStatus is the site's view of its task (nil: none was asked for).
type AutoDNSStatus struct {
	ProviderID   uuid.UUID          `json:"provider_id"`
	ProviderName string             `json:"provider_name"`
	State        string             `json:"state"`
	FailureCode  *string            `json:"failure_code"`
	Attempts     int                `json:"attempts"`
	Results      []AutoDNSRecordRow `json:"results"`
	UpdatedAt    time.Time          `json:"updated_at"`
}

// AutoDNSRecordRow is one domain's outcome (Code empty: pointed at the CNAME).
type AutoDNSRecordRow struct {
	Domain string `json:"domain"`
	Before string `json:"before,omitempty"`
	Code   string `json:"code,omitempty"`
}

// enqueueSiteAutoDNS checks the account belongs to the site's scope and is
// verified, then stores the task (create transaction).
func enqueueSiteAutoDNS(ctx context.Context, tx pgx.Tx, scopeID, siteID, providerID uuid.UUID, now time.Time) error {
	var ok bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM dns_providers WHERE scope_id=$1 AND id=$2
		AND status='verified' AND NOT credential_revoked AND `+ownAutoDNSProviderSQL+`)`,
		scopeID, providerID, dnsacme.PlatformProviderCopyID(scopeID)).Scan(&ok); err != nil {
		return err
	}
	if !ok {
		return ErrAutoDNSProvider
	}
	_, err := tx.Exec(ctx, `INSERT INTO site_auto_dns_tasks (site_id, scope_id, provider_id, next_attempt_at, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $4, $4)`, siteID, scopeID, providerID, now)
	return err
}

// AutoDNSClaim is one due task handed to the worker.
type AutoDNSClaim struct {
	SiteID, ScopeID, ProviderID uuid.UUID
	Generation                  int64
	Attempts                    int
	CNAME                       string
	Domains                     []string
}

// ClaimAutoDNS leases up to limit due tasks for lease (next_attempt_at moves
// past the lease, so a crashed worker's task comes back by itself).
func (s *Store) ClaimAutoDNS(ctx context.Context, limit int, lease time.Duration) ([]AutoDNSClaim, error) {
	now := s.now().UTC()
	rows, err := s.pool.Query(ctx, `WITH due AS (
			SELECT task.site_id FROM site_auto_dns_tasks task
			WHERE task.state='pending' AND task.next_attempt_at <= $1
			ORDER BY task.next_attempt_at LIMIT $2 FOR UPDATE SKIP LOCKED)
		UPDATE site_auto_dns_tasks task SET next_attempt_at=$3, attempts=task.attempts+1, updated_at=$1
		FROM due, sites site
		WHERE task.site_id=due.site_id AND site.id=task.site_id AND site.scope_id=task.scope_id
		RETURNING task.site_id, task.scope_id, task.provider_id, task.generation, task.attempts,
			COALESCE(NULLIF(site.cname,''), ''), site.deleted_at IS NOT NULL`, now, limit, now.Add(lease))
	if err != nil {
		return nil, err
	}
	var claims []AutoDNSClaim
	var deleted []uuid.UUID
	for rows.Next() {
		var claim AutoDNSClaim
		var gone bool
		if err := rows.Scan(&claim.SiteID, &claim.ScopeID, &claim.ProviderID, &claim.Generation, &claim.Attempts,
			&claim.CNAME, &gone); err != nil {
			rows.Close()
			return nil, err
		}
		if gone {
			deleted = append(deleted, claim.SiteID)
			continue
		}
		claims = append(claims, claim)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(deleted) > 0 {
		if _, err := s.pool.Exec(ctx, `DELETE FROM site_auto_dns_tasks WHERE site_id = ANY($1)`, deleted); err != nil {
			return nil, err
		}
	}
	for index := range claims {
		domains, err := s.activeDomains(ctx, claims[index].ScopeID, claims[index].SiteID)
		if err != nil && !errors.Is(err, ErrInvalidInput) {
			return nil, err
		}
		claims[index].Domains = domains
	}
	return claims, nil
}

func (s *Store) activeDomains(ctx context.Context, scopeID, siteID uuid.UUID) ([]string, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	return selectActiveSiteDomains(ctx, tx, scopeID, siteID)
}

// AutoDNSOutcome is what the worker reports for one claim.
type AutoDNSOutcome struct {
	Results []AutoDNSRecordRow
	// Code empty: every domain points at the CNAME (done). Otherwise
	// Temporary retries with backoff until autoDNSMaxAttempts.
	Code      string
	Temporary bool
}

// ErrAutoDNSClaimLost: the claim is no longer the task's current one (its
// lease expired and another worker claimed it again, or a sync replaced it);
// its outcome is dropped (DNS-ASYNC-20261027-03).
var ErrAutoDNSClaimLost = errors.New("site auto DNS claim lost")

// CompleteAutoDNS stores the outcome only while the claim is the task's
// current one: same generation and same attempt (each claim increments
// attempts). Otherwise ErrAutoDNSClaimLost.
func (s *Store) CompleteAutoDNS(ctx context.Context, claim AutoDNSClaim, outcome AutoDNSOutcome) error {
	now := s.now().UTC()
	// results must be a JSON array (migration 492): a claim still waiting for
	// its CNAME has no rows, and nil would marshal to null and fail the round.
	if outcome.Results == nil {
		outcome.Results = []AutoDNSRecordRow{}
	}
	results, err := json.Marshal(outcome.Results)
	if err != nil {
		return err
	}
	state, code, next := AutoDNSDone, (*string)(nil), now
	if outcome.Code != "" {
		failure := outcome.Code
		state, code = AutoDNSFailed, &failure
		if outcome.Temporary && claim.Attempts < autoDNSMaxAttempts {
			state, code = AutoDNSPending, nil
			next = now.Add(autoDNSBackoff(claim.Attempts))
		} else if outcome.Temporary {
			failure = AutoDNSRetriesExhausted + ":" + outcome.Code
		}
	}
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		command, err := tx.Exec(ctx, `UPDATE site_auto_dns_tasks SET state=$3, failure_code=$4, results=$5,
				next_attempt_at=$6, updated_at=$7, completed_at=CASE WHEN $3='pending' THEN NULL ELSE $7::timestamptz END
			WHERE site_id=$1 AND generation=$2 AND attempts=$8 AND state='pending'`,
			claim.SiteID, claim.Generation, state, code, string(results), next, now, claim.Attempts)
		if err != nil {
			return err
		}
		if command.RowsAffected() == 0 {
			return ErrAutoDNSClaimLost
		}
		if state == AutoDNSPending {
			return nil
		}
		result := "success"
		if state == AutoDNSFailed {
			result = "failure"
		}
		return s.auditor.Append(ctx, tx, audit.Event{ScopeID: claim.ScopeID, Action: "site.auto_dns.apply",
			ResourceType: "site", ResourceID: claim.SiteID.String(), Result: result,
			RequestID: fmt.Sprintf("site-auto-dns/%s/%d", claim.SiteID, claim.Generation),
			Payload: map[string]any{"provider_id": claim.ProviderID.String(), "failure_code": outcome.Code,
				"domains": len(outcome.Results)}})
	})
}

// autoDNSBackoff: 30s, 1m, 2m, ... capped at 30 minutes.
func autoDNSBackoff(attempts int) time.Duration {
	delay := 30 * time.Second
	for range max(attempts-1, 0) {
		delay *= 2
		if delay >= 30*time.Minute {
			return 30 * time.Minute
		}
	}
	return delay
}

// SyncAutoDNSRequest is 解析检测 > 同步解析: run the site's task again now,
// optionally through another of the owner's accounts.
type SyncAutoDNSRequest struct {
	SiteID     uuid.UUID
	ProviderID *uuid.UUID
	RequestID  string
}

// SyncAutoDNS resets (or creates) the task. Repeating it is harmless: each
// call only schedules one more converging run (the writer is idempotent).
func (s *Store) SyncAutoDNS(ctx context.Context, actor Actor, request SyncAutoDNSRequest) (AutoDNSStatus, error) {
	var status AutoDNSStatus
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var scopeID uuid.UUID
		var current *uuid.UUID
		err := tx.QueryRow(ctx, `SELECT site.scope_id, task.provider_id FROM sites site
			LEFT JOIN site_auto_dns_tasks task ON task.site_id=site.id
			WHERE site.id=$1 AND site.deleted_at IS NULL AND ($2='platform' OR site.scope_id=$3)
			FOR UPDATE OF site`, request.SiteID, actor.ScopeKind, actor.ScopeID).Scan(&scopeID, &current)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		provider := request.ProviderID
		if provider == nil {
			provider = current
		}
		if provider == nil {
			return ErrInvalidInput
		}
		var ok bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM dns_providers WHERE scope_id=$1 AND id=$2
			AND status='verified' AND NOT credential_revoked AND `+ownAutoDNSProviderSQL+`)`,
			scopeID, *provider, dnsacme.PlatformProviderCopyID(scopeID)).Scan(&ok); err != nil {
			return err
		}
		if !ok {
			return ErrAutoDNSProvider
		}
		now := s.now().UTC()
		if _, err := tx.Exec(ctx, `INSERT INTO site_auto_dns_tasks (site_id, scope_id, provider_id, next_attempt_at, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $4, $4)
			ON CONFLICT (site_id) DO UPDATE SET provider_id=EXCLUDED.provider_id, state='pending', attempts=0,
				generation=site_auto_dns_tasks.generation+1, failure_code=NULL, next_attempt_at=$4, updated_at=$4,
				completed_at=NULL`, request.SiteID, scopeID, *provider, now); err != nil {
			return mapAutoDNSError(err)
		}
		if err := s.auditor.Append(ctx, tx, audit.Event{ScopeID: scopeID, ActorUserID: &actor.UserID,
			Action: "site.auto_dns.sync", ResourceType: "site", ResourceID: request.SiteID.String(),
			RequestID: request.RequestID, Result: "success",
			Payload: map[string]any{"provider_id": provider.String()}}); err != nil {
			return err
		}
		statuses, err := loadAutoDNSStatuses(ctx, tx, []uuid.UUID{request.SiteID})
		if err != nil {
			return err
		}
		status = *statuses[request.SiteID]
		return nil
	})
	return status, err
}

func mapAutoDNSError(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23503" {
		return ErrAutoDNSProvider
	}
	return err
}

type autoDNSQuerier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// loadAutoDNSStatuses: site ID → status, for the sites that have a task.
func loadAutoDNSStatuses(ctx context.Context, db autoDNSQuerier, siteIDs []uuid.UUID) (map[uuid.UUID]*AutoDNSStatus, error) {
	statuses := make(map[uuid.UUID]*AutoDNSStatus, len(siteIDs))
	if len(siteIDs) == 0 {
		return statuses, nil
	}
	rows, err := db.Query(ctx, `SELECT task.site_id, task.provider_id, provider.name, task.state, task.failure_code,
			task.attempts, task.results, task.updated_at
		FROM site_auto_dns_tasks task
		JOIN dns_providers provider ON provider.scope_id=task.scope_id AND provider.id=task.provider_id
		WHERE task.site_id = ANY($1)`, siteIDs)
	if err != nil {
		return nil, fmt.Errorf("load site auto DNS: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var siteID uuid.UUID
		var status AutoDNSStatus
		var results []byte
		if err := rows.Scan(&siteID, &status.ProviderID, &status.ProviderName, &status.State, &status.FailureCode,
			&status.Attempts, &results, &status.UpdatedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(results, &status.Results); err != nil {
			return nil, err
		}
		statuses[siteID] = &status
	}
	return statuses, rows.Err()
}

func (s *Service) SyncAutoDNS(ctx context.Context, actor Actor, request SyncAutoDNSRequest) (AutoDNSStatus, error) {
	if !validActor(actor) || request.SiteID == uuid.Nil || (request.ProviderID != nil && *request.ProviderID == uuid.Nil) ||
		request.RequestID == "" {
		return AutoDNSStatus{}, ErrInvalidInput
	}
	return s.store.SyncAutoDNS(ctx, actor, request)
}
