package l4lineswitch

import (
	"context"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/cnameallocation"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresDNSGate reads the CNAME owners of the scope's L4 sites. An owner is
// settled when its allocation is done, no retarget of it is in flight, the
// values DNS last committed contain no address of a retiring node, and that
// commit is older than cnameallocation.PropagationWindow.
type PostgresDNSGate struct {
	pool *pgxpool.Pool
	iam  *iamlock.Authorizer
}

func NewPostgresDNSGate(pool *pgxpool.Pool, iam *iamlock.Authorizer) (*PostgresDNSGate, error) {
	if pool == nil || iam == nil || !iam.Configured() {
		return nil, ErrInvalidInput
	}
	return &PostgresDNSGate{pool: pool, iam: iam}, nil
}

type dnsOwner struct {
	zoneID      uuid.UUID
	settled     bool
	addresses   []string
	cname       string
	committedAt time.Time
}

func (gate *PostgresDNSGate) Check(ctx context.Context, actor Actor, value Switch) (DNSGateStatus, error) {
	if ctx == nil || gate == nil || !validAuthority(actor) || value.ID == uuid.Nil || value.ConfigurationScopeID == uuid.Nil {
		return DNSGateStatus{}, ErrInvalidInput
	}
	var status DNSGateStatus
	err := pgx.BeginTxFunc(ctx, gate.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead}, func(tx pgx.Tx) error {
		if err := authorizeTx(ctx, tx, gate.iam, actor, value.ConfigurationScopeID, value.ID, PermissionManage); err != nil {
			return err
		}
		var err error
		status, err = ReadDNSGate(ctx, tx, value.ConfigurationScopeID, value.RetiringNodes)
		return err
	})
	if err != nil {
		return DNSGateStatus{}, err
	}
	return status, nil
}

// ReadDNSGate evaluates the gate inside the caller's transaction; callers
// authorize first.
func ReadDNSGate(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, retiringNodes []uuid.UUID) (DNSGateStatus, error) {
	var status DNSGateStatus
	var now time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return DNSGateStatus{}, fmt.Errorf("%w: read database clock", ErrPersistence)
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT host(address) FROM node_line_endpoints
		WHERE node_id=ANY($1::uuid[])`, retiringNodes)
	if err != nil {
		return DNSGateStatus{}, fmt.Errorf("%w: read retiring addresses", ErrPersistence)
	}
	retiringList, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return DNSGateStatus{}, fmt.Errorf("%w: read retiring addresses", ErrPersistence)
	}
	retiring := make(map[string]struct{}, len(retiringList))
	for _, address := range retiringList {
		retiring[address] = struct{}{}
	}
	rows, err = tx.Query(ctx, `SELECT COALESCE(frozen.zone_id,'00000000-0000-0000-0000-000000000000'::uuid),
		allocation.state='done' AND frozen.job_id IS NOT NULL AND NOT EXISTS (
			SELECT 1 FROM dns_cname_retargets busy WHERE busy.tenant_scope_id=allocation.tenant_scope_id
			  AND busy.allocation_id=allocation.id AND busy.state IN ('pending','applying')),
		COALESCE(applied.target_a,frozen.target_a,'{}')||COALESCE(applied.target_aaaa,frozen.target_aaaa,'{}'),
		COALESCE(applied.target_cname,''),
		COALESCE(applied.updated_at,frozen.updated_at,allocation.updated_at)
		FROM cname_allocations allocation
		LEFT JOIN cname_allocation_targets frozen ON frozen.tenant_id=allocation.tenant_id AND frozen.job_id=allocation.job_id
		LEFT JOIN LATERAL (SELECT target_a,target_aaaa,target_cname,updated_at FROM dns_cname_retargets prior
		WHERE prior.tenant_scope_id=allocation.tenant_scope_id AND prior.allocation_id=allocation.id
		  AND prior.base_job_id=allocation.job_id AND prior.state='committed'
		ORDER BY prior.sequence DESC LIMIT 1) applied ON true
		WHERE allocation.tenant_scope_id=$1 AND (EXISTS (
		-- A stream's CNAME (no website, migration 506) is its package's
		-- allocation, or its own (migration 505) while it overrides.
		SELECT 1 FROM l4_forwards forward WHERE forward.scope_id=allocation.tenant_scope_id
		  AND forward.deleted_at IS NULL
		  AND forward.package_subscription_id=allocation.package_subscription_id) OR EXISTS (
		SELECT 1 FROM cname_stream_bindings binding
		JOIN l4_forwards forward ON forward.scope_id=binding.tenant_scope_id AND forward.id=binding.stream_id
		  AND forward.deleted_at IS NULL AND (forward.cname_domain IS NOT NULL OR forward.cname_mode IS NOT NULL)
		WHERE binding.tenant_scope_id=allocation.tenant_scope_id AND binding.allocation_id=allocation.id))
		ORDER BY allocation.id`, scopeID)
	if err != nil {
		return DNSGateStatus{}, fmt.Errorf("%w: read CNAME owners", ErrPersistence)
	}
	owners, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (dnsOwner, error) {
		var owner dnsOwner
		return owner, row.Scan(&owner.zoneID, &owner.settled, &owner.addresses, &owner.cname, &owner.committedAt)
	})
	if err != nil {
		return DNSGateStatus{}, fmt.Errorf("%w: read CNAME owners", ErrPersistence)
	}
	status = DNSGateStatus{State: DNSGateReady, Owners: len(owners)}
	var readyAt time.Time
	for _, owner := range owners {
		pointsAtRetiring := false
		if owner.cname == "" {
			for _, address := range owner.addresses {
				if _, found := retiring[address]; found {
					pointsAtRetiring = true
					break
				}
			}
		}
		if !owner.settled || pointsAtRetiring {
			status.PendingOwners++
			continue
		}
		settings, err := cnameallocation.LoadPublishSettings(ctx, tx, scopeID, owner.zoneID, uuid.Nil, 0)
		if err != nil {
			return DNSGateStatus{}, fmt.Errorf("%w: read CNAME TTL", ErrPersistence)
		}
		if at := owner.committedAt.Add(cnameallocation.PropagationWindow(settings.TTL)); at.After(readyAt) {
			readyAt = at
		}
	}
	switch {
	case status.PendingOwners > 0:
		status.State = DNSGateRetargetPending
	case readyAt.After(now):
		status.State = DNSGatePropagationWait
		at := readyAt.UTC()
		status.ReadyAt = &at
	}
	return status, nil
}

var _ DNSGate = (*PostgresDNSGate)(nil)
