package l4forward

import (
	"context"
	"errors"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/cnameallocation"
	"github.com/jackc/pgx/v5"
)

// 四层转发自有 CNAME (migration 505). A stream with its own CNAME domain or
// mode gets its own hostname: the batch action queues an intent the CNAME
// worker executes (allocate, write to DNS, check, done); clearing both
// overrides, or deleting the stream, retires the hostname (its records are
// deleted from DNS). Domain and mode inherit field by field: the stream's,
// else its package's (no website, migration 506; "" = the scope's default
// CNAME zone; package mode shared = package, else site). The DNS task is
// anchored at the stream itself (migration 507).

func hasCNAMEOverride(overrides Overrides) bool {
	return overrides.CNAMEDomain != nil || overrides.CNAMEMode != nil
}

// syncStreamCNAME runs after a stream's CNAME override changed (or on
// regenerate): an override that remains queues an intent; one that was
// removed retires the stream's hostname.
func syncStreamCNAME(ctx context.Context, tx pgx.Tx, actor Actor, previous Overrides, item Forward, requestID string,
	regenerate bool, now time.Time) error {
	if !hasCNAMEOverride(item.Overrides) {
		if !hasCNAMEOverride(previous) {
			return nil
		}
		return cnameallocation.RetireStreamOwnersTx(ctx, tx, item.ScopeID, item.ID, cnameallocation.RetireStreamReleased, now)
	}
	var domain, mode string
	if item.PackageSubscriptionID == nil {
		// No package (community edition): the stream's own CNAME domain and
		// mode only; a stream has no package to share.
		if item.Overrides.CNAMEDomain != nil {
			domain = *item.Overrides.CNAMEDomain
		}
		mode = "site"
		if item.Overrides.CNAMEMode != nil {
			mode = *item.Overrides.CNAMEMode
		}
	} else if err := tx.QueryRow(ctx, `SELECT COALESCE($3::text, NULLIF(subscription.product_snapshot#>>'{spec,cname,domain}',''), ''),
			COALESCE($4::text, CASE subscription.product_snapshot#>>'{spec,cname,mode}' WHEN 'shared' THEN 'package' ELSE 'site' END)
		FROM package_subscriptions subscription WHERE subscription.tenant_scope_id=$1 AND subscription.id=$2`,
		item.ScopeID, *item.PackageSubscriptionID, item.Overrides.CNAMEDomain, item.Overrides.CNAMEMode).Scan(&domain, &mode); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	_, err := cnameallocation.EnqueueStreamIntentTx(ctx, tx, cnameallocation.StreamIntent{
		TenantScopeID: item.ScopeID, StreamID: item.ID, ActorScopeID: actor.ScopeID,
		ActorUserID: actor.UserID, Mode: cnameallocation.Mode(mode), Domain: domain, Regenerate: regenerate,
		RequestID: requestID,
	}, now)
	if errors.Is(err, cnameallocation.ErrInvalidInput) {
		return ErrInvalidInput
	}
	return err
}

// regenerateStreamCNAME is 重新生成 of the stream's own CNAME: only a stream
// with its own CNAME whose last generation failed (stream_cname_not_failed).
// The stream itself is not changed (no revision, no publication).
func (s *Store) regenerateStreamCNAME(ctx context.Context, tx pgx.Tx, actor Actor, current Forward, requestID string) (Forward, string, error) {
	if !hasCNAMEOverride(current.Overrides) {
		return Forward{}, "stream_cname_not_overridden", nil
	}
	var failed bool
	if err := tx.QueryRow(ctx, `SELECT COALESCE((SELECT job.state IN ('failed','cancelled') FROM cname_stream_intents intent
			JOIN background_jobs job ON job.tenant_id=intent.tenant_id AND job.id=intent.job_id
			WHERE intent.tenant_scope_id=$1 AND intent.stream_id=$2 ORDER BY intent.created_at DESC,intent.job_id DESC LIMIT 1),false)
		OR EXISTS (SELECT 1 FROM cname_allocations WHERE tenant_scope_id=$1 AND stream_owner_id=$2 AND state='failed')`,
		current.ScopeID, current.ID).Scan(&failed); err != nil {
		return Forward{}, "", err
	}
	if !failed {
		return Forward{}, "stream_cname_not_failed", nil
	}
	if err := syncStreamCNAME(ctx, tx, actor, current.Overrides, current, requestID, true, s.now().UTC()); err != nil {
		return Forward{}, "", err
	}
	if err := s.auditor.Append(ctx, tx, audit.Event{
		ScopeID: current.ScopeID, ActorUserID: &actor.UserID, Action: "stream.cname.regenerate",
		ResourceType: "stream", ResourceID: current.ID.String(), RequestID: requestID, Result: "success",
		Payload: map[string]any{"revision": current.Revision},
	}); err != nil {
		return Forward{}, "", err
	}
	item, err := scanForward(tx.QueryRow(ctx, forwardSelect+" WHERE f.id = $1 AND f.deleted_at IS NULL", current.ID))
	if err != nil {
		return Forward{}, "", err
	}
	return item, "", nil
}
