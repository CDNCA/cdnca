package cnameallocation

import (
	"context"
	"errors"

	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Platform execution is restricted to an immutable intent created under a
// still-live administrator session. It never borrows the tenant owner's identity.
func lockPlatformSiteAuthority(ctx context.Context, tx pgx.Tx, req AllocateRequest) (siteAuthority, error) {
	if req.platformIntentID == uuid.Nil {
		return siteAuthority{}, ErrNotFound
	}
	if err := iamlock.AcquireShared(ctx, tx); err != nil {
		return siteAuthority{}, err
	}
	if _, err := iamlock.AcquireScopes(ctx, tx, []uuid.UUID{req.ActorScopeID, req.TargetScopeID}); err != nil {
		return siteAuthority{}, err
	}
	var site siteAuthority
	err := tx.QueryRow(ctx, `SELECT scope.tenant_id,site.owner_user_id,site.package_subscription_id,site.package_id,site.revision,site.cname_task_id
  FROM sites site JOIN access_scopes scope ON scope.id=site.scope_id AND scope.kind='tenant'
  JOIN tenants tenant ON tenant.id=scope.tenant_id AND tenant.status='active'
  JOIN cname_allocation_intents intent ON intent.tenant_scope_id=site.scope_id AND intent.site_id=site.id
  JOIN cname_platform_intent_sessions authority ON authority.tenant_id=intent.tenant_id AND authority.job_id=intent.job_id
  JOIN auth_sessions session ON session.id=authority.actor_session_id AND session.user_id=intent.actor_user_id AND session.scope_id=intent.actor_scope_id
  JOIN access_scopes actor_scope ON actor_scope.id=intent.actor_scope_id AND actor_scope.kind='platform'
  JOIN memberships membership ON membership.scope_id=actor_scope.id AND membership.user_id=intent.actor_user_id AND membership.status='active'
  JOIN users actor ON actor.id=membership.user_id AND actor.status='active'
  WHERE site.scope_id=$1 AND site.id=$2 AND site.deleted_at IS NULL
   AND intent.actor_scope_id=$3 AND intent.actor_user_id=$4 AND intent.job_id=$5
   AND intent.expected_site_revision=$6 AND intent.mode=$7 AND intent.domain=$8 AND intent.hostname=$9
   AND intent.idempotency_key=$10 AND intent.request_id=$11
   AND session.revoked_at IS NULL AND session.expires_at>clock_timestamp()
   AND EXISTS(SELECT 1 FROM role_assignments a JOIN role_permissions p ON p.role_id=a.role_id
     WHERE a.scope_id=$3 AND a.user_id=$4 AND p.permission_name IN('platform.admin','package_subscriptions.manage'))
   AND EXISTS(SELECT 1 FROM role_assignments a JOIN role_permissions p ON p.role_id=a.role_id
     WHERE a.scope_id=$3 AND a.user_id=$4 AND p.permission_name IN('platform.admin','sites.manage'))
   AND EXISTS(SELECT 1 FROM role_assignments a JOIN role_permissions p ON p.role_id=a.role_id
     WHERE a.scope_id=$3 AND a.user_id=$4 AND p.permission_name IN('platform.admin','dns.manage'))
  FOR UPDATE OF site`, req.TargetScopeID, req.SiteID, req.ActorScopeID, req.ActorUserID, req.platformIntentID,
		req.ExpectedSiteRevision, string(req.Mode), req.Domain, req.Hostname, req.IdempotencyKey, req.RequestID).Scan(
		&site.tenantID, &site.ownerUserID, &site.packageSubscriptionID, &site.packageID, &site.revision, &site.cnameTaskID)
	if errors.Is(err, pgx.ErrNoRows) {
		return siteAuthority{}, failWith(FailureSiteAuthority, ErrNotFound)
	}
	if err != nil {
		return siteAuthority{}, err
	}
	return site, checkSiteCurrency(site, req)
}
