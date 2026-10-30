package site

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/cnameallocation"
	"github.com/cdnca/cdnca/services/control-api/internal/tenantaccess"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// 更换所属用户（重建式过户）：平台管理员把网站
// 换给另一个用户。1.0.35 每个用户独占一个租户，站点的作用域被数十张表的复合
// 外键与不可变触发器钉住，所以不原地改归属，而是在同一事务里删除原站、在目标
// 用户的租户里新建同配置的站点（站点 ID 变）。套餐由目标用户自选名下有效订阅，
// 或不选（规则仍生成 CNAME）。CNAME 主机名不能保留（claim 只追加且
// 全局唯一、DNS 区按租户），新站重新分配；原 CNAME 按删除规则退役。历史统计、
// 日志、账单留在原用户名下。

// TransferRequest moves site ID (at ExpectedRevision) to TargetUserID.
// TargetSubscriptionID is one of the target user's own package
// subscriptions, or nil for no package.
type TransferRequest struct {
	ID                   uuid.UUID
	ExpectedRevision     int64
	TargetUserID         uuid.UUID
	TargetSubscriptionID *uuid.UUID
	IdempotencyKey       string
	RequestID            string
}

// TransferResult is the new site (in the target user's tenant) and the id
// of the deleted one.
type TransferResult struct {
	Site       Site      `json:"site"`
	FromSiteID uuid.UUID `json:"from_site_id"`
	FromCNAME  string    `json:"from_cname"`
	// Copied / Released: TransferItem* carried to the new site, and those
	// not carried that the administrator configures again.
	Copied   []string `json:"copied"`
	Released []string `json:"released"`
	Replayed bool     `json:"-"`
}

// ErrTransferTarget: the target user is not an active user with a tenant of
// its own, or is the site's current owner.
var ErrTransferTarget = errors.New("site transfer target user is invalid")

// transferFields: the new site's fields from the current site. The CNAME
// policy, 默认网站 and site group are not carried over (they belong to the
// old owner's package / the platform / the old owner's groups).
// Without the certificate (not carried) HTTPS is off on the new site.
func transferFields(current Site, subscriptionID *uuid.UUID, https bool) SiteFields {
	boolPtr := func(value bool) *bool { return &value }
	fields := SiteFields{
		Domain: current.Domain, Domains: slices.Clone(current.Domains),
		HTTPPorts: slices.Clone(current.HTTPPorts), HTTPSPorts: slices.Clone(current.HTTPSPorts),
		Origins: slices.Clone(current.Origins), TLSProtocols: slices.Clone(current.TLSProtocols),
		IPv6Enabled: current.ListenerState.IPv6DesiredEnabled, HTTPSEnabled: current.HTTPSEnabled && https,
		Enabled:         current.Enabled,
		TLSCipherPreset: &current.TLSCipherPreset, TLSCipherSuites: slices.Clone(current.TLSCipherSuites),
		TLSOCSPStapling: boolPtr(current.TLSOCSPStapling), TLSClientAuth: &current.TLSClientAuth,
		HTTP2Enabled: boolPtr(current.HTTP2Enabled), HTTP3Enabled: boolPtr(current.HTTP3Enabled),
		ForceHTTPS: boolPtr(current.ForceHTTPS), HTTPSRedirectPort: &current.HTTPSRedirectPort,
		CacheSharedAcrossDomains: boolPtr(current.CacheSharedAcrossDomains),
		CacheStatusHeader:        boolPtr(current.CacheStatusHeader),
	}
	if !fields.HTTPSEnabled {
		fields.HTTPSPorts, fields.ForceHTTPS, fields.HTTP3Enabled = nil, boolPtr(false), boolPtr(false)
		fields.HTTPSRedirectPort = nil
	}
	if current.TLSClientCAPEM != "" {
		fields.TLSClientCAPEM = &current.TLSClientCAPEM
	}
	if current.TLSPreferServerCiphers != nil {
		fields.TLSPreferServerCiphers = boolPtr(*current.TLSPreferServerCiphers)
	}
	if subscriptionID != nil {
		id := *subscriptionID
		fields.PackageSubscriptionID = &id
	}
	return fields
}

// Transfer is platform-administrator only (tenantaccess rule): the target's
// tenant is never the actor's own scope.
func (s *Service) Transfer(ctx context.Context, actor Actor, request TransferRequest) (TransferResult, error) {
	if !validActor(actor) {
		return TransferResult{}, ErrInvalidInput
	}
	if actor.ScopeKind != "platform" {
		return TransferResult{}, ErrPermissionDenied
	}
	if request.ID == uuid.Nil || request.ExpectedRevision < 1 || request.TargetUserID == uuid.Nil ||
		(request.TargetSubscriptionID != nil && *request.TargetSubscriptionID == uuid.Nil) ||
		!validWriteMetadata(request.IdempotencyKey, request.RequestID) {
		return TransferResult{}, ErrInvalidInput
	}
	return s.store.Transfer(ctx, actor, request)
}

func (s *Store) Transfer(ctx context.Context, actor Actor, request TransferRequest) (TransferResult, error) {
	var result TransferResult
	var denial error
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		admin, err := tenantaccess.IsPlatformAdmin(ctx, tx, actor.UserID, actor.ScopeID)
		if err != nil {
			return err
		}
		if !admin {
			return ErrPermissionDenied
		}
		current, err := selectSite(ctx, tx, request.ID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		pool, err := selectOriginPool(ctx, tx, request.ID)
		if err != nil {
			return err
		}
		var targetScopeID uuid.UUID
		err = tx.QueryRow(ctx, `SELECT membership.scope_id FROM memberships membership
			JOIN users account ON account.id=membership.user_id AND account.status='active'
			JOIN access_scopes scope ON scope.id=membership.scope_id AND scope.kind='tenant'
			JOIN tenants tenant ON tenant.id=scope.tenant_id AND tenant.status='active'
			WHERE membership.user_id=$1 AND membership.status='active'
			  AND NOT EXISTS (SELECT 1 FROM identity_user_deletions deletion WHERE deletion.user_id=account.id)
			ORDER BY membership.created_at,membership.scope_id LIMIT 1`, request.TargetUserID).Scan(&targetScopeID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrTransferTarget
		}
		if err != nil {
			return err
		}
		if request.TargetUserID == current.ownerID {
			return ErrTransferTarget
		}
		// Both tenants' IAM scope locks in one set: a transaction takes the
		// scope locks once (iam_scope_locks_v1 rejects a second, different set).
		if err := authorizeAutomaticMutations(ctx, tx, actor, []uuid.UUID{current.ScopeID, targetScopeID}); err != nil {
			return err
		}
		// What the old site had (HTTP policy, cache, certificate, rule
		// libraries, auto defense, challenge), read before it is deleted.
		snapshot, err := s.readTransferSnapshot(ctx, tx, current)
		if err != nil {
			return err
		}
		defer snapshot.close()
		// The old tenant's verified apexes of the site go with it (before the
		// create half's domain trust check); a no-op on replay.
		movedApexes, err := s.transferDomainOwnershipsTx(ctx, tx, actor, current, targetScopeID, request.RequestID, s.now().UTC())
		if err != nil {
			return err
		}
		// The old CNAME keeps answering for a day (the new site gets a new
		// one); the delete half's own retirement is then a no-op.
		if err := cnameallocation.RetireTransferredSiteOwnersTx(ctx, tx, current.ScopeID, request.ID, s.now().UTC()); err != nil {
			return err
		}
		// The delete half: idempotency record, domain facts, CNAME jobs.
		var deleted DeleteResult
		if err := s.deleteTx(ctx, tx, actor, DeleteRequest{ID: request.ID, ExpectedRevision: request.ExpectedRevision,
			IdempotencyKey: request.IdempotencyKey, RequestID: request.RequestID, preauthorized: true}, transferDigest(request), &deleted); err != nil {
			return err
		}
		if deleted.Replayed {
			return s.replayTransfer(ctx, tx, actor, request, &result)
		}
		fields := transferFields(current, request.TargetSubscriptionID, snapshot.carriesHTTPS())
		if err := normalizeFields(&fields); err != nil {
			return err
		}
		if err := normalizeOriginPool(&pool); err != nil {
			return err
		}
		newID, err := uuid.NewV7()
		if err != nil {
			return err
		}
		create := CreateRequest{TargetScopeID: targetScopeID, OwnerUserID: request.TargetUserID, Fields: fields,
			OriginPool: &pool, IdempotencyKey: request.IdempotencyKey, RequestID: request.RequestID, preauthorized: true}
		var created WriteResult
		if err := s.createTx(ctx, tx, actor, create, newID, transferDigest(request), &created, &denial); err != nil {
			return err
		}
		if denial != nil {
			return denial
		}
		copied, released, err := s.copyTransferSnapshot(ctx, tx, actor, current, created.Site, snapshot,
			request.RequestID, s.now().UTC())
		if err != nil {
			return err
		}
		redact(&created.Site, actor.ScopeKind)
		result = TransferResult{Site: created.Site, FromSiteID: request.ID, FromCNAME: current.CNAME,
			Copied: copied, Released: released}
		return s.auditor.Append(ctx, tx, audit.Event{
			ScopeID:      targetScopeID,
			ActorUserID:  &actor.UserID,
			Action:       "site.transfer",
			ResourceType: "site",
			ResourceID:   created.Site.ID.String(),
			RequestID:    request.RequestID,
			Result:       "success",
			Payload: map[string]any{
				"actor_scope_id": actor.ScopeID.String(), "from_site_id": request.ID.String(),
				"from_scope_id": current.ScopeID.String(), "from_owner_user_id": current.ownerID.String(),
				"to_scope_id": targetScopeID.String(), "to_owner_user_id": request.TargetUserID.String(),
				"site_domain": current.Domain, "package_subscription_id": subscriptionText(request.TargetSubscriptionID),
				"copied": copied, "released": released, "domain_ownerships": movedApexes,
			},
		})
	})
	if err != nil {
		return TransferResult{}, fmt.Errorf("transfer site: %w", err)
	}
	return result, nil
}

// replayTransfer answers a repeated request from the create half's record.
func (s *Store) replayTransfer(ctx context.Context, tx pgx.Tx, actor Actor, request TransferRequest, result *TransferResult) error {
	write, found, err := s.findWrite(ctx, tx, actor.UserID, "site.create", request.IdempotencyKey, transferDigest(request))
	if err != nil {
		return err
	}
	if !found {
		return ErrRevisionConflict
	}
	if err := decodeStoredSite(write.ResponseBody, &result.Site); err != nil {
		return fmt.Errorf("decode stored site transfer response: %w", err)
	}
	redact(&result.Site, actor.ScopeKind)
	result.FromSiteID, result.Replayed = request.ID, true
	var cname *string
	err = tx.QueryRow(ctx, `SELECT COALESCE(payload->'copied','[]'),COALESCE(payload->'released','[]'),
		(SELECT cname FROM sites WHERE id=$2) FROM audit_events
		WHERE action='site.transfer' AND resource_id=$1 ORDER BY occurred_at DESC LIMIT 1`,
		result.Site.ID.String(), request.ID).Scan(&result.Copied, &result.Released, &cname)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if cname != nil {
		result.FromCNAME = *cname
	}
	return nil
}

func transferDigest(request TransferRequest) [32]byte {
	digest, _ := digestRequest(struct {
		Operation      string     `json:"operation"`
		ID             uuid.UUID  `json:"id"`
		Revision       int64      `json:"expected_revision"`
		TargetUserID   uuid.UUID  `json:"target_user_id"`
		SubscriptionID *uuid.UUID `json:"target_subscription_id,omitempty"`
	}{"site.transfer", request.ID, request.ExpectedRevision, request.TargetUserID, request.TargetSubscriptionID})
	return digest
}

func subscriptionText(id *uuid.UUID) string {
	if id == nil {
		return ""
	}
	return id.String()
}
