package site

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/domaintrust"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// 过户转移域名验证：原租户已验证的 apex
// 会让目标租户建站被拒（domain_verified_by_other），所以过户事务里把站点域名涉及的
// apex 验证转给目标租户：原租户的验证置 revoked，目标租户的同 apex 验证置 verified
// （沿用原验证方式、令牌与验证时间）。原租户还有别的网站在用该 apex 时拒绝过户，
// 不替原租户做取舍。只转站点域名涉及的 apex；审计记管理员，两边租户各一条。

// ErrTransferApexInUse: another site of the old owner still uses a verified
// apex of the transferred site (DomainError carries the domain and apex).
var ErrTransferApexInUse = errors.New("the verified domain apex is still used by another site of the current owner")

// transferApexes is the sorted, unique apexes of the site's domains.
func transferApexes(current Site) map[string]string {
	result := map[string]string{}
	for _, domain := range append([]string{current.Domain}, current.Domains...) {
		if domain == "" {
			continue
		}
		if apex, err := domaintrust.Apex(domain); err == nil {
			if _, seen := result[apex]; !seen {
				result[apex] = domain
			}
		}
	}
	return result
}

// transferDomainOwnershipsTx moves the old tenant's verified ownership of
// the site's apexes to the target tenant. Run before the site is deleted
// (the old site's own domains are excluded by site id).
func (s *Store) transferDomainOwnershipsTx(ctx context.Context, tx pgx.Tx, actor Actor, current Site,
	targetScopeID uuid.UUID, requestID string, now time.Time) ([]string, error) {
	domainOf := transferApexes(current)
	apexes := make([]string, 0, len(domainOf))
	for apex := range domainOf {
		apexes = append(apexes, apex)
	}
	slices.Sort(apexes)
	if len(apexes) == 0 {
		return nil, nil
	}
	type proof struct {
		id                uuid.UUID
		apex, method, tok string
		verifiedAt        time.Time
	}
	rows, err := tx.Query(ctx, `SELECT id,apex,method,token,verified_at FROM domain_ownerships
		WHERE scope_id=$1 AND status='verified' AND apex=ANY($2::text[]) ORDER BY apex FOR UPDATE`, current.ScopeID, apexes)
	if err != nil {
		return nil, err
	}
	var proofs []proof
	for rows.Next() {
		var item proof
		if err := rows.Scan(&item.id, &item.apex, &item.method, &item.tok, &item.verifiedAt); err != nil {
			rows.Close()
			return nil, err
		}
		proofs = append(proofs, item)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	moved := make([]string, 0, len(proofs))
	for _, item := range proofs {
		// Another live site of the old owner under this apex keeps the proof.
		var other string
		err := tx.QueryRow(ctx, `SELECT active.canonical_domain FROM site_domain_active active
			JOIN sites site ON site.id=active.site_id AND site.scope_id=active.scope_id AND site.deleted_at IS NULL
			WHERE active.scope_id=$1 AND active.site_id<>$2
			  AND (active.canonical_domain=$3 OR active.canonical_domain LIKE '%.' || $3)
			ORDER BY active.canonical_domain LIMIT 1`, current.ScopeID, current.ID, item.apex).Scan(&other)
		if err == nil {
			return nil, &domaintrust.DomainError{Err: ErrTransferApexInUse, Domain: other, Apex: item.apex}
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
		if _, err := tx.Exec(ctx, `UPDATE domain_ownerships SET status='revoked',updated_at=GREATEST(updated_at,$2),
			revision=revision+1 WHERE id=$1`, item.id, now); err != nil {
			return nil, err
		}
		var targetID uuid.UUID
		if err := tx.QueryRow(ctx, `INSERT INTO domain_ownerships(id,scope_id,apex,method,token,status,verified_at,
				last_checked_at,last_failure_code,created_by_user_id,created_at,updated_at)
			VALUES($1,$2,$3,$4,$5,'verified',$6,$7,'',$8,$7,$7)
			ON CONFLICT (scope_id,apex) DO UPDATE SET method=EXCLUDED.method,token=EXCLUDED.token,status='verified',
				verified_at=EXCLUDED.verified_at,last_checked_at=EXCLUDED.last_checked_at,last_failure_code='',
				updated_at=GREATEST(domain_ownerships.created_at,domain_ownerships.updated_at,EXCLUDED.updated_at),
				revision=domain_ownerships.revision+1
			RETURNING id`, uuid.Must(uuid.NewV7()), targetScopeID, item.apex, item.method, item.tok, item.verifiedAt,
			now, actor.UserID).Scan(&targetID); err != nil {
			return nil, err
		}
		payload := map[string]any{"apex": item.apex, "site_id": current.ID.String(), "site_domain": current.Domain,
			"from_scope_id": current.ScopeID.String(), "to_scope_id": targetScopeID.String(),
			"actor_scope_id": actor.ScopeID.String()}
		for _, scoped := range []struct{ scopeID, resourceID uuid.UUID }{{current.ScopeID, item.id}, {targetScopeID, targetID}} {
			event := audit.Event{ScopeID: scoped.scopeID, ActorUserID: &actor.UserID, Action: "domain_ownership.admin_transfer",
				ResourceType: "domain_ownership", ResourceID: scoped.resourceID.String(), RequestID: requestID,
				Result: "success", Payload: payload}
			if err := s.auditor.Append(ctx, tx, event); err != nil {
				return nil, err
			}
		}
		moved = append(moved, item.apex)
	}
	return moved, nil
}
