// Package certnotify tells certificate owners what needs their attention:
// a certificate that expires within one of
// the platform's notice days, and a scheduled renewal that failed.
//
// Renewal stays at 30 days before expiry with retries
// (acmeworker), and a reminder is a notification center event the member
// subscribes to by channel. Each (certificate version, notice day) is told
// once; a version that a newer active version of the same certificate has
// replaced is not told at all.
package certnotify

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	EventExpiring     = "certificate.expiring"
	EventExpired      = "certificate.expired"
	EventRenewFailed  = "certificate.renew_failed"
	templateVersion   = 1
	expiringSource    = "cert-expiring/"
	expiredSource     = "cert-expired/"
	renewFailedSource = "cert-renew-failed/"
	// expiredLookback bounds how long after expiry a certificate is still
	// told about (an installation that was down at the moment of expiry).
	expiredLookback = 7 * 24 * time.Hour
)

// DefaultNoticeDays is used until the platform sets its own (系统设置 >
// 其他设置 > 证书到期提醒).
var DefaultNoticeDays = []int{30, 14, 7, 3, 1}

// MaxNoticeDays bounds a notice day (the renewal window is 30 days; 60 lets
// an uploaded certificate be replaced in time).
const MaxNoticeDays = 60

// ValidNoticeDays: 1..8 distinct days, each 1..MaxNoticeDays, descending.
func ValidNoticeDays(days []int) bool {
	if len(days) < 1 || len(days) > 8 {
		return false
	}
	for index, day := range days {
		if day < 1 || day > MaxNoticeDays || index > 0 && days[index-1] <= day {
			return false
		}
	}
	return true
}

// Enqueuer is notification.Store.
type Enqueuer interface {
	EnqueueTx(context.Context, pgx.Tx, notification.EnqueueRequest) (notification.EnqueueResult, error)
}

// Notifier finds due reminders.
type Notifier struct {
	pool       *pgxpool.Pool
	enqueuer   Enqueuer
	now        func() time.Time
	noticeDays func(context.Context, pgx.Tx) ([]int, error)
}

func New(pool *pgxpool.Pool, enqueuer Enqueuer, now func() time.Time,
	noticeDays func(context.Context, pgx.Tx) ([]int, error)) (*Notifier, error) {
	if pool == nil || enqueuer == nil || now == nil || noticeDays == nil {
		return nil, errors.New("certificate notifier dependencies are missing")
	}
	return &Notifier{pool: pool, enqueuer: enqueuer, now: now, noticeDays: noticeDays}, nil
}

// expiring is one certificate version inside a notice window.
type expiring struct {
	scopeID, assetID, versionID, recipient uuid.UUID
	name                                   string
	sans                                   []string
	notAfter                               time.Time
	threshold                              int
}

// NotifyExpiring enqueues every due expiry reminder of up to limit
// certificate versions (and an expired notice for active versions that
// expired in the last 7 days) and returns how many were enqueued.
func (n *Notifier) NotifyExpiring(ctx context.Context, limit int) (int, error) {
	if limit < 1 || limit > 10_000 {
		return 0, errors.New("certificate notifier limit out of range")
	}
	enqueued := 0
	err := pgx.BeginFunc(ctx, n.pool, func(tx pgx.Tx) error {
		days, err := n.noticeDays(ctx, tx)
		if err != nil {
			return err
		}
		if !ValidNoticeDays(days) {
			days = DefaultNoticeDays
		}
		now := n.now().UTC()
		// The active version of each live, unrevoked certificate whose not_after
		// is within the widest notice window, or passed in the last 7 days
		// (told as expired). The threshold is the smallest notice day not
		// shorter than the time left: a certificate with 6 days left is past its
		// 7-day notice. Recipients: certificateRecipients.
		rows, err := tx.Query(ctx, `WITH active AS (
				SELECT DISTINCT ON (tenant_scope_id,asset_id) tenant_scope_id,asset_id,version_id
				FROM certificate_asset_activation_facts ORDER BY tenant_scope_id,asset_id,sequence DESC
			)
			SELECT asset.tenant_scope_id,asset.id,version.id,asset.name,version.sans,version.not_after,
			       version.imported_by_user_id
			FROM certificate_assets asset
			JOIN active ON active.tenant_scope_id=asset.tenant_scope_id AND active.asset_id=asset.id
			JOIN certificate_asset_versions version ON version.tenant_scope_id=asset.tenant_scope_id
			  AND version.asset_id=asset.id AND version.id=active.version_id
			JOIN access_scopes scope ON scope.id=asset.tenant_scope_id AND scope.kind='tenant'
			WHERE asset.deleted_at IS NULL AND version.not_after > $3
			  AND version.not_after <= $1
			  AND NOT EXISTS (SELECT 1 FROM certificate_asset_revocation_facts revoked
			      WHERE revoked.tenant_scope_id=asset.tenant_scope_id AND revoked.asset_id=asset.id
			        AND revoked.version_id=version.id)
			ORDER BY version.not_after,version.id LIMIT $2`, now.Add(time.Duration(days[0])*24*time.Hour), limit,
			now.Add(-expiredLookback))
		if err != nil {
			return fmt.Errorf("read expiring certificates: %w", err)
		}
		var due []expiring
		for rows.Next() {
			var item expiring
			var importer uuid.UUID
			if err := rows.Scan(&item.scopeID, &item.assetID, &item.versionID, &item.name, &item.sans,
				&item.notAfter, &importer); err != nil {
				rows.Close()
				return fmt.Errorf("scan expiring certificate: %w", err)
			}
			left := item.notAfter.Sub(now)
			item.threshold = days[0]
			for _, day := range days {
				if time.Duration(day)*24*time.Hour >= left {
					item.threshold = day
				}
			}
			item.recipient = importer
			due = append(due, item)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return fmt.Errorf("iterate expiring certificates: %w", err)
		}
		for _, item := range due {
			recipients, err := certificateRecipients(ctx, tx, item.scopeID, item.recipient)
			if err != nil {
				return err
			}
			eventType, source := EventExpiring, expiringSource+item.versionID.String()+"/"+strconv.Itoa(item.threshold)
			values := map[string]string{
				"certificate_name": item.name, "domains": domainList(item.sans), "not_after": shanghai(item.notAfter),
			}
			if item.notAfter.After(now) {
				values["days_left"] = strconv.Itoa(int(item.notAfter.Sub(now).Hours() / 24))
			} else {
				eventType, source = EventExpired, expiredSource+item.versionID.String()
			}
			for _, recipient := range recipients {
				sent, err := n.enqueue(ctx, tx, item.scopeID, recipient, source, eventType, values)
				if err != nil {
					return err
				}
				if sent {
					enqueued++
				}
			}
		}
		return nil
	})
	return enqueued, err
}

// RenewFailedTx tells the owner of a renewal order that it failed, inside
// the transaction that failed it. Orders that are not renewals are ignored
// (a first issuance failure is shown where it was requested).
func RenewFailedTx(ctx context.Context, tx pgx.Tx, enqueuer Enqueuer, scopeID, orderID uuid.UUID, code string) error {
	if enqueuer == nil {
		return nil
	}
	var parent *uuid.UUID
	var domains []string
	var owner uuid.UUID
	var notAfter *time.Time
	if err := tx.QueryRow(ctx, `SELECT child.renewal_of_order_id,child.domains,child.created_by_user_id,parent.not_after
		FROM certificate_orders child
		LEFT JOIN certificate_orders parent ON parent.scope_id=child.scope_id AND parent.id=child.renewal_of_order_id
		WHERE child.scope_id=$1 AND child.id=$2`, scopeID, orderID).Scan(&parent, &domains, &owner, &notAfter); err != nil {
		return fmt.Errorf("read failed certificate order: %w", err)
	}
	if parent == nil {
		return nil
	}
	expires := "未知"
	if notAfter != nil {
		expires = shanghai(*notAfter)
	}
	values := map[string]string{"domains": domainList(domains), "reason": failureReason(code), "not_after": expires}
	recipients, err := certificateRecipients(ctx, tx, scopeID, owner)
	if err != nil {
		return err
	}
	for _, recipient := range recipients {
		if _, err := (&Notifier{enqueuer: enqueuer}).enqueue(ctx, tx, scopeID, recipient,
			renewFailedSource+orderID.String(), EventRenewFailed, values); err != nil {
			return err
		}
	}
	return nil
}

// certificateRecipients: the owner when still an active member, plus the
// active members holding certificates.manage; sorted, distinct.
func certificateRecipients(ctx context.Context, tx pgx.Tx, scopeID, owner uuid.UUID) ([]uuid.UUID, error) {
	rows, err := tx.Query(ctx, `SELECT DISTINCT membership.user_id FROM memberships membership
		JOIN users member ON member.id=membership.user_id AND member.status='active'
		WHERE membership.scope_id=$1 AND membership.status='active' AND (membership.user_id=$2 OR EXISTS (
			SELECT 1 FROM role_assignments assignment
			JOIN role_permissions grant_row ON grant_row.role_id=assignment.role_id
			 AND grant_row.permission_name='certificates.manage'
			WHERE assignment.scope_id=membership.scope_id AND assignment.user_id=membership.user_id))
		ORDER BY membership.user_id`, scopeID, owner)
	if err != nil {
		return nil, fmt.Errorf("read certificate notice recipients: %w", err)
	}
	return pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
}

// enqueue sends one event under a savepoint: a recipient whose delivery
// fails (or who was told already) never blocks the others.
func (n *Notifier) enqueue(ctx context.Context, tx pgx.Tx, scopeID, recipient uuid.UUID, source, eventType string,
	values map[string]string) (bool, error) {
	var already bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM notification_events
		WHERE scope_id=$1 AND recipient_user_id=$2 AND source_event_id=$3 AND event_type=$4)`,
		scopeID, recipient, source, eventType).Scan(&already); err != nil {
		return false, fmt.Errorf("read certificate notice: %w", err)
	}
	if already {
		return false, nil
	}
	templateID := eventType + ".zh-cn"
	templateContext := notification.TemplateContext{}
	for name, value := range values {
		templateContext[name] = notification.PublicValue(value)
	}
	request := notification.EnqueueRequest{
		ScopeID: scopeID, RecipientID: recipient, SourceEventID: source, EventType: eventType,
		Policy: notification.DeliveryTenantSubscribed,
		Templates: map[notification.Channel]notification.TemplateRef{
			notification.ChannelSMS:   {ID: templateID, Version: templateVersion, Channel: notification.ChannelSMS},
			notification.ChannelEmail: {ID: templateID, Version: templateVersion, Channel: notification.ChannelEmail},
		},
		Contexts: map[notification.Channel]notification.TemplateContext{
			notification.ChannelSMS: templateContext, notification.ChannelEmail: templateContext},
		AuditRequestID: source,
	}
	savepoint, err := tx.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = savepoint.Rollback(context.Background()) }()
	if _, err := n.enqueuer.EnqueueTx(ctx, savepoint, request); err != nil {
		if errors.Is(err, notification.ErrTenantScopeDenied) {
			return false, nil
		}
		return false, fmt.Errorf("enqueue %s: %w", eventType, err)
	}
	return true, savepoint.Commit(ctx)
}

// domainList is at most three names, then "等N个".
func domainList(names []string) string {
	sorted := slices.Clone(names)
	slices.Sort(sorted)
	if len(sorted) <= 3 {
		return joinNames(sorted)
	}
	return joinNames(sorted[:3]) + "等" + strconv.Itoa(len(sorted)) + "个"
}

func joinNames(names []string) string {
	result := ""
	for index, name := range names {
		if index > 0 {
			result += "、"
		}
		result += name
	}
	return result
}

func shanghai(value time.Time) string {
	location, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		location = time.FixedZone("CST", 8*3600)
	}
	return value.In(location).Format("2006-01-02 15:04")
}

// failureReason is a short Chinese reason for a failure code (the console's
// certificateFailureCodes.ts has the full list).
func failureReason(code string) string {
	switch code {
	case "acme_rate_limited":
		return "证书签发请求过于频繁"
	case "acme_authorization_invalid":
		return "证书签发机构验证域名失败（请检查解析或 DNS API）"
	case "acme_order_rejected":
		return "证书签发机构拒绝了订单"
	case "acme_account_unavailable":
		return "证书签发机构账户不可用（EAB 凭据可能失效）"
	case "acme_directory_unavailable":
		return "证书签发机构暂时无法连接"
	case "acme_challenge_publish_failed", "acme_challenge_propagation_failed":
		return "写入或生效验证记录失败"
	case "acme_dns_provider_unavailable", "acme_dns_provider_invalid":
		return "DNS API 不可用或配置无效"
	case "acme_http01_no_serving_node", "acme_http01_node_unsupported":
		return "没有可完成文件验证的节点"
	case "acme_timeout":
		return "签发处理超时"
	default:
		return "签发失败（" + code + "）"
	}
}
