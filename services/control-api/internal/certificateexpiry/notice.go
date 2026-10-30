package certificateexpiry

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Notification center events seeded by migration 200, produced from 371.
const (
	NoticeExpiring = "certificate.expiring"
	NoticeExpired  = "certificate.expired"

	noticeManagePermission = "certificates.manage"
	noticeListedDomains    = 5
)

func noticeEventType(stage string) string {
	if stage == StageExpired {
		return NoticeExpired
	}
	return NoticeExpiring
}

// notify enqueues the stage's notice inside the fact transaction under a
// savepoint: a notification failure is logged and never loses the fact,
// event or audit record.
func (scanner *Scanner) notify(ctx context.Context, tx pgx.Tx, fact Fact, now time.Time) {
	if scanner.notices == nil {
		return
	}
	savepoint, err := tx.Begin(ctx)
	if err == nil {
		err = scanner.notifyTx(ctx, savepoint, fact, now)
		if err == nil {
			err = savepoint.Commit(ctx)
		}
		_ = savepoint.Rollback(context.Background())
	}
	if err != nil {
		slog.Warn("certificate expiry notice not enqueued", "version_id", fact.VersionID, "stage", fact.Stage,
			"error", err)
	}
}

// noticeRecipients: the asset's owner while an active member of the tenant;
// an asset without one notifies the tenant's active certificate managers.
func noticeRecipients(ctx context.Context, tx pgx.Tx, fact Fact) ([]uuid.UUID, error) {
	rows, err := tx.Query(ctx, `
		WITH owner AS (
			SELECT asset.owner_user_id AS user_id FROM certificate_assets asset
			JOIN memberships membership ON membership.scope_id=asset.tenant_scope_id
			 AND membership.user_id=asset.owner_user_id AND membership.status='active'
			JOIN users member ON member.id=asset.owner_user_id AND member.status='active'
			WHERE asset.tenant_scope_id=$1 AND asset.id=$2
		)
		SELECT user_id FROM owner
		UNION
		SELECT DISTINCT membership.user_id FROM memberships membership
		JOIN users member ON member.id=membership.user_id AND member.status='active'
		JOIN role_assignments assignment ON assignment.scope_id=membership.scope_id AND assignment.user_id=membership.user_id
		JOIN role_permissions grant_row ON grant_row.role_id=assignment.role_id AND grant_row.permission_name=$3
		WHERE membership.scope_id=$1 AND membership.status='active' AND NOT EXISTS (SELECT 1 FROM owner)
		ORDER BY 1`, fact.TenantScopeID, fact.AssetID, noticeManagePermission)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
}

func (scanner *Scanner) notifyTx(ctx context.Context, tx pgx.Tx, fact Fact, now time.Time) error {
	eventType := noticeEventType(fact.Stage)
	var name string
	var domains []string
	if err := tx.QueryRow(ctx, `SELECT asset.name, v.sans FROM certificate_assets asset
		JOIN certificate_asset_versions v ON v.tenant_scope_id=asset.tenant_scope_id AND v.asset_id=asset.id AND v.id=$3
		WHERE asset.tenant_scope_id=$1 AND asset.id=$2`, fact.TenantScopeID, fact.AssetID, fact.VersionID).
		Scan(&name, &domains); err != nil {
		return fmt.Errorf("read certificate: %w", err)
	}
	listed := strings.Join(domains[:min(len(domains), noticeListedDomains)], "、")
	if len(domains) > noticeListedDomains {
		listed += "等"
	}
	daysLeft := int(math.Ceil(fact.NotAfter.Sub(now).Hours() / 24))
	values := map[string]string{
		"certificate_name": name,
		"not_after":        shanghai(fact.NotAfter),
		"days_left":        strconv.Itoa(max(daysLeft, 0)),
		"domains":          listed,
	}
	templateID := eventType + ".zh-cn"
	// The newest version of each channel's template, filled with exactly the
	// variables it declares, so an edited template keeps enqueueing.
	rows, err := tx.Query(ctx, `SELECT DISTINCT ON (channel) channel, version, variables FROM notification_templates
		WHERE template_id=$1 ORDER BY channel, version DESC`, templateID)
	if err != nil {
		return err
	}
	templates := map[notification.Channel]notification.TemplateRef{}
	contexts := map[notification.Channel]notification.TemplateContext{}
	for rows.Next() {
		var channel string
		var version int64
		var variables []string
		if err := rows.Scan(&channel, &version, &variables); err != nil {
			rows.Close()
			return err
		}
		ref := notification.TemplateRef{ID: templateID, Version: uint64(version), Channel: notification.Channel(channel)}
		context := notification.TemplateContext{}
		for _, variable := range variables {
			context[variable] = notification.PublicValue(values[variable])
		}
		templates[ref.Channel], contexts[ref.Channel] = ref, context
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if len(templates) == 0 {
		return errors.New("certificate expiry notice template is missing")
	}
	recipients, err := noticeRecipients(ctx, tx, fact)
	if err != nil {
		return fmt.Errorf("read certificate notice recipients: %w", err)
	}
	sourceEventID := "certificate-expiry/" + fact.VersionID.String() + "/" + fact.Stage
	for _, recipient := range recipients {
		if _, err := scanner.notices.EnqueueTx(ctx, tx, notification.EnqueueRequest{
			ScopeID: fact.TenantScopeID, RecipientID: recipient, SourceEventID: sourceEventID, EventType: eventType,
			Policy: notification.DeliveryTenantSubscribed, Templates: templates, Contexts: contexts,
			AuditRequestID: sourceEventID,
		}); err != nil {
			return fmt.Errorf("enqueue certificate expiry notice: %w", err)
		}
	}
	return nil
}

func shanghai(value time.Time) string {
	location, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		location = time.FixedZone("CST", 8*3600)
	}
	return value.In(location).Format("2006-01-02 15:04:05")
}
