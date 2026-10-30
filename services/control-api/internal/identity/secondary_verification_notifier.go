package identity

import (
	"context"
	"errors"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/jackc/pgx/v5"
)

var secondaryVerificationDeadlineZone = func() *time.Location {
	location, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		return time.FixedZone("CST", 8*3600)
	}
	return location
}()

// NotificationSecondaryVerificationNotifier sends the FX57 notice by email and
// SMS (migration templates identity_secondary_verification v1). It is a
// required notice (system_required), but administrators can still switch the
// event off in the notification delivery policy.
type NotificationSecondaryVerificationNotifier struct{ Store *notification.Store }

func (notifier NotificationSecondaryVerificationNotifier) NotifySecondaryVerificationTx(ctx context.Context, tx pgx.Tx, notice SecondaryVerificationNotice) error {
	if notifier.Store == nil {
		return errors.New("secondary verification notification store is unavailable")
	}
	var enabled bool
	err := tx.QueryRow(ctx, `SELECT enabled FROM notification_event_policies WHERE event_type=$1`, SecondaryVerificationEventType).Scan(&enabled)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if errors.Is(err, pgx.ErrNoRows) || !enabled {
		return nil
	}
	_, err = notifier.Store.EnqueueTx(ctx, tx, SecondaryVerificationEnqueueRequest(notice))
	return err
}

func SecondaryVerificationEnqueueRequest(notice SecondaryVerificationNotice) notification.EnqueueRequest {
	deadline := "不限"
	if notice.Deadline != nil {
		deadline = notice.Deadline.In(secondaryVerificationDeadlineZone).Format("2006-01-02 15:04:05")
	}
	return notification.EnqueueRequest{
		ScopeID: notice.ScopeID, RecipientID: notice.UserID, EventType: SecondaryVerificationEventType,
		SourceEventID: "secondary-verification:" + notice.UserID.String() + ":" + notice.RequestedAt.UTC().Format("20060102T150405.000000Z"),
		Policy:        notification.DeliverySystemRequired,
		Templates: map[notification.Channel]notification.TemplateRef{
			notification.ChannelEmail: {ID: secondaryVerificationTemplate, Version: 1, Channel: notification.ChannelEmail},
			notification.ChannelSMS:   {ID: secondaryVerificationTemplate, Version: 1, Channel: notification.ChannelSMS},
		},
		Contexts: map[notification.Channel]notification.TemplateContext{
			notification.ChannelEmail: {"username": notification.PublicValue(notice.Username), "deadline": notification.PublicValue(deadline)},
			notification.ChannelSMS:   {"deadline": notification.PublicValue(deadline)},
		},
		AuditRequestID: notice.RequestID,
	}
}
