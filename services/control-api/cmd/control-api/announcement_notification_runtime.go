package main

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/cdnca/cdnca/services/control-api/internal/announcement"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/notificationcontrol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	errAnnouncementNotificationAdapterInvalid = errors.New("announcement_notification_adapter_invalid")
	errAnnouncementNotificationNoticeInvalid  = errors.New("announcement_notification_notice_invalid")
	errAnnouncementNotificationEnqueueFailed  = errors.New("announcement_notification_enqueue_failed")
)

const (
	announcementPublishedEventType             = "announcement.published"
	announcementPublishedTemplateID            = "announcement_published"
	announcementPublishedLegacyTemplateVersion = uint64(1)
)

type announcementNotificationOutbox struct {
	store *notification.Store
}

func newAnnouncementNotificationOutbox(store *notification.Store) (*announcementNotificationOutbox, error) {
	if store == nil {
		return nil, errAnnouncementNotificationAdapterInvalid
	}
	return &announcementNotificationOutbox{store: store}, nil
}

func (outbox *announcementNotificationOutbox) EnqueuePublication(
	ctx context.Context,
	tx pgx.Tx,
	notice announcement.PublicationNotice,
) error {
	if outbox == nil || outbox.store == nil {
		return errAnnouncementNotificationAdapterInvalid
	}
	if err := validateAnnouncementPublicationNotice(ctx, tx, notice); err != nil {
		return err
	}

	templates, err := notificationcontrol.ActiveTemplateRefs(ctx, tx, announcementPublishedTemplateID)
	if err != nil {
		return fmt.Errorf("%w: %w", errAnnouncementNotificationEnqueueFailed, err)
	}
	sourceEventID := announcementPublicationSourceEventID(notice.AnnouncementID, notice.Version)
	contexts := announcementPublishedContextsForTemplates(notice.Title, notice.Body, templates)
	contextValidationPolicies := make(map[notification.Channel]notification.ContextValidationPolicy)
	if emailRef, exists := templates[notification.ChannelEmail]; exists {
		policy, err := notification.AnnouncementPublishedEmailContextValidationPolicy(emailRef)
		if err != nil {
			return fmt.Errorf("%w: %w", errAnnouncementNotificationEnqueueFailed, err)
		}
		contextValidationPolicies[notification.ChannelEmail] = policy
	}
	for _, recipientID := range notice.RecipientIDs {
		_, err := outbox.store.EnqueueTx(ctx, tx, notification.EnqueueRequest{
			ScopeID:                   notice.ScopeID,
			RecipientID:               recipientID,
			SourceEventID:             sourceEventID,
			EventType:                 announcementPublishedEventType,
			Policy:                    notification.DeliveryTenantSubscribed,
			Templates:                 templates,
			Contexts:                  contexts,
			ContextValidationPolicies: contextValidationPolicies,
			AuditRequestID: announcementPublicationAuditRequestID(
				notice.AnnouncementID,
				notice.Version,
				recipientID,
			),
		})
		if err != nil {
			return fmt.Errorf("%w: %w", errAnnouncementNotificationEnqueueFailed, err)
		}
	}
	return nil
}

func validateAnnouncementPublicationNotice(
	ctx context.Context,
	tx pgx.Tx,
	notice announcement.PublicationNotice,
) error {
	if ctx == nil || tx == nil || notice.ScopeID == uuid.Nil ||
		notice.AnnouncementID == uuid.Nil || notice.Version < 1 || notice.PublishedAt.IsZero() ||
		notice.Title == "" || notice.Body == "" || len(notice.RecipientIDs) == 0 ||
		len(notice.RecipientIDs) != len(notice.InboxEventIDs) {
		return errAnnouncementNotificationNoticeInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	recipients := make(map[uuid.UUID]struct{}, len(notice.RecipientIDs))
	inboxEvents := make(map[uuid.UUID]struct{}, len(notice.InboxEventIDs))
	for index, recipientID := range notice.RecipientIDs {
		inboxEventID := notice.InboxEventIDs[index]
		if recipientID == uuid.Nil || inboxEventID == uuid.Nil {
			return errAnnouncementNotificationNoticeInvalid
		}
		if _, duplicate := recipients[recipientID]; duplicate {
			return errAnnouncementNotificationNoticeInvalid
		}
		if _, duplicate := inboxEvents[inboxEventID]; duplicate {
			return errAnnouncementNotificationNoticeInvalid
		}
		recipients[recipientID] = struct{}{}
		inboxEvents[inboxEventID] = struct{}{}
	}
	return nil
}

func announcementPublishedTemplates() map[notification.Channel]notification.TemplateRef {
	// Retained for legacy test fixtures; publication resolves active versions from PostgreSQL.
	return map[notification.Channel]notification.TemplateRef{
		notification.ChannelEmail: {
			ID: announcementPublishedTemplateID, Version: announcementPublishedLegacyTemplateVersion, Channel: notification.ChannelEmail,
		},
		notification.ChannelSMS: {
			ID: announcementPublishedTemplateID, Version: announcementPublishedLegacyTemplateVersion, Channel: notification.ChannelSMS,
		},
	}
}

func announcementPublishedContexts(title, body string) map[notification.Channel]notification.TemplateContext {
	return announcementPublishedContextsForTemplates(title, body, announcementPublishedTemplates())
}

func announcementPublishedContextsForTemplates(
	title, body string,
	_ map[notification.Channel]notification.TemplateRef,
) map[notification.Channel]notification.TemplateContext {
	contexts := map[notification.Channel]notification.TemplateContext{
		notification.ChannelEmail: notification.AnnouncementPublishedEmailContext(title, body),
	}
	if len(title) > notification.MaxVariableValueBytes || len(body) > notification.MaxVariableValueBytes ||
		len("title")+len(title)+len("body")+len(body) > notification.MaxContextBytes {
		return contexts
	}
	smsContext := notification.TemplateContext{
		"title": notification.PublicValue(title),
		"body":  notification.PublicValue(body),
	}
	contexts[notification.ChannelSMS] = smsContext
	return contexts
}

func announcementPublicationSourceEventID(announcementID uuid.UUID, version int64) string {
	return "announcement:" + announcementID.String() + ":v" + strconv.FormatInt(version, 10)
}

func announcementPublicationAuditRequestID(announcementID uuid.UUID, version int64, recipientID uuid.UUID) string {
	return "announcement-publication:" + announcementID.String() + ":v" +
		strconv.FormatInt(version, 10) + ":" + recipientID.String()
}

var _ announcement.PublicationOutbox = (*announcementNotificationOutbox)(nil)
