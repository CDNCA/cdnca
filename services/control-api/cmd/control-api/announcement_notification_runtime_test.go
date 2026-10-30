package main

import (
	"context"
	"errors"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/announcement"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
)

func TestAnnouncementNotificationAdapterStableContractErrors(t *testing.T) {
	if adapter, err := newAnnouncementNotificationOutbox(nil); adapter != nil ||
		!errors.Is(err, errAnnouncementNotificationAdapterInvalid) {
		t.Fatalf("nil store adapter = (%#v, %v)", adapter, err)
	}
	adapter := &announcementNotificationOutbox{}
	err := adapter.EnqueuePublication(context.Background(), nil, announcement.PublicationNotice{})
	if !errors.Is(err, errAnnouncementNotificationAdapterInvalid) {
		t.Fatalf("invalid adapter error = %v", err)
	}
	if got := announcementPublicationSourceEventID(uuid.MustParse("00000000-0000-0000-0000-000000000001"), 9); got != "announcement:00000000-0000-0000-0000-000000000001:v9" {
		t.Fatalf("source event id = %q", got)
	}
	if got := announcementPublicationAuditRequestID(
		uuid.MustParse("00000000-0000-0000-0000-000000000001"),
		9,
		uuid.MustParse("00000000-0000-0000-0000-000000000002"),
	); got != "announcement-publication:00000000-0000-0000-0000-000000000001:v9:00000000-0000-0000-0000-000000000002" {
		t.Fatalf("audit request id = %q", got)
	}
	templates := announcementPublishedTemplates()
	if len(announcementPublishedContexts("title", "body")) != 2 || len(templates) != 2 ||
		templates[notification.ChannelEmail].ID != announcementPublishedTemplateID ||
		templates[notification.ChannelSMS].ID != announcementPublishedTemplateID {
		t.Fatal("fixed announcement notification contract is unavailable")
	}
}
