package announcement

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestPublicationNoticeCarriesFrozenContentAndRecipientEventPairs(t *testing.T) {
	pool := isolatedAnnouncementPool(t)
	fixture := seedAnnouncementFixture(t, pool)
	outbox := &capturingPublicationOutbox{}
	store, err := NewStoreWithDependencies(
		pool, audit.New(pool), outbox, func() time.Time { return fixedNow },
		testCursorKeyring("test", 0x5a), testAnnouncementAuthorizer{},
	)
	if err != nil {
		t.Fatal(err)
	}
	item, err := store.CreateDraft(context.Background(), fixture.admin, CreateDraftRequest{
		Content: Content{Title: "冻结标题", Body: "冻结正文"},
		Audience: Audience{
			UserIDs:  []uuid.UUID{fixture.userA},
			GroupIDs: []uuid.UUID{fixture.groupID},
		},
		WithdrawalVisibility: VisibilityRetain,
		IdempotencyKey:       "notice-create",
		RequestID:            "req-notice-create",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Publish(context.Background(), fixture.admin, PublishRequest{
		AnnouncementID: item.ID, Version: item.Version, ExpectedRevision: item.Revision,
		IdempotencyKey: "notice-publish", RequestID: "req-notice-publish",
	}); err != nil {
		t.Fatal(err)
	}

	notice := outbox.notice
	if notice.ScopeID != fixture.scopeID || notice.AnnouncementID != item.ID || notice.Version != item.Version ||
		notice.Title != "冻结标题" || notice.Body != "冻结正文" || !notice.PublishedAt.Equal(fixedNow) {
		t.Fatalf("publication notice metadata = %+v", notice)
	}
	if len(notice.RecipientIDs) != 2 || len(notice.InboxEventIDs) != len(notice.RecipientIDs) {
		t.Fatalf("publication notice recipients/events = %d/%d", len(notice.RecipientIDs), len(notice.InboxEventIDs))
	}
	seenRecipients := make(map[uuid.UUID]bool, len(notice.RecipientIDs))
	seenEvents := make(map[uuid.UUID]bool, len(notice.InboxEventIDs))
	for index, recipientID := range notice.RecipientIDs {
		eventID := notice.InboxEventIDs[index]
		if recipientID == uuid.Nil || eventID == uuid.Nil || seenRecipients[recipientID] || seenEvents[eventID] {
			t.Fatalf("invalid publication pair %d = %s/%s", index, recipientID, eventID)
		}
		seenRecipients[recipientID] = true
		seenEvents[eventID] = true
		var title, body string
		if err := pool.QueryRow(context.Background(), `SELECT title,body FROM announcement_inbox_events
			WHERE tenant_scope_id=$1 AND id=$2 AND recipient_user_id=$3`, notice.ScopeID, eventID, recipientID).
			Scan(&title, &body); err != nil {
			t.Fatal(err)
		}
		if title != notice.Title || body != notice.Body {
			t.Fatalf("inbox content for pair %d = %q/%q", index, title, body)
		}
	}
}

type capturingPublicationOutbox struct {
	notice PublicationNotice
}

func (o *capturingPublicationOutbox) EnqueuePublication(_ context.Context, _ pgx.Tx, notice PublicationNotice) error {
	if o.notice.AnnouncementID != uuid.Nil {
		return fmt.Errorf("publication notice enqueued more than once")
	}
	o.notice = notice
	return nil
}
