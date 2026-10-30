package announcement

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestBoundedSnapshotItemsTreatsLimitAsMaximum(t *testing.T) {
	for _, test := range []struct {
		name, body string
		limit      int
		count      int
	}{
		{name: "default 20 maximum body", body: strings.Repeat("x", MaxBodyBytes), limit: DefaultPageSize, count: DefaultPageSize},
		{name: "requested 100 maximum body", body: strings.Repeat("x", MaxBodyBytes), limit: MaxPageSize, count: MaxPageSize},
		{name: "JSON escape boundary", body: strings.Repeat("<", MaxBodyBytes), limit: DefaultPageSize, count: 4},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidates := make([]Announcement, test.count)
			for index := range candidates {
				candidates[index] = snapshotTestAnnouncement(test.body)
			}
			items, cursor, err := boundedSnapshotItems(candidates, test.limit, func(Announcement) string {
				return strings.Repeat("c", maxSnapshotCursorBytes)
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(items) == 0 || len(items) >= test.count || len(items) > test.limit || len(cursor) != maxSnapshotCursorBytes {
				t.Fatalf("items=%d count=%d limit=%d cursor=%d", len(items), test.count, test.limit, len(cursor))
			}
			encoded, err := json.Marshal(AnnouncementPage{Items: items, NextCursor: cursor})
			if err != nil {
				t.Fatal(err)
			}
			if len(encoded)+1 > snapshotResponseBytes {
				t.Fatalf("encoded page with newline = %d bytes", len(encoded)+1)
			}
		})
	}

	small := make([]Announcement, MaxPageSize)
	for index := range small {
		small[index] = snapshotTestAnnouncement("body")
	}
	items, cursor, err := boundedSnapshotItems(small, DefaultPageSize, func(Announcement) string { return "cursor" })
	if err != nil || len(items) != DefaultPageSize || cursor == "" {
		t.Fatalf("count bounded page items=%d cursor=%q err=%v", len(items), cursor, err)
	}
}

func TestBoundedSnapshotItemsFitsMaximumSchemaItems(t *testing.T) {
	announcementItem := snapshotTestAnnouncement(strings.Repeat("<", MaxBodyBytes))
	announcementItem.Title = strings.Repeat("<", MaxTitleRunes)
	announcementItem.Audience.UserIDs = make([]uuid.UUID, MaxAudienceTargets)
	for index := range announcementItem.Audience.UserIDs {
		announcementItem.Audience.UserIDs[index] = uuid.New()
	}
	announcementItems, cursor, err := boundedSnapshotItems([]Announcement{announcementItem}, MaxPageSize, func(Announcement) string { return "unused" })
	if err != nil || len(announcementItems) != 1 || cursor != "" {
		t.Fatalf("maximum announcement item items=%d cursor=%q err=%v", len(announcementItems), cursor, err)
	}
	assertSnapshotPageBudget(t, AnnouncementPage{Items: announcementItems})

	inboxItem := InboxMessage{
		ID: uuid.New(), AnnouncementID: uuid.New(), AnnouncementVersion: 1,
		Title: strings.Repeat("<", MaxTitleRunes), Body: strings.Repeat("<", MaxBodyBytes),
		PublishedAt: time.Date(2026, 7, 23, 8, 0, 0, 0, time.UTC), StateRevision: 1,
	}
	inboxItems, cursor, err := boundedSnapshotItems([]InboxMessage{inboxItem}, MaxPageSize, func(InboxMessage) string { return "unused" })
	if err != nil || len(inboxItems) != 1 || cursor != "" {
		t.Fatalf("maximum inbox item items=%d cursor=%q err=%v", len(inboxItems), cursor, err)
	}
	assertSnapshotPageBudget(t, InboxPage{Items: inboxItems})
}

func TestBoundedSnapshotItemsRejectsBrokenInternalInvariant(t *testing.T) {
	item := snapshotTestAnnouncement(strings.Repeat("<", MaxBodyBytes*3))
	if _, _, err := boundedSnapshotItems([]Announcement{item}, DefaultPageSize, func(Announcement) string { return "unused" }); err == nil {
		t.Fatal("oversized internal item was accepted")
	}
	if _, _, err := boundedSnapshotItems([]chan int{make(chan int)}, DefaultPageSize, func(chan int) string { return "unused" }); err == nil {
		t.Fatal("unmarshalable internal item was accepted")
	}
}

func TestBoundedSnapshotItemsUsesExactEnvelopeAndFailsClosedCursor(t *testing.T) {
	t.Run("empty page is an array", func(t *testing.T) {
		items, cursor, err := boundedSnapshotItems([]int(nil), 1, nil)
		if err != nil || items == nil || len(items) != 0 || cursor != "" {
			t.Fatalf("empty page items=%v cursor=%q err=%v", items, cursor, err)
		}
		encoded, err := json.Marshal(struct {
			Items []int `json:"items"`
		}{Items: items})
		if err != nil || string(encoded) != `{"items":[]}` {
			t.Fatalf("empty page wire=%s err=%v", encoded, err)
		}
	})

	t.Run("single exact page needs no cursor reserve", func(t *testing.T) {
		payload := strings.Repeat("x", snapshotResponseBytes-len(`{"items":[]}`)-1-2)
		items, cursor, err := boundedSnapshotItems([]string{payload}, 1, nil)
		if err != nil || len(items) != 1 || cursor != "" {
			t.Fatalf("exact page items=%d cursor=%q err=%v", len(items), cursor, err)
		}
		assertGenericSnapshotPageBudget(t, items, cursor)
	})

	t.Run("nil cursor callback fails closed when truncated", func(t *testing.T) {
		if _, _, err := boundedSnapshotItems([]int{1, 2}, 1, nil); err == nil {
			t.Fatal("nil cursor callback was accepted for a truncated page")
		}
	})

	for _, test := range []struct {
		name   string
		cursor string
	}{
		{name: "empty", cursor: ""},
		{name: "too long", cursor: strings.Repeat("c", maxSnapshotCursorBytes+1)},
	} {
		t.Run(test.name+" cursor rejected", func(t *testing.T) {
			if _, _, err := boundedSnapshotItems([]int{1, 2}, 1, func(int) string { return test.cursor }); err == nil {
				t.Fatalf("invalid cursor length %d was accepted", len(test.cursor))
			}
		})
	}

	t.Run("escaped cursor shrinks exact page and preserves progression", func(t *testing.T) {
		type candidate struct {
			ID   int    `json:"id"`
			Body string `json:"body"`
		}
		baseBody := strings.Repeat("x", snapshotResponseBytes/3-128)
		candidates := []candidate{
			{ID: 1, Body: baseBody},
			{ID: 2, Body: baseBody},
			{ID: 3, Body: baseBody},
		}
		terminalWire, err := json.Marshal(struct {
			Items []candidate `json:"items"`
		}{Items: candidates})
		if err != nil {
			t.Fatal(err)
		}
		remainingBytes := snapshotResponseBytes - len(terminalWire) - 1
		if remainingBytes < 0 {
			t.Fatalf("initial terminal page exceeds budget by %d bytes", -remainingBytes)
		}
		candidates[2].Body += strings.Repeat("x", remainingBytes)

		exactItems, exactCursor, err := boundedSnapshotItems(candidates, len(candidates), nil)
		if err != nil || len(exactItems) != 3 || exactCursor != "" {
			t.Fatalf("exact terminal page items=%d cursor=%q err=%v", len(exactItems), exactCursor, err)
		}
		exactWire, err := json.Marshal(struct {
			Items []candidate `json:"items"`
		}{Items: exactItems})
		if err != nil || len(exactWire)+1 != snapshotResponseBytes {
			t.Fatalf("exact terminal page bytes=%d err=%v", len(exactWire)+1, err)
		}

		candidates = append(candidates, candidate{ID: 4, Body: "tail"})
		cursorFor := func(last candidate) string {
			prefix := strconv.Itoa(last.ID) + ":"
			return prefix + strings.Repeat("<", maxSnapshotCursorBytes-len(prefix))
		}
		firstItems, firstCursor, err := boundedSnapshotItems(candidates, 3, cursorFor)
		if err != nil || len(firstItems) != 2 {
			t.Fatalf("escaped cursor page items=%d cursor=%q err=%v", len(firstItems), firstCursor, err)
		}
		if len(firstCursor) != maxSnapshotCursorBytes || !strings.HasPrefix(firstCursor, "2:") {
			t.Fatalf("escaped cursor length=%d prefix=%q", len(firstCursor), firstCursor[:min(len(firstCursor), 2)])
		}
		assertGenericSnapshotPageBudget(t, firstItems, firstCursor)

		secondItems, secondCursor, err := boundedSnapshotItems(candidates[2:], 3, cursorFor)
		if err != nil || len(secondItems) != 2 || secondCursor != "" {
			t.Fatalf("terminal continuation items=%d cursor=%q err=%v", len(secondItems), secondCursor, err)
		}
		assertGenericSnapshotPageBudget(t, secondItems, secondCursor)

		seen := make(map[int]struct{}, len(candidates))
		for _, item := range append(firstItems, secondItems...) {
			if _, duplicate := seen[item.ID]; duplicate {
				t.Fatalf("duplicate candidate %d", item.ID)
			}
			seen[item.ID] = struct{}{}
		}
		if len(seen) != len(candidates) {
			t.Fatalf("seen=%d candidates=%d", len(seen), len(candidates))
		}
	})
}

func TestBoundedSnapshotItemsProgressesWithoutLossOrDuplicates(t *testing.T) {
	type candidate struct {
		ID   int    `json:"id"`
		Body string `json:"body"`
	}
	candidates := make([]candidate, 9)
	for index := range candidates {
		candidates[index] = candidate{ID: index + 1, Body: strings.Repeat("<>&", 32)}
	}
	remaining := candidates
	seen := make(map[int]struct{}, len(candidates))
	for len(remaining) > 0 {
		items, cursor, err := boundedSnapshotItems(remaining, 2, func(last candidate) string {
			return strconv.Itoa(last.ID)
		})
		if err != nil || len(items) == 0 {
			t.Fatalf("page remaining=%d items=%d cursor=%q err=%v", len(remaining), len(items), cursor, err)
		}
		assertGenericSnapshotPageBudget(t, items, cursor)
		for _, item := range items {
			if _, duplicate := seen[item.ID]; duplicate {
				t.Fatalf("duplicate candidate %d", item.ID)
			}
			seen[item.ID] = struct{}{}
		}
		remaining = remaining[len(items):]
		if len(remaining) > 0 && cursor != strconv.Itoa(items[len(items)-1].ID) {
			t.Fatalf("cursor=%q last=%d", cursor, items[len(items)-1].ID)
		}
		if len(remaining) == 0 && cursor != "" {
			t.Fatalf("terminal cursor=%q", cursor)
		}
	}
	if len(seen) != len(candidates) {
		t.Fatalf("seen=%d candidates=%d", len(seen), len(candidates))
	}
}

func snapshotTestAnnouncement(body string) Announcement {
	now := time.Date(2026, 7, 23, 8, 0, 0, 0, time.UTC)
	return Announcement{
		ID: uuid.New(), ScopeID: uuid.New(), Version: 1, HeadVersion: 1, Revision: 1,
		Status: StatusPublished, Title: "title", Body: body, Audience: Audience{All: true},
		WithdrawalVisibility: VisibilityRetain, PublishedAt: &now, CreatedAt: now, StateChangedAt: now,
	}
}

func assertSnapshotPageBudget(t *testing.T, page any) {
	t.Helper()
	encoded, err := json.Marshal(page)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded)+1 > snapshotResponseBytes {
		t.Fatalf("single-item page with newline = %d bytes", len(encoded)+1)
	}
}

func assertGenericSnapshotPageBudget[T any](t *testing.T, items []T, cursor string) {
	t.Helper()
	encoded, err := json.Marshal(struct {
		Items      []T    `json:"items"`
		NextCursor string `json:"next_cursor,omitempty"`
	}{Items: items, NextCursor: cursor})
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded)+1 > snapshotResponseBytes {
		t.Fatalf("generic page with newline = %d bytes", len(encoded)+1)
	}
}
