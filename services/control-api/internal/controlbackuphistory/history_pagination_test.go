package controlbackuphistory

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/controlbackup"
)

func paginationReader(t *testing.T, count int) (*FileReader, *time.Time) {
	t.Helper()
	key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("P", ed25519.SeedSize)))
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 9, 28, 1, 0, 0, 0, time.UTC)
	for index := 0; index < count; index++ {
		writeRunFact(t, root, controlbackup.BackupRunStart{Schema: controlbackup.BackupRunStartSchema, BackupID: fmt.Sprintf("run-%02d", index), InstallationID: "11111111-1111-4111-8111-111111111111", SourceClusterID: "control-a", PlanSHA256: strings.Repeat("a", 64), StartedAt: base}, key, false)
	}
	now := base.Add(time.Hour)
	reader, err := NewFileReader(root, "11111111-1111-4111-8111-111111111111", "control-a", map[string]ed25519.PublicKey{"run-key": key.Public().(ed25519.PublicKey)}, []byte(strings.Repeat("x", 32)), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	return reader, &now
}

func TestFileReaderPaginationKeepsFilteredTotalAndStableOrder(t *testing.T) {
	reader, _ := paginationReader(t, 21)
	query := Query{Limit: 10, State: "unknown"}
	for pageIndex := 0; pageIndex < 3; pageIndex++ {
		page, err := reader.List(t.Context(), query)
		if err != nil {
			t.Fatal(err)
		}
		if page.TotalCount != 21 {
			t.Errorf("page %d total=%d, want filtered total 21", pageIndex+1, page.TotalCount)
		}
		wantLength := 10
		if pageIndex == 2 {
			wantLength = 1
		}
		if len(page.Items) != wantLength {
			t.Fatalf("page %d has %d items, want %d", pageIndex+1, len(page.Items), wantLength)
		}
		for index, item := range page.Items {
			if want := fmt.Sprintf("run-%02d", 20-pageIndex*10-index); item.BackupID != want {
				t.Errorf("page %d item %d=%q, want %q", pageIndex+1, index, item.BackupID, want)
			}
		}
		if (pageIndex < 2) != (page.NextCursor != "") {
			t.Fatalf("page %d unexpected cursor presence", pageIndex+1)
		}
		query.Cursor = page.NextCursor
	}
}

func TestFileReaderCursorRejectsChangedFilters(t *testing.T) {
	reader, now := paginationReader(t, 21)
	initial := Query{Limit: 10, State: "unknown", From: now.Add(-time.Hour), To: *now}
	first, err := reader.List(t.Context(), initial)
	if err != nil || first.NextCursor == "" {
		t.Fatalf("first page: %+v, %v", first, err)
	}
	for _, change := range []struct {
		name string
		edit func(*Query)
	}{
		{"backup ID", func(query *Query) { query.BackupID = "run-00" }},
		{"state", func(query *Query) { query.State = "failed" }},
		{"removed state", func(query *Query) { query.State = "" }},
		{"from", func(query *Query) { query.From = query.From.Add(-time.Minute) }},
		{"to", func(query *Query) { query.To = query.To.Add(-time.Minute) }},
	} {
		t.Run(change.name, func(t *testing.T) {
			query := initial
			query.Cursor = first.NextCursor
			change.edit(&query)
			if _, err := reader.List(t.Context(), query); err != ErrInvalidCursor {
				t.Fatalf("changed filter accepted: err=%v", err)
			}
		})
	}
}

func TestFileReaderCursorPreservesDefaultWindowAcrossRequests(t *testing.T) {
	reader, now := paginationReader(t, 21)
	first, err := reader.List(t.Context(), Query{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	*now = now.Add(32 * 24 * time.Hour)
	second, err := reader.List(t.Context(), Query{Limit: 10, Cursor: first.NextCursor})
	if err != nil {
		t.Fatal(err)
	}
	if second.TotalCount != 21 || len(second.Items) != 10 || second.Items[0].BackupID != "run-10" {
		t.Fatalf("cursor changed its time window: %+v", second)
	}
	fresh, err := reader.List(t.Context(), Query{Limit: 10})
	if err != nil || fresh.TotalCount != 0 || len(fresh.Items) != 0 {
		t.Fatalf("fresh request should use the current window: %+v, %v", fresh, err)
	}
}

func TestFileReaderSupportsObservedPageSizesAndCapsAt300(t *testing.T) {
	reader, _ := paginationReader(t, 301)
	for _, limit := range []int{10, 30, 100, 300} {
		page, err := reader.List(t.Context(), Query{Limit: limit})
		if err != nil || len(page.Items) != limit || page.TotalCount != 301 || page.NextCursor == "" {
			t.Errorf("limit %d: count=%d total=%d err=%v", limit, len(page.Items), page.TotalCount, err)
		}
	}
	for _, limit := range []int{-1, 20, 50, 301} {
		if _, err := reader.List(t.Context(), Query{Limit: limit}); err != ErrInvalidInput {
			t.Errorf("limit %d: err=%v, want invalid input", limit, err)
		}
	}
}
