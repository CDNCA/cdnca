package dnsacme

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestDNSProviderCursorIsTamperEvidentAndBoundToScopeAndLimit(t *testing.T) {
	cipher, err := NewAESGCMCredentialCipher("dns-provider-page-test", []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	service := NewService(nil, cipher)
	actor := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant"}
	last := Provider{
		ID: uuid.New(), ScopeID: actor.ScopeID,
		CreatedAt: time.Date(2026, 8, 8, 1, 2, 3, 456000000, time.UTC),
	}

	cursor, err := service.encodeProviderCursor(actor, 20, last)
	if err != nil || cursor == "" || strings.Contains(cursor, actor.ScopeID.String()) {
		t.Fatalf("encodeProviderCursor() = %q, %v", cursor, err)
	}
	decoded, err := service.decodeProviderCursor(actor, ProviderPageRequest{Limit: 20, Cursor: cursor})
	if err != nil || decoded.CreatedAt != last.CreatedAt || decoded.ID != last.ID {
		t.Fatalf("decodeProviderCursor() = %+v, %v", decoded, err)
	}

	otherScope := actor
	otherScope.ScopeID = uuid.New()
	tampered := cursor[:len(cursor)-1] + map[bool]string{true: "A", false: "B"}[cursor[len(cursor)-1] != 'A']
	for name, requestActor := range map[string]struct {
		actor Actor
		input ProviderPageRequest
	}{
		"scope": {otherScope, ProviderPageRequest{Limit: 20, Cursor: cursor}},
		"limit": {actor, ProviderPageRequest{Limit: 10, Cursor: cursor}},
		"bytes": {actor, ProviderPageRequest{Limit: 20, Cursor: tampered}},
	} {
		if _, err := service.decodeProviderCursor(requestActor.actor, requestActor.input); err != ErrInvalidInput {
			t.Fatalf("%s cursor error = %v, want %v", name, err, ErrInvalidInput)
		}
	}
}

func TestDNSProviderKeysetKeepsInsertedRowsOffLaterPages(t *testing.T) {
	created := time.Date(2026, 8, 8, 4, 0, 0, 0, time.UTC)
	first := Provider{ID: uuid.MustParse("ffffffff-ffff-4fff-8fff-ffffffffffff"), CreatedAt: created}
	boundary := Provider{ID: uuid.MustParse("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"), CreatedAt: created}
	oldSameTime := Provider{ID: uuid.MustParse("dddddddd-dddd-4ddd-8ddd-dddddddddddd"), CreatedAt: created}
	oldEarlier := Provider{ID: uuid.MustParse("cccccccc-cccc-4ccc-8ccc-cccccccccccc"), CreatedAt: created.Add(-time.Second)}
	inserted := Provider{ID: uuid.New(), CreatedAt: created.Add(time.Second)}
	cursor := providerPageCursor{CreatedAt: boundary.CreatedAt, ID: boundary.ID}

	rows := []Provider{inserted, first, boundary, oldSameTime, oldEarlier}
	var secondPage []uuid.UUID
	for _, row := range rows {
		if row.CreatedAt.Before(cursor.CreatedAt) || row.CreatedAt.Equal(cursor.CreatedAt) && row.ID.String() < cursor.ID.String() {
			secondPage = append(secondPage, row.ID)
		}
	}
	if len(secondPage) != 2 || secondPage[0] != oldSameTime.ID || secondPage[1] != oldEarlier.ID {
		t.Fatalf("second page IDs = %v", secondPage)
	}

	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test file")
	}
	source, err := os.ReadFile(filepath.Join(filepath.Dir(currentFile), "store.go"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, required := range []string{
		"created_at < $3 OR (created_at = $3 AND id < $4)",
		"ORDER BY created_at DESC, id DESC",
		"LIMIT $5",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("provider keyset query missing %q", required)
		}
	}
}

func TestDNSProviderPageRequestEnforcesLimitBounds(t *testing.T) {
	for _, input := range []ProviderPageRequest{{Limit: 0}, {Limit: 1}, {Limit: 100}} {
		if err := validateProviderPageRequest(input); err != nil {
			t.Fatalf("validateProviderPageRequest(%+v) = %v", input, err)
		}
	}
	for _, input := range []ProviderPageRequest{{Limit: -1}, {Limit: 101}, {Limit: 1, Cursor: strings.Repeat("x", 4097)}} {
		if err := validateProviderPageRequest(input); err != ErrInvalidInput {
			t.Fatalf("validateProviderPageRequest(%+v) = %v, want %v", input, err, ErrInvalidInput)
		}
	}
}
