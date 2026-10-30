package apikey

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/apikeycredential"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

func TestAPIKeyListPageSnapshotKeysetContract(t *testing.T) {
	snapshot := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	scopeID := uuid.MustParse("00000000-0000-4000-8000-000000000101")
	userID := uuid.MustParse("00000000-0000-4000-8000-000000000102")
	rows := []Key{
		pageKey(5, scopeID, userID, "cfk_AAAAAAAAAAAAAAAAAAAAAA", "Alpha", StatusActive, snapshot.Add(-time.Minute)),
		pageKey(4, scopeID, userID, "cfk_BBBBBBBBBBBBBBBBBBBBBB", "Beta", StatusActive, snapshot.Add(-time.Minute)),
		pageKey(3, scopeID, userID, "cfk_CCCCCCCCCCCCCCCCCCCCCC", "Gamma", StatusActive, snapshot.Add(-2*time.Minute)),
		pageKey(2, scopeID, userID, "cfk_DDDDDDDDDDDDDDDDDDDDDD", "Delta", StatusActive, snapshot.Add(-3*time.Minute)),
		pageKey(1, scopeID, userID, "cfk_EEEEEEEEEEEEEEEEEEEEEE", "Epsilon", StatusActive, snapshot.Add(-4*time.Minute)),
	}
	reader := &pageReaderFixture{rows: &rows}
	service := pageTestService(snapshot, scopeID, userID, reader.read)
	principal := tenantPagePrincipal(scopeID, userID)

	first, err := service.ListSelfPage(t.Context(), principal, APIKeyListInput{Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if got := pageIDs(first.Items); !reflect.DeepEqual(got, []int{5, 4}) || first.NextCursor == "" || !first.SnapshotAt.Equal(snapshot) {
		t.Fatalf("first page = ids=%v cursor=%t snapshot=%s", got, first.NextCursor != "", first.SnapshotAt)
	}

	// Rows created after the first snapshot never enter this traversal. Physical
	// deletion removes a row, while status changes are observed in later pages.
	rows = append(rows, pageKey(9, scopeID, userID, "cfk_FFFFFFFFFFFFFFFFFFFFFF", "Late", StatusActive, snapshot.Add(time.Second)))
	rows = removePageKey(rows, 3)
	for index := range rows {
		if rows[index].ID == pageUUID(2) {
			rows[index].Status = StatusRevoked
		}
	}
	second, err := service.ListSelfPage(t.Context(), principal, APIKeyListInput{Limit: 2, Cursor: first.NextCursor})
	if err != nil {
		t.Fatal(err)
	}
	if got := pageIDs(second.Items); !reflect.DeepEqual(got, []int{2, 1}) || second.NextCursor != "" || !second.SnapshotAt.Equal(snapshot) {
		t.Fatalf("second page = ids=%v cursor=%q snapshot=%s", got, second.NextCursor, second.SnapshotAt)
	}
	if second.Items[0].Status != StatusRevoked {
		t.Fatalf("later page hid committed status update: %#v", second.Items[0])
	}
	if len(reader.requests) != 2 || reader.requests[0].HasAfter || !reader.requests[1].HasAfter ||
		reader.requests[0].Limit != 3 || reader.requests[1].AfterID != pageUUID(4) ||
		!reader.requests[1].AfterCreatedAt.Equal(snapshot.Add(-time.Minute)) {
		t.Fatalf("store requests = %#v", reader.requests)
	}
	if _, exists := reflect.TypeOf(apiKeyPageStoreRequest{}).FieldByName("Cursor"); exists {
		t.Fatal("store request must not receive opaque cursor text")
	}
}

func TestAPIKeyListPageFilterCursorAndIsolationContract(t *testing.T) {
	now := time.Date(2026, 8, 7, 13, 0, 0, 0, time.UTC)
	scopeID := uuid.MustParse("00000000-0000-4000-8000-000000000201")
	userID := uuid.MustParse("00000000-0000-4000-8000-000000000202")
	targetScopeID := uuid.MustParse("00000000-0000-4000-8000-000000000203")
	targetUserID := uuid.MustParse("00000000-0000-4000-8000-000000000204")
	rows := []Key{
		pageKey(2, scopeID, userID, "cfk_AAAAAAAAAAAAAAAAAAAAAA", "Alpha Key", StatusActive, now.Add(-time.Minute)),
		pageKey(3, scopeID, userID, "cfk_AAAAAAAAAAAAAAAAAAAAAA", "Alpha Key", StatusActive, now.Add(-2*time.Minute)),
		pageKey(1, targetScopeID, targetUserID, "cfk_BBBBBBBBBBBBBBBBBBBBBB", "Admin Key", StatusActive, now.Add(-time.Minute)),
	}
	reader := &pageReaderFixture{rows: &rows}
	service := pageTestService(now, scopeID, userID, reader.read)
	principal := tenantPagePrincipal(scopeID, userID)

	page, err := service.ListSelfPage(t.Context(), principal, APIKeyListInput{
		Limit: 1, Status: " ACTIVE ", Name: "  ALPHA KEY ", KeyID: " cfk_AAAAAAAAAAAAAAAAAAAAAA ",
	})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("filtered page = %#v, err=%v", page, err)
	}
	request := reader.requests[len(reader.requests)-1]
	if request.ScopeID != scopeID || request.UserID != userID || request.Status != StatusActive ||
		request.Name != "alpha key" || request.KeyID != "cfk_AAAAAAAAAAAAAAAAAAAAAA" {
		t.Fatalf("normalized owner request = %#v", request)
	}

	before := len(reader.requests)
	for _, changed := range []APIKeyListInput{
		{Limit: 2, Status: "active", Name: "alpha key", KeyID: "cfk_AAAAAAAAAAAAAAAAAAAAAA", Cursor: page.NextCursor},
		{Limit: 1, Status: "revoked", Name: "alpha key", KeyID: "cfk_AAAAAAAAAAAAAAAAAAAAAA", Cursor: page.NextCursor},
		{Limit: 1, Status: "active", Name: "beta", KeyID: "cfk_AAAAAAAAAAAAAAAAAAAAAA", Cursor: page.NextCursor},
		{Limit: 1, Status: "active", Name: "alpha key", KeyID: "cfk_BBBBBBBBBBBBBBBBBBBBBB", Cursor: page.NextCursor},
	} {
		if _, err := service.ListSelfPage(t.Context(), principal, changed); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("changed cursor binding error = %v", err)
		}
	}
	if _, err := service.ListSelfPage(t.Context(), tenantPagePrincipal(targetScopeID, userID), APIKeyListInput{Limit: 1, Cursor: page.NextCursor}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-scope cursor error = %v", err)
	}
	if len(reader.requests) != before {
		t.Fatal("invalid cursor reached the store")
	}

	for _, input := range []APIKeyListInput{
		{Limit: -1}, {Limit: 101}, {Status: "unknown"}, {Name: "   "}, {Name: strings.Repeat("x", 129)},
		{KeyID: "cfk_invalid"}, {Cursor: "not-a-signed-cursor"},
	} {
		if _, err := service.ListSelfPage(t.Context(), principal, input); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("invalid input %#v error = %v", input, err)
		}
	}

	admin := identity.Principal{
		UserID:    uuid.MustParse("00000000-0000-4000-8000-000000000205"),
		ScopeID:   uuid.MustParse("00000000-0000-4000-8000-000000000206"),
		ScopeKind: "platform", Permissions: []string{"api_keys.admin.manage"},
	}
	service.pageTargetPrincipal = func(context.Context, uuid.UUID, uuid.UUID) (identity.Principal, error) {
		return tenantPagePrincipal(targetScopeID, targetUserID), nil
	}
	adminPage, err := service.AdminListPage(t.Context(), admin, targetScopeID, targetUserID, APIKeyListInput{Limit: 10})
	if err != nil || len(adminPage.Items) != 1 || adminPage.Items[0].UserID != targetUserID {
		t.Fatalf("admin page = %#v, err=%v", adminPage, err)
	}
	request = reader.requests[len(reader.requests)-1]
	if request.ScopeID != targetScopeID || request.UserID != targetUserID {
		t.Fatalf("admin request escaped exact target = %#v", request)
	}
	service.pageTargetPrincipal = func(context.Context, uuid.UUID, uuid.UUID) (identity.Principal, error) {
		return identity.Principal{}, ErrNotFound
	}
	before = len(reader.requests)
	if _, err := service.AdminListPage(t.Context(), admin, targetScopeID, targetUserID, APIKeyListInput{Limit: 10}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("disabled target error = %v", err)
	}
	if len(reader.requests) != before {
		t.Fatal("disabled target reached the store")
	}
	service.pageTargetPrincipal = func(context.Context, uuid.UUID, uuid.UUID) (identity.Principal, error) {
		return tenantPagePrincipal(targetScopeID, targetUserID), nil
	}
	for name, scopeID := range map[string]uuid.UUID{
		"missing":    uuid.Nil,
		"mismatched": scopeID,
	} {
		before = len(reader.requests)
		if _, err := service.AdminListPage(t.Context(), admin, scopeID, targetUserID, APIKeyListInput{Limit: 10}); !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("%s explicit tenant scope error = %v", name, err)
		}
		if len(reader.requests) != before {
			t.Fatalf("%s explicit tenant scope reached the store", name)
		}
	}
}

func TestAPIKeyListCursorTTLAndLegacyCompatibility(t *testing.T) {
	issuedAt := time.Date(2026, 8, 7, 15, 0, 0, 0, time.UTC)
	currentTime := issuedAt
	scopeID := uuid.MustParse("00000000-0000-4000-8000-000000000401")
	userID := uuid.MustParse("00000000-0000-4000-8000-000000000402")
	rows := []Key{
		pageKey(2, scopeID, userID, "cfk_AAAAAAAAAAAAAAAAAAAAAA", "First", StatusActive, issuedAt.Add(-time.Minute)),
		pageKey(1, scopeID, userID, "cfk_BBBBBBBBBBBBBBBBBBBBBB", "Second", StatusActive, issuedAt.Add(-2*time.Minute)),
	}
	reader := &pageReaderFixture{rows: &rows}
	service := pageTestService(issuedAt, scopeID, userID, reader.read)
	service.now = func() time.Time { return currentTime }
	principal := tenantPagePrincipal(scopeID, userID)

	first, err := service.ListSelfPage(t.Context(), principal, APIKeyListInput{Limit: 1})
	if err != nil || first.NextCursor == "" {
		t.Fatalf("first page = %#v, err=%v", first, err)
	}
	payload := decodeCursorPayload(t, first.NextCursor)
	if payload["v"] != float64(2) || payload["issued_at"] != issuedAt.Format(time.RFC3339) ||
		payload["expires_at"] != issuedAt.Add(15*time.Minute).Format(time.RFC3339) {
		t.Fatalf("v2 cursor payload = %#v", payload)
	}

	currentTime = issuedAt.Add(15*time.Minute - time.Second)
	page, err := service.ListSelfPage(t.Context(), principal, APIKeyListInput{Limit: 1, Cursor: first.NextCursor})
	got := pageIDs(page.Items)
	if err != nil || !reflect.DeepEqual(got, []int{1}) {
		t.Fatalf("pre-expiry page = %#v, err=%v", page, err)
	}
	if !page.SnapshotAt.Equal(issuedAt) {
		t.Fatalf("snapshot crossed cursor boundary: %s", page.SnapshotAt)
	}

	currentTime = issuedAt.Add(15 * time.Minute)
	before := len(reader.requests)
	if _, err := service.ListSelfPage(t.Context(), principal, APIKeyListInput{Limit: 1, Cursor: first.NextCursor}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("exact-expiry error = %v", err)
	}
	if len(reader.requests) != before {
		t.Fatal("expired v2 cursor reached the store")
	}

	legacy := signCursorPayload(t, service.pepper, "cdnca-control-api/api-key/list-cursor/v1\x00", struct {
		Version        int       `json:"v"`
		Audience       string    `json:"aud"`
		ScopeID        uuid.UUID `json:"scope_id"`
		UserID         uuid.UUID `json:"user_id"`
		SnapshotAt     time.Time `json:"snapshot_at"`
		AfterCreatedAt time.Time `json:"after_created_at"`
		AfterID        uuid.UUID `json:"after_id"`
		Limit          int       `json:"limit"`
		Status         string    `json:"status"`
		Name           string    `json:"name"`
		KeyID          string    `json:"key_id"`
	}{1, "self", scopeID, userID, issuedAt, rows[0].CreatedAt, rows[0].ID, 1, "", "", ""})
	currentTime = issuedAt.Add(15*time.Minute - time.Second)
	if page, err := service.ListSelfPage(t.Context(), principal, APIKeyListInput{Limit: 1, Cursor: legacy}); err != nil || len(page.Items) != 1 {
		t.Fatalf("bounded legacy page = %#v, err=%v", page, err)
	}
	currentTime = issuedAt.Add(15 * time.Minute)
	before = len(reader.requests)
	if _, err := service.ListSelfPage(t.Context(), principal, APIKeyListInput{Limit: 1, Cursor: legacy}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expired legacy error = %v", err)
	}
	if len(reader.requests) != before {
		t.Fatal("expired legacy cursor reached the store")
	}

	v2 := func(snapshotAt, wireIssuedAt, expiresAt time.Time) string {
		return signCursorPayload(t, service.pepper, "cdnca-control-api/api-key/list-cursor/v2\x00", struct {
			Version        int       `json:"v"`
			Audience       string    `json:"aud"`
			ScopeID        uuid.UUID `json:"scope_id"`
			UserID         uuid.UUID `json:"user_id"`
			IssuedAt       time.Time `json:"issued_at"`
			ExpiresAt      time.Time `json:"expires_at"`
			SnapshotAt     time.Time `json:"snapshot_at"`
			AfterCreatedAt time.Time `json:"after_created_at"`
			AfterID        uuid.UUID `json:"after_id"`
			Limit          int       `json:"limit"`
			Status         string    `json:"status"`
			Name           string    `json:"name"`
			KeyID          string    `json:"key_id"`
		}{2, "self", scopeID, userID, wireIssuedAt, expiresAt, snapshotAt, rows[0].CreatedAt, rows[0].ID, 1, "", "", ""})
	}
	currentTime = issuedAt
	invalid := []string{
		v2(issuedAt.Add(time.Second), issuedAt.Add(time.Second), issuedAt.Add(15*time.Minute+time.Second)),
		v2(issuedAt, issuedAt, issuedAt.Add(16*time.Minute)),
		signNonCanonicalCursorPayload(t, service.pepper, "cdnca-control-api/api-key/list-cursor/v2\x00", v2(issuedAt, issuedAt, issuedAt.Add(15*time.Minute))),
	}
	before = len(reader.requests)
	for _, cursor := range invalid {
		if _, err := service.ListSelfPage(t.Context(), principal, APIKeyListInput{Limit: 1, Cursor: cursor}); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("invalid v2 cursor error = %v", err)
		}
	}
	if len(reader.requests) != before {
		t.Fatal("invalid v2 cursor reached the store")
	}
}

func TestAPIKeyListCompatibilityWrapperUsesBoundedPages(t *testing.T) {
	now := time.Date(2026, 8, 7, 14, 0, 0, 0, time.UTC)
	scopeID := uuid.MustParse("00000000-0000-4000-8000-000000000301")
	userID := uuid.MustParse("00000000-0000-4000-8000-000000000302")
	rows := make([]Key, 205)
	for index := range rows {
		rows[index] = pageKey(index+1, scopeID, userID, "cfk_AAAAAAAAAAAAAAAAAAAAAA", "Key", StatusActive, now.Add(-time.Duration(index)*time.Second))
	}
	reader := &pageReaderFixture{rows: &rows}
	service := pageTestService(now, scopeID, userID, reader.read)
	items, err := service.ListSelf(t.Context(), tenantPagePrincipal(scopeID, userID))
	if err != nil || len(items) != len(rows) {
		t.Fatalf("compatibility list = %d items, err=%v", len(items), err)
	}
	if len(reader.requests) != 3 {
		t.Fatalf("compatibility wrapper store calls = %d, want 3", len(reader.requests))
	}
	for _, request := range reader.requests {
		if request.Limit != 101 {
			t.Fatalf("unbounded compatibility request = %#v", request)
		}
	}
}

type pageReaderFixture struct {
	rows     *[]Key
	requests []apiKeyPageStoreRequest
}

func (fixture *pageReaderFixture) read(_ context.Context, request apiKeyPageStoreRequest) ([]Key, error) {
	fixture.requests = append(fixture.requests, request)
	items := make([]Key, 0, request.Limit)
	for _, item := range *fixture.rows {
		if item.ScopeID != request.ScopeID || item.UserID != request.UserID || item.CreatedAt.After(request.SnapshotAt) {
			continue
		}
		if request.HasAfter && (item.CreatedAt.After(request.AfterCreatedAt) ||
			(item.CreatedAt.Equal(request.AfterCreatedAt) && bytes.Compare(item.ID[:], request.AfterID[:]) >= 0)) {
			continue
		}
		if request.Status != "" && item.Status != request.Status ||
			request.Name != "" && strings.ToLower(item.Name) != request.Name ||
			request.KeyID != "" && item.KeyID != request.KeyID {
			continue
		}
		items = append(items, item)
	}
	sort.Slice(items, func(left, right int) bool {
		if !items[left].CreatedAt.Equal(items[right].CreatedAt) {
			return items[left].CreatedAt.After(items[right].CreatedAt)
		}
		return bytes.Compare(items[left].ID[:], items[right].ID[:]) > 0
	})
	if request.Offset >= len(items) {
		items = items[:0]
	} else {
		items = items[request.Offset:]
	}
	if len(items) > request.Limit {
		items = items[:request.Limit]
	}
	return items, nil
}

func pageTestService(
	now time.Time,
	scopeID, userID uuid.UUID,
	reader func(context.Context, apiKeyPageStoreRequest) ([]Key, error),
) *Service {
	keyring, err := apikeycredential.NewPepperKeyring(apikeycredential.PepperKeyringConfig{
		ActiveVersion: LegacyPepperVersion,
		Active:        bytes.Repeat([]byte{0x42}, 32),
	})
	if err != nil {
		panic(err)
	}
	service := &Service{
		pepper: keyring, now: func() time.Time { return now }, pageList: reader,
	}
	service.pageTargetPrincipal = func(_ context.Context, targetScopeID, targetUserID uuid.UUID) (identity.Principal, error) {
		if targetScopeID != scopeID || targetUserID != userID {
			return identity.Principal{}, ErrNotFound
		}
		return tenantPagePrincipal(scopeID, userID), nil
	}
	return service
}

func tenantPagePrincipal(scopeID, userID uuid.UUID) identity.Principal {
	tenantID := uuid.MustParse("00000000-0000-4000-8000-000000000399")
	return identity.Principal{
		UserID: userID, ScopeID: scopeID, ScopeKind: "tenant", TenantID: &tenantID,
		Permissions: []string{"api_keys.self.manage"},
	}
}

func pageKey(number int, scopeID, userID uuid.UUID, keyID, name, status string, createdAt time.Time) Key {
	return Key{ID: pageUUID(number), ScopeID: scopeID, UserID: userID, KeyID: keyID, Name: name, Status: status, CreatedAt: createdAt}
}

func pageUUID(number int) uuid.UUID {
	return uuid.MustParse(fmt.Sprintf("00000000-0000-4000-8000-%012d", number))
}

func pageIDs(items []Key) []int {
	result := make([]int, len(items))
	for index := range items {
		result[index] = int(items[index].ID[15])
	}
	return result
}

func removePageKey(items []Key, number int) []Key {
	for index := range items {
		if items[index].ID == pageUUID(number) {
			return append(items[:index], items[index+1:]...)
		}
	}
	return items
}

func signCursorPayload(t *testing.T, pepper apikeycredential.PepperKeyring, domain string, value any) string {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return signRawCursorPayload(pepper, domain, payload)
}

func signNonCanonicalCursorPayload(t *testing.T, pepper apikeycredential.PepperKeyring, domain, canonicalCursor string) string {
	t.Helper()
	parts := strings.Split(canonicalCursor, ".")
	if len(parts) != 2 {
		t.Fatalf("cursor parts = %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	payload = append([]byte(" \n"), payload...)
	return signRawCursorPayload(pepper, domain, payload)
}

func signRawCursorPayload(pepper apikeycredential.PepperKeyring, domain string, payload []byte) string {
	_, signature, ok := pepper.SignActive(domain, payload)
	if !ok {
		panic("test pepper keyring is not configured")
	}
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(signature[:])
}

func decodeCursorPayload(t *testing.T, cursor string) map[string]any {
	t.Helper()
	parts := strings.Split(cursor, ".")
	if len(parts) != 2 {
		t.Fatalf("cursor parts = %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := json.Unmarshal(payload, &result); err != nil {
		t.Fatal(err)
	}
	return result
}
