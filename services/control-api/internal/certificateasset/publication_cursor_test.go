package certificateasset

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestPublicationCursorRoundTripAndKeyRotation45(t *testing.T) {
	oldKey := bytes.Repeat([]byte{0x41}, 32)
	currentKey := bytes.Repeat([]byte{0x42}, 32)
	actor, tenantScopeID, filter, cursor := publicationCursorFixture45()

	oldCodec := mustPublicationCursorCodec45(t, PublicationCursorKeyring{
		ActiveKID: "old", Keys: map[string][]byte{"old": oldKey},
	})
	oldToken, err := oldCodec.Encode(actor, tenantScopeID, filter, cursor)
	if err != nil {
		t.Fatal(err)
	}
	if oldToken == "" || strings.Contains(oldToken, "{") || strings.Contains(oldToken, actor.UserID.String()) {
		t.Fatalf("cursor is not opaque: %q", oldToken)
	}

	rotated := mustPublicationCursorCodec45(t, PublicationCursorKeyring{
		ActiveKID: "current", Keys: map[string][]byte{"current": currentKey, "old": oldKey},
	})
	decoded, err := rotated.Decode(oldToken, actor, tenantScopeID, filter)
	if err != nil || !reflect.DeepEqual(decoded, cursor) {
		t.Fatalf("rotated decode = (%+v, %v), want %+v", decoded, err, cursor)
	}
	currentToken, err := rotated.Encode(actor, tenantScopeID, filter, cursor)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := oldCodec.Decode(currentToken, actor, tenantScopeID, filter); !errors.Is(err, ErrInvalidPublicationCursor) {
		t.Fatalf("old keyring accepted current cursor: %v", err)
	}
	payload := publicationCursorPayload45(t, currentToken)
	if !bytes.Contains(payload, []byte(`"kid":"current"`)) {
		t.Fatalf("active KID did not sign cursor: %s", payload)
	}

	oldKey[0], currentKey[0] = 0, 0
	if _, err := rotated.Decode(oldToken, actor, tenantScopeID, filter); err != nil {
		t.Fatalf("codec retained caller-owned key bytes: %v", err)
	}
}

func TestPublicationCursorBindsIdentityTenantFiltersAndPosition45(t *testing.T) {
	key := bytes.Repeat([]byte{0x51}, 32)
	codec := mustPublicationCursorCodec45(t, PublicationCursorKeyring{
		ActiveKID: "current", Keys: map[string][]byte{"current": key},
	})
	actor, tenantScopeID, filter, cursor := publicationCursorFixture45()
	token, err := codec.Encode(actor, tenantScopeID, filter, cursor)
	if err != nil {
		t.Fatal(err)
	}

	actorVariants := []Actor{
		{UserID: uuid.New(), ScopeID: actor.ScopeID, ScopeKind: actor.ScopeKind},
		{UserID: actor.UserID, ScopeID: uuid.New(), ScopeKind: actor.ScopeKind},
		{UserID: actor.UserID, ScopeID: actor.ScopeID, ScopeKind: ScopePlatform},
	}
	for _, other := range actorVariants {
		assertInvalidPublicationCursorDecode45(t, codec, token, other, tenantScopeID, filter)
	}
	assertInvalidPublicationCursorDecode45(t, codec, token, actor, uuid.New(), filter)
	for _, other := range []PublicationStatusFilter{
		{State: "retry_wait", Operation: filter.Operation, SiteID: filter.SiteID},
		{State: filter.State, Operation: "unpublish", SiteID: filter.SiteID},
		{State: filter.State, Operation: filter.Operation, SiteID: uuid.New()},
		{},
	} {
		assertInvalidPublicationCursorDecode45(t, codec, token, actor, tenantScopeID, other)
	}

	raw := publicationCursorRaw45(t, token)
	for _, mutation := range []struct {
		name string
		old  string
		new  string
	}{
		{name: "snapshot", old: cursor.SnapshotAt.Format(time.RFC3339Nano), new: cursor.SnapshotAt.Add(time.Second).Format(time.RFC3339Nano)},
		{name: "occurred at", old: cursor.LastOccurredAt.Format(time.RFC3339Nano), new: cursor.LastOccurredAt.Add(time.Second).Format(time.RFC3339Nano)},
		{name: "site", old: cursor.LastSiteID.String(), new: uuid.NewString()},
		{name: "revision", old: `"last_binding_revision":17`, new: `"last_binding_revision":18`},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			mutated := bytes.Replace(raw, []byte(mutation.old), []byte(mutation.new), 1)
			if bytes.Equal(mutated, raw) {
				t.Fatalf("fixture did not contain %q", mutation.old)
			}
			packet := append(append([]byte(nil), mutated...), publicationCursorTag45(key, mutated)...)
			// Keep the original tag so every signed pagination position is immutable.
			copy(packet[len(mutated):], publicationCursorTag45(key, raw))
			assertInvalidPublicationCursorDecode45(t, codec,
				base64.RawURLEncoding.EncodeToString(packet), actor, tenantScopeID, filter)
		})
	}
}

func TestPublicationCursorRejectsNonCanonicalAndMalformedTokens45(t *testing.T) {
	key := bytes.Repeat([]byte{0x61}, 32)
	codec := mustPublicationCursorCodec45(t, PublicationCursorKeyring{
		ActiveKID: "current", Keys: map[string][]byte{"current": key},
	})
	actor, tenantScopeID, filter, cursor := publicationCursorFixture45()
	token, err := codec.Encode(actor, tenantScopeID, filter, cursor)
	if err != nil {
		t.Fatal(err)
	}
	raw := publicationCursorRaw45(t, token)

	invalidPayloads := map[string][]byte{
		"duplicate field": bytes.Replace(raw, []byte(`{"v":1,`), []byte(`{"v":1,"v":1,`), 1),
		"unknown field":   bytes.Replace(raw, []byte(`}`), []byte(`,"unknown":true}`), 1),
		"trailing value":  append(append([]byte(nil), raw...), []byte(`{}`)...),
		"whitespace":      append([]byte{' ', '\n'}, raw...),
		"invalid utf8":    append(append([]byte(nil), raw[:len(raw)-1]...), 0xff, '}'),
		"nil user uuid":   bytes.Replace(raw, []byte(actor.UserID.String()), []byte(uuid.Nil.String()), 1),
		"invalid uuid":    bytes.Replace(raw, []byte(actor.ScopeID.String()), []byte("00000000-0000-0000-0000-00000000000x"), 1),
		"unknown kid":     bytes.Replace(raw, []byte(`"kid":"current"`), []byte(`"kid":"missing"`), 1),
		"non UTC time": bytes.Replace(raw,
			[]byte(cursor.SnapshotAt.Format(time.RFC3339Nano)),
			[]byte(strings.TrimSuffix(cursor.SnapshotAt.Format(time.RFC3339Nano), "Z")+"+00:00"), 1),
		"sub microsecond time": bytes.Replace(raw,
			[]byte(cursor.SnapshotAt.Format(time.RFC3339Nano)),
			[]byte(cursor.SnapshotAt.Add(time.Nanosecond).Format(time.RFC3339Nano)), 1),
	}
	for name, payload := range invalidPayloads {
		t.Run(name, func(t *testing.T) {
			assertInvalidPublicationCursorDecode45(t, codec,
				publicationCursorSigned45(key, payload), actor, tenantScopeID, filter)
		})
	}

	for name, malformed := range map[string]string{
		"empty":        "",
		"padded":       token + "=",
		"bad alphabet": token[:len(token)-1] + "+",
		"too large":    strings.Repeat("A", 4097),
		"only tag":     base64.RawURLEncoding.EncodeToString(make([]byte, sha256.Size)),
	} {
		t.Run(name, func(t *testing.T) {
			assertInvalidPublicationCursorDecode45(t, codec, malformed, actor, tenantScopeID, filter)
		})
	}
}

func TestPublicationCursorRejectsInvalidConfigurationAndInputs45(t *testing.T) {
	validKey := bytes.Repeat([]byte{0x71}, 32)
	for name, keyring := range map[string]PublicationCursorKeyring{
		"empty":          {},
		"missing active": {ActiveKID: "current", Keys: map[string][]byte{"old": validKey}},
		"bad kid":        {ActiveKID: "bad/kid", Keys: map[string][]byte{"bad/kid": validKey}},
		"short key":      {ActiveKID: "current", Keys: map[string][]byte{"current": validKey[:31]}},
		"long key":       {ActiveKID: "current", Keys: map[string][]byte{"current": bytes.Repeat([]byte{1}, 65)}},
		"too many keys": {
			ActiveKID: "current",
			Keys:      map[string][]byte{"current": validKey, "old": validKey, "older": validKey},
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewPublicationCursorCodec(keyring); !errors.Is(err, ErrInvalidPublicationCursorConfig) {
				t.Fatalf("NewPublicationCursorCodec() error = %v", err)
			}
		})
	}

	codec := mustPublicationCursorCodec45(t, PublicationCursorKeyring{
		ActiveKID: "current", Keys: map[string][]byte{"current": validKey},
	})
	actor, tenantScopeID, filter, cursor := publicationCursorFixture45()
	invalidActors := []Actor{
		{ScopeID: actor.ScopeID, ScopeKind: actor.ScopeKind},
		{UserID: actor.UserID, ScopeKind: actor.ScopeKind},
		{UserID: actor.UserID, ScopeID: actor.ScopeID, ScopeKind: "operator"},
		{UserID: actor.UserID, ScopeID: uuid.New(), ScopeKind: ScopeTenant},
	}
	for _, invalid := range invalidActors {
		_, err := codec.Encode(invalid, tenantScopeID, filter, cursor)
		assertInvalidPublicationCursor45(t, PublicationStatusCursor{}, err)
	}
	for _, invalid := range []PublicationStatusCursor{
		{},
		{SnapshotAt: cursor.SnapshotAt, LastOccurredAt: cursor.SnapshotAt.Add(time.Second), LastSiteID: cursor.LastSiteID, LastBindingRevision: 17},
		{SnapshotAt: cursor.SnapshotAt, LastOccurredAt: cursor.LastOccurredAt, LastBindingRevision: 17},
		{SnapshotAt: cursor.SnapshotAt, LastOccurredAt: cursor.LastOccurredAt, LastSiteID: cursor.LastSiteID},
		{SnapshotAt: cursor.SnapshotAt.Add(time.Nanosecond), LastOccurredAt: cursor.LastOccurredAt, LastSiteID: cursor.LastSiteID, LastBindingRevision: 17},
	} {
		_, err := codec.Encode(actor, tenantScopeID, filter, invalid)
		assertInvalidPublicationCursor45(t, PublicationStatusCursor{}, err)
	}
	if _, err := codec.Encode(actor, uuid.Nil, filter, cursor); !errors.Is(err, ErrInvalidPublicationCursor) {
		t.Fatalf("nil tenant error = %v", err)
	}
	if _, err := codec.Encode(actor, tenantScopeID, PublicationStatusFilter{State: "failed"}, cursor); !errors.Is(err, ErrInvalidPublicationCursor) {
		t.Fatalf("invalid filter error = %v", err)
	}
	var nilCodec *PublicationCursorCodec
	if _, err := nilCodec.Encode(actor, tenantScopeID, filter, cursor); !errors.Is(err, ErrInvalidPublicationCursor) {
		t.Fatalf("nil codec encode error = %v", err)
	}
	assertInvalidPublicationCursorDecode45(t, nilCodec, "opaque", actor, tenantScopeID, filter)
}

func publicationCursorFixture45() (Actor, uuid.UUID, PublicationStatusFilter, PublicationStatusCursor) {
	tenantScopeID := uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	actor := Actor{
		UserID:    uuid.MustParse("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
		ScopeID:   tenantScopeID,
		ScopeKind: ScopeTenant,
	}
	filter := PublicationStatusFilter{
		State:     "succeeded",
		Operation: "publish",
		SiteID:    uuid.MustParse("cccccccc-cccc-4ccc-8ccc-cccccccccccc"),
	}
	cursor := PublicationStatusCursor{
		SnapshotAt:          time.Date(2026, 8, 7, 10, 11, 12, 123456000, time.UTC),
		LastOccurredAt:      time.Date(2026, 8, 7, 10, 10, 11, 654321000, time.UTC),
		LastSiteID:          uuid.MustParse("dddddddd-dddd-4ddd-8ddd-dddddddddddd"),
		LastBindingRevision: 17,
	}
	return actor, tenantScopeID, filter, cursor
}

func mustPublicationCursorCodec45(t *testing.T, keyring PublicationCursorKeyring) *PublicationCursorCodec {
	t.Helper()
	codec, err := NewPublicationCursorCodec(keyring)
	if err != nil {
		t.Fatal(err)
	}
	return codec
}

func assertInvalidPublicationCursor45(t *testing.T, _ PublicationStatusCursor, err error) {
	t.Helper()
	if !errors.Is(err, ErrInvalidPublicationCursor) {
		t.Fatalf("cursor error = %v, want stable %v", err, ErrInvalidPublicationCursor)
	}
	if err.Error() != ErrInvalidPublicationCursor.Error() {
		t.Fatalf("cursor error leaked detail: %q", err)
	}
}

func assertInvalidPublicationCursorDecode45(
	t *testing.T,
	codec *PublicationCursorCodec,
	token string,
	actor Actor,
	tenantScopeID uuid.UUID,
	filter PublicationStatusFilter,
) {
	t.Helper()
	cursor, err := codec.Decode(token, actor, tenantScopeID, filter)
	assertInvalidPublicationCursor45(t, cursor, err)
}

func publicationCursorPayload45(t *testing.T, token string) []byte {
	t.Helper()
	raw := publicationCursorRaw45(t, token)
	return append([]byte(nil), raw...)
}

func publicationCursorRaw45(t *testing.T, token string) []byte {
	t.Helper()
	packet, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(packet) <= sha256.Size {
		t.Fatalf("invalid fixture cursor packet: %v", err)
	}
	return append([]byte(nil), packet[:len(packet)-sha256.Size]...)
}

func publicationCursorSigned45(key, payload []byte) string {
	packet := append(append([]byte(nil), payload...), publicationCursorTag45(key, payload)...)
	return base64.RawURLEncoding.EncodeToString(packet)
}

func publicationCursorTag45(key, payload []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("cdnca.certificate-publication-status.cursor.v1\x00"))
	_, _ = mac.Write(payload)
	return mac.Sum(nil)
}
