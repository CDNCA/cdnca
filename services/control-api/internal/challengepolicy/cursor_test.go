package challengepolicy

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestCursorCodecRejectsConfigurationWithoutStrongInjectedKey(t *testing.T) {
	for _, test := range []struct {
		name     string
		audience string
		keyID    string
		key      []byte
	}{
		{name: "missing audience", keyID: "kid", key: bytes.Repeat([]byte{1}, minCursorKeyBytes)},
		{name: "missing key id", audience: "aud", key: bytes.Repeat([]byte{1}, minCursorKeyBytes)},
		{name: "short key", audience: "aud", keyID: "kid", key: bytes.Repeat([]byte{1}, minCursorKeyBytes-1)},
		{name: "oversized key", audience: "aud", keyID: "kid", key: bytes.Repeat([]byte{1}, maxCursorKeyBytes+1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewCursorCodec(test.audience, test.keyID, test.key); !errors.Is(err, ErrInvalidCursorConfig) {
				t.Fatalf("NewCursorCodec error = %v", err)
			}
		})
	}
	codec := testCursorCodec(t, 7)
	if _, err := NewStoreWithClock(nil, time.Now, nil, codec); !errors.Is(err, ErrInvalidStoreConfig) {
		t.Fatalf("nil pool store error = %v", err)
	}
	if _, err := NewStoreWithClock(&pgxpool.Pool{}, time.Now, nil, nil); !errors.Is(err, ErrInvalidStoreConfig) {
		t.Fatalf("nil cursor store error = %v", err)
	}
}

func TestCursorCodecBindsAudienceActorScopeFiltersAndCanonicalPayload(t *testing.T) {
	codec := testCursorCodec(t, 7)
	enabled := false
	actor := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant"}
	filter := ListFilter{
		TargetScopeID: uuid.New(), SiteID: uuid.New(), Host: "www.example.test",
		Enabled: &enabled, Limit: 25,
	}
	position := pageCursor{CreatedAt: time.Date(2026, 7, 23, 4, 0, 0, 123000, time.UTC), ID: uuid.New()}
	encoded, err := codec.encode(actor, filter, position)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := codec.decode(encoded, actor, filter)
	if err != nil || *decoded != position {
		t.Fatalf("decode = (%#v, %v)", decoded, err)
	}

	wrongKey := testCursorCodec(t, 8)
	wrongAudience, err := NewCursorCodec("other-audience", codec.keyID, codec.key)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		codec  *CursorCodec
		actor  Actor
		filter ListFilter
		cursor string
	}{
		{name: "wrong key", codec: wrongKey, actor: actor, filter: filter, cursor: encoded},
		{name: "wrong audience", codec: wrongAudience, actor: actor, filter: filter, cursor: encoded},
		{name: "cross actor user", codec: codec, actor: Actor{UserID: uuid.New(), ScopeID: actor.ScopeID, ScopeKind: actor.ScopeKind}, filter: filter, cursor: encoded},
		{name: "cross actor scope", codec: codec, actor: Actor{UserID: actor.UserID, ScopeID: uuid.New(), ScopeKind: actor.ScopeKind}, filter: filter, cursor: encoded},
		{name: "cross actor kind", codec: codec, actor: Actor{UserID: actor.UserID, ScopeID: actor.ScopeID, ScopeKind: "platform"}, filter: filter, cursor: encoded},
		{name: "cross target", codec: codec, actor: actor, filter: mutateCursorFilter(filter, func(value *ListFilter) { value.TargetScopeID = uuid.New() }), cursor: encoded},
		{name: "cross site", codec: codec, actor: actor, filter: mutateCursorFilter(filter, func(value *ListFilter) { value.SiteID = uuid.New() }), cursor: encoded},
		{name: "cross host", codec: codec, actor: actor, filter: mutateCursorFilter(filter, func(value *ListFilter) { value.Host = "other.example.test" }), cursor: encoded},
		{name: "cross enabled", codec: codec, actor: actor, filter: mutateCursorFilter(filter, func(value *ListFilter) { other := true; value.Enabled = &other }), cursor: encoded},
		{name: "missing enabled", codec: codec, actor: actor, filter: mutateCursorFilter(filter, func(value *ListFilter) { value.Enabled = nil }), cursor: encoded},
		{name: "cross limit", codec: codec, actor: actor, filter: mutateCursorFilter(filter, func(value *ListFilter) { value.Limit++ }), cursor: encoded},
		{name: "overlong", codec: codec, actor: actor, filter: filter, cursor: strings.Repeat("x", maxCursorBytes+1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := test.codec.decode(test.cursor, test.actor, test.filter); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("decode error = %v", err)
			}
		})
	}

	for _, mutation := range []struct {
		name   string
		change func(*cursorPayload)
	}{
		{name: "wrong version", change: func(value *cursorPayload) { value.Version++ }},
		{name: "wrong key id", change: func(value *cursorPayload) { value.KeyID = "other-key" }},
		{name: "wrong sort", change: func(value *cursorPayload) { value.Sort = "id_asc" }},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			changed := resignCursor(t, codec, encoded, mutation.change, false)
			if _, err := codec.decode(changed, actor, filter); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("decode error = %v", err)
			}
		})
	}
	rewritten := resignCursor(t, codec, encoded, func(*cursorPayload) {}, true)
	if _, err := codec.decode(rewritten, actor, filter); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("semantically rewritten cursor error = %v", err)
	}
}

func mutateCursorFilter(value ListFilter, mutate func(*ListFilter)) ListFilter {
	result := value
	mutate(&result)
	return result
}

func resignCursor(t *testing.T, codec *CursorCodec, encoded string, mutate func(*cursorPayload), indent bool) string {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(strings.SplitN(encoded, ".", 2)[0])
	if err != nil {
		t.Fatal(err)
	}
	var payload cursorPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	mutate(&payload)
	raw, err = json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if indent {
		var formatted bytes.Buffer
		if err := json.Indent(&formatted, raw, "", "  "); err != nil {
			t.Fatal(err)
		}
		raw = formatted.Bytes()
	}
	return codec.sign(raw)
}
