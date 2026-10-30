package audit

import (
	"bytes"
	"crypto/sha256"
	"context"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/google/uuid"
)

// tp-b6b: the request User-Agent reaches the record cleaned and bounded.
func TestEnrichTakesCleanedUserAgentFromContext(t *testing.T) {
	cases := map[string]struct{ raw, want string }{
		"plain":            {"Mozilla/5.0 (Macintosh) Chrome/141.0", "Mozilla/5.0 (Macintosh) Chrome/141.0"},
		"control removed":  {" Mozilla/5.0\r\n\x00\x1b[31m\u0085X \t", "Mozilla/5.0[31mX"},
		"invalid utf8":     {"Mozilla\xff/5.0", "Mozilla/5.0"},
		"only controls":    {"\r\n\t", ""},
		"cut to 512 bytes": {strings.Repeat("a", 511) + "é" + "tail", strings.Repeat("a", 511)},
	}
	for name, test := range cases {
		got, err := enrich(WithUserAgent(context.Background(), test.raw), Event{Action: "site.update", Result: "success"})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got.UserAgent != test.want || len(got.UserAgent) > maxUserAgentBytes || !utf8.ValidString(got.UserAgent) {
			t.Errorf("%s: user agent = %q, want %q", name, got.UserAgent, test.want)
		}
	}
	if got, _ := enrich(context.Background(), Event{Action: "site.update", Result: "success"}); got.UserAgent != "" {
		t.Fatalf("no request UA = %q", got.UserAgent)
	}
}

// An empty user agent leaves the v2 canonical bytes as before (rows written
// before 490 and the SQL hash of migration 392 still verify); a non-empty one
// is covered by the hash.
func TestUserAgentHashIsOmittedWhenEmpty(t *testing.T) {
	event := record{ID: uuid.New(), ScopeID: uuid.New(), StreamPosition: 1, Action: "site.update", ResourceType: "site",
		ResourceID: "s", RequestID: "r", Result: "success", Payload: []byte(`{}`), Category: "site", ActorKind: "system",
		Changes: []byte(`[]`)}
	empty, err := computeHash(event)
	if err != nil {
		t.Fatal(err)
	}
	canonical := `{"version":2,"id":"` + event.ID.String() + `","scope_id":"` + event.ScopeID.String() +
		`","stream_position":1,"actor_user_id":null,"action":"site.update","resource_type":"site","resource_id":"s",` +
		`"request_id":"r","result":"success","payload":{},"previous_hash":"","occurred_at":"0001-01-01T00:00:00Z",` +
		`"category":"site","actor_kind":"system","actor_ref":"","source_ip":"","reason_code":"","changes":[]}`
	if digest := sha256Sum([]byte(canonical)); !bytes.Equal(empty, digest) {
		t.Fatalf("empty user agent changed the v2 canonical form")
	}
	event.UserAgent = "Mozilla/5.0"
	withUA, err := computeHash(event)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(empty, withUA) {
		t.Fatal("user agent is not covered by the hash")
	}
}

func sha256Sum(value []byte) []byte {
	digest := sha256.Sum256(value)
	return digest[:]
}
