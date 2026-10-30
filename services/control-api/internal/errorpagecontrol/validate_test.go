package errorpagecontrol

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestStaticBodyMatchesEdgeRejections(t *testing.T) {
	t.Parallel()
	valid := []struct {
		mime string
		body []byte
	}{
		{"text/plain", []byte("temporarily unavailable")},
		{"application/json", []byte(`{"error":"unavailable"}`)},
		{"text/html", []byte(`<!doctype html><html><body><h1>Unavailable</h1></body></html>`)},
	}
	for _, test := range valid {
		if err := validateStaticBody(test.mime, test.body); err != nil {
			t.Fatalf("valid %s body: %v", test.mime, err)
		}
	}
	invalid := []struct {
		name string
		mime string
		body []byte
	}{
		{"empty", "text/plain", nil},
		{"nul", "text/plain", []byte("bad\x00body")},
		{"utf8", "text/plain", []byte{0xff}},
		{"template", "text/plain", []byte("{{secret}}")},
		{"json", "application/json", []byte(`{"bad"`)},
		{"script", "text/html", []byte(`<script>alert(1)</script>`)},
		{"handler", "text/html", []byte(`<p onclick="x()">bad</p>`)},
		{"form", "text/html", []byte(`<form></form>`)},
		{"external", "text/html", []byte(`<img src="https://example.test/x">`)},
		{"style URL", "text/html", []byte(`<p style="background:url(//x)">bad</p>`)},
		{"escaped style URL", "text/html", []byte(`<p style="background:u\\72l(//x)">bad</p>`)},
		{"inline CSS", "text/html", []byte(`<p style="color:red">bad</p>`)},
		{"SSI", "text/html", []byte(`<!--#include virtual="/x" -->`)},
		{"unsupported content type", "text/css", []byte(`body { color: red }`)},
		{"over edge limit", "text/plain", bytes.Repeat([]byte("x"), int(MaxEdgeResourceBytes)+1)},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			if err := validateStaticBody(test.mime, test.body); !errors.Is(err, ErrUnsafeContent) {
				t.Fatalf("error=%v, want ErrUnsafeContent", err)
			}
		})
	}
}

func TestReadBoundedStopsAtLimitDuringRead(t *testing.T) {
	t.Parallel()
	reader := &countingReader{reader: strings.NewReader(strings.Repeat("x", 4096))}
	_, err := readBounded(reader, 128)
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("error=%v, want ErrInvalidInput", err)
	}
	if reader.read != 129 {
		t.Fatalf("read=%d, want 129", reader.read)
	}
}

func TestPageCursorIsBoundToActorEndpointAndScope(t *testing.T) {
	t.Parallel()
	actor := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant"}
	target := actor.ScopeID
	encoded, err := encodePageCursor("assets?status=ready", actor, target, time.Unix(10, 0), uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodePageCursor(encoded, "assets?status=ready", actor, target); err != nil {
		t.Fatal(err)
	}
	other := actor
	other.ScopeID = uuid.New()
	if _, err := decodePageCursor(encoded, "assets?status=ready", other, other.ScopeID); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("cross-scope cursor error=%v", err)
	}
	if _, err := decodePageCursor(encoded, "rules?site_id=&enabled=", actor, target); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("cross-endpoint cursor error=%v", err)
	}
	if _, err := decodePageCursor(encoded, "assets?status=staged", actor, target); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("cross-filter cursor error=%v", err)
	}
}

type countingReader struct {
	reader io.Reader
	read   int
}

func (reader *countingReader) Read(buffer []byte) (int, error) {
	read, err := reader.reader.Read(buffer)
	reader.read += read
	return read, err
}

func TestSnapshotJSONUsesEdgeShapeWithoutStorageLocator(t *testing.T) {
	t.Parallel()
	policy := Snapshot{
		Schema: SchemaV1, Version: "control-1", Revision: 1,
		Global: SnapshotScope{Rules: []SnapshotRule{{
			ID: "rule", Category: CategoryEdgeRoute, Match: SnapshotMatch{Codes: []int{404}},
			Resource: SnapshotResource{MIMEType: "text/plain", Size: 4, SHA256: strings.Repeat("a", 64), File: "sha256/" + strings.Repeat("a", 64)},
		}}},
		Sites: []SnapshotSite{},
	}
	encoded, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"storage_object_key", "staging_object_key", "credential", "created_at", "snapshot_sha256"} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			t.Fatalf("snapshot contains %q: %s", forbidden, encoded)
		}
	}
}

func TestValidAssetName(t *testing.T) {
	for name, want := range map[string]bool{
		"": true, "维护页.html": true, "a b": true, string([]rune("一二三四五六七八九十")[0:10]): true,
		" lead": false, "trail ": false, "tab\tname": false, "nl\n": false, "\u0085x": false,
		string(make([]rune, 128)): false, // NUL runes are control characters
	} {
		if got := ValidAssetName(name); got != want {
			t.Errorf("ValidAssetName(%q) = %v, want %v", name, got, want)
		}
	}
	long := ""
	for range 128 {
		long += "页"
	}
	if !ValidAssetName(long) || ValidAssetName(long+"页") {
		t.Error("128 runes allowed, 129 refused")
	}
}
