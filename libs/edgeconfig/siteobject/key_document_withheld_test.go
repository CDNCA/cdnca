package siteobject

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func keyDocumentFixture(withheld []string) KeyDocument {
	return KeyDocument{
		Schema: KeySchema, ConfigurationScopeID: "11111111-1111-4111-8111-111111111111",
		ConfigVersionID: "22222222-2222-4222-8222-222222222222", RootSHA256: strings.Repeat("a", 64),
		KeyEpoch: 1, ContentKey: bytes.Repeat([]byte{7}, ContentKeySize), L4WithheldStreams: withheld,
	}
}

// L4_STREAM_SELECTION v1: a key document may name the forwards the node does
// not serve (sorted, unique UUIDs); without any the field is not encoded,
// so an older node's key document is byte for byte what it was.
func TestKeyDocumentL4WithheldStreams(t *testing.T) {
	withheld := []string{"33333333-3333-4333-8333-333333333331", "33333333-3333-4333-8333-333333333332"}
	encoded, err := Encode(keyDocumentFixture(withheld))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseKeyDocument(encoded)
	if err != nil || len(parsed.L4WithheldStreams) != 2 || parsed.L4WithheldStreams[1] != withheld[1] {
		t.Fatalf("parse = %+v, %v", parsed.L4WithheldStreams, err)
	}
	plain, err := Encode(keyDocumentFixture(nil))
	if err != nil || bytes.Contains(plain, []byte("l4_withheld_streams")) {
		t.Fatalf("no withheld streams encoded as %s (%v)", plain, err)
	}
	if _, err := ParseKeyDocument(plain); err != nil {
		t.Fatalf("plain key document: %v", err)
	}
	// An empty list on the wire is not the object encoding (omitted).
	empty := bytes.Replace(plain, []byte(`}`), []byte(`,"l4_withheld_streams":[]}`), 1)
	if _, err := ParseKeyDocument(empty); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty list: err = %v", err)
	}
	for name, bad := range map[string][]string{
		"unsorted":  {withheld[1], withheld[0]},
		"duplicate": {withheld[0], withheld[0]},
		"not uuid":  {"stream-1"},
	} {
		encoded, err := Encode(keyDocumentFixture(bad))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseKeyDocument(encoded); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s: err = %v", name, err)
		}
	}
}
