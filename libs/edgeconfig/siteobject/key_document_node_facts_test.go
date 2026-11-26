package siteobject

import (
	"bytes"
	"errors"
	"testing"
)

// NODE_STORAGE v2: the key document carries when control read the node
// facts; without it the field is not encoded, and a negative or unsafe value
// is refused.
func TestKeyDocumentNodeFactsAt(t *testing.T) {
	document := keyDocumentFixture(nil)
	document.NodeFactsAt = 1_764_028_800_123_456
	encoded, err := Encode(document)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseKeyDocument(encoded)
	if err != nil || parsed.NodeFactsAt != document.NodeFactsAt {
		t.Fatalf("parse = %d, %v", parsed.NodeFactsAt, err)
	}
	plain, err := Encode(keyDocumentFixture(nil))
	if err != nil || bytes.Contains(plain, []byte("node_facts_at")) {
		t.Fatalf("no node facts time encoded as %s (%v)", plain, err)
	}
	for _, bad := range []int64{-1, maxSafeInteger + 1} {
		document.NodeFactsAt = bad
		encoded, err := Encode(document)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseKeyDocument(encoded); !errors.Is(err, ErrInvalid) {
			t.Fatalf("node facts time %d: err = %v", bad, err)
		}
	}
}
