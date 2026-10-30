package siteobject

import (
	"bytes"
	"errors"
	"testing"
)

// NODE_REGION v1 (fz-x12): the key document carries the node's region code;
// without one the field is not encoded, and a code that is not a region
// catalog code is refused.
func TestKeyDocumentNodeRegion(t *testing.T) {
	document := keyDocumentFixture(nil)
	document.NodeRegion = "region-12"
	encoded, err := Encode(document)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseKeyDocument(encoded)
	if err != nil || parsed.NodeRegion != "region-12" {
		t.Fatalf("parse = %q, %v", parsed.NodeRegion, err)
	}
	plain, err := Encode(keyDocumentFixture(nil))
	if err != nil || bytes.Contains(plain, []byte("node_region")) {
		t.Fatalf("no region encoded as %s (%v)", plain, err)
	}
	for _, bad := range []string{"华东", "CN-East", "-east", "cn_east", "cn.east"} {
		document.NodeRegion = bad
		encoded, err := Encode(document)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseKeyDocument(encoded); !errors.Is(err, ErrInvalid) {
			t.Fatalf("region %q: err = %v", bad, err)
		}
	}
}
