package siteobject

import (
	"bytes"
	"errors"
	"fmt"
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

// SITE_SELECTION v1: the withheld websites are a
// bitmap over the root's websites in site_id order; without any the field
// is not encoded. Malformed bitmaps are refused.
func TestKeyDocumentWithheldSites(t *testing.T) {
	ids := []string{"55555555-5555-4555-8555-555555555553", "55555555-5555-4555-8555-555555555551", "55555555-5555-4555-8555-555555555552"}
	bitmap := NewSiteBitmap(ids, map[string]bool{ids[0]: true})
	if bitmap.Sites != 3 || len(bitmap.Bitmap) != 1 || bitmap.Bitmap[0] != 0b100 || !bitmap.Withheld(2) || bitmap.Withheld(0) || bitmap.Count() != 1 {
		t.Fatalf("bitmap = %+v (site_id order: ...553 is the third)", bitmap)
	}
	if NewSiteBitmap(ids, nil) != nil {
		t.Fatal("no website withheld must omit the field")
	}
	document := keyDocumentFixture(nil)
	document.WithheldSites = bitmap
	encoded, err := Encode(document)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseKeyDocument(encoded)
	if err != nil || parsed.WithheldSites == nil || parsed.WithheldSites.Sites != 3 || !parsed.WithheldSites.Withheld(2) {
		t.Fatalf("parse = %+v, %v", parsed.WithheldSites, err)
	}
	plain, err := Encode(keyDocumentFixture(nil))
	if err != nil || bytes.Contains(plain, []byte("withheld_sites")) {
		t.Fatalf("no withheld sites encoded as %s (%v)", plain, err)
	}
	for name, bad := range map[string]*SiteBitmap{
		"no sites":       {Sites: 0, Bitmap: []byte{}},
		"short":          {Sites: 9, Bitmap: []byte{1}},
		"long":           {Sites: 3, Bitmap: []byte{1, 0}},
		"trailing bits":  {Sites: 3, Bitmap: []byte{0b1001}},
		"withholds none": {Sites: 3, Bitmap: []byte{0}},
		"too many":       {Sites: MaxWithheldSitesBitmapSites + 1, Bitmap: make([]byte, (MaxWithheldSitesBitmapSites+8)/8)},
	} {
		document := keyDocumentFixture(nil)
		document.WithheldSites = bad
		encoded, err := Encode(document)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseKeyDocument(encoded); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s: err = %v", name, err)
		}
	}
}

// The largest key document the format allows (every list at its bound, the
// bitmap at its bound) fits MaxKeyDocumentBytes, so control never writes a
// valid document an Agent declaring SITE_SELECTION refuses for its size.
func TestKeyDocumentLargestFitsTheBound(t *testing.T) {
	ids := func(count int, prefix string) []string {
		result := make([]string, count)
		for index := range result {
			result[index] = fmt.Sprintf("%s-0000-4000-8000-%012d", prefix, index)
		}
		return result
	}
	document := keyDocumentFixture(ids(MaxL4WithheldStreams, "33333333"))
	document.TrafficStopStreams = ids(MaxTrafficStopStreams, "44444444")
	document.NodeRegion = strings.Repeat("r", 63)
	all := &SiteBitmap{Sites: MaxWithheldSitesBitmapSites, Bitmap: bytes.Repeat([]byte{0xff}, MaxWithheldSitesBitmapSites/8)}
	document.WithheldSites = all
	encoded, err := Encode(document)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) > MaxKeyDocumentBytes {
		t.Fatalf("largest key document %d bytes > MaxKeyDocumentBytes %d", len(encoded), MaxKeyDocumentBytes)
	}
	if _, err := ParseKeyDocument(encoded); err != nil {
		t.Fatalf("largest key document refused: %v", err)
	}
	t.Logf("largest key document %d bytes (bound %d)", len(encoded), MaxKeyDocumentBytes)
	// 100,000 websites, 99,000 withheld: the bitmap is 12,500 bytes.
	sites := ids(100000, "55555555")
	withheld := map[string]bool{}
	for _, id := range sites[:99000] {
		withheld[id] = true
	}
	scale := keyDocumentFixture(nil)
	scale.WithheldSites = NewSiteBitmap(sites, withheld)
	if encoded, err = Encode(scale); err != nil || len(encoded) > 20000 || scale.WithheldSites.Count() != 99000 {
		t.Fatalf("100k/99k key document %d bytes, %d withheld, %v", len(encoded), scale.WithheldSites.Count(), err)
	}
	t.Logf("100,000 websites, 99,000 withheld: key document %d bytes", len(encoded))
}
