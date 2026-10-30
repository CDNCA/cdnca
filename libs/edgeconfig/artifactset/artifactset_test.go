package artifactset

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"
)

const testNodeID = "6f1c1b7e-2d0a-4d5e-9b51-0d3c9a7d2e11"

func digestOf(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func testItem(t *testing.T, content, compressed []byte) Item {
	t.Helper()
	segments := SplitSegments(compressed, 4)
	item := Item{ArtifactID: "ipintel/base", Version: "ipintel-20261017-000007", Revision: 7, MediaType: MediaTypeIPIntel,
		SHA256: digestOf(content), Size: int64(len(content)), Compression: CompressionZstd,
		CompressedSHA256: digestOf(compressed), CompressedSize: int64(len(compressed)), Encryption: EncryptionNone}
	for _, segment := range segments {
		item.Segments = append(item.Segments, Segment{SHA256: digestOf(segment), Size: int64(len(segment))})
	}
	return item
}

func testKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{7}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	return public, private
}

func TestSignVerifyRoundTripAndTamper(t *testing.T) {
	public, private := testKey(t)
	set := Set{NodeID: testNodeID, Revision: 3, IssuedAt: time.Unix(1792195200, 0),
		Items: []Item{testItem(t, []byte("library"), []byte("compressed-library"))}}
	encoded, err := Sign(set, "edge-key-1", private)
	if err != nil {
		t.Fatal(err)
	}
	resolve := func(keyID string) (ed25519.PublicKey, bool) { return public, keyID == "edge-key-1" }
	verified, err := Verify(encoded, resolve)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Revision != 3 || len(verified.Items) != 1 || verified.Items[0].ArtifactID != "ipintel/base" {
		t.Fatalf("verified set = %+v", verified)
	}
	tampered := bytes.Replace(encoded, []byte(`"revision":3`), []byte(`"revision":4`), 1)
	if _, err := Verify(tampered, resolve); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("tampered set error = %v, want ErrUntrusted", err)
	}
	if _, err := Verify(encoded, func(string) (ed25519.PublicKey, bool) { return nil, false }); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("unknown key error = %v", err)
	}
	if _, err := Verify(append(bytes.Clone(encoded), ' '), resolve); !errors.Is(err, ErrInvalidSet) {
		t.Fatalf("non canonical set error = %v", err)
	}
}

func TestEmptySetIsValid(t *testing.T) {
	_, private := testKey(t)
	// A complete desired set with no items uninstalls everything.
	if _, err := Sign(Set{NodeID: testNodeID, Revision: 1, IssuedAt: time.Unix(1, 0), Items: []Item{}}, "k", private); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRejectsBadSets(t *testing.T) {
	_, private := testKey(t)
	good := testItem(t, []byte("library"), []byte("compressed-library"))
	cases := map[string]func(*Set){
		"zero revision":      func(set *Set) { set.Revision = 0 },
		"zero item revision": func(set *Set) { set.Items[0].Revision = 0 },
		"bad node":           func(set *Set) { set.NodeID = "not a node" },
		"nil items":          func(set *Set) { set.Items = nil },
		"duplicate artifact": func(set *Set) { set.Items = []Item{good, good} },
		"unknown media":      func(set *Set) { set.Items[0].MediaType = "application/x-anything" },
		"bad artifact id":    func(set *Set) { set.Items[0].ArtifactID = "../etc" },
		"segment sum":        func(set *Set) { set.Items[0].CompressedSize++ },
		"no segments":        func(set *Set) { set.Items[0].Segments = nil },
		"encrypted":          func(set *Set) { set.Items[0].Encryption = "install_wrapped" },
		"key wrap on ip library": func(set *Set) {
			set.Items[0].KeyWrap = &KeyWrap{RecipientKeyID: "x25519:" + digestOf(nil), WrappedKey: "AAAAAAAAAAAAAAAAAAAAAAAA"}
		},
		"bad wrapped key": func(set *Set) {
			set.Items[0].MediaType = MediaTypeRulePack
			set.Items[0].KeyWrap = &KeyWrap{RecipientKeyID: "x25519:" + digestOf(nil), WrappedKey: "not base64!"}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			set := Set{NodeID: testNodeID, Revision: 1, IssuedAt: time.Unix(1, 0), Items: []Item{good}}
			set.Items = append([]Item(nil), set.Items...)
			set.Items[0].Segments = append([]Segment(nil), good.Segments...)
			mutate(&set)
			if _, err := Sign(set, "k", private); !errors.Is(err, ErrInvalidSet) {
				t.Fatalf("Sign error = %v, want ErrInvalidSet", err)
			}
		})
	}
}

func TestJoinChecksEverySegmentAndTheWhole(t *testing.T) {
	content, compressed := []byte("library"), []byte("compressed-library-bytes")
	item := testItem(t, content, compressed)
	segments := SplitSegments(compressed, 4)
	joined, err := item.Join(segments)
	if err != nil || !bytes.Equal(joined, compressed) {
		t.Fatalf("Join = %q, %v", joined, err)
	}
	tampered := append([][]byte(nil), segments...)
	tampered[1] = []byte("XXXX")
	if _, err := item.Join(tampered); !errors.Is(err, ErrSegmentMismatch) {
		t.Fatalf("tampered Join error = %v", err)
	}
	if _, err := item.Join(segments[:1]); !errors.Is(err, ErrSegmentMismatch) {
		t.Fatalf("short Join error = %v", err)
	}
}

func TestReceiptRules(t *testing.T) {
	setDigest := digestOf([]byte("set"))
	applied := Receipt{NodeID: testNodeID, Revision: 2, SetSHA256: setDigest, Result: ResultApplied,
		ActiveRevision: 2, ActiveSetSHA256: setDigest, ReportedAt: time.Unix(5, 0),
		Items: []ItemResult{{ArtifactID: "ipintel/base", Version: "7", SHA256: digestOf([]byte("x")), Result: ResultApplied}}}
	encoded, err := EncodeReceipt(applied)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := DecodeReceipt(encoded); err != nil || decoded.Result != ResultApplied {
		t.Fatalf("DecodeReceipt = %+v, %v", decoded, err)
	}
	rejected := applied
	rejected.Result, rejected.ActiveRevision, rejected.ActiveSetSHA256 = ResultRejected, 1, digestOf([]byte("lkg"))
	rejected.Items = []ItemResult{{ArtifactID: "ipintel/base", Version: "7", SHA256: digestOf([]byte("x")),
		Result: ResultRejected, Reason: ReasonSegmentMismatch}}
	if _, err := EncodeReceipt(rejected); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]Receipt{
		"applied with rejected item": func() Receipt { r := applied; r.Items = rejected.Items; return r }(),
		"rejected switched":          func() Receipt { r := rejected; r.ActiveRevision = r.Revision; return r }(),
		"rejected without reason": func() Receipt {
			r := rejected
			r.Items = []ItemResult{{ArtifactID: "ipintel/base", Version: "7", SHA256: digestOf([]byte("x")), Result: ResultRejected}}
			return r
		}(),
		"unknown reason": func() Receipt {
			r := rejected
			r.Items = []ItemResult{{ArtifactID: "ipintel/base", Version: "7", SHA256: digestOf([]byte("x")), Result: ResultRejected, Reason: "whatever"}}
			return r
		}(),
	} {
		if _, err := EncodeReceipt(bad); err == nil {
			t.Errorf("%s: EncodeReceipt accepted %+v", name, bad)
		}
	}
}

func TestObjectPath(t *testing.T) {
	digest := digestOf([]byte("object"))
	path, err := ObjectPath("/var/lib/cdnca-edge/objects", digest)
	if err != nil {
		t.Fatal(err)
	}
	want := "/var/lib/cdnca-edge/objects/sha256/" + digest[:2] + "/" + digest[2:4] + "/" + digest
	if path != want {
		t.Fatalf("ObjectPath = %s, want %s", path, want)
	}
	if _, err := ObjectPath("/x", "ABC"); err == nil {
		t.Fatal("ObjectPath accepted a bad digest")
	}
}

func TestRulePackItemsWithKeyWrap(t *testing.T) {
	public, private := testKey(t)
	plain := testItem(t, []byte("pack-a"), []byte("compressed-pack-a"))
	plain.ArtifactID, plain.MediaType = "crs_profile/crs-pl1", MediaTypeRulePack
	sealed := testItem(t, []byte("pack-b"), []byte("compressed-pack-b"))
	sealed.ArtifactID, sealed.MediaType = "rule_pack/"+digestOf([]byte("pack-b")), MediaTypeRulePack
	sealed.KeyWrap = &KeyWrap{RecipientKeyID: "x25519:" + digestOf(nil), WrappedKey: "AAAAAAAAAAAAAAAAAAAAAAAA_-"}
	encoded, err := Sign(Set{NodeID: testNodeID, Revision: 1, IssuedAt: time.Unix(1, 0), Items: []Item{plain, sealed}}, "k", private)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded[:bytes.Index(encoded, []byte("rule_pack/"))], []byte("key_wrap")) {
		t.Fatal("an item without a key wrap encodes key_wrap")
	}
	set, err := Verify(encoded, func(string) (ed25519.PublicKey, bool) { return public, true })
	if err != nil || set.Items[1].KeyWrap == nil || *set.Items[1].KeyWrap != *sealed.KeyWrap {
		t.Fatalf("verified = %+v, %v", set.Items, err)
	}
}
