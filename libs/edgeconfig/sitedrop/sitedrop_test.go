package sitedrop

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"
)

const (
	testNode   = "11111111-1111-4111-8111-111111111111"
	testSiteA  = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	testSiteB  = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	testTenant = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
)

func testKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return public, private
}

func testList(issued int64) List {
	return List{NodeID: testNode, Revision: 3, IssuedAt: issued, Sites: []Site{
		{SiteID: testSiteB, TenantID: testTenant, Since: issued - 10, Until: issued + 3600},
		{SiteID: testSiteA, TenantID: testTenant, Since: issued, Until: issued + 60},
	}}
}

func TestSignOpenRoundTrip(t *testing.T) {
	public, private := testKey(t)
	issued := time.Now().Unix()
	encoded, err := Sign(testList(issued), "edge-1", private)
	if err != nil {
		t.Fatal(err)
	}
	trusted := func(id string) (ed25519.PublicKey, bool) { return public, id == "edge-1" }
	list, err := Open(encoded, testNode, trusted)
	if err != nil {
		t.Fatal(err)
	}
	if list.Sites[0].SiteID != testSiteA || list.Revision != 3 {
		t.Fatalf("not canonical: %+v", list)
	}
	if node, revision, err := Route(encoded); err != nil || node != testNode || revision != 3 {
		t.Fatalf("route %s %d %v", node, revision, err)
	}
	active := list.Active(time.Unix(issued+120, 0))
	if len(active) != 1 || active[testSiteB].Unix() != issued+3600 {
		t.Fatalf("active %v", active)
	}
	if _, err := Open(encoded, "22222222-2222-4222-8222-222222222222", trusted); !errors.Is(err, ErrWrongNode) {
		t.Fatalf("wrong node: %v", err)
	}
	other, _ := testKey(t)
	if _, err := Open(encoded, testNode, func(string) (ed25519.PublicKey, bool) { return other, true }); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("untrusted: %v", err)
	}
	tampered := []byte(strings.Replace(string(encoded), `"revision":3`, `"revision":4`, 1))
	if _, err := Open(tampered, testNode, trusted); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("tampered: %v", err)
	}
}

func TestEmptyListLiftsEverything(t *testing.T) {
	public, private := testKey(t)
	encoded, err := Sign(List{NodeID: testNode, Revision: 9, IssuedAt: time.Now().Unix()}, "edge-1", private)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"sites":[]`) {
		t.Fatalf("empty list encoding %s", encoded)
	}
	list, err := Open(encoded, testNode, func(string) (ed25519.PublicKey, bool) { return public, true })
	if err != nil || len(list.Active(time.Now())) != 0 {
		t.Fatalf("%+v %v", list, err)
	}
}

func TestValidationRejects(t *testing.T) {
	_, private := testKey(t)
	issued := time.Now().Unix()
	week := int64(MaxDuration / time.Second)
	for name, mutate := range map[string]func(*List){
		"until over 7 days": func(l *List) { l.Sites[0].Until = issued + week + 1 },
		"until not future":  func(l *List) { l.Sites[0].Until = issued },
		"since after issue": func(l *List) { l.Sites[0].Since = issued + 1 },
		"duplicate site":    func(l *List) { l.Sites[1].SiteID = l.Sites[0].SiteID },
		"bad site id":       func(l *List) { l.Sites[0].SiteID = "SITE" },
		"bad tenant":        func(l *List) { l.Sites[0].TenantID = "" },
		"zero revision":     func(l *List) { l.Revision = 0 },
		"bad node":          func(l *List) { l.NodeID = "node" },
		"too many sites":    func(l *List) { l.Sites = make([]Site, MaxSites+1) },
		"zero issued":       func(l *List) { l.IssuedAt = 0 },
	} {
		list := testList(issued)
		mutate(&list)
		if _, err := Sign(list, "edge-1", private); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Exactly 7 days is allowed.
	list := testList(issued)
	list.Sites[0].Until = issued + week
	if _, err := Sign(list, "edge-1", private); err != nil {
		t.Fatal(err)
	}
}

func TestDecodeIsStrict(t *testing.T) {
	_, private := testKey(t)
	encoded, err := Sign(testList(time.Now().Unix()), "edge-1", private)
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string]string{
		"unknown field": strings.Replace(string(encoded), `{"schema"`, `{"x":1,"schema"`, 1),
		"trailing":      string(encoded) + " {}",
		"spaces":        strings.Replace(string(encoded), `"revision":3`, `"revision": 3`, 1),
		"unsigned":      strings.Replace(string(encoded), `"signature":"`, `"signaturx":"`, 1),
	} {
		if _, err := Decode([]byte(raw)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
