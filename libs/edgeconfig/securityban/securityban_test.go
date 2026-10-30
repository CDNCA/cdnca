package securityban

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"
)

const (
	testNode = "11111111-1111-4111-8111-111111111111"
	testSite = "22222222-2222-4222-8222-222222222222"
)

func signedList(t *testing.T, private ed25519.PrivateKey, mutate func(*List)) []byte {
	t.Helper()
	list := List{Schema: Schema, NodeID: testNode, Revision: 3, IssuedAt: 1_800_000_000,
		Bans: []Ban{{SiteID: testSite, Client: "2001:db8::1", Until: 1_800_000_600, Source: "waf"},
			{SiteID: testSite, Client: "198.51.100.7", Until: 1_800_000_300, Source: "manual"}},
		Releases:  []Release{{SiteID: testSite, Client: "203.0.113.5", ReleasedAt: 1_799_999_000}},
		Algorithm: Algorithm, KeyID: "edge-publish:1"}
	list.Canonical()
	if mutate != nil {
		mutate(&list)
	}
	payload, err := SigningPayload(list)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := Seal(list, ed25519.Sign(private, payload))
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestListSignOpenAndRuntime(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(nil)
	trusted := func(key string) (ed25519.PublicKey, bool) { return public, key == "edge-publish:1" }
	encoded := signedList(t, private, nil)
	list, err := Open(encoded, testNode, trusted)
	if err != nil {
		t.Fatal(err)
	}
	if node, revision, err := Route(encoded); err != nil || node != testNode || revision != 3 {
		t.Fatalf("route = %s %d %v", node, revision, err)
	}
	runtime := list.Runtime(time.Unix(1_800_000_400, 0))
	if runtime.Revision != 3 || len(runtime.Bans) != 1 || runtime.Bans[0].Client != "2001:db8::1" || len(runtime.Releases) != 1 {
		t.Fatalf("runtime snapshot drops the wrong bans: %+v", runtime)
	}
	if _, err := Open(encoded, "33333333-3333-4333-8333-333333333333", trusted); !errors.Is(err, ErrInvalid) {
		t.Fatalf("wrong node accepted: %v", err)
	}
	_, other, _ := ed25519.GenerateKey(nil)
	if _, err := Open(signedList(t, other, nil), testNode, trusted); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("foreign signature accepted: %v", err)
	}
	tampered := append([]byte(nil), encoded...)
	tampered[len(tampered)-3] ^= 1
	if _, err := Open(tampered, testNode, trusted); err == nil {
		t.Fatal("tampered list accepted")
	}
}

func TestListRejectsNonCanonicalEntries(t *testing.T) {
	_, private, _ := ed25519.GenerateKey(nil)
	for name, mutate := range map[string]func(*List){
		"unsorted":       func(list *List) { list.Bans[0], list.Bans[1] = list.Bans[1], list.Bans[0] },
		"duplicate":      func(list *List) { list.Bans[1] = list.Bans[0] },
		"mapped address": func(list *List) { list.Bans[1].Client = "::ffff:198.51.100.7" },
		"loopback":       func(list *List) { list.Bans[1].Client = "127.0.0.1" },
		"bad source":     func(list *List) { list.Bans[0].Source = "auto" },
		"no revision":    func(list *List) { list.Revision = 0 },
	} {
		list := List{Schema: Schema, NodeID: testNode, Revision: 1, IssuedAt: 1,
			Bans: []Ban{{SiteID: testSite, Client: "198.51.100.7", Until: 2, Source: "cc"},
				{SiteID: testSite, Client: "198.51.100.8", Until: 2, Source: "cc"}},
			Releases: []Release{}, Algorithm: Algorithm, KeyID: "k"}
		mutate(&list)
		if _, err := SigningPayload(list); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s accepted", name)
		}
	}
	_ = private
	if client, ok := CanonicalClient("::ffff:198.51.100.7"); !ok || client != "198.51.100.7" {
		t.Fatalf("mapped address canonical = %q", client)
	}
}

// TestListSources: automatic defense bans (ADR 0010 section 8.2) travel on
// the list with source autodefense; unknown sources stay refused.
func TestListSources(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(nil)
	trusted := func(string) (ed25519.PublicKey, bool) { return public, true }
	for _, source := range []string{"autodefense", "waf"} {
		encoded := signedList(t, private, func(list *List) { list.Bans[0].Source = source })
		if _, err := Open(encoded, testNode, trusted); err != nil {
			t.Errorf("source %s refused: %v", source, err)
		}
	}
	list := List{Schema: Schema, NodeID: testNode, Revision: 1, IssuedAt: 1, Algorithm: Algorithm, KeyID: "k",
		Bans: []Ban{{SiteID: testSite, Client: "198.51.100.7", Until: 2, Source: "robot"}}, Releases: []Release{}}
	if _, err := SigningPayload(list); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown source accepted: %v", err)
	}
}

// fix-cidrban: a client is an address or a network (IPv4 /8../32, IPv6
// /32../128), carried as the masked network; a full-length prefix is the
// bare address. Too wide networks and networks overlapping loopback,
// unspecified, multicast or link-local are refused.
func TestCanonicalClientNetworks(t *testing.T) {
	for raw, want := range map[string]string{
		"203.0.113.7":             "203.0.113.7",
		"203.0.113.7/32":          "203.0.113.7",
		"203.0.113.7/24":          "203.0.113.0/24",
		"203.0.113.0/24":          "203.0.113.0/24",
		"10.0.0.0/8":              "10.0.0.0/8",
		"2001:DB8::1/64":          "2001:db8::/64",
		"2001:db8::/32":           "2001:db8::/32",
		"2001:db8::1/128":         "2001:db8::1",
		"::ffff:198.51.100.7/128": "",
	} {
		got, ok := CanonicalClient(raw)
		if want == "" {
			if ok {
				t.Errorf("CanonicalClient(%q) = %q, want refused", raw, got)
			}
			continue
		}
		if !ok || got != want {
			t.Errorf("CanonicalClient(%q) = %q %v, want %q", raw, got, ok, want)
		}
	}
	for _, raw := range []string{"203.0.0.0/7", "0.0.0.0/0", "2001::/31", "::/0", "127.0.0.0/8", "0.0.0.0/8",
		"224.0.0.0/8", "169.254.0.0/16", "fe80::/64", "ff02::/32", "::/32", "203.0.113.0/33", "203.0.113.0/", "/24",
		"203.0.113.0/024", "fe80::1%eth0/64", " 203.0.113.0/24"} {
		if got, ok := CanonicalClient(raw); ok {
			t.Errorf("CanonicalClient(%q) = %q, want refused", raw, got)
		}
	}
	if !IsNetwork("203.0.113.0/24") || IsNetwork("203.0.113.7") {
		t.Fatal("IsNetwork")
	}
}

// A list may carry network bans and releases; a non-canonical network is refused.
func TestListNetworkEntries(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(nil)
	trusted := func(string) (ed25519.PublicKey, bool) { return public, true }
	encoded := signedList(t, private, func(list *List) {
		list.Bans = append(list.Bans, Ban{SiteID: testSite, Client: "198.51.100.0/24", Until: 1_800_000_900, Source: "manual"})
		list.Releases = append(list.Releases, Release{SiteID: testSite, Client: "2001:db8:1::/48", ReleasedAt: 1_799_999_000})
		list.Canonical()
	})
	list, err := Open(encoded, testNode, trusted)
	if err != nil {
		t.Fatal(err)
	}
	if !list.HasNetworks() {
		t.Fatal("HasNetworks = false")
	}
	runtime := list.Runtime(time.Unix(1_800_000_400, 0))
	if len(runtime.Bans) != 2 || runtime.Bans[0].Client != "198.51.100.0/24" {
		t.Fatalf("runtime bans = %+v", runtime.Bans)
	}
	unmasked := List{Schema: Schema, NodeID: testNode, Revision: 1, IssuedAt: 1, Algorithm: Algorithm, KeyID: "k",
		Bans: []Ban{{SiteID: testSite, Client: "198.51.100.7/24", Until: 2, Source: "manual"}}, Releases: []Release{}}
	if _, err := SigningPayload(unmasked); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unmasked network accepted: %v", err)
	}
}
