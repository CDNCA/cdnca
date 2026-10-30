package xdp

import "testing"

func TestSNIHashIsReversedLowerCaseFNV(t *testing.T) {
	// The program hashes from the last byte, so the suffix after a dot is
	// a prefix of the walk: example.com's hash is reached on the way to
	// www.example.com.
	if sniHash("Example.COM") != sniHash("example.com") {
		t.Fatal("hash is case sensitive")
	}
	if sniHash("example.com") == sniHash("moc.elpmaxe") {
		t.Fatal("hash does not walk backwards")
	}
}

func TestSiteDropEntries(t *testing.T) {
	entries, err := SiteDrop{
		SNIPorts:  []uint16{443},
		DropNames: []string{"a.example.com", "*.example.com", "*.", "bad*.example.com", "Shop.Example.NET."},
		KeepNames: []string{"keep.example.com", "*.example.com"},
	}.sniEntries()
	if err != nil {
		t.Fatal(err)
	}
	want := map[uint64]uint8{
		sniHash("a.example.com"):    sniDropExact,
		sniHash("example.com"):      sniDropWildcard | sniKeepWildcard,
		sniHash("shop.example.net"): sniDropExact,
		sniHash("keep.example.com"): sniKeepExact,
	}
	if len(entries) != len(want) {
		t.Fatalf("entries = %v", entries)
	}
	for key, flags := range want {
		if entries[key] != flags {
			t.Fatalf("entry %x = %d, want %d", key, entries[key], flags)
		}
	}
	if !(SiteDrop{SNIPorts: []uint16{443}}).empty() || (SiteDrop{Ports: []uint16{1}}).empty() {
		t.Fatal("empty is wrong")
	}
}
