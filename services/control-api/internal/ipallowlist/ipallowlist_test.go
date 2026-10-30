package ipallowlist

import (
	"reflect"
	"testing"
)

func TestNormalizeCanonicalizesAddressesAndPrefixes(t *testing.T) {
	got, err := Normalize([]string{"10.1.2.3/8", "192.0.2.7", "::ffff:192.0.2.7", "2001:db8::1/32", "198.51.100.4/32", "10.0.0.0/8"}, 32)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10.0.0.0/8", "192.0.2.7", "198.51.100.4", "2001:db8::/32"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	mapped, err := Canonical("::ffff:10.0.0.0/104")
	if err != nil || mapped != "10.0.0.0/8" {
		t.Fatalf("mapped prefix = %q %v", mapped, err)
	}
}

func TestNormalizeRejectsInvalidEntries(t *testing.T) {
	for _, raw := range []string{"", " 10.0.0.1", "10.0.0.1/33", "fe80::1%eth0", "host.example", "10.0.0.0/", "::ffff:10.0.0.0/90"} {
		if _, err := Normalize([]string{raw}, 32); err == nil {
			t.Fatalf("%q accepted", raw)
		}
	}
	if _, err := Normalize(nil, 32); err == nil {
		t.Fatal("nil accepted")
	}
	if _, err := Normalize([]string{"10.0.0.1", "10.0.0.2"}, 1); err == nil {
		t.Fatal("over limit accepted")
	}
}

func TestContainsMatchesAddressesAndPrefixes(t *testing.T) {
	entries := []string{"10.0.0.0/8", "192.0.2.7", "2001:db8::/32"}
	for source, want := range map[string]bool{
		"10.200.1.1": true, "::ffff:10.0.0.9": true, "192.0.2.7": true, "192.0.2.8": false,
		"2001:db8:1::5": true, "2001:db9::1": false, "": false, "not-an-ip": false, "11.0.0.1": false,
	} {
		if Contains(entries, source) != want {
			t.Fatalf("Contains(%q) != %v", source, want)
		}
	}
}
