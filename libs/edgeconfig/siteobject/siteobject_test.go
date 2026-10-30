package siteobject

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"slices"
	"testing"
)

const testScopeID = "5c0b0000-0000-4000-8000-000000000001"

func TestSealOpen(t *testing.T) {
	key := make([]byte, ContentKeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	plaintext := []byte(`{"schema":"cdnca.edge.site/v2"}`)
	digest, wire, err := Seal(key, testScopeID, plaintext)
	if err != nil || digest != Digest(plaintext) {
		t.Fatal(err)
	}
	again, wireAgain, err := Seal(key, testScopeID, plaintext)
	if err != nil || again != digest || !bytes.Equal(wire, wireAgain) {
		t.Fatal("sealing is not deterministic for one key and plaintext")
	}
	opened, err := Open(key, testScopeID, digest, wire)
	if err != nil || !bytes.Equal(opened, plaintext) {
		t.Fatal(err)
	}
	other := bytes.Clone(key)
	other[0] ^= 1
	if _, err := Open(other, testScopeID, digest, wire); err == nil {
		t.Fatal("opened with another key")
	}
	if _, err := Open(key, "5c0b0000-0000-4000-8000-000000000002", digest, wire); err == nil {
		t.Fatal("opened under another scope")
	}
	if _, err := Open(key, testScopeID, Digest([]byte("x")), wire); err == nil {
		t.Fatal("opened under another digest")
	}
	if _, _, err := Seal(key, testScopeID, []byte{}); err != nil {
		t.Fatal("an empty file object must seal")
	}
}

func TestBucketCountAndIndex(t *testing.T) {
	for sites, want := range map[int]int{0: 1, 1: 1, 256: 1, 257: 2, 5000: 32, MaxSites: MaxBuckets} {
		if got, err := BucketCount(sites); err != nil || got != want {
			t.Fatalf("BucketCount(%d) = %d, %v; want %d", sites, got, err, want)
		}
	}
	if _, err := BucketCount(MaxSites + 1); err == nil {
		t.Fatal("more sites than the format bound were accepted")
	}
	for index := 0; index < 1000; index++ {
		siteID := fmt.Sprintf("%08x-0000-4000-8000-000000000000", index)
		small, large := BucketIndex(siteID, 8), BucketIndex(siteID, 16)
		if large%8 != small {
			t.Fatalf("doubling moved %s from %d to %d", siteID, small, large)
		}
	}
}

func TestRootCapabilitiesV2(t *testing.T) {
	got, err := RootCapabilitiesV2([]Capability{{"cc", 2}, {"site_runtime", 4}})
	if err != nil || !slices.Equal(got, []Capability{{"cc", 2}, {"site_runtime", DynamicRoutingSiteRuntimeVersion}}) {
		t.Fatalf("%v %v", got, err)
	}
	if _, err := RootCapabilitiesV2([]Capability{{"site_runtime", 8}}); err == nil {
		t.Fatal("an inner document above the document site_runtime range was accepted")
	}
	if _, err := RootCapabilitiesV2([]Capability{{"http1", 1}}); err == nil {
		t.Fatal("capabilities without site_runtime were accepted")
	}
}
