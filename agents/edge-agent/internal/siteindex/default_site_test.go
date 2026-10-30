package siteindex

import "testing"

// site-backend6 默认站点: the default site's "" entry is indexed on its
// ports; two default sites on a port (only while scopes republish one after
// the other) leave the port without a fallback rather than fail the index.
func TestBuildDefaultSite(t *testing.T) {
	plain := testSite(1, "a.example.test", nil, 80)
	fallback := testSite(2, "b.example.test", nil, 80, 443)
	fallback.Default = true
	index, err := Build(1, []Object{object(t, plain), object(t, fallback)})
	if err != nil {
		t.Fatal(err)
	}
	want := object(t, fallback).Digest
	for _, port := range []int{80, 443} {
		if digest, ok := lookup(index, port, ""); !ok || digest != want {
			t.Fatalf("port %d default = %v %v, want the default site", port, digest, ok)
		}
	}
	second := testSite(3, "c.example.test", nil, 80)
	second.Default = true
	index, err = Build(1, []Object{object(t, plain), object(t, fallback), object(t, second)})
	if err != nil {
		t.Fatalf("two default sites: %v", err)
	}
	if _, ok := lookup(index, 80, ""); ok {
		t.Fatal("port 80 with two default sites must have no fallback")
	}
	if digest, ok := lookup(index, 443, ""); !ok || digest != want {
		t.Fatal("port 443 keeps its one default site")
	}
}
