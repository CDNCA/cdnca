package siteobject

import (
	"bytes"
	"errors"
	"testing"
)

func TestValidNodeStorageDirectory(t *testing.T) {
	for _, good := range []string{"/data/cache", "/var/cache/cdnca", "/var/lib/cdnca/c1", "/var/log/cdnca", "/opt/x", "/srv/a.b_c-d", "/mnt/disk1/cache"} {
		if !ValidNodeStorageDirectory(good) {
			t.Errorf("%q refused", good)
		}
	}
	for _, bad := range []string{"", "/", "/data", "/data/", "/etc/cdnca", "/usr/local/cache", "/tmp/cache", "/root/c", "/home/a",
		"/var/tmp/x", "/variable/x", "/data/../etc", "/data/./x", "data/cache", "/data//x", "/data/a b", "/data/a;b", "/data/$x",
		"/data/缓存", "/data/a\nb", "/datax/y", "/proc/x", "/run/x"} {
		if ValidNodeStorageDirectory(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestNodeStorageValidate(t *testing.T) {
	cases := []struct {
		storage NodeStorage
		ok      bool
	}{
		{NodeStorage{}, true},
		{NodeStorage{CacheDirectory: "/data/cache", CacheMaxBytes: 10 << 30, LogDirectory: "/data/logs"}, true},
		{NodeStorage{CacheDirectory: "/data/x", LogDirectory: "/data/x"}, false},
		{NodeStorage{CacheDirectory: "/data/x", LogDirectory: "/data/x/logs"}, false},
		{NodeStorage{CacheDirectory: "/data/x/cache", LogDirectory: "/data/x"}, false},
		{NodeStorage{CacheDirectory: "/data/x", LogDirectory: "/data/xy"}, true},
		{NodeStorage{CacheMaxBytes: 1 << 20}, false},
		{NodeStorage{CacheMaxBytes: -1}, false},
		{NodeStorage{CacheMaxBytes: NodeStorageMaxCacheBytes + 1}, false},
	}
	for _, c := range cases {
		if got := c.storage.Validate(); got != c.ok {
			t.Errorf("%+v: Validate = %v", c.storage, got)
		}
	}
}

// NODE_STORAGE v1: the key document carries the node's storage settings;
// omitted when none, an empty or invalid object is refused.
func TestKeyDocumentNodeStorage(t *testing.T) {
	document := keyDocumentFixture(nil)
	document.NodeStorage = &NodeStorage{CacheDirectory: "/data/cache", CacheMaxBytes: 2 << 30, LogDirectory: "/data/logs"}
	encoded, err := Encode(document)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseKeyDocument(encoded)
	if err != nil || parsed.NodeStorage == nil || *parsed.NodeStorage != *document.NodeStorage {
		t.Fatalf("parse = %+v, %v", parsed.NodeStorage, err)
	}
	plain, err := Encode(keyDocumentFixture(nil))
	if err != nil || bytes.Contains(plain, []byte("node_storage")) {
		t.Fatalf("no storage encoded as %s (%v)", plain, err)
	}
	for _, bad := range []NodeStorage{{}, {CacheDirectory: "/etc/x"}, {CacheMaxBytes: 1}} {
		document.NodeStorage = &bad
		encoded, err := Encode(document)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseKeyDocument(encoded); !errors.Is(err, ErrInvalid) {
			t.Fatalf("storage %+v: err = %v", bad, err)
		}
	}
}
