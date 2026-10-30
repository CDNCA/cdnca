package node

import (
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/protobuf/proto"
)

func TestDeclaresStorage(t *testing.T) {
	encode := func(features ...*agentv1.Capability) []byte {
		payload, err := proto.Marshal(&agentv1.AgentCapabilities{Features: features})
		if err != nil {
			t.Fatal(err)
		}
		return payload
	}
	if !DeclaresStorage(encode(&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_NODE_STORAGE, ApiVersion: 1})) {
		t.Fatal("v1 not declared")
	}
	if DeclaresStorage(nil) || DeclaresStorage([]byte{0xff}) ||
		DeclaresStorage(encode(&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_NODE_REGION, ApiVersion: 1})) {
		t.Fatal("old agent / no snapshot must read as not declared")
	}
}

// The cache limit is checked against the reported disk holding the cache
// directory (longest path prefix; the directory the node runs when none is
// set); no telemetry = not checked.
func TestCacheDiskBytes(t *testing.T) {
	telemetry := []byte(`{"disks":[{"path":"/","total_bytes":50},{"path":"/data","total_bytes":2000},{"path":"/data2","total_bytes":7}],
		"storage":{"cache_directory":"/data/run/cache"}}`)
	for directory, want := range map[string]uint64{
		"/data/cache": 2000, "/data": 2000, "/var/cache/x": 50, "/data2/x": 7, "/datax/y": 50, "": 2000,
	} {
		if got := cacheDiskBytes(telemetry, directory); got != want {
			t.Errorf("%q: %d, want %d", directory, got, want)
		}
	}
	if cacheDiskBytes(nil, "/data/x") != 0 || cacheDiskBytes([]byte("{"), "/data/x") != 0 {
		t.Fatal("no telemetry must be unknown")
	}
}

func TestNormalizeManagementSettingsStorage(t *testing.T) {
	valid := func(mutate func(*NodeManagementSettings)) NodeManagementSettings {
		settings := DefaultNodeManagementSettings()
		mutate(&settings)
		return settings
	}
	// Existing rows keep being editable (other tabs): the storage rules apply
	// when the storage itself changes (checkStorageChange), not to every save.
	settings := valid(func(s *NodeManagementSettings) { s.CacheDirectory = "/etc/legacy" })
	if err := normalizeManagementSettings(&settings); err != nil {
		t.Fatalf("legacy value refused on save: %v", err)
	}
	if !sameStorage(settings, settings) {
		t.Fatal("sameStorage")
	}
	changed := settings
	changed.CacheLimitGB = 1
	if sameStorage(settings, changed) {
		t.Fatal("limit change not seen")
	}
	if (NodeManagementSettings{CacheDirectory: "/data/c", CacheLimitGB: 2, LogDirectory: "/data/l"}).Storage().CacheMaxBytes != 2<<30 {
		t.Fatal("GB to bytes")
	}
}
