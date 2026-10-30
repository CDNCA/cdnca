package nativebackup

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// A console opened with enable-gateway-access (or installed --mode control)
// keeps its Gateway settings in systemd drop-ins, nftables units and a Redis
// include directory. They must move with a migration, so the new host runs
// with Gateway access without running enable-gateway-access again.
func TestGatewayAccessFilesTravelWithConfigAndRuntime(t *testing.T) {
	source := Layout{Root: t.TempDir()}
	files := map[string]string{
		"etc/cdnca-control/control.env":                                           "A=1\n",
		"etc/cdnca-control/gateway-access.env":                                    "REDIS_URL=redis://:p@127.0.0.1:6379/0\n",
		"etc/redis/cdnca-gateway/redis-gateway.conf":                              "requirepass p\n",
		"etc/redis/cdnca-gateway/server.pem":                                      "pem",
		"etc/redis/redis.conf":                                                    "port 6379\ninclude /etc/redis/cdnca-gateway/redis-gateway.conf\n",
		"etc/systemd/system/cdnca-control-api.service.d/60-gateway-access.conf":   "[Service]\nEnvironmentFile=/etc/cdnca-control/gateway-access.env\n",
		"etc/systemd/system/cdnca-control-api.service.d/50-dns-runtime.conf":      "[Service]\n",
		"etc/systemd/system/cdnca-agent-gateway.service.d/60-gateway-access.conf": "[Service]\nEnvironmentFile=/etc/cdnca-control/gateway-access-local.env\n",
		"etc/systemd/system/cdnca-gateway-access.service":                         "[Unit]\n",
		"etc/systemd/system/cdnca-gateway-access.path":                            "[Path]\n",
		"etc/systemd/system/cdnca-gateway-access-reload.service":                  "[Unit]\n",
		"data/cdnca-native-root/cdnca/current":                                    "x",
		"var/lib/cdnca-control/gateway-access/allowed-ips":                        "203.0.113.7\n",
	}
	writeTree(t, source.Root, files, nil)

	target := Layout{Root: t.TempDir()}
	owners := &recordingOwners{chowned: map[string][2]int{}}
	for _, paths := range [][]treePath{configPaths, runtimePaths} {
		var archive bytes.Buffer
		if _, err := ArchiveTree(source, paths, &archive); err != nil {
			t.Fatal(err)
		}
		if _, err := ExtractTree(target, paths, owners, &archive); err != nil {
			t.Fatal(err)
		}
	}
	for name, want := range files {
		got, err := os.ReadFile(filepath.Join(target.Root, name))
		switch name {
		case "etc/redis/redis.conf", "etc/systemd/system/cdnca-control-api.service.d/50-dns-runtime.conf":
			// The distribution's Redis configuration belongs to the dependency
			// installer on the target; the DNS drop-in is out of scope here.
			if err == nil {
				t.Errorf("%s must not be archived", name)
			}
		default:
			if err != nil || string(got) != want {
				t.Errorf("%s = %q, %v; want %q", name, got, err, want)
			}
		}
	}
}

type gatewayRestoreRig struct {
	*testRig
	bundle Bundle
}

// gatewayRig prepares a target after the tree components have restored the
// Gateway access files (memory components stand in for the trees).
func gatewayRig(t *testing.T, redisConfig, includeDir string) gatewayRestoreRig {
	rig := newRig(t)
	bundle := rig.backupBundle()
	write := func(name, content string) {
		path := rig.host.Layout.Path(name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(redisConfig, "port 6379\n")
	if includeDir != "" {
		write(includeDir+"/redis-gateway.conf", "requirepass p\n")
		write("/etc/systemd/system/cdnca-gateway-access.service", "[Unit]\n")
		write("/etc/systemd/system/cdnca-gateway-access.path", "[Path]\n")
	}
	write("/etc/systemd/system/cdnca-control-api.service", "[Unit]\n")
	rig.systemd.states["redis-server.service"] = &UnitState{Loaded: true, Active: true, Enabled: true}
	rig.systemd.calls = nil
	return gatewayRestoreRig{testRig: rig, bundle: bundle}
}

func TestRestoreAttachesRedisGatewayIncludeAndStartsFirewallFirst(t *testing.T) {
	rig := gatewayRig(t, "/etc/redis/redis.conf", "/etc/redis/cdnca-gateway")
	if _, err := rig.restorer(nil).Run(context.Background(), RestoreRequest{Bundle: rig.bundle, Identity: rig.keys.Identity}); err != nil {
		t.Fatal(err)
	}
	config, _ := os.ReadFile(rig.host.Layout.Path("/etc/redis/redis.conf"))
	if want := "port 6379\n\ninclude /etc/redis/cdnca-gateway/redis-gateway.conf\n"; string(config) != want {
		t.Fatalf("redis.conf = %q", config)
	}
	want := []string{"daemon-reload", "stop redis-server.service", "start redis-server.service",
		"enable cdnca-gateway-access.service", "start cdnca-gateway-access.service",
		"enable cdnca-gateway-access.path", "start cdnca-gateway-access.path",
		"enable cdnca-control-api.service", "start cdnca-control-api.service"}
	if !reflect.DeepEqual(rig.systemd.calls, want) {
		t.Fatalf("calls = %v", rig.systemd.calls)
	}
}

func TestRestoreLeavesRedisAloneWithoutGatewayAccess(t *testing.T) {
	rig := gatewayRig(t, "/etc/redis/redis.conf", "")
	if _, err := rig.restorer(nil).Run(context.Background(), RestoreRequest{Bundle: rig.bundle, Identity: rig.keys.Identity}); err != nil {
		t.Fatal(err)
	}
	if config, _ := os.ReadFile(rig.host.Layout.Path("/etc/redis/redis.conf")); string(config) != "port 6379\n" {
		t.Fatalf("redis.conf changed: %q", config)
	}
	for _, call := range rig.systemd.calls {
		if strings.Contains(call, "redis") || strings.Contains(call, "gateway-access") {
			t.Fatalf("unexpected %q in %v", call, rig.systemd.calls)
		}
	}
}

func TestRestoreDoesNotDuplicateRedisInclude(t *testing.T) {
	rig := gatewayRig(t, "/etc/redis.conf", "/etc/cdnca-gateway")
	line := "include /etc/cdnca-gateway/redis-gateway.conf"
	_ = os.WriteFile(rig.host.Layout.Path("/etc/redis.conf"), []byte("port 6379\n"+line+"\n"), 0o644)
	if _, err := rig.restorer(nil).Run(context.Background(), RestoreRequest{Bundle: rig.bundle, Identity: rig.keys.Identity}); err != nil {
		t.Fatal(err)
	}
	config, _ := os.ReadFile(rig.host.Layout.Path("/etc/redis.conf"))
	if strings.Count(string(config), line) != 1 || slices.Contains(rig.systemd.calls, "stop redis-server.service") {
		t.Fatalf("redis.conf = %q calls = %v", config, rig.systemd.calls)
	}
}

func TestRestorePreflightRequiresNftablesForGatewayAccess(t *testing.T) {
	rig := newRig(t)
	bundle := rig.backupBundle()
	for index := range bundle.Manifest.Components {
		if bundle.Manifest.Components[index].Name == ComponentRuntime {
			bundle.Manifest.Components[index].Detail = map[string]string{"paths": NativeRoot + "," + gatewayAccessFirewallUnit}
		}
	}
	restorer := rig.restorer(nil)
	_, err := restorer.Run(context.Background(), RestoreRequest{Bundle: bundle, Identity: rig.keys.Identity})
	if err == nil || !strings.Contains(err.Error(), "restore_target_missing_nftables") || len(rig.restored) != 0 {
		t.Fatalf("err = %v restored = %v", err, rig.restored)
	}
	nft := rig.host.Layout.Path("/usr/sbin/nft")
	_ = os.MkdirAll(filepath.Dir(nft), 0o755)
	_ = os.WriteFile(nft, nil, 0o755)
	if err := restorer.preflightGatewayAccess(bundle.Manifest); err != nil {
		t.Fatal(err)
	}
}
