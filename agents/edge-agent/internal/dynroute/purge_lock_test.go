package dynroute

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/dyncache"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
)

type okControl struct{}

func (okControl) Post(context.Context, string, []byte) ([]byte, error) {
	return []byte("{}"), nil
}

// purgeLockRuntime: one cached site in a one-zone pool, and a FIFO in its
// zone named like a cache file: the zone scan blocks opening it until the
// test opens it for writing (release), so a purge is held mid-scan.
func purgeLockRuntime(t *testing.T) (*Runtime, string, func()) {
	t.Helper()
	const prefix = "aaaaaaaa0000000000000000000000a1"
	runtime := newTestRuntime(t, 0)
	runtime.sites = []edgesite.Site{{SiteID: "s", TenantID: "t", Hosts: edgesite.Hosts{Primary: "a.test"},
		Listeners: []edgesite.Listener{{Port: 80}},
		Cache: &edgesite.Cache{KeyPrefix: prefix, Generation: "1111111111111111", Domain: "a.test", KeyByHost: true,
			Policy: edgeconfig.CachePolicyDocument{Mode: edgeconfig.CacheOverride, QueryMode: edgeconfig.CacheQueryPreserve}}}}
	runtime.zones = dyncache.Zones{Root: filepath.Join(t.TempDir(), "cache"), Count: 1}
	runtime.generations = &dyncache.Generations{Path: filepath.Join(t.TempDir(), "generations.json"), Control: okControl{}}
	zone, _ := runtime.zones.ZoneOf(prefix)
	key := prefix + "|1111111111111111|0|a.test|80|/dir/a.css"
	object := dyncache.FilePath(zone, key)
	if err := os.MkdirAll(filepath.Dir(object), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(object, append(make([]byte, 64), "\nKEY: "+key+"\n"...), 0o600); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(filepath.Dir(object), "ffffffffffffffffffffffffffffffff")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	released := false
	release := func() {
		if released {
			return
		}
		released = true
		writer, err := os.OpenFile(fifo, os.O_WRONLY, 0)
		if err != nil {
			t.Error(err)
			return
		}
		writer.Close()
	}
	t.Cleanup(release)
	return runtime, object, release
}

// A directory or site purge scans the zone
// without holding the runtime lock, so a long scan does not hold up the
// activation, telemetry or anything else that takes it.
func TestPurgeScanDoesNotHoldTheRuntimeLock(t *testing.T) {
	for _, name := range []string{"prefix", "site"} {
		t.Run(name, func(t *testing.T) {
			runtime, object, release := purgeLockRuntime(t)
			done := make(chan error, 1)
			go func() {
				var err error
				if name == "prefix" {
					var results []dyncache.Result
					results, err = runtime.Purge(context.Background(), "t", "s", []string{"http://a.test/dir/"}, true)
					if err == nil && results[0].Affected != 1 {
						t.Errorf("prefix purge removed %d", results[0].Affected)
					}
				} else {
					_, _, err = runtime.PurgeSite(context.Background(), "t", "s")
				}
				done <- err
			}()
			time.Sleep(200 * time.Millisecond) // the scan reaches the FIFO and blocks
			select {
			case err := <-done:
				t.Fatalf("purge returned before the scan was released: %v", err)
			default:
			}
			sites := make(chan int, 1)
			go func() { sites <- len(runtime.Sites()) }()
			select {
			case count := <-sites:
				if count != 1 {
					t.Fatalf("sites %d", count)
				}
			case <-time.After(2 * time.Second):
				release()
				<-done
				t.Fatal("Sites() waited for the purge scan: the runtime lock is held")
			}
			release()
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(object); !os.IsNotExist(err) {
				t.Fatalf("object kept: %v", err)
			}
		})
	}
}
