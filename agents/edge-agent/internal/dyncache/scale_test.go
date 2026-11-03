//go:build scale

// Scale benchmark of the zone-scan purges (tests/scale/cache-purge/run.sh).
// Not part of the normal suite:
//
//	go test -c -tags scale -o dyncache.test ./internal/dyncache
//	SCALE_ROOT=/data/ds SCALE_TARGET=1000000 SCALE_OTHER=0 ./dyncache.test -test.run TestScaleGenerate
//	SCALE_ROOT=/data/ds SCALE_TARGET=1000000 ./dyncache.test -test.run TestScaleRepair
//	SCALE_ROOT=/data/ds SCALE_SCENARIO=dir10 ./dyncache.test -test.run TestScaleRun -test.v
//
// Files are laid out as nginx writes them (levels=1:2, md5(key) file name,
// a 336-byte binary header, "\nKEY: <key>\n", the response header, the body).
// The target site is s0; the zone may also hold SCALE_OTHER files of nine
// other sites (the zone is shared by every site whose prefix maps to it).
//
// Target site file i: path /d<i%10>/e<(i/10)%10>/f<i>.css; host www.s0.test,
// except d9 files (10%) on a<(i/100)%10>.img.s0.test. So /d0/ is 10% of the
// site, /d0/e0/ 1%, "*.img.s0.test" 10%, "*.img.s0.test/d9/e0/" 1%.
package dyncache

import (
	"context"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func scaleEnv(t *testing.T, name string, fallback int) int {
	raw := os.Getenv(name)
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return value
}

func scalePrefix(site int) string {
	digest := md5.Sum([]byte("scale-site-" + strconv.Itoa(site)))
	return hex.EncodeToString(digest[:])
}

const scaleToken = "0123456789abcdef"

// scaleSite is the target site s0 (key by host, a wildcard alias).
func scaleSite() Site {
	return Site{SiteID: "s0", Prefix: scalePrefix(0), Token: scaleToken, Domain: "www.s0.test", KeyByHost: true,
		Names: []string{"www.s0.test", "*.img.s0.test"}, Ports: map[int]string{80: "http"}}
}

func scaleKey(site, index int) string {
	host := "www.s" + strconv.Itoa(site) + ".test"
	if site == 0 && index%10 == 9 {
		host = "a" + strconv.Itoa(index/100%10) + ".img.s0.test"
	}
	return scalePrefix(site) + "|" + scaleToken + "|0|" + host + "|80|/d" + strconv.Itoa(index%10) + "/e" +
		strconv.Itoa(index/10%10) + "/f" + strconv.Itoa(index) + ".css"
}

func scaleZones(root string) Zones { return Zones{Root: filepath.Join(root, "cache"), Count: 1} }

// scaleContent is a cache file as nginx writes it (ngx_http_file_cache_header_t
// v5 is 336 bytes on 64-bit Linux; the key line follows it).
func scaleContent(key string, body int) []byte {
	header := make([]byte, 336)
	binary.LittleEndian.PutUint64(header, 5)
	response := "HTTP/1.1 200 OK\r\nContent-Type: text/css\r\nContent-Length: " + strconv.Itoa(body) + "\r\n\r\n"
	content := append(header, "\nKEY: "+key+"\n"+response...)
	return append(content, make([]byte, body)...)
}

// scaleEach runs fn(site, index) over the dataset with 32 workers: target
// files 0..target-1 of s0, then other files spread over s1..s9.
func scaleEach(target, other int, fn func(site, index int) error) error {
	var next atomic.Int64
	var failure atomic.Value
	var group sync.WaitGroup
	total := int64(target + other)
	for range 32 {
		group.Add(1)
		go func() {
			defer group.Done()
			for {
				start := next.Add(4096) - 4096
				if start >= total || failure.Load() != nil {
					return
				}
				for item := start; item < min(start+4096, total); item++ {
					site, index := 0, int(item)
					if item >= int64(target) {
						j := int(item) - target
						site, index = j%9+1, j/9
					}
					if err := fn(site, index); err != nil {
						failure.Store(err)
						return
					}
				}
			}
		}()
	}
	group.Wait()
	if err, _ := failure.Load().(error); err != nil {
		return err
	}
	return nil
}

func scaleWrite(dir string, body int, onlyMissing bool) func(site, index int) error {
	return func(site, index int) error {
		key := scaleKey(site, index)
		path := FilePath(dir, key)
		if onlyMissing {
			if _, err := os.Lstat(path); err == nil {
				return nil
			}
		}
		return os.WriteFile(path, scaleContent(key, body), 0o600)
	}
}

func scaleDirs(dir string) error {
	for first := range 16 {
		for second := range 256 {
			if err := os.MkdirAll(filepath.Join(dir, fmt.Sprintf("%x", first), fmt.Sprintf("%02x", second)), 0o700); err != nil {
				return err
			}
		}
	}
	return nil
}

// TestScaleGenerate writes the dataset (SCALE_TARGET s0 files, SCALE_OTHER
// files of s1..s9, SCALE_BODY body bytes).
func TestScaleGenerate(t *testing.T) {
	root := os.Getenv("SCALE_ROOT")
	if root == "" {
		t.Skip("SCALE_ROOT not set")
	}
	target, other, body := scaleEnv(t, "SCALE_TARGET", 100000), scaleEnv(t, "SCALE_OTHER", 0), scaleEnv(t, "SCALE_BODY", 1024)
	dir, _ := scaleZones(root).ZoneOf(scalePrefix(0))
	if err := scaleDirs(dir); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if err := scaleEach(target, other, scaleWrite(dir, body, false)); err != nil {
		t.Fatal(err)
	}
	meta, _ := json.Marshal(map[string]int{"target": target, "other": other, "body": body})
	if err := os.WriteFile(filepath.Join(root, "dataset.json"), meta, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Logf("generated %d files in %s", target+other, time.Since(started))
}

func scaleDataset(t *testing.T, root string) (target, other, body int) {
	raw, err := os.ReadFile(filepath.Join(root, "dataset.json"))
	if err != nil {
		t.Fatal(err)
	}
	var meta map[string]int
	if err := json.Unmarshal(raw, &meta); err != nil {
		t.Fatal(err)
	}
	return meta["target"], meta["other"], meta["body"]
}

// scaleRemoved: the target files a scenario removes (SCALE_SCENARIO of the
// run; "i" prefix = the same purge through the index); nil = unknown.
func scaleRemoved(scenario string) func(index int) bool {
	switch strings.TrimPrefix(scenario, "i") {
	case "dir10":
		return func(index int) bool { return index%10 == 0 }
	case "dir1":
		return func(index int) bool { return index%100 == 0 }
	case "wild10":
		return func(index int) bool { return index%10 == 9 }
	case "wild1":
		return func(index int) bool { return index%100 == 9 }
	case "wildexact":
		return func(index int) bool { return index == 9 }
	case "exact", "exactscan":
		return func(index int) bool { return index == 21 }
	case "site":
		return func(int) bool { return true }
	}
	return nil
}

// TestScaleRepair rewrites the target site's files a run removed: those of
// SCALE_SCENARIO, else every missing one (an lstat per file).
func TestScaleRepair(t *testing.T) {
	root := os.Getenv("SCALE_ROOT")
	if root == "" {
		t.Skip("SCALE_ROOT not set")
	}
	target, _, body := scaleDataset(t, root)
	dir, _ := scaleZones(root).ZoneOf(scalePrefix(0))
	started := time.Now()
	write := scaleWrite(dir, body, true)
	if removed := scaleRemoved(os.Getenv("SCALE_SCENARIO")); removed != nil {
		rewrite := scaleWrite(dir, body, false)
		write = func(site, index int) error {
			if !removed(index) {
				return nil
			}
			return rewrite(site, index)
		}
	}
	if err := scaleEach(target, 0, write); err != nil {
		t.Fatal(err)
	}
	t.Logf("repaired in %s", time.Since(started))
}

// scaleIO is /proc/self/io (zero off Linux).
func scaleIO() map[string]int64 {
	values := map[string]int64{}
	raw, err := os.ReadFile("/proc/self/io")
	if err != nil {
		return values
	}
	for _, line := range strings.Split(string(raw), "\n") {
		name, value, ok := strings.Cut(line, ": ")
		if ok {
			values[name], _ = strconv.ParseInt(value, 10, 64)
		}
	}
	return values
}

// scaleScenarios are the purges measured; each returns what it removed.
func scaleScenarios(t *testing.T, zones Zones, root string) map[string]func(context.Context) (Result, error) {
	site := scaleSite()
	parse := func(raw string, prefix bool) []Target {
		target, err := ParseTarget(site, raw, prefix)
		if err != nil {
			t.Fatal(err)
		}
		return []Target{target}
	}
	generations := &Generations{Path: filepath.Join(t.TempDir(), "generations.json"), Control: &fakeControl{}}
	purge := func(raw string, prefix bool, generations *Generations) func(context.Context) (Result, error) {
		targets := parse(raw, prefix)
		return func(ctx context.Context) (Result, error) { return zones.Purge(ctx, site, targets, prefix, generations) }
	}
	projected := site
	projected.Projected = true
	exactTargets := parse("http://www.s0.test/d1/e2/f21.css", false)
	scenarios := map[string]func(context.Context) (Result, error){
		"dir10":     purge("http://www.s0.test/d0/", true, nil),
		"dir1":      purge("http://www.s0.test/d0/e0/", true, nil),
		"wild10":    purge("http://*.img.s0.test/", true, nil),
		"wild1":     purge("http://*.img.s0.test/d9/e0/", true, nil),
		"wildexact": purge("http://*.img.s0.test/d9/e0/f9.css", false, nil),
		"exact":     purge("http://www.s0.test/d1/e2/f21.css", false, generations),
		"exactscan": func(ctx context.Context) (Result, error) {
			return zones.Purge(ctx, projected, exactTargets, false, generations)
		},
		"site": func(ctx context.Context) (Result, error) {
			_, result, err := zones.PurgeSite(ctx, generations, site)
			return result, err
		},
		"usage": func(ctx context.Context) (Result, error) {
			usage, err := zones.UsageBySite(ctx)
			var result Result
			for _, value := range usage {
				result.Affected += value.Objects
			}
			return result, err
		},
	}
	if scaleIndexScenarios != nil {
		for name, scenario := range scaleIndexScenarios(t, zones, root) {
			scenarios[name] = scenario
		}
	}
	return scenarios
}

// scaleIndexScenarios (scale_index_test.go) adds the
// index scenarios; scaleNotes are extra result fields they report.
var (
	scaleIndexScenarios func(t *testing.T, zones Zones, root string) map[string]func(context.Context) (Result, error)
	scaleNotes          = map[string]any{}
)

// TestScaleRun runs SCALE_SCENARIO once and prints one SCALE_RESULT line
// (SCALE_DEADLINE, default 1h = the control plane's lease, bounds it).
func TestScaleRun(t *testing.T) {
	root := os.Getenv("SCALE_ROOT")
	if root == "" {
		t.Skip("SCALE_ROOT not set")
	}
	target, other, body := scaleDataset(t, root)
	name := os.Getenv("SCALE_SCENARIO")
	scenario, ok := scaleScenarios(t, scaleZones(root), root)[name]
	if !ok {
		t.Fatalf("unknown scenario %q", name)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(scaleEnv(t, "SCALE_DEADLINE", 3600))*time.Second)
	defer cancel()
	runtime.GC()
	var peak atomic.Uint64
	done := make(chan struct{})
	go func() {
		var stats runtime.MemStats
		for {
			runtime.ReadMemStats(&stats)
			if stats.HeapInuse > peak.Load() {
				peak.Store(stats.HeapInuse)
			}
			select {
			case <-done:
				return
			case <-time.After(50 * time.Millisecond):
			}
		}
	}()
	var before, after syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &before)
	ioBefore := scaleIO()
	started := time.Now()
	result, err := scenario(ctx)
	elapsed := time.Since(started)
	ioAfter := scaleIO()
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &after)
	close(done)
	failure := ""
	if err != nil {
		failure = err.Error()
	}
	cpu := func(value syscall.Timeval) float64 { return float64(value.Sec) + float64(value.Usec)/1e6 }
	fields := map[string]any{
		"scenario": name, "label": os.Getenv("SCALE_LABEL"), "target": target, "other": other, "body": body,
		"seconds": elapsed.Seconds(), "affected": result.Affected, "error": failure,
		"user_s": cpu(after.Utime) - cpu(before.Utime), "sys_s": cpu(after.Stime) - cpu(before.Stime),
		"maxrss_kb": after.Maxrss, "heap_peak_mb": float64(peak.Load()) / (1 << 20),
		"read_bytes_mb":  float64(ioAfter["read_bytes"]-ioBefore["read_bytes"]) / (1 << 20),
		"rchar_mb":       float64(ioAfter["rchar"]-ioBefore["rchar"]) / (1 << 20),
		"syscr":          ioAfter["syscr"] - ioBefore["syscr"],
		"write_bytes_mb": float64(ioAfter["write_bytes"]-ioBefore["write_bytes"]) / (1 << 20),
	}
	for name, value := range scaleNotes {
		fields[name] = value
	}
	line, _ := json.Marshal(fields)
	fmt.Println("SCALE_RESULT " + string(line))
}
