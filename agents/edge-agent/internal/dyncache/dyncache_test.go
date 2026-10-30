package dyncache

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

const (
	prefixA = "aaaaaaaa0000000000000000000000a1"
	prefixB = "aaaaaaaa0000000000000000000000b2" // same zone as A (same first 8 hex)
	tokenA  = "1111111111111111"
	tokenB  = "2222222222222222"
)

func siteA() Site {
	return Site{SiteID: "a", Prefix: prefixA, Token: tokenA, Domain: "a.test", KeyByHost: true,
		Names: []string{"a.test", "*.a.test"}, Ports: map[int]string{80: "http", 443: "https"}, QuotaBytes: 4 << 10}
}

func siteB() Site {
	return Site{SiteID: "b", Prefix: prefixB, Token: tokenB, Domain: "b.test", KeyByHost: true,
		Names: []string{"b.test"}, Ports: map[int]string{80: "http"}, QuotaBytes: 1 << 30}
}

// writeObject writes a file the way nginx does: <zone>/<last>/<2 before>/<md5>,
// a binary header, "\nKEY: <key>\n", then the response.
func writeObject(t *testing.T, zones Zones, prefix, key string, size int, accessed time.Time) string {
	t.Helper()
	dir, err := zones.ZoneOf(prefix)
	if err != nil {
		t.Fatal(err)
	}
	path := FilePath(dir, key)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	content := append(make([]byte, 64), []byte("\nKEY: "+key+"\nHTTP/1.1 200 OK\r\n\r\n")...)
	content = append(content, make([]byte, size)...)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, accessed, accessed); err != nil {
		t.Fatal(err)
	}
	return path
}

func key(site Site, generation uint64, host string, port int, policy string) string {
	return site.Prefix + "|" + site.Token + "|" + strconv.FormatUint(generation, 10) + "|" + host + "|" + strconv.Itoa(port) + "|" + policy
}

type fakeControl struct{ posts []string }

func (control *fakeControl) Post(_ context.Context, path string, body []byte) ([]byte, error) {
	control.posts = append(control.posts, path+" "+string(body))
	return []byte("{}"), nil
}

func exists(path string) bool { _, err := os.Stat(path); return err == nil }

func TestParseKey(t *testing.T) {
	parsed, ok := ParseKey(key(siteA(), 3, "www.a.test", 443, "/x/y.css?v=1"))
	if !ok || parsed.Generation != 3 || parsed.Host != "www.a.test" || parsed.Port != 443 || parsed.Path != "/x/y.css" || parsed.PolicyKey != "/x/y.css?v=1" {
		t.Fatalf("%+v %v", parsed, ok)
	}
	for _, bad := range []string{
		"v2|0a1b9999-0000-4000-8000-000000000001|site|config|a.test|80|/a", // v7 key
		prefixA + "|" + tokenA + "|x|a.test|80|/a",
		prefixA + "|" + tokenA + "|0|a.test|0|/a",
		prefixA + "|" + tokenA + "|0|a.test|80|a",
	} {
		if _, ok := ParseKey(bad); ok {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestPurgeIsolatesSites(t *testing.T) {
	ctx := context.Background()
	zones := Zones{Root: t.TempDir(), Count: 4}
	now := time.Now()
	a1 := writeObject(t, zones, prefixA, key(siteA(), 0, "a.test", 80, "/a.css"), 10, now)
	a2 := writeObject(t, zones, prefixA, key(siteA(), 0, "a.test", 80, "/dir/b.css"), 10, now)
	a3 := writeObject(t, zones, prefixA, key(siteA(), 0, "www.a.test", 80, "/a.css"), 10, now)
	a4 := writeObject(t, zones, prefixA, key(siteA(), 0, "a.test", 443, "/a.css"), 10, now)
	b1 := writeObject(t, zones, prefixB, key(siteB(), 0, "b.test", 80, "/a.css"), 10, now)
	b2 := writeObject(t, zones, prefixB, key(siteB(), 0, "b.test", 80, "/dir/b.css"), 10, now)

	target, err := ParseTarget(siteA(), "http://a.test/a.css", false)
	if err != nil {
		t.Fatal(err)
	}
	control := &fakeControl{}
	generations := &Generations{Path: filepath.Join(t.TempDir(), "gen.json"), Control: control}
	result, err := zones.Purge(ctx, siteA(), []Target{target}, false, generations)
	if err != nil || result.Affected != 1 || exists(a1) || !exists(a3) || !exists(a4) || !exists(b1) {
		t.Fatalf("exact (fast path): %+v %v", result, err)
	}
	// prefix: the directory only, this host and port only
	target, _ = ParseTarget(siteA(), "http://a.test/dir/", true)
	if result, err := zones.Purge(ctx, siteA(), []Target{target}, true, nil); err != nil || result.Affected != 1 || exists(a2) || !exists(b2) {
		t.Fatalf("prefix: %+v %v", result, err)
	}
	// whole site: generation bump + removal of the site's older objects; B untouched
	generation, result, err := zones.PurgeSite(ctx, generations, siteA())
	if err != nil || generation != 1 || result.Affected != 2 || exists(a3) || exists(a4) || !exists(b1) || !exists(b2) {
		t.Fatalf("site: gen %d %+v %v", generation, result, err)
	}
	var stored map[string]uint64
	raw, _ := os.ReadFile(generations.Path)
	if json.Unmarshal(raw, &stored) != nil || stored[prefixA] != 1 || stored[prefixB] != 0 {
		t.Fatalf("persisted %s", raw)
	}
	if len(control.posts) != 1 || control.posts[0] != fmt.Sprintf(`/cache/generations {"generations":{"%s":1}}`, prefixA) {
		t.Fatalf("control %v", control.posts)
	}
	// the node learns every generation after a start
	if err := generations.Sync(ctx); err != nil || control.posts[1] != fmt.Sprintf(`/cache/generations {"generations":{"%s":1},"replace":true}`, prefixA) {
		t.Fatalf("sync %v %v", control.posts, err)
	}
	// a URL the site does not serve is refused
	for _, bad := range []string{"http://b.test/a", "https://a.test:80/a", "ftp://a.test/a", "http://a.test:8080/a"} {
		if _, err := ParseTarget(siteA(), bad, false); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
	if _, err := ParseTarget(siteA(), "http://deep.www.a.test/a", false); err != nil {
		t.Errorf("wildcard name refused: %v", err)
	}
}

func TestProjectedKeysPurgeEveryVariant(t *testing.T) {
	zones := Zones{Root: t.TempDir(), Count: 1}
	site := siteA()
	site.Projected = true
	p1 := writeObject(t, zones, prefixA, key(site, 0, "a.test", 80, "/p.js?~q=aa&~v=bb"), 1, time.Now())
	p2 := writeObject(t, zones, prefixA, key(site, 0, "a.test", 80, "/p.js?~q=cc&~v=bb"), 1, time.Now())
	other := writeObject(t, zones, prefixA, key(site, 0, "a.test", 80, "/q.js?~q=aa&~v=bb"), 1, time.Now())
	target, _ := ParseTarget(site, "http://a.test/p.js?x=1", false)
	result, err := zones.Purge(context.Background(), site, []Target{target}, false, nil)
	if err != nil || result.Affected != 2 || exists(p1) || exists(p2) || !exists(other) {
		t.Fatalf("%+v %v", result, err)
	}
}

func TestSoftQuotaEvictsPerSite(t *testing.T) {
	zones := Zones{Root: t.TempDir(), Count: 4}
	base := time.Now().Add(-time.Hour)
	var aPaths []string
	for index := range 8 {
		aPaths = append(aPaths, writeObject(t, zones, prefixA, key(siteA(), 0, "a.test", 80, fmt.Sprintf("/%d", index)), 1000, base.Add(time.Duration(index)*time.Minute)))
	}
	var bPaths []string
	for index := range 8 {
		bPaths = append(bPaths, writeObject(t, zones, prefixB, key(siteB(), 0, "b.test", 80, fmt.Sprintf("/%d", index)), 1000, base))
	}
	usage, err := zones.UsageBySite(context.Background())
	if err != nil || usage[prefixA].Objects != 8 || usage[prefixB].Objects != 8 {
		t.Fatalf("%v %v", usage, err)
	}
	quotaA := siteA()
	quotaA.QuotaBytes = usage[prefixA].Bytes / 2
	result, err := zones.CleanQuota(context.Background(), map[string]Site{prefixA: quotaA, prefixB: siteB()}, 0.9)
	if err != nil || result.Sites != 1 || result.Removed < 4 {
		t.Fatalf("%+v %v", result, err)
	}
	// least recently used first; B (under its quota) untouched
	if exists(aPaths[0]) || !exists(aPaths[7]) {
		t.Fatal("not LRU order")
	}
	for _, path := range bPaths {
		if !exists(path) {
			t.Fatal("site B lost objects")
		}
	}
	after, _ := zones.UsageBySite(context.Background())
	if after[prefixA].Bytes > quotaA.QuotaBytes*9/10 {
		t.Fatalf("site A still at %d of %d", after[prefixA].Bytes, quotaA.QuotaBytes)
	}
}

func TestForeignAndTamperedFilesAreIgnored(t *testing.T) {
	zones := Zones{Root: t.TempDir(), Count: 1}
	path := writeObject(t, zones, prefixA, key(siteA(), 0, "a.test", 80, "/a"), 1, time.Now())
	// a file whose name is not md5(key) is never trusted (or removed)
	tampered := filepath.Join(filepath.Dir(path), "0123456789abcdef0123456789abcdef")
	raw, _ := os.ReadFile(path)
	if err := os.WriteFile(tampered, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	count := 0
	_ = zones.WalkAll(context.Background(), func(Entry) error { count++; return nil })
	if count != 1 {
		t.Fatalf("visited %d", count)
	}
	site := siteA()
	if _, _, err := zones.PurgeSite(context.Background(), &Generations{Path: filepath.Join(t.TempDir(), "g"), Control: &fakeControl{}}, site); err != nil {
		t.Fatal(err)
	}
	if !exists(tampered) || exists(path) {
		t.Fatal("purge touched an untrusted file or kept the site's object")
	}
}

// A slice variant's keys end in |slice=<range>: the policy key is what
// precedes it, so an exact URL purge removes every slice of the URL.
func TestSliceKeysPurgeEverySlice(t *testing.T) {
	plain := key(siteA(), 0, "www.a.test", 443, "/v.mp4")
	parsed, ok := ParseKey(plain + "|slice=bytes=1048576-2097151")
	if !ok || parsed.PolicyKey != "/v.mp4" || parsed.Path != "/v.mp4" || parsed.Slice != "bytes=1048576-2097151" {
		t.Fatalf("%+v %v", parsed, ok)
	}
	site := siteA()
	site.Sliced = true
	target := Target{Host: "www.a.test", Port: 443, URI: "/v.mp4", Path: "/v.mp4"}
	if !target.matches(site, parsed, false) {
		t.Fatal("slice of the URL not matched")
	}
	if whole, _ := ParseKey(plain); whole.Slice != "" || !target.matches(site, whole, false) {
		t.Fatalf("whole object %+v", whole)
	}
}

// CACHE_WILDCARD_PURGE（fp-site2，用户 Q4）：动态路由节点刷新 "*.a.test" 清掉本站
// 该后缀下所有主机的对象（精确 URL 与目录），不碰裸域、别的端口与别的站点。
func TestWildcardPurgeClearsHostsUnderSuffix(t *testing.T) {
	ctx := context.Background()
	zones := Zones{Root: t.TempDir(), Count: 4}
	now := time.Now()
	www := writeObject(t, zones, prefixA, key(siteA(), 0, "www.a.test", 80, "/a.css"), 10, now)
	deep := writeObject(t, zones, prefixA, key(siteA(), 0, "x.y.a.test", 80, "/a.css"), 10, now)
	bare := writeObject(t, zones, prefixA, key(siteA(), 0, "a.test", 80, "/a.css"), 10, now)
	tls := writeObject(t, zones, prefixA, key(siteA(), 0, "www.a.test", 443, "/a.css"), 10, now)
	other := writeObject(t, zones, prefixA, key(siteA(), 0, "www.a.test", 80, "/b.css"), 10, now)
	dir := writeObject(t, zones, prefixA, key(siteA(), 0, "img.a.test", 80, "/dir/c.css"), 10, now)
	b1 := writeObject(t, zones, prefixB, key(siteB(), 0, "b.test", 80, "/a.css"), 10, now)

	target, err := ParseTarget(siteA(), "http://*.a.test/a.css", false)
	if err != nil || target.WildcardSuffix != "a.test" {
		t.Fatalf("parse: %+v %v", target, err)
	}
	generations := &Generations{Path: filepath.Join(t.TempDir(), "gen.json"), Control: &fakeControl{}}
	result, err := zones.Purge(ctx, siteA(), []Target{target}, false, generations)
	if err != nil || result.Affected != 2 || exists(www) || exists(deep) || !exists(bare) || !exists(tls) || !exists(other) || !exists(b1) {
		t.Fatalf("wildcard exact: %+v %v", result, err)
	}
	target, _ = ParseTarget(siteA(), "http://*.a.test/dir/", true)
	if result, err := zones.Purge(ctx, siteA(), []Target{target}, true, nil); err != nil || result.Affected != 1 || exists(dir) {
		t.Fatalf("wildcard prefix: %+v %v", result, err)
	}
	for _, bad := range []string{"http://*.test/a", "http://*.b.test/a", "http://*.*.a.test/a", "http://w*.a.test/a"} {
		if _, err := ParseTarget(siteA(), bad, false); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
	// 按站点主域名记键的站点：主域名在通配下才清。
	byDomain := siteA()
	byDomain.KeyByHost, byDomain.Domain = false, "*.a.test"
	keyed := writeObject(t, zones, prefixA, key(byDomain, 0, "*.a.test", 80, "/k.css"), 10, now)
	target, _ = ParseTarget(byDomain, "http://*.a.test/k.css", false)
	if result, err := zones.Purge(ctx, byDomain, []Target{target}, false, nil); err != nil || result.Affected != 1 || exists(keyed) {
		t.Fatalf("domain-keyed wildcard: %+v %v", result, err)
	}
}
