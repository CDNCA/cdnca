package cachetask

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// FX20: 刷新必须覆盖新鲜度站点（缓存键带 generation|token 前缀）与 Range 切片缓存区。

func putRawCacheEntry(t *testing.T, root, key string) string {
	t.Helper()
	path := nginxCachePath(root, key)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("\x00\x00\nKEY: "+key+"\ncache-body"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func freshnessKey(generation, token string, site SiteContext, port uint16, requestURI string) string {
	return generation + "|" + token + "|v=1|tenant=" + site.TenantID + "|site=" + site.SiteID +
		"|config=" + strconv.FormatUint(site.ConfigRevision, 10) + "|scheme=http|host=" + site.Domain +
		"|port=" + strconv.Itoa(int(port)) + "|method=GET|request=" + requestURI
}

func rangeIdentityForTest(site SiteContext) string {
	digest := sha256.Sum256([]byte(site.TenantID + "\x00" + site.SiteID + "\x00" + site.Domain + "\x00" +
		strconv.Itoa(int(site.ListenPort))))
	return hex.EncodeToString(digest[:8])
}

func rangeKey(site SiteContext, version, slice, requestURI string) string {
	return "v=" + version + "|policy=3|tenant=" + site.TenantID + "|site=" + site.SiteID + "|range=" + slice +
		"|scheme=http|host=" + site.Domain + "|port=" + strconv.Itoa(int(site.ListenPort)) + "|request=" + requestURI
}

func freshnessSite(site SiteContext) SiteContext {
	site.Listeners = []ListenerContext{{
		Domain: site.Domain, Scheme: site.Scheme, ListenPort: site.ListenPort, PrewarmPort: site.PrewarmPort,
		PrewarmPathPrefix: site.PrewarmPathPrefix, CacheEnabled: true, CacheFreshness: true,
	}}
	return site
}

func assertGone(t *testing.T, paths ...string) {
	t.Helper()
	for _, path := range paths {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("cache entry %s still present: %v", path, err)
		}
	}
}

func assertKept(t *testing.T, paths ...string) {
	t.Helper()
	for _, path := range paths {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("cache entry %s removed: %v", path, err)
		}
	}
}

func TestPurgeReachesCacheFreshnessKeys(t *testing.T) {
	root := testStateRoot(t)
	site := freshnessSite(testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, 19080, 7))
	manager := testManager(t, root, resolverFor(site), nil)
	namespace := filepath.Join(root, "shared", "cache", site.CacheIdentity)
	genA, genB := strings.Repeat("a", 64), strings.Repeat("b", 64)
	tokA, tokB := strings.Repeat("c", 64), strings.Repeat("d", 64)

	exactOld := putRawCacheEntry(t, namespace, freshnessKey(genA, tokA, site, site.ListenPort, "/asset?q=1"))
	exactNew := putRawCacheEntry(t, namespace, freshnessKey(genB, tokB, site, site.ListenPort, "/asset?q=1"))
	otherQuery := putRawCacheEntry(t, namespace, freshnessKey(genB, tokB, site, site.ListenPort, "/asset?q=2"))
	imageA := putRawCacheEntry(t, namespace, freshnessKey(genB, tokB, site, site.ListenPort, "/images/a.png"))
	imageB := putRawCacheEntry(t, namespace, freshnessKey(genB, tokA, site, site.ListenPort, "/images/sub/b.png?x=1"))
	imageEncoded := putRawCacheEntry(t, namespace, freshnessKey(genB, tokB, site, site.ListenPort, "/images/%E4%B8%AD.png"))
	outside := putRawCacheEntry(t, namespace, freshnessKey(genB, tokB, site, site.ListenPort, "/images-old/a.png"))
	prewarmed := putRawCacheEntry(t, namespace, freshnessKey(genB, tokB, site, site.PrewarmPort,
		site.PrewarmPathPrefix+"asset?q=1"))

	result, err := manager.Execute(context.Background(), taskFor(site, "freshness-exact", ActionPurgeExact, cacheURL(site, "/asset?q=1")))
	if err != nil || result.State != StateSucceeded || result.Items[0].Code != CodePurged || result.Items[0].Affected != 2 {
		t.Fatalf("freshness exact purge = %+v, %v", result, err)
	}
	assertGone(t, exactOld, exactNew)
	assertKept(t, otherQuery, imageA, outside, prewarmed)

	result, err = manager.Execute(context.Background(), taskFor(site, "freshness-prefix", ActionPurgePrefix, cacheURL(site, "/images/")))
	if err != nil || result.State != StateSucceeded || result.Items[0].Affected != 3 {
		t.Fatalf("freshness prefix purge = %+v, %v", result, err)
	}
	assertGone(t, imageA, imageB, imageEncoded)
	assertKept(t, outside, otherQuery)

	result, err = manager.Execute(context.Background(), taskFor(site, "freshness-site", ActionPurgeSite))
	if err != nil || result.State != StateSucceeded || result.Items[0].Affected != 3 {
		t.Fatalf("freshness site purge = %+v, %v", result, err)
	}
	assertGone(t, otherQuery, outside, prewarmed)
}

func TestPurgeReachesAdvancedCacheFreshnessKeys(t *testing.T) {
	root := testStateRoot(t)
	site := freshnessSite(testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, 19080, 7))
	site.QueryMode = "ignore"
	manager := testManager(t, root, resolverFor(site), nil)
	namespace := filepath.Join(root, "shared", "cache", site.CacheIdentity)
	gen, tok := strings.Repeat("a", 64), strings.Repeat("b", 64)
	vary := strings.Repeat("e", 64)
	projected, err := cachePolicyKeyURI(site, "/asset?q=1", vary)
	if err != nil {
		t.Fatal(err)
	}
	exact := putRawCacheEntry(t, namespace, gen+"|"+tok+"|"+cacheKeyValue(site, projected))
	other := putRawCacheEntry(t, namespace, gen+"|"+tok+"|"+cacheKeyValue(site, "/other?~q="+strings.Repeat("1", 64)+"&~v="+vary))

	result, err := manager.Execute(context.Background(), taskFor(site, "advanced-exact", ActionPurgeExact, cacheURL(site, "/asset?q=9")))
	if err != nil || result.State != StateSucceeded || result.Items[0].Affected != 1 {
		t.Fatalf("advanced freshness exact purge = %+v, %v", result, err)
	}
	assertGone(t, exact)
	assertKept(t, other)

	// 只有缓存规则（preserve、无 vary）的新鲜度站点：键为 gen|token|v2|...|<uri>，精确刷新不能按无前缀路径直接算。
	legacy := freshnessSite(testSite("tenant-a", "site-l", "config-v1", "legacy.example.test", 18081, 19080, 7))
	legacyManager := testManager(t, root, resolverFor(legacy), nil)
	legacyNamespace := filepath.Join(root, "shared", "cache", legacy.CacheIdentity)
	legacyEntry := putRawCacheEntry(t, legacyNamespace, gen+"|"+tok+"|"+cacheKeyValue(legacy, "/asset?q=1"))
	result, err = legacyManager.Execute(context.Background(), taskFor(legacy, "legacy-exact", ActionPurgeExact, cacheURL(legacy, "/asset?q=1")))
	if err != nil || result.State != StateSucceeded || result.Items[0].Affected != 1 {
		t.Fatalf("rule-only freshness exact purge = %+v, %v", result, err)
	}
	assertGone(t, legacyEntry)
}

func TestPurgeReachesRangeSliceCache(t *testing.T) {
	root := testStateRoot(t)
	site := testSite("tenant-a", "site-a", "config-v2", "video.example.test", 18080, 19080, 7)
	manager := testManager(t, root, resolverFor(site), nil)
	rangeRoot := filepath.Join(root, "shared", "range", rangeIdentityForTest(site))
	slices := []string{
		putRawCacheEntry(t, rangeRoot, rangeKey(site, "config-v2", "bytes=0-1048575", "/video.mp4")),
		putRawCacheEntry(t, rangeRoot, rangeKey(site, "config-v2", "bytes=1048576-2097151", "/video.mp4")),
		putRawCacheEntry(t, rangeRoot, rangeKey(site, "config-v2", "bytes=0-10,20-30", "/video.mp4")),
		putRawCacheEntry(t, rangeRoot, rangeKey(site, "config-v1", "bytes=0-1048575", "/video.mp4")),
	}
	otherQuery := putRawCacheEntry(t, rangeRoot, rangeKey(site, "config-v2", "bytes=0-1048575", "/video.mp4?token=1"))
	media := putRawCacheEntry(t, rangeRoot, rangeKey(site, "config-v2", "bytes=0-1048575", "/media/a.mp4"))
	prewarmed := putCacheEntry(t, root, site, "/video.mp4")

	result, err := manager.Execute(context.Background(), taskFor(site, "range-exact", ActionPurgeExact, cacheURL(site, "/video.mp4")))
	if err != nil || result.State != StateSucceeded || result.Items[0].Affected != 5 {
		t.Fatalf("range exact purge = %+v, %v", result, err)
	}
	assertGone(t, append(slices, prewarmed)...)
	assertKept(t, otherQuery, media)

	result, err = manager.Execute(context.Background(), taskFor(site, "range-prefix", ActionPurgePrefix, cacheURL(site, "/media/")))
	if err != nil || result.State != StateSucceeded || result.Items[0].Affected != 1 {
		t.Fatalf("range prefix purge = %+v, %v", result, err)
	}
	assertGone(t, media)

	result, err = manager.Execute(context.Background(), taskFor(site, "range-site", ActionPurgeSite))
	if err != nil || result.State != StateSucceeded || result.Items[0].Affected != 1 {
		t.Fatalf("range site purge = %+v, %v", result, err)
	}
	assertGone(t, otherQuery)
}

func TestPurgeRangeSliceRejectsForeignKeyAndRecoversDeleteIntent(t *testing.T) {
	root := testStateRoot(t)
	site := testSite("tenant-a", "site-a", "config-v2", "video.example.test", 18080, 19080, 7)
	manager := testManager(t, root, resolverFor(site), nil)
	rangeRoot := filepath.Join(root, "shared", "range", rangeIdentityForTest(site))
	foreign := site
	foreign.SiteID = "site-b"
	putRawCacheEntry(t, rangeRoot, rangeKey(foreign, "config-v2", "bytes=0-1", "/video.mp4"))
	result, err := manager.Execute(context.Background(), taskFor(site, "range-foreign", ActionPurgeSite))
	if err != nil || result.State != StateFailed || result.Items[0].Code != CodeCacheMetadataInvalid {
		t.Fatalf("foreign range key purge = %+v, %v", result, err)
	}

	cleanRoot := testStateRoot(t)
	cleanManager := testManager(t, cleanRoot, resolverFor(site), nil)
	slice := putRawCacheEntry(t, filepath.Join(cleanRoot, "shared", "range", rangeIdentityForTest(site)),
		rangeKey(site, "config-v2", "bytes=0-1", "/video.mp4"))
	cleanManager.deleteEntries = func(_ context.Context, entries []cacheEntry) (int, error) {
		if len(entries) != 1 || entries[0].area == "" {
			t.Fatalf("range entry planned without its area: %+v", entries)
		}
		if err := os.Remove(slice); err != nil {
			t.Fatal(err)
		}
		return 0, errors.New("crash after unlink")
	}
	task := taskFor(site, "range-intent", ActionPurgeExact, cacheURL(site, "/video.mp4"))
	result, err = cleanManager.Execute(context.Background(), task)
	if err != nil || result.State != StateSucceeded || result.Items[0].Affected != 1 {
		t.Fatalf("range delete intent recovery = %+v, %v", result, err)
	}
}
