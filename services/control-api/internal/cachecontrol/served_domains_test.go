package cachecontrol

import (
	"errors"
	"testing"
)

// A site serving a "*." primary and an alias accepts URLs under any name it
// serves and keeps the URL's own host (the node prewarms under it); the
// wildcard itself is refused with its own error, as are names it does not
// serve (the bare suffix, other domains).
func TestTargetHostCoveredBySiteDomains(t *testing.T) {
	site := siteDescriptor{
		Domain: "*.x.example", Domains: []string{"*.x.example", "alias.example.test"},
		HTTPPorts: []string{"80"}, HTTPSPorts: []string{"443"},
	}
	for raw, want := range map[string]string{
		"http://a.x.example/item":         "http://a.x.example/item",
		"https://Deep.A.x.example/item":   "https://deep.a.x.example/item",
		"http://alias.example.test/item?": "http://alias.example.test/item?",
	} {
		target, err := normalizeTargetURL(raw, false, site, false)
		if err != nil || target.CanonicalURL != want {
			t.Fatalf("%s: target %+v err %v, want %s", raw, target, err, want)
		}
	}
	// ("%2A" in a host is already refused by url.Parse.)
	for _, raw := range []string{"http://*.x.example/item", "https://*.x.example:443/item"} {
		_, err := normalizeTargetURL(raw, false, site, false)
		if !errors.Is(err, ErrWildcardTargetHost) || !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("%s: err %v, want ErrWildcardTargetHost", raw, err)
		}
	}
	for _, raw := range []string{"http://x.example/item", "http://other.example.test/item", "http://a.alias.example.test/item"} {
		if _, err := normalizeTargetURL(raw, false, site, false); !errors.Is(err, ErrInvalidInput) || errors.Is(err, ErrWildcardTargetHost) {
			t.Fatalf("%s: err %v, want invalid", raw, err)
		}
	}
	// A site with an exact primary and no other name keeps its rule.
	exact := siteDescriptor{Domain: "example.com", HTTPPorts: []string{"80"}}
	if _, err := normalizeTargetURL("http://www.example.com/a", false, exact, false); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("exact site accepted another host: %v", err)
	}
}

// Q4：刷新可填通配主机，只限本站服务的名称；预热仍只收具体主机。
func TestPurgeAcceptsWildcardHostTheSiteServes(t *testing.T) {
	site := siteDescriptor{
		Domain: "*.x.example", Domains: []string{"*.x.example", "a.y.example", "b.y.example"},
		HTTPPorts: []string{"80"}, HTTPSPorts: []string{"443"},
	}
	for raw, want := range map[string]string{
		"http://*.x.example/item":      "http://*.x.example/item",
		"https://*.X.example:443/dir/": "https://*.x.example/dir/",
		"http://*.y.example/item":      "http://*.y.example/item",      // 站点服务 y.example 下的具体名
		"http://*.deep.x.example/item": "http://*.deep.x.example/item", // 被 *.x.example 覆盖
	} {
		targets, err := normalizeTargets([]string{raw}, ActionPurge, TargetExactURL, site)
		if err != nil || len(targets) != 1 || targets[0].CanonicalURL != want {
			t.Fatalf("purge %s: %+v %v, want %s", raw, targets, err, want)
		}
	}
	for _, raw := range []string{"http://*.example/item", "http://*.other.test/item", "http://*.*.x.example/item", "http://a*.x.example/item"} {
		_, err := normalizeTargets([]string{raw}, ActionPurge, TargetExactURL, site)
		if !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("purge %s: err %v, want refused", raw, err)
		}
	}
	if _, err := normalizeTargets([]string{"http://*.x.example/item"}, ActionPrewarm, TargetExactURL, site); !errors.Is(err, ErrWildcardTargetHost) {
		t.Fatalf("prewarm wildcard: err %v, want ErrWildcardTargetHost", err)
	}
}
