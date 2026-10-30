package cachecontrolhttp

import (
	"net/url"
	"testing"
)

// fix-cacheflow2 P2-07 (CACHE-ADD-02): the browser's URLSearchParams encodes
// "/" as %2F, "," as %2C and " " as "+"; the query is decoded once with the
// standard rules instead of being refused.
func TestCanonicalQueryAcceptsStandardEncoding(t *testing.T) {
	for raw, want := range map[string]url.Values{
		"search=%2Fassets%2Freview.js":          {"search": {"/assets/review.js"}},
		"state=failed%2Cpartial_failed":         {"state": {"failed,partial_failed"}},
		"search=%E4%B8%AD%E6%96%87&limit=30":    {"search": {"中文"}, "limit": {"30"}},
		"search=a+b":                            {"search": {"a b"}},
		"search=100%25":                         {"search": {"100%"}},
		"search=/assets/review.js&state=failed": {"search": {"/assets/review.js"}, "state": {"failed"}},
	} {
		got, err := parseCanonicalQuery(raw)
		if err != nil {
			t.Errorf("%q refused: %v", raw, err)
			continue
		}
		if len(got) != len(want) {
			t.Errorf("%q = %v, want %v", raw, got, want)
		}
		for key, values := range want {
			if got.Get(key) != values[0] {
				t.Errorf("%q %s = %q, want %q", raw, key, got.Get(key), values[0])
			}
		}
	}
	for _, raw := range []string{
		"search=%zz", "search=%", "search", "=x", "search=", "search=a&search=b", "a=1&&b=2",
		"search=a;b", "%73earch=x&search=y",
	} {
		if _, err := parseCanonicalQuery(raw); err == nil {
			t.Errorf("%q accepted", raw)
		}
	}
}
