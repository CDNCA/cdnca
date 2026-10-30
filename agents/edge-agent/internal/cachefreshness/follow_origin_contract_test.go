package cachefreshness

import (
	"bytes"
	"net/http"
	"slices"
	"testing"
	"time"
)

func TestFollowOriginDisabledKeepsConfiguredFreshness(t *testing.T) {
	policy := baselineFollowOriginPolicy(false)
	stored := time.Unix(1_750_000_000, 0)
	object := originObject(stored)
	object.OriginCacheControl = []string{"max-age=1"}

	decision, err := Decide(policy, RequestFacts{Method: "GET"}, object, stored.Add(2*time.Second))
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if decision.Reason != ReasonFreshHit || decision.FreshSeconds != 30 {
		t.Fatalf("disabled decision = %#v, want configured 30 second freshness", decision)
	}
}

func TestFollowOriginFreshnessPrecedenceAndAge(t *testing.T) {
	stored := time.Unix(1_750_000_000, 0)
	date := stored.Add(-10 * time.Second)
	tests := []struct {
		name       string
		object     ObjectFacts
		wantFresh  uint64
		wantSource OriginFreshnessSource
	}{
		{
			name: "s-maxage before max-age and expires",
			object: withOriginHeaders(originObject(stored), []string{"public, max-age=80, s-maxage=120"},
				[]string{"20"}, []string{date.Format(http.TimeFormat)}, []string{date.Add(200 * time.Second).Format(http.TimeFormat)}),
			wantFresh: 100, wantSource: FreshnessSourceSMaxAge,
		},
		{
			name: "max-age before expires",
			object: withOriginHeaders(originObject(stored), []string{"max-age=80"},
				[]string{"20"}, []string{date.Format(http.TimeFormat)}, []string{date.Add(200 * time.Second).Format(http.TimeFormat)}),
			wantFresh: 60, wantSource: FreshnessSourceMaxAge,
		},
		{
			name: "expires minus date",
			object: withOriginHeaders(originObject(stored), nil,
				[]string{"20"}, []string{date.Format(http.TimeFormat)}, []string{date.Add(200 * time.Second).Format(http.TimeFormat)}),
			wantFresh: 180, wantSource: FreshnessSourceExpires,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy := baselineFollowOriginPolicy(true)
			fresh, err := Decide(policy, RequestFacts{Method: "GET"}, test.object, stored.Add(time.Duration(test.wantFresh-1)*time.Second))
			if err != nil {
				t.Fatalf("fresh Decide: %v", err)
			}
			if fresh.Reason != ReasonFreshHit || fresh.FreshSeconds != test.wantFresh || fresh.OriginFreshnessSource != test.wantSource {
				t.Fatalf("fresh decision = %#v", fresh)
			}

			expired, err := Decide(policy, RequestFacts{Method: "GET"}, test.object, stored.Add(time.Duration(test.wantFresh)*time.Second))
			if err != nil {
				t.Fatalf("expired Decide: %v", err)
			}
			if expired.Reason != ReasonMiss || expired.State != StateExpired {
				t.Fatalf("boundary decision = %#v, want expired miss", expired)
			}
		})
	}
}

func TestFollowOriginHigherPriorityDirectivesIgnoreLowerPriorityInvalidHeaders(t *testing.T) {
	stored := time.Unix(1_750_000_000, 0)
	tests := []struct {
		name       string
		control    string
		wantReason ReasonCode
		wantFresh  uint64
		wantSource OriginFreshnessSource
	}{
		{
			name: "s-maxage ignores invalid date and expires", control: "s-maxage=120, max-age=80",
			wantReason: ReasonFreshHit, wantFresh: 100, wantSource: FreshnessSourceSMaxAge,
		},
		{
			name: "max-age ignores invalid date and expires", control: "max-age=80",
			wantReason: ReasonFreshHit, wantFresh: 60, wantSource: FreshnessSourceMaxAge,
		},
		{
			name: "no-store ignores invalid freshness metadata", control: "no-store",
			wantReason: ReasonOriginUncacheable,
		},
		{
			name: "private ignores invalid freshness metadata", control: "private",
			wantReason: ReasonOriginUncacheable,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			object := originObject(stored)
			object.OriginCacheControl = []string{test.control}
			object.OriginAge = []string{"20"}
			object.OriginDate = []string{"invalid-date"}
			object.OriginExpires = []string{"invalid-expires"}
			decision, err := Decide(baselineFollowOriginPolicy(true), RequestFacts{Method: "GET"}, object, stored)
			if err != nil {
				t.Fatalf("Decide: %v", err)
			}
			if decision.Reason != test.wantReason || decision.FreshSeconds != test.wantFresh ||
				decision.OriginFreshnessSource != test.wantSource {
				t.Fatalf("decision = %#v", decision)
			}
		})
	}
}

func TestFollowOriginNoCacheAndMustRevalidateExpireImmediately(t *testing.T) {
	stored := time.Unix(1_750_000_000, 0)
	policy := validPolicy()
	policy.FollowOriginHeaders = true
	for _, directive := range []string{"no-cache, max-age=300", "must-revalidate, max-age=300"} {
		t.Run(directive, func(t *testing.T) {
			object := originObject(stored)
			object.OriginCacheControl = []string{directive}
			object.FailureClass = FailureUpdating
			decision, err := Decide(policy, RequestFacts{Method: "GET"}, object, stored)
			if err != nil {
				t.Fatalf("Decide: %v", err)
			}
			if decision.Reason != ReasonMiss || decision.State != StateExpired || decision.FreshSeconds != 0 {
				t.Fatalf("decision = %#v, want immediately expired miss", decision)
			}
		})
	}
}

func TestFollowOriginUncacheableDirectivesAndVaryStar(t *testing.T) {
	stored := time.Unix(1_750_000_000, 0)
	tests := []struct {
		name   string
		mutate func(*ObjectFacts)
	}{
		{"no-store", func(object *ObjectFacts) { object.OriginCacheControl = []string{"no-store, max-age=300"} }},
		{"private", func(object *ObjectFacts) { object.OriginCacheControl = []string{"private, max-age=300"} }},
		{"vary star", func(object *ObjectFacts) {
			object.OriginCacheControl = []string{"max-age=300"}
			object.OriginVary = []string{"*"}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			object := originObject(stored)
			test.mutate(&object)
			decision, err := Decide(baselineFollowOriginPolicy(true), RequestFacts{Method: "GET"}, object, stored)
			if err != nil {
				t.Fatalf("Decide: %v", err)
			}
			if decision.Reason != ReasonOriginUncacheable || !decision.Bypass {
				t.Fatalf("decision = %#v, want origin uncacheable bypass", decision)
			}
		})
	}
}

func TestFollowOriginInvalidOrUnsafeHeadersFailClosed(t *testing.T) {
	stored := time.Unix(1_750_000_000, 0)
	tests := []struct {
		name   string
		mutate func(*ObjectFacts)
	}{
		{"duplicate max-age", func(object *ObjectFacts) { object.OriginCacheControl = []string{"max-age=30, max-age=30"} }},
		{"conflicting max-age", func(object *ObjectFacts) { object.OriginCacheControl = []string{"max-age=30", "max-age=31"} }},
		{"malformed max-age", func(object *ObjectFacts) { object.OriginCacheControl = []string{"max-age=abc"} }},
		{"duplicate age", func(object *ObjectFacts) {
			object.OriginCacheControl = []string{"max-age=30"}
			object.OriginAge = []string{"1", "1"}
		}},
		{"negative age", func(object *ObjectFacts) {
			object.OriginCacheControl = []string{"max-age=30"}
			object.OriginAge = []string{"-1"}
		}},
		{"expires without date", func(object *ObjectFacts) { object.OriginExpires = []string{stored.Format(http.TimeFormat)} }},
		{"duplicate date", func(object *ObjectFacts) {
			object.OriginDate = []string{stored.Format(time.RFC1123), stored.Format(time.RFC1123)}
			object.OriginExpires = []string{stored.Add(time.Minute).Format(time.RFC1123)}
		}},
		{"invalid vary", func(object *ObjectFacts) {
			object.OriginCacheControl = []string{"max-age=30"}
			object.OriginVary = []string{"Accept Language"}
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			object := originObject(stored)
			test.mutate(&object)
			decision, err := Decide(baselineFollowOriginPolicy(true), RequestFacts{Method: "GET"}, object, stored)
			if err != nil {
				t.Fatalf("Decide: %v", err)
			}
			if decision.Reason != ReasonOriginHeadersInvalid || !decision.Bypass || !decision.Fallback {
				t.Fatalf("decision = %#v, want fail-closed invalid origin headers", decision)
			}
		})
	}
}

func TestFollowOriginVaryNamesAreSummaryOnly(t *testing.T) {
	stored := time.Unix(1_750_000_000, 0)
	object := originObject(stored)
	object.OriginCacheControl = []string{"max-age=30"}
	object.OriginVary = []string{"X-Device, Accept-Encoding", "accept-encoding"}

	decision, err := Decide(baselineFollowOriginPolicy(true), RequestFacts{Method: "GET"}, object, stored.Add(time.Second))
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if decision.Reason != ReasonFreshHit || !slices.Equal(decision.VaryHeaders, []string{"accept-encoding", "x-device"}) {
		t.Fatalf("decision = %#v, want fresh with normalized Vary summary", decision)
	}
}

func TestObjectFactsCanonicalDigestIncludesRawOriginFacts(t *testing.T) {
	stored := time.Unix(1_750_000_000, 123)
	base := withOriginHeaders(originObject(stored), []string{"max-age=60"}, []string{"3"},
		[]string{stored.Format(http.TimeFormat)}, []string{stored.Add(time.Minute).Format(http.TimeFormat)})
	base.OriginVary = []string{"Accept-Encoding"}

	canonical := CanonicalObjectFacts(base)
	if len(canonical) == 0 || canonical[len(canonical)-1] != '\n' {
		t.Fatalf("canonical facts = %q, want newline-terminated bytes", canonical)
	}
	if !bytes.Equal(canonical, CanonicalObjectFacts(base)) || ObjectFactsDigest(base) != ObjectFactsDigest(base) {
		t.Fatal("canonical facts or digest is not deterministic")
	}

	mutations := []func(*ObjectFacts){
		func(value *ObjectFacts) { value.OriginCacheControl = []string{"max-age=61"} },
		func(value *ObjectFacts) { value.OriginAge = []string{"4"} },
		func(value *ObjectFacts) { value.OriginDate = []string{stored.Add(time.Second).Format(time.RFC1123)} },
		func(value *ObjectFacts) {
			value.OriginExpires = []string{stored.Add(2 * time.Minute).Format(time.RFC1123)}
		},
		func(value *ObjectFacts) { value.OriginVary = []string{"X-Device"} },
	}
	for index, mutate := range mutations {
		candidate := base
		mutate(&candidate)
		if ObjectFactsDigest(candidate) == ObjectFactsDigest(base) {
			t.Errorf("mutation %d did not change object facts digest", index)
		}
	}

	decision, err := Decide(baselineFollowOriginPolicy(true), RequestFacts{Method: "GET"}, base, stored)
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if decision.ObjectFactsSHA256 == "" {
		t.Fatal("decision omitted object facts digest")
	}
	if decision.Reason != ReasonFreshHit {
		t.Fatalf("valid canonical facts decision = %#v, want fresh hit", decision)
	}
}

func TestCompileFollowOriginChangesPolicyDigestOnlyWhenEnabled(t *testing.T) {
	disabled := validPolicy()
	enabled := disabled
	enabled.FollowOriginHeaders = true

	left, err := Compile(disabled, testPaths())
	if err != nil {
		t.Fatalf("compile disabled: %v", err)
	}
	right, err := Compile(enabled, testPaths())
	if err != nil {
		t.Fatalf("compile enabled: %v", err)
	}
	if bytes.Contains(left.CanonicalPolicy, []byte(`"follow_origin_headers"`)) {
		t.Fatalf("disabled canonical policy changed: %s", left.CanonicalPolicy)
	}
	if !bytes.Contains(right.CanonicalPolicy, []byte(`"follow_origin_headers":true`)) || left.Digest == right.Digest {
		t.Fatal("enabled follow-origin contract did not enter the compiled digest")
	}
}

func baselineFollowOriginPolicy(enabled bool) Policy {
	policy := validPolicy()
	policy.Mode = ModeBaseline
	policy.Enhancement = EnhancementPolicy{Enabled: false}
	policy.FollowOriginHeaders = enabled
	return policy
}

func originObject(stored time.Time) ObjectFacts {
	return ObjectFacts{Exists: true, Cacheable: true, StoredAt: stored}
}

func withOriginHeaders(object ObjectFacts, cacheControl, age, date, expires []string) ObjectFacts {
	object.OriginCacheControl = cacheControl
	object.OriginAge = age
	object.OriginDate = date
	object.OriginExpires = expires
	return object
}

// FX28: 新鲜度模式下源站没有显式寿命时用配置的默认 TTL（与非新鲜度模式的 proxy_cache_valid 一致），
// 超过 2^31-1 秒的寿命按 RFC 9111 截断而不是判无效。
func TestFollowOriginDefaultsAndClampsLifetime(t *testing.T) {
	stored := time.Unix(1_750_000_000, 0)
	far := time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name       string
		mutate     func(*ObjectFacts)
		wantFresh  uint64
		wantSource OriginFreshnessSource
	}{
		{"no cache headers", func(*ObjectFacts) {}, 30, FreshnessSourceDefault},
		{"no expires ignores unusable date", func(object *ObjectFacts) { object.OriginDate = []string{"invalid"} }, 30, FreshnessSourceDefault},
		{"cache-control without lifetime", func(object *ObjectFacts) {
			object.OriginCacheControl = []string{"public"}
			object.OriginAge = []string{"10"}
			object.OriginDate = []string{stored.Format(http.TimeFormat)}
		}, 30, FreshnessSourceDefault},
		{"max-age beyond 2^31", func(object *ObjectFacts) { object.OriginCacheControl = []string{"max-age=99999999999999999999999"} },
			maxOriginFreshnessSeconds, FreshnessSourceMaxAge},
		{"expires beyond 2^31", func(object *ObjectFacts) {
			object.OriginDate = []string{stored.Format(http.TimeFormat)}
			object.OriginExpires = []string{far.Format(http.TimeFormat)}
		}, maxOriginFreshnessSeconds, FreshnessSourceExpires},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			object := originObject(stored)
			test.mutate(&object)
			decision, err := Decide(baselineFollowOriginPolicy(true), RequestFacts{Method: "GET"}, object, stored.Add(time.Second))
			if err != nil {
				t.Fatalf("Decide: %v", err)
			}
			if decision.Reason != ReasonFreshHit || decision.FreshSeconds != test.wantFresh ||
				decision.OriginFreshnessSource != test.wantSource {
				t.Fatalf("decision = %#v, want fresh %d from %s", decision, test.wantFresh, test.wantSource)
			}
		})
	}
}
