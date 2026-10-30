package site

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

// site-backend6: the site edit options of the origin section.
func TestNormalizeSiteEdgeOptions(t *testing.T) {
	pool := OriginPool{SearchEngineOrigin: " Spider.Example.TEST:8080 "}
	if err := normalizeSiteEdgeOptions(&pool); err != nil {
		t.Fatal(err)
	}
	if pool.SearchEngineOrigin != "spider.example.test:8080" || pool.L2Mode != SiteL2Package ||
		pool.ResponseBuffering == nil || !*pool.ResponseBuffering || pool.RequestBuffering == nil || !*pool.RequestBuffering {
		t.Fatalf("normalized %+v", pool)
	}
	config := uuid.New()
	for name, invalid := range map[string]OriginPool{
		"search engine path":     {SearchEngineOrigin: "spider.example.test/x"},
		"custom without config":  {L2Mode: SiteL2Custom},
		"package with config":    {L2Mode: SiteL2Package, L2ConfigID: &config},
		"off with config":        {L2Mode: SiteL2Off, L2ConfigID: &config},
		"unknown L2 mode":        {L2Mode: "global"},
		"search engine userinfo": {SearchEngineOrigin: "user@spider.example.test"},
	} {
		if err := normalizeSiteEdgeOptions(&invalid); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	custom := OriginPool{L2Mode: SiteL2Custom, L2ConfigID: &config}
	if err := normalizeSiteEdgeOptions(&custom); err != nil {
		t.Fatal(err)
	}
}

// 剩余 N 天 (tp-b3a-be): the competitor's Math.ceil of the time left, 0 once passed.
func TestPackageRemainingDays(t *testing.T) {
	ends := time.Date(2026, 11, 3, 8, 10, 37, 0, time.UTC)
	for _, test := range []struct {
		now  time.Time
		want int
	}{
		{ends, 0},
		{ends.Add(time.Second), 0},
		{ends.Add(-time.Second), 1},
		{ends.Add(-24 * time.Hour), 1},
		{ends.Add(-24*time.Hour - time.Second), 2},
		// 16:00 Asia/Shanghai on 10-25 = 08:00 UTC: the count is of elapsed time
		{time.Date(2026, 10, 25, 8, 0, 0, 0, time.UTC), 10},
	} {
		if got := PackageRemainingDays(ends, test.now); got != test.want {
			t.Fatalf("PackageRemainingDays(%s) = %d, want %d", test.now, got, test.want)
		}
	}
}

// 已过期 N 天: whole days, 0 before and within the first day.
func TestPackageExpiredDays(t *testing.T) {
	ends := time.Date(2026, 5, 3, 8, 10, 37, 0, time.UTC)
	for _, test := range []struct {
		now  time.Time
		want int
	}{
		{ends.Add(-time.Hour), 0},
		{ends, 0},
		{ends.Add(23 * time.Hour), 0},
		{ends.Add(24 * time.Hour), 1},
		{time.Date(2026, 10, 22, 18, 41, 9, 0, time.UTC), 172},
	} {
		if got := PackageExpiredDays(ends, test.now); got != test.want {
			t.Fatalf("PackageExpiredDays(%s) = %d, want %d", test.now, got, test.want)
		}
	}
}
