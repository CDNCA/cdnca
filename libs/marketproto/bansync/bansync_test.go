package bansync

import (
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func request() Request {
	return Request{SiteID: uuid.New(), LeafSiteID: uuid.New(), Revision: 1_700_000_000_000,
		Bans: []Ban{
			{Ref: uuid.MustParse("00000000-0000-0000-0000-000000000002"), Client: "198.51.100.9", Until: 1_800_000_000, Source: "manual", Reason: "  scan  "},
			{Ref: uuid.MustParse("00000000-0000-0000-0000-000000000001"), Client: "2001:db8::/48", Until: 1_800_000_000, Source: "cc"},
		},
		Releases: []Release{{Ref: uuid.MustParse("00000000-0000-0000-0000-000000000003"), ReleasedAt: 1_700_000_000}}}
}

func TestNormalizeSortsAndTrims(t *testing.T) {
	r := request()
	if err := r.Normalize(); err != nil {
		t.Fatal(err)
	}
	if r.Bans[0].Ref.String() != "00000000-0000-0000-0000-000000000001" || r.Bans[1].Reason != "scan" {
		t.Fatalf("normalized = %+v", r.Bans)
	}
	// Order does not change the digest; content and not the revision does.
	other := request()
	other.Revision++
	other.Bans[0], other.Bans[1] = other.Bans[1], other.Bans[0]
	if err := other.Normalize(); err != nil || other.Digest() != r.Digest() {
		t.Fatalf("digest differs for the same content: %v", err)
	}
	other.Bans[0].Until++
	if other.Digest() == r.Digest() {
		t.Fatal("digest ignores until")
	}
	empty := Request{SiteID: uuid.New(), LeafSiteID: uuid.New(), Revision: 1}
	if err := empty.Normalize(); err != nil || empty.Bans == nil || empty.Releases == nil {
		t.Fatalf("empty snapshot: %+v %v", empty, err)
	}
}

func TestNormalizeRefusesBadSnapshots(t *testing.T) {
	ref := uuid.New()
	for name, mutate := range map[string]func(*Request){
		"no site":          func(r *Request) { r.SiteID = uuid.Nil },
		"no leaf site":     func(r *Request) { r.LeafSiteID = uuid.Nil },
		"no revision":      func(r *Request) { r.Revision = 0 },
		"nil ref":          func(r *Request) { r.Bans[0].Ref = uuid.Nil },
		"duplicate ref":    func(r *Request) { r.Bans[1].Ref = r.Bans[0].Ref },
		"ban and release":  func(r *Request) { r.Releases[0].Ref = r.Bans[0].Ref },
		"no until":         func(r *Request) { r.Bans[0].Until = 0 },
		"unknown source":   func(r *Request) { r.Bans[0].Source = "market" },
		"client garbage":   func(r *Request) { r.Bans[0].Client = "198.51.100.9 OR 1=1" },
		"client inner bad": func(r *Request) { r.Bans[0].Client = "1.2.x.4" },
		"client empty":     func(r *Request) { r.Bans[0].Client = "" },
		"reason control":   func(r *Request) { r.Bans[0].Reason = "a\nb" },
		"reason long":      func(r *Request) { r.Bans[0].Reason = strings.Repeat("封", MaxReason+1) },
		"release time":     func(r *Request) { r.Releases[0].ReleasedAt = 0 },
		"too many bans": func(r *Request) {
			r.Bans = make([]Ban, MaxBans+1)
			for i := range r.Bans {
				r.Bans[i] = Ban{Ref: uuid.New(), Client: "198.51.100.1", Until: 1, Source: "manual"}
			}
		},
		"too many releases": func(r *Request) {
			r.Releases = make([]Release, MaxReleases+1)
			for i := range r.Releases {
				r.Releases[i] = Release{Ref: uuid.New(), ReleasedAt: 1}
			}
		},
	} {
		r := request()
		mutate(&r)
		if err := r.Normalize(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	r := request()
	r.Bans[0].Reason = strings.Repeat("封", MaxReason)
	r.Releases[0].Ref = ref
	if err := r.Normalize(); err != nil {
		t.Fatalf("longest reason refused: %v", err)
	}
}

func TestUnsupported(t *testing.T) {
	if !Unsupported("market supply: operation not supported") || Unsupported(ErrCodeRateLimited) {
		t.Fatal("Unsupported")
	}
}
