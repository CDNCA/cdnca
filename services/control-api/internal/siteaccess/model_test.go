package siteaccess

import (
	"errors"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

func TestNormalizeSiteAccess(t *testing.T) {
	facts := siteFacts{domains: []string{"a.example.test", "old.example.test"}, https: true}
	input := Settings{
		HostRedirects: []edgeconfig.HostRedirect{{SourceHost: "OLD.example.test ", TargetHost: "www.example.test",
			TargetScheme: "https", Status: 301, PreserveURI: true}},
		HSTS:        &edgeconfig.SiteHSTS{MaxAgeSeconds: 31536000, IncludeSubdomains: true, Preload: true},
		Compression: &edgeconfig.SiteCompression{Enabled: true, Types: []string{"Text/CSS", "application/json", "text/css"}},
		Limits:      &edgeconfig.SiteRequestLimits{ConnectionsPerIP: 10},
		BasicAuth: &BasicAuth{Realm: "staff", Users: []BasicAuthUser{{Username: "bob", Password: "correct horse"},
			{Username: "alice"}}},
		ForceHTTPS: ForceHTTPS{Status: 302, ExcludeHosts: []string{"OLD.example.test"}},
	}
	kept := edgeconfig.BasicAuthUserWithSalt("alice", strings.Repeat("ab", 16), "old password")
	published, settings, err := normalize(input, facts, map[string]edgeconfig.BasicAuthUser{"alice": kept})
	if err != nil {
		t.Fatal(err)
	}
	if published.HostRedirects[0].SourceHost != "old.example.test" || strings.Join(published.Compression.Types, ",") != "application/json,text/css" {
		t.Fatalf("not canonical: %+v", published)
	}
	// a kept user keeps its salt and hash; a new password gets a fresh salt,
	// independent of the site id
	bob := published.BasicAuth.Users[1]
	if published.BasicAuth.Users[0] != kept || bob.Username != "bob" || !bob.Verify("correct horse") ||
		len(bob.Salt) != 32 || bob.Salt == kept.Salt {
		t.Fatalf("basic auth secrets: %+v", published.BasicAuth.Users)
	}
	for _, user := range settings.BasicAuth.Users {
		if user.Password != "" {
			t.Fatal("password returned")
		}
	}
	if settings.ForceHTTPS.ExcludeHosts[0] != "old.example.test" || settings.ForceHTTPS.Status != 302 {
		t.Fatalf("force HTTPS: %+v", settings.ForceHTTPS)
	}
	if _, settings, err := normalize(Settings{}, facts, nil); err != nil || settings.ForceHTTPS.Status != 301 {
		t.Fatalf("empty settings: %v %+v", err, settings)
	}
	for name, test := range map[string]struct {
		mutate func(*Settings, *siteFacts)
		want   error
	}{
		"HSTS without HTTPS":       {func(s *Settings, f *siteFacts) { f.https = false; s.ForceHTTPS = ForceHTTPS{} }, ErrNeedsHTTPS},
		"force status without TLS": {func(s *Settings, f *siteFacts) { f.https = false; s.HSTS = nil }, ErrNeedsHTTPS},
		"unknown user kept":        {func(s *Settings, _ *siteFacts) { s.BasicAuth.Users[1].Username = "carol" }, ErrInvalidInput},
		"short password":           {func(s *Settings, _ *siteFacts) { s.BasicAuth.Users[0].Password = "short" }, ErrInvalidInput},
		"duplicate user":           {func(s *Settings, _ *siteFacts) { s.BasicAuth.Users[1] = s.BasicAuth.Users[0] }, ErrInvalidInput},
		"redirect wildcard source": {func(s *Settings, _ *siteFacts) { s.HostRedirects[0].SourceHost = "*.example.test" }, ErrInvalidInput},
		"exclude unknown domain":   {func(s *Settings, _ *siteFacts) { s.ForceHTTPS.ExcludeHosts = []string{"x.example.test"} }, ErrInvalidInput},
		"exclude every domain": {func(s *Settings, _ *siteFacts) {
			s.ForceHTTPS.ExcludeHosts = []string{"a.example.test", "old.example.test"}
		}, ErrInvalidInput},
		"force status 303": {func(s *Settings, _ *siteFacts) { s.ForceHTTPS.Status = 303 }, ErrInvalidInput},
		"bad MIME":         {func(s *Settings, _ *siteFacts) { s.Compression.Types = []string{"text"} }, ErrInvalidInput},
	} {
		value := input
		value.HostRedirects = append([]edgeconfig.HostRedirect(nil), input.HostRedirects...)
		auth := *input.BasicAuth
		auth.Users = append([]BasicAuthUser(nil), input.BasicAuth.Users...)
		value.BasicAuth = &auth
		compression := *input.Compression
		value.Compression = &compression
		value.ForceHTTPS.ExcludeHosts = append([]string(nil), input.ForceHTTPS.ExcludeHosts...)
		facts := facts
		test.mutate(&value, &facts)
		if _, _, err := normalize(value, facts, map[string]edgeconfig.BasicAuthUser{"alice": edgeconfig.BasicAuthUserWithSalt("alice", strings.Repeat("ab", 16), "x")}); !errors.Is(err, test.want) {
			t.Errorf("%s: %v, want %v", name, err, test.want)
		}
	}
}

// Encodings are canonical (gzip only = absent), WebP is
// published, and the audit summary names encodings and levels.
func TestNormalizeSiteAccessBrotliAndWebP(t *testing.T) {
	facts := siteFacts{domains: []string{"a.example.test"}}
	input := Settings{
		Compression: &edgeconfig.SiteCompression{Enabled: true, Types: []string{"text/css"}, Encodings: []string{" GZIP", "br", "br"},
			GzipLevel: 6, BrotliLevel: 5},
		WebP: &edgeconfig.SiteWebP{Enabled: true, Quality: 70},
	}
	published, settings, err := normalize(input, facts, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(published.Compression.Encodings, ",") != "br,gzip" || published.WebP == nil || published.WebP.Quality != 70 ||
		settings.WebP == nil {
		t.Fatalf("published: %+v %+v", published.Compression, published.WebP)
	}
	audit := summary(settings)
	if audit["compression_encodings"] != "br,gzip" || audit["compression_brotli_level"] != 5 || audit["webp"] != true {
		t.Fatalf("summary: %v", audit)
	}
	input.Compression.Encodings, input.Compression.BrotliLevel = []string{"gzip"}, 0
	if published, _, err = normalize(input, facts, nil); err != nil || published.Compression.Encodings != nil {
		t.Fatalf("gzip only: %v %+v", err, published.Compression)
	}
	input.Compression.Encodings = []string{"zstd"}
	if _, _, err = normalize(input, facts, nil); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("zstd: %v", err)
	}
	if got := readable(edgeconfig.SiteAccess{WebP: &edgeconfig.SiteWebP{Enabled: true}}, 301, nil); got.WebP == nil {
		t.Fatal("readable drops WebP")
	}
}

// Response rules keep their order, header names are lower
// cased, an empty list publishes nothing and reads back as [], invalid
// rules are refused.
func TestNormalizeSiteAccessResponseRules(t *testing.T) {
	facts := siteFacts{domains: []string{"a.example.test"}}
	rules := []edgeconfig.SiteResponseRule{
		{ID: "strip", Headers: []edgeconfig.ResponseHeaderCondition{{Name: "X-Powered-By ", Op: edgeconfig.ResponseHeaderExists}},
			Action: edgeconfig.ResponseActionHeaders, HeaderActions: []edgeconfig.ResponseHeaderAction{{Kind: edgeconfig.ResponseHeaderDelete, Name: "X-Powered-By"}}},
		{ID: "block", Statuses: []edgeconfig.StatusRange{{From: 500, To: 599}}, Action: edgeconfig.ResponseActionBlock, Status: 503},
	}
	published, settings, err := normalize(Settings{ResponseRules: rules}, facts, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(published.ResponseRules) != 2 || published.ResponseRules[0].ID != "strip" ||
		published.ResponseRules[0].Headers[0].Name != "x-powered-by" || published.ResponseRules[0].HeaderActions[0].Name != "x-powered-by" ||
		published.ResponseRules[1].Headers != nil || len(settings.ResponseRules) != 2 {
		t.Fatalf("not canonical: %+v", published.ResponseRules)
	}
	if summary(settings)["response_rules"] != 2 {
		t.Fatalf("audit summary: %v", summary(settings))
	}
	empty, settings, err := normalize(Settings{ResponseRules: []edgeconfig.SiteResponseRule{}}, facts, nil)
	if err != nil || !empty.Empty() || empty.ResponseRules != nil || settings.ResponseRules == nil {
		t.Fatalf("empty rules: %v %+v %+v", err, empty, settings.ResponseRules)
	}
	if read := readable(edgeconfig.SiteAccess{}, 301, nil); read.ResponseRules == nil || len(read.ResponseRules) != 0 {
		t.Fatalf("read without rules: %+v", read.ResponseRules)
	}
	bad := []edgeconfig.SiteResponseRule{{ID: "x", Action: edgeconfig.ResponseActionHeaders,
		HeaderActions: []edgeconfig.ResponseHeaderAction{{Kind: edgeconfig.ResponseHeaderSet, Name: "Content-Length", Value: "1"}}}}
	if _, _, err := normalize(Settings{ResponseRules: bad}, facts, nil); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("reserved header accepted: %v", err)
	}
}

// A market leaf writes the subscriber's salted hashes as they are
// (normalize's hashed users): no password, the salt and hash kept; a user
// both hashed and with a password, or a malformed hash, is refused.
func TestNormalizeTakesHashedUsers(t *testing.T) {
	facts := siteFacts{domains: []string{"a.example.test"}, https: true}
	alice := edgeconfig.BasicAuthUserWithSalt("alice", strings.Repeat("cd", 16), "correct horse")
	input := Settings{BasicAuth: &BasicAuth{Realm: "staff", Users: []BasicAuthUser{{Username: "alice"}}}}
	published, settings, err := normalizeHashed(input, facts, nil, []edgeconfig.BasicAuthUser{alice})
	if err != nil || published.BasicAuth.Users[0] != alice || settings.BasicAuth.Users[0] != (BasicAuthUser{Username: "alice"}) {
		t.Fatalf("published = %+v settings = %+v err = %v", published.BasicAuth, settings.BasicAuth, err)
	}
	bad := alice
	bad.Salt = "xx"
	if _, _, err := normalizeHashed(input, facts, nil, []edgeconfig.BasicAuthUser{bad}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("bad salt: %v", err)
	}
	input.BasicAuth.Users[0].Password = "another one"
	if _, _, err := normalizeHashed(input, facts, nil, []edgeconfig.BasicAuthUser{alice}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("password and hash: %v", err)
	}
}
