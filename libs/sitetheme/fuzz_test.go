package sitetheme

import (
	"errors"
	"strings"
	"testing"
)

// FuzzParse: Parse never panics, every failure is an *Error with the
// site_theme. prefix, and whatever it accepts honours the invariants the
// callers rely on (no admin for third parties, safe bundle paths, digests
// that match the data, entry present).
func FuzzParse(f *testing.F) {
	f.Add(encode(f, fixtureV2()), false)
	f.Add(encode(f, v1Package()), true)
	pkg := fixtureV2()
	pkg["applies_to"] = []any{"admin", "user", "site"}
	f.Add(encode(f, pkg), true)
	pkg = fixtureV2()
	withFile("../x.html", "x")(pkg)
	f.Add(encode(f, pkg), false)
	f.Add([]byte(`{"schema":"cdnca.site-theme/v2"}`), false)
	f.Add([]byte(`{}`), false)
	f.Fuzz(func(t *testing.T, raw []byte, isOfficial bool) {
		opt := thirdParty()
		if isOfficial {
			opt = official()
		}
		theme, err := Parse(raw, opt)
		if err != nil {
			var invalid *Error
			if !errors.As(err, &invalid) || !strings.HasPrefix(invalid.Code, ErrorPrefix) || theme != nil {
				t.Fatalf("error %v (%T)", err, err)
			}
			return
		}
		if theme == nil || len(theme.AppliesTo) == 0 {
			t.Fatal("accepted without scopes")
		}
		if !isOfficial && theme.Allows(ScopeAdmin) {
			t.Fatal("third party admin accepted")
		}
		if theme.Bundle != nil {
			entry := false
			for _, file := range theme.Bundle.Files {
				if !ValidBundlePath(file.Path) || file.SHA256 != sum(string(file.Data)) || file.Size != int64(len(file.Data)) {
					t.Fatalf("bad file %q", file.Path)
				}
				entry = entry || file.Path == theme.Bundle.Entry
			}
			if !entry {
				t.Fatal("entry missing")
			}
		}
	})
}

// FuzzBundleScan: the scanner never panics on arbitrary file bodies.
func FuzzBundleScan(f *testing.F) {
	for _, seed := range []string{indexHTML, appJS, "<base href=x>", "/dashboard/login?x", "/dashboard/login/x", "/v1/control-site/assets/../", "<script src=//x>"} {
		f.Add("html", []byte(seed))
		f.Add("js", []byte(seed))
	}
	f.Fuzz(func(t *testing.T, ext string, data []byte) {
		if scanFile(ext, data) == "" && textExtensions[ext] {
			// Whatever passes may only name the three platform auth pages.
			text := normalizeText(data)
			for rest := text; ; {
				index := strings.Index(rest, "/dashboard")
				if index < 0 {
					break
				}
				if !allowedDashboardRef(rest[index:]) {
					t.Fatalf("accepted dashboard reference in %q", text)
				}
				rest = rest[index+1:]
			}
		}
		_ = checkAuthCSS(string(data))
		_ = SafeSVG(data)
	})
}
