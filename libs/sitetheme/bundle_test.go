package sitetheme

import (
	"strings"
	"testing"
)

func TestBundlePaths(t *testing.T) {
	good := []string{"index.html", "assets/app.js", "a/b/c/d.css", "img/logo-2x.png", "fonts/x_y.woff2", "_next/a.js"}
	for _, p := range good {
		if !ValidBundlePath(p) {
			t.Errorf("rejected %q", p)
		}
	}
	bad := []string{"", "/index.html", "../x.html", "a/../b.html", "a/./b.html", "./a.html", "a//b.html", "a/", `a\b.html`,
		"C:/x.html", "c:x.html", ".env", "a/.git/config", "a b.html", "a/%2e%2e/b.html", "a\x00.html", "é.html",
		strings.Repeat("a/", 129) + "x.html", "a/..", ".."}
	for _, p := range bad {
		if ValidBundlePath(p) {
			t.Errorf("accepted %q", p)
		}
	}
	for _, p := range []string{"../x.html", "/etc/passwd.txt", "C:/a.html", `a\..\b.html`, "a/../../x.js"} {
		pkg := fixtureV2()
		bundleFiles(pkg)[0].(map[string]any)["path"] = p
		_, err := Parse(encode(t, pkg), thirdParty())
		expectCode(t, "traversal "+p, err, "bundle_path")
	}
}

func TestBundleExtensions(t *testing.T) {
	for ext := range BundleExtensions {
		pkg := fixtureV2()
		body := "x"
		if ext == "html" || ext == "svg" {
			body = "<p>x</p>"
		}
		withFile("f/a."+ext, body)(pkg)
		if _, err := Parse(encode(t, pkg), thirdParty()); err != nil {
			t.Errorf(".%s rejected: %v", ext, err)
		}
	}
	for _, name := range []string{"a.php", "a.exe", "a.htm", "a.xhtml", "a.wasm", "a.sh", "a", "a.HTML.php", "a.shtml", "a.xml", "sw.appcache"} {
		pkg := fixtureV2()
		withFile("f/"+name, "x")(pkg)
		_, err := Parse(encode(t, pkg), thirdParty())
		expectCode(t, "extension "+name, err, "bundle_extension")
	}
	// Extension check is case-insensitive.
	pkg := fixtureV2()
	withFile("f/A.PNG", pngBody)(pkg)
	if _, err := Parse(encode(t, pkg), thirdParty()); err != nil {
		t.Errorf(".PNG rejected: %v", err)
	}
}

func TestBundleManifest(t *testing.T) {
	cases := map[string]struct {
		mutate func(map[string]any)
		code   string
	}{
		"sha mismatch": {func(p map[string]any) { bundleFiles(p)[1].(map[string]any)["sha256"] = sum("other") }, "bundle_sha256_mismatch"},
		"sha upper": {func(p map[string]any) {
			f := bundleFiles(p)[1].(map[string]any)
			f["sha256"] = strings.ToUpper(f["sha256"].(string))
		}, "bundle_sha256"},
		"sha short":       {func(p map[string]any) { bundleFiles(p)[1].(map[string]any)["sha256"] = "abc" }, "bundle_sha256"},
		"sha missing":     {func(p map[string]any) { delete(bundleFiles(p)[1].(map[string]any), "sha256") }, "bundle_sha256"},
		"data not base64": {func(p map[string]any) { bundleFiles(p)[1].(map[string]any)["data_base64"] = "!!" }, "bundle_data"},
		"duplicate path":  {func(p map[string]any) { bundleFiles(p)[1] = file("index.html", indexHTML) }, "bundle_duplicate"},
		"duplicate case":  {func(p map[string]any) { bundleFiles(p)[1] = file("INDEX.html", indexHTML) }, "bundle_duplicate"},
		"no files":        {func(p map[string]any) { p["site_bundle"].(map[string]any)["files"] = []any{} }, "bundle_files"},
		"no entry file":   {func(p map[string]any) { bundleFiles(p)[0] = file("home.html", indexHTML) }, "bundle_entry"},
		"entry not html":  {func(p map[string]any) { p["site_bundle"].(map[string]any)["entry"] = "assets/app.js" }, "bundle_entry"},
		"entry traversal": {func(p map[string]any) { p["site_bundle"].(map[string]any)["entry"] = "../index.html" }, "bundle_entry"},
		"entry case": {func(p map[string]any) {
			p["site_bundle"].(map[string]any)["entry"] = "INDEX.html"
		}, "bundle_entry"},
	}
	for name, c := range cases {
		pkg := fixtureV2()
		c.mutate(pkg)
		_, err := Parse(encode(t, pkg), thirdParty())
		expectCode(t, name, err, c.code)
	}
	pkg := fixtureV2()
	bundleFiles(pkg)[0] = file("home.html", indexHTML)
	pkg["site_bundle"].(map[string]any)["entry"] = "home.html"
	theme, err := Parse(encode(t, pkg), thirdParty())
	if err != nil || theme.Bundle.Entry != "home.html" {
		t.Fatalf("custom entry: %v", err)
	}
	pkg = fixtureV2()
	files := []any{}
	for i := 0; i <= BundleMaxFiles; i++ {
		files = append(files, file("f/"+strings.Repeat("a", i%100+1)+"-"+itoa(i)+".txt", "x"))
	}
	pkg["site_bundle"].(map[string]any)["files"] = append(files, file("index.html", indexHTML))
	_, err = Parse(encode(t, pkg), thirdParty())
	expectCode(t, "too many files", err, "bundle_files")
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	s := ""
	for ; i > 0; i /= 10 {
		s = string(rune('0'+i%10)) + s
	}
	return s
}

// The forbidden references, each in the file kinds it can appear in.
func TestBundleForbidden(t *testing.T) {
	cases := []struct {
		name, path, body, code string
	}{
		{"dashboard link", "index.html", `<a href="/dashboard/">后台</a>`, "bundle_dashboard"},
		{"dashboard upper", "index.html", `<a href="/DASHBOARD">x</a>`, "bundle_dashboard"},
		{"dashboard js", "assets/app.js", `location.href = "/dashboard/#/login"`, "bundle_dashboard"},
		{"dashboard escaped", "assets/app.js", `location.href = "\/dashboard"`, "bundle_dashboard"},
		{"dashboard unicode", "assets/app.js", `location.href = "\u002fdashboard"`, "bundle_dashboard"},
		{"dashboard percent", "assets/app.js", `fetch("%2Fdashboard")`, "bundle_dashboard"},
		{"dashboard entity", "index.html", `<a href="&#47;dashboard">x</a>`, "bundle_dashboard"},
		{"dashboard json", "data.json", `{"next":"/dashboard"}`, "bundle_dashboard"},
		{"dashboard css", "assets/app.css", `.a{background:url(/dashboard/x.png)}`, "bundle_dashboard"},
		{"dashboard svg", "img/a.svg", `<svg><a href="/dashboard"/></svg>`, "bundle_dashboard"},
		{"dashboard map", "assets/app.js.map", `{"sources":["/dashboard/x"]}`, "bundle_dashboard"},
		{"dashboard bare", "index.html", `<a href="/dashboard">x</a>`, "bundle_dashboard"},
		{"dashboard slash", "index.html", `<a href="/dashboard/">x</a>`, "bundle_dashboard"},
		{"dashboard sites", "index.html", `<a href="/dashboard/sites">x</a>`, "bundle_dashboard"},
		{"dashboard login subpath", "index.html", `<a href="/dashboard/login/x">x</a>`, "bundle_dashboard"},
		{"dashboard login trailing slash", "index.html", `<a href="/dashboard/login/">x</a>`, "bundle_dashboard"},
		{"dashboard login suffix", "index.html", `<a href="/dashboard/loginx">x</a>`, "bundle_dashboard"},
		{"dashboard login dash", "index.html", `<a href="/dashboard/login-admin">x</a>`, "bundle_dashboard"},
		{"dashboard login ext", "index.html", `<a href="/dashboard/login.html">x</a>`, "bundle_dashboard"},
		{"dashboard login dotdot", "index.html", `<a href="/dashboard/login/../sites">x</a>`, "bundle_dashboard"},
		{"dashboard login percent slash", "index.html", `<a href="/dashboard/login%2Fx">x</a>`, "bundle_dashboard"},
		{"dashboard login escaped slash", "assets/app.js", `location.href = "\/dashboard\/login\/x"`, "bundle_dashboard"},
		{"dashboard login percent", "index.html", `<a href="/dashboard/login%3Fx">x</a>`, "bundle_dashboard"},
		{"dashboard login then other", "assets/app.js", `a("/dashboard/login"); b("/dashboard/sites")`, "bundle_dashboard"},
		{"dashboard login query redirect", "index.html", `<a href="/dashboard/login?next=/dashboard/sites">x</a>`, "bundle_dashboard"},
		{"dashboard register subpath", "index.html", `<a href="/dashboard/register/admin">x</a>`, "bundle_dashboard"},
		{"dashboard forgot prefix", "index.html", `<a href="/dashboard/forgot">x</a>`, "bundle_dashboard"},
		{"dashboard forgot subpath", "index.html", `<a href="/dashboard/forgot-password/x">x</a>`, "bundle_dashboard"},
		{"dashboard hash route", "assets/app.js", `location.href = "/dashboard/#/login"`, "bundle_dashboard"},
		{"v1 admin", "assets/app.js", `fetch("/v1/admin/control-site")`, "bundle_api"},
		{"v1 auth", "assets/app.js", `fetch("/v1/auth/login",{method:"POST"})`, "bundle_api"},
		{"v1 root", "assets/app.js", `const api = "/v1/"`, "bundle_api"},
		{"v1 bare", "assets/app.js", `const api = "/v1"`, "bundle_api"},
		{"v1 concat", "assets/app.js", `fetch("/v1" + "/admin")`, "bundle_api"},
		{"v1 content prefix", "assets/app.js", `fetch("/v1/control-site/contents")`, "bundle_api"},
		{"v1 content subpath", "assets/app.js", `fetch("/v1/control-site/content/x")`, "bundle_api"},
		{"v1 control-site admin", "assets/app.js", `fetch("/v1/control-site/themes")`, "bundle_api"},
		{"v1 assets climb", "assets/app.js", `fetch("/v1/control-site/assets/../../admin/users")`, "bundle_api"},
		{"v1 assets subdir", "assets/app.js", `fetch("/v1/control-site/assets/x/y")`, "bundle_api"},
		{"v1 escaped", "assets/app.js", `fetch("\/v1\/users")`, "bundle_api"},
		{"v1 percent", "assets/app.js", `fetch("%2fv1%2fusers")`, "bundle_api"},
		{"v1 html", "index.html", `<form action="/v1/auth/login"></form>`, "bundle_api"},
		{"v1 absolute url", "assets/app.js", `fetch("https://ctl.example.com/v1/admin")`, "bundle_api"},
		{"sw register", "assets/app.js", `navigator.serviceWorker.register("/sw.js")`, "bundle_service_worker"},
		{"sw split", "assets/app.js", `navigator["serviceWorker"].register("sw.js")`, "bundle_service_worker"},
		{"sw html", "index.html", `<script>navigator.serviceWorker.register('sw.js')</script>`, "bundle_service_worker"},
		{"sw upper", "assets/app.js", `navigator.SERVICEWORKER`, "bundle_service_worker"},
		{"base", "index.html", `<html><head><base href="https://evil/"></head></html>`, "bundle_base"},
		{"base upper", "index.html", `<BASE HREF="/x/">`, "bundle_base"},
		{"base self closing", "index.html", `<base/>`, "bundle_base"},
		{"base in script", "index.html", `<script>document.write("<base href=//evil>")</script>`, "bundle_base"},
		{"base in js", "assets/app.js", `document.head.innerHTML = "< base href='//evil'>"`, "bundle_base"},
		{"external script", "index.html", `<script src="https://cdn.example.com/x.js"></script>`, "bundle_external_script"},
		{"external script http", "index.html", `<script src="http://cdn.example.com/x.js"></script>`, "bundle_external_script"},
		{"protocol relative script", "index.html", `<script src="//cdn.example.com/x.js"></script>`, "bundle_external_script"},
		{"data script", "index.html", `<script src="data:text/javascript,alert(1)"></script>`, "bundle_external_script"},
		{"javascript script", "index.html", `<script src="javascript:alert(1)"></script>`, "bundle_external_script"},
		{"backslash script", "index.html", `<script src="\\evil.example\x.js"></script>`, "bundle_external_script"},
		{"upper script", "index.html", `<SCRIPT SRC="HTTPS://cdn.example.com/x.js"></SCRIPT>`, "bundle_external_script"},
		{"spaced script", "index.html", `<script src=" https://cdn.example.com/x.js "></script>`, "bundle_external_script"},
		{"modulepreload", "index.html", `<link rel="modulepreload" href="https://cdn.example.com/x.js">`, "bundle_external_script"},
		{"preload script", "index.html", `<link rel="preload" as="script" href="//cdn.example.com/x.js">`, "bundle_external_script"},
		{"inline import", "index.html", `<script type="module">import x from "https://cdn.example.com/x.js"</script>`, "bundle_external_script"},
		{"js import", "assets/app.js", `import { x } from "https://esm.sh/x"`, "bundle_external_script"},
		{"js dynamic import", "assets/app.mjs", `await import('//cdn.example.com/x.js')`, "bundle_external_script"},
		{"admin selector", "assets/app.css", `html[data-cdnca-role="admin"] body{display:none}`, "bundle_admin"},
	}
	for _, c := range cases {
		pkg := fixtureV2()
		withFile(c.path, c.body)(pkg)
		_, err := Parse(encode(t, pkg), thirdParty())
		expectCode(t, c.name, err, c.code)
		// The official publisher is held to the same page bundle rules.
		_, err = Parse(encode(t, pkg), official())
		expectCode(t, "official "+c.name, err, c.code)
	}
}

func TestBundleAllowed(t *testing.T) {
	cases := []struct{ name, path, body string }{
		{"public content", "assets/app.js", `fetch("/v1/control-site/content")`},
		{"public content query", "assets/app.js", `fetch("/v1/control-site/content?x=1")`},
		{"public content single quote", "assets/app.js", `fetch('/v1/control-site/content')`},
		{"public asset", "assets/app.js", `img.src = "/v1/control-site/assets/" + sha`},
		{"public asset digest", "index.html", `<img src="/v1/control-site/assets/` + strings.Repeat("a", 64) + `">`},
		{"both public", "assets/app.js", `a("/v1/control-site/content");b("/v1/control-site/assets/")`},
		{"v10", "assets/app.js", `const x = "/v10/thing"; const y = "/v1beta"`},
		{"relative script", "index.html", `<script src="assets/app.js"></script><script src="./a.js"></script><script src="/site/a.js"></script>`},
		{"inline script", "index.html", `<script>console.log("hi")</script>`},
		{"external link", "index.html", `<a href="https://example.com">x</a><img src="https://example.com/a.png">`},
		{"external stylesheet", "index.html", `<link rel="stylesheet" href="https://fonts.example.com/a.css">`},
		{"login hash", "index.html", `<a href="/auth/login">登录</a><a href="#register">注册</a>`},
		{"relative import", "assets/app.js", `import x from "./x.js"; import("./y.js")`},
		{"base word", "assets/app.js", `const database = 1; const baseUrl = "/"`},
		{"png binary", "img/x.png", pngBody + "/dashboard /v1/admin serviceWorker <base>"},
		{"woff binary", "fonts/x.woff2", "/dashboard"},
		{"script query colon", "index.html", `<script src="assets/a.js?t=1:2"></script>`},
		{"dashboard login", "index.html", `<a href="/dashboard/login">登录</a>`},
		{"dashboard register", "index.html", `<a href='/dashboard/register'>注册</a>`},
		{"dashboard forgot", "index.html", `<a href="/dashboard/forgot-password">忘记密码</a>`},
		{"dashboard login query", "index.html", `<a href="/dashboard/login?redirect=home&lang=zh-CN">x</a>`},
		{"dashboard register hash", "index.html", `<a href="/dashboard/register#top">x</a>`},
		{"dashboard login upper", "index.html", `<a href="/DASHBOARD/LOGIN">x</a>`},
		{"dashboard login escaped", "assets/app.js", `location.href = "\/dashboard\/login"`},
		{"dashboard login percent", "assets/app.js", `location.href = "%2Fdashboard%2Flogin"`},
		{"dashboard login entity", "index.html", `<a href="&#47;dashboard&#47;register">x</a>`},
		{"dashboard all three", "assets/app.js", "a(`/dashboard/login`);b('/dashboard/register');c(\"/dashboard/forgot-password\")"},
		{"dashboard login absolute", "index.html", `<a href="https://ctl.example.com/dashboard/login">x</a>`},
		{"dashboard login json", "data.json", `{"login":"/dashboard/login","register":"/dashboard/register"}`},
		{"user role selector", "assets/app.css", `html[data-cdnca-role="user"] body{color:red}`},
	}
	for _, c := range cases {
		pkg := fixtureV2()
		withFile(c.path, c.body)(pkg)
		if _, err := Parse(encode(t, pkg), thirdParty()); err != nil {
			t.Errorf("%s rejected: %v", c.name, err)
		}
	}
}

func TestRelativeRef(t *testing.T) {
	for value, want := range map[string]bool{
		"a.js": true, "./a.js": true, "/a.js": true, "a/b.js?x=1:2": true, "a.js#x:y": true,
		"https://x": false, "//x": false, "data:x": false, "javascript:x": false, `\\x\a.js`: false, "a:b": false,
	} {
		if relativeRef(value) != want {
			t.Errorf("relativeRef(%q) != %v", value, want)
		}
	}
}
