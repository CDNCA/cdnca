package main

// waf-cookie-fp (-only adaptive): 严格防护's weak rules do not read cookies;
// the real-traffic cookie shapes that filled the weak sums pass, attacks in
// a cookie (plain, in a JWT, base64, URL-encoded JSON) are still blocked by
// the strong rules or the detectors on the decoded values, and a value with
// an unbalanced [ no longer answers 500 (CMDI.glob).
// waf-cookie-fp2: a cookie out of the site's learned profile (a typed cookie
// parameter) enters the tier's cookie variant, where the weak rules read it.

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"slices"

	"github.com/cdnca/cdnca/libs/edgeconfig/autodefense"
)

// profiledCookie: s.waf.test learned cookie pref as a short identifier
// (site level key, no charset class).
var profiledCookie = autodefense.WAFTypedParam{Key: autodefense.WAFParamKey("", "cookie", "pref"), Type: "ident", MaxLenBucket: 4}

// knownCookieNames: f.waf.test is cookie mature and knows pref and sid
// (waf_adapt cookie_names, low halves of the cookie keys, ascending).
var knownCookieNames = func() []string {
	names := []string{autodefense.WAFCookieKey("pref")[8:], autodefense.WAFCookieKey("sid")[8:]}
	slices.Sort(names)
	return names
}()

func cookieChecks() {
	api := func(cookie string) map[string]string {
		return map[string]string{"Accept": "application/json", "Cookie": cookie}
	}
	b64 := base64.RawURLEncoding.EncodeToString
	benign := map[string]string{
		// the top rules of scripts/security/datasets/results/cookie-rules-diag.md
		"consent json": "_tracking_consent=" + url.QueryEscape(`{"con":{"CMP":{"a":"","m":"","p":"","s":""}},"v":"2.1","region":"FRIDF","reg":"","purposes":{"a":true,"p":true,"m":true,"t":true},"display_banner":false,"sale_of_data_region":false,"consent_id":"9F1C2D3E-4B5A-6789-ABCD-EF0123456789"}`),
		"utag packed":  "utag_main=v_id:01926c23e430002277b8da446bda0506f001c0670086e$_sn:1$_se:1$_ss:1$_st:1728392944497$ses_id:1728391144497%3Bexp-session$_pn:1%3Bexp-session",
		"fd.ga json":   "fd.ga={%22loggedIn%22:false%2C%22location%22:%22%22%2C%22type%22:%22Normal%22%2C%22user_auth%22:%22MDM%22%2C%22user_state%22:%22Guest%22}",
		"optanon":      "OptanonConsent=isGpcEnabled=0&datestamp=Tue+Oct+08+2024+13%3A39%3A06+GMT%2B0200&version=202409.1.0&groups=C0001%3A1%2CC0002%3A1%2CC0004%3A1&geolocation=FR%3BIDF",
		"jwt session":  "session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + b64([]byte(`{"sub":"1234567890","name":"John Doe","iat":1516239022}`)) + ".dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
		"akamai":       "bm_sv=1A2B3C4D5E6F~YAAQx2kbF7+abcdefghij/klmnopQRSTUVWXYZ0123456789+abcdefghijklmnopq==~1; ak_bmsc=0ABCDEF1234567890~000000000000000000000000000000~YAAQ",
	}
	for name, cookie := range benign {
		r := send(http.MethodGet, "s.waf.test", "/static/app.js", "", api(cookie))
		check("cookie benign "+name, r.status == 200, "严格防护 %d", r.status)
	}
	attacks := map[string]string{
		"plain sqli (PL1 strong)": "id=" + url.QueryEscape("1' OR '1'='1"),
		"plain xss (PL1 strong)":  "pref=" + url.QueryEscape("<script>alert(1)</script>"),
		"jwt payload sqli":        "session=eyJhbGciOiJIUzI1NiJ9." + b64([]byte(`{"sub":"1' UNION SELECT password FROM users--"}`)) + ".sig",
		"base64 ssti":             "t=" + base64.StdEncoding.EncodeToString([]byte("{{7*7}}{{config.__class__.__init__.__globals__}}")),
		"json leaf cmd":           "prefs=" + url.QueryEscape(`{"theme":"dark; cat /etc/passwd"}`),
	}
	for name, cookie := range attacks {
		r := send(http.MethodGet, "s.waf.test", "/t", "", api(cookie))
		check("cookie attack "+name, r.status == 403, "严格防护 %d", r.status)
	}
	// a weak-only cookie payload (CRS 932240-3, PL2): in the profiled cookie
	// out of shape, the variant reads it (932240 + shape = weak threshold);
	// in an unprofiled cookie, or on a site without a cookie profile (o), the
	// weak rules do not read cookies; a cookie that fits passes
	weakOnly := "una$$me -a" // as the CRS test sends it
	for _, c := range []struct {
		name, host, cookie string
		status             int
	}{
		{"profiled fits", "s.waf.test", "pref=dark", 200},
		{"profiled out of shape weak hit", "s.waf.test", "pref=" + weakOnly, 403},
		{"unprofiled weak hit", "s.waf.test", "other=" + weakOnly, 200},
		{"no cookie profile weak hit", "o.waf.test", "pref=" + weakOnly, 200},
		{"profiled out of shape alone", "s.waf.test", "pref=dark-mode-with-a-long-name", 200},
		// ri-wire Cookie 名集合 (f: cookie mature, knows pref and sid, no
		// typed cookie): a known name's weak hit is not read; an unseen name
		// is clean on its own; the platform's own cookies are not the site's
		{"mature known name weak hit", "f.waf.test", "pref=" + weakOnly, 200},
		{"mature unseen name clean", "f.waf.test", "pref=dark; theme=light", 200},
		{"mature platform cookie", "f.waf.test", "pref=dark; __cdnca_waf_grey=x", 200},
	} {
		r := send(http.MethodGet, c.host, "/static/app.js", "", api(c.cookie))
		check("cookie profile "+c.name, r.status == c.status, "%s %d, want %d", c.host, r.status, c.status)
	}
	// ri-wire Cookie 名集合: weak-only cookie payloads (two PL2 command
	// injection hits, 10 = the weak threshold) under an unseen name on the
	// mature site f enter the variant and are blocked; the same under a
	// known name, or on o (not cookie mature), are not read. Sent raw:
	// ModSecurity does not decode cookie values, so a URL-escaped payload
	// misses 932240 (t:none); no ";" (the cookie separator).
	weakPair := "una$$me -a /x" // 932240 (evasion) + 932200 (bypass with a path), no PL1 hit
	unseen := send(http.MethodGet, "f.waf.test", "/static/app.js", "", api("test="+weakPair))
	known := send(http.MethodGet, "f.waf.test", "/static/app.js", "", api("pref="+weakPair))
	other := send(http.MethodGet, "o.waf.test", "/static/app.js", "", api("test="+weakPair))
	check("cookie unseen name variant", unseen.status == 403 && known.status == 200 && other.status == 200,
		"unseen on f %d (want 403), known on f %d, unseen on o %d (want 200)", unseen.status, known.status, other.status)

	// GoTestWAF false-pos texts-46: 500 before the CMDI.glob fix
	for _, host := range []string{"s.waf.test", "p.waf.test"} {
		r := send(http.MethodGet, host, "/?q="+url.QueryEscape("[Host: type: {["), "", map[string]string{"Accept": "application/json"})
		check("unbalanced bracket "+host, r.status != 500, "status %d", r.status)
	}
}
