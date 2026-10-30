package edgeskeleton

import (
	"strings"
	"testing"
)

// HTTP 302 scheduling: the landing and realip go on plain
// shared servers only, the size dictionary, variables, Lua path and table
// path are rendered once; off renders none of it.
func TestRenderSchedule302(t *testing.T) {
	off := render(t, testInput())
	if strings.Contains(off, "sched302") || strings.Contains(off, "X-Cdnca-S302") {
		t.Fatal("schedule302 rendered while off")
	}
	input := testInput()
	input.Schedule302 = true
	config := render(t, input)
	for _, want := range []string{
		"lua_shared_dict cdnca_sched302_sizes 16m;",
		`"/usr/local/share/cdnca/sched302/?.lua;/usr/local/share/cdnca/dynroute/?.lua;`,
		`schedule302_table = "/var/lib/cdnca-edge/state/schedule302/table.json",`,
		"    ~^/_cdnca302/ 1;\n",
		`set $cdnca_sched302_token "";`,
	} {
		if !strings.Contains(config, want) {
			t.Fatalf("missing %q", want)
		}
	}
	plain := server(t, config, 80)
	for _, want := range []string{"real_ip_header X-Cdnca-S302-Client;", "location ^~ /_cdnca302/ {",
		"proxy_pass http://127.0.0.1:$cdnca_sched302_port$cdnca_sched302_uri;"} {
		if !strings.Contains(plain, want) {
			t.Fatalf("plain server misses %q", want)
		}
	}
	if tls := server(t, config, 443); strings.Contains(tls, "_cdnca302") || strings.Contains(tls, "X-Cdnca-S302") {
		t.Fatal("TLS server has the landing")
	}
}

// Per-site gzip (D13-c0 ⑥): off renders no gzip in the servers; on, every
// server compresses any type and length (the Lua gate narrows it) and the
// system default reaches configure.
func TestRenderSiteGzip(t *testing.T) {
	if off := render(t, testInput()); strings.Contains(server(t, off, 80), "gzip") || strings.Contains(off, "site_gzip") {
		t.Fatal("site gzip rendered while off")
	}
	input := testInput()
	input.SiteGzip = true
	config := render(t, input)
	for _, port := range []int{80, 443, 8443} {
		if !strings.Contains(server(t, config, port), siteGzipServer) {
			t.Fatalf("server %d lacks the site gzip directives", port)
		}
	}
	if !strings.Contains(config, "site_gzip = { disabled = true, vary = false, min_length = 20, types = {  } },") {
		t.Fatal("configure lacks the nginx default site_gzip")
	}
}
