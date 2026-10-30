package edgeconfig

import (
	"strings"
	"testing"
)

func TestSiteTrafficLimitDirectives(t *testing.T) {
	limit := SiteTrafficLimit{Exceeded: true, Period: SiteTrafficLimitMonthly}
	directives, err := SiteTrafficLimitDirectives(limit, "33333333-3333-4333-8333-333333333333", "/runtime/release")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"location @cdnca_traffic_limit {",
		`io.open("/runtime/release/traffic-limit/33333333-3333-4333-8333-333333333333.html", "rb")`,
		"ngx.status = 509",
		"error_page 509 @cdnca_traffic_limit;", `if ($uri !~ "^/\.well-known/acme-challenge/") { return 509; }`,
	} {
		if !strings.Contains(directives, want) {
			t.Errorf("directives missing %q:\n%s", want, directives)
		}
	}
	if string(SiteTrafficLimitNotice(limit)) != DefaultSiteTrafficNoticeHTML ||
		string(SiteTrafficLimitNotice(SiteTrafficLimit{Exceeded: true, Period: "daily", NoticeHTML: "<p>x</p>"})) != "<p>x</p>" {
		t.Fatal("notice page")
	}
	if directives, _ := SiteTrafficLimitDirectives(SiteTrafficLimit{}, "s", "/r"); directives != "" {
		t.Fatal("a site within its caps renders the notice")
	}
	for _, invalid := range []SiteTrafficLimit{
		{Exceeded: true}, {Exceeded: true, Period: "weekly"}, {Period: "daily"},
		{Exceeded: true, Period: "daily", NoticeHTML: strings.Repeat("x", MaxSiteTrafficNoticeBytes+1)},
	} {
		if invalid.Validate() == nil {
			t.Errorf("accepted %+v", invalid)
		}
	}
}
