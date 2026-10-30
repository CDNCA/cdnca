package edgeconfig

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// SiteTrafficLimit is a website's own traffic cap (independent of its
// package): once the site's traffic in the current day,
// month or since the limit was set reaches a cap, the control plane publishes
// the site with Exceeded set and every node answers its requests with the
// notice page (HTTP 509) until the period rolls over or
// the cap is raised. Only Exceeded and the page reach the node; the caps and
// the usage stay on the control plane.
type SiteTrafficLimit struct {
	// Exceeded: the site is over a cap now (the reason is Period).
	Exceeded bool `json:"exceeded"`
	// Period is the cap that is reached: daily, monthly or total ("" when
	// not exceeded).
	Period string `json:"period,omitempty"`
	// NoticeHTML is the page served while exceeded; "" serves the default.
	NoticeHTML string `json:"notice_html,omitempty"`
}

const (
	SiteTrafficLimitDaily   = "daily"
	SiteTrafficLimitMonthly = "monthly"
	SiteTrafficLimitTotal   = "total"
	// SiteTrafficLimitStatus is the response status while exceeded
	// (509 Bandwidth Limit Exceeded).
	SiteTrafficLimitStatus = 509
	// MaxSiteTrafficNoticeBytes bounds the notice page.
	MaxSiteTrafficNoticeBytes = 64 << 10
)

// DefaultSiteTrafficNoticeHTML is the notice page when the site set none.
const DefaultSiteTrafficNoticeHTML = `<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>Traffic limit exceeded</title></head>
<body><h1>网站流量已超出限制</h1><p>The traffic of this website has exceeded its limit. Please contact the website administrator.</p></body></html>
`

func (limit SiteTrafficLimit) Validate() error {
	if !limit.Exceeded {
		if limit.Period != "" {
			return ErrInvalidConfig
		}
	} else if limit.Period != SiteTrafficLimitDaily && limit.Period != SiteTrafficLimitMonthly && limit.Period != SiteTrafficLimitTotal {
		return ErrInvalidConfig
	}
	if len(limit.NoticeHTML) > MaxSiteTrafficNoticeBytes || !utf8.ValidString(limit.NoticeHTML) ||
		strings.ContainsRune(limit.NoticeHTML, 0) {
		return ErrInvalidConfig
	}
	return nil
}

// SiteTrafficLimitNoticePath is the notice page file of a site inside a
// release (relative to the release root).
func SiteTrafficLimitNoticePath(siteID string) string {
	return "traffic-limit/" + siteID + ".html"
}

// SiteTrafficLimitDirectives is the server{} part of an exceeded site: every
// request (ACME HTTP-01 challenges excepted, so certificates keep renewing)
// gets the notice page with status 509. releaseRoot is the absolute release
// directory holding SiteTrafficLimitNoticePath. "" when not exceeded.
func SiteTrafficLimitDirectives(limit SiteTrafficLimit, siteID, releaseRoot string) (string, error) {
	if err := limit.Validate(); err != nil {
		return "", err
	}
	if !limit.Exceeded {
		return "", nil
	}
	// The page is read in Lua so every method gets it (the static file
	// handler refuses POST with 405); the file is the release's own copy.
	var output strings.Builder
	output.WriteString("    location @cdnca_traffic_limit {\n")
	output.WriteString("      internal;\n")
	output.WriteString("      add_header Cache-Control \"no-store\" always;\n")
	fmt.Fprintf(&output, "      content_by_lua_block {\n        local file = io.open(%s, \"rb\")\n", luaQuoteString(releaseRoot+"/"+SiteTrafficLimitNoticePath(siteID)))
	output.WriteString("        local body = file and file:read(\"*a\") or \"traffic limit exceeded\\n\"\n")
	output.WriteString("        if file then file:close() end\n")
	fmt.Fprintf(&output, "        ngx.status = %d\n", SiteTrafficLimitStatus)
	output.WriteString("        ngx.header[\"Content-Type\"] = \"text/html; charset=utf-8\"\n")
	output.WriteString("        ngx.print(body)\n      }\n    }\n")
	fmt.Fprintf(&output, "    error_page %d @cdnca_traffic_limit;\n", SiteTrafficLimitStatus)
	fmt.Fprintf(&output, "    if ($uri !~ \"^/\\.well-known/acme-challenge/\") { return %d; }\n", SiteTrafficLimitStatus)
	return output.String(), nil
}

// SiteTrafficLimitNotice is the page content of an exceeded site.
func SiteTrafficLimitNotice(limit SiteTrafficLimit) []byte {
	if limit.NoticeHTML != "" {
		return []byte(limit.NoticeHTML)
	}
	return []byte(DefaultSiteTrafficNoticeHTML)
}

// luaQuoteString is a Lua string literal of value.
func luaQuoteString(value string) string {
	return strconv.Quote(value)
}
