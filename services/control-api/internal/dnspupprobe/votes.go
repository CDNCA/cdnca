package dnspupprobe

import (
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/marketprobe"
)

// Vote is one dnspup checkpoint's answer, tagged with its region / carrier
// (marketprobe codes) for per-line verdicts. Voted=false: the checkpoint did
// not answer (unavailable / timeout without an HTTP answer) and is no vote.
type Vote struct {
	NodeID    string
	Region    string // marketprobe.Region code ("cn", "hk", …; "" unknown)
	Carrier   string // marketprobe.Carrier code ("telecom", …; "" unknown)
	OK, Voted bool
	Reason    string // failed votes: status_5xx / status / connect
	LatencyMS int
}

// HTTPTarget is an origin dnspup's http probe can express: dnspup connects
// to the URL's host and sends it as Host (and SNI for https) with system
// trust, so only targets whose Host/SNI is the connect host and that use
// system trust qualify (the rest stay with the other sources).
type HTTPTarget struct {
	Host       string
	Port       int
	HTTPS      bool
	HostHeader string
	ServerName string
	Path       string
	CustomCA   bool
}

// HTTPURL is the dnspup target URL of target; ok=false: dnspup cannot probe it.
func HTTPURL(target HTTPTarget) (string, bool) {
	host := strings.ToLower(strings.TrimSuffix(target.Host, "."))
	if host == "" || target.Port < 1 || target.Port > 65535 || target.CustomCA || strings.Contains(host, "*") ||
		!sameHost(target.HostHeader, host, target.Port, target.HTTPS) ||
		target.HTTPS && !strings.EqualFold(strings.TrimSuffix(target.ServerName, "."), host) {
		return "", false
	}
	if ip := net.ParseIP(host); ip == nil && !strings.Contains(host, ".") {
		return "", false
	}
	scheme, defaultPort := "http", 80
	if target.HTTPS {
		scheme, defaultPort = "https", 443
	}
	address := host
	if strings.Contains(host, ":") {
		address = "[" + host + "]"
	}
	if target.Port != defaultPort {
		address = net.JoinHostPort(host, strconv.Itoa(target.Port))
	}
	path, query, _ := strings.Cut(target.Path, "?")
	if path == "" || path[0] != '/' {
		path = "/" + path
	}
	built := &url.URL{Scheme: scheme, Host: address, Path: path, RawQuery: query}
	value := built.String()
	if len(value) > 2048 {
		return "", false
	}
	return value, true
}

// sameHost: header names host (optionally with the effective port).
func sameHost(header, host string, port int, https bool) bool {
	header = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(header), "."))
	if header == host || header == "["+host+"]" {
		return true
	}
	name, rawPort, err := net.SplitHostPort(header)
	return err == nil && strings.Trim(strings.TrimSuffix(name, "."), "[]") == host && rawPort == strconv.Itoa(port)
}

// HTTPVotes maps http results: an HTTP answer below 500 (or equal to expect
// when expect > 0) is OK, any other answer a failure; no answer at all
// (unavailable) is no vote; a connection failure votes "connect".
func HTTPVotes(results []Result, expect int) []Vote {
	votes := make([]Vote, 0, len(results))
	for _, result := range results {
		vote := tag(result)
		switch {
		case result.Status == "unavailable" || result.Status == "unknown":
		case result.HTTPStatus > 0:
			vote.Voted = true
			vote.OK = expect > 0 && result.HTTPStatus == expect || expect == 0 && result.HTTPStatus < 500
			if !vote.OK {
				vote.Reason = "status_5xx"
				if expect > 0 {
					vote.Reason = "status"
				}
			}
			vote.LatencyMS = max(result.TotalTime, result.LatencyMS)
		case result.Status == "bad" || result.Status == "timeout":
			vote.Voted, vote.Reason = true, "connect"
		}
		votes = append(votes, vote)
	}
	return votes
}

// TCPVotes maps tcping results: status ok (at least one connect) is OK,
// timeout / bad a failure, unavailable no vote.
func TCPVotes(results []Result) []Vote {
	votes := make([]Vote, 0, len(results))
	for _, result := range results {
		vote := tag(result)
		switch result.Status {
		case "ok":
			vote.Voted, vote.OK, vote.LatencyMS = true, true, max(result.AvgLatency, result.LatencyMS)
		case "timeout", "bad":
			vote.Voted, vote.Reason = true, "connect"
		}
		votes = append(votes, vote)
	}
	return votes
}

// tag reads the checkpoint's region and carrier (dnspup: region = province
// or country name, isp = 电信 / 联通 / 移动 / …; location = node name).
func tag(result Result) Vote {
	region, ok := marketprobe.Region(result.Region)
	if !ok {
		region, _ = marketprobe.Region(result.Location)
	}
	carrier, ok := marketprobe.Carrier(result.ISP)
	if !ok {
		carrier, _ = marketprobe.Carrier(result.Location)
	}
	return Vote{NodeID: result.NodeID, Region: region, Carrier: carrier}
}
