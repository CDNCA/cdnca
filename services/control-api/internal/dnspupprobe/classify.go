package dnspupprobe

import (
	"errors"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/marketprobe"
)

// Checkpoint areas.
const (
	AreaMainland = "mainland"
	AreaHKMOTW   = "hkmotw"
	AreaOverseas = "overseas"
)

// Checkpoint carriers (dnspup isp is free text; edu and bgp are matched by
// keyword, everything unmatched is other).
const (
	CarrierTelecom = "telecom"
	CarrierUnicom  = "unicom"
	CarrierMobile  = "mobile"
	CarrierEdu     = "edu"
	CarrierBGP     = "bgp"
	CarrierOther   = "other"
)

var (
	allAreas    = []string{AreaMainland, AreaHKMOTW, AreaOverseas}
	allCarriers = []string{CarrierTelecom, CarrierUnicom, CarrierMobile, CarrierEdu, CarrierBGP, CarrierOther}
	eduWords    = []string{"教育", "cernet", "edu"}
)

// Place is where a checkpoint is: area, carrier and province (mainland short
// province name; hk / mo / tw / ISO code elsewhere; "" unknown).
type Place struct {
	Area, Carrier, Province string
}

// PlaceOf classifies a checkpoint from dnspup's region / location / isp.
func PlaceOf(region, location, isp string) Place {
	code, ok := marketprobe.Region(region)
	if !ok {
		code, _ = marketprobe.Region(location)
	}
	place := Place{Carrier: CarrierOther}
	switch {
	case code == "cn":
		place.Area = AreaMainland
		province, found := marketprobe.Province(region)
		if !found {
			province, _ = marketprobe.Province(location)
		}
		place.Province = province
	case code == "hk" || code == "mo" || code == "tw":
		place.Area, place.Province = AreaHKMOTW, code
	case code != "":
		place.Area, place.Province = AreaOverseas, code
	}
	lower := strings.ToLower(isp)
	for _, word := range eduWords {
		if strings.Contains(lower, word) {
			place.Carrier = CarrierEdu
			return place
		}
	}
	if carrier, ok := marketprobe.Carrier(isp); ok {
		place.Carrier = carrier
	} else if carrier, ok := marketprobe.Carrier(location); ok {
		place.Carrier = carrier
	}
	return place
}

// MaxCheckpoints is dnspup's per-job checkpoint limit (models.go
// MaxProbeNodeSelectionCount).
const MaxCheckpoints = 100

// Selection picks checkpoints: groups are area × carrier; empty lists mean
// any. Provinces take mainland short names or region codes (hk, us, …).
type Selection struct {
	Areas              []string `json:"areas"`
	Carriers           []string `json:"carriers"`
	IncludeProvinces   []string `json:"include_provinces"`
	ExcludeProvinces   []string `json:"exclude_provinces"`
	ExcludeCheckpoints []string `json:"exclude_checkpoints"`
	PointsPerGroup     int      `json:"points_per_group"`
	Rotate             bool     `json:"rotate"`
}

var (
	ErrInvalidSelection = errors.New("invalid dnspup checkpoint selection")
	placeToken          = regexp.MustCompile(`^([a-z]{2}|[\p{Han}]{2,3})$`)
	checkpointToken     = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,64}$`)
)

func uniqueIn(values, allowed []string, pattern *regexp.Regexp, limit int) bool {
	if len(values) > limit {
		return false
	}
	seen := map[string]bool{}
	for _, value := range values {
		if seen[value] || allowed != nil && !slices.Contains(allowed, value) || pattern != nil && !pattern.MatchString(value) {
			return false
		}
		seen[value] = true
	}
	return true
}

// Validate bounds the selection (points 1..20, known codes, no repeats).
func (selection Selection) Validate() error {
	if selection.PointsPerGroup < 1 || selection.PointsPerGroup > 20 ||
		!uniqueIn(selection.Areas, allAreas, nil, len(allAreas)) ||
		!uniqueIn(selection.Carriers, allCarriers, nil, len(allCarriers)) ||
		!uniqueIn(selection.IncludeProvinces, nil, placeToken, 64) ||
		!uniqueIn(selection.ExcludeProvinces, nil, placeToken, 64) ||
		!uniqueIn(selection.ExcludeCheckpoints, nil, checkpointToken, 100) {
		return ErrInvalidSelection
	}
	return nil
}

// Matches reports whether a checkpoint at place passes the filters.
func (selection Selection) Matches(id string, place Place) bool {
	return place.Area != "" && (len(selection.Areas) == 0 || slices.Contains(selection.Areas, place.Area)) &&
		(len(selection.Carriers) == 0 || slices.Contains(selection.Carriers, place.Carrier)) &&
		(len(selection.IncludeProvinces) == 0 || slices.Contains(selection.IncludeProvinces, place.Province)) &&
		!slices.Contains(selection.ExcludeProvinces, place.Province) &&
		!slices.Contains(selection.ExcludeCheckpoints, id)
}

// Picked is a selected checkpoint and its place.
type Picked struct {
	ID string
	Place
}

// Select takes up to PointsPerGroup online checkpoints of every area ×
// carrier group passing the filters (at most MaxCheckpoints in all). Rotate
// shifts each group's start by round so the points change between rounds;
// otherwise the first ones in ID order are taken (stable comparisons).
func Select(checkpoints []Checkpoint, selection Selection, round int64) []Picked {
	groups := map[string][]Picked{}
	for _, checkpoint := range checkpoints {
		if checkpoint.ID == "" || checkpoint.Status != "" && checkpoint.Status != "online" {
			continue
		}
		place := PlaceOf(checkpoint.Region, checkpoint.City, checkpoint.ISP)
		if !selection.Matches(checkpoint.ID, place) {
			continue
		}
		key := place.Area + "|" + place.Carrier
		groups[key] = append(groups[key], Picked{ID: checkpoint.ID, Place: place})
	}
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var out []Picked
	for _, key := range keys {
		members := groups[key]
		sort.Slice(members, func(i, j int) bool { return members[i].ID < members[j].ID })
		offset := 0
		if selection.Rotate && round > 0 {
			offset = int(round % int64(len(members)))
		}
		for index := 0; index < min(selection.PointsPerGroup, len(members)) && len(out) < MaxCheckpoints; index++ {
			out = append(out, members[(offset+index)%len(members)])
		}
	}
	return out
}

// Failure categories (diagnosis only; nothing here works around carrier
// blocking).
const (
	FailureOK      = "ok"
	FailureRefused = "refused"
	FailureTimeout = "timeout"
	FailureReset   = "reset"
	FailureTLS     = "tls"
	FailureHTTP    = "http"
	FailureDNS     = "dns"
	FailureOther   = "other"
)

// FailureTexts are the Chinese names used in alerts (the console has its own
// zh-CN / en-US texts).
var FailureTexts = map[string]string{
	FailureOK: "正常", FailureRefused: "连不上", FailureTimeout: "超时", FailureReset: "被重置",
	FailureTLS: "TLS 握手失败", FailureHTTP: "HTTP 错误", FailureDNS: "解析错误", FailureOther: "其他",
}

// Judge is one checkpoint's verdict for a probe of kind (tcping, ping, http,
// https, dns): voted=false when the checkpoint did not answer. http(s): any
// answer below 500 is reachable. dns: status ok and, with expect, at least
// one answer in expect.
func Judge(kind string, result Result, expect []string) (voted, ok bool, failure string) {
	if result.Status == "" || result.Status == "unavailable" || result.Status == "unknown" {
		return false, false, ""
	}
	switch kind {
	case "http", "https":
		if result.HTTPStatus > 0 {
			if result.HTTPStatus < 500 {
				return true, true, FailureOK
			}
			return true, false, FailureHTTP
		}
	case "dns":
		if result.Status == "ok" {
			if len(expect) == 0 || slices.ContainsFunc(result.Values, func(value string) bool {
				return slices.ContainsFunc(expect, func(want string) bool {
					return strings.EqualFold(strings.TrimSuffix(value, "."), strings.TrimSuffix(want, "."))
				})
			}) {
				return true, true, FailureOK
			}
			return true, false, FailureDNS
		}
	default:
		if result.Status == "ok" {
			return true, true, FailureOK
		}
	}
	return true, false, failureOf(result)
}

func failureOf(result Result) string {
	code := result.ErrorCode
	switch {
	case code == "tcp_connect_refused":
		return FailureRefused
	case code == "tcp_connect_timeout" || code == "icmp_timeout" || code == "dns_timeout":
		return FailureTimeout
	case strings.HasPrefix(code, "dns_") || code == "trusted_dns_resolution_failed" || code == "ip_version_unavailable":
		return FailureDNS
	}
	text := strings.ToLower(result.Error)
	switch {
	case strings.Contains(text, "no such host") || strings.Contains(text, "server misbehaving") ||
		strings.Contains(text, "lookup ") && !strings.Contains(text, "timeout"):
		return FailureDNS
	case strings.Contains(text, "tls:") || strings.Contains(text, "x509") || strings.Contains(text, "certificate") ||
		strings.Contains(text, "handshake"):
		return FailureTLS
	case strings.Contains(text, "connection reset") || strings.Contains(text, "reset by peer") ||
		strings.Contains(text, "broken pipe") || strings.HasSuffix(text, "eof"):
		return FailureReset
	case strings.Contains(text, "refused") || strings.Contains(text, "no route to host") ||
		strings.Contains(text, "network is unreachable"):
		return FailureRefused
	case result.Status == "timeout" || strings.Contains(text, "timeout") || strings.Contains(text, "deadline exceeded"):
		return FailureTimeout
	}
	return FailureOther
}

// Latency is the checkpoint's latency in milliseconds (the field dnspup fills
// depends on the probe type).
func Latency(result Result) int {
	return max(result.TotalTime, result.AvgLatency, result.LatencyMS)
}
