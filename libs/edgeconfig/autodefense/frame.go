package autodefense

import (
	"bytes"
	"encoding/json"
	"io"
	"slices"
)

// Collection frame (ADR 0010 section 4.1): every second each nginx worker
// POSTs one frame per flush to the agent over the local unix socket
// (location only reachable by the agent, ADR 0009 section 8.2), then clears
// its tables. JSON, one object per request body. The Lua producer
// (cdnca_autodefense.lua, AD-04) and the agent consumer (AD-05) both test
// against DecodeFrame.

const (
	FrameSchema = "cdnca.autodefense.frame/v1"
	// Per worker per site per second bounds (section 4.1).
	MaxFrameIPs      = 4096
	MaxFrameBehavior = 256
	MaxFrameSamples  = 64
	MaxFrameSites    = 10000
	MaxFrameBytes    = 8 << 20
	// LatencyBuckets: log2 microsecond buckets 0-15 (bucket 15 is >= 2^15 us).
	LatencyBuckets = 16
)

type Frame struct {
	Schema string `json:"schema"`
	Worker int64  `json:"worker"` // ngx.worker.id()
	PID    int64  `json:"pid"`
	Second int64  `json:"second"` // Unix second the counters belong to
	// Revision is the snapshot revision the worker's gate read.
	Revision uint64      `json:"revision"`
	Sites    []FrameSite `json:"sites"`
}

type FrameSite struct {
	SiteID string `json:"site_id"`
	// Exact counters of the second.
	Requests        int64   `json:"requests"`
	Status2xx       int64   `json:"status_2xx"`
	Status3xx       int64   `json:"status_3xx"`
	Status4xx       int64   `json:"status_4xx"`
	Status404       int64   `json:"status_404"`
	Status5xx       int64   `json:"status_5xx"`
	CacheHit        int64   `json:"cache_hit"`
	UpstreamError   int64   `json:"upstream_error"`
	UpstreamTimeout int64   `json:"upstream_timeout"`
	Bytes           int64   `json:"bytes"`
	Latency         []int64 `json:"latency"` // LatencyBuckets counts
	// Gate counters: requests the gate passed by whitelist, challenged,
	// limited, blocked; signature hits by ID (shadow included).
	Whitelisted   int64            `json:"whitelisted"`
	Challenged    int64            `json:"challenged"`
	ChallengePass int64            `json:"challenge_pass"`
	Limited       int64            `json:"limited"`
	Blocked       int64            `json:"blocked"`
	SignatureHits map[string]int64 `json:"signature_hits"`
	// IPs: per client request counts (canonical address -> count); Overflow
	// counts requests of clients beyond MaxFrameIPs.
	IPs      map[string]int64 `json:"ips"`
	Overflow int64            `json:"overflow"`
	// Behavior of the top MaxFrameBehavior clients of the second.
	Behavior []FrameBehavior `json:"behavior"`
	Samples  []FrameSample   `json:"samples"`
	// Params: clean request parameter samples for the adaptive WAF profile
	// (ADR 0011 section 3.6, RI-05), at most MaxFrameParamSamples; values
	// never enter the frame. Absent until the Lua producer fills it.
	Params []FrameParamSample `json:"params,omitempty"`
	// BotHits: requests of the second per bot class (BotCategories) the
	// gate classified while the class's overlay item was engaged;
	// absent when none.
	BotHits map[string]int64 `json:"bot_hits,omitempty"`
	// JA4Challenged / JA4ChallengePass: the gate counters of the second
	// split by JA4 for requests a ja4 mitigation entry challenged (the
	// node's script JA4 challenge list, ADR 0010 §7A.6), at most
	// MaxFrameJA4 each; absent when none.
	JA4Challenged    map[string]int64 `json:"ja4_challenged,omitempty"`
	JA4ChallengePass map[string]int64 `json:"ja4_challenge_pass,omitempty"`
}

// MaxFrameJA4 bounds the per JA4 challenge counters of one site (the JA4
// challenge list holds at most 64 entries, §7A.6).
const MaxFrameJA4 = 64

// FrameBehavior: Welford accumulators of the request intervals (mean and M2
// in microseconds), distinct path hash count (8 bit hashes), static count,
// requests without Referer / Cookie.
type FrameBehavior struct {
	Client      string `json:"client"`
	Requests    int64  `json:"requests"`
	IntervalN   int64  `json:"interval_n"`
	IntervalAvg int64  `json:"interval_avg_us"`
	IntervalM2  int64  `json:"interval_m2_us2"`
	Paths       int64  `json:"paths"`
	Static      int64  `json:"static"`
	NoReferer   int64  `json:"no_referer"`
	NoCookie    int64  `json:"no_cookie"`
}

// FrameSample is one reservoir sample tuple (section 4.1). Values follow
// the signature dimensions' canonical forms; empty means unknown (JA4 is
// empty on QUIC).
type FrameSample struct {
	Client          string   `json:"client"`
	CIDR            string   `json:"cidr"`
	ASN             string   `json:"asn"`
	Tags            []string `json:"tags"`
	Country         string   `json:"country"`
	JA4             string   `json:"ja4"`
	UAFamily        string   `json:"ua_family"`
	UAHash          string   `json:"ua_hash"`
	PathTemplate    string   `json:"path_template"`
	QueryNamesHash  string   `json:"query_names_hash"`
	QueryEntropy    int64    `json:"query_entropy_bucket"`
	Method          string   `json:"method"`
	HTTPVersion     string   `json:"http_version"`
	HeaderOrderHash string   `json:"header_order_hash"`
	Missing         []string `json:"missing"`
	Status          int64    `json:"status"`
	CacheStatus     string   `json:"cache_status"`
	BytesBucket     int64    `json:"bytes_bucket"`
}

// DecodeFrame strictly decodes and validates one frame.
func DecodeFrame(encoded []byte) (Frame, error) {
	if len(encoded) == 0 || len(encoded) > MaxFrameBytes {
		return Frame{}, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var frame Frame
	if err := decoder.Decode(&frame); err != nil {
		return Frame{}, ErrInvalid
	}
	if _, err := decoder.Token(); err != io.EOF || !frame.valid() {
		return Frame{}, ErrInvalid
	}
	return frame, nil
}

func (frame Frame) valid() bool {
	if frame.Schema != FrameSchema || frame.Worker < 0 || frame.Worker > 1024 || frame.PID <= 0 ||
		!validTime(frame.Second, false) || frame.Revision > MaxValue || frame.Sites == nil || len(frame.Sites) > MaxFrameSites {
		return false
	}
	seen := map[string]bool{}
	for _, site := range frame.Sites {
		if !uuidPattern.MatchString(site.SiteID) || seen[site.SiteID] || !site.valid() {
			return false
		}
		seen[site.SiteID] = true
	}
	return true
}

func (site FrameSite) valid() bool {
	for _, count := range []int64{site.Requests, site.Status2xx, site.Status3xx, site.Status4xx, site.Status404, site.Status5xx,
		site.CacheHit, site.UpstreamError, site.UpstreamTimeout, site.Bytes, site.Whitelisted, site.Challenged,
		site.ChallengePass, site.Limited, site.Blocked, site.Overflow} {
		if !validInt(count) {
			return false
		}
	}
	if len(site.Latency) != LatencyBuckets || site.IPs == nil || len(site.IPs) > MaxFrameIPs || site.SignatureHits == nil ||
		len(site.SignatureHits) > MaxSignaturesPerSite || site.Behavior == nil || len(site.Behavior) > MaxFrameBehavior ||
		site.Samples == nil || len(site.Samples) > MaxFrameSamples || site.Status404 > site.Status4xx || !validFrameParams(site.Params) {
		return false
	}
	for _, count := range site.Latency {
		if !validInt(count) {
			return false
		}
	}
	for id, count := range site.SignatureHits {
		if !hash16Pattern.MatchString(id) || !validInt(count) {
			return false
		}
	}
	for client, count := range site.IPs {
		if canonical, ok := CanonicalAddress(client); !ok || canonical != client || !validInt(count) {
			return false
		}
	}
	for _, behavior := range site.Behavior {
		if canonical, ok := CanonicalAddress(behavior.Client); !ok || canonical != behavior.Client {
			return false
		}
		for _, value := range []int64{behavior.Requests, behavior.IntervalN, behavior.IntervalAvg, behavior.IntervalM2,
			behavior.Paths, behavior.Static, behavior.NoReferer, behavior.NoCookie} {
			if !validInt(value) {
				return false
			}
		}
	}
	for _, sample := range site.Samples {
		if !sample.valid() {
			return false
		}
	}
	for class, count := range site.BotHits {
		if !slices.Contains(BotCategories, class) || !validInt(count) {
			return false
		}
	}
	for _, byJA4 := range []map[string]int64{site.JA4Challenged, site.JA4ChallengePass} {
		if len(byJA4) > MaxFrameJA4 {
			return false
		}
		for ja4, count := range byJA4 {
			if !ValidCondition(DimJA4, ja4) || !validInt(count) {
				return false
			}
		}
	}
	return true
}

func (sample FrameSample) valid() bool {
	if canonical, ok := CanonicalAddress(sample.Client); !ok || canonical != sample.Client ||
		!ValidCondition(DimCIDR, sample.CIDR) || sample.Tags == nil || len(sample.Tags) > 16 || sample.Missing == nil ||
		sample.QueryEntropy < 0 || sample.QueryEntropy > 15 || sample.Status < 100 || sample.Status > 599 ||
		!ValidCondition(DimBytesBucket, itoa(sample.BytesBucket)) || len(sample.CacheStatus) > 16 {
		return false
	}
	optional := map[string]string{DimASN: sample.ASN, DimCountry: sample.Country, DimJA4: sample.JA4, DimUAFamily: sample.UAFamily,
		DimUAHash: sample.UAHash, DimPathTemplate: sample.PathTemplate, DimQueryNamesHash: sample.QueryNamesHash,
		DimMethod: sample.Method, DimHTTPVersion: sample.HTTPVersion, DimHeaderOrderHash: sample.HeaderOrderHash}
	for dim, value := range optional {
		if value != "" && !ValidCondition(dim, value) {
			return false
		}
	}
	for _, tag := range sample.Tags {
		if !ValidCondition(DimIPTag, tag) {
			return false
		}
	}
	for _, missing := range sample.Missing {
		if !ValidCondition(DimMissingHeader, missing) {
			return false
		}
	}
	return true
}
