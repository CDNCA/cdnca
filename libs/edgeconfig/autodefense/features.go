package autodefense

import (
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// Feature registries (ADR 0010 section 4.2). Numeric features are carried
// in milli units (x1000): a rate is per second x 1000, a ratio is 0-1000000
// (fraction x 1000000 / 1000 = permille x 1000), a duration is microseconds
// x 1000. The registry is frozen; a new feature is a contract change.

// SiteFeatures are the numeric site-level features with a baseline band.
var SiteFeatures = []string{
	"asn_entropy",
	"bytes_rate",
	"cache_hit_ratio",
	"challenge_pass_ratio",
	"idc_ratio",
	"interval_cv",
	"latency_p95_us",
	"latency_p99_us",
	"new_ip_ratio",
	"no_cookie_ratio",
	"no_referer_ratio",
	"path_entropy",
	"per_ip_404_p99",
	"per_ip_p50",
	"per_ip_p99",
	"ratio_404",
	"ratio_4xx",
	"ratio_5xx",
	"request_rate",
	"requests_per_ip",
	"session_depth",
	"static_ratio",
	"unique_cidr",
	"unique_ip",
	"upstream_timeout_ratio",
}

// PortGroupFeatures are the numeric layer 4 features (node x port group).
var PortGroupFeatures = []string{
	"handshake_complete_ratio",
	"idle_conns",
	"invalid_rate",
	"listen_overflow_rate",
	"malformed_rate",
	"new_conn_rate",
	"per_ip_conns_p99",
	"per_ip_new_conn_p99",
	"source_cidr_entropy",
	"syn_rate",
	"syncookie_failed_rate",
	"syncookie_sent_rate",
	"udp_bytes_rate",
	"udp_packet_rate",
}

// SiteDistributions / PortGroupDistributions are the distribution features
// (JSD against the baseline share vector).
var (
	SiteDistributions      = []string{"asn", "country", "header_order", "ja4", "path_template", "status", "ua_family"}
	PortGroupDistributions = []string{"packet_length"}
)

// Signature dimensions (section 6.1 candidate items). Each validates its
// value; buckets are frozen strings.
const (
	DimJA4             = "ja4"
	DimUAHash          = "ua_hash"
	DimUAFamily        = "ua_family"
	DimPathTemplate    = "path_template"
	DimQueryNamesHash  = "query_names_hash"
	DimHeaderOrderHash = "header_order_hash"
	DimMissingHeader   = "missing_header" // accept | accept_language | referer | cookie
	DimHTTPVersion     = "http_version"
	DimMethod          = "method"
	DimASN             = "asn"
	DimCIDR            = "cidr" // IPv4 /24 or IPv6 /48
	DimCountry         = "country"
	DimIPTag           = "ip_tag"
	DimStatus          = "status"
	DimBytesBucket     = "bytes_bucket"
	DimIntervalCV      = "interval_cv_bucket"
	DimUniquePathRatio = "unique_path_ratio_bucket"
	DimStaticRatio     = "static_ratio_bucket"
	DimChallengePassed = "challenge_passed"
)

var (
	hash16Pattern   = regexp.MustCompile(`^[0-9a-f]{16}$`)
	hash8Pattern    = regexp.MustCompile(`^[0-9a-f]{8}$`)
	countryPattern  = regexp.MustCompile(`^[A-Z]{2}$`)
	methodPattern   = regexp.MustCompile(`^[A-Z]{1,16}$`)
	statusPattern   = regexp.MustCompile(`^[1-5][0-9]{2}$`)
	templatePattern = regexp.MustCompile(`^/[\x21-\x7e]{0,255}$`)
	// ja4Pattern equals edgeconfig.JA4Pattern (a test pins it).
	ja4Pattern = regexp.MustCompile(`^[tqd](?:1[0-3]|s[23]|d[1-3]|00)[di][0-9]{4}[0-9A-Za-z]{2}_[0-9a-f]{12}_[0-9a-f]{12}$`)
)

var bucketValues = map[string][]string{
	DimMissingHeader:   {"accept", "accept_language", "cookie", "referer"},
	DimHTTPVersion:     {"1.0", "1.1", "2", "3"},
	DimIntervalCV:      {"ge0.3", "lt0.1", "mid"}, // < 0.1, 0.1-0.3, >= 0.3
	DimUniquePathRatio: {"ge0.3", "lt0.05", "mid"},
	DimStaticRatio:     {"none", "some"},
	DimChallengePassed: {"0", "1"},
}

// Dimensions lists every signature dimension in name order.
func Dimensions() []string {
	return []string{DimASN, DimBytesBucket, DimChallengePassed, DimCIDR, DimCountry, DimHTTPVersion, DimHeaderOrderHash,
		DimIPTag, DimIntervalCV, DimJA4, DimMethod, DimMissingHeader, DimPathTemplate, DimQueryNamesHash, DimStaticRatio,
		DimStatus, DimUAFamily, DimUAHash, DimUniquePathRatio}
}

// ValidCondition reports whether value is a canonical value of dim.
func ValidCondition(dim, value string) bool {
	switch dim {
	case DimJA4:
		return ja4Pattern.MatchString(value)
	case DimUAHash, DimQueryNamesHash, DimHeaderOrderHash:
		return hash16Pattern.MatchString(value)
	case DimUAFamily, DimIPTag:
		return slugPattern.MatchString(value)
	case DimPathTemplate:
		return templatePattern.MatchString(value)
	case DimMethod:
		return methodPattern.MatchString(value)
	case DimASN:
		number, err := strconv.ParseUint(value, 10, 32)
		return err == nil && number > 0 && strconv.FormatUint(number, 10) == value
	case DimCIDR:
		prefix, ok := CanonicalPrefix(value)
		return ok && prefix == value && (strings.Contains(value, ":") && strings.HasSuffix(value, "/48") ||
			!strings.Contains(value, ":") && strings.HasSuffix(value, "/24"))
	case DimCountry:
		return countryPattern.MatchString(value)
	case DimStatus:
		return statusPattern.MatchString(value)
	case DimBytesBucket: // floor(log2(bytes + 1)), 0-40
		number, err := strconv.ParseUint(value, 10, 8)
		return err == nil && number <= 40 && strconv.FormatUint(number, 10) == value
	}
	values, ok := bucketValues[dim]
	if !ok {
		return false
	}
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

// CanonicalAddress is a client address as snapshots carry it (IPv4 dotted,
// IPv6 compressed lower case, no zone, IPv4-mapped unmapped).
func CanonicalAddress(raw string) (string, bool) {
	address, err := netip.ParseAddr(raw)
	if err != nil || address.Zone() != "" || address.IsUnspecified() {
		return "", false
	}
	return address.Unmap().String(), true
}

// CanonicalPrefix is a network as snapshots carry it (masked, IPv4-mapped
// unmapped).
func CanonicalPrefix(raw string) (string, bool) {
	prefix, err := netip.ParsePrefix(raw)
	if err != nil || prefix.Addr().Zone() != "" {
		return "", false
	}
	if prefix.Addr().Is4In6() {
		bits := prefix.Bits() - 96
		if bits < 0 {
			return "", false
		}
		prefix = netip.PrefixFrom(prefix.Addr().Unmap(), bits)
	}
	return prefix.Masked().String(), true
}

func contains(list []string, value string) bool {
	for _, candidate := range list {
		if candidate == value {
			return true
		}
	}
	return false
}

func itoa(value int64) string { return strconv.FormatInt(value, 10) }
