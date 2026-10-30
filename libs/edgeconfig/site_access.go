package edgeconfig

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// SiteAccess is a site's request handling settings in a site runtime v2
// document (site.access): host redirects, HSTS, compression,
// per-client connection and per-request rate limits, basic authentication
// and a maintenance page. Absent fields are off; the node renders each in the
// site's own server{} or location / (nginx inherits nothing between sites).
type SiteAccess struct {
	HostRedirects []HostRedirect       `json:"host_redirects,omitempty"`
	HSTS          *SiteHSTS            `json:"hsts,omitempty"`
	Compression   *SiteCompression     `json:"compression,omitempty"`
	Limits        *SiteRequestLimits   `json:"limits,omitempty"`
	BasicAuth     *SiteBasicAuth       `json:"basic_auth,omitempty"`
	Maintenance   *SiteMaintenancePage `json:"maintenance,omitempty"`
	WebP          *SiteWebP            `json:"webp,omitempty"`
	// ResponseRules: response phase rules on status and headers
	// (EDGE_RESPONSE_RULES; site_response_rules.go).
	ResponseRules []SiteResponseRule `json:"response_rules,omitempty"`
}

// HostRedirect sends every request for one of the site's domains to another
// host (domain-level 301/302/307/308), keeping the request URI and query
// unless PreserveURI is false (then the target's root). TargetScheme
// "follow" keeps the request's scheme. ACME HTTP-01 challenges are not
// redirected, as forced HTTPS does not redirect them.
type HostRedirect struct {
	SourceHost   string `json:"source_host"`
	TargetHost   string `json:"target_host"`
	TargetScheme string `json:"target_scheme"`
	TargetPort   int    `json:"target_port,omitempty"`
	Status       int    `json:"status"`
	PreserveURI  bool   `json:"preserve_uri"`
}

// SiteHSTS adds Strict-Transport-Security to the site's HTTPS responses
// (never to plain HTTP, RFC 6797 §7.2). Preload needs a max-age of at least
// one year and includeSubDomains (the hstspreload.org submission rules).
type SiteHSTS struct {
	MaxAgeSeconds     int64 `json:"max_age_seconds"`
	IncludeSubdomains bool  `json:"include_subdomains"`
	Preload           bool  `json:"preload"`
}

// SiteCompression is the site's response compression: off (Enabled false),
// or on for the listed MIME types from MinLengthBytes with the listed
// encodings (Encodings: "br" and/or "gzip", sorted; absent = gzip only). A
// client that accepts both gets Brotli. GzipLevel (1-9) and BrotliLevel
// (0-11) are the compression levels, 0 = the node default (the system gzip
// level, Brotli 6). Without it the platform default (the system nginx gzip,
// text/html only) applies. Brotli or a level of its own needs EDGE_BROTLI.
type SiteCompression struct {
	Enabled        bool     `json:"enabled"`
	Types          []string `json:"types"`
	MinLengthBytes int64    `json:"min_length_bytes"`
	Encodings      []string `json:"encodings,omitempty"`
	GzipLevel      int      `json:"gzip_level,omitempty"`
	BrotliLevel    int      `json:"brotli_level,omitempty"`
}

// SiteCompressionBrotli is the "br" encoding of SiteCompression.Encodings.
const (
	SiteCompressionBrotli = "br"
	SiteCompressionGzip   = "gzip"
)

// NeedsEdgeBrotli reports compression settings only an EDGE_BROTLI node
// executes: Brotli, or a gzip/Brotli level of the site's own.
func (compression *SiteCompression) NeedsEdgeBrotli() bool {
	return compression != nil && compression.Enabled &&
		(slices.Contains(compression.Encodings, SiteCompressionBrotli) || compression.GzipLevel != 0 || compression.BrotliLevel != 0)
}

// SiteWebP converts the site's JPEG and PNG responses to WebP for clients
// whose Accept lists image/webp (EDGE_WEBP). The node converts an image the
// first time it passes (the client still gets the original) and serves the
// WebP from then on, for images up to MaxBytes and MaxPixels; anything it
// cannot convert, or that would not get smaller, stays the original.
// Quality is the WebP quality (1-100, 0 = 80).
type SiteWebP struct {
	Enabled bool `json:"enabled"`
	Quality int  `json:"quality,omitempty"`
}

// SiteRequestLimits are the HTTP-layer per-client limits (the kernel-level
// connection limits are ge-ddos's): concurrent requests per client address
// (limit_conn, HTTP/2 streams count) and the response rate per request
// (limit_rate), optionally after a burst. 0 is unlimited.
type SiteRequestLimits struct {
	ConnectionsPerIP   int   `json:"connections_per_ip,omitempty"`
	RateBytesPerSecond int64 `json:"rate_bytes_per_second,omitempty"`
	RateAfterBytes     int64 `json:"rate_after_bytes,omitempty"`
}

// SiteBasicAuth requires HTTP basic authentication. Each user carries a
// random 16 byte salt and SHA-256(salt || password) in hex, independent of
// the site (a market leaf takes them as they are; control
// never stores or publishes a password); the node computes one sha256 per
// request in Lua.
type SiteBasicAuth struct {
	Realm string          `json:"realm"`
	Users []BasicAuthUser `json:"users"`
	// ExcludePathPrefixes are not authenticated (health checks, webhooks).
	ExcludePathPrefixes []string `json:"exclude_path_prefixes,omitempty"`
}

type BasicAuthUser struct {
	Username string `json:"username"`
	// Salt is 16 random bytes, lower-case hex.
	Salt string `json:"salt"`
	// SHA256 is SHA-256(salt bytes || password), lower-case hex.
	SHA256 string `json:"sha256"`
}

// SiteMaintenancePage answers every request (except ACME HTTP-01 and the
// allowed client networks) with Status and a fixed body, without contacting
// the origin.
type SiteMaintenancePage struct {
	Status       int      `json:"status"`
	ContentType  string   `json:"content_type"`
	Body         string   `json:"body"`
	RetryAfter   int      `json:"retry_after_seconds,omitempty"`
	AllowedCIDRs []string `json:"allowed_cidrs,omitempty"`
}

const (
	MaxSiteHostRedirects       = 100
	MaxSiteCompressionTypes    = 64
	MaxSiteBasicAuthUsers      = 64
	MaxSiteBasicAuthExclusions = 32
	MaxSiteMaintenanceBody     = 64 << 10
	MaxSiteMaintenanceCIDRs    = 64
	MaxSiteHSTSMaxAge          = int64(2 * 365 * 24 * 3600)
	MinSiteHSTSPreloadMaxAge   = int64(365 * 24 * 3600)
	MaxSiteRateBytesPerSecond  = int64(10 << 30)
	MaxSiteConnectionsPerIP    = 65535
)

var (
	siteAccessMIMEPattern     = regexp.MustCompile(`^[!#$%&'*+.^_` + "`" + `|~0-9a-z-]+/[!#$%&'*+.^_` + "`" + `|~0-9a-z-]+$`)
	siteAccessUsernamePattern = regexp.MustCompile(`^[A-Za-z0-9._@+-]{1,64}$`)
	siteAccessRealmPattern    = regexp.MustCompile(`^[A-Za-z0-9 ._@+-]{1,64}$`)
	siteAccessSHA256Pattern   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	siteAccessSaltPattern     = regexp.MustCompile(`^[0-9a-f]{32}$`)
	siteAccessPathPattern     = regexp.MustCompile(`^/[A-Za-z0-9._~!$&'()*+,;=:@/-]{0,255}$`)
	siteAccessContentTypes    = []string{"text/html", "text/plain", "application/json"}
)

// NewBasicAuthUser hashes password with a fresh random 16 byte salt.
func NewBasicAuthUser(username, password string) (BasicAuthUser, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return BasicAuthUser{}, err
	}
	return BasicAuthUserWithSalt(username, hex.EncodeToString(salt), password), nil
}

// BasicAuthUserWithSalt hashes password with the given hex salt (tests and
// fixtures; writes use NewBasicAuthUser).
func BasicAuthUserWithSalt(username, saltHex, password string) BasicAuthUser {
	salt, _ := hex.DecodeString(saltHex)
	digest := sha256.Sum256(append(salt, []byte(password)...))
	return BasicAuthUser{Username: username, Salt: saltHex, SHA256: hex.EncodeToString(digest[:])}
}

// Verify reports whether password matches, in constant time.
func (user BasicAuthUser) Verify(password string) bool {
	want := BasicAuthUserWithSalt(user.Username, user.Salt, password)
	return subtle.ConstantTimeCompare([]byte(want.SHA256), []byte(user.SHA256)) == 1
}

// Empty reports an access object with nothing in it (control omits it).
func (access SiteAccess) Empty() bool {
	return len(access.HostRedirects) == 0 && access.HSTS == nil && access.Compression == nil &&
		access.Limits == nil && access.BasicAuth == nil && access.Maintenance == nil && access.WebP == nil &&
		len(access.ResponseRules) == 0
}

// ValidateSiteAccess checks a site's access settings against its domains
// and whether it has an HTTPS listener (HSTS needs one). Values must
// already be canonical: lists sorted, hosts lower case.
func ValidateSiteAccess(access SiteAccess, domains []string, hasTLS bool) error {
	if access.Empty() {
		return ErrInvalidConfig
	}
	if len(access.HostRedirects) > MaxSiteHostRedirects {
		return ErrInvalidConfig
	}
	for index, redirect := range access.HostRedirects {
		if index > 0 && access.HostRedirects[index-1].SourceHost >= redirect.SourceHost ||
			!slices.Contains(domains, redirect.SourceHost) || strings.HasPrefix(redirect.SourceHost, "*.") {
			return ErrInvalidConfig
		}
		target, err := normalizeDNSName(redirect.TargetHost, true)
		if err != nil || target != redirect.TargetHost || target == redirect.SourceHost && redirect.TargetPort == 0 ||
			redirect.TargetScheme != "http" && redirect.TargetScheme != "https" && redirect.TargetScheme != "follow" ||
			redirect.TargetPort < 0 || redirect.TargetPort > 65535 ||
			redirect.Status != 301 && redirect.Status != 302 && redirect.Status != 307 && redirect.Status != 308 {
			return ErrInvalidConfig
		}
	}
	if hsts := access.HSTS; hsts != nil {
		if !hasTLS || hsts.MaxAgeSeconds < 0 || hsts.MaxAgeSeconds > MaxSiteHSTSMaxAge ||
			hsts.Preload && (!hsts.IncludeSubdomains || hsts.MaxAgeSeconds < MinSiteHSTSPreloadMaxAge) {
			return ErrInvalidConfig
		}
	}
	if compression := access.Compression; compression != nil {
		if compression.Types == nil || len(compression.Types) > MaxSiteCompressionTypes ||
			compression.MinLengthBytes < 0 || compression.MinLengthBytes > 1<<30 ||
			compression.Enabled && len(compression.Types) == 0 || !compression.Enabled && len(compression.Types) != 0 ||
			compression.GzipLevel < 0 || compression.GzipLevel > 9 || compression.BrotliLevel < 0 || compression.BrotliLevel > 11 ||
			!compression.Enabled && (compression.Encodings != nil || compression.GzipLevel != 0 || compression.BrotliLevel != 0) {
			return ErrInvalidConfig
		}
		if compression.Encodings != nil {
			if !slices.Equal(compression.Encodings, []string{SiteCompressionBrotli}) && !slices.Equal(compression.Encodings, []string{SiteCompressionGzip}) &&
				!slices.Equal(compression.Encodings, []string{SiteCompressionBrotli, SiteCompressionGzip}) ||
				compression.GzipLevel != 0 && !slices.Contains(compression.Encodings, SiteCompressionGzip) ||
				compression.BrotliLevel != 0 && !slices.Contains(compression.Encodings, SiteCompressionBrotli) {
				return ErrInvalidConfig
			}
		} else if compression.BrotliLevel != 0 {
			return ErrInvalidConfig
		}
		for index, value := range compression.Types {
			if len(value) > 128 || !siteAccessMIMEPattern.MatchString(value) || index > 0 && compression.Types[index-1] >= value {
				return ErrInvalidConfig
			}
		}
	}
	if webp := access.WebP; webp != nil && (!webp.Enabled || webp.Quality < 0 || webp.Quality > 100) {
		// off is the field's absence
		return ErrInvalidConfig
	}
	if access.ResponseRules != nil && (len(access.ResponseRules) == 0 || validateSiteResponseRules(access.ResponseRules) != nil) {
		return ErrInvalidConfig
	}
	if limits := access.Limits; limits != nil {
		if limits.ConnectionsPerIP < 0 || limits.ConnectionsPerIP > MaxSiteConnectionsPerIP ||
			limits.RateBytesPerSecond < 0 || limits.RateBytesPerSecond > MaxSiteRateBytesPerSecond ||
			limits.RateAfterBytes < 0 || limits.RateAfterBytes > 1<<40 ||
			limits.RateAfterBytes != 0 && limits.RateBytesPerSecond == 0 ||
			limits.ConnectionsPerIP == 0 && limits.RateBytesPerSecond == 0 {
			return ErrInvalidConfig
		}
	}
	if auth := access.BasicAuth; auth != nil {
		if !siteAccessRealmPattern.MatchString(auth.Realm) || len(auth.Users) == 0 || len(auth.Users) > MaxSiteBasicAuthUsers ||
			len(auth.ExcludePathPrefixes) > MaxSiteBasicAuthExclusions {
			return ErrInvalidConfig
		}
		for index, user := range auth.Users {
			if !siteAccessUsernamePattern.MatchString(user.Username) || !siteAccessSaltPattern.MatchString(user.Salt) ||
				!siteAccessSHA256Pattern.MatchString(user.SHA256) ||
				index > 0 && auth.Users[index-1].Username >= user.Username {
				return ErrInvalidConfig
			}
		}
		for index, prefix := range auth.ExcludePathPrefixes {
			if !siteAccessPathPattern.MatchString(prefix) || strings.Contains(prefix, "//") || strings.Contains(prefix, "/..") ||
				strings.Contains(prefix, "/./") || index > 0 && auth.ExcludePathPrefixes[index-1] >= prefix {
				return ErrInvalidConfig
			}
		}
	}
	if page := access.Maintenance; page != nil {
		if page.Status < 200 || page.Status > 599 || page.Status >= 300 && page.Status < 400 ||
			!slices.Contains(siteAccessContentTypes, page.ContentType) ||
			len(page.Body) > MaxSiteMaintenanceBody || !ascii(page.Body) && !validUTF8NoControl(page.Body) ||
			page.RetryAfter < 0 || page.RetryAfter > 86400*7 || len(page.AllowedCIDRs) > MaxSiteMaintenanceCIDRs {
			return ErrInvalidConfig
		}
		for index, cidr := range page.AllowedCIDRs {
			if prefix, err := normalizeCIDR(cidr); err != nil || prefix.String() != cidr ||
				index > 0 && page.AllowedCIDRs[index-1] >= cidr {
				return ErrInvalidConfig
			}
		}
	}
	return nil
}

// SiteAccessHTTP is the http{} level a scope's site access needs: one shared
// per-client connection zone (keyed by site and client address, so sites do
// not share counts).
func SiteAccessHTTP(anyConnectionLimit bool) string {
	if !anyConnectionLimit {
		return ""
	}
	return "  limit_conn_zone $cdnca_site_access_key zone=cdnca_site_conn_ip:10m;\n"
}

// SiteAccessServer is the server{} level of a site listener: the
// connection-limit key and limits, HSTS (TLS listeners only), compression
// and the host redirects (ACME HTTP-01 excepted).
func SiteAccessServer(siteID string, access *SiteAccess, tls bool) string {
	if access == nil {
		return ""
	}
	var output strings.Builder
	if limits := access.Limits; limits != nil && limits.ConnectionsPerIP > 0 {
		fmt.Fprintf(&output, "    set $cdnca_site_access_key \"%s$binary_remote_addr\";\n", siteID)
		fmt.Fprintf(&output, "    limit_conn cdnca_site_conn_ip %d;\n    limit_conn_status 429;\n    limit_conn_log_level warn;\n",
			limits.ConnectionsPerIP)
	}
	if limits := access.Limits; limits != nil && limits.RateBytesPerSecond > 0 {
		fmt.Fprintf(&output, "    limit_rate %d;\n", limits.RateBytesPerSecond)
		if limits.RateAfterBytes > 0 {
			fmt.Fprintf(&output, "    limit_rate_after %d;\n", limits.RateAfterBytes)
		}
	}
	if hsts := access.HSTS; hsts != nil && tls {
		value := "max-age=" + strconv.FormatInt(hsts.MaxAgeSeconds, 10)
		if hsts.IncludeSubdomains {
			value += "; includeSubDomains"
		}
		if hsts.Preload {
			value += "; preload"
		}
		// more_set_headers also covers error responses and replaces an
		// origin's own header instead of sending two.
		fmt.Fprintf(&output, "    more_set_headers \"Strict-Transport-Security: %s\";\n", value)
	}
	if compression := access.Compression; compression != nil {
		if !compression.Enabled {
			output.WriteString("    gzip off;\n")
		} else {
			types := gzipTypesWithoutHTML(compression.Types)
			output.WriteString("    gzip on;\n    gzip_proxied any;\n")
			if len(types) != 0 {
				fmt.Fprintf(&output, "    gzip_types %s;\n", strings.Join(types, " "))
			}
			fmt.Fprintf(&output, "    gzip_min_length %d;\n", compression.MinLengthBytes)
		}
	}
	for _, redirect := range access.HostRedirects {
		scheme := redirect.TargetScheme
		if scheme == "follow" {
			scheme = "$scheme"
		}
		target := scheme + "://" + redirect.TargetHost
		if redirect.TargetPort != 0 {
			target += ":" + strconv.Itoa(redirect.TargetPort)
		}
		if redirect.PreserveURI {
			target += "$request_uri"
		} else {
			target += "/"
		}
		// $host is lower case without the port (nginx normalizes it).
		fmt.Fprintf(&output, "    set $cdnca_host_redirect \"\";\n")
		fmt.Fprintf(&output, "    if ($host = %q) { set $cdnca_host_redirect \"%d\"; }\n", redirect.SourceHost, redirect.Status)
		fmt.Fprintf(&output, "    if ($uri ~ \"^/\\.well-known/acme-challenge/\") { set $cdnca_host_redirect \"\"; }\n")
		fmt.Fprintf(&output, "    if ($cdnca_host_redirect = \"%d\") { return %d %s; }\n", redirect.Status, redirect.Status, target)
	}
	return output.String()
}

func validUTF8NoControl(value string) bool {
	for _, character := range value {
		if character == 0xfffd || character < 0x20 && character != '\n' && character != '\r' && character != '\t' || character == 0x7f {
			return false
		}
	}
	return true
}

// gzipTypesWithoutHTML drops text/html: nginx always compresses it and
// rejects it in gzip_types as a duplicate.
func gzipTypesWithoutHTML(values []string) []string {
	types := make([]string, 0, len(values))
	for _, value := range values {
		if value != "text/html" {
			types = append(types, value)
		}
	}
	return types
}
