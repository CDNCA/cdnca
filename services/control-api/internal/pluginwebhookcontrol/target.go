package pluginwebhookcontrol

import (
	"net"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"
)

var dnsLabelPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
var rawPathCharacterPattern = regexp.MustCompile(`^[A-Za-z0-9._~!$&'()*+,;=:@/-]$`)

type CanonicalTarget struct {
	URL  string
	Host string
	Path string
}

type TargetValidator interface {
	Validate(string) (CanonicalTarget, error)
}

type canonicalTargetValidator struct{}

func NewTargetValidator() TargetValidator { return canonicalTargetValidator{} }

func (canonicalTargetValidator) Validate(raw string) (CanonicalTarget, error) {
	if raw == "" || len(raw) > 2048 || !utf8.ValidString(raw) {
		return CanonicalTarget{}, ErrTargetForbidden
	}
	parsed, err := url.ParseRequestURI(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Opaque != "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Host == "" {
		return CanonicalTarget{}, ErrTargetForbidden
	}
	host := strings.ToLower(parsed.Hostname())
	if parsed.Port() != "" && parsed.Port() != "443" || !validWebhookHost(host) {
		return CanonicalTarget{}, ErrTargetForbidden
	}
	escaped := parsed.EscapedPath()
	if escaped == "" {
		escaped = "/"
	}
	if len(escaped) > 512 || escaped[0] != '/' || strings.Contains(strings.ToLower(escaped), "%2f") ||
		strings.Contains(strings.ToLower(escaped), "%5c") || !canonicalEscapedPath(escaped) {
		return CanonicalTarget{}, ErrTargetForbidden
	}
	return CanonicalTarget{URL: "https://" + host + escaped, Host: host, Path: escaped}, nil
}

func validWebhookHost(host string) bool {
	if len(host) == 0 || len(host) > 253 || host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") ||
		strings.HasSuffix(host, ".internal") || strings.HasPrefix(host, "xn--") ||
		strings.Contains(host, ".xn--") || net.ParseIP(host) != nil {
		return false
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if !dnsLabelPattern.MatchString(label) {
			return false
		}
	}
	return true
}

func canonicalEscapedPath(path string) bool {
	for index := 0; index < len(path); index++ {
		if path[index] == '%' {
			if index+2 >= len(path) || !upperHex(path[index+1]) || !upperHex(path[index+2]) {
				return false
			}
			start := index
			for index < len(path) && path[index] == '%' {
				if index+2 >= len(path) || !upperHex(path[index+1]) || !upperHex(path[index+2]) {
					return false
				}
				index += 3
			}
			decoded, err := url.PathUnescape(path[start:index])
			if err != nil || !utf8.ValidString(decoded) || strings.ContainsAny(decoded, "/\\") {
				return false
			}
			for _, value := range decoded {
				if value <= 159 || value == 160 || value == 5760 || value >= 8192 && value <= 8202 || value == 8232 || value == 8233 || value == 8239 || value == 8287 || value == 12288 {
					return false
				}
			}
			index--
		} else if !rawPathCharacterPattern.MatchString(path[index : index+1]) {
			return false
		}
	}
	decoded, err := url.PathUnescape(path)
	if err != nil || !utf8.ValidString(decoded) || strings.Contains(decoded, "\\") {
		return false
	}
	for _, segment := range strings.Split(decoded, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func upperHex(value byte) bool { return value >= '0' && value <= '9' || value >= 'A' && value <= 'F' }
