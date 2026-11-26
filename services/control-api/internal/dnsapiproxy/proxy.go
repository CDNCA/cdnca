// Package dnsapiproxy is the platform 「http代理」 (系统设置 › 其它配置 › 访问与网络):
// when set, the control plane's requests to DNS provider APIs (record
// management, ACME DNS-01, credential checks) go through this HTTP(S) proxy;
// when empty they go direct. Environment proxies (HTTPS_PROXY, ...) are never
// used for these requests. TLS verification of the provider is unchanged.
package dnsapiproxy

import (
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// MaxLength bounds the stored setting.
const MaxLength = 2048

// RedactedPassword replaces the proxy password in every read of the setting;
// a save that sends it back keeps the stored password (Restore).
const RedactedPassword = "********"

var hostLabel = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

// Parse is the proxy URL of a valid non-empty setting:
// http(s)://[user[:password]@]host[:port][/], host a DNS name or IP literal.
func Parse(raw string) (*url.URL, bool) {
	if raw == "" || len(raw) > MaxLength || !utf8.ValidString(raw) ||
		strings.IndexFunc(raw, func(r rune) bool { return r <= ' ' || r == 0x7f }) >= 0 {
		return nil, false
	}
	lower := strings.ToLower(raw)
	if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
		return nil, false
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "http" && parsed.Scheme != "https" || parsed.Opaque != "" ||
		parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" ||
		parsed.Path != "" && parsed.Path != "/" || strings.HasSuffix(parsed.Host, ":") ||
		parsed.User != nil && parsed.User.Username() == "" ||
		!validHost(parsed.Hostname()) || !validPort(parsed.Port()) {
		return nil, false
	}
	return parsed, true
}

// Valid reports whether raw may be saved ("" is direct).
func Valid(raw string) bool {
	_, ok := Parse(raw)
	return raw == "" || ok
}

func validHost(host string) bool {
	if address, err := netip.ParseAddr(host); err == nil {
		return address.Zone() == ""
	}
	if host == "" || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if !hostLabel.MatchString(label) {
			return false
		}
	}
	return true
}

func validPort(port string) bool {
	if port == "" {
		return true
	}
	value, err := strconv.Atoi(port)
	return err == nil && value >= 1 && value <= 65535
}

// Redact is raw with its password replaced by RedactedPassword; raw itself
// when it has no password.
func Redact(raw string) string {
	parsed, ok := Parse(raw)
	if !ok || parsed.User == nil {
		return raw
	}
	if _, has := parsed.User.Password(); !has {
		return raw
	}
	// Built by hand: url.URL.String would escape the mask to %2A.
	return parsed.Scheme + "://" + url.User(parsed.User.Username()).String() + ":" + RedactedPassword + "@" +
		parsed.Host + parsed.EscapedPath()
}

// Restore puts the stored password back into a saved value that carries
// RedactedPassword (the form sends back what it read). ok is false when the
// value carries RedactedPassword but stored is not the same proxy and user:
// the password has to be typed again.
func Restore(incoming, stored string) (string, bool) {
	parsed, valid := Parse(incoming)
	if !valid || parsed.User == nil {
		return incoming, true
	}
	if password, has := parsed.User.Password(); !has || password != RedactedPassword {
		return incoming, true
	}
	previous, valid := Parse(stored)
	if !valid || previous.User == nil || previous.Scheme != parsed.Scheme ||
		!strings.EqualFold(previous.Host, parsed.Host) || previous.User.Username() != parsed.User.Username() {
		return incoming, false
	}
	password, has := previous.User.Password()
	if !has {
		return incoming, false
	}
	parsed.User = url.UserPassword(parsed.User.Username(), password)
	return parsed.String(), true
}
