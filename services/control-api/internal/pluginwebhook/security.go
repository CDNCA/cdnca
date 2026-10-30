package pluginwebhook

import (
	"context"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

const maxDNSAnswers = 16

type Resolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

type resolvedTarget struct {
	URL       *url.URL
	Hostname  string
	Port      string
	Addresses []netip.Addr
}

var forbiddenPrefixes = mustPrefixes(
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.31.196.0/24", "192.52.193.0/24",
	"192.88.99.0/24", "192.168.0.0/16", "192.175.48.0/24",
	"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
	"::/96", "::ffff:0:0/96", "::ffff:0:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48",
	"100::/64", "100:0:0:1::/64", "2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20",
	"5f00::/16", "fc00::/7", "fe80::/10", "ff00::/8",
)

func resolveTarget(ctx context.Context, rawURL string, resolver Resolver) (resolvedTarget, error) {
	if ctx == nil || resolver == nil {
		return resolvedTarget{}, ErrInvalidConfig
	}
	parsed, err := parseTargetURL(rawURL)
	if err != nil {
		return resolvedTarget{}, err
	}
	hostname := parsed.Hostname()
	port := parsed.Port()
	if port == "" {
		port = "443"
	}
	addresses, err := resolver.LookupNetIP(ctx, "ip", hostname)
	if err != nil || len(addresses) == 0 || len(addresses) > maxDNSAnswers {
		return resolvedTarget{}, ErrTargetResolution
	}
	unique := make([]netip.Addr, 0, len(addresses))
	seen := make(map[netip.Addr]struct{}, len(addresses))
	for _, address := range addresses {
		if !publicAddress(address) {
			return resolvedTarget{}, ErrTargetForbidden
		}
		if _, exists := seen[address]; !exists {
			seen[address] = struct{}{}
			unique = append(unique, address)
		}
	}
	return resolvedTarget{URL: parsed, Hostname: hostname, Port: port, Addresses: unique}, nil
}

func parseTargetURL(rawURL string) (*url.URL, error) {
	if len(rawURL) == 0 || len(rawURL) > 2048 {
		return nil, ErrTargetForbidden
	}
	for index := 0; index < len(rawURL); index++ {
		if rawURL[index] < 0x20 || rawURL[index] == 0x7f || rawURL[index] == '\\' {
			return nil, ErrTargetForbidden
		}
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" || parsed.ForceQuery {
		return nil, ErrTargetForbidden
	}
	hostname := parsed.Hostname()
	if hostname == "" || hostname != strings.ToLower(hostname) || hostname == "localhost" || strings.HasSuffix(hostname, ".localhost") ||
		strings.HasSuffix(hostname, ".local") || strings.HasSuffix(hostname, ".internal") || !validASCIIHostname(hostname) {
		return nil, ErrTargetForbidden
	}
	if parsed.Port() != "" {
		port, portErr := strconv.Atoi(parsed.Port())
		if portErr != nil || port != 443 {
			return nil, ErrTargetForbidden
		}
	}
	if parsed.Path == "" {
		return nil, ErrTargetForbidden
	}
	escapedPath := parsed.EscapedPath()
	if len(escapedPath) < 1 || len(escapedPath) > 512 ||
		strings.Contains(strings.ToLower(escapedPath), "%2f") || strings.Contains(strings.ToLower(escapedPath), "%5c") {
		return nil, ErrTargetForbidden
	}
	for index := 0; index < len(parsed.Path); index++ {
		if parsed.Path[index] < 0x20 || parsed.Path[index] == 0x7f || parsed.Path[index] == '\\' {
			return nil, ErrTargetForbidden
		}
	}
	for _, segment := range strings.Split(parsed.Path, "/") {
		if segment == "." || segment == ".." {
			return nil, ErrTargetForbidden
		}
	}
	canonicalEscapedPath := (&url.URL{Path: parsed.Path}).EscapedPath()
	if escapedPath != canonicalEscapedPath {
		return nil, ErrTargetForbidden
	}
	canonical := *parsed
	canonical.Host = hostname
	canonical.RawPath = ""
	canonicalInput := rawURL
	defaultPortPrefix := "https://" + hostname + ":443"
	if strings.HasPrefix(canonicalInput, defaultPortPrefix) {
		canonicalInput = "https://" + hostname + canonicalInput[len(defaultPortPrefix):]
	}
	if canonical.String() != canonicalInput {
		return nil, ErrTargetForbidden
	}
	parsed.Host = hostname
	parsed.RawPath = ""
	return parsed, nil
}

func publicAddress(address netip.Addr) bool {
	if !address.IsValid() || !address.IsGlobalUnicast() {
		return false
	}
	for _, prefix := range forbiddenPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

func validASCIIHostname(hostname string) bool {
	if len(hostname) > 253 {
		return false
	}
	if _, err := netip.ParseAddr(hostname); err == nil {
		return false
	}
	labels := strings.Split(hostname, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' || strings.HasPrefix(label, "xn--") {
			return false
		}
		for _, character := range label {
			if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func mustPrefixes(values ...string) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			panic(fmt.Sprintf("invalid built-in prefix %q", value))
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes
}
