package originroute

import (
	"fmt"
	"net/netip"
	"strings"
)

func normalizeDNSPolicy(value *DNSPolicy, pools []Pool) (*DNSPolicy, error) {
	hasHostname := false
	for _, pool := range pools {
		for _, endpoint := range pool.Endpoints {
			if _, err := netip.ParseAddr(endpoint.Host); err != nil {
				hasHostname = true
			}
		}
	}
	if value == nil {
		if !hasHostname {
			return nil, nil
		}
		return &DNSPolicy{
			QueryTimeoutMS:  DefaultDNSQueryTimeoutMS,
			MinTTLSeconds:   DefaultDNSMinTTLSeconds,
			MaxTTLSeconds:   DefaultDNSMaxTTLSeconds,
			StaleTTLSeconds: DefaultDNSStaleTTLSeconds,
		}, nil
	}

	result := *value
	if result.Resolver != "" {
		resolver, err := parseSafeAddress(result.Resolver, false)
		if err != nil {
			return nil, invalid("DNS resolver must be an unzoned unicast IP literal")
		}
		result.Resolver = resolver.String()
	}
	if result.QueryTimeoutMS < 100 || result.QueryTimeoutMS > 5000 ||
		result.MinTTLSeconds < 1 || result.MinTTLSeconds > 300 ||
		result.MaxTTLSeconds < result.MinTTLSeconds || result.MaxTTLSeconds > 86400 ||
		result.StaleTTLSeconds < 1 || result.StaleTTLSeconds > 86400 {
		return nil, invalid("DNS query timeout or TTL bounds are invalid")
	}
	return &result, nil
}

func normalizeDNSHostname(value string) (string, error) {
	if value == "" || strings.TrimSpace(value) != value {
		return "", fmt.Errorf("endpoint DNS hostname is empty or padded")
	}
	value = strings.ToLower(strings.TrimSuffix(value, "."))
	if len(value) < 1 || len(value) > 253 || value == "localhost" ||
		strings.HasSuffix(value, ".in-addr.arpa") || strings.HasSuffix(value, ".ip6.arpa") {
		return "", fmt.Errorf("endpoint DNS hostname is local, reverse, or too long")
	}
	labels := strings.Split(value, ".")
	if len(labels) < 2 {
		return "", fmt.Errorf("endpoint DNS hostname must be fully qualified")
	}
	for _, label := range labels {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("endpoint DNS hostname label is invalid")
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return "", fmt.Errorf("endpoint DNS hostname must use ASCII letters, digits, and hyphens")
			}
		}
	}
	if _, err := netip.ParseAddr(value); err == nil {
		return "", fmt.Errorf("endpoint DNS hostname is an ambiguous IP literal")
	}
	last := labels[len(labels)-1]
	if strings.IndexFunc(last, func(character rune) bool { return character >= 'a' && character <= 'z' }) < 0 {
		return "", fmt.Errorf("endpoint DNS hostname final label must contain a letter")
	}
	return value, nil
}
