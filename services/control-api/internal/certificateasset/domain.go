package certificateasset

import (
	"regexp"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

var dnsLabelPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func CoversDomain(sans []string, domain string) bool {
	normalizedDomain, err := normalizeDNSName(domain, false)
	if err != nil {
		return false
	}
	for _, san := range sans {
		normalizedSAN, sanErr := normalizeDNSName(san, true)
		if sanErr != nil {
			continue
		}
		if normalizedSAN == normalizedDomain {
			return true
		}
		if !strings.HasPrefix(normalizedSAN, "*.") {
			continue
		}
		suffix := normalizedSAN[2:]
		if strings.HasSuffix(normalizedDomain, "."+suffix) &&
			strings.Count(normalizedDomain, ".") == strings.Count(suffix, ".")+1 {
			return true
		}
	}
	return false
}

func RequireCoverage(sans []string, domains []string) error {
	if len(domains) == 0 || len(domains) > MaxCertificateSANs {
		return ErrInvalidInput
	}
	for _, domain := range domains {
		normalized, err := normalizeDNSName(domain, true)
		if err != nil {
			return ErrDomainNotCovered
		}
		if strings.HasPrefix(normalized, "*.") {
			matched := false
			for _, san := range sans {
				normalizedSAN, sanErr := normalizeDNSName(san, true)
				if sanErr == nil && normalizedSAN == normalized {
					matched = true
					break
				}
			}
			if !matched {
				return ErrDomainNotCovered
			}
			continue
		}
		if !CoversDomain(sans, domain) {
			return ErrDomainNotCovered
		}
	}
	return nil
}

func normalizeDNSName(value string, allowWildcard bool) (string, error) {
	if !utf8.ValidString(value) || value == "" || strings.TrimSpace(value) != value ||
		strings.HasSuffix(value, ".") || containsControl(value) {
		return "", ErrInvalidSAN
	}
	wildcard := false
	if strings.HasPrefix(value, "*.") {
		if !allowWildcard || strings.Count(value, "*") != 1 {
			return "", ErrInvalidSAN
		}
		wildcard = true
		value = value[2:]
	} else if strings.Contains(value, "*") {
		return "", ErrInvalidSAN
	}
	ascii, err := idna.Lookup.ToASCII(value)
	if err != nil {
		return "", ErrInvalidSAN
	}
	ascii = strings.ToLower(ascii)
	if len(ascii) == 0 || len(ascii) > 253 {
		return "", ErrInvalidSAN
	}
	labels := strings.Split(ascii, ".")
	if len(labels) < 2 {
		return "", ErrInvalidSAN
	}
	for _, label := range labels {
		if !dnsLabelPattern.MatchString(label) {
			return "", ErrInvalidSAN
		}
	}
	if wildcard {
		if _, err := publicsuffix.EffectiveTLDPlusOne(ascii); err != nil {
			return "", ErrInvalidSAN
		}
		return "*." + ascii, nil
	}
	return ascii, nil
}

func containsControl(value string) bool {
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return true
		}
	}
	return false
}

func validOpaqueName(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && strings.TrimSpace(value) == value &&
		utf8.ValidString(value) && !containsControl(value)
}
