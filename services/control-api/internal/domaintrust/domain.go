// Package domaintrust holds the pieces of domain trust (v6.1.0 #11 blocklist,
// #12 ownership) that site writes, the blocklist admin and the ownership
// service share: canonical names, apex (eTLD+1) derivation, blocklist
// matching, the platform ownership policy and write idempotency.
package domaintrust

import (
	"errors"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

var (
	ErrInvalidInput        = errors.New("invalid domain trust input")
	ErrNotFound            = errors.New("domain trust record not found")
	ErrRevisionConflict    = errors.New("domain trust revision conflict")
	ErrIdempotencyConflict = errors.New("domain trust idempotency key reused with different input")
	ErrConflict            = errors.New("domain trust record conflicts with an existing record")
	ErrPermissionDenied    = errors.New("domain trust permission denied")
)

// Policy is the platform ownership verification level (system settings).
type Policy string

const (
	PolicyOff          Policy = "off"
	PolicyWildcardOnly Policy = "wildcard_only"
	PolicyAll          Policy = "all"
	DefaultPolicy             = PolicyWildcardOnly
)

func ValidPolicy(value string) bool {
	switch Policy(value) {
	case PolicyOff, PolicyWildcardOnly, PolicyAll:
		return true
	}
	return false
}

// Normalize returns the canonical ASCII lower-case form of a site domain.
// wildcard allows a single leading "*." label.
func Normalize(raw string, wildcard bool) (string, error) {
	domain := strings.TrimSuffix(strings.TrimSpace(raw), ".")
	prefix := ""
	if strings.HasPrefix(domain, "*.") {
		if !wildcard {
			return "", ErrInvalidInput
		}
		prefix, domain = "*.", domain[2:]
	}
	if domain == "" {
		return "", ErrInvalidInput
	}
	base, err := idna.Lookup.ToASCII(domain)
	if err != nil {
		return "", ErrInvalidInput
	}
	base = strings.ToLower(base)
	if len(prefix+base) > 253 {
		return "", ErrInvalidInput
	}
	labels := strings.Split(base, ".")
	if len(labels) < 2 {
		return "", ErrInvalidInput
	}
	for _, label := range labels {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", ErrInvalidInput
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return "", ErrInvalidInput
			}
		}
	}
	return prefix + base, nil
}

// Apex is the registrable domain (eTLD+1 by the public suffix list) a
// canonical domain or wildcard belongs to; ownership is proven per apex.
func Apex(canonical string) (string, error) {
	base := strings.TrimPrefix(canonical, "*.")
	apex, err := publicsuffix.EffectiveTLDPlusOne(base)
	if err != nil || apex == "" {
		return "", ErrInvalidInput
	}
	return apex, nil
}

// Family is the name a wildcard must be rooted at to cover the domain
// (www.a.com -> a.com, *.a.com -> a.com); it matches site_domain_family_299.
func Family(canonical string) string {
	if strings.HasPrefix(canonical, "*.") {
		return canonical[2:]
	}
	if index := strings.IndexByte(canonical, '.'); index >= 0 {
		return canonical[index+1:]
	}
	return ""
}

// IsWildcard reports whether a canonical domain is a "*." wildcard.
func IsWildcard(canonical string) bool { return strings.HasPrefix(canonical, "*.") }

// suffixes lists the name and every parent with at least two labels:
// a.b.example.com -> a.b.example.com, b.example.com, example.com.
func suffixes(base string) []string {
	result := []string{base}
	for {
		index := strings.IndexByte(base, '.')
		if index < 0 {
			break
		}
		base = base[index+1:]
		if !strings.Contains(base, ".") {
			break
		}
		result = append(result, base)
	}
	return result
}
