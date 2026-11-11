// Package contentrewrite is a site's 内容改写: the settings
// the control plane stores (Settings, Normalize), the form the node runs
// (Node, Compile) and the streaming engine (Stream) the console's tester
// runs on the control plane. edge/openresty/dynroute/cdnca_rewrite.lua is
// the same algorithm in Lua: any change here is made there too.
package contentrewrite

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	KindLink    = "link"
	KindReplace = "replace"
	KindHTTPS   = "https"

	SchemeKeep  = "keep"
	SchemeHTTPS = "https"
	SchemeHTTP  = "http"

	TypeHTML = "text/html"
	TypeCSS  = "text/css"
	TypeJS   = "application/javascript"

	MaxRules      = 50
	MaxPaths      = 10
	MaxPathBytes  = 256
	MaxFromHosts  = 20
	MaxHTTPSHosts = 50
	MaxFindBytes  = 256
	MaxReplace    = 1024
	MaxNameRunes  = 64

	DefaultMaxBytes int64 = 2 << 20
	MinMaxBytes     int64 = 64 << 10
	MaxMaxBytes     int64 = 16 << 20
)

// ErrInvalid: the settings are refused; the error is a *FieldError.
var ErrInvalid = errors.New("invalid content rewrite settings")

// FieldError names the refused field (e.g. "rules[2].find") and why.
type FieldError struct {
	Field  string
	Reason string
}

func (e *FieldError) Error() string { return fmt.Sprintf("%s: %s", e.Field, e.Reason) }
func (e *FieldError) Unwrap() error { return ErrInvalid }

// Settings is what a site stores (sites.content_rewrite, migration 655).
type Settings struct {
	MaxBytes int64  `json:"max_bytes"`
	Rules    []Rule `json:"rules"`
}

// Rule is one rule; the fields of the other kinds stay empty.
type Rule struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Enabled      bool     `json:"enabled"`
	Kind         string   `json:"kind"`
	Paths        []string `json:"paths"`
	ContentTypes []string `json:"content_types"`
	// link
	FromHosts []string `json:"from_hosts,omitempty"`
	ToHost    string   `json:"to_host,omitempty"`
	Scheme    string   `json:"scheme,omitempty"`
	// replace
	Find       string `json:"find,omitempty"`
	Replace    string `json:"replace,omitempty"`
	Regex      bool   `json:"regex,omitempty"`
	IgnoreCase bool   `json:"ignore_case,omitempty"`
	// https
	IncludeSiteDomains bool     `json:"include_site_domains,omitempty"`
	Hosts              []string `json:"hosts,omitempty"`
}

var (
	idPattern   = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)
	hostPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)
	typeOrder   = []string{TypeHTML, TypeCSS, TypeJS}
)

// Empty: no rule at all (stored as NULL).
func (s Settings) Empty() bool { return len(s.Rules) == 0 }

// Normalize validates and canonicalizes settings (host names lower-cased,
// lists deduplicated, content types in a fixed order, defaults filled).
func Normalize(settings Settings) (Settings, error) {
	out := Settings{MaxBytes: settings.MaxBytes, Rules: []Rule{}}
	if out.MaxBytes == 0 {
		out.MaxBytes = DefaultMaxBytes
	}
	if out.MaxBytes < MinMaxBytes || out.MaxBytes > MaxMaxBytes {
		return Settings{}, &FieldError{"max_bytes", "must be between 64 KiB and 16 MiB"}
	}
	if len(settings.Rules) > MaxRules {
		return Settings{}, &FieldError{"rules", "at most 50 rules"}
	}
	seen := map[string]bool{}
	for index, rule := range settings.Rules {
		normalized, err := normalizeRule(rule)
		if err != nil {
			var field *FieldError
			if errors.As(err, &field) {
				field.Field = fmt.Sprintf("rules[%d].%s", index, field.Field)
			}
			return Settings{}, err
		}
		if seen[normalized.ID] {
			return Settings{}, &FieldError{fmt.Sprintf("rules[%d].id", index), "duplicate id"}
		}
		seen[normalized.ID] = true
		out.Rules = append(out.Rules, normalized)
	}
	return out, nil
}

func normalizeRule(rule Rule) (Rule, error) {
	out := Rule{ID: rule.ID, Name: strings.TrimSpace(rule.Name), Enabled: rule.Enabled, Kind: rule.Kind}
	if !idPattern.MatchString(out.ID) {
		return Rule{}, &FieldError{"id", "must be 1-32 of a-z, 0-9 and -"}
	}
	if !utf8.ValidString(out.Name) || utf8.RuneCountInString(out.Name) > MaxNameRunes {
		return Rule{}, &FieldError{"name", "at most 64 characters"}
	}
	paths, err := normalizePaths(rule.Paths)
	if err != nil {
		return Rule{}, err
	}
	out.Paths = paths
	types, err := normalizeTypes(rule.ContentTypes)
	if err != nil {
		return Rule{}, err
	}
	out.ContentTypes = types
	switch rule.Kind {
	case KindLink:
		return normalizeLink(rule, out)
	case KindReplace:
		return normalizeReplace(rule, out)
	case KindHTTPS:
		return normalizeHTTPS(rule, out)
	}
	return Rule{}, &FieldError{"kind", "must be link, replace or https"}
}

func normalizePaths(paths []string) ([]string, error) {
	if len(paths) > MaxPaths {
		return nil, &FieldError{"paths", "at most 10 paths"}
	}
	out := []string{}
	for _, path := range paths {
		if path == "" || path[0] != '/' || len(path) > MaxPathBytes || strings.ContainsAny(path, "?#") {
			return nil, &FieldError{"paths", "a path starts with / and has no ? or #, at most 256 bytes"}
		}
		for index := 0; index < len(path); index++ {
			if path[index] <= ' ' || path[index] > '~' {
				return nil, &FieldError{"paths", "printable ASCII without spaces only"}
			}
		}
		if !slices.Contains(out, path) {
			out = append(out, path)
		}
	}
	return out, nil
}

func normalizeTypes(types []string) ([]string, error) {
	if len(types) == 0 {
		return []string{TypeHTML}, nil
	}
	set := map[string]bool{}
	for _, value := range types {
		value = strings.ToLower(strings.TrimSpace(value))
		if !slices.Contains(typeOrder, value) {
			return nil, &FieldError{"content_types", "must be text/html, text/css or application/javascript"}
		}
		set[value] = true
	}
	out := []string{}
	for _, value := range typeOrder {
		if set[value] {
			out = append(out, value)
		}
	}
	return out, nil
}

func normalizeLink(rule Rule, out Rule) (Rule, error) {
	if len(rule.FromHosts) == 0 || len(rule.FromHosts) > MaxFromHosts {
		return Rule{}, &FieldError{"from_hosts", "1-20 host names"}
	}
	out.FromHosts = []string{}
	for _, host := range rule.FromHosts {
		host = strings.ToLower(strings.TrimSpace(host))
		if !hostPattern.MatchString(host) || len(host) > 253 {
			return Rule{}, &FieldError{"from_hosts", "a host name without port, like old.example.com"}
		}
		if !slices.Contains(out.FromHosts, host) {
			out.FromHosts = append(out.FromHosts, host)
		}
	}
	out.ToHost = strings.ToLower(strings.TrimSpace(rule.ToHost))
	name, port, hasPort := strings.Cut(out.ToHost, ":")
	if !hostPattern.MatchString(name) || len(name) > 253 {
		return Rule{}, &FieldError{"to_host", "a host name, optionally with :port"}
	}
	if hasPort {
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 || strconv.Itoa(number) != port {
			return Rule{}, &FieldError{"to_host", "port must be 1-65535"}
		}
	}
	if slices.Contains(out.FromHosts, out.ToHost) {
		return Rule{}, &FieldError{"to_host", "equals one of the old host names"}
	}
	out.Scheme = rule.Scheme
	if out.Scheme == "" {
		out.Scheme = SchemeKeep
	}
	if out.Scheme != SchemeKeep && out.Scheme != SchemeHTTPS && out.Scheme != SchemeHTTP {
		return Rule{}, &FieldError{"scheme", "must be keep, https or http"}
	}
	return out, nil
}

func normalizeReplace(rule Rule, out Rule) (Rule, error) {
	if rule.Find == "" || len(rule.Find) > MaxFindBytes {
		return Rule{}, &FieldError{"find", "1-256 bytes"}
	}
	if len(rule.Replace) > MaxReplace {
		return Rule{}, &FieldError{"replace", "at most 1024 bytes"}
	}
	out.Find, out.Replace, out.Regex, out.IgnoreCase = rule.Find, rule.Replace, rule.Regex, rule.IgnoreCase
	if rule.Regex || rule.IgnoreCase {
		pattern := rule.Find
		if !rule.Regex {
			pattern = regexp.QuoteMeta(rule.Find)
		}
		compiled, err := compilePattern(pattern, rule.IgnoreCase)
		if err != nil {
			return Rule{}, &FieldError{"find", err.Error()}
		}
		if rule.Regex {
			if reason := checkTemplate(rule.Replace, compiled.groups); reason != "" {
				return Rule{}, &FieldError{"replace", reason}
			}
		}
	}
	return out, nil
}

func normalizeHTTPS(rule Rule, out Rule) (Rule, error) {
	out.IncludeSiteDomains = rule.IncludeSiteDomains
	if len(rule.Hosts) > MaxHTTPSHosts {
		return Rule{}, &FieldError{"hosts", "at most 50 host names"}
	}
	out.Hosts = []string{}
	for _, host := range rule.Hosts {
		host = strings.ToLower(strings.TrimSpace(host))
		name := strings.TrimPrefix(host, "*.")
		if !hostPattern.MatchString(name) || len(name) > 253 {
			return Rule{}, &FieldError{"hosts", "a host name or *.suffix"}
		}
		if !slices.Contains(out.Hosts, host) {
			out.Hosts = append(out.Hosts, host)
		}
	}
	if !out.IncludeSiteDomains && len(out.Hosts) == 0 {
		return Rule{}, &FieldError{"hosts", "name a host or include the site's domains"}
	}
	return out, nil
}
