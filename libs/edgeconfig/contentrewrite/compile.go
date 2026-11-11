package contentrewrite

import (
	"regexp"
	"slices"
	"strings"
)

// Node is the site object field content_rewrite: only the
// enabled rules, ready to run.
type Node struct {
	MaxBytes int64      `json:"max_bytes"`
	Rules    []NodeRule `json:"rules"`
}

// NodeRule: Types are short names (html, css, js); Paths empty = every path.
type NodeRule struct {
	Kind  string   `json:"kind"`
	Paths []string `json:"paths"`
	Types []string `json:"types"`
	// link: old host -> new host and scheme
	Map map[string]LinkTarget `json:"map,omitempty"`
	// replace: Literal (plain search) or Pattern (canonical, MaxLen bytes)
	Literal string `json:"literal,omitempty"`
	Pattern string `json:"pattern,omitempty"`
	MaxLen  int    `json:"max_len,omitempty"`
	Replace string `json:"replace,omitempty"`
	// https: exact names or "*.suffix"
	Hosts []string `json:"hosts,omitempty"`
}

type LinkTarget struct {
	Host   string `json:"host"`
	Scheme string `json:"scheme"`
}

var shortTypes = map[string]string{TypeHTML: "html", TypeCSS: "css", TypeJS: "js"}

// Compile turns normalized settings into the node form; siteHosts are the
// site's domains (primary and aliases) an https rule with
// include_site_domains adds. nil when no rule is enabled.
func Compile(settings Settings, siteHosts []string) (*Node, error) {
	node, _, err := compile(settings, siteHosts)
	return node, err
}

// compile also returns the settings rule ID of each node rule (the tester).
func compile(settings Settings, siteHosts []string) (*Node, []string, error) {
	node := &Node{MaxBytes: settings.MaxBytes, Rules: []NodeRule{}}
	if node.MaxBytes == 0 {
		node.MaxBytes = DefaultMaxBytes
	}
	ids := []string{}
	for _, rule := range settings.Rules {
		if !rule.Enabled {
			continue
		}
		out := NodeRule{Kind: rule.Kind, Paths: slices.Clone(rule.Paths), Types: []string{}}
		if out.Paths == nil {
			out.Paths = []string{}
		}
		for _, value := range rule.ContentTypes {
			out.Types = append(out.Types, shortTypes[value])
		}
		if len(out.Types) == 0 {
			out.Types = []string{"html"}
		}
		switch rule.Kind {
		case KindLink:
			out.Map = map[string]LinkTarget{}
			for _, host := range rule.FromHosts {
				out.Map[host] = LinkTarget{Host: rule.ToHost, Scheme: rule.Scheme}
			}
		case KindReplace:
			// the node always reads a template: plain text is escaped
			out.Replace = rule.Replace
			if !rule.Regex {
				out.Replace = escapeTemplate(rule.Replace)
			}
			if !rule.Regex && !rule.IgnoreCase {
				out.Literal = rule.Find
				break
			}
			source := rule.Find
			if !rule.Regex {
				source = regexp.QuoteMeta(rule.Find)
			}
			compiled, err := compilePattern(source, rule.IgnoreCase)
			if err != nil {
				return nil, nil, &FieldError{"rules." + rule.ID + ".find", err.Error()}
			}
			out.Pattern, out.MaxLen = compiled.source, compiled.maxLen
		case KindHTTPS:
			hosts := slices.Clone(rule.Hosts)
			if rule.IncludeSiteDomains {
				for _, host := range siteHosts {
					hosts = append(hosts, strings.ToLower(host))
				}
			}
			slices.Sort(hosts)
			out.Hosts = slices.Compact(hosts)
		}
		node.Rules = append(node.Rules, out)
		ids = append(ids, rule.ID)
	}
	if len(node.Rules) == 0 {
		return nil, nil, nil
	}
	return node, ids, nil
}

// Valid is the node-side shape check (edgesite.Validate).
func (n *Node) Valid() bool {
	if n.MaxBytes < MinMaxBytes || n.MaxBytes > MaxMaxBytes || len(n.Rules) == 0 || len(n.Rules) > MaxRules {
		return false
	}
	for _, rule := range n.Rules {
		if len(rule.Paths) > MaxPaths || len(rule.Types) == 0 {
			return false
		}
		for _, value := range rule.Types {
			if value != "html" && value != "css" && value != "js" {
				return false
			}
		}
		switch rule.Kind {
		case KindLink:
			if len(rule.Map) == 0 {
				return false
			}
		case KindReplace:
			if (rule.Literal == "") == (rule.Pattern == "") || rule.Pattern != "" && (rule.MaxLen < 1 || rule.MaxLen > MaxMatchBytes) {
				return false
			}
		case KindHTTPS:
			if len(rule.Hosts) == 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// PathMatches: a path without "*" is a prefix; with "*" each "*" matches any
// run of bytes and the whole path must match (cdnca_rewrite.path_matches).
func PathMatches(patterns []string, path string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, value := range patterns {
		if globMatches(value, path) {
			return true
		}
	}
	return false
}

func globMatches(value, path string) bool {
	if !strings.Contains(value, "*") {
		return strings.HasPrefix(path, value)
	}
	parts := strings.Split(value, "*")
	if !strings.HasPrefix(path, parts[0]) {
		return false
	}
	position := len(parts[0])
	last := parts[len(parts)-1]
	for _, part := range parts[1 : len(parts)-1] {
		at := strings.Index(path[position:], part)
		if at < 0 {
			return false
		}
		position += at + len(part)
	}
	return len(path)-position >= len(last) && strings.HasSuffix(path, last)
}

// TypeKey is a Content-Type's short name ("" for any other type).
func TypeKey(contentType string) string {
	mime, _, _ := strings.Cut(contentType, ";")
	switch strings.ToLower(strings.TrimSpace(mime)) {
	case "text/html":
		return "html"
	case "text/css":
		return "css"
	case "application/javascript", "text/javascript", "application/x-javascript":
		return "js"
	}
	return ""
}

// Active is the node rules that apply to a response (path and type).
func (n *Node) Active(path, typeKey string) []int {
	out := []int{}
	for index, rule := range n.Rules {
		if slices.Contains(rule.Types, typeKey) && PathMatches(rule.Paths, path) {
			out = append(out, index)
		}
	}
	return out
}

// Wants: some rule's path matches (access phase: the request is fetched
// plain whatever its type turns out to be).
func (n *Node) Wants(path string) bool {
	for _, rule := range n.Rules {
		if PathMatches(rule.Paths, path) {
			return true
		}
	}
	return false
}
