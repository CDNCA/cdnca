// Command openapi-catalog builds the public API catalogue shown on
// www.cdnca.com/developers/api from the OpenAPI contracts.
//
// It reads root documents under api/openapi/v1 (control.yaml, sites.yaml,
// dns-acme.yaml by default), follows cross-file path-item $refs such as
// '../../control-themes.openapi.yaml#/paths/~1v1~1theme~1current', and writes
// api-catalog.json (method, path, summary, auth kinds, operationId and group
// per operation) plus api-operations/<group>.json with each operation's detail:
// description, required permissions and features, parameters, request body and
// response fields (top level only) and response status codes. Only integration-facing operations are listed: /v1/internal/* is
// excluded (www-design.md §5.5). Nested schemas are named, not expanded. When several roots
// declare the same method+path (dns-acme.yaml repeats 15 control.yaml paths),
// the earlier root in the list wins.
//
// Auth follows OpenAPI rules: operation-level security wins, otherwise the
// root document's security applies (a referenced file's own root security does
// not, so the "API key" badge is never over-claimed). Scheme names resolve in
// the components of the file that defines the operation, then the root file.
//
// Usage:
//
//	openapi-catalog -repo <repo> -out apps/www/src/generated
//	openapi-catalog -repo <repo> -out ... -check   # exit 1 if any output is stale
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

var defaultRoots = []string{"control.yaml", "sites.yaml", "dns-acme.yaml"}

// excludedPrefixes are never published (internal, machine-to-machine).
var excludedPrefixes = []string{"/v1/internal/"}

var httpMethods = []string{"get", "post", "put", "patch", "delete", "head", "options", "trace"}

type Operation struct {
	Method     string   `json:"method"`
	Path       string   `json:"path"`
	Summary    string   `json:"summary"`
	// SummaryZh is x-summary-zh: the contract's own Chinese summary (shown on the Chinese site).
	SummaryZh  string   `json:"summary_zh,omitempty"`
	Auth       []string `json:"auth"`
	APIKey     bool     `json:"api_key"`
	Tags       []string `json:"tags,omitempty"`
	Deprecated bool     `json:"deprecated,omitempty"`
	Source     string   `json:"source"`
	// OperationID anchors the detail entry (www /developers/api/<group>#<operation_id>).
	OperationID string `json:"operation_id"`
	// Detail goes to api-operations/<group>.json, not the index.
	Detail *Detail `json:"-"`
}

// Detail is everything the contract states about one operation beyond the
// index row. It is written per group so the index page stays small.
type Detail struct {
	OperationID string   `json:"operation_id"`
	Method      string   `json:"method"`
	Path        string   `json:"path"`
	Summary     string   `json:"summary"`
	SummaryZh   string   `json:"summary_zh,omitempty"`
	Auth        []string `json:"auth"`
	Description string   `json:"description,omitempty"`
	// DescriptionZh (x-description-zh on operations, parameters, properties and responses) is
	// written in the contract next to the English text; nothing is machine-translated here.
	DescriptionZh string `json:"description_zh,omitempty"`
	// Permissions must all be held; AnyPermissions needs one of them
	// (x-required-permissions / x-permissions / x-permission "a | b" / x-required-any-permission).
	Permissions    []string   `json:"permissions,omitempty"`
	AnyPermissions []string   `json:"any_permissions,omitempty"`
	Features       []string   `json:"features,omitempty"`
	RecentReauth   bool       `json:"recent_reauth,omitempty"`
	Params         []Field    `json:"params,omitempty"`
	Body           *Body      `json:"body,omitempty"`
	Responses      []Response `json:"responses,omitempty"`
}

// Field is one parameter or one top-level schema property.
type Field struct {
	Name        string `json:"name"`
	In          string `json:"in,omitempty"`
	Type        string `json:"type"`
	Required      bool   `json:"required,omitempty"`
	Description   string `json:"description,omitempty"`
	DescriptionZh string `json:"description_zh,omitempty"`
}

type Body struct {
	ContentTypes []string `json:"content_types"`
	Required     bool     `json:"required,omitempty"`
	Fields       []Field  `json:"fields,omitempty"`
}

type Response struct {
	Status        string  `json:"status"`
	Description   string  `json:"description,omitempty"`
	DescriptionZh string  `json:"description_zh,omitempty"`
	Fields        []Field `json:"fields,omitempty"`
}

type Group struct {
	ID         string      `json:"id"`
	Prefix     string      `json:"prefix"`
	Count      int         `json:"count"`
	APIKey     int         `json:"api_key_count"`
	Operations []Operation `json:"operations"`
}

type Catalog struct {
	Sources []string `json:"sources"`
	Total   int      `json:"total"`
	APIKey  int      `json:"api_key_count"`
	Groups  []Group  `json:"groups"`
}

// loader caches parsed YAML documents by absolute path.
type loader struct {
	docs map[string]*yaml.Node
}

func (l *loader) load(path string) (*yaml.Node, error) {
	if d, ok := l.docs[path]; ok {
		return d, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var n yaml.Node
	if err := yaml.Unmarshal(b, &n); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if n.Kind != yaml.DocumentNode || len(n.Content) == 0 {
		return nil, fmt.Errorf("%s: empty document", path)
	}
	l.docs[path] = n.Content[0]
	return n.Content[0], nil
}

func mapGet(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

// pointer walks a JSON pointer ("/paths/~1v1~1x") inside a document.
func pointer(doc *yaml.Node, ptr string) (*yaml.Node, error) {
	if ptr == "" || ptr == "/" {
		return doc, nil
	}
	if !strings.HasPrefix(ptr, "/") {
		return nil, fmt.Errorf("bad pointer %q", ptr)
	}
	cur := doc
	for _, raw := range strings.Split(ptr[1:], "/") {
		tok := strings.ReplaceAll(strings.ReplaceAll(raw, "~1", "/"), "~0", "~")
		next := mapGet(cur, tok)
		if next == nil {
			return nil, fmt.Errorf("pointer %q: %q not found", ptr, tok)
		}
		cur = next
	}
	return cur, nil
}

// resolve follows $ref chains starting in file. It returns the target node
// and the file it lives in.
func (l *loader) resolve(file string, n *yaml.Node) (*yaml.Node, string, error) {
	seen := map[string]bool{}
	for {
		ref := mapGet(n, "$ref")
		if ref == nil {
			return n, file, nil
		}
		target, frag, _ := strings.Cut(ref.Value, "#")
		next := file
		if target != "" {
			next = filepath.Clean(filepath.Join(filepath.Dir(file), target))
		}
		key := next + "#" + frag
		if seen[key] {
			return nil, "", fmt.Errorf("$ref cycle at %s", key)
		}
		seen[key] = true
		doc, err := l.load(next)
		if err != nil {
			return nil, "", err
		}
		n, err = pointer(doc, frag)
		if err != nil {
			return nil, "", fmt.Errorf("%s: %w", ref.Value, err)
		}
		file = next
	}
}

// schemeKind classifies a security scheme: apiKey, bearer, basic, mtls, oauth2, oidc.
func (l *loader) schemeKind(file, rootFile, name string) (string, error) {
	for _, f := range []string{file, rootFile} {
		doc, err := l.load(f)
		if err != nil {
			return "", err
		}
		s := mapGet(mapGet(mapGet(doc, "components"), "securitySchemes"), name)
		if s == nil {
			continue
		}
		s, _, err = l.resolve(f, s)
		if err != nil {
			return "", err
		}
		typ := mapGet(s, "type")
		if typ == nil {
			return "", fmt.Errorf("%s: security scheme %s has no type", f, name)
		}
		switch typ.Value {
		case "apiKey":
			return "apiKey", nil
		case "http":
			if sc := mapGet(s, "scheme"); sc != nil && strings.EqualFold(sc.Value, "basic") {
				return "basic", nil
			}
			return "bearer", nil
		case "mutualTLS":
			return "mtls", nil
		case "oauth2":
			return "oauth2", nil
		case "openIdConnect":
			return "oidc", nil
		}
		return "", fmt.Errorf("%s: security scheme %s has unknown type %q", f, name, typ.Value)
	}
	return "", fmt.Errorf("security scheme %q not defined in %s or %s", name, file, rootFile)
}

// authKinds returns the sorted distinct kinds of a security requirement list;
// an empty list (security: []) means "none".
func (l *loader) authKinds(file, rootFile string, sec *yaml.Node) ([]string, error) {
	if sec.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("%s: security is not a list", file)
	}
	set := map[string]bool{}
	for _, req := range sec.Content {
		if req.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("%s: security requirement is not a map", file)
		}
		if len(req.Content) == 0 {
			set["none"] = true
		}
		for i := 0; i < len(req.Content); i += 2 {
			k, err := l.schemeKind(file, rootFile, req.Content[i].Value)
			if err != nil {
				return nil, err
			}
			set[k] = true
		}
	}
	if len(set) == 0 {
		set["none"] = true
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out, nil
}

// ---- operation detail ---------------------------------------------------------
//
// Only what the contract states is copied: parameters, request-body and
// response content types with their top-level schema properties, response
// status codes with descriptions, and the permission / feature extensions.
// Nested schemas are named, not expanded.

func strList(n *yaml.Node) []string {
	if n == nil {
		return nil
	}
	if n.Kind == yaml.ScalarNode {
		var out []string
		for _, p := range strings.Split(n.Value, "|") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
		return out
	}
	var out []string
	for _, x := range n.Content {
		out = append(out, x.Value)
	}
	return out
}

func scalar(n *yaml.Node, key string) string {
	if v := mapGet(n, key); v != nil && v.Kind == yaml.ScalarNode {
		return strings.TrimSpace(v.Value)
	}
	return ""
}

// refName returns the last pointer token of a $ref ("…/schemas/SiteList" -> SiteList).
func refName(n *yaml.Node) string {
	ref := scalar(n, "$ref")
	if ref == "" {
		return ""
	}
	_, frag, _ := strings.Cut(ref, "#")
	return frag[strings.LastIndex(frag, "/")+1:]
}

// typeOf describes a schema in one short string: string(uuid), integer, array<Site>, A | B, Site.
func (l *loader) typeOf(file string, n *yaml.Node, depth int) string {
	if n == nil {
		return ""
	}
	name := refName(n)
	s, f, err := l.resolve(file, n)
	if err != nil || s == nil {
		return name
	}
	if depth > 3 {
		if name != "" {
			return name
		}
		return "object"
	}
	for _, k := range []string{"oneOf", "anyOf"} {
		if alt := mapGet(s, k); alt != nil {
			var parts []string
			for _, a := range alt.Content {
				parts = append(parts, l.typeOf(f, a, depth+1))
			}
			return strings.Join(parts, " | ")
		}
	}
	typ := mapGet(s, "type")
	var types []string
	if typ != nil {
		types = strList(typ)
		if typ.Kind == yaml.SequenceNode {
			types = nil
			for _, x := range typ.Content {
				types = append(types, x.Value)
			}
		}
	}
	if len(types) == 0 {
		if name != "" {
			return name
		}
		if mapGet(s, "allOf") != nil || mapGet(s, "properties") != nil {
			return "object"
		}
		if c := mapGet(s, "const"); c != nil {
			return "const " + c.Value
		}
		return "any"
	}
	var parts []string
	for _, t := range types {
		switch t {
		case "array":
			parts = append(parts, "array<"+l.typeOf(f, mapGet(s, "items"), depth+1)+">")
		case "object":
			if name != "" {
				parts = append(parts, name)
			} else {
				parts = append(parts, "object")
			}
		default:
			if fm := scalar(s, "format"); fm != "" {
				t += "(" + fm + ")"
			}
			if e := mapGet(s, "enum"); e != nil && len(e.Content) > 0 && len(e.Content) <= 12 {
				t += ": " + strings.Join(strList(e), " / ")
			}
			parts = append(parts, t)
		}
	}
	return strings.Join(parts, " | ")
}

// properties returns the top-level properties of an object schema, merging allOf.
func (l *loader) properties(file string, n *yaml.Node, depth int) []Field {
	s, f, err := l.resolve(file, n)
	if err != nil || s == nil || depth > 4 {
		return nil
	}
	var out []Field
	if all := mapGet(s, "allOf"); all != nil {
		for _, a := range all.Content {
			out = mergeFields(out, l.properties(f, a, depth+1))
		}
	}
	required := map[string]bool{}
	for _, r := range strList(mapGet(s, "required")) {
		required[r] = true
	}
	if props := mapGet(s, "properties"); props != nil {
		for i := 0; i+1 < len(props.Content); i += 2 {
			p := props.Content[i+1]
			desc, descZh := scalar(p, "description"), scalar(p, "x-description-zh")
			if desc == "" || descZh == "" {
				if r, _, err := l.resolve(f, p); err == nil {
					if desc == "" {
						desc = scalar(r, "description")
					}
					if descZh == "" {
						descZh = scalar(r, "x-description-zh")
					}
				}
			}
			out = mergeFields(out, []Field{{Name: props.Content[i].Value, Type: l.typeOf(f, p, 0), Required: required[props.Content[i].Value],
				Description: publicText(desc), DescriptionZh: publicText(descZh)}})
		}
	}
	// required may sit on an allOf branch without the property itself.
	for i := range out {
		if required[out[i].Name] {
			out[i].Required = true
		}
	}
	return out
}

func mergeFields(a, b []Field) []Field {
	for _, x := range b {
		found := false
		for i := range a {
			if a[i].Name == x.Name && a[i].In == x.In {
				if x.Required {
					a[i].Required = true
				}
				if a[i].Description == "" {
					a[i].Description = x.Description
				}
				found = true
				break
			}
		}
		if !found {
			a = append(a, x)
		}
	}
	return a
}

func (l *loader) params(file string, lists ...*yaml.Node) []Field {
	var out []Field
	for _, list := range lists {
		if list == nil {
			continue
		}
		for _, raw := range list.Content {
			p, f, err := l.resolve(file, raw)
			if err != nil || p == nil {
				continue
			}
			field := Field{Name: scalar(p, "name"), In: scalar(p, "in"), Type: l.typeOf(f, mapGet(p, "schema"), 0),
				Required: scalar(p, "required") == "true", Description: publicText(scalar(p, "description")),
				DescriptionZh: publicText(scalar(p, "x-description-zh"))}
			replaced := false
			for i := range out {
				if out[i].Name == field.Name && out[i].In == field.In {
					out[i], replaced = field, true // operation level overrides path-item level
				}
			}
			if !replaced {
				out = append(out, field)
			}
		}
	}
	return out
}

// content returns the media types of a content map and the fields of the JSON one.
func (l *loader) content(file string, c *yaml.Node) ([]string, []Field) {
	types := []string{}
	if c == nil {
		return types, nil
	}
	var fields []Field
	for i := 0; i+1 < len(c.Content); i += 2 {
		mt := c.Content[i].Value
		types = append(types, mt)
		if fields == nil && (mt == "application/json" || strings.HasSuffix(mt, "+json") || mt == "multipart/form-data") {
			fields = l.properties(file, mapGet(c.Content[i+1], "schema"), 0)
		}
	}
	return types, fields
}

// internalRef matches contract notes meant for maintainers: design-record and
// task numbers, repository paths and migration numbers. They are not public
// documentation, so publicText drops them.
var internalRef = regexp.MustCompile(`\bADR[ -]?\d{4}\b|\b(?:PA|RS|AD|GW|ML|RI|FX|NF|LIC|DR)-\d+[a-z]?\b|\b(?:libs|services|apps|docs|tools|scripts|packages|api)/[\w./-]+|\bmigration \d+|\buser decision\b|§`)

var (
	parenthetical = regexp.MustCompile(`\s*\([^()]*\)`)
	sentenceEnd   = regexp.MustCompile(`[.;!?](\s+|$)`)
)

// publicText removes parentheticals that carry an internal reference, then
// any sentence that still does. What is left is contract text as written.
func publicText(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	s = parenthetical.ReplaceAllStringFunc(s, func(p string) string {
		if internalRef.MatchString(p) {
			return ""
		}
		return p
	})
	if !internalRef.MatchString(s) {
		return strings.TrimSpace(s)
	}
	var keep []string
	last := 0
	for _, m := range sentenceEnd.FindAllStringIndex(s, -1) {
		if sent := strings.TrimSpace(s[last:m[1]]); sent != "" && !internalRef.MatchString(sent) {
			keep = append(keep, sent)
		}
		last = m[1]
	}
	if sent := strings.TrimSpace(s[last:]); sent != "" && !internalRef.MatchString(sent) {
		keep = append(keep, sent)
	}
	return strings.Join(keep, " ")
}

func (l *loader) detail(op0 *Operation, file string, item, op *yaml.Node) error {
	op0.OperationID = scalar(op, "operationId")
	if op0.OperationID == "" {
		return errors.New("operation has no operationId")
	}
	o := &Detail{OperationID: op0.OperationID, Method: op0.Method, Path: op0.Path, Summary: op0.Summary, SummaryZh: op0.SummaryZh,
		Auth: op0.Auth, Description: publicText(scalar(op, "description")), DescriptionZh: publicText(scalar(op, "x-description-zh"))}
	op0.Detail = o
	o.Permissions = append(strList(mapGet(op, "x-required-permissions")), strList(mapGet(op, "x-permissions"))...)
	o.AnyPermissions = strList(mapGet(op, "x-required-any-permission"))
	if p := strList(mapGet(op, "x-permission")); len(p) == 1 {
		o.Permissions = append(o.Permissions, p...)
	} else if len(p) > 1 {
		o.AnyPermissions = append(o.AnyPermissions, p...)
	}
	o.Features = strList(mapGet(op, "x-required-features"))
	o.RecentReauth = scalar(op, "x-requires-recent-reauthentication") == "true"
	o.Params = l.params(file, mapGet(item, "parameters"), mapGet(op, "parameters"))
	if rb := mapGet(op, "requestBody"); rb != nil {
		r, f, err := l.resolve(file, rb)
		if err != nil {
			return err
		}
		types, fields := l.content(f, mapGet(r, "content"))
		o.Body = &Body{ContentTypes: types, Required: scalar(r, "required") == "true", Fields: fields}
	}
	if rs := mapGet(op, "responses"); rs != nil {
		// the whole responses map may itself be a $ref to a shared set
		rs, rsFile, err := l.resolve(file, rs)
		if err != nil {
			return err
		}
		for i := 0; i+1 < len(rs.Content); i += 2 {
			r, f, err := l.resolve(rsFile, rs.Content[i+1])
			if err != nil {
				return err
			}
			resp := Response{Status: rs.Content[i].Value, Description: publicText(scalar(r, "description")),
				DescriptionZh: publicText(scalar(r, "x-description-zh"))}
			if strings.HasPrefix(resp.Status, "2") {
				_, resp.Fields = l.content(f, mapGet(r, "content"))
			}
			o.Responses = append(o.Responses, resp)
		}
	}
	return nil
}

// groupPrefix: /v1/sites/{id} -> /v1/sites; /v1/admin/analytics/x -> /v1/admin/analytics.
func groupPrefix(path string) string {
	seg := strings.Split(strings.TrimPrefix(path, "/"), "/")
	n := 2
	if len(seg) > 2 && seg[1] == "admin" {
		n = 3
	}
	if len(seg) < n {
		n = len(seg)
	}
	return "/" + strings.Join(seg[:n], "/")
}

func groupID(prefix string) string {
	s := strings.TrimPrefix(prefix, "/v1/")
	s = strings.NewReplacer("/", "-", "{", "", "}", "", ".", "-", "_", "-").Replace(s)
	return strings.ToLower(s)
}

func excluded(path string) bool {
	for _, p := range excludedPrefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// Build reads the root documents (relative to <repo>/api/openapi/v1) and
// returns the catalogue. Source paths are reported relative to repo.
func Build(repo string, roots []string) (*Catalog, error) {
	l := &loader{docs: map[string]*yaml.Node{}}
	base := filepath.Join(repo, "api", "openapi", "v1")
	seen := map[string]string{}
	var ops []Operation
	for _, r := range roots {
		rootFile := filepath.Join(base, r)
		doc, err := l.load(rootFile)
		if err != nil {
			return nil, err
		}
		rootSec := mapGet(doc, "security")
		paths := mapGet(doc, "paths")
		if paths == nil {
			continue
		}
		for i := 0; i+1 < len(paths.Content); i += 2 {
			p := paths.Content[i].Value
			if excluded(p) {
				continue
			}
			item, file, err := l.resolve(rootFile, paths.Content[i+1])
			if err != nil {
				return nil, fmt.Errorf("%s %s: %w", r, p, err)
			}
			rel, _ := filepath.Rel(repo, file)
			for _, m := range httpMethods {
				op := mapGet(item, m)
				if op == nil {
					continue
				}
				key := strings.ToUpper(m) + " " + p
				if _, ok := seen[key]; ok {
					// dns-acme.yaml repeats part of control.yaml; earlier roots win.
					continue
				}
				seen[key] = r
				sec := mapGet(op, "security")
				secFile := file
				if sec == nil {
					sec, secFile = rootSec, rootFile
				}
				auth := []string{"none"}
				if sec != nil {
					if auth, err = l.authKinds(secFile, rootFile, sec); err != nil {
						return nil, fmt.Errorf("%s: %w", key, err)
					}
				}
				o := Operation{Method: strings.ToUpper(m), Path: p, Auth: auth, Source: filepath.ToSlash(rel)}
				for _, a := range auth {
					if a == "apiKey" {
						o.APIKey = true
					}
				}
				if s := mapGet(op, "summary"); s != nil {
					o.Summary = publicText(s.Value)
				}
				o.SummaryZh = publicText(scalar(op, "x-summary-zh"))
				if t := mapGet(op, "tags"); t != nil {
					for _, x := range t.Content {
						o.Tags = append(o.Tags, x.Value)
					}
				}
				if d := mapGet(op, "deprecated"); d != nil && d.Value == "true" {
					o.Deprecated = true
				}
				if err := l.detail(&o, file, item, op); err != nil {
					return nil, fmt.Errorf("%s: %w", key, err)
				}
				ops = append(ops, o)
			}
		}
	}
	if len(ops) == 0 {
		return nil, errors.New("no operations found")
	}
	byPrefix := map[string]*Group{}
	for _, o := range ops {
		pre := groupPrefix(o.Path)
		g := byPrefix[pre]
		if g == nil {
			g = &Group{ID: groupID(pre), Prefix: pre}
			byPrefix[pre] = g
		}
		g.Operations = append(g.Operations, o)
	}
	cat := &Catalog{}
	for _, r := range roots {
		cat.Sources = append(cat.Sources, "api/openapi/v1/"+r)
	}
	ids := map[string]string{}
	for _, g := range byPrefix {
		if prev, ok := ids[g.ID]; ok {
			return nil, fmt.Errorf("group id %q collides: %s and %s", g.ID, prev, g.Prefix)
		}
		ids[g.ID] = g.Prefix
		sort.Slice(g.Operations, func(i, j int) bool {
			a, b := g.Operations[i], g.Operations[j]
			if a.Path != b.Path {
				return a.Path < b.Path
			}
			return methodRank(a.Method) < methodRank(b.Method)
		})
		g.Count = len(g.Operations)
		for _, o := range g.Operations {
			if o.APIKey {
				g.APIKey++
			}
		}
		cat.Total += g.Count
		cat.APIKey += g.APIKey
		cat.Groups = append(cat.Groups, *g)
	}
	sort.Slice(cat.Groups, func(i, j int) bool { return cat.Groups[i].Prefix < cat.Groups[j].Prefix })
	return cat, nil
}

func methodRank(m string) int {
	for i, x := range httpMethods {
		if strings.EqualFold(x, m) {
			return i
		}
	}
	return len(httpMethods)
}

func encode(c any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")
	if err := enc.Encode(c); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// GroupDetail is one api-operations/<group id>.json file.
type GroupDetail struct {
	ID         string    `json:"id"`
	Prefix     string    `json:"prefix"`
	Operations []*Detail `json:"operations"`
}

// Outputs renders the index and the per-group detail files, keyed by path
// relative to the index's directory.
func Outputs(c *Catalog) (map[string][]byte, error) {
	out := map[string][]byte{}
	b, err := encode(c)
	if err != nil {
		return nil, err
	}
	out[indexName] = b
	for _, g := range c.Groups {
		d := GroupDetail{ID: g.ID, Prefix: g.Prefix}
		for _, o := range g.Operations {
			d.Operations = append(d.Operations, o.Detail)
		}
		if out[detailDir+"/"+g.ID+".json"], err = encode(d); err != nil {
			return nil, err
		}
	}
	return out, nil
}

const (
	indexName = "api-catalog.json"
	detailDir = "api-operations"
)

func fail(err error) {
	fmt.Fprintln(os.Stderr, "openapi-catalog:", err)
	os.Exit(1)
}

func main() {
	repo := flag.String("repo", ".", "repository root")
	out := flag.String("out", "apps/www/src/generated", "output directory for api-catalog.json and api-operations/ (relative to repo unless absolute)")
	check := flag.Bool("check", false, "do not write; exit 1 if any output is stale")
	flag.Parse()
	cat, err := Build(*repo, defaultRoots)
	if err != nil {
		fail(err)
	}
	files, err := Outputs(cat)
	if err != nil {
		fail(err)
	}
	dst := *out
	if !filepath.IsAbs(dst) {
		dst = filepath.Join(*repo, dst)
	}
	if *check {
		stale := staleFiles(dst, files)
		if len(stale) > 0 {
			fmt.Fprintf(os.Stderr, "openapi-catalog: stale under %s: %s; regenerate with pnpm -C apps/www catalog\n", dst, strings.Join(stale, ", "))
			os.Exit(1)
		}
		return
	}
	// Remove detail files of groups that no longer exist.
	old, _ := filepath.Glob(filepath.Join(dst, detailDir, "*.json"))
	for _, f := range old {
		if _, ok := files[detailDir+"/"+filepath.Base(f)]; !ok {
			if err := os.Remove(f); err != nil {
				fail(err)
			}
		}
	}
	for name, b := range files {
		p := filepath.Join(dst, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			fail(err)
		}
		if err := os.WriteFile(p, b, 0o644); err != nil {
			fail(err)
		}
	}
	fmt.Printf("openapi-catalog: %d operations in %d groups (%d API-key) -> %s\n", cat.Total, len(cat.Groups), cat.APIKey, dst)
}

// staleFiles lists outputs that differ from disk, plus detail files on disk
// that would not be generated.
func staleFiles(dst string, files map[string][]byte) []string {
	var stale []string
	for name, b := range files {
		cur, err := os.ReadFile(filepath.Join(dst, filepath.FromSlash(name)))
		if err != nil || !bytes.Equal(cur, b) {
			stale = append(stale, name)
		}
	}
	old, _ := filepath.Glob(filepath.Join(dst, detailDir, "*.json"))
	for _, f := range old {
		if _, ok := files[detailDir+"/"+filepath.Base(f)]; !ok {
			stale = append(stale, detailDir+"/"+filepath.Base(f)+" (orphan)")
		}
	}
	sort.Strings(stale)
	return stale
}
