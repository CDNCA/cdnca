package errorpage

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
)

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type canonicalPolicy struct {
	Schema    string              `json:"schema"`
	Version   string              `json:"version"`
	Revision  uint64              `json:"revision"`
	Resources []canonicalResource `json:"resources"`
	Bindings  []canonicalBinding  `json:"bindings"`
}

type canonicalResource struct {
	Key        string `json:"key"`
	MIMEType   string `json:"mime_type"`
	Size       int64  `json:"size_bytes"`
	SHA256     string `json:"sha256"`
	BodyBase64 string `json:"body_base64"`
	StyleHash  string `json:"style_hash,omitempty"`
}

type canonicalBinding struct {
	SiteKey     string   `json:"site_key,omitempty"`
	Category    Category `json:"category"`
	Status      int      `json:"status"`
	RuleID      string   `json:"rule_id"`
	ResourceKey string   `json:"resource_key"`
}

type candidate struct {
	ruleID      string
	specificity int
	resourceKey string
}

func Compile(policy Policy, resourceRoot string) (Artifact, error) {
	if policy.Schema != SchemaV1 || !identifierPattern.MatchString(policy.Version) || policy.Revision == 0 {
		return Artifact{}, invalidPolicy("schema, version, or revision is invalid")
	}
	if len(policy.Sites) > MaxSites || len(policy.Global.Rules) > MaxRulesPerScope {
		return Artifact{}, invalidPolicy("policy exceeds scope limits")
	}

	resources := make(map[string]CompiledResource)
	bindings := make(map[string]canonicalBinding)
	if err := compileScope("", policy.Global.Rules, resourceRoot, resources, bindings); err != nil {
		return Artifact{}, err
	}
	seenSites := make(map[string]struct{}, len(policy.Sites))
	for _, site := range policy.Sites {
		if !identifierPattern.MatchString(site.SiteKey) || len(site.Rules) > MaxRulesPerScope {
			return Artifact{}, invalidPolicy("site scope is invalid")
		}
		if _, exists := seenSites[site.SiteKey]; exists {
			return Artifact{}, invalidPolicy("site scope %q is duplicated", site.SiteKey)
		}
		seenSites[site.SiteKey] = struct{}{}
		for _, rule := range site.Rules {
			if rule.Category == CategoryNoHost || rule.Category == CategoryUnknownSite {
				return Artifact{}, invalidPolicy("category %q is global-only", rule.Category)
			}
		}
		if err := compileScope(site.SiteKey, site.Rules, resourceRoot, resources, bindings); err != nil {
			return Artifact{}, err
		}
	}
	if len(bindings) > MaxBindingsPerPolicy {
		return Artifact{}, invalidPolicy("binding count is outside the allowed range")
	}
	unknownSite := 0
	for _, binding := range bindings {
		if binding.Category == CategoryUnknownSite {
			unknownSite++
		}
	}
	// The domain mismatch page answers with one status (default servers).
	if unknownSite > 1 {
		return Artifact{}, invalidPolicy("unknown_site has more than one status")
	}
	totalResourceBytes := int64(0)
	for _, resource := range resources {
		totalResourceBytes += resource.Size
	}
	if totalResourceBytes > MaxPolicyResourceBytes {
		return Artifact{}, invalidPolicy("policy resource bytes exceed the allowed total")
	}

	canonical := canonicalPolicy{Schema: SchemaV1, Version: policy.Version, Revision: policy.Revision}
	resourceKeys := make([]string, 0, len(resources))
	for key := range resources {
		resourceKeys = append(resourceKeys, key)
	}
	sort.Strings(resourceKeys)
	for _, key := range resourceKeys {
		resource := resources[key]
		canonical.Resources = append(canonical.Resources, canonicalResource{
			Key: key, MIMEType: resource.MIMEType, Size: resource.Size, SHA256: resource.SHA256,
			BodyBase64: base64.StdEncoding.EncodeToString(resource.Body), StyleHash: resource.StyleHash,
		})
	}
	bindingKeys := make([]string, 0, len(bindings))
	for key := range bindings {
		bindingKeys = append(bindingKeys, key)
	}
	sort.Strings(bindingKeys)
	for _, key := range bindingKeys {
		canonical.Bindings = append(canonical.Bindings, bindings[key])
	}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return Artifact{}, invalidPolicy("canonical encoding failed")
	}
	digest := sha256.Sum256(encoded)
	runtimeLua := renderRuntimeLua(canonical)
	if len(encoded) > MaxArtifactBytes || len(runtimeLua) > MaxArtifactBytes {
		return Artifact{}, invalidPolicy("compiled artifact exceeds the allowed size")
	}
	runtimeDigest := sha256.Sum256(runtimeLua)

	lookupBindings := make(map[string]string, len(bindings))
	for key, binding := range bindings {
		lookupBindings[key] = binding.ResourceKey
	}
	return Artifact{
		Version: policy.Version, Revision: policy.Revision,
		Digest: hex.EncodeToString(digest[:]), RuntimeSHA256: hex.EncodeToString(runtimeDigest[:]),
		CanonicalJSON: append([]byte(nil), encoded...), RuntimeLua: append([]byte(nil), runtimeLua...),
		BindingCount: len(bindings), ResourceCount: len(resources),
		bindings: lookupBindings, resources: cloneResources(resources),
	}, nil
}

func compileScope(siteKey string, rules []Rule, resourceRoot string, resources map[string]CompiledResource, bindings map[string]canonicalBinding) error {
	seenRuleIDs := make(map[string]struct{}, len(rules))
	selected := make(map[string]candidate)
	for _, rule := range rules {
		if !identifierPattern.MatchString(rule.ID) || !validCategory(rule.Category) {
			return invalidPolicy("rule identity or category is invalid")
		}
		if _, exists := seenRuleIDs[rule.ID]; exists {
			return invalidPolicy("rule %q is duplicated in one scope", rule.ID)
		}
		seenRuleIDs[rule.ID] = struct{}{}
		resource, err := loadResource(rule.Resource, resourceRoot)
		if err != nil {
			return fmt.Errorf("%w: rule %q: %w", ErrInvalidPolicy, rule.ID, err)
		}
		resourceKey := resource.MIMEType + "|" + resource.SHA256
		if previous, exists := resources[resourceKey]; exists && !bytes.Equal(previous.Body, resource.Body) {
			return invalidPolicy("resource key collision")
		}
		resources[resourceKey] = resource
		matches, err := expandMatch(rule.Category, rule.Match)
		if err != nil {
			return invalidPolicy("rule %q: %v", rule.ID, err)
		}
		for status, specificity := range matches {
			key := bindingKey(siteKey, rule.Category, status)
			previous, exists := selected[key]
			if exists && previous.ruleID != rule.ID && previous.specificity == specificity {
				return invalidPolicy("rules %q and %q have equal precedence for %s", previous.ruleID, rule.ID, key)
			}
			if !exists || specificity < previous.specificity {
				selected[key] = candidate{ruleID: rule.ID, specificity: specificity, resourceKey: resourceKey}
			}
		}
	}
	for key, value := range selected {
		site, category, status := splitBindingKey(key)
		bindings[key] = canonicalBinding{
			SiteKey: site, Category: category, Status: status,
			RuleID: value.ruleID, ResourceKey: value.resourceKey,
		}
	}
	return nil
}

func expandMatch(category Category, match StatusMatch) (map[int]int, error) {
	if len(match.Codes) == 0 && len(match.Ranges) == 0 {
		return nil, fmt.Errorf("status selector is empty")
	}
	result := make(map[int]int)
	for _, code := range match.Codes {
		if !categoryAllowsStatus(category, code) {
			return nil, fmt.Errorf("status %d is invalid for category %q", code, category)
		}
		result[code] = 1
	}
	for _, statusRange := range match.Ranges {
		if statusRange.From > statusRange.To || !categoryAllowsStatus(category, statusRange.From) || !categoryAllowsStatus(category, statusRange.To) {
			return nil, fmt.Errorf("status range %d-%d is invalid for category %q", statusRange.From, statusRange.To, category)
		}
		width := statusRange.To - statusRange.From + 1
		for status := statusRange.From; status <= statusRange.To; status++ {
			if previous, exists := result[status]; !exists || width < previous {
				result[status] = width
			}
		}
	}
	return result, nil
}

func categoryAllowsStatus(category Category, status int) bool {
	switch category {
	case CategoryOriginResponse, CategoryEdgeRoute:
		return status >= 400 && status <= 599
	case CategoryEdgeConnect:
		return status == 502 || status == 503 || status == 504
	case CategoryNoHost:
		return status == 400
	case CategoryUnknownSite:
		// The domain mismatch answer: 404/410 "not here",
		// 403 refused, 421 misdirected (the default).
		return status == 403 || status == 404 || status == 410 || status == 421
	default:
		return false
	}
}

func validCategory(category Category) bool {
	switch category {
	case CategoryOriginResponse, CategoryEdgeRoute, CategoryEdgeConnect, CategoryNoHost, CategoryUnknownSite:
		return true
	default:
		return false
	}
}

func bindingKey(siteKey string, category Category, status int) string {
	return siteKey + "|" + string(category) + "|" + strconv.Itoa(status)
}

func splitBindingKey(key string) (string, Category, int) {
	first := bytes.IndexByte([]byte(key), '|')
	last := bytes.LastIndexByte([]byte(key), '|')
	status, _ := strconv.Atoi(key[last+1:])
	return key[:first], Category(key[first+1 : last]), status
}

func renderRuntimeLua(policy canonicalPolicy) []byte {
	var output bytes.Buffer
	output.WriteString("-- generated by cdnca edge-agent; static data only\n")
	fmt.Fprintf(&output, "local policy = { schema = %s, version = %s, revision = %d, resources = {}, bindings = {} }\n", luaQuote(policy.Schema), luaQuote(policy.Version), policy.Revision)
	for _, resource := range policy.Resources {
		style := ""
		if resource.StyleHash != "" {
			style = ", style_hash = " + luaQuote(resource.StyleHash)
		}
		fmt.Fprintf(&output, "policy.resources[%s] = { mime = %s, size = %d, sha256 = %s, body = ngx.decode_base64(%s)%s }\n",
			luaQuote(resource.Key), luaQuote(resource.MIMEType), resource.Size, luaQuote(resource.SHA256), luaQuote(resource.BodyBase64), style)
	}
	for _, binding := range policy.Bindings {
		fmt.Fprintf(&output, "policy.bindings[%s] = %s\n", luaQuote(bindingKey(binding.SiteKey, binding.Category, binding.Status)), luaQuote(binding.ResourceKey))
	}
	output.WriteString("return policy\n")
	return output.Bytes()
}

func luaQuote(value string) string {
	return strconv.Quote(value)
}

func cloneResources(input map[string]CompiledResource) map[string]CompiledResource {
	result := make(map[string]CompiledResource, len(input))
	for key, resource := range input {
		resource.Body = append([]byte(nil), resource.Body...)
		result[key] = resource
	}
	return result
}

func validDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func invalidPolicy(format string, arguments ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidPolicy, fmt.Sprintf(format, arguments...))
}
