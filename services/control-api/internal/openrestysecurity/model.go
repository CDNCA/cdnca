package openrestysecurity

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	PermissionRead   = "openresty_security.read"
	PermissionManage = "openresty_security.manage"
	ScopeTenant      = "tenant"
	ScopePlatform    = "platform"
	ScopeGlobal      = "global"
	ScopeRegion      = "region"
	ScopeNode        = "node"

	CredentialSession = "session"
	CredentialAPIKey  = "api_key"
)

var (
	ErrUnauthenticated     = errors.New("OpenResty security authentication required")
	ErrPermissionDenied    = errors.New("OpenResty security permission denied")
	ErrNotFound            = errors.New("OpenResty security configuration not found")
	ErrInvalidInput        = errors.New("invalid OpenResty security configuration")
	ErrRevisionConflict    = errors.New("OpenResty security revision conflict")
	ErrIdempotencyConflict = errors.New("OpenResty security idempotency conflict")
	ErrDuplicateTarget     = errors.New("OpenResty security target already configured")
	ErrUnavailable         = errors.New("OpenResty security configuration unavailable")
)

type Config map[string]json.RawMessage

type Document struct {
	ID             uuid.UUID         `json:"id"`
	TargetScopeID  uuid.UUID         `json:"-"`
	ScopeType      string            `json:"scope_type"`
	ScopeID        string            `json:"scope_id"`
	ScopeLabel     string            `json:"scope_label,omitempty"`
	Revision       int64             `json:"revision"`
	Config         Config            `json:"config"`
	KeyConfigured  bool              `json:"key_configured"`
	UpdatedAt      time.Time         `json:"updated_at"`
	DocumentSHA256 [sha256.Size]byte `json:"-"`
	KeyOverride    bool              `json:"-"`
	// Sources (effective documents only, fix-fwregion) names, for every
	// field of Config, the layer it comes from: global, region or node.
	Sources map[string]string `json:"sources,omitempty"`
}

type OverridePage struct {
	Items    []Document `json:"items"`
	Page     int        `json:"page"`
	PageSize int        `json:"page_size"`
	Total    int        `json:"total"`
}

type TargetOption struct {
	Value       string `json:"value"`
	Label       string `json:"label"`
	Description string `json:"description,omitempty"`
}

type TargetPage struct {
	Items    []TargetOption `json:"items"`
	Page     int            `json:"page"`
	PageSize int            `json:"page_size"`
	Total    int            `json:"total"`
}

type RuleGroup struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	Enabled       bool      `json:"enabled"`
	Kind          string    `json:"kind"`
	SystemRule    bool      `json:"system_rule"`
	SystemRuleID  string    `json:"system_rule_id,omitempty"`
	SystemRuleKey string    `json:"system_rule_key,omitempty"`
	Owner         string    `json:"owner,omitempty"`
	CreatedAt     time.Time `json:"created_at,omitempty"`
	Sort          int       `json:"sort,omitempty"`
}

type RuleGroupStateRequest struct {
	Actor         Actor
	TargetScopeID uuid.UUID
	SystemRuleID  string
	Enabled       bool
}

type WAFResourceLimits struct {
	CandidatePerParam   int `json:"candidate_per_param"`
	CandidatePerRequest int `json:"candidate_per_request"`
	FFIPerRequest       int `json:"ffi_per_request"`
	JSONMaxLeaves       int `json:"json_max_leaves"`
	JSONMaxNodes        int `json:"json_max_nodes"`
	JSONMaxDepth        int `json:"json_max_depth"`
	JSONMaxStringBytes  int `json:"json_max_string_bytes"`
	JSONBodyBytes       int `json:"json_body_bytes"`
	MultipartMaxParts   int `json:"multipart_max_parts"`
	BodyScanBytes       int `json:"body_scan_bytes"`
}

var recommendedWAFResourceLimits = WAFResourceLimits{
	CandidatePerParam: 2048, CandidatePerRequest: 4096, FFIPerRequest: 8192,
	JSONMaxLeaves: 2048, JSONMaxNodes: 9216, JSONMaxDepth: 64,
	JSONMaxStringBytes: 256 * 1024, JSONBodyBytes: 1024 * 1024,
	MultipartMaxParts: 128, BodyScanBytes: 16 * 1024 * 1024,
}

var allFields = map[string]struct{}{
	"cc_enable": {}, "block_time": {}, "white_time": {}, "default_block_way": {},
	"ipset_auto_enable": {}, "site_block_qps": {}, "block_page_num_limit": {}, "block_page_not_counted": {},
	"tmp_white_total_limit": {}, "tmp_white_per_limit": {}, "custom_white": {}, "custom_black": {},
	"ssl_handshake_limit": {}, "default_page_refuse": {}, "force_default_page_cc": {},
	"auto_default_page_cc_qps": {}, "default_page_rule": {}, "icmp_drop": {}, "key": {},
	"auto_delete_access_log": {}, "auto_switch": {}, "cc_img_url_type": {}, "cc_img_url": {}, "at_hour": {},
	"slider_html": {}, "captcha_html": {}, "click_html": {}, "delay_jump_html": {}, "rotate_html": {},
	"easy_click_html": {}, "easy_slider_html": {}, "log": {}, "well_known_auto_protect_count": {},
	"internal_qps": {}, "internal_res_block_time": {}, "internal_rule": {},
	"waf_enable": {}, "waf_resource_limits": {},
}

var overrideFields = map[string]struct{}{
	"waf_enable": {}, "waf_resource_limits": {}, "cc_enable": {}, "block_time": {}, "white_time": {},
	"tmp_white_total_limit": {}, "tmp_white_per_limit": {}, "custom_white": {}, "custom_black": {},
	"ssl_handshake_limit": {}, "default_page_refuse": {}, "default_page_rule": {}, "icmp_drop": {}, "key": {},
	"auto_delete_access_log": {}, "auto_switch": {}, "slider_html": {}, "captcha_html": {}, "click_html": {},
	"delay_jump_html": {}, "rotate_html": {}, "easy_click_html": {}, "easy_slider_html": {}, "log": {},
}

func RecommendedWAFResourceLimits() WAFResourceLimits { return recommendedWAFResourceLimits }

func DefaultGlobalConfig() Config {
	return mustConfig(map[string]any{
		"cc_enable": true, "block_time": 3600, "white_time": 21600, "default_block_way": "exit",
		"ipset_auto_enable": true, "site_block_qps": 200, "block_page_num_limit": 200,
		"block_page_not_counted": true, "default_page_rule": "10003", "waf_enable": false,
		"waf_resource_limits": recommendedWAFResourceLimits,
	})
}

func DecodeConfig(input []byte, override bool) (Config, error) {
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	var config Config
	if err := decoder.Decode(&config); err != nil || config == nil {
		return nil, ErrInvalidInput
	}
	if decoder.More() {
		return nil, ErrInvalidInput
	}
	if err := ValidateConfig(config, override); err != nil {
		return nil, err
	}
	return CloneConfig(config), nil
}

func ValidateConfig(config Config, override bool) error {
	allowed := allFields
	if override {
		allowed = overrideFields
	}
	for name, raw := range config {
		if _, ok := allowed[name]; !ok || len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return ErrInvalidInput
		}
		if err := validateField(name, raw); err != nil {
			return err
		}
	}
	return nil
}

func validateField(name string, raw json.RawMessage) error {
	switch name {
	case "cc_enable", "ipset_auto_enable", "block_page_not_counted", "default_page_refuse", "icmp_drop", "waf_enable":
		var value bool
		return decodeExact(raw, &value)
	case "block_time", "site_block_qps", "block_page_num_limit", "tmp_white_total_limit", "tmp_white_per_limit",
		"ssl_handshake_limit", "auto_default_page_cc_qps", "well_known_auto_protect_count", "internal_qps", "internal_res_block_time":
		return validateInteger(raw, 0, 1<<31-1)
	case "white_time":
		return validateInteger(raw, 600, 1<<31-1)
	case "at_hour":
		return validateInteger(raw, 0, 23)
	case "auto_delete_access_log":
		return validateInteger(raw, 0, 2)
	case "default_block_way":
		return validateEnum(raw, "ipset", "exit", "page")
	case "force_default_page_cc":
		return validateEnum(raw, "force", "auto")
	case "cc_img_url_type":
		return validateEnum(raw, "system", "custom")
	case "custom_white", "custom_black":
		return validateString(raw, 1<<20, false)
	case "slider_html", "captcha_html", "click_html", "delay_jump_html", "rotate_html", "easy_click_html", "easy_slider_html":
		return validateString(raw, 2<<20, false)
	case "default_page_rule":
		return validateString(raw, 128, false)
	case "cc_img_url":
		return validateString(raw, 2048, false)
	case "key":
		return validateString(raw, 4096, false)
	case "auto_switch":
		var value struct {
			Enable   bool   `json:"enable"`
			QPS50x   int    `json:"qps_50x"`
			QPSTotal int    `json:"qps_total"`
			Rule     string `json:"rule"`
			Seconds  int    `json:"seconds"`
		}
		if err := decodeExact(raw, &value); err != nil || value.QPS50x < 0 || value.QPSTotal < 0 || value.Seconds < 0 || len(value.Rule) > 128 {
			return ErrInvalidInput
		}
	case "log":
		var value struct {
			Level   string `json:"log_level"`
			DebugIP string `json:"debug_ip"`
		}
		if err := decodeExact(raw, &value); err != nil || value.Level != "info" && value.Level != "debug" || len(value.DebugIP) > 128 {
			return ErrInvalidInput
		}
		if value.DebugIP != "" {
			if _, err := netip.ParseAddr(value.DebugIP); err != nil {
				return ErrInvalidInput
			}
		}
	case "internal_rule":
		var value []struct {
			Period int `json:"period"`
			Reqs   int `json:"reqs"`
		}
		if err := decodeExact(raw, &value); err != nil || len(value) != 3 {
			return ErrInvalidInput
		}
		for _, rule := range value {
			if rule.Period < 0 || rule.Reqs < 0 {
				return ErrInvalidInput
			}
		}
	case "waf_resource_limits":
		var value WAFResourceLimits
		if err := decodeExact(raw, &value); err != nil || !validWAFResourceLimits(value) {
			return ErrInvalidInput
		}
	default:
		return ErrInvalidInput
	}
	return nil
}

func validWAFResourceLimits(value WAFResourceLimits) bool {
	return between(value.CandidatePerParam, 256, 4096) && between(value.CandidatePerRequest, 1024, 16384) &&
		between(value.FFIPerRequest, 2048, 32768) && between(value.JSONMaxLeaves, 64, 4096) &&
		between(value.JSONMaxNodes, 1024, 32768) && between(value.JSONMaxDepth, 16, 128) &&
		between(value.JSONMaxStringBytes, 16*1024, 1024*1024) && between(value.JSONBodyBytes, 256*1024, 4*1024*1024) &&
		between(value.MultipartMaxParts, 16, 512) && between(value.BodyScanBytes, 1024*1024, 64*1024*1024) &&
		value.JSONMaxLeaves <= value.CandidatePerParam && value.CandidatePerParam <= value.CandidatePerRequest &&
		value.JSONBodyBytes <= value.BodyScanBytes
}

func ApplyPatch(base, patch Config, override bool) (Config, error) {
	if err := ValidateConfig(patch, override); err != nil {
		return nil, err
	}
	result := CloneConfig(base)
	for name, value := range patch {
		result[name] = slices.Clone(value)
	}
	if err := ValidateConfig(result, override); err != nil {
		return nil, err
	}
	return result, nil
}

func ValidateOverridePatch(patch Config, removedFields []string) error {
	if len(patch) == 0 || ValidateConfig(patch, true) != nil || removedFields != nil && len(removedFields) == 0 || len(removedFields) > len(overrideFields) {
		return ErrInvalidInput
	}
	seen := make(map[string]struct{}, len(removedFields))
	for _, name := range removedFields {
		if _, allowed := overrideFields[name]; !allowed {
			return ErrInvalidInput
		}
		if _, duplicate := seen[name]; duplicate {
			return ErrInvalidInput
		}
		if _, overlaps := patch[name]; overlaps {
			return ErrInvalidInput
		}
		seen[name] = struct{}{}
	}
	return nil
}

func ApplyOverridePatch(base, patch Config, removedFields []string) (Config, error) {
	if err := ValidateOverridePatch(patch, removedFields); err != nil {
		return nil, err
	}
	result := CloneConfig(base)
	for _, name := range removedFields {
		if _, exists := result[name]; !exists && name != "key" {
			return nil, ErrInvalidInput
		}
		delete(result, name)
	}
	for name, value := range patch {
		result[name] = slices.Clone(value)
	}
	if len(result) == 0 {
		return nil, ErrInvalidInput
	}
	if err := ValidateConfig(result, true); err != nil {
		return nil, err
	}
	return result, nil
}

func Effective(global, region, node Config) (Config, error) {
	result, err := ApplyPatch(DefaultGlobalConfig(), global, false)
	if err != nil {
		return nil, err
	}
	if region != nil {
		if err := ValidateConfig(region, true); err != nil {
			return nil, err
		}
		for name, value := range region {
			result[name] = slices.Clone(value)
		}
	}
	if node != nil {
		if err := ValidateConfig(node, true); err != nil {
			return nil, err
		}
		for name, value := range node {
			result[name] = slices.Clone(value)
		}
	}
	return result, nil
}

// EffectiveSources is, for every field of Effective(global, region, node),
// the layer that sets it (Effective's precedence: node, region, global).
func EffectiveSources(global, region, node Config) map[string]string {
	result := map[string]string{}
	for name := range DefaultGlobalConfig() {
		result[name] = ScopeGlobal
	}
	for name := range global {
		result[name] = ScopeGlobal
	}
	for name := range region {
		result[name] = ScopeRegion
	}
	for name := range node {
		result[name] = ScopeNode
	}
	return result
}

func StripSecret(config Config) (Config, *string, error) {
	result := CloneConfig(config)
	raw, ok := result["key"]
	if !ok {
		return result, nil, nil
	}
	delete(result, "key")
	var secret string
	if err := json.Unmarshal(raw, &secret); err != nil {
		return nil, nil, ErrInvalidInput
	}
	return result, &secret, nil
}

func Canonical(config Config) ([]byte, [sha256.Size]byte, error) {
	if err := ValidateConfig(config, false); err != nil {
		return nil, [sha256.Size]byte{}, err
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		return nil, [sha256.Size]byte{}, ErrInvalidInput
	}
	return encoded, sha256.Sum256(encoded), nil
}

func CloneConfig(input Config) Config {
	result := make(Config, len(input))
	for name, value := range input {
		result[name] = slices.Clone(value)
	}
	return result
}

func validScope(scopeType, scopeID string) bool {
	switch scopeType {
	case ScopeGlobal:
		return scopeID == "0"
	case ScopeNode:
		parsed, err := uuid.Parse(scopeID)
		return err == nil && parsed != uuid.Nil && parsed.String() == scopeID
	case ScopeRegion:
		return scopeID == strings.TrimSpace(scopeID) && len(scopeID) >= 1 && len(scopeID) <= 64
	default:
		return false
	}
}

func mustConfig(input map[string]any) Config {
	result := make(Config, len(input))
	for name, value := range input {
		encoded, err := json.Marshal(value)
		if err != nil {
			panic(err)
		}
		result[name] = encoded
	}
	return result
}

func decodeExact(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return ErrInvalidInput
	}
	var extra any
	if err := decoder.Decode(&extra); err == nil {
		return ErrInvalidInput
	}
	return nil
}

func validateInteger(raw []byte, minimum, maximum int) error {
	var value int
	if err := decodeExact(raw, &value); err != nil || value < minimum || value > maximum {
		return ErrInvalidInput
	}
	return nil
}

func validateEnum(raw []byte, values ...string) error {
	var value string
	if err := decodeExact(raw, &value); err != nil || !slices.Contains(values, value) {
		return ErrInvalidInput
	}
	return nil
}

func validateString(raw []byte, maximum int, required bool) error {
	var value string
	if err := decodeExact(raw, &value); err != nil || len(value) > maximum || required && strings.TrimSpace(value) == "" {
		return ErrInvalidInput
	}
	return nil
}

func between(value, minimum, maximum int) bool { return value >= minimum && value <= maximum }
