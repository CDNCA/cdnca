package edgeconfig

import (
	"net/http"
	"slices"
)

// Access log fields (fix-logfields, system configuration category
// access_log_fields): which optional fields of an access event are recorded.
// The basic fields (time, site, host, path, status, method, protocol, bytes,
// duration, client IP, cache status) are always recorded: traffic, billing
// and the analytics rollups read them. The block page mark (block_page) is
// optional: without it the control plane clears blocked before writing, so
// package billing counts block pages as traffic. An optional field that is not selected is not
// stored: a header is not captured on the node (it never enters the site's
// capture allowlist), a scalar field is cleared by the control plane before
// the event is written to ClickHouse.

// AccessLogField is one optional field of the catalog.
type AccessLogField struct {
	Key   string
	Group string
	// Header is the canonical header name of a request/response header
	// field ("" for a scalar field).
	Header string
	// Response: Header is a response header.
	Response bool
	// Bytes is the typical stored size of one value (an estimate shown on
	// the settings page).
	Bytes int
}

// Access log field groups, in display order.
const (
	AccessLogGroupBasic    = "basic"
	AccessLogGroupClient   = "client"
	AccessLogGroupRequest  = "request_headers"
	AccessLogGroupResponse = "response_headers"
	AccessLogGroupOrigin   = "origin"
	AccessLogGroupCache    = "cache"
	AccessLogGroupSecurity = "security"
	AccessLogGroupTLS      = "tls_fingerprint"
)

// Access log field keys.
const (
	AccessLogFieldClientFamily    = "client_family"
	AccessLogFieldClientGeo       = "client_geo"
	AccessLogFieldReferer         = "referer"
	AccessLogFieldUserAgent       = "user_agent"
	AccessLogFieldAcceptLanguage  = "accept_language"
	AccessLogFieldXForwardedFor   = "x_forwarded_for"
	AccessLogFieldXRealIP         = "x_real_ip"
	AccessLogFieldContentType     = "content_type"
	AccessLogFieldContentEncoding = "content_encoding"
	AccessLogFieldOriginTiming    = "origin_timing"
	AccessLogFieldUpstreamAddr    = "upstream_addr"
	AccessLogFieldCacheControl    = "cache_control"
	AccessLogFieldBlockPage       = "block_page"
	AccessLogFieldJA4             = "ja4"
)

// AccessLogFieldCatalog is every optional field, in display order.
var AccessLogFieldCatalog = []AccessLogField{
	{Key: AccessLogFieldClientFamily, Group: AccessLogGroupClient, Bytes: 2},
	{Key: AccessLogFieldClientGeo, Group: AccessLogGroupClient, Bytes: 8},
	{Key: AccessLogFieldReferer, Group: AccessLogGroupRequest, Header: "Referer", Bytes: 80},
	{Key: AccessLogFieldUserAgent, Group: AccessLogGroupRequest, Header: "User-Agent", Bytes: 120},
	{Key: AccessLogFieldAcceptLanguage, Group: AccessLogGroupRequest, Header: "Accept-Language", Bytes: 30},
	{Key: AccessLogFieldContentType, Group: AccessLogGroupResponse, Header: "Content-Type", Response: true, Bytes: 25},
	{Key: AccessLogFieldContentEncoding, Group: AccessLogGroupResponse, Header: "Content-Encoding", Response: true, Bytes: 6},
	{Key: AccessLogFieldOriginTiming, Group: AccessLogGroupOrigin, Bytes: 12},
	{Key: AccessLogFieldUpstreamAddr, Group: AccessLogGroupOrigin, Bytes: 20},
	{Key: AccessLogFieldCacheControl, Group: AccessLogGroupCache, Header: "Cache-Control", Response: true, Bytes: 25},
	{Key: AccessLogFieldXForwardedFor, Group: AccessLogGroupSecurity, Header: "X-Forwarded-For", Bytes: 30},
	{Key: AccessLogFieldXRealIP, Group: AccessLogGroupSecurity, Header: "X-Real-Ip", Bytes: 16},
	{Key: AccessLogFieldBlockPage, Group: AccessLogGroupSecurity, Bytes: 1},
	{Key: AccessLogFieldJA4, Group: AccessLogGroupTLS, Bytes: 36},
}

// DefaultAccessLogFields is the selection of a platform that never saved
// one: the small scalar fields (the block page mark included) and Referer,
// User-Agent and Content-Type; the other headers and the origin address are off.
var DefaultAccessLogFields = []string{
	AccessLogFieldClientFamily, AccessLogFieldClientGeo, AccessLogFieldReferer, AccessLogFieldUserAgent,
	AccessLogFieldContentType, AccessLogFieldOriginTiming, AccessLogFieldBlockPage, AccessLogFieldJA4,
}

// AccessLogFields is the access_log_fields category value.
type AccessLogFields struct {
	Fields []string `json:"fields"`
}

// NormalizeAccessLogFields returns value with its fields in catalog order;
// an unknown or repeated key is refused.
func NormalizeAccessLogFields(value AccessLogFields) (AccessLogFields, error) {
	if value.Fields == nil {
		return AccessLogFields{}, ErrInvalidConfig
	}
	seen := make(map[string]bool, len(value.Fields))
	for _, key := range value.Fields {
		if seen[key] || accessLogField(key) == nil {
			return AccessLogFields{}, ErrInvalidConfig
		}
		seen[key] = true
	}
	result := AccessLogFields{Fields: []string{}}
	for _, field := range AccessLogFieldCatalog {
		if seen[field.Key] {
			result.Fields = append(result.Fields, field.Key)
		}
	}
	return result, nil
}

// EffectiveAccessLogFields is the stored selection, or the default.
func EffectiveAccessLogFields(value *AccessLogFields) AccessLogFields {
	if value == nil {
		return AccessLogFields{Fields: slices.Clone(DefaultAccessLogFields)}
	}
	return AccessLogFields{Fields: slices.Clone(value.Fields)}
}

// Has reports whether key is selected.
func (value AccessLogFields) Has(key string) bool { return slices.Contains(value.Fields, key) }

// Headers are the selected request and response header names (canonical,
// sorted).
func (value AccessLogFields) Headers() (request, response []string) {
	request, response = []string{}, []string{}
	for _, field := range AccessLogFieldCatalog {
		if field.Header == "" || !value.Has(field.Key) {
			continue
		}
		if field.Response {
			response = append(response, field.Header)
		} else {
			request = append(request, field.Header)
		}
	}
	slices.Sort(request)
	slices.Sort(response)
	return request, response
}

// MergeCaptureHeaders is allowlist plus extra, canonical, unique and sorted
// (the capture allowlist form).
func MergeCaptureHeaders(allowlist, extra []string) []string {
	result := make([]string, 0, len(allowlist)+len(extra))
	for _, name := range append(slices.Clone(allowlist), extra...) {
		name = http.CanonicalHeaderKey(name)
		if !slices.Contains(result, name) {
			result = append(result, name)
		}
	}
	slices.Sort(result)
	return result
}

func accessLogField(key string) *AccessLogField {
	for index := range AccessLogFieldCatalog {
		if AccessLogFieldCatalog[index].Key == key {
			return &AccessLogFieldCatalog[index]
		}
	}
	return nil
}
