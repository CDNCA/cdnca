// Package pluginprovider is the third-party provider plugin declaration and
// wire protocol (PA-22, ADR 0007 §8.2): a C1 external_https plugin that
// implements a DNS, SMS, mail or ICP (备案查询) provider for the control plane.
//
// The license service builds the declaration from the signed manifest
// (spec.entrypoint.base_url / provider_response_key, spec.provides,
// spec.permissions) and serves it to authorized installations as artifact
// plugin_provider/<plugin id>; the control plane materializes it, runs the
// installation contract against the plugin's sandbox and only then lets an
// administrator enable it. The same code builds and re-checks the
// declaration on both sides.
//
// Protocol cdnca.provider/v1: every call is
//
//	POST {base_url}/cdnca-provider/v1/{kind}/{action}
//	X-Cdnca-Provider-Installation: <control installation id>
//	X-Cdnca-Provider-Timestamp:    <unix seconds>
//	X-Cdnca-Provider-Nonce:        <32 hex>
//	X-Cdnca-Provider-Signature:    base64url(Ed25519(installation key, RequestMessage))
//
// and the plugin answers 200 with an Envelope signed by its response key:
//
//	X-Cdnca-Provider-Response-Signature: base64url(Ed25519(provider_response_key, ResponseMessage))
//
// The response signature binds the request nonce, so a captured answer
// cannot be replayed for another call. A plugin must reject a request whose
// signature, timestamp (±300 s) or nonce (seen before) is wrong with HTTP 401.
package pluginprovider

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	// Schema is the declaration served as artifact plugin_provider/<plugin id>.
	Schema = "cdnca.plugin-provider/v1"
	// Protocol is echoed in every request and response envelope.
	Protocol = "cdnca.provider/v1"
	// ProtocolVersion is spec.provides[].protocol_version this release speaks.
	ProtocolVersion = "1"
	// PathPrefix is appended to base_url: {base_url}/cdnca-provider/v1/{kind}/{action}.
	PathPrefix = "/cdnca-provider/v1/"

	KindDNS = "dns"
	KindSMS = "sms"
	KindICP = "icp"
	// KindMail sends email (system notifications) instead of the built-in SMTP.
	KindMail = "mail"
	// KindPayment is a collection channel (PA-23): high risk, see payment.go.
	KindPayment = "payment"

	HeaderInstallation      = "X-Cdnca-Provider-Installation"
	HeaderTimestamp         = "X-Cdnca-Provider-Timestamp"
	HeaderNonce             = "X-Cdnca-Provider-Nonce"
	HeaderSignature         = "X-Cdnca-Provider-Signature"
	HeaderResponseSignature = "X-Cdnca-Provider-Response-Signature"

	RequestDomain  = "cdnca-provider-request/v1"
	ResponseDomain = "cdnca-provider-response/v1"

	// MaxClockSkewSeconds bounds the request timestamp a plugin accepts.
	MaxClockSkewSeconds = 300
	// MaxDocumentBytes bounds the canonical declaration.
	MaxDocumentBytes = 16 << 10
)

// Kinds are the provider kinds opened to third parties (PA-22 dns / sms /
// icp, PA-23 payment, mail; cdn is official only).
var Kinds = []string{KindDNS, KindICP, KindMail, KindPayment, KindSMS}

// Actions per kind. verify proves reachability and signature handling.
var Actions = map[string][]string{
	KindDNS: {"verify", "list_records", "create_record", "update_record", "delete_record"},
	KindSMS: {"verify", "send"},
	KindICP: {"verify", "query"},
	// health: the plugin can send now (its upstream account works); no mail.
	KindMail: {"verify", "health", "send"},
	KindPayment: {"verify", "create_checkout", "query_payment", "verify_callback", "refund", "reconcile",
		"sandbox_settle"},
}

// Error codes a plugin may return (envelope error.code). Anything else is
// treated as provider_error.
var ErrorCodes = []string{"invalid_request", "unauthorized", "not_found", "conflict", "zone_not_found",
	"rate_limited", "quota_exceeded", "unavailable", "unsupported", "provider_error", "invalid_signature"}

// Permission is the consent permission a manifest declares for each kind it
// provides; a kind without its permission is refused (over-reach).
func Permission(kind string) string { return "providers." + kind + ".provide" }

var (
	ErrInvalid     = errors.New("invalid provider plugin declaration")
	ErrNoProviders = errors.New("manifest provides no third-party provider kind")
	// ErrPermission: a provided kind lacks its consent permission.
	ErrPermission = errors.New("provider kind declared without its permission")

	pluginIDPattern  = regexp.MustCompile(`^[a-z0-9]+(?:[.-][a-z0-9]+)+$`)
	versionPattern   = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)
	permissionRegexp = regexp.MustCompile(`^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*){1,7}$`)
	hostLabelPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	basePathPattern  = regexp.MustCompile(`^(/[A-Za-z0-9._~!$&'()*+,;=:@%-]+)*$`)
)

// Provided is one spec.provides entry.
type Provided struct {
	Kind            string `json:"kind"`
	ProtocolVersion string `json:"protocol_version"`
}

// Declaration is what the control plane materializes.
type Declaration struct {
	Schema      string   `json:"schema"`
	PluginID    string   `json:"plugin_id"`
	Version     string   `json:"version"`
	BaseURL     string   `json:"base_url"`
	ResponseKey string   `json:"response_key"`
	Kinds       []string `json:"kinds"`
	Permissions []string `json:"permissions"`
}

// Has reports whether the declaration provides kind.
func (declaration Declaration) Has(kind string) bool { return slices.Contains(declaration.Kinds, kind) }

// PublicKey decodes the response verification key.
func (declaration Declaration) PublicKey() (ed25519.PublicKey, bool) {
	return DecodeResponseKey(declaration.ResponseKey)
}

// DecodeResponseKey accepts an unpadded base64url Ed25519 public key.
func DecodeResponseKey(value string) (ed25519.PublicKey, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(raw) != ed25519.PublicKeySize || base64.RawURLEncoding.EncodeToString(raw) != value {
		return nil, false
	}
	return ed25519.PublicKey(raw), true
}

// CanonicalBaseURL: https, DNS host (no IP literal, no localhost), default
// port, optional path without query/fragment or trailing "/".
func CanonicalBaseURL(value string) (string, bool) {
	if value == "" || len(value) > 2048 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return "", false
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Opaque != "" || parsed.RawQuery != "" ||
		parsed.ForceQuery || parsed.Fragment != "" || parsed.Port() != "" || parsed.Host != parsed.Hostname() {
		return "", false
	}
	host := parsed.Hostname()
	if host == "" || len(host) > 253 || net.ParseIP(host) != nil || host == "localhost" ||
		strings.HasSuffix(host, ".localhost") || !strings.Contains(host, ".") {
		return "", false
	}
	for _, label := range strings.Split(host, ".") {
		if !hostLabelPattern.MatchString(label) {
			return "", false
		}
	}
	path := strings.TrimSuffix(parsed.EscapedPath(), "/")
	if !basePathPattern.MatchString(path) || strings.Contains(path, "/./") || strings.Contains(path, "/../") ||
		strings.HasSuffix(path, "/.") || strings.HasSuffix(path, "/..") {
		return "", false
	}
	return "https://" + host + path, true
}

// Build makes the canonical declaration from manifest facts. Only the
// third-party kinds are kept (notify / cdn are not opened);
// ErrNoProviders when none remains, ErrPermission when a kept kind lacks
// providers.<kind>.provide, ErrInvalid for anything malformed.
func Build(pluginID, version, baseURL, responseKey string, provides []Provided, permissions []string) (Declaration, []byte, error) {
	if !pluginIDPattern.MatchString(pluginID) || len(pluginID) > 128 || !versionPattern.MatchString(version) ||
		len(version) > 64 {
		return Declaration{}, nil, ErrInvalid
	}
	sortedPermissions := append([]string{}, permissions...)
	sort.Strings(sortedPermissions)
	for index, permission := range sortedPermissions {
		if len(permission) > 128 || !permissionRegexp.MatchString(permission) ||
			index > 0 && sortedPermissions[index-1] == permission {
			return Declaration{}, nil, ErrInvalid
		}
	}
	kinds := []string{}
	seen := map[string]bool{}
	for _, provided := range provides {
		if seen[provided.Kind] {
			return Declaration{}, nil, ErrInvalid
		}
		seen[provided.Kind] = true
		if !slices.Contains(Kinds, provided.Kind) {
			continue
		}
		if provided.ProtocolVersion != ProtocolVersion {
			return Declaration{}, nil, ErrInvalid
		}
		if !slices.Contains(sortedPermissions, Permission(provided.Kind)) {
			return Declaration{}, nil, ErrPermission
		}
		kinds = append(kinds, provided.Kind)
	}
	if len(kinds) == 0 {
		return Declaration{}, nil, ErrNoProviders
	}
	sort.Strings(kinds)
	base, ok := CanonicalBaseURL(baseURL)
	if !ok {
		return Declaration{}, nil, ErrInvalid
	}
	if _, ok := DecodeResponseKey(responseKey); !ok {
		return Declaration{}, nil, ErrInvalid
	}
	declaration := Declaration{Schema: Schema, PluginID: pluginID, Version: version, BaseURL: base,
		ResponseKey: responseKey, Kinds: kinds, Permissions: sortedPermissions}
	encoded, err := json.Marshal(declaration)
	if err != nil || len(encoded) > MaxDocumentBytes {
		return Declaration{}, nil, ErrInvalid
	}
	return declaration, encoded, nil
}

// Parse decodes a declaration strictly; the bytes must be exactly what
// Build produces.
func Parse(content []byte) (Declaration, error) {
	if len(content) == 0 || len(content) > MaxDocumentBytes {
		return Declaration{}, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var declaration Declaration
	if err := decoder.Decode(&declaration); err != nil {
		return Declaration{}, ErrInvalid
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) || declaration.Schema != Schema {
		return Declaration{}, ErrInvalid
	}
	provides := make([]Provided, 0, len(declaration.Kinds))
	for _, kind := range declaration.Kinds {
		provides = append(provides, Provided{Kind: kind, ProtocolVersion: ProtocolVersion})
	}
	rebuilt, encoded, err := Build(declaration.PluginID, declaration.Version, declaration.BaseURL,
		declaration.ResponseKey, provides, declaration.Permissions)
	if err != nil || !bytes.Equal(encoded, content) {
		return Declaration{}, ErrInvalid
	}
	return rebuilt, nil
}

// ValidAction reports a known kind/action pair.
func ValidAction(kind, action string) bool { return slices.Contains(Actions[kind], action) }

func bodyDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// RequestMessage is what the control plane's installation key signs.
func RequestMessage(installationID, pluginID, kind, action, timestamp, nonce string, body []byte) []byte {
	return []byte(RequestDomain + "\n" + installationID + "\n" + pluginID + "\n" + kind + "\n" + action + "\n" +
		timestamp + "\n" + nonce + "\n" + bodyDigest(body))
}

// ResponseMessage is what the plugin's response key signs.
func ResponseMessage(pluginID, kind, action, nonce string, body []byte) []byte {
	return []byte(ResponseDomain + "\n" + pluginID + "\n" + kind + "\n" + action + "\n" + nonce + "\n" + bodyDigest(body))
}

// EncodeSignature / DecodeSignature use unpadded base64url.
func EncodeSignature(signature []byte) string { return base64.RawURLEncoding.EncodeToString(signature) }

func DecodeSignature(value string) ([]byte, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	return raw, err == nil && len(raw) == ed25519.SignatureSize
}

// Envelope is every response body.
type Envelope struct {
	Protocol string          `json:"protocol"`
	OK       bool            `json:"ok"`
	Error    *EnvelopeError  `json:"error,omitempty"`
	Data     json.RawMessage `json:"data,omitempty"`
}

type EnvelopeError struct {
	Code    string `json:"code"`
	Message string `json:"message,omitempty"`
}

// KnownErrorCode maps a plugin error code to the fixed set.
func KnownErrorCode(code string) string {
	if slices.Contains(ErrorCodes, code) {
		return code
	}
	return "provider_error"
}
