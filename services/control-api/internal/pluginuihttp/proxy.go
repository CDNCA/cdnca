package pluginuihttp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
)

// The restricted plugin API proxy. A page asks the host (postMessage
// api.request); the host calls POST /v1/plugin-ui/{plugin_id}/proxy with
// its own session; the control plane forwards the call to the plugin's
// api_base_url with a signed context instead of any user credential:
//
//	X-Cdnca-Plugin-Context:   base64url(canonical context JSON)
//	X-Cdnca-Plugin-Signature: base64url(Ed25519(installation key,
//	    "cdnca-plugin-ui-proxy/v1\n" + METHOD + "\n" + path?query + "\n" +
//	    hex(sha256(body)) + "\n" + context header value))
//	X-Cdnca-Plugin-Key-Id:    the installation key fingerprint
//
// The backend verifies the signature with the installation public key the
// platform administrator gave it, checks expires_at and remembers nonce.
const (
	ProxySignatureDomain = "cdnca-plugin-ui-proxy/v1"
	ContextSchema        = "cdnca.plugin-ui-context/v1"

	maxProxyRequestBytes  = 256 << 10
	maxProxyResponseBytes = 1 << 20
	proxyContextTTL       = 60 * time.Second
)

var (
	proxyPathPattern  = regexp.MustCompile(`^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{0,511}$`)
	proxyQueryPattern = regexp.MustCompile(`^[A-Za-z0-9._~!$&'()*+,;=:@%/?-]*$`)
	proxyMethods      = map[string]bool{http.MethodGet: true, http.MethodPost: true, http.MethodPut: true,
		http.MethodPatch: true, http.MethodDelete: true}
)

// ProxyRequest is the host's request body.
type ProxyRequest struct {
	Method string          `json:"method"`
	Path   string          `json:"path"`
	Query  string          `json:"query,omitempty"`
	Body   json.RawMessage `json:"body,omitempty"`
	PageID string          `json:"page_id"`
	SiteID *uuid.UUID      `json:"site_id,omitempty"`
}

// ProxyResponse is what the host relays back to the page.
type ProxyResponse struct {
	Status int             `json:"status"`
	Body   json.RawMessage `json:"body"`
}

// Context is the signed context the plugin backend receives (non-sensitive:
// no token, no email, no phone).
type Context struct {
	Schema         string     `json:"schema"`
	InstallationID uuid.UUID  `json:"installation_id"`
	PluginID       string     `json:"plugin_id"`
	PageID         string     `json:"page_id"`
	UserID         uuid.UUID  `json:"user_id"`
	DisplayName    string     `json:"display_name"`
	Role           string     `json:"role"`
	TenantScopeID  uuid.UUID  `json:"tenant_scope_id"`
	SiteID         *uuid.UUID `json:"site_id,omitempty"`
	Locale         string     `json:"locale"`
	RequestID      string     `json:"request_id"`
	Nonce          string     `json:"nonce"`
	IssuedAt       time.Time  `json:"issued_at"`
	ExpiresAt      time.Time  `json:"expires_at"`
}

// Signer signs proxied calls with the installation key.
type Signer struct {
	InstallationID uuid.UUID
	PrivateKey     ed25519.PrivateKey
}

// KeyID is the installation key fingerprint (first 16 hex of sha256).
func (signer Signer) KeyID() string {
	public, _ := signer.PrivateKey.Public().(ed25519.PublicKey)
	sum := sha256.Sum256(public)
	return hex.EncodeToString(sum[:8])
}

// PublicKey is the installation public key (base64url) the administrator
// gives the plugin backend.
func (signer Signer) PublicKey() string {
	public, _ := signer.PrivateKey.Public().(ed25519.PublicKey)
	return base64.RawURLEncoding.EncodeToString(public)
}

// SignatureMessage is what the signature covers.
func SignatureMessage(method, target string, body []byte, contextHeader string) []byte {
	sum := sha256.Sum256(body)
	return []byte(ProxySignatureDomain + "\n" + method + "\n" + target + "\n" + hex.EncodeToString(sum[:]) + "\n" + contextHeader)
}

// validProxyRequest checks the request the host sends.
func validProxyRequest(request ProxyRequest) bool {
	if !proxyMethods[request.Method] || !proxyPathPattern.MatchString(request.Path) || strings.Contains(request.Path, "//") ||
		len(request.Query) > 1024 || !proxyQueryPattern.MatchString(request.Query) || request.PageID == "" ||
		len(request.PageID) > 32 {
		return false
	}
	for _, segment := range strings.Split(request.Path, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	if len(request.Body) > 0 && (request.Method == http.MethodGet || !json.Valid(request.Body)) {
		return false
	}
	return true
}

// Forwarder sends the proxied request; the default only dials public
// addresses and never follows redirects.
type Forwarder interface {
	Do(*http.Request) (*http.Response, error)
}

func newPublicForwarder() Forwarder {
	dialer := &net.Dialer{Timeout: 5 * time.Second, Control: func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		addr, err := netip.ParseAddr(host)
		if err != nil || !publicAddress(addr) {
			return errors.New("plugin backend resolves to a non-public address")
		}
		return nil
	}}
	return &http.Client{Timeout: 15 * time.Second,
		Transport: &http.Transport{DialContext: dialer.DialContext, Proxy: nil, TLSHandshakeTimeout: 5 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second, MaxResponseHeaderBytes: 32 << 10, MaxIdleConnsPerHost: 4},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func publicAddress(addr netip.Addr) bool {
	addr = addr.Unmap()
	return addr.IsValid() && addr.IsGlobalUnicast() && !addr.IsPrivate() && !addr.IsLoopback() &&
		!addr.IsLinkLocalUnicast() && !addr.IsMulticast() && !addr.IsUnspecified() &&
		!netip.MustParsePrefix("100.64.0.0/10").Contains(addr) && !netip.MustParsePrefix("198.18.0.0/15").Contains(addr) &&
		!netip.MustParsePrefix("fc00::/7").Contains(addr)
}

// forward builds, signs and sends one proxied call.
func forward(ctx context.Context, client Forwarder, signer Signer, apiBase string, request ProxyRequest,
	callContext Context) (ProxyResponse, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return ProxyResponse{}, err
	}
	callContext.Schema, callContext.InstallationID = ContextSchema, signer.InstallationID
	callContext.Nonce = base64.RawURLEncoding.EncodeToString(nonce)
	callContext.ExpiresAt = callContext.IssuedAt.Add(proxyContextTTL)
	encoded, err := json.Marshal(callContext)
	if err != nil {
		return ProxyResponse{}, err
	}
	contextHeader := base64.RawURLEncoding.EncodeToString(encoded)
	target := request.Path
	if request.Query != "" {
		target += "?" + request.Query
	}
	body := []byte(request.Body)
	outbound, err := http.NewRequestWithContext(ctx, request.Method, apiBase+target, bytes.NewReader(body))
	if err != nil {
		return ProxyResponse{}, err
	}
	signature := ed25519.Sign(signer.PrivateKey, SignatureMessage(request.Method, target, body, contextHeader))
	outbound.Header.Set("X-Cdnca-Plugin-Context", contextHeader)
	outbound.Header.Set("X-Cdnca-Plugin-Signature", base64.RawURLEncoding.EncodeToString(signature))
	outbound.Header.Set("X-Cdnca-Plugin-Key-Id", signer.KeyID())
	outbound.Header.Set("Accept", "application/json")
	if len(body) > 0 {
		outbound.Header.Set("Content-Type", "application/json")
	}
	response, err := client.Do(outbound)
	if err != nil {
		return ProxyResponse{}, fmt.Errorf("plugin backend unreachable: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		return ProxyResponse{}, errors.New("plugin backend redirected")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxProxyResponseBytes+1))
	if err != nil || len(raw) > maxProxyResponseBytes {
		return ProxyResponse{}, errors.New("plugin backend response too large")
	}
	// Only JSON goes back to the page (no HTML, no scripts, no headers).
	if len(bytes.TrimSpace(raw)) == 0 {
		raw = []byte("null")
	}
	if !json.Valid(raw) {
		return ProxyResponse{}, errors.New("plugin backend response is not JSON")
	}
	return ProxyResponse{Status: response.StatusCode, Body: raw}, nil
}

// limiter is a fixed-window per-key request limit.
type limiter struct {
	mu      sync.Mutex
	window  time.Duration
	limit   int
	buckets map[string]limiterBucket
}

type limiterBucket struct {
	start time.Time
	count int
}

func (l *limiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.buckets == nil {
		l.buckets = map[string]limiterBucket{}
	}
	bucket := l.buckets[key]
	if now.Sub(bucket.start) >= l.window {
		bucket = limiterBucket{start: now}
	}
	if bucket.count >= l.limit {
		return false
	}
	bucket.count++
	l.buckets[key] = bucket
	if len(l.buckets) > 10000 {
		for candidate, value := range l.buckets {
			if now.Sub(value.start) >= l.window {
				delete(l.buckets, candidate)
			}
		}
	}
	return true
}
