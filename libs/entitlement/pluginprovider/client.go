package pluginprovider

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"syscall"
	"time"
)

const (
	maxRequestBytes  = 256 << 10
	maxResponseBytes = 1 << 20
	requestTimeout   = 15 * time.Second
	userAgent        = "cdnca-control-api/provider-plugin"
)

// Error codes of the client (stable, safe to store and show).
const (
	CodeInvalidRequest       = "invalid_request"
	CodeUnauthorized         = "unauthorized"
	CodeNotFound             = "not_found"
	CodeRateLimited          = "rate_limited"
	CodeUnavailable          = "unavailable"
	CodeTimeout              = "timeout"
	CodeBlockedAddress       = "blocked_address"
	CodeInvalidResponse      = "invalid_response"
	CodeBadResponseSignature = "bad_response_signature"
)

// Error is a classified call failure. Remote is true when the plugin itself
// answered ok=false with Code (one of ErrorCodes).
type Error struct {
	Code      string
	Remote    bool
	Temporary bool
}

func (e *Error) Error() string { return "provider plugin call failed: " + e.Code }

// CodeOf returns the code of a call error ("" when err is not one).
func CodeOf(err error) string {
	var target *Error
	if errors.As(err, &target) {
		return target.Code
	}
	return ""
}

func failure(code string, temporary bool) *Error { return &Error{Code: code, Temporary: temporary} }

// Signer is the control plane installation identity requests are signed with.
type Signer struct {
	InstallationID string
	PrivateKey     ed25519.PrivateKey
}

// Options let tests reach an httptest server. HTTPClient replaces the
// production client (public addresses only, no proxy, no redirects).
type Options struct {
	HTTPClient *http.Client
	Now        func() time.Time
}

// Client calls one provider plugin.
type Client struct {
	declaration Declaration
	responseKey ed25519.PublicKey
	signer      Signer
	http        *http.Client
	now         func() time.Time
}

func NewClient(declaration Declaration, signer Signer, options Options) (*Client, error) {
	key, ok := declaration.PublicKey()
	if !ok || len(signer.PrivateKey) != ed25519.PrivateKeySize || signer.InstallationID == "" {
		return nil, ErrInvalid
	}
	if _, ok := CanonicalBaseURL(declaration.BaseURL); !ok {
		return nil, ErrInvalid
	}
	client := options.HTTPClient
	if client == nil {
		client = PublicHTTPClient(nil)
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	return &Client{declaration: declaration, responseKey: key, signer: signer, http: client, now: now}, nil
}

// Declaration returns the plugin declaration the client talks to.
func (client *Client) Declaration() Declaration { return client.declaration }

// PublicHTTPClient dials public unicast addresses only (no loopback,
// private, link-local, CGNAT, documentation or reserved ranges, checked at
// connect time against DNS rebinding), never uses a proxy and never follows
// redirects. tlsConfig nil = system roots, TLS 1.2+.
func PublicHTTPClient(tlsConfig *tls.Config) *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second, Control: func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return errBlocked
		}
		parsed, err := netip.ParseAddr(host)
		if err != nil || Blocked(parsed) {
			return errBlocked
		}
		return nil
	}}
	if tlsConfig == nil {
		tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	return &http.Client{Timeout: requestTimeout,
		Transport: &http.Transport{Proxy: nil, DialContext: dialer.DialContext, ForceAttemptHTTP2: true,
			TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: requestTimeout, MaxResponseHeaderBytes: 64 << 10,
			IdleConnTimeout: 30 * time.Second, TLSClientConfig: tlsConfig},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

var errBlocked = errors.New("provider plugin address is not allowed")

var blockedPrefixes = func() []netip.Prefix {
	values := []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15",
		"198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64",
		"2001::/32", "2001:db8::/32", "2002::/16", "fc00::/7"}
	prefixes := make([]netip.Prefix, len(values))
	for index, value := range values {
		prefixes[index] = netip.MustParsePrefix(value)
	}
	return prefixes
}()

// Blocked reports an address the control plane must never connect to.
func Blocked(address netip.Addr) bool {
	address = address.Unmap()
	if !address.IsValid() || address.IsLoopback() || address.IsPrivate() || address.IsUnspecified() ||
		address.IsMulticast() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() ||
		address.IsInterfaceLocalMulticast() {
		return true
	}
	for _, prefix := range blockedPrefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func signWith(client *Client, kind, action, timestamp, nonce string, body []byte) []byte {
	return ed25519.Sign(client.signer.PrivateKey, RequestMessage(client.signer.InstallationID,
		client.declaration.PluginID, kind, action, timestamp, nonce, body))
}

// tamper alters an outgoing request (contract runner negative cases only).
type tamper func(request *http.Request, body []byte, nonce string) []byte

// Call sends one action and decodes envelope data into result (nil = ignore).
func (client *Client) Call(ctx context.Context, kind, action string, request any, result any) error {
	_, err := client.call(ctx, kind, action, request, result, nil, nil)
	return err
}

// Signed is a verified plugin answer as received: the envelope bytes and
// the response signature over them (payment facts keep their digests).
type Signed struct {
	Body      []byte
	Signature []byte
}

// CallSigned is Call that also returns the signed answer.
func (client *Client) CallSigned(ctx context.Context, kind, action string, request any, result any) (Signed, error) {
	var signed Signed
	_, err := client.call(ctx, kind, action, request, result, nil, &signed)
	return signed, err
}

func (client *Client) call(ctx context.Context, kind, action string, request any, result any,
	alter tamper, signed *Signed) (int, error) {
	if ctx == nil || !client.declaration.Has(kind) || !ValidAction(kind, action) {
		return 0, failure(CodeInvalidRequest, false)
	}
	body, err := json.Marshal(request)
	if err != nil || len(body) > maxRequestBytes {
		return 0, failure(CodeInvalidRequest, false)
	}
	var nonceBytes [16]byte
	if _, err := rand.Read(nonceBytes[:]); err != nil {
		return 0, failure(CodeUnavailable, true)
	}
	nonce := hex.EncodeToString(nonceBytes[:])
	timestamp := strconv.FormatInt(client.now().UTC().Unix(), 10)
	outbound, err := http.NewRequestWithContext(ctx, http.MethodPost,
		client.declaration.BaseURL+PathPrefix+kind+"/"+action, nil)
	if err != nil {
		return 0, failure(CodeInvalidRequest, false)
	}
	outbound.Header.Set("Content-Type", "application/json")
	outbound.Header.Set("Accept", "application/json")
	outbound.Header.Set("User-Agent", userAgent)
	outbound.Header.Set(HeaderInstallation, client.signer.InstallationID)
	outbound.Header.Set(HeaderTimestamp, timestamp)
	outbound.Header.Set(HeaderNonce, nonce)
	outbound.Header.Set(HeaderSignature, EncodeSignature(ed25519.Sign(client.signer.PrivateKey,
		RequestMessage(client.signer.InstallationID, client.declaration.PluginID, kind, action, timestamp, nonce, body))))
	if alter != nil {
		body = alter(outbound, body, nonce)
		nonce = outbound.Header.Get(HeaderNonce)
	}
	outbound.Body = io.NopCloser(bytes.NewReader(body))
	outbound.ContentLength = int64(len(body))
	response, err := client.http.Do(outbound)
	if err != nil {
		switch {
		case ctx.Err() != nil:
			return 0, failure(CodeTimeout, true)
		case errors.Is(err, errBlocked):
			return 0, failure(CodeBlockedAddress, false)
		default:
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				return 0, failure(CodeTimeout, true)
			}
			return 0, failure(CodeUnavailable, true)
		}
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return response.StatusCode, failure(CodeUnavailable, true)
	}
	switch {
	case response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden:
		return response.StatusCode, failure(CodeUnauthorized, false)
	case response.StatusCode == http.StatusTooManyRequests:
		return response.StatusCode, failure(CodeRateLimited, true)
	case response.StatusCode >= 500:
		return response.StatusCode, failure(CodeUnavailable, true)
	case response.StatusCode != http.StatusOK || len(raw) > maxResponseBytes:
		return response.StatusCode, failure(CodeInvalidResponse, false)
	}
	signature, ok := DecodeSignature(response.Header.Get(HeaderResponseSignature))
	if !ok || !ed25519.Verify(client.responseKey, ResponseMessage(client.declaration.PluginID, kind, action, nonce, raw),
		signature) {
		return response.StatusCode, failure(CodeBadResponseSignature, false)
	}
	if signed != nil {
		signed.Body, signed.Signature = raw, signature
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var envelope Envelope
	if err := decoder.Decode(&envelope); err != nil || envelope.Protocol != Protocol {
		return response.StatusCode, failure(CodeInvalidResponse, false)
	}
	if !envelope.OK {
		code := "provider_error"
		if envelope.Error != nil {
			code = KnownErrorCode(envelope.Error.Code)
		}
		return response.StatusCode, &Error{Code: code, Remote: true,
			Temporary: code == "rate_limited" || code == "unavailable"}
	}
	if result == nil {
		return response.StatusCode, nil
	}
	if len(envelope.Data) == 0 || json.Unmarshal(envelope.Data, result) != nil {
		return response.StatusCode, failure(CodeInvalidResponse, false)
	}
	return response.StatusCode, nil
}
