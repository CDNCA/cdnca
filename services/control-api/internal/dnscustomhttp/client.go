// Package dnscustomhttp is the client of the "自定义 HTTP 接口" DNS provider
// (provider_type custom_http): an operator's own
// DNS system behind one HTTPS endpoint, spoken to with the signed JSON
// protocol of docs/dns/custom-http-provider.md.
//
// This client verifies TLS, signs the request body (HMAC-SHA256 over
// timestamp, nonce and body digest, so a captured request cannot be replayed
// with another body), never follows redirects, bounds the response, and
// refuses to connect to loopback, private, link-local or reserved addresses
// at dial time (no SSRF into the control plane's network, no DNS rebinding).
package dnscustomhttp

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

const (
	ProviderType = "custom_http"
	// Protocol is sent in every request and must be echoed by the endpoint.
	Protocol = "cdnca.dns-custom-http/v1"

	HeaderTimestamp = "X-Cdnca-Timestamp"
	HeaderNonce     = "X-Cdnca-Nonce"
	HeaderSignature = "X-Cdnca-Signature"

	maxResponseBytes = 1 << 20
	maxRecords       = 10000
	requestTimeout   = 15 * time.Second
	userAgent        = "cdnca-control-api/dns-custom-http"
)

// Credential field names (stored encrypted like every DNS credential).
const (
	FieldEndpoint = "endpoint"
	FieldSecret   = "secret"
)

var (
	ErrInvalidCredentials = errors.New("custom HTTP DNS credentials are invalid")
	ErrBlockedAddress     = errors.New("custom HTTP DNS endpoint address is not allowed")
	// ErrRejected: the endpoint answered with ok=false (code in RemoteError).
	ErrRejected     = errors.New("custom HTTP DNS endpoint rejected the request")
	ErrUnauthorized = errors.New("custom HTTP DNS endpoint rejected the signature")
	ErrUnavailable  = errors.New("custom HTTP DNS endpoint is unavailable")
	ErrMalformed    = errors.New("custom HTTP DNS endpoint answered malformed data")
	ErrTimeout      = errors.New("custom HTTP DNS endpoint timed out")
	ErrNotFound     = errors.New("custom HTTP DNS record not found")
	ErrRateLimited  = errors.New("custom HTTP DNS endpoint is rate limited")
)

// RemoteError carries the endpoint's short error code (never shown verbatim
// beyond the code; the message is dropped).
type RemoteError struct {
	Code string
	base error
}

// Rejected returns the ErrRejected error carrying an endpoint code (used by
// other endpoint clients sharing these sentinels).
func Rejected(code string) error { return &RemoteError{Code: code, base: ErrRejected} }

func (e *RemoteError) Error() string { return e.base.Error() + ": " + e.Code }
func (e *RemoteError) Unwrap() error { return e.base }

// Record is one DNS record of the zone. Line is a unified line name
// (默认/电信/联通/移动/境外, "" = 默认); Name is the fully qualified owner
// without the trailing dot.
type Record struct {
	ID    string `json:"id,omitempty"`
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
	TTL   uint32 `json:"ttl"`
	Line  string `json:"line,omitempty"`
}

// Credentials validates and returns the endpoint URL and secret.
func Credentials(fields map[string]string) (*url.URL, string, error) {
	return credentials(fields, Blocked)
}

// ValidShape checks the credential fields without the address policy (the
// client enforces it when connecting); stored credentials are re-checked with
// it on every use.
func ValidShape(fields map[string]string) bool {
	_, _, err := credentials(fields, func(netip.Addr) bool { return false })
	return err == nil
}

func credentials(fields map[string]string, blocked func(netip.Addr) bool) (*url.URL, string, error) {
	if len(fields) != 2 {
		return nil, "", ErrInvalidCredentials
	}
	raw, secret := fields[FieldEndpoint], fields[FieldSecret]
	endpoint, err := parseEndpoint(raw, blocked)
	if err != nil {
		return nil, "", err
	}
	if len(secret) < 16 || len(secret) > 512 || !printable(secret) {
		return nil, "", ErrInvalidCredentials
	}
	return endpoint, secret, nil
}

// ParseEndpoint accepts an https URL without credentials, fragment or
// literal blocked address; the host's resolved addresses are checked again
// at every dial.
func ParseEndpoint(raw string) (*url.URL, error) { return parseEndpoint(raw, Blocked) }

func parseEndpoint(raw string, blocked func(netip.Addr) bool) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || len(raw) > 2048 || parsed.Scheme != "https" || parsed.User != nil || parsed.Fragment != "" ||
		parsed.Opaque != "" || parsed.RawQuery != "" || !printable(raw) {
		return nil, ErrInvalidCredentials
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "" || host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return nil, ErrInvalidCredentials
	}
	if address, err := netip.ParseAddr(host); err == nil && blocked(address) {
		return nil, ErrBlockedAddress
	}
	return parsed, nil
}

func printable(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

var blockedPrefixes = func() []netip.Prefix {
	values := []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15",
		"198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64",
		"2001::/32", "2001:db8::/32", "2002::/16"}
	prefixes := make([]netip.Prefix, len(values))
	for index, value := range values {
		prefixes[index] = netip.MustParsePrefix(value)
	}
	return prefixes
}()

// Blocked: loopback, private, link-local (cloud metadata), CGNAT, multicast,
// documentation, NAT64/6to4/Teredo and reserved addresses.
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

// Client talks to one endpoint.
type Client struct {
	endpoint *url.URL
	secret   []byte
	http     *http.Client
	now      func() time.Time
}

// Options let tests reach an httptest server: Blocked replaces the address
// policy, TLS the trust roots.
type Options struct {
	Blocked func(netip.Addr) bool
	TLS     *tls.Config
	Now     func() time.Time
}

func New(fields map[string]string, options Options) (*Client, error) {
	blocked := options.Blocked
	if blocked == nil {
		blocked = Blocked
	}
	endpoint, secret, err := credentials(fields, blocked)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, Control: func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return ErrBlockedAddress
		}
		parsed, err := netip.ParseAddr(host)
		if err != nil || blocked(parsed) {
			return ErrBlockedAddress
		}
		return nil
	}}
	transport := &http.Transport{Proxy: nil, DialContext: dialer.DialContext, ForceAttemptHTTP2: true,
		TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: requestTimeout, MaxResponseHeaderBytes: 64 << 10,
		IdleConnTimeout: 30 * time.Second, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	if options.TLS != nil {
		transport.TLSClientConfig = options.TLS.Clone()
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	return &Client{endpoint: endpoint, secret: []byte(secret), now: now, http: &http.Client{Transport: transport,
		Timeout: requestTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

// Close clears the secret and idle connections.
func (client *Client) Close() {
	if client == nil {
		return
	}
	clear(client.secret)
	client.http.CloseIdleConnections()
}

// Sign returns the signature of one request: hex HMAC-SHA256 over
// "<protocol>\n<timestamp>\n<nonce>\n<hex sha256(body)>". Endpoints verify it
// and reject a timestamp more than 300 seconds off and a reused nonce.
func Sign(secret []byte, timestamp, nonce string, body []byte) string {
	digest := sha256.Sum256(body)
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(Protocol + "\n" + timestamp + "\n" + nonce + "\n" + hex.EncodeToString(digest[:])))
	return hex.EncodeToString(mac.Sum(nil))
}

type envelope struct {
	Protocol string                 `json:"protocol"`
	OK       bool                   `json:"ok"`
	Error    *struct{ Code string } `json:"error"`
	Data     json.RawMessage        `json:"data"`
}

func (client *Client) call(ctx context.Context, action string, params map[string]any, result any) error {
	payload := map[string]any{"protocol": Protocol, "action": action}
	for key, value := range params {
		payload[key] = value
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return ErrMalformed
	}
	var nonceBytes [16]byte
	if _, err := rand.Read(nonceBytes[:]); err != nil {
		return ErrUnavailable
	}
	timestamp := strconv.FormatInt(client.now().UTC().Unix(), 10)
	nonce := hex.EncodeToString(nonceBytes[:])
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return ErrInvalidCredentials
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", userAgent)
	request.Header.Set(HeaderTimestamp, timestamp)
	request.Header.Set(HeaderNonce, nonce)
	request.Header.Set(HeaderSignature, Sign(client.secret, timestamp, nonce, body))
	response, err := client.http.Do(request)
	if err != nil {
		switch {
		case ctx.Err() != nil:
			return ctx.Err()
		case errors.Is(err, ErrBlockedAddress):
			return ErrBlockedAddress
		case errors.Is(err, context.DeadlineExceeded) || isTimeout(err):
			return ErrTimeout
		default:
			return ErrUnavailable
		}
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return ErrUnavailable
	}
	switch {
	case response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden:
		return ErrUnauthorized
	case response.StatusCode == http.StatusTooManyRequests:
		return ErrRateLimited
	case response.StatusCode >= 500:
		return ErrUnavailable
	case response.StatusCode != http.StatusOK || len(raw) > maxResponseBytes:
		return ErrMalformed
	}
	var decoded envelope
	if err := json.Unmarshal(raw, &decoded); err != nil || decoded.Protocol != Protocol {
		return ErrMalformed
	}
	if !decoded.OK {
		code := "error"
		if decoded.Error != nil && validCode(decoded.Error.Code) {
			code = decoded.Error.Code
		}
		if code == "not_found" {
			return ErrNotFound
		}
		return &RemoteError{Code: code, base: ErrRejected}
	}
	if result == nil {
		return nil
	}
	if len(decoded.Data) == 0 || json.Unmarshal(decoded.Data, result) != nil {
		return ErrMalformed
	}
	return nil
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func validCode(code string) bool {
	if code == "" || len(code) > 64 {
		return false
	}
	for _, character := range code {
		if !(character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '_') {
			return false
		}
	}
	return true
}

// Verify proves the endpoint is reachable, speaks the protocol and accepts
// the secret.
func (client *Client) Verify(ctx context.Context) error {
	return client.call(ctx, "verify", nil, nil)
}

// ListRecords returns the zone's records, of one owner when name is set.
func (client *Client) ListRecords(ctx context.Context, zone, name string) ([]Record, error) {
	params := map[string]any{"zone": zone}
	if name != "" {
		params["name"] = name
	}
	var data struct {
		Records []Record `json:"records"`
	}
	if err := client.call(ctx, "list_records", params, &data); err != nil {
		return nil, err
	}
	if len(data.Records) > maxRecords {
		return nil, ErrMalformed
	}
	seen := make(map[string]struct{}, len(data.Records))
	for index, record := range data.Records {
		record.Name = strings.ToLower(strings.TrimSuffix(record.Name, "."))
		record.Type = strings.ToUpper(record.Type)
		if !validID(record.ID) || record.Name == "" || len(record.Value) > 4096 || record.TTL == 0 {
			return nil, ErrMalformed
		}
		if _, duplicate := seen[record.ID]; duplicate {
			return nil, ErrMalformed
		}
		seen[record.ID] = struct{}{}
		data.Records[index] = record
	}
	return data.Records, nil
}

// CreateRecord creates a record and returns its id.
func (client *Client) CreateRecord(ctx context.Context, zone string, record Record) (string, error) {
	record.ID = ""
	var data struct {
		ID string `json:"id"`
	}
	if err := client.call(ctx, "create_record", map[string]any{"zone": zone, "record": record}, &data); err != nil {
		return "", err
	}
	if !validID(data.ID) {
		return "", ErrMalformed
	}
	return data.ID, nil
}

// UpdateRecord replaces the record with id.
func (client *Client) UpdateRecord(ctx context.Context, zone string, record Record) error {
	if !validID(record.ID) {
		return ErrInvalidCredentials
	}
	return client.call(ctx, "update_record", map[string]any{"zone": zone, "record": record}, nil)
}

// DeleteRecord deletes the record with id; a missing record is ErrNotFound.
func (client *Client) DeleteRecord(ctx context.Context, zone, id string) error {
	if !validID(id) {
		return ErrInvalidCredentials
	}
	return client.call(ctx, "delete_record", map[string]any{"zone": zone, "id": id}, nil)
}

func validID(id string) bool {
	return id != "" && len(id) <= 256 && printable(id)
}
