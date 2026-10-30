// Package icpquery checks ICP filing status for marketplace supplies that
// require it (docs/marketplace/06-compliance.md §1). It runs on the seller's
// own controller with the seller's own API key; keys never leave this process
// and never appear in errors.
package icpquery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

type Provider string

const (
	ProviderTianAPI Provider = "tianapi"
	ProviderALAPI   Provider = "alapi"
	ProviderCustom  Provider = "custom_http"
)

type Status string

const (
	Filed   Status = "filed"
	Unfiled Status = "unfiled"
)

const (
	responseBodyLimit = 64 << 10
	requestTimeout    = 10 * time.Second
	userAgent         = "cdnca-control-api/icp-query"
	maxKeyLength      = 256
	maxTemplateLength = 1024
)

var (
	ErrInvalidInput = errors.New("icp query input is invalid")
	ErrCredential   = errors.New("icp query provider rejected the credential")
	ErrQuota        = errors.New("icp query provider quota exhausted")
	ErrRateLimited  = errors.New("icp query provider rate limited")
	ErrProvider     = errors.New("icp query provider returned an error")
	ErrTransport    = errors.New("icp query provider unreachable")

	dnsLabelPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
)

// Config is what a seller fills in. Custom fields apply to ProviderCustom only.
type Config struct {
	Provider Provider `json:"provider"`
	APIKey   string   `json:"-"`
	// URLTemplate must be https and contain {domain}; {key} is optional.
	URLTemplate string `json:"url_template,omitempty"`
	// StatusPath is a dot path into the JSON response, e.g. "data.is_icp".
	StatusPath string `json:"status_path,omitempty"`
	// FiledValues lists string forms meaning "filed"; empty means a JSON true,
	// non-zero number or non-empty string other than "false"/"0".
	FiledValues []string `json:"filed_values,omitempty"`
	LicencePath string   `json:"licence_path,omitempty"`
	SubjectPath string   `json:"subject_path,omitempty"`
}

func (c Config) Validate() error {
	if c.APIKey == "" || len(c.APIKey) > maxKeyLength || strings.ContainsAny(c.APIKey, "\r\n") {
		return ErrInvalidInput
	}
	switch c.Provider {
	case ProviderTianAPI, ProviderALAPI:
		return nil
	case ProviderCustom:
		if len(c.URLTemplate) > maxTemplateLength || !strings.Contains(c.URLTemplate, "{domain}") || c.StatusPath == "" {
			return ErrInvalidInput
		}
		probe := strings.NewReplacer("{domain}", "example.com", "{key}", "k").Replace(c.URLTemplate)
		u, err := url.Parse(probe)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
			return ErrInvalidInput
		}
		return nil
	default:
		return ErrInvalidInput
	}
}

type Result struct {
	Domain    string    `json:"domain"` // registrable domain that was checked
	Status    Status    `json:"status"`
	Licence   string    `json:"licence,omitempty"`
	Subject   string    `json:"subject,omitempty"`
	Provider  Provider  `json:"provider"`
	CheckedAt time.Time `json:"checked_at"`
}

type Client struct {
	http    *http.Client
	now     func() time.Time
	tianAPI string
	alAPI   string
}

// New returns a client whose dialer refuses loopback, private and link-local
// targets, so a seller-supplied custom URL cannot reach internal services.
func New() *Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second, Control: refusePrivate}
	transport := &http.Transport{DialContext: dialer.DialContext, TLSHandshakeTimeout: 5 * time.Second, MaxIdleConns: 4}
	return &Client{
		http:    &http.Client{Timeout: requestTimeout, Transport: transport, CheckRedirect: noRedirect},
		now:     time.Now,
		tianAPI: "https://apis.tianapi.com/icp/index",
		alAPI:   "https://v3.alapi.cn/api/icp",
	}
}

func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

func refusePrivate(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return err
	}
	ip = ip.Unmap()
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() || ip.IsMulticast() || netip.MustParsePrefix("100.64.0.0/10").Contains(ip) {
		return ErrTransport
	}
	return nil
}

// RegistrableDomain maps a hostname to the domain ICP filing is recorded on.
func RegistrableDomain(hostname string) (string, error) {
	value := strings.TrimSuffix(strings.TrimSpace(hostname), ".")
	if value == "" || strings.Contains(value, "*") {
		return "", ErrInvalidInput
	}
	ascii, err := idna.Lookup.ToASCII(value)
	if err != nil {
		return "", ErrInvalidInput
	}
	ascii = strings.ToLower(ascii)
	if len(ascii) > 253 {
		return "", ErrInvalidInput
	}
	for _, label := range strings.Split(ascii, ".") {
		if !dnsLabelPattern.MatchString(label) {
			return "", ErrInvalidInput
		}
	}
	root, err := publicsuffix.EffectiveTLDPlusOne(ascii)
	if err != nil {
		return "", ErrInvalidInput
	}
	return root, nil
}

func (c *Client) Query(ctx context.Context, cfg Config, hostname string) (Result, error) {
	if err := cfg.Validate(); err != nil {
		return Result{}, err
	}
	domain, err := RegistrableDomain(hostname)
	if err != nil {
		return Result{}, err
	}
	var target string
	switch cfg.Provider {
	case ProviderTianAPI:
		target = c.tianAPI + "?" + url.Values{"key": {cfg.APIKey}, "domain": {domain}}.Encode()
	case ProviderALAPI:
		target = c.alAPI + "?" + url.Values{"token": {cfg.APIKey}, "domain": {domain}}.Encode()
	case ProviderCustom:
		target = strings.NewReplacer("{domain}", url.QueryEscape(domain), "{key}", url.QueryEscape(cfg.APIKey)).Replace(cfg.URLTemplate)
	}
	body, status, err := c.get(ctx, target)
	if err != nil {
		return Result{}, err
	}
	var result Result
	switch cfg.Provider {
	case ProviderTianAPI:
		result, err = parseTianAPI(body)
	case ProviderALAPI:
		result, err = parseALAPI(body, status)
	case ProviderCustom:
		result, err = parseCustom(body, status, cfg)
	}
	if err != nil {
		return Result{}, err
	}
	result.Domain, result.Provider, result.CheckedAt = domain, cfg.Provider, c.now().UTC()
	return result, nil
}

func (c *Client) get(ctx context.Context, target string) ([]byte, int, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, 0, ErrInvalidInput
	}
	request.Header.Set("User-Agent", userAgent)
	request.Header.Set("Accept", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		// Never wrap: *url.Error carries the full URL including the key.
		return nil, 0, ErrTransport
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, responseBodyLimit+1))
	if err != nil || len(body) > responseBodyLimit {
		return nil, 0, ErrProvider
	}
	return body, response.StatusCode, nil
}

func decodeObject(body []byte) (map[string]any, error) {
	var value map[string]any
	if err := json.Unmarshal(body, &value); err != nil {
		return nil, fmt.Errorf("%w: response is not a JSON object", ErrProvider)
	}
	return value, nil
}
