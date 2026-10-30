package errorpageobjectstore

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

const (
	maxCACertificateBytes = 1 << 20
	maxConfiguredObject   = 64 << 20
)

var (
	ErrInvalidConfig = errors.New("invalid error page object store config")
	ErrInvalidKey    = errors.New("invalid error page object key")
	ErrInvalidObject = errors.New("invalid error page object")

	regionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,62}$`)
	bucketPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	keyPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]*$`)
)

type Config struct {
	Endpoint              string                  `json:"endpoint"`
	Region                string                  `json:"region"`
	Bucket                string                  `json:"bucket"`
	Prefix                string                  `json:"prefix"`
	Credentials           aws.CredentialsProvider `json:"-"`
	CACertificatePEM      []byte                  `json:"-"`
	ConnectTimeout        time.Duration           `json:"connect_timeout"`
	TLSHandshakeTimeout   time.Duration           `json:"tls_handshake_timeout"`
	ResponseHeaderTimeout time.Duration           `json:"response_header_timeout"`
	RequestTimeout        time.Duration           `json:"request_timeout"`
	MaxObjectSize         int64                   `json:"max_object_size"`
	MaxAttempts           int                     `json:"max_attempts"`
}

type safeConfig struct {
	Endpoint              string        `json:"endpoint"`
	Region                string        `json:"region"`
	Bucket                string        `json:"bucket"`
	Prefix                string        `json:"prefix"`
	ConnectTimeout        time.Duration `json:"connect_timeout"`
	TLSHandshakeTimeout   time.Duration `json:"tls_handshake_timeout"`
	ResponseHeaderTimeout time.Duration `json:"response_header_timeout"`
	RequestTimeout        time.Duration `json:"request_timeout"`
	MaxObjectSize         int64         `json:"max_object_size"`
	MaxAttempts           int           `json:"max_attempts"`
}

func (config Config) String() string {
	encoded, _ := json.Marshal(config.safe())
	return string(encoded)
}

func (config Config) GoString() string { return config.String() }

func (config Config) MarshalJSON() ([]byte, error) { return json.Marshal(config.safe()) }

func (config Config) safe() safeConfig {
	return safeConfig{
		Endpoint: safeEndpoint(config.Endpoint), Region: config.Region, Bucket: config.Bucket, Prefix: config.Prefix,
		ConnectTimeout: config.ConnectTimeout, TLSHandshakeTimeout: config.TLSHandshakeTimeout,
		ResponseHeaderTimeout: config.ResponseHeaderTimeout, RequestTimeout: config.RequestTimeout,
		MaxObjectSize: config.MaxObjectSize, MaxAttempts: config.MaxAttempts,
	}
}

func safeEndpoint(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "<invalid>"
	}
	return strings.ToLower(parsed.Scheme) + "://" + parsed.Host
}

type validatedConfig struct {
	Config
	endpoint *url.URL
	roots    *x509.CertPool
}

func validateConfig(config Config) (validatedConfig, error) {
	endpoint, err := validateEndpoint(config.Endpoint)
	if err != nil {
		return validatedConfig{}, configError("endpoint")
	}
	if !regionPattern.MatchString(config.Region) {
		return validatedConfig{}, configError("region")
	}
	if !validBucket(config.Bucket) {
		return validatedConfig{}, configError("bucket")
	}
	if err := validatePrefix(config.Prefix); err != nil {
		return validatedConfig{}, configError("prefix")
	}
	if nilCredentialsProvider(config.Credentials) {
		return validatedConfig{}, configError("credentials")
	}
	if !validTimeout(config.ConnectTimeout) || !validTimeout(config.TLSHandshakeTimeout) ||
		!validTimeout(config.ResponseHeaderTimeout) || config.RequestTimeout < 100*time.Millisecond ||
		config.RequestTimeout > 5*time.Minute || config.RequestTimeout < config.ConnectTimeout ||
		config.RequestTimeout < config.TLSHandshakeTimeout || config.RequestTimeout < config.ResponseHeaderTimeout {
		return validatedConfig{}, configError("timeouts")
	}
	if config.MaxObjectSize < 1 || config.MaxObjectSize > maxConfiguredObject {
		return validatedConfig{}, configError("max_object_size")
	}
	if config.MaxAttempts < 1 || config.MaxAttempts > 5 {
		return validatedConfig{}, configError("max_attempts")
	}
	roots, err := certificatePool(config.CACertificatePEM)
	if err != nil {
		return validatedConfig{}, configError("ca_certificate")
	}
	config.CACertificatePEM = bytes.Clone(config.CACertificatePEM)
	return validatedConfig{Config: config, endpoint: endpoint, roots: roots}, nil
}

func nilCredentialsProvider(provider aws.CredentialsProvider) bool {
	if provider == nil {
		return true
	}
	value := reflect.ValueOf(provider)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func validateEndpoint(raw string) (*url.URL, error) {
	if raw == "" || strings.ContainsAny(raw, "\r\n\t") {
		return nil, ErrInvalidConfig
	}
	endpoint, err := url.Parse(raw)
	if err != nil || endpoint.Opaque != "" || endpoint.User != nil || endpoint.Host == "" ||
		endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" || endpoint.RawFragment != "" ||
		endpoint.RawPath != "" || endpoint.Path != "" && endpoint.Path != "/" {
		return nil, ErrInvalidConfig
	}
	scheme := strings.ToLower(endpoint.Scheme)
	if scheme != "https" && scheme != "http" {
		return nil, ErrInvalidConfig
	}
	hostname := endpoint.Hostname()
	if hostname == "" || !isASCIIHost(hostname) {
		return nil, ErrInvalidConfig
	}
	if scheme == "http" {
		ip := net.ParseIP(hostname)
		if ip == nil || !ip.IsLoopback() {
			return nil, ErrInvalidConfig
		}
	}
	if port := endpoint.Port(); port != "" {
		value, err := net.LookupPort("tcp", port)
		if err != nil || value < 1 || value > 65535 {
			return nil, ErrInvalidConfig
		}
	}
	endpoint.Scheme = scheme
	endpoint.Path = ""
	return endpoint, nil
}

func isASCIIHost(host string) bool {
	if strings.HasSuffix(host, ".") || strings.Contains(host, "%") {
		return false
	}
	for _, char := range host {
		if char > 127 || char <= 32 {
			return false
		}
	}
	return true
}

func validBucket(bucket string) bool {
	if !bucketPattern.MatchString(bucket) || strings.Contains(bucket, "..") || net.ParseIP(bucket) != nil {
		return false
	}
	for _, label := range strings.Split(bucket, ".") {
		if label == "" || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
	}
	return true
}

func validatePrefix(prefix string) error {
	if len(prefix) > 128 || strings.HasSuffix(prefix, "/") {
		return ErrInvalidKey
	}
	return validateKeySegments(prefix)
}

func validateObjectKey(key string) error {
	if len(key) > 512 {
		return ErrInvalidKey
	}
	return validateKeySegments(key)
}

func validateKeySegments(key string) error {
	if !keyPattern.MatchString(key) || strings.ContainsAny(key, `%\\?#`) {
		return ErrInvalidKey
	}
	for _, segment := range strings.Split(key, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return ErrInvalidKey
		}
	}
	return nil
}

func validTimeout(timeout time.Duration) bool {
	return timeout >= 10*time.Millisecond && timeout <= time.Minute
}

func certificatePool(certificatePEM []byte) (*x509.CertPool, error) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}
	roots = roots.Clone()
	if len(certificatePEM) == 0 {
		return roots, nil
	}
	if len(certificatePEM) > maxCACertificateBytes {
		return nil, ErrInvalidConfig
	}
	rest := certificatePEM
	count := 0
	for len(bytes.TrimSpace(rest)) > 0 {
		block, remaining := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, ErrInvalidConfig
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, ErrInvalidConfig
		}
		roots.AddCert(certificate)
		count++
		rest = remaining
	}
	if count == 0 {
		return nil, ErrInvalidConfig
	}
	return roots, nil
}

func newHTTPClient(config validatedConfig) *http.Client {
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: config.ConnectTimeout, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: config.roots.Clone()},
		TLSHandshakeTimeout:   config.TLSHandshakeTimeout,
		ResponseHeaderTimeout: config.ResponseHeaderTimeout,
		ExpectContinueTimeout: time.Second,
		MaxIdleConns:          32,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       90 * time.Second,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   config.RequestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("object store redirects disabled")
		},
	}
}

func configError(field string) error {
	return fmt.Errorf("%s: %w", field, ErrInvalidConfig)
}
