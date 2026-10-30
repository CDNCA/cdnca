package originauthverifier

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/originauthcontrol"
)

const (
	ResultAccepted             = "accepted"
	ResultCredentialRejected   = "credential_rejected"
	ResultProviderUnavailable  = "provider_unavailable"
	ResultInvalidConfiguration = "invalid_configuration"
)

var (
	ErrCredentialRejected   = errors.New("origin credential rejected")
	ErrProviderUnavailable  = errors.New("origin provider unavailable")
	ErrInvalidConfiguration = errors.New("invalid origin verifier configuration")
)

type Probe struct {
	Endpoint string
	Region   string
	Bucket   string
	Object   string
	Enabled  bool
}

func (probe Probe) String() string   { return fmt.Sprintf("{enabled:%t}", probe.Enabled) }
func (probe Probe) GoString() string { return probe.String() }
func (probe Probe) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Enabled bool `json:"enabled"`
	}{Enabled: probe.Enabled})
}

type Config struct {
	S3                    Probe
	OSS                   Probe
	COS                   Probe
	ConnectTimeout        time.Duration
	TLSHandshakeTimeout   time.Duration
	ResponseHeaderTimeout time.Duration
	RequestTimeout        time.Duration
	MaxResponseBytes      int64
	MaxAttempts           int
	MaxConcurrent         int
	RootCAs               *x509.CertPool
	Now                   func() time.Time
}

func (config Config) String() string {
	encoded, _ := config.MarshalJSON()
	return string(encoded)
}

func (config Config) GoString() string { return config.String() }

func (config Config) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		S3                    Probe         `json:"s3"`
		OSS                   Probe         `json:"oss"`
		COS                   Probe         `json:"cos"`
		ConnectTimeout        time.Duration `json:"connect_timeout"`
		TLSHandshakeTimeout   time.Duration `json:"tls_handshake_timeout"`
		ResponseHeaderTimeout time.Duration `json:"response_header_timeout"`
		RequestTimeout        time.Duration `json:"request_timeout"`
		MaxResponseBytes      int64         `json:"max_response_bytes"`
		MaxAttempts           int           `json:"max_attempts"`
		MaxConcurrent         int           `json:"max_concurrent"`
	}{
		S3: config.S3, OSS: config.OSS, COS: config.COS,
		ConnectTimeout: config.ConnectTimeout, TLSHandshakeTimeout: config.TLSHandshakeTimeout,
		ResponseHeaderTimeout: config.ResponseHeaderTimeout, RequestTimeout: config.RequestTimeout,
		MaxResponseBytes: config.MaxResponseBytes, MaxAttempts: config.MaxAttempts,
		MaxConcurrent: config.MaxConcurrent,
	})
}

type Result struct {
	Code      string
	Retryable bool
}

type Resolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

type dialContextFunc func(context.Context, string, string) (net.Conn, error)

type providerVerifier interface {
	verify(context.Context, Probe, originauthcontrol.CredentialSecret, *http.Client) error
}

type providerVerifierFunc func(context.Context, Probe, originauthcontrol.CredentialSecret, *http.Client) error

func (function providerVerifierFunc) verify(
	ctx context.Context,
	probe Probe,
	credential originauthcontrol.CredentialSecret,
	client *http.Client,
) error {
	return function(ctx, probe, credential, client)
}
