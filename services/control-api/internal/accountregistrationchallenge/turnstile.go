package accountregistrationchallenge

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
)

const (
	defaultTurnstileEndpoint = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
	defaultTurnstileTimeout  = 5 * time.Second
	maximumTurnstileTimeout  = 10 * time.Second
	defaultTurnstileMaxBytes = 16 << 10
	maximumTurnstileMaxBytes = 64 << 10
	maximumTurnstileCABytes  = 1 << 20
)

type TurnstileConfig struct {
	Endpoint         string
	Secret           string
	ExpectedHostname string
	ExpectedAction   string
	CAFile           string
	Client           *http.Client
	Timeout          time.Duration
	MaxResponseBytes int64
}

type TurnstileVerifier struct {
	endpoint         url.URL
	secret           string
	expectedHostname string
	expectedAction   string
	client           *http.Client
	timeout          time.Duration
	maxResponseBytes int64
}

type turnstileResponse struct {
	Success     bool     `json:"success"`
	Hostname    string   `json:"hostname"`
	Action      string   `json:"action"`
	ChallengeTS string   `json:"challenge_ts"`
	ErrorCodes  []string `json:"error-codes"`
}

func NewTurnstileVerifier(config TurnstileConfig) (*TurnstileVerifier, error) {
	explicitEndpoint := config.Endpoint != ""
	if config.Endpoint == "" {
		config.Endpoint = defaultTurnstileEndpoint
	}
	if config.Timeout == 0 {
		config.Timeout = defaultTurnstileTimeout
	}
	if config.MaxResponseBytes == 0 {
		config.MaxResponseBytes = defaultTurnstileMaxBytes
	}
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil ||
		endpoint.RawQuery != "" || endpoint.Fragment != "" || len(config.Secret) < 16 ||
		!validTurnstileMetadata(config.ExpectedHostname) || !validTurnstileMetadata(config.ExpectedAction) ||
		config.Timeout <= 0 || config.Timeout > maximumTurnstileTimeout ||
		config.MaxResponseBytes < 1024 || config.MaxResponseBytes > maximumTurnstileMaxBytes ||
		config.Client != nil || config.CAFile != "" && !explicitEndpoint {
		return nil, ErrInvalidConfig
	}
	roots, err := loadTurnstileRoots(config.CAFile)
	if err != nil {
		return nil, ErrInvalidConfig
	}
	transport := &http.Transport{
		Proxy: nil,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			RootCAs:    roots,
		},
		TLSHandshakeTimeout:   config.Timeout,
		ResponseHeaderTimeout: config.Timeout,
	}
	config.Client = &http.Client{
		Transport: transport,
		Timeout:   config.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("Turnstile redirects are disabled")
		},
	}
	return &TurnstileVerifier{
		endpoint: *endpoint, secret: config.Secret, expectedHostname: config.ExpectedHostname,
		expectedAction: config.ExpectedAction, client: config.Client, timeout: config.Timeout,
		maxResponseBytes: config.MaxResponseBytes,
	}, nil
}

func loadTurnstileRoots(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, nil
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrInvalidConfig
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
		info.Size() < 1 || info.Size() > maximumTurnstileCABytes || info.Mode().Perm()&0o400 == 0 ||
		info.Mode().Perm()&0o022 != 0 {
		return nil, ErrInvalidConfig
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrInvalidConfig
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) ||
		openedInfo.Size() < 1 || openedInfo.Size() > maximumTurnstileCABytes ||
		openedInfo.Mode().Perm()&0o400 == 0 || openedInfo.Mode().Perm()&0o022 != 0 {
		return nil, ErrInvalidConfig
	}
	encoded, err := io.ReadAll(io.LimitReader(file, maximumTurnstileCABytes+1))
	if err != nil || len(encoded) == 0 || len(encoded) > maximumTurnstileCABytes {
		return nil, ErrInvalidConfig
	}
	roots := x509.NewCertPool()
	remaining := bytes.TrimSpace(encoded)
	count := 0
	for len(remaining) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, ErrInvalidConfig
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, ErrInvalidConfig
		}
		roots.AddCert(certificate)
		count++
		remaining = bytes.TrimSpace(rest)
	}
	if count == 0 {
		return nil, ErrInvalidConfig
	}
	return roots, nil
}

func (verifier *TurnstileVerifier) Verify(ctx context.Context, request HumanVerification) error {
	if verifier == nil || verifier.client == nil || ctx == nil || len(request.Token) < 22 || len(request.Token) > 4096 ||
		strings.TrimSpace(request.Token) != request.Token ||
		strings.IndexFunc(request.Token, func(value rune) bool { return unicode.IsSpace(value) || unicode.IsControl(value) }) >= 0 ||
		request.Source == "" || !metadataPattern.MatchString(request.IdempotencyKey) {
		return ErrHumanInvalid
	}
	values := url.Values{
		"secret": {verifier.secret}, "response": {request.Token}, "remoteip": {request.Source},
		"idempotency_key": {request.IdempotencyKey},
	}
	requestCtx, cancel := context.WithTimeout(ctx, verifier.timeout)
	defer cancel()
	httpRequest, err := http.NewRequestWithContext(requestCtx, http.MethodPost, verifier.endpoint.String(),
		strings.NewReader(values.Encode()))
	if err != nil {
		return ErrHumanUnavailable
	}
	httpRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpRequest.Header.Set("Accept", "application/json")
	response, err := verifier.client.Do(httpRequest)
	if err != nil {
		return ErrHumanUnavailable
	}
	defer response.Body.Close()
	mediaType, parameters, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" || len(parameters) != 0 || response.StatusCode != http.StatusOK {
		return ErrHumanUnavailable
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, verifier.maxResponseBytes+1))
	if err != nil || len(raw) == 0 || int64(len(raw)) > verifier.maxResponseBytes || rejectDuplicateJSONKeys(raw) != nil {
		return ErrHumanUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var result turnstileResponse
	if err := decoder.Decode(&result); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return ErrHumanUnavailable
	}
	if !result.Success {
		return ErrHumanInvalid
	}
	if result.Hostname != verifier.expectedHostname || result.Action != verifier.expectedAction {
		return ErrHumanInvalid
	}
	if _, err := time.Parse(time.RFC3339, result.ChallengeTS); err != nil {
		return ErrHumanInvalid
	}
	return nil
}

func validTurnstileMetadata(value string) bool {
	return value != "" && len(value) <= 253 && strings.TrimSpace(value) == value &&
		strings.IndexFunc(value, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) }) < 0
}

func rejectDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]struct{}{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return ErrHumanUnavailable
				}
				if _, exists := seen[key]; exists {
					return ErrHumanUnavailable
				}
				seen[key] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return ErrHumanUnavailable
		}
	}
	return walk()
}
