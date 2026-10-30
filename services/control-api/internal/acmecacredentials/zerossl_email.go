package acmecacredentials

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"time"
)

// fix-certops：按 ZeroSSL 邮箱自动获取 EAB（与 acme.sh 同一公开接口：
// POST form email=… → {"success":true,"eab_kid":"…","eab_hmac_key":"…"}）。
// 取到后走 Save 加密保存，HMAC 密钥不回给调用方。
const ZeroSSLEABEndpoint = "https://api.zerossl.com/acme/eab-credentials-email"

var ErrEABFetchFailed = errors.New("acme_ca_credentials_eab_fetch_failed")

// ZeroSSLEABFetcher calls the ZeroSSL EAB endpoint. Endpoint and Client are
// injectable for tests (a fake server); production uses ZeroSSLEABEndpoint.
type ZeroSSLEABFetcher struct {
	Endpoint string
	Client   *http.Client
}

func NewZeroSSLEABFetcher() *ZeroSSLEABFetcher {
	return &ZeroSSLEABFetcher{Endpoint: ZeroSSLEABEndpoint, Client: &http.Client{
		Timeout:       15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// ValidEABEmail is a single plain address (no display name), at most 254 bytes.
func ValidEABEmail(email string) bool {
	if email == "" || len(email) > 254 || strings.TrimSpace(email) != email {
		return false
	}
	parsed, err := mail.ParseAddress(email)
	return err == nil && parsed.Name == "" && parsed.Address == email
}

// Fetch returns the EAB key ID and the base64url HMAC key ZeroSSL issues for email.
func (f *ZeroSSLEABFetcher) Fetch(ctx context.Context, email string) (keyID, hmacKey string, err error) {
	if f == nil || f.Client == nil || !strings.HasPrefix(f.Endpoint, "https://") {
		return "", "", ErrUnavailable
	}
	if !ValidEABEmail(email) {
		return "", "", ErrInvalidInput
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, f.Endpoint,
		strings.NewReader(url.Values{"email": {email}}.Encode()))
	if err != nil {
		return "", "", ErrUnavailable
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	response, err := f.Client.Do(request)
	if err != nil {
		return "", "", fmt.Errorf("%w: request", ErrEABFetchFailed)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	if err != nil || response.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("%w: status %d", ErrEABFetchFailed, response.StatusCode)
	}
	var result struct {
		Success    bool   `json:"success"`
		EABKID     string `json:"eab_kid"`
		EABHMACKey string `json:"eab_hmac_key"`
	}
	if json.Unmarshal(body, &result) != nil || !result.Success || result.EABKID == "" || result.EABHMACKey == "" {
		return "", "", fmt.Errorf("%w: response", ErrEABFetchFailed)
	}
	return result.EABKID, result.EABHMACKey, nil
}
