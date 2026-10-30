package dnsacme

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestProviderVerifierDispatcherCloudflareRegression(t *testing.T) {
	const token = "cloudflare-token"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if authorization := r.Header.Get("Authorization"); authorization != "Bearer "+token {
			t.Errorf("Authorization = %q", authorization)
		}
		_, _ = w.Write([]byte(`{"success":true,"result":{"id":"zone-cf","status":"active"}}`))
	}))
	t.Cleanup(server.Close)
	dispatcher := newProviderVerifierDispatcher(
		newCloudflareProviderVerifier(server.URL, server.Client(), time.Second),
		nil,
		nil,
		nil,
		nil,
	)
	if err := dispatcher.VerifyCredentials(context.Background(), "cloudflare", map[string]string{"api_token": token}); err != nil {
		t.Fatalf("VerifyCredentials() error = %v", err)
	}
	if err := dispatcher.Verify(context.Background(), "cloudflare", token); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
}

func TestProviderVerifierDispatcherRejectsInvalidCredentialStructures(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		calls.Add(1)
	}))
	t.Cleanup(server.Close)
	dispatcher := newProviderVerifierDispatcher(
		newCloudflareProviderVerifier(server.URL, server.Client(), time.Second),
		newAliyunProviderVerifier(server.URL, server.Client(), time.Second, time.Now, func() string { return "nonce" }),
		newHuaweiProviderVerifier(server.URL, server.Client(), time.Second, time.Now),
		newDNSPodProviderVerifier(server.URL, server.Client(), time.Second),
		newDNSComProviderVerifier(server.URL, server.Client(), time.Second, time.Now),
	)
	dispatcher.dnsla = newDNSLAProviderVerifier(server.URL, server.Client(), time.Second)
	tests := []struct {
		name         string
		providerType string
		credentials  map[string]string
	}{
		{name: "cloudflare missing", providerType: "cloudflare", credentials: map[string]string{}},
		{name: "cloudflare extra", providerType: "cloudflare", credentials: map[string]string{"api_token": "token", "extra": "value"}},
		{name: "cloudflare empty", providerType: "cloudflare", credentials: map[string]string{"api_token": ""}},
		{name: "aliyun missing id", providerType: "aliyun", credentials: map[string]string{"access_key_secret": "secret"}},
		{name: "aliyun missing secret", providerType: "aliyun", credentials: map[string]string{"access_key_id": "id"}},
		{name: "aliyun extra", providerType: "aliyun", credentials: map[string]string{"access_key_id": "id", "access_key_secret": "secret", "extra": "value"}},
		{name: "aliyun empty id", providerType: "aliyun", credentials: map[string]string{"access_key_id": "", "access_key_secret": "secret"}},
		{name: "aliyun empty secret", providerType: "aliyun", credentials: map[string]string{"access_key_id": "id", "access_key_secret": ""}},
		{name: "aliyun padded", providerType: "aliyun", credentials: map[string]string{"access_key_id": " id", "access_key_secret": "secret"}},
		{name: "huawei missing", providerType: "huawei", credentials: map[string]string{"access_key": "ak"}},
		{name: "huawei extra", providerType: "huawei", credentials: map[string]string{"access_key": "ak", "secret_key": "sk", "region": "cn-north-4", "project_id": huaweiTestProjectID, "endpoint": server.URL}},
		{name: "huawei padded access key", providerType: "huawei", credentials: map[string]string{"access_key": " ak", "secret_key": "sk", "region": "cn-north-4", "project_id": huaweiTestProjectID}},
		{name: "huawei unsafe access key", providerType: "huawei", credentials: map[string]string{"access_key": "ak,value", "secret_key": "sk", "region": "cn-north-4", "project_id": huaweiTestProjectID}},
		{name: "huawei oversized access key", providerType: "huawei", credentials: map[string]string{"access_key": strings.Repeat("a", 129), "secret_key": "sk", "region": "cn-north-4", "project_id": huaweiTestProjectID}},
		{name: "huawei oversized secret", providerType: "huawei", credentials: map[string]string{"access_key": "ak", "secret_key": strings.Repeat("s", 257), "region": "cn-north-4", "project_id": huaweiTestProjectID}},
		{name: "huawei invalid secret", providerType: "huawei", credentials: map[string]string{"access_key": "ak", "secret_key": "sk\nvalue", "region": "cn-north-4", "project_id": huaweiTestProjectID}},
		{name: "huawei arbitrary region", providerType: "huawei", credentials: map[string]string{"access_key": "ak", "secret_key": "sk", "region": "example.invalid", "project_id": huaweiTestProjectID}},
		{name: "huawei invalid project", providerType: "huawei", credentials: map[string]string{"access_key": "ak", "secret_key": "sk", "region": "cn-north-4", "project_id": "not-a-project"}},
		{name: "dnspod missing id", providerType: "dnspod_cn", credentials: map[string]string{"dp_key": "key"}},
		{name: "dnspod missing key", providerType: "dnspod_cn", credentials: map[string]string{"dp_id": "12345"}},
		{name: "dnspod extra", providerType: "dnspod_cn", credentials: map[string]string{"dp_id": "12345", "dp_key": "key", "endpoint": server.URL}},
		{name: "dnspod zero id", providerType: "dnspod_cn", credentials: map[string]string{"dp_id": "0", "dp_key": "key"}},
		{name: "dnspod leading zero id", providerType: "dnspod_cn", credentials: map[string]string{"dp_id": "0123", "dp_key": "key"}},
		{name: "dnspod oversized id", providerType: "dnspod_cn", credentials: map[string]string{"dp_id": strings.Repeat("1", 21), "dp_key": "key"}},
		{name: "dnspod nonnumeric id", providerType: "dnspod_cn", credentials: map[string]string{"dp_id": "123a", "dp_key": "key"}},
		{name: "dnspod empty key", providerType: "dnspod_cn", credentials: map[string]string{"dp_id": "12345", "dp_key": ""}},
		{name: "dnspod oversized key", providerType: "dnspod_cn", credentials: map[string]string{"dp_id": "12345", "dp_key": strings.Repeat("k", 257)}},
		{name: "dnspod key with space", providerType: "dnspod_cn", credentials: map[string]string{"dp_id": "12345", "dp_key": "key value"}},
		{name: "dnspod key with comma", providerType: "dnspod_cn", credentials: map[string]string{"dp_id": "12345", "dp_key": "key,value"}},
		{name: "dnspod key with control", providerType: "dnspod_cn", credentials: map[string]string{"dp_id": "12345", "dp_key": "key\nvalue"}},
		{name: "dnscom missing key", providerType: "dns_com", credentials: map[string]string{"api_secret": "secret"}},
		{name: "dnscom missing secret", providerType: "dns_com", credentials: map[string]string{"api_key": "key"}},
		{name: "dnscom extra", providerType: "dns_com", credentials: map[string]string{"api_key": "key", "api_secret": "secret", "endpoint": server.URL}},
		{name: "dnscom empty key", providerType: "dns_com", credentials: map[string]string{"api_key": "", "api_secret": "secret"}},
		{name: "dnscom empty secret", providerType: "dns_com", credentials: map[string]string{"api_key": "key", "api_secret": ""}},
		{name: "dnscom padded key", providerType: "dns_com", credentials: map[string]string{"api_key": " key", "api_secret": "secret"}},
		{name: "dnscom key pair delimiter", providerType: "dns_com", credentials: map[string]string{"api_key": "key=value", "api_secret": "secret"}},
		{name: "dnscom key field delimiter", providerType: "dns_com", credentials: map[string]string{"api_key": "key&value", "api_secret": "secret"}},
		{name: "dnscom control in secret", providerType: "dns_com", credentials: map[string]string{"api_key": "key", "api_secret": "secret\nvalue"}},
		{name: "dnscom oversized key", providerType: "dns_com", credentials: map[string]string{"api_key": strings.Repeat("k", 129), "api_secret": "secret"}},
		{name: "dnscom oversized secret", providerType: "dns_com", credentials: map[string]string{"api_key": "key", "api_secret": strings.Repeat("s", 257)}},
		{name: "dnsla missing id", providerType: "dns_la", credentials: map[string]string{"api_secret": "secret"}},
		{name: "dnsla missing secret", providerType: "dns_la", credentials: map[string]string{"api_id": "id"}},
		{name: "dnsla extra", providerType: "dns_la", credentials: map[string]string{"api_id": "id", "api_secret": "secret", "endpoint": server.URL}},
		{name: "dnsla empty id", providerType: "dns_la", credentials: map[string]string{"api_id": "", "api_secret": "secret"}},
		{name: "dnsla colon id", providerType: "dns_la", credentials: map[string]string{"api_id": "id:other", "api_secret": "secret"}},
		{name: "dnsla control secret", providerType: "dns_la", credentials: map[string]string{"api_id": "id", "api_secret": "secret\nvalue"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := dispatcher.VerifyCredentials(context.Background(), test.providerType, test.credentials)
			if !errors.Is(err, ErrProviderCredentialsInvalid) {
				t.Fatalf("VerifyCredentials() error = %v", err)
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatalf("invalid credentials made %d upstream requests", calls.Load())
	}
}

func TestProviderVerifierDispatcherHuawei(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "dns.ap-southeast-3.myhuaweicloud.com" {
			t.Errorf("Host = %q", r.Host)
		}
		_, _ = w.Write([]byte(`{"zones":[],"metadata":{"total_count":0}}`))
	}))
	t.Cleanup(server.Close)
	dispatcher := newProviderVerifierDispatcher(
		nil,
		nil,
		newHuaweiProviderVerifier(server.URL, server.Client(), time.Second, time.Now),
		nil,
		nil,
	)
	err := dispatcher.VerifyCredentials(context.Background(), "huawei", map[string]string{
		"access_key": "ak",
		"secret_key": "sk",
		"region":     "ap-southeast-3",
		"project_id": huaweiTestProjectID,
	})
	if err != nil {
		t.Fatalf("VerifyCredentials() error = %v", err)
	}
}

func TestProviderVerifierDispatcherDNSPodCN(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":{"code":"1"},"info":{"user":{}}}`))
	}))
	t.Cleanup(server.Close)
	dispatcher := newProviderVerifierDispatcher(
		nil,
		nil,
		nil,
		newDNSPodProviderVerifier(server.URL, server.Client(), time.Second),
		nil,
	)
	err := dispatcher.VerifyCredentials(context.Background(), "dnspod_cn", map[string]string{
		"dp_id":  "12345",
		"dp_key": "dnspod-key",
	})
	if err != nil {
		t.Fatalf("VerifyCredentials() error = %v", err)
	}
}

func TestProviderVerifierDispatcherDNSCom(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"code":0,"message":"","data":{"total":0,"data":[]}}`))
	}))
	t.Cleanup(server.Close)
	dispatcher := newProviderVerifierDispatcher(
		nil,
		nil,
		nil,
		nil,
		newDNSComProviderVerifier(server.URL, server.Client(), time.Second, time.Now),
	)
	err := dispatcher.VerifyCredentials(context.Background(), "dns_com", map[string]string{
		"api_key":    "dnscom-api-key",
		"api_secret": "dnscom-api-secret",
	})
	if err != nil {
		t.Fatalf("VerifyCredentials() error = %v", err)
	}
}

func TestProviderVerifierDispatcherDNSLA(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"code":200,"data":{"total":0,"results":[]}}`))
	}))
	t.Cleanup(server.Close)
	dispatcher := newProviderVerifierDispatcher(nil, nil, nil, nil, nil)
	dispatcher.dnsla = newDNSLAProviderVerifier(server.URL, server.Client(), time.Second)
	err := dispatcher.VerifyCredentials(context.Background(), "dns_la", map[string]string{
		"api_id":     dnslaTestAPIID,
		"api_secret": dnslaTestAPISecret,
	})
	if err != nil {
		t.Fatalf("VerifyCredentials() error = %v", err)
	}
}

func TestProviderVerifierDispatcherRejectsNilContextBeforeProviderCall(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		calls.Add(1)
	}))
	t.Cleanup(server.Close)
	dispatcher := newProviderVerifierDispatcher(
		newCloudflareProviderVerifier(server.URL, server.Client(), time.Second),
		newAliyunProviderVerifier(server.URL, server.Client(), time.Second, time.Now, func() string { return "nonce" }),
		newHuaweiProviderVerifier(server.URL, server.Client(), time.Second, time.Now),
		newDNSPodProviderVerifier(server.URL, server.Client(), time.Second),
		newDNSComProviderVerifier(server.URL, server.Client(), time.Second, time.Now),
	)
	dispatcher.dnsla = newDNSLAProviderVerifier(server.URL, server.Client(), time.Second)
	tests := []struct {
		name         string
		providerType string
		credentials  map[string]string
	}{
		{name: "cloudflare", providerType: "cloudflare", credentials: map[string]string{"api_token": "cloudflare-token"}},
		{name: "aliyun", providerType: "aliyun", credentials: map[string]string{"access_key_id": "access-key-id", "access_key_secret": "access-key-secret"}},
		{name: "huawei", providerType: "huawei", credentials: map[string]string{"access_key": "ak", "secret_key": "sk", "region": "cn-north-4", "project_id": huaweiTestProjectID}},
		{name: "dnspod_cn", providerType: "dnspod_cn", credentials: map[string]string{"dp_id": dnspodTestID, "dp_key": dnspodTestKey}},
		{name: "dns_com", providerType: "dns_com", credentials: map[string]string{"api_key": dnscomTestAPIKey, "api_secret": dnscomTestAPISecret}},
		{name: "dns_la", providerType: "dns_la", credentials: map[string]string{"api_id": dnslaTestAPIID, "api_secret": dnslaTestAPISecret}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var (
				err        error
				panicValue any
			)
			func() {
				defer func() { panicValue = recover() }()
				err = dispatcher.VerifyCredentials(nil, test.providerType, test.credentials)
			}()
			if panicValue != nil {
				t.Fatalf("VerifyCredentials() panicked: %v", panicValue)
			}
			if err != ErrProviderVerificationUnavailable {
				t.Fatalf("VerifyCredentials() error = %v, want %v", err, ErrProviderVerificationUnavailable)
			}
			if retryAfter := ProviderVerificationRetryAfter(err); retryAfter != "" {
				t.Fatalf("Retry-After = %q, want empty", retryAfter)
			}
		})
	}

	var (
		err        error
		panicValue any
	)
	func() {
		defer func() { panicValue = recover() }()
		err = dispatcher.Verify(nil, "cloudflare", "cloudflare-token")
	}()
	if panicValue != nil {
		t.Fatalf("legacy Verify() panicked: %v", panicValue)
	}
	if err != ErrProviderVerificationUnavailable {
		t.Fatalf("legacy Verify() error = %v, want %v", err, ErrProviderVerificationUnavailable)
	}
	if retryAfter := ProviderVerificationRetryAfter(err); retryAfter != "" {
		t.Fatalf("legacy Retry-After = %q, want empty", retryAfter)
	}
	if calls.Load() != 0 {
		t.Fatalf("nil-context verification made %d upstream requests", calls.Load())
	}
}

func TestProviderVerifierDispatcherNilContextPreservesCredentialPrecedence(t *testing.T) {
	dispatcher := newProviderVerifierDispatcher(nil, nil, nil, nil, nil)
	if err := dispatcher.VerifyCredentials(nil, "cloudflare", map[string]string{}); err != ErrProviderCredentialsInvalid {
		t.Fatalf("invalid credentials error = %v, want %v", err, ErrProviderCredentialsInvalid)
	}
	if err := dispatcher.VerifyCredentials(nil, "dnsdun", map[string]string{"secret": "value"}); err != ErrProviderVerificationUnsupported {
		t.Fatalf("unsupported provider error = %v, want %v", err, ErrProviderVerificationUnsupported)
	}
}

func TestProviderVerifierDispatcherRejectsUnsupportedProvider(t *testing.T) {
	dispatcher := newProviderVerifierDispatcher(nil, nil, nil, nil, nil)
	if err := dispatcher.VerifyCredentials(context.Background(), "dnsdun", map[string]string{"secret": "value"}); !errors.Is(err, ErrProviderVerificationUnsupported) {
		t.Fatalf("VerifyCredentials() error = %v", err)
	}
	if err := dispatcher.Verify(context.Background(), "aliyun", "not-used"); !errors.Is(err, ErrProviderVerificationUnsupported) {
		t.Fatalf("legacy Aliyun Verify() error = %v", err)
	}
}

var _ ProviderVerifier = (*ProviderVerifierDispatcher)(nil)
var _ CredentialProviderVerifier = (*ProviderVerifierDispatcher)(nil)
