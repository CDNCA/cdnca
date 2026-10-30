package originauthverifier

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/originauthcontrol"
)

const (
	testOSSAccessKey = "test-only-oss-access-key-id"
	testOSSSecretKey = "test-only-oss-secret-not-real"
	testOSSToken     = "test-only-oss-session-token"
)

func TestOSSVerifierSignsOnlyConfiguredHeadObject(t *testing.T) {
	recorder := &ossRoundTripper{responses: []ossResponse{{status: http.StatusOK}}}
	err := newOSSVerifier(2).verify(t.Context(), validOSSProbe(), validOSSCredentials(), controlledProviderClient(recorder))
	if err != nil {
		t.Fatalf("verify() error = %v", err)
	}

	requests := recorder.Requests()
	if len(requests) != 1 {
		t.Fatalf("request count = %d, want 1", len(requests))
	}
	request := requests[0]
	if request.Method != http.MethodHead {
		t.Fatalf("method = %q, want HEAD", request.Method)
	}
	if request.URL.Scheme != "https" || request.URL.Host != "oss-cn-hangzhou.aliyuncs.com" ||
		request.URL.Path != "/cdnca-probe/read-only/health.txt" {
		t.Fatal("request did not target the configured path-style probe")
	}
	authorization := request.Header.Get("Authorization")
	if !strings.HasPrefix(authorization, "OSS4-HMAC-SHA256 Credential="+testOSSAccessKey+"/") ||
		!strings.Contains(authorization, "/cn-hangzhou/oss/aliyun_v4_request") {
		t.Fatal("Authorization header does not contain an OSS SDK V4 credential scope")
	}
	if request.Header.Get("Date") == "" || request.Header.Get("X-Oss-Content-Sha256") == "" {
		t.Fatal("missing required OSS V4 headers")
	}
	if request.Header.Get("X-Oss-Security-Token") != testOSSToken {
		t.Fatal("session token header missing")
	}
	for _, secret := range []string{testOSSAccessKey, testOSSSecretKey, testOSSToken} {
		if strings.Contains(request.URL.String(), secret) {
			t.Fatal("request URL contains credential material")
		}
	}
	if strings.Contains(authorization, testOSSSecretKey) || strings.Contains(authorization, testOSSToken) {
		t.Fatal("Authorization header contains secret material")
	}
}

func TestOSSVerifierRejectsInvalidConfigurationWithoutRequest(t *testing.T) {
	validProbe := validOSSProbe()
	validCredentials := validOSSCredentials()
	tests := []struct {
		name        string
		probe       Probe
		credentials originauthcontrol.CredentialSecret
		client      *http.Client
	}{
		{name: "disabled", probe: mutateOSSProbe(validProbe, func(value *Probe) { value.Enabled = false }), credentials: validCredentials, client: &http.Client{}},
		{name: "non tls", probe: mutateOSSProbe(validProbe, func(value *Probe) { value.Endpoint = "http://oss.example.test" }), credentials: validCredentials, client: &http.Client{}},
		{name: "endpoint path", probe: mutateOSSProbe(validProbe, func(value *Probe) { value.Endpoint += "/api" }), credentials: validCredentials, client: &http.Client{}},
		{name: "wrong endpoint region", probe: mutateOSSProbe(validProbe, func(value *Probe) { value.Region = "cn-beijing" }), credentials: validCredentials, client: &http.Client{}},
		{name: "invalid region", probe: mutateOSSProbe(validProbe, func(value *Probe) { value.Region = "CN Hangzhou" }), credentials: validCredentials, client: &http.Client{}},
		{name: "invalid bucket", probe: mutateOSSProbe(validProbe, func(value *Probe) { value.Bucket = "Bad_Bucket" }), credentials: validCredentials, client: &http.Client{}},
		{name: "object traversal", probe: mutateOSSProbe(validProbe, func(value *Probe) { value.Object = "a/../probe" }), credentials: validCredentials, client: &http.Client{}},
		{name: "missing access key", probe: validProbe, credentials: mutateOSSCredential(validCredentials, func(value *originauthcontrol.CredentialSecret) { value.AccessKeyID = "" }), client: &http.Client{}},
		{name: "missing secret", probe: validProbe, credentials: mutateOSSCredential(validCredentials, func(value *originauthcontrol.CredentialSecret) { value.SecretAccessKey = "" }), client: &http.Client{}},
		{name: "credential control", probe: validProbe, credentials: mutateOSSCredential(validCredentials, func(value *originauthcontrol.CredentialSecret) { value.SecretAccessKey += "\n" }), client: &http.Client{}},
		{name: "nil client", probe: validProbe, credentials: validCredentials},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := newOSSVerifier(2).verify(t.Context(), test.probe, test.credentials, test.client)
			if !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("verify() error = %v, want ErrInvalidConfiguration", err)
			}
			assertNoOSSSecret(t, err.Error(), test.probe, test.credentials)
		})
	}
}

func TestOSSVerifierRejectsEndpointRegionMismatchBeforeRequest(t *testing.T) {
	probe := validOSSProbe()
	probe.Region = "cn-beijing"
	recorder := &ossRoundTripper{responses: []ossResponse{{status: http.StatusOK}}}
	err := newOSSVerifier(2).verify(t.Context(), probe, validOSSCredentials(), controlledProviderClient(recorder))
	if !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("verify() error = %v, want ErrInvalidConfiguration", err)
	}
	if got := len(recorder.Requests()); got != 0 {
		t.Fatalf("request count = %d, want 0", got)
	}
}

func TestOSSVerifierClassifiesResponsesAndBoundsRetries(t *testing.T) {
	tests := []struct {
		name     string
		response ossResponse
		want     error
		attempts int
	}{
		{name: "invalid access key", response: ossErrorResponse(http.StatusForbidden, "InvalidAccessKeyId"), want: ErrCredentialRejected, attempts: 1},
		{name: "signature mismatch", response: ossErrorResponse(http.StatusForbidden, "SignatureDoesNotMatch"), want: ErrCredentialRejected, attempts: 1},
		{name: "expired token", response: ossErrorResponse(http.StatusForbidden, "SecurityTokenExpired"), want: ErrCredentialRejected, attempts: 1},
		{name: "access denied", response: ossErrorResponse(http.StatusForbidden, "AccessDenied"), want: ErrCredentialRejected, attempts: 1},
		{name: "missing bucket", response: ossErrorResponse(http.StatusNotFound, "NoSuchBucket"), want: ErrInvalidConfiguration, attempts: 1},
		{name: "missing object", response: ossErrorResponse(http.StatusNotFound, "NoSuchKey"), want: ErrInvalidConfiguration, attempts: 1},
		{name: "redirect", response: ossErrorResponse(http.StatusMovedPermanently, "PermanentRedirect"), want: ErrInvalidConfiguration, attempts: 1},
		{name: "throttled", response: ossErrorResponse(http.StatusTooManyRequests, "TooManyRequests"), want: ErrProviderUnavailable, attempts: 2},
		{name: "server error", response: ossErrorResponse(http.StatusServiceUnavailable, "ServiceUnavailable"), want: ErrProviderUnavailable, attempts: 2},
		{name: "transport", response: ossResponse{err: errors.New("sensitive transport failure")}, want: ErrProviderUnavailable, attempts: 2},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := &ossRoundTripper{responses: []ossResponse{test.response}}
			err := newOSSVerifier(2).verify(t.Context(), validOSSProbe(), validOSSCredentials(), controlledProviderClient(recorder))
			if !errors.Is(err, test.want) {
				t.Fatalf("verify() error = %v, want %v", err, test.want)
			}
			if got := len(recorder.Requests()); got != test.attempts {
				t.Fatalf("request count = %d, want %d", got, test.attempts)
			}
			assertNoOSSSecret(t, err.Error(), validOSSProbe(), validOSSCredentials())
			if strings.Contains(err.Error(), "sensitive") {
				t.Fatal("verify() leaked provider response details")
			}
		})
	}
}

func TestOSSVerifierRecoversWithinRetryBudget(t *testing.T) {
	recorder := &ossRoundTripper{responses: []ossResponse{
		ossErrorResponse(http.StatusServiceUnavailable, "ServiceUnavailable"),
		{status: http.StatusOK},
	}}
	err := newOSSVerifier(2).verify(t.Context(), validOSSProbe(), validOSSCredentials(), controlledProviderClient(recorder))
	if err != nil {
		t.Fatalf("verify() error = %v", err)
	}
	if got := len(recorder.Requests()); got != 2 {
		t.Fatalf("request count = %d, want 2", got)
	}
}

func validOSSProbe() Probe {
	return Probe{
		Endpoint: "https://oss-cn-hangzhou.aliyuncs.com",
		Region:   "cn-hangzhou",
		Bucket:   "cdnca-probe",
		Object:   "read-only/health.txt",
		Enabled:  true,
	}
}

func validOSSCredentials() originauthcontrol.CredentialSecret {
	return originauthcontrol.CredentialSecret{
		AccessKeyID:     testOSSAccessKey,
		SecretAccessKey: testOSSSecretKey,
		SessionToken:    testOSSToken,
	}
}

func mutateOSSProbe(value Probe, mutate func(*Probe)) Probe {
	mutate(&value)
	return value
}

func mutateOSSCredential(value originauthcontrol.CredentialSecret, mutate func(*originauthcontrol.CredentialSecret)) originauthcontrol.CredentialSecret {
	mutate(&value)
	return value
}

func assertNoOSSSecret(t *testing.T, value string, probe Probe, credential originauthcontrol.CredentialSecret) {
	t.Helper()
	for _, sensitive := range []string{
		credential.AccessKeyID, credential.SecretAccessKey, credential.SessionToken,
		probe.Endpoint, probe.Bucket, probe.Object,
	} {
		if sensitive != "" && strings.Contains(value, sensitive) {
			t.Fatal("value contains sensitive verifier input")
		}
	}
}

type ossResponse struct {
	status int
	body   string
	err    error
}

func ossErrorResponse(status int, code string) ossResponse {
	return ossResponse{
		status: status,
		body:   fmt.Sprintf(`<Error><Code>%s</Code><Message>sensitive provider body</Message><RequestId>test</RequestId></Error>`, code),
	}
}

type ossRoundTripper struct {
	mu        sync.Mutex
	responses []ossResponse
	requests  []*http.Request
}

func (transport *ossRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	transport.requests = append(transport.requests, request.Clone(request.Context()))
	index := len(transport.requests) - 1
	if index >= len(transport.responses) {
		index = len(transport.responses) - 1
	}
	response := transport.responses[index]
	if response.err != nil {
		return nil, response.err
	}
	return &http.Response{
		StatusCode: response.status,
		Status:     fmt.Sprintf("%d test", response.status),
		Header:     http.Header{"Content-Type": []string{"application/xml"}},
		Body:       io.NopCloser(strings.NewReader(response.body)),
		Request:    request,
	}, nil
}

func (transport *ossRoundTripper) Requests() []*http.Request {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	return append([]*http.Request(nil), transport.requests...)
}
