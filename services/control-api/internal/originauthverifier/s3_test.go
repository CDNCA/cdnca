package originauthverifier

import (
	"context"
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
	testS3AccessKey = "AKIDEXAMPLE"
	testS3SecretKey = "test-secret-not-real"
	testS3Token     = "test-session-token-not-real"
)

func TestS3VerifierSignsOnlyConfiguredHeadObject(t *testing.T) {
	recorder := &s3RoundTripper{responses: []s3Response{{status: http.StatusOK}}}
	verifier := s3Verifier(2)
	err := verifier.verify(t.Context(), validS3Probe(), validS3Credentials(), &http.Client{Transport: recorder})
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
	if request.URL.Scheme != "https" || request.URL.Host != "s3.us-east-1.amazonaws.com" ||
		request.URL.EscapedPath() != "/cdnca-probe/read-only/health.txt" {
		t.Fatalf("request target = %s://%s%s, want configured path-style object", request.URL.Scheme, request.URL.Host, request.URL.EscapedPath())
	}
	authorization := request.Header.Get("Authorization")
	if !strings.HasPrefix(authorization, "AWS4-HMAC-SHA256 Credential="+testS3AccessKey+"/") ||
		!strings.Contains(authorization, "/us-east-1/s3/aws4_request") {
		t.Fatalf("Authorization header does not contain an AWS SDK SigV4 credential scope")
	}
	if request.Header.Get("X-Amz-Date") == "" || request.Header.Get("X-Amz-Content-Sha256") == "" {
		t.Fatalf("missing required SigV4 headers")
	}
	if strings.Contains(authorization, testS3SecretKey) {
		t.Fatal("SigV4 header contains the secret access key")
	}
}

func TestS3VerifierSupportsCompatiblePathStyleAndSessionToken(t *testing.T) {
	probe := validS3Probe()
	probe.Endpoint = "https://objects.example.test"
	probe.Region = "custom-1"
	probe.Bucket = "isolated-probe"
	probe.Object = "health/object with space"
	recorder := &s3RoundTripper{responses: []s3Response{{status: http.StatusOK}}}

	err := s3Verifier(1).verify(t.Context(), probe, validS3Credentials(), &http.Client{Transport: recorder})
	if err != nil {
		t.Fatalf("verify() error = %v", err)
	}
	request := recorder.Requests()[0]
	if request.URL.Host != "objects.example.test" || request.URL.EscapedPath() != "/isolated-probe/health/object%20with%20space" {
		t.Fatalf("compatible request target = %s, want path-style configured object", request.URL.String())
	}
	if got := request.Header.Get("X-Amz-Security-Token"); got != testS3Token {
		t.Fatalf("session token header missing")
	}
	if !strings.Contains(request.Header.Get("Authorization"), "x-amz-security-token") {
		t.Fatalf("session token is not covered by SigV4 signed headers")
	}
}

func TestS3VerifierRejectsInvalidConfigurationWithoutRequest(t *testing.T) {
	validProbe := validS3Probe()
	validCredentials := validS3Credentials()
	tests := []struct {
		name        string
		probe       Probe
		credentials originauthcontrol.CredentialSecret
		client      *http.Client
	}{
		{name: "disabled", probe: func() Probe { value := validProbe; value.Enabled = false; return value }(), credentials: validCredentials, client: &http.Client{}},
		{name: "missing endpoint", probe: func() Probe { value := validProbe; value.Endpoint = ""; return value }(), credentials: validCredentials, client: &http.Client{}},
		{name: "non tls", probe: func() Probe { value := validProbe; value.Endpoint = "http://s3.example.test"; return value }(), credentials: validCredentials, client: &http.Client{}},
		{name: "endpoint user info", probe: func() Probe { value := validProbe; value.Endpoint = "https://user@s3.example.test"; return value }(), credentials: validCredentials, client: &http.Client{}},
		{name: "endpoint path", probe: func() Probe { value := validProbe; value.Endpoint = "https://s3.example.test/api"; return value }(), credentials: validCredentials, client: &http.Client{}},
		{name: "endpoint query", probe: func() Probe {
			value := validProbe
			value.Endpoint = "https://s3.example.test?secret=value"
			return value
		}(), credentials: validCredentials, client: &http.Client{}},
		{name: "invalid region", probe: func() Probe { value := validProbe; value.Region = "US EAST 1"; return value }(), credentials: validCredentials, client: &http.Client{}},
		{name: "invalid bucket", probe: func() Probe { value := validProbe; value.Bucket = "Bad_Bucket"; return value }(), credentials: validCredentials, client: &http.Client{}},
		{name: "missing object", probe: func() Probe { value := validProbe; value.Object = ""; return value }(), credentials: validCredentials, client: &http.Client{}},
		{name: "absolute object", probe: func() Probe { value := validProbe; value.Object = "/health"; return value }(), credentials: validCredentials, client: &http.Client{}},
		{name: "object control", probe: func() Probe { value := validProbe; value.Object = "health\nleak"; return value }(), credentials: validCredentials, client: &http.Client{}},
		{name: "missing access key", probe: validProbe, credentials: func() originauthcontrol.CredentialSecret {
			value := validCredentials
			value.AccessKeyID = ""
			return value
		}(), client: &http.Client{}},
		{name: "missing secret", probe: validProbe, credentials: func() originauthcontrol.CredentialSecret {
			value := validCredentials
			value.SecretAccessKey = ""
			return value
		}(), client: &http.Client{}},
		{name: "credential control", probe: validProbe, credentials: func() originauthcontrol.CredentialSecret {
			value := validCredentials
			value.SecretAccessKey += "\n"
			return value
		}(), client: &http.Client{}},
		{name: "nil client", probe: validProbe, credentials: validCredentials},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := s3Verifier(2).verify(t.Context(), test.probe, test.credentials, test.client)
			if !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("verify() error = %v, want ErrInvalidConfiguration", err)
			}
			assertNoS3Secret(t, err.Error(), test.probe, test.credentials)
		})
	}
}

func TestS3VerifierRejectsInvalidRetryBound(t *testing.T) {
	for _, attempts := range []int{0, 4} {
		t.Run(fmt.Sprintf("attempts-%d", attempts), func(t *testing.T) {
			err := s3Verifier(attempts).verify(
				t.Context(), validS3Probe(), validS3Credentials(), &http.Client{Transport: &s3RoundTripper{}},
			)
			if !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("verify() error = %v, want ErrInvalidConfiguration", err)
			}
		})
	}
}

func TestS3VerifierClassifiesProviderResponsesWithoutLeaks(t *testing.T) {
	tests := []struct {
		name   string
		status int
		code   string
		want   error
	}{
		{name: "invalid access key", status: http.StatusForbidden, code: "InvalidAccessKeyId", want: ErrCredentialRejected},
		{name: "signature mismatch", status: http.StatusForbidden, code: "SignatureDoesNotMatch", want: ErrCredentialRejected},
		{name: "expired token", status: http.StatusBadRequest, code: "ExpiredToken", want: ErrCredentialRejected},
		{name: "access denied", status: http.StatusForbidden, code: "AccessDenied", want: ErrCredentialRejected},
		{name: "unauthorized", status: http.StatusUnauthorized, want: ErrCredentialRejected},
		{name: "missing bucket", status: http.StatusNotFound, code: "NoSuchBucket", want: ErrInvalidConfiguration},
		{name: "missing object", status: http.StatusNotFound, code: "NoSuchKey", want: ErrInvalidConfiguration},
		{name: "wrong region", status: http.StatusBadRequest, code: "AuthorizationHeaderMalformed", want: ErrInvalidConfiguration},
		{name: "redirect", status: http.StatusMovedPermanently, code: "PermanentRedirect", want: ErrInvalidConfiguration},
		{name: "throttled", status: http.StatusTooManyRequests, code: "SlowDown", want: ErrProviderUnavailable},
		{name: "server error", status: http.StatusServiceUnavailable, code: "ServiceUnavailable", want: ErrProviderUnavailable},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body := ""
			if test.code != "" {
				body = fmt.Sprintf(`<Error><Code>%s</Code><Message>sensitive upstream %s %s %s</Message></Error>`,
					test.code, testS3SecretKey, validS3Probe().Endpoint, validS3Probe().Object)
			}
			recorder := &s3RoundTripper{responses: []s3Response{{status: test.status, body: body}}}
			err := s3Verifier(1).verify(t.Context(), validS3Probe(), validS3Credentials(), &http.Client{Transport: recorder})
			if !errors.Is(err, test.want) {
				t.Fatalf("verify() error = %v, want %v", err, test.want)
			}
			assertNoS3Secret(t, err.Error(), validS3Probe(), validS3Credentials())
			if strings.Contains(err.Error(), "sensitive upstream") ||
				test.code != "" && strings.Contains(err.Error(), test.code) {
				t.Fatalf("verify() leaked provider response details")
			}
		})
	}
}

func TestS3VerifierBoundsRetriesAndRedactsTransportErrors(t *testing.T) {
	probe := validS3Probe()
	credentials := validS3Credentials()
	tests := []struct {
		name     string
		response s3Response
	}{
		{name: "transport", response: s3Response{err: fmt.Errorf("dial %s using %s for %s", probe.Endpoint, credentials.SecretAccessKey, probe.Object)}},
		{name: "throttled", response: s3Response{status: http.StatusTooManyRequests, body: `<Error><Code>SlowDown</Code><Message>sensitive</Message></Error>`}},
		{name: "unavailable", response: s3Response{status: http.StatusServiceUnavailable, body: `<Error><Code>ServiceUnavailable</Code><Message>sensitive</Message></Error>`}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := &s3RoundTripper{responses: []s3Response{test.response}}
			err := s3Verifier(2).verify(t.Context(), probe, credentials, &http.Client{Transport: recorder})
			if !errors.Is(err, ErrProviderUnavailable) {
				t.Fatalf("verify() error = %v, want ErrProviderUnavailable", err)
			}
			if got := len(recorder.Requests()); got != 2 {
				t.Fatalf("request count = %d, want bounded 2", got)
			}
			assertNoS3Secret(t, err.Error(), probe, credentials)
		})
	}
}

func TestS3VerifierDoesNotRetryCredentialRejection(t *testing.T) {
	recorder := &s3RoundTripper{responses: []s3Response{
		{status: http.StatusForbidden, body: `<Error><Code>SignatureDoesNotMatch</Code><Message>sensitive</Message></Error>`},
		{status: http.StatusOK},
	}}
	err := s3Verifier(3).verify(t.Context(), validS3Probe(), validS3Credentials(), &http.Client{Transport: recorder})
	if !errors.Is(err, ErrCredentialRejected) {
		t.Fatalf("verify() error = %v, want ErrCredentialRejected", err)
	}
	if got := len(recorder.Requests()); got != 1 {
		t.Fatalf("request count = %d, want 1", got)
	}
}

func TestS3VerifierMapsContextFailureWithoutDetails(t *testing.T) {
	probe := validS3Probe()
	credentials := validS3Credentials()
	recorder := &s3RoundTripper{responses: []s3Response{{err: context.DeadlineExceeded}}}
	err := s3Verifier(1).verify(t.Context(), probe, credentials, &http.Client{Transport: recorder})
	if !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("verify() error = %v, want ErrProviderUnavailable", err)
	}
	assertNoS3Secret(t, err.Error(), probe, credentials)
}

func validS3Probe() Probe {
	return Probe{
		Endpoint: "https://s3.us-east-1.amazonaws.com",
		Region:   "us-east-1",
		Bucket:   "cdnca-probe",
		Object:   "read-only/health.txt",
		Enabled:  true,
	}
}

func validS3Credentials() originauthcontrol.CredentialSecret {
	return originauthcontrol.CredentialSecret{
		AccessKeyID:     testS3AccessKey,
		SecretAccessKey: testS3SecretKey,
		SessionToken:    testS3Token,
	}
}

func assertNoS3Secret(t *testing.T, value string, probe Probe, credentials originauthcontrol.CredentialSecret) {
	t.Helper()
	for _, sensitive := range []string{
		credentials.AccessKeyID, credentials.SecretAccessKey, credentials.SessionToken,
		probe.Endpoint, probe.Bucket, probe.Object,
	} {
		if sensitive != "" && strings.Contains(value, sensitive) {
			t.Fatalf("value contains sensitive verifier input")
		}
	}
}

type s3Response struct {
	status int
	body   string
	err    error
}

type s3RoundTripper struct {
	mu        sync.Mutex
	responses []s3Response
	requests  []*http.Request
}

func (transport *s3RoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	transport.requests = append(transport.requests, request.Clone(request.Context()))
	index := len(transport.requests) - 1
	if len(transport.responses) == 0 {
		return nil, errors.New("unexpected request")
	}
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

func (transport *s3RoundTripper) Requests() []*http.Request {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	return append([]*http.Request(nil), transport.requests...)
}
