package dnsproviderremote

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"testing/iotest"
	"time"
)

func TestHTTPStatusClassificationSurvivesUnreadableOrOversizedBody(t *testing.T) {
	const (
		responseSecret = "sensitive-response-body"
		readSecret     = "sensitive-read-error"
		credential     = "sensitive-credential"
	)
	tests := []struct {
		name       string
		status     int
		unreadable bool
		wantCode   ErrorCode
		wantRetry  time.Duration
		temporary  bool
	}{
		{name: "401 oversized", status: http.StatusUnauthorized, wantCode: CodeCredentialsRejected},
		{name: "403 unreadable", status: http.StatusForbidden, unreadable: true, wantCode: CodeCredentialsRejected},
		{name: "408 oversized", status: http.StatusRequestTimeout, wantCode: CodeTimeout, temporary: true},
		{name: "429 unreadable", status: http.StatusTooManyRequests, unreadable: true, wantCode: CodeRateLimited, wantRetry: 37 * time.Second, temporary: true},
		{name: "502 oversized", status: http.StatusBadGateway, wantCode: CodeUnavailable, temporary: true},
		{name: "302 unreadable", status: http.StatusFound, unreadable: true, wantCode: CodeInvalidResponse},
		{name: "200 oversized", status: http.StatusOK, wantCode: CodeInvalidResponse},
		{name: "201 unreadable", status: http.StatusCreated, unreadable: true, wantCode: CodeInvalidResponse},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := newBoundedHTTPClient(roundTripFunc(func(*http.Request) (*http.Response, error) {
				body := io.NopCloser(strings.NewReader(strings.Repeat(responseSecret, responseBodyLimit)))
				if test.unreadable {
					body = io.NopCloser(iotest.ErrReader(errors.New(readSecret)))
				}
				return &http.Response{
					StatusCode: test.status,
					Header: http.Header{
						"Retry-After": []string{"37"},
						"Location":    []string{"https://example.invalid/credential-capture"},
					},
					Body: body,
				}, nil
			}), time.Second)
			response, err := client.do(context.Background(), http.MethodGet, endpoint{
				baseURL: "https://api.example.test", host: "api.example.test",
			}, "/records", nil, http.Header{"Authorization": []string{"Bearer " + credential}})
			if err == nil {
				err = classifyHTTP(response, remoteProviderTestTime)
			}

			var remoteError *Error
			if !errors.As(err, &remoteError) || remoteError.Code != test.wantCode ||
				remoteError.RetryAfter != test.wantRetry || remoteError.Temporary != test.temporary {
				t.Fatalf("error = %+v, want code=%s retry=%s temporary=%t", err, test.wantCode, test.wantRetry, test.temporary)
			}
			for _, sensitive := range []string{responseSecret, readSecret, credential, "Authorization"} {
				if strings.Contains(err.Error(), sensitive) || strings.Contains(fmt.Sprintf("%+v", err), sensitive) {
					t.Fatalf("error leaked %q: %+v", sensitive, err)
				}
			}
		})
	}
}
