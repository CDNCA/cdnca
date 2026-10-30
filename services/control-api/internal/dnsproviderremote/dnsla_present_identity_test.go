package dnsproviderremote

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/acmeworker"
)

func TestDNSLAPresentVerifiesCreatedRecordIdentity(t *testing.T) {
	const (
		apiID           = "dnsla-api-id-sensitive"
		apiSecret       = "dnsla-api-secret-sensitive"
		upstreamMessage = "dnsla-upstream-sensitive-message"
		domainID        = "zone-dnsla-created"
		recordID        = "record-dnsla-created"
	)
	record := func(overrides map[string]any) map[string]any {
		value := map[string]any{
			"id": recordID, "domainId": domainID, "host": testRelative,
			"type": 16, "data": testValue, "ttl": 600,
		}
		for name, override := range overrides {
			value[name] = override
		}
		return value
	}
	tests := []struct {
		name           string
		listStatus     int
		listBody       any
		listRaw        string
		retryAfter     string
		blockList      bool
		cancelList     bool
		timeout        time.Duration
		wantCode       ErrorCode
		wantTemporary  bool
		wantRetryAfter time.Duration
		wantContextErr error
		wantSuccess    bool
	}{
		{name: "matching list succeeds", listBody: []map[string]any{record(nil)}, wantSuccess: true},
		{name: "wrong domain", listBody: []map[string]any{record(map[string]any{"domainId": "zone-dnsla-other"})}, wantCode: CodeInvalidResponse},
		{name: "wrong record id", listBody: []map[string]any{record(map[string]any{"id": "record-dnsla-other"})}, wantCode: CodeInvalidResponse},
		{name: "wrong host", listBody: []map[string]any{record(map[string]any{"host": "other-owner"})}, wantCode: CodeInvalidResponse},
		{name: "wrong type", listBody: []map[string]any{record(map[string]any{"type": 1})}, wantCode: CodeInvalidResponse},
		{name: "wrong data", listBody: []map[string]any{record(map[string]any{"data": testOtherValue})}, wantCode: CodeInvalidResponse},
		{name: "created record absent", listBody: []map[string]any{record(map[string]any{"id": "record-dnsla-other"})}, wantCode: CodeInvalidResponse},
		{name: "duplicate record", listBody: []map[string]any{record(nil), record(nil)}, wantCode: CodeRecordMismatch},
		{name: "oversized list", listRaw: strings.Repeat("x", responseBodyLimit+1), wantCode: CodeInvalidResponse},
		{name: "malformed list", listRaw: `{"code":200,"data":{"total":1,"results":[}`, wantCode: CodeInvalidResponse},
		{name: "http 401", listStatus: http.StatusUnauthorized, listRaw: upstreamMessage, wantCode: CodeCredentialsRejected},
		{name: "http 403", listStatus: http.StatusForbidden, listRaw: upstreamMessage, wantCode: CodeCredentialsRejected},
		{name: "http 408", listStatus: http.StatusRequestTimeout, listRaw: upstreamMessage, wantCode: CodeTimeout, wantTemporary: true, wantContextErr: context.DeadlineExceeded},
		{name: "http 429", listStatus: http.StatusTooManyRequests, listRaw: upstreamMessage, retryAfter: "37", wantCode: CodeRateLimited, wantTemporary: true, wantRetryAfter: 37 * time.Second},
		{name: "http 5xx", listStatus: http.StatusBadGateway, listRaw: upstreamMessage, wantCode: CodeUnavailable, wantTemporary: true},
		{name: "redirect", listStatus: http.StatusFound, listRaw: upstreamMessage, wantCode: CodeInvalidResponse},
		{name: "internal timeout", blockList: true, timeout: 20 * time.Millisecond, wantCode: CodeTimeout, wantTemporary: true, wantContextErr: context.DeadlineExceeded},
		{name: "caller cancellation", blockList: true, cancelList: true, wantCode: CodeCancelled, wantContextErr: context.Canceled},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var domainCalls, createCalls, listCalls, deleteCalls atomic.Int32
			ctx := context.Background()
			cancel := func() {}
			if test.cancelList {
				ctx, cancel = context.WithCancel(ctx)
			}
			defer cancel()
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				username, password, ok := r.BasicAuth()
				if r.Host != "api.dns.la" || !ok || username != apiID || password != apiSecret {
					t.Errorf("unexpected DNS.LA authentication")
				}
				switch {
				case r.Method == http.MethodGet && r.URL.Path == "/api/domain":
					domainCalls.Add(1)
					if r.URL.Query().Get("domain") != testZone {
						t.Errorf("domain query = %s", r.URL.RawQuery)
					}
					writeTestJSON(t, w, map[string]any{"code": 200, "data": map[string]any{
						"id": domainID, "domain": testZone + ".",
					}})
				case r.Method == http.MethodPost && r.URL.Path == "/api/record":
					createCalls.Add(1)
					var body struct {
						DomainID string `json:"domainId"`
						Type     int    `json:"type"`
						Host     string `json:"host"`
						Data     string `json:"data"`
						TTL      int    `json:"ttl"`
					}
					if err := decodeJSONBody(r, &body); err != nil || body.DomainID != domainID || body.Type != 16 ||
						body.Host != testRelative || body.Data != testValue || body.TTL != 600 {
						t.Errorf("create body = %+v", body)
					}
					writeTestJSON(t, w, map[string]any{"code": 200, "data": map[string]any{"id": recordID}})
				case r.Method == http.MethodGet && r.URL.Path == "/api/recordList":
					listCalls.Add(1)
					query := r.URL.Query()
					if query.Get("pageIndex") != "1" || query.Get("pageSize") != "100" ||
						query.Get("domainId") != domainID || query.Get("type") != "16" ||
						query.Get("host") != testRelative || query.Get("data") != testValue {
						t.Errorf("record list query = %s", r.URL.RawQuery)
					}
					if test.cancelList {
						cancel()
					}
					if test.blockList {
						<-r.Context().Done()
						return
					}
					if test.retryAfter != "" {
						w.Header().Set("Retry-After", test.retryAfter)
					}
					if test.listStatus != 0 {
						w.WriteHeader(test.listStatus)
					}
					if test.listRaw != "" {
						_, _ = w.Write([]byte(test.listRaw))
					} else {
						writeTestJSON(t, w, map[string]any{"code": 200, "data": map[string]any{
							"total": len(test.listBody.([]map[string]any)), "results": test.listBody,
						}})
					}
				case r.Method == http.MethodDelete && r.URL.Path == "/api/record":
					deleteCalls.Add(1)
					writeTestJSON(t, w, map[string]any{"code": 200, "data": nil})
				default:
					t.Errorf("unexpected DNS.LA request %s %s", r.Method, r.URL.String())
					w.WriteHeader(http.StatusNotFound)
				}
			})
			timeout := test.timeout
			if timeout == 0 {
				timeout = time.Second
			}
			adapter, source := newProviderTestAdapter(t, ProviderConfig{
				ProviderType: providerDNSLA, ZoneName: testZone,
				Credentials: map[string]string{"api_id": apiID, "api_secret": apiSecret},
			}, handler, timeout)

			handle, err := adapter.PresentTXT(ctx, testChallenge())
			if test.wantSuccess {
				if err != nil {
					t.Fatalf("PresentTXT: %v", err)
				}
				requireHandle(t, handle, providerDNSLA, domainID, recordID)
			} else {
				if handle != (acmeworker.RemoteTXTHandle{}) {
					t.Fatalf("failed present returned handle %+v", handle)
				}
				assertRemoteError(t, err, test.wantCode)
				var remoteError *Error
				if !errors.As(err, &remoteError) || remoteError.Temporary != test.wantTemporary ||
					remoteError.RetryAfter != test.wantRetryAfter {
					t.Fatalf("error = %+v, want temporary=%v retry-after=%v", err, test.wantTemporary, test.wantRetryAfter)
				}
				if test.wantContextErr != nil && !errors.Is(err, test.wantContextErr) {
					t.Fatalf("error %v does not match %v", err, test.wantContextErr)
				}
				for _, sensitive := range []string{apiID, apiSecret, "Authorization", upstreamMessage} {
					if strings.Contains(err.Error(), sensitive) || strings.Contains(fmt.Sprintf("%+v", err), sensitive) {
						t.Fatalf("error leaked %q: %+v", sensitive, err)
					}
				}
			}
			if domainCalls.Load() != 1 || createCalls.Load() != 1 || listCalls.Load() != 1 || deleteCalls.Load() != 0 {
				t.Fatalf("calls domain/create/list/delete=%d/%d/%d/%d, want 1/1/1/0", domainCalls.Load(), createCalls.Load(), listCalls.Load(), deleteCalls.Load())
			}
			if !source.credentialsCleared() {
				t.Fatal("provider credentials were retained")
			}
		})
	}
}

func decodeJSONBody(request *http.Request, target any) error {
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return err
	}
	return decodeJSON(body, target)
}
