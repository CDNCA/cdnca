package dnsproviderremote

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/acmeworker"
)

func TestDNSComPresentVerifiesCreatedRecordIdentity(t *testing.T) {
	const (
		apiKey          = "dnscom-api-key-sensitive"
		apiSecret       = "dnscom-api-secret-sensitive"
		upstreamMessage = "dnscom-upstream-sensitive-message"
		domainID        = "zone-dnscom-created"
		recordID        = "record-dnscom-created"
	)
	createdRecord := func(overrides map[string]any) map[string]any {
		record := map[string]any{
			"domain_id": domainID, "record_id": recordID, "record": testRelative,
			"type": "TXT", "value": testValue, "ttl": 600,
		}
		for name, value := range overrides {
			if value == nil {
				delete(record, name)
			} else {
				record[name] = value
			}
		}
		return record
	}
	tests := []struct {
		name           string
		createBody     map[string]any
		getStatus      int
		getBody        any
		getRaw         string
		retryAfter     string
		blockGet       bool
		cancelGet      bool
		timeout        time.Duration
		wantCode       ErrorCode
		wantTemporary  bool
		wantRetryAfter time.Duration
		wantContextErr error
		wantSuccess    bool
		wantGetCalls   int32
	}{
		{name: "matching direct read succeeds", getBody: createdRecord(nil), wantSuccess: true, wantGetCalls: 1},
		{name: "create ttl omitted", createBody: createdRecord(map[string]any{"ttl": nil}), wantCode: CodeInvalidResponse},
		{name: "create ttl zero", createBody: createdRecord(map[string]any{"ttl": 0}), wantCode: CodeInvalidResponse},
		{name: "create ttl drift", createBody: createdRecord(map[string]any{"ttl": 599}), wantCode: CodeInvalidResponse},
		{name: "domain id mismatch", getBody: createdRecord(map[string]any{"domain_id": "zone-dnscom-other"}), wantCode: CodeInvalidResponse, wantGetCalls: 1},
		{name: "record id mismatch", getBody: createdRecord(map[string]any{"record_id": "record-dnscom-other"}), wantCode: CodeInvalidResponse, wantGetCalls: 1},
		{name: "wrong owner", getBody: createdRecord(map[string]any{"record": "other-owner"}), wantCode: CodeInvalidResponse, wantGetCalls: 1},
		{name: "wrong record", getBody: createdRecord(map[string]any{"record": "other-record"}), wantCode: CodeInvalidResponse, wantGetCalls: 1},
		{name: "wrong type", getBody: createdRecord(map[string]any{"type": "A"}), wantCode: CodeInvalidResponse, wantGetCalls: 1},
		{name: "wrong value", getBody: createdRecord(map[string]any{"value": testOtherValue}), wantCode: CodeInvalidResponse, wantGetCalls: 1},
		{name: "direct ttl omitted", getBody: createdRecord(map[string]any{"ttl": nil}), wantCode: CodeInvalidResponse, wantGetCalls: 1},
		{name: "direct ttl zero", getBody: createdRecord(map[string]any{"ttl": 0}), wantCode: CodeInvalidResponse, wantGetCalls: 1},
		{name: "direct ttl drift", getBody: createdRecord(map[string]any{"ttl": 599}), wantCode: CodeInvalidResponse, wantGetCalls: 1},
		{name: "claimed record absent", getStatus: http.StatusNotFound, wantCode: CodeInvalidResponse, wantGetCalls: 1},
		{name: "malformed direct read", getRaw: `{"code":0,"data":{"domain_id":` + "}", wantCode: CodeInvalidResponse, wantGetCalls: 1},
		{name: "malformed record id", getBody: createdRecord(map[string]any{"record_id": "record id malformed"}), wantCode: CodeInvalidResponse, wantGetCalls: 1},
		{name: "http 401", getStatus: http.StatusUnauthorized, getRaw: upstreamMessage, wantCode: CodeCredentialsRejected, wantGetCalls: 1},
		{name: "http 403", getStatus: http.StatusForbidden, getRaw: upstreamMessage, wantCode: CodeCredentialsRejected, wantGetCalls: 1},
		{name: "http 408", getStatus: http.StatusRequestTimeout, getRaw: upstreamMessage, wantCode: CodeTimeout, wantTemporary: true, wantContextErr: context.DeadlineExceeded, wantGetCalls: 1},
		{name: "http 429", getStatus: http.StatusTooManyRequests, getRaw: upstreamMessage, retryAfter: "37", wantCode: CodeRateLimited, wantTemporary: true, wantRetryAfter: 37 * time.Second, wantGetCalls: 1},
		{name: "http 5xx", getStatus: http.StatusBadGateway, getRaw: upstreamMessage, wantCode: CodeUnavailable, wantTemporary: true, wantGetCalls: 1},
		{name: "internal timeout", blockGet: true, timeout: 20 * time.Millisecond, wantCode: CodeTimeout, wantTemporary: true, wantContextErr: context.DeadlineExceeded, wantGetCalls: 1},
		{name: "caller cancellation", blockGet: true, cancelGet: true, wantCode: CodeCancelled, wantContextErr: context.Canceled, wantGetCalls: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var createCalls, getCalls, deleteCalls atomic.Int32
			ctx := context.Background()
			cancel := func() {}
			if test.cancelGet {
				ctx, cancel = context.WithCancel(ctx)
			}
			defer cancel()
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.Host != "openapi.dns.com" ||
					!verifyDNSComTestSignature(r.URL.Query(), apiSecret) || r.URL.Query().Get("api_key") != apiKey {
					t.Errorf("unexpected DNS.COM request: %s", r.URL.String())
				}
				switch r.URL.Path {
				case "/api/record/create/":
					createCalls.Add(1)
					if r.URL.Query().Get("domain") != testZone || r.URL.Query().Get("record") != testRelative ||
						r.URL.Query().Get("type") != "TXT" || r.URL.Query().Get("value") != testValue {
						t.Errorf("create query = %s", r.URL.RawQuery)
					}
					createBody := test.createBody
					if createBody == nil {
						createBody = createdRecord(nil)
					}
					writeTestJSON(t, w, map[string]any{"code": 0, "data": createBody})
				case "/api/record/getOne/":
					getCalls.Add(1)
					if r.URL.Query().Get("domain") != domainID || r.URL.Query().Get("record_id") != recordID {
						t.Errorf("getOne query = %s", r.URL.RawQuery)
					}
					if test.cancelGet {
						cancel()
					}
					if test.blockGet {
						<-r.Context().Done()
						return
					}
					if test.retryAfter != "" {
						w.Header().Set("Retry-After", test.retryAfter)
					}
					if test.getStatus != 0 {
						w.WriteHeader(test.getStatus)
					}
					if test.getRaw != "" {
						_, _ = w.Write([]byte(test.getRaw))
					} else if test.getBody != nil {
						writeTestJSON(t, w, map[string]any{"code": 0, "data": test.getBody})
					}
				case "/api/record/operate/":
					deleteCalls.Add(1)
					writeTestJSON(t, w, map[string]any{"code": 0, "data": nil})
				default:
					t.Errorf("unexpected DNS.COM path %q", r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
				}
			})
			timeout := test.timeout
			if timeout == 0 {
				timeout = time.Second
			}
			adapter, source := newProviderTestAdapter(t, ProviderConfig{
				ProviderType: providerDNSCom, ZoneName: testZone,
				Credentials: map[string]string{"api_key": apiKey, "api_secret": apiSecret},
			}, handler, timeout)

			handle, err := adapter.PresentTXT(ctx, testChallenge())
			if test.wantSuccess {
				if err != nil {
					t.Fatalf("PresentTXT: %v", err)
				}
				requireHandle(t, handle, providerDNSCom, domainID, recordID)
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
				for _, sensitive := range []string{apiKey, apiSecret, "sign", upstreamMessage} {
					if strings.Contains(err.Error(), sensitive) || strings.Contains(fmt.Sprintf("%+v", err), sensitive) {
						t.Fatalf("error leaked %q: %+v", sensitive, err)
					}
				}
			}
			if createCalls.Load() != 1 || getCalls.Load() != test.wantGetCalls || deleteCalls.Load() != 0 {
				t.Fatalf("calls create=%d get=%d delete=%d, want 1/%d/0",
					createCalls.Load(), getCalls.Load(), deleteCalls.Load(), test.wantGetCalls)
			}
			if !source.credentialsCleared() {
				t.Fatal("provider credentials were retained")
			}
		})
	}
}

func TestDNSComCleanupPreflightRequiresTTLIdentity(t *testing.T) {
	const (
		apiKey    = "dnscom-cleanup-api-key-sensitive"
		apiSecret = "dnscom-cleanup-api-secret-sensitive"
		domainID  = "zone-dnscom-cleanup"
		recordID  = "record-dnscom-cleanup"
	)
	for _, test := range []struct {
		name string
		ttl  any
	}{
		{name: "omitted", ttl: nil},
		{name: "zero", ttl: 0},
		{name: "drift", ttl: 599},
	} {
		t.Run(test.name, func(t *testing.T) {
			var getCalls, deleteCalls atomic.Int32
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/record/getOne/":
					getCalls.Add(1)
					record := map[string]any{
						"domain_id": domainID, "record_id": recordID, "record": testRelative,
						"type": "TXT", "value": testValue,
					}
					if test.ttl != nil {
						record["ttl"] = test.ttl
					}
					writeTestJSON(t, w, map[string]any{"code": 0, "data": record})
				case "/api/record/operate/":
					deleteCalls.Add(1)
					writeTestJSON(t, w, map[string]any{"code": 0, "data": nil})
				default:
					t.Errorf("unexpected DNS.COM path %q", r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
				}
			})
			adapter, _ := newProviderTestAdapter(t, ProviderConfig{
				ProviderType: providerDNSCom, ZoneName: testZone,
				Credentials: map[string]string{"api_key": apiKey, "api_secret": apiSecret},
			}, handler, time.Second)
			handle, err := encodeTestHandle(t, testChallenge(), ProviderConfig{
				ProviderType: providerDNSCom, ZoneName: testZone,
				Credentials: map[string]string{"api_key": apiKey, "api_secret": apiSecret},
			}, recordHandle{
				Provider: providerDNSCom, Zone: testZone, ZoneID: domainID, RecordID: recordID, Owner: testOwner,
			})
			if err != nil {
				t.Fatal(err)
			}
			assertRemoteError(t, adapter.DeleteTXT(t.Context(), testChallengeWithHandle(handle)), CodeInvalidResponse)
			if getCalls.Load() != 1 || deleteCalls.Load() != 0 {
				t.Fatalf("calls get=%d delete=%d, want 1/0", getCalls.Load(), deleteCalls.Load())
			}
		})
	}
}
