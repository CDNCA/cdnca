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

func TestAliyunPresentVerifiesCreatedRecordIdentity(t *testing.T) {
	const (
		accessKeyID     = "aliyun-access-key-sensitive"
		accessKeySecret = "aliyun-secret-sensitive"
		upstreamMessage = "aliyun-upstream-sensitive-message"
		recordID        = "record-ali-created"
	)
	describeRecord := func(overrides map[string]any) map[string]any {
		response := map[string]any{
			"RequestId": "request-describe", "RecordId": recordID, "RR": testRelative,
			"Type": "TXT", "Value": testValue, "DomainName": testZone, "TTL": 60,
		}
		for name, value := range overrides {
			response[name] = value
		}
		return response
	}
	describeRecordWithout := func(field string) map[string]any {
		response := describeRecord(nil)
		delete(response, field)
		return response
	}
	tests := []struct {
		name             string
		describeStatus   int
		describeBody     any
		describeRaw      string
		retryAfter       string
		blockDescribe    bool
		cancelDescribe   bool
		timeout          time.Duration
		wantCode         ErrorCode
		wantTemporary    bool
		wantRetryAfter   time.Duration
		wantContextError error
		wantSuccess      bool
	}{
		{
			name: "matching direct read succeeds", describeBody: describeRecord(nil), wantSuccess: true,
		},
		{
			name: "omitted ttl", describeBody: describeRecordWithout("TTL"), wantCode: CodeRecordMismatch,
		},
		{
			name: "zero ttl", describeBody: describeRecord(map[string]any{"TTL": 0}), wantCode: CodeRecordMismatch,
		},
		{
			name: "wrong ttl", describeBody: describeRecord(map[string]any{"TTL": 600}), wantCode: CodeRecordMismatch,
		},
		{
			name: "claimed record id absent", describeStatus: http.StatusBadRequest,
			describeBody: map[string]any{
				"RequestId": "request-missing", "Code": "InvalidRecordId.NotFound", "Message": upstreamMessage,
			},
			wantCode: CodeInvalidResponse,
		},
		{
			name: "wrong owner", describeBody: describeRecord(map[string]any{"RR": "other-owner"}),
			wantCode: CodeInvalidResponse,
		},
		{
			name: "wrong domain", describeBody: describeRecord(map[string]any{"DomainName": "other.test"}),
			wantCode: CodeInvalidResponse,
		},
		{
			name: "wrong type", describeBody: describeRecord(map[string]any{"Type": "A"}),
			wantCode: CodeInvalidResponse,
		},
		{
			name: "wrong value", describeBody: describeRecord(map[string]any{"Value": testOtherValue}),
			wantCode: CodeInvalidResponse,
		},
		{
			name: "different record id", describeBody: describeRecord(map[string]any{"RecordId": "record-ali-other"}),
			wantCode: CodeInvalidResponse,
		},
		{
			name: "malformed record id", describeBody: describeRecord(map[string]any{"RecordId": "record id malformed"}),
			wantCode: CodeInvalidResponse,
		},
		{
			name: "http 401", describeStatus: http.StatusUnauthorized, describeRaw: upstreamMessage,
			wantCode: CodeCredentialsRejected,
		},
		{
			name: "http 403", describeStatus: http.StatusForbidden, describeRaw: upstreamMessage,
			wantCode: CodeCredentialsRejected,
		},
		{
			name: "http 408", describeStatus: http.StatusRequestTimeout, describeRaw: upstreamMessage,
			wantCode: CodeTimeout, wantTemporary: true, wantContextError: context.DeadlineExceeded,
		},
		{
			name: "http 429", describeStatus: http.StatusTooManyRequests, describeRaw: upstreamMessage,
			retryAfter: "37", wantCode: CodeRateLimited, wantTemporary: true, wantRetryAfter: 37 * time.Second,
		},
		{
			name: "http 5xx", describeStatus: http.StatusBadGateway, describeRaw: upstreamMessage,
			wantCode: CodeUnavailable, wantTemporary: true,
		},
		{
			name: "internal timeout", blockDescribe: true, timeout: 20 * time.Millisecond,
			wantCode: CodeTimeout, wantTemporary: true, wantContextError: context.DeadlineExceeded,
		},
		{
			name: "caller cancellation", blockDescribe: true, cancelDescribe: true,
			wantCode: CodeCancelled, wantContextError: context.Canceled,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var addCalls, getCalls, deleteCalls atomic.Int32
			ctx := context.Background()
			cancel := func() {}
			if test.cancelDescribe {
				ctx, cancel = context.WithCancel(ctx)
			}
			defer cancel()
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Query().Get("Action") {
				case "AddDomainRecord":
					addCalls.Add(1)
					writeTestJSON(t, w, map[string]any{"RequestId": "request-add", "RecordId": recordID})
				case "DescribeDomainRecordInfo":
					getCalls.Add(1)
					if r.URL.Query().Get("RecordId") != recordID {
						t.Errorf("describe RecordId = %q, want %q", r.URL.Query().Get("RecordId"), recordID)
					}
					if test.cancelDescribe {
						cancel()
					}
					if test.blockDescribe {
						<-r.Context().Done()
						return
					}
					if test.retryAfter != "" {
						w.Header().Set("Retry-After", test.retryAfter)
					}
					if test.describeStatus != 0 {
						w.WriteHeader(test.describeStatus)
					}
					if test.describeRaw != "" {
						_, _ = w.Write([]byte(test.describeRaw))
					} else {
						writeTestJSON(t, w, test.describeBody)
					}
				case "DeleteDomainRecord":
					deleteCalls.Add(1)
					writeTestJSON(t, w, map[string]any{"RequestId": "request-delete", "RecordId": recordID})
				default:
					t.Errorf("unexpected Aliyun action %q", r.URL.Query().Get("Action"))
					w.WriteHeader(http.StatusBadRequest)
				}
			})
			timeout := test.timeout
			if timeout == 0 {
				timeout = time.Second
			}
			adapter, source := newProviderTestAdapter(t, ProviderConfig{
				ProviderType: providerAliyun, ZoneName: testZone,
				Credentials: map[string]string{"access_key_id": accessKeyID, "access_key_secret": accessKeySecret},
			}, handler, timeout)

			handle, err := adapter.PresentTXT(ctx, testChallenge())
			if test.wantSuccess {
				if err != nil {
					t.Fatalf("PresentTXT: %v", err)
				}
				requireHandle(t, handle, providerAliyun, testZone, recordID)
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
				if test.wantContextError != nil && !errors.Is(err, test.wantContextError) {
					t.Fatalf("error %v does not match %v", err, test.wantContextError)
				}
				for _, sensitive := range []string{accessKeyID, accessKeySecret, "Signature", upstreamMessage} {
					if strings.Contains(err.Error(), sensitive) || strings.Contains(fmt.Sprintf("%+v", err), sensitive) {
						t.Fatalf("error leaked %q: %+v", sensitive, err)
					}
				}
			}
			if addCalls.Load() != 1 || getCalls.Load() != 1 || deleteCalls.Load() != 0 {
				t.Fatalf("calls add=%d get=%d delete=%d, want 1/1/0", addCalls.Load(), getCalls.Load(), deleteCalls.Load())
			}
			if !source.credentialsCleared() {
				t.Fatal("provider credentials were retained")
			}
		})
	}
}

func TestAliyunDeleteRequiresExpectedTTL(t *testing.T) {
	const recordID = "record-ali-cleanup"
	for _, test := range []struct {
		name        string
		ttl         int
		omitTTL     bool
		wantSuccess bool
	}{
		{name: "matching ttl", ttl: 60, wantSuccess: true},
		{name: "omitted ttl", omitTTL: true},
		{name: "zero ttl"},
		{name: "wrong ttl", ttl: 600},
	} {
		t.Run(test.name, func(t *testing.T) {
			var describeCalls, deleteCalls atomic.Int32
			handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				switch request.URL.Query().Get("Action") {
				case "DescribeDomainRecordInfo":
					if describeCalls.Add(1) > 1 {
						writer.WriteHeader(http.StatusBadRequest)
						writeTestJSON(t, writer, map[string]any{
							"RequestId": "request-missing", "Code": "InvalidRecordId.NotFound",
						})
						return
					}
					response := map[string]any{
						"RequestId": "request-describe", "RecordId": recordID, "RR": testRelative,
						"Type": "TXT", "Value": testValue, "DomainName": testZone,
					}
					if !test.omitTTL {
						response["TTL"] = test.ttl
					}
					writeTestJSON(t, writer, response)
				case "DeleteDomainRecord":
					deleteCalls.Add(1)
					writeTestJSON(t, writer, map[string]any{
						"RequestId": "request-delete", "RecordId": recordID,
					})
				default:
					t.Errorf("unexpected Aliyun action %q", request.URL.Query().Get("Action"))
					writer.WriteHeader(http.StatusBadRequest)
				}
			})
			config := ProviderConfig{
				ProviderType: providerAliyun, ZoneName: testZone,
				Credentials: map[string]string{
					"access_key_id": "cleanup-access", "access_key_secret": "cleanup-secret",
				},
			}
			adapter, source := newProviderTestAdapter(t, config, handler, time.Second)
			handle, err := encodeTestHandle(t, testChallenge(), config, recordHandle{
				Provider: providerAliyun, Zone: testZone, ZoneID: testZone,
				RecordID: recordID, Owner: testOwner,
			})
			if err != nil {
				t.Fatal(err)
			}
			err = adapter.DeleteTXT(t.Context(), testChallengeWithHandle(handle))
			if test.wantSuccess {
				if err != nil {
					t.Fatalf("DeleteTXT() error = %v", err)
				}
			} else if ErrorCodeOf(err) != CodeRecordMismatch {
				t.Fatalf("DeleteTXT() error = %v, want %s", err, CodeRecordMismatch)
			}
			wantDescribe, wantDelete := int32(1), int32(0)
			if test.wantSuccess {
				wantDescribe, wantDelete = 2, 1
			}
			if describeCalls.Load() != wantDescribe || deleteCalls.Load() != wantDelete {
				t.Fatalf("describe/delete calls=%d/%d, want %d/%d",
					describeCalls.Load(), deleteCalls.Load(), wantDescribe, wantDelete)
			}
			if !source.credentialsCleared() {
				t.Fatal("provider credentials were retained")
			}
		})
	}
}
