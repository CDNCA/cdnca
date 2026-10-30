package dnsproviderremote

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/acmeworker"
	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/google/uuid"
)

const (
	cloudflare404Token           = "cloudflare-404-secret-token"
	cloudflare404ProviderMessage = "cloudflare-sensitive-provider-message"
	cloudflare404ZoneID          = "zone-cf"
	cloudflare404RecordID        = "record-cf-target"
)

func TestCloudflare404EnvelopePreservesKnownErrors(t *testing.T) {
	known := []struct {
		name       string
		code       int
		want       ErrorCode
		temporary  bool
		retryAfter string
		wantRetry  time.Duration
	}{
		{name: "invalid token", code: 9109, want: CodeCredentialsRejected},
		{name: "authentication error", code: 10000, want: CodeCredentialsRejected},
		{
			name: "rate limited", code: 1015, want: CodeRateLimited, temporary: true,
			retryAfter: "7200", wantRetry: time.Hour,
		},
	}
	for _, test := range known {
		t.Run("observe known envelope/"+test.name, func(t *testing.T) {
			fixture := &cloudflare404Fixture{getReply: cloudflare404Reply{
				kind: "envelope", code: test.code, retryAfter: test.retryAfter,
			}}
			adapter, source, challenge := newCloudflare404Adapter(t, fixture)
			err := adapter.ObserveTXT(t.Context(), challenge)
			assertCloudflare404Error(t, err, test.want, test.temporary, test.wantRetry)
			assertCloudflare404Calls(t, fixture, 1, 0)
			if !source.credentialsCleared() {
				t.Fatal("observe retained decrypted credentials")
			}
		})

		t.Run("delete known envelope/"+test.name, func(t *testing.T) {
			fixture := &cloudflare404Fixture{
				getReply: cloudflare404Reply{kind: "exact"},
				deleteReply: cloudflare404Reply{
					kind: "envelope", code: test.code, retryAfter: test.retryAfter,
				},
			}
			adapter, source, challenge := newCloudflare404Adapter(t, fixture)
			err := adapter.DeleteTXT(t.Context(), challenge)
			assertCloudflare404Error(t, err, test.want, test.temporary, test.wantRetry)
			wantGets := 1
			if test.want == CodeRateLimited {
				wantGets = 2
			}
			assertCloudflare404Calls(t, fixture, wantGets, 1)
			if !source.credentialsCleared() {
				t.Fatal("delete retained decrypted credentials")
			}
		})
	}

	for _, reply := range []struct {
		name  string
		reply cloudflare404Reply
	}{
		{name: "empty body", reply: cloudflare404Reply{kind: "empty"}},
		{name: "malformed body", reply: cloudflare404Reply{kind: "malformed"}},
	} {
		t.Run("observe unparseable response/"+reply.name, func(t *testing.T) {
			fixture := &cloudflare404Fixture{getReply: reply.reply}
			adapter, source, challenge := newCloudflare404Adapter(t, fixture)
			err := adapter.ObserveTXT(t.Context(), challenge)
			assertCloudflare404Error(t, err, CodeInvalidResponse, false, 0)
			assertCloudflare404Calls(t, fixture, 1, 0)
			if !source.credentialsCleared() {
				t.Fatal("observe retained decrypted credentials")
			}
		})

		t.Run("delete unparseable preflight/"+reply.name, func(t *testing.T) {
			fixture := &cloudflare404Fixture{getReply: reply.reply}
			adapter, source, challenge := newCloudflare404Adapter(t, fixture)
			err := adapter.DeleteTXT(t.Context(), challenge)
			assertCloudflare404Error(t, err, CodeInvalidResponse, false, 0)
			assertCloudflare404Calls(t, fixture, 1, 0)
			if !source.credentialsCleared() {
				t.Fatal("delete retained decrypted credentials")
			}
		})

		t.Run("delete unparseable response/"+reply.name, func(t *testing.T) {
			fixture := &cloudflare404Fixture{
				getReply: cloudflare404Reply{kind: "exact"}, deleteReply: reply.reply,
			}
			adapter, source, challenge := newCloudflare404Adapter(t, fixture)
			err := adapter.DeleteTXT(t.Context(), challenge)
			assertCloudflare404Error(t, err, CodeInvalidResponse, false, 0)
			assertCloudflare404Calls(t, fixture, 1, 1)
			if !source.credentialsCleared() {
				t.Fatal("delete retained decrypted credentials")
			}
		})
	}

	recordMissing := cloudflare404Reply{kind: "envelope", code: 81044}
	t.Run("observe record missing", func(t *testing.T) {
		fixture := &cloudflare404Fixture{getReply: recordMissing}
		adapter, source, challenge := newCloudflare404Adapter(t, fixture)
		err := adapter.ObserveTXT(t.Context(), challenge)
		assertCloudflare404Error(t, err, CodeRecordNotFound, true, 0)
		assertCloudflare404Calls(t, fixture, 1, 0)
		if !source.credentialsCleared() {
			t.Fatal("observe retained decrypted credentials")
		}
	})

	t.Run("delete record missing preflight", func(t *testing.T) {
		fixture := &cloudflare404Fixture{getReply: recordMissing}
		adapter, source, challenge := newCloudflare404Adapter(t, fixture)
		if err := adapter.DeleteTXT(t.Context(), challenge); err != nil {
			t.Fatalf("idempotent delete error = %v", err)
		}
		assertCloudflare404Calls(t, fixture, 1, 0)
		if !source.credentialsCleared() {
			t.Fatal("delete retained decrypted credentials")
		}
	})

	t.Run("delete record missing response", func(t *testing.T) {
		fixture := &cloudflare404Fixture{
			getReply: cloudflare404Reply{kind: "exact"}, deleteReply: recordMissing,
		}
		adapter, source, challenge := newCloudflare404Adapter(t, fixture)
		if err := adapter.DeleteTXT(t.Context(), challenge); err != nil {
			t.Fatalf("idempotent delete response error = %v", err)
		}
		assertCloudflare404Calls(t, fixture, 2, 1)
		if !source.credentialsCleared() {
			t.Fatal("delete retained decrypted credentials")
		}
	})
}

func TestCloudflare404UnknownEnvelopeFailsClosed(t *testing.T) {
	unknown := cloudflare404Reply{kind: "envelope", code: 7777}

	t.Run("observe", func(t *testing.T) {
		fixture := &cloudflare404Fixture{getReply: unknown}
		adapter, source, challenge := newCloudflare404Adapter(t, fixture)
		err := adapter.ObserveTXT(t.Context(), challenge)
		assertCloudflare404Error(t, err, CodeInvalidResponse, false, 0)
		assertCloudflare404Calls(t, fixture, 1, 0)
		if !source.credentialsCleared() {
			t.Fatal("observe retained decrypted credentials")
		}
	})

	t.Run("delete preflight", func(t *testing.T) {
		fixture := &cloudflare404Fixture{getReply: unknown}
		adapter, source, challenge := newCloudflare404Adapter(t, fixture)
		err := adapter.DeleteTXT(t.Context(), challenge)
		assertCloudflare404Error(t, err, CodeInvalidResponse, false, 0)
		assertCloudflare404Calls(t, fixture, 1, 0)
		if !source.credentialsCleared() {
			t.Fatal("delete retained decrypted credentials")
		}
	})

	t.Run("delete response", func(t *testing.T) {
		fixture := &cloudflare404Fixture{
			getReply: cloudflare404Reply{kind: "exact"}, deleteReply: unknown,
		}
		adapter, source, challenge := newCloudflare404Adapter(t, fixture)
		err := adapter.DeleteTXT(t.Context(), challenge)
		assertCloudflare404Error(t, err, CodeInvalidResponse, false, 0)
		assertCloudflare404Calls(t, fixture, 1, 1)
		if !source.credentialsCleared() {
			t.Fatal("delete retained decrypted credentials")
		}
	})
}

func TestCloudflareReconcile404PreservesKnownErrors(t *testing.T) {
	known := []struct {
		name       string
		code       int
		want       ErrorCode
		class      dnscheck.ProviderErrorClass
		retryAfter string
		wantRetry  time.Duration
	}{
		{name: "invalid token", code: 9109, want: CodeCredentialsRejected, class: dnscheck.ProviderErrorPermanent},
		{name: "authentication error", code: 10000, want: CodeCredentialsRejected, class: dnscheck.ProviderErrorPermanent},
		{
			name: "rate limited", code: 1015, want: CodeRateLimited, class: dnscheck.ProviderErrorTransient,
			retryAfter: "7200", wantRetry: time.Hour,
		},
	}
	for _, test := range known {
		t.Run(test.name, func(t *testing.T) {
			config := completeTestConfig(reconcileHTTPProviderConfig(providerCloudflare))
			config.Credentials["api_token"] = cloudflare404Token
			getCalls, deleteCalls := 0, 0
			providerAdapter, source := newProviderTestAdapter(t, config, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if request.Header.Get("Authorization") != "Bearer "+cloudflare404Token {
					t.Error("request did not use the expected Cloudflare credential")
				}
				switch {
				case request.Method == http.MethodGet && request.URL.Path == "/zones":
					writeTestJSON(t, writer, map[string]any{"success": true, "result": []any{
						map[string]any{"id": cloudflare404ZoneID, "name": testZone},
					}})
				case request.Method == http.MethodGet && request.URL.Path == "/zones/"+cloudflare404ZoneID+"/dns_records/"+cloudflare404RecordID:
					getCalls++
					writer.Header().Set("Retry-After", test.retryAfter)
					writer.WriteHeader(http.StatusNotFound)
					writeTestJSON(t, writer, map[string]any{
						"success": false, "result": nil,
						"errors": []map[string]any{{"code": test.code, "message": cloudflare404ProviderMessage}},
					})
				case request.Method == http.MethodDelete:
					deleteCalls++
					writer.WriteHeader(http.StatusNoContent)
				default:
					t.Errorf("unexpected Cloudflare request: %s %s", request.Method, request.URL.RequestURI())
					writer.WriteHeader(http.StatusNotFound)
				}
			}), time.Second)
			authority := newReconcileHTTPAuthority(config, 7)
			adapter, err := NewReconcileAdapter(authority, &providerReconcileRemote{adapter: providerAdapter})
			if err != nil {
				t.Fatal(err)
			}
			result, err := adapter.Mutate(t.Context(), dnscheck.ProviderMutation{
				ClientRequestID: "cloudflare-404-" + test.name,
				TenantID:        config.TenantID, SiteID: uuid.New(), ZoneID: config.ZoneID, ExpectedRevision: 7,
				Operation: dnscheck.ProviderOperation{
					Action: dnscheck.ProviderDelete, RecordID: cloudflare404RecordID,
					Name: "www.example.test.", Type: dnscheck.RecordA, Value: "192.0.2.10", TTL: 300,
				},
			})
			var providerErr *dnscheck.ProviderError
			if !errors.As(err, &providerErr) || providerErr.Class != test.class ||
				providerErr.Code != string(test.want) || providerErr.RetryAfter != test.wantRetry {
				t.Fatalf("Mutate()=(%+v,%v), provider error=%+v", result, err, providerErr)
			}
			if result.RecordID != "" || result.Revision != 0 || authority.revision != 7 ||
				getCalls != 1 || deleteCalls != 0 {
				t.Fatalf("result=%+v revision=%d get=%d delete=%d", result, authority.revision, getCalls, deleteCalls)
			}
			for _, secret := range []string{cloudflare404Token, cloudflare404ProviderMessage, "Authorization", "Bearer"} {
				if strings.Contains(err.Error(), secret) || strings.Contains(fmt.Sprintf("%+v", err), secret) {
					t.Fatalf("error leaked %q", secret)
				}
			}
			if !source.credentialsCleared() {
				t.Fatal("reconcile lookup retained decrypted credentials")
			}
		})
	}
}

func newCloudflare404Adapter(t *testing.T,
	fixture *cloudflare404Fixture) (*Adapter, *staticSource, acmeworker.ChallengeIdentity) {
	t.Helper()
	fixture.t = t
	config := ProviderConfig{
		ProviderType: providerCloudflare, ZoneName: testZone,
		Credentials: map[string]string{"api_token": cloudflare404Token},
	}
	adapter, source := newProviderTestAdapter(t, config, fixture, time.Second)
	handle, err := encodeTestHandle(t, testChallenge(), config, recordHandle{
		Provider: providerCloudflare, Zone: testZone, ZoneID: cloudflare404ZoneID,
		RecordID: cloudflare404RecordID, Owner: testOwner,
	})
	if err != nil {
		t.Fatalf("encode handle: %v", err)
	}
	return adapter, source, testChallengeWithHandle(handle)
}

func assertCloudflare404Error(t *testing.T, err error, code ErrorCode,
	temporary bool, retryAfter time.Duration) {
	t.Helper()
	assertRemoteError(t, err, code)
	var remote *Error
	if !errors.As(err, &remote) || remote.Temporary != temporary || remote.RetryAfter != retryAfter {
		t.Fatalf("error = %+v, temporary=%t retryAfter=%s", err, temporary, retryAfter)
	}
	formatted := fmt.Sprintf("%+v", err)
	for _, secret := range []string{
		cloudflare404Token, cloudflare404ProviderMessage, "Authorization", "Bearer",
	} {
		if strings.Contains(err.Error(), secret) || strings.Contains(formatted, secret) {
			t.Fatalf("error leaked %q", secret)
		}
	}
}

func assertCloudflare404Calls(t *testing.T, fixture *cloudflare404Fixture, gets, deletes int) {
	t.Helper()
	if fixture.getCalls != gets || fixture.deleteCalls != deletes || len(fixture.unexpected) != 0 {
		t.Fatalf("get=%d delete=%d unexpected=%v",
			fixture.getCalls, fixture.deleteCalls, fixture.unexpected)
	}
}

type cloudflare404Reply struct {
	kind       string
	code       int
	retryAfter string
}

type cloudflare404Fixture struct {
	t           *testing.T
	getReply    cloudflare404Reply
	deleteReply cloudflare404Reply
	deleted     bool
	getCalls    int
	deleteCalls int
	unexpected  []string
}

func (fixture *cloudflare404Fixture) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Host != "api.cloudflare.com" ||
		request.Header.Get("Authorization") != "Bearer "+cloudflare404Token {
		fixture.t.Errorf("unexpected Cloudflare endpoint or authorization")
	}
	wantPath := "/zones/" + cloudflare404ZoneID + "/dns_records/" + cloudflare404RecordID
	if request.URL.Path != wantPath {
		fixture.unexpected = append(fixture.unexpected, request.Method+" "+request.URL.Path)
		writer.WriteHeader(http.StatusNotFound)
		return
	}
	var reply cloudflare404Reply
	switch request.Method {
	case http.MethodGet:
		fixture.getCalls++
		if fixture.deleted {
			reply = fixture.deleteReply
		} else {
			reply = fixture.getReply
		}
	case http.MethodDelete:
		fixture.deleteCalls++
		fixture.deleted = true
		reply = fixture.deleteReply
	default:
		fixture.unexpected = append(fixture.unexpected, request.Method+" "+request.URL.Path)
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	fixture.writeReply(writer, reply)
}

func (fixture *cloudflare404Fixture) writeReply(writer http.ResponseWriter, reply cloudflare404Reply) {
	switch reply.kind {
	case "exact":
		writeTestJSON(fixture.t, writer, map[string]any{"success": true, "result": map[string]any{
			"id": cloudflare404RecordID, "zone_id": cloudflare404ZoneID,
			"name": testOwner, "type": "TXT", "content": testValue,
		}})
	case "empty":
		writer.WriteHeader(http.StatusNotFound)
	case "malformed":
		writer.WriteHeader(http.StatusNotFound)
		_, _ = writer.Write([]byte("{" + cloudflare404ProviderMessage))
	case "envelope":
		writer.Header().Set("Retry-After", reply.retryAfter)
		writer.WriteHeader(http.StatusNotFound)
		writeTestJSON(fixture.t, writer, map[string]any{
			"success": false, "result": nil,
			"errors": []map[string]any{{"code": reply.code, "message": cloudflare404ProviderMessage}},
		})
	default:
		fixture.t.Errorf("unsupported Cloudflare reply %q", reply.kind)
		writer.WriteHeader(http.StatusInternalServerError)
	}
}
