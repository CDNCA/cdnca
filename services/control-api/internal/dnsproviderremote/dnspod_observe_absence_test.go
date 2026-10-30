package dnsproviderremote

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/acmeworker"
)

func TestDNSPodObserveAndDeleteAbsenceSemantics(t *testing.T) {
	const (
		dpID  = "123456"
		dpKey = "dnspod-observe-absence-secret"
	)
	newAdapter := func(t *testing.T, handler http.Handler) (*Adapter, *staticSource, acmeworker.ChallengeIdentity) {
		t.Helper()
		config := ProviderConfig{
			ProviderType: providerDNSPodCN,
			ZoneName:     testZone,
			Credentials:  map[string]string{"dp_id": dpID, "dp_key": dpKey},
		}
		adapter, source := newProviderTestAdapter(t, config, handler, time.Second)
		handle, err := encodeTestHandle(t, testChallenge(), config, recordHandle{
			Provider: providerDNSPodCN, Zone: testZone, ZoneID: testZone,
			RecordID: "record-dnspod-absence", Owner: testOwner,
		})
		if err != nil {
			t.Fatal(err)
		}
		return adapter, source, testChallengeWithHandle(handle)
	}
	verifyRequest := func(t *testing.T, request *http.Request) {
		t.Helper()
		if request.Host != "dnsapi.cn" || request.Method != http.MethodPost || request.ParseForm() != nil ||
			request.Form.Get("login_token") != dpID+","+dpKey {
			t.Errorf("unexpected DNSPod request authentication")
		}
	}
	writeMissing := func(t *testing.T, writer http.ResponseWriter) {
		t.Helper()
		writeTestJSON(t, writer, map[string]any{"status": map[string]any{
			"code": "10", "message": "sensitive DNSPod provider message",
		}})
	}
	assertTemporaryAbsence := func(t *testing.T, err error) {
		t.Helper()
		assertRemoteError(t, err, CodeRecordNotFound)
		var remote *Error
		if !errors.As(err, &remote) || !remote.Temporary || remote.RetryAfter != 0 {
			t.Fatalf("error = %+v, want temporary record-not-found", err)
		}
		for _, secret := range []string{dpKey, "sensitive DNSPod provider message", "login_token"} {
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("error leaked %q", secret)
			}
		}
	}

	t.Run("observe retries provider absence", func(t *testing.T) {
		var infoCalls, removeCalls atomic.Int32
		adapter, source, challenge := newAdapter(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			verifyRequest(t, request)
			switch request.URL.Path {
			case "/Record.Info":
				infoCalls.Add(1)
				writeMissing(t, writer)
			case "/Record.Remove":
				removeCalls.Add(1)
				writeTestJSON(t, writer, map[string]any{"status": map[string]any{"code": "1"}})
			default:
				t.Errorf("unexpected DNSPod path %q", request.URL.Path)
				writer.WriteHeader(http.StatusNotFound)
			}
		}))
		assertTemporaryAbsence(t, adapter.ObserveTXT(t.Context(), challenge))
		if infoCalls.Load() != 1 || removeCalls.Load() != 0 {
			t.Fatalf("Record.Info calls = %d, Record.Remove calls = %d, want 1/0", infoCalls.Load(), removeCalls.Load())
		}
		if !source.credentialsCleared() {
			t.Fatal("observe retained decrypted credentials")
		}
	})

	t.Run("delete preflight absence is idempotent", func(t *testing.T) {
		var infoCalls, removeCalls atomic.Int32
		adapter, source, challenge := newAdapter(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			verifyRequest(t, request)
			switch request.URL.Path {
			case "/Record.Info":
				infoCalls.Add(1)
				writeMissing(t, writer)
			case "/Record.Remove":
				removeCalls.Add(1)
				writeTestJSON(t, writer, map[string]any{"status": map[string]any{"code": "1"}})
			default:
				t.Errorf("unexpected DNSPod path %q", request.URL.Path)
				writer.WriteHeader(http.StatusNotFound)
			}
		}))
		if err := adapter.DeleteTXT(t.Context(), challenge); err != nil {
			t.Fatalf("DeleteTXT absence: %v", err)
		}
		if infoCalls.Load() != 1 || removeCalls.Load() != 0 {
			t.Fatalf("Record.Info calls = %d, Record.Remove calls = %d, want 1/0", infoCalls.Load(), removeCalls.Load())
		}
		if !source.credentialsCleared() {
			t.Fatal("delete retained decrypted credentials")
		}
	})

	t.Run("delete confirmation absence is idempotent", func(t *testing.T) {
		var infoCalls, removeCalls atomic.Int32
		adapter, source, challenge := newAdapter(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			verifyRequest(t, request)
			switch request.URL.Path {
			case "/Record.Info":
				if infoCalls.Add(1) == 1 {
					writeTestJSON(t, writer, map[string]any{
						"status": map[string]any{"code": "1"},
						"domain": map[string]any{"id": "example.test", "domain": testZone},
						"record": map[string]any{
							"id": "record-dnspod-absence", "sub_domain": testRelative,
							"record_type": "TXT", "value": testValue, "record_line": "默认", "ttl": "600",
						},
					})
					return
				}
				writeMissing(t, writer)
			case "/Record.Remove":
				removeCalls.Add(1)
				writeTestJSON(t, writer, map[string]any{"status": map[string]any{"code": "1"}})
			default:
				t.Errorf("unexpected DNSPod path %q", request.URL.Path)
				writer.WriteHeader(http.StatusNotFound)
			}
		}))
		if err := adapter.DeleteTXT(t.Context(), challenge); err != nil {
			t.Fatalf("DeleteTXT confirmation absence: %v", err)
		}
		if infoCalls.Load() != 2 || removeCalls.Load() != 1 {
			t.Fatalf("Record.Info calls = %d, Record.Remove calls = %d, want 2/1", infoCalls.Load(), removeCalls.Load())
		}
		if !source.credentialsCleared() {
			t.Fatal("delete retained decrypted credentials")
		}
	})

	t.Run("request taxonomy remains permanent", func(t *testing.T) {
		var calls atomic.Int32
		config := ProviderConfig{
			ProviderType: providerDNSPodCN,
			ZoneName:     testZone,
			Credentials:  map[string]string{"dp_id": dpID, "dp_key": dpKey},
		}
		adapter, _ := newProviderTestAdapter(t, config, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			verifyRequest(t, request)
			calls.Add(1)
			writeMissing(t, writer)
		}), time.Second)
		_, err := (&dnsPodProvider{adapter: adapter}).request(t.Context(), config, "/Record.Info", url.Values{
			"domain": {testZone}, "record_id": {"record-dnspod-absence"},
		})
		assertRemoteError(t, err, CodeRecordNotFound)
		var remote *Error
		if !errors.As(err, &remote) || remote.Temporary || remote.RetryAfter != 0 || calls.Load() != 1 {
			t.Fatalf("request error = %+v, calls = %d, want permanent record-not-found and one call", err, calls.Load())
		}
	})
}
