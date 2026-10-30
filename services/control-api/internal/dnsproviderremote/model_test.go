package dnsproviderremote

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/acmeworker"
)

func TestDNSDunFailsClosedBeforeNetwork(t *testing.T) {
	var requests atomic.Int32
	adapter, source := newProviderTestAdapter(t, ProviderConfig{
		ProviderType: "dnsdun", ZoneName: testZone,
		Credentials: map[string]string{"api_id": "must-not-migrate", "api_secret": "must-not-migrate"},
	}, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
	}), time.Second)
	_, err := adapter.PresentTXT(context.Background(), testChallenge())
	assertRemoteError(t, err, CodeUnsupported)
	if requests.Load() != 0 || source.callCount() != 1 || supportedProvider("dnsdun") {
		t.Fatalf("requests=%d sourceCalls=%d supported=%v", requests.Load(), source.callCount(), supportedProvider("dnsdun"))
	}
	if !supportedProvider(providerDNSLA) || providerDNSLA != "dns_la" {
		t.Fatalf("DNS.LA provider type = %q", providerDNSLA)
	}
}

func TestMalformedHandlesFailBeforeCredentialResolution(t *testing.T) {
	unknownField := base64.RawURLEncoding.EncodeToString([]byte(
		`{"v":1,"p":"cloudflare","z":"example.test","zi":"zone","ri":"record","o":"_acme-challenge.example.test.","extra":true}`,
	))
	legacyProvider := base64.RawURLEncoding.EncodeToString([]byte(
		`{"v":1,"p":"dnsdun","z":"example.test","zi":"zone","ri":"record","o":"_acme-challenge.example.test."}`,
	))
	tests := []acmeworker.RemoteTXTHandle{
		{},
		{ProviderRef: testProviderRef, RecordRef: "not-versioned"},
		{ProviderRef: testProviderRef, RecordRef: "v1.not-base64!"},
		{ProviderRef: testProviderRef, RecordRef: "v1." + unknownField},
		{ProviderRef: testProviderRef, RecordRef: "v1." + legacyProvider},
		{ProviderRef: testProviderRef, RecordRef: "v1." + strings.Repeat("a", 1024)},
	}
	for index, handle := range tests {
		t.Run(string(rune('a'+index)), func(t *testing.T) {
			source := &staticSource{config: ProviderConfig{
				ProviderType: providerCloudflare, ZoneName: testZone,
				Credentials: map[string]string{"api_token": "secret"},
			}}
			adapter := newStaticTestAdapter(t, source)
			challenge := testChallengeWithHandle(handle)
			err := adapter.ObserveTXT(context.Background(), challenge)
			assertRemoteError(t, err, CodeInvalidInput)
			if source.callCount() != 0 {
				t.Fatalf("source calls = %d", source.callCount())
			}
		})
	}
}

func TestHandleProviderAndZoneMustMatchResolvedProvider(t *testing.T) {
	providerHandle, err := encodeTestHandle(t, testChallenge(), ProviderConfig{
		ProviderType: providerCloudflare, ZoneName: testZone,
		Credentials: map[string]string{"api_token": "secret"},
	}, recordHandle{
		Provider: providerCloudflare, Zone: testZone, ZoneID: "zone", RecordID: "record", Owner: testOwner,
	})
	if err != nil {
		t.Fatal(err)
	}
	providerAdapter := newStaticTestAdapter(t, &staticSource{config: ProviderConfig{
		ProviderType: providerAliyun, ZoneName: testZone,
		Credentials: map[string]string{"access_key_id": "access", "access_key_secret": "secret"},
	}})
	assertRemoteError(t, providerAdapter.ObserveTXT(context.Background(), testChallengeWithHandle(providerHandle)), CodeRecordMismatch)

	owner := "_acme-challenge.sub.example.test."
	zoneChallenge := testChallenge()
	zoneChallenge.RecordName = owner
	zoneHandle, err := encodeTestHandle(t, zoneChallenge, ProviderConfig{
		ProviderType: providerCloudflare, ZoneName: testZone,
		Credentials: map[string]string{"api_token": "secret"},
	}, recordHandle{
		Provider: providerCloudflare, Zone: testZone, ZoneID: "zone", RecordID: "record", Owner: owner,
	})
	if err != nil {
		t.Fatal(err)
	}
	zoneAdapter := newStaticTestAdapter(t, &staticSource{config: ProviderConfig{
		ProviderType: providerCloudflare, ZoneName: "sub.example.test",
		Credentials: map[string]string{"api_token": "secret"},
	}})
	zoneChallenge.TXTHandle = zoneHandle
	assertRemoteError(t, zoneAdapter.ObserveTXT(context.Background(), zoneChallenge), CodeRecordMismatch)
}

func TestDeleteRefusesOwnerOrValueMismatch(t *testing.T) {
	tests := []struct {
		name     string
		owner    string
		value    string
		typeName string
	}{
		{name: "owner", owner: "other.example.test.", value: testValue, typeName: "TXT"},
		{name: "value", owner: testOwner, value: testOtherValue, typeName: "TXT"},
		{name: "type", owner: testOwner, value: testValue, typeName: "CNAME"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var deleteCalls atomic.Int32
			adapter, _ := newProviderTestAdapter(t, ProviderConfig{
				ProviderType: providerCloudflare, ZoneName: testZone,
				Credentials: map[string]string{"api_token": "secret"},
			}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodDelete {
					deleteCalls.Add(1)
				}
				writeTestJSON(t, w, map[string]any{"success": true, "result": map[string]any{
					"id": "record", "zone_id": "zone", "name": test.owner, "type": test.typeName, "content": test.value,
				}})
			}), time.Second)
			handle, err := encodeTestHandle(t, testChallenge(), ProviderConfig{
				ProviderType: providerCloudflare, ZoneName: testZone,
				Credentials: map[string]string{"api_token": "secret"},
			}, recordHandle{
				Provider: providerCloudflare, Zone: testZone, ZoneID: "zone", RecordID: "record", Owner: testOwner,
			})
			if err != nil {
				t.Fatal(err)
			}
			assertRemoteError(t, adapter.DeleteTXT(context.Background(), testChallengeWithHandle(handle)), CodeRecordMismatch)
			if deleteCalls.Load() != 0 {
				t.Fatalf("delete calls = %d", deleteCalls.Load())
			}
		})
	}
}

func TestHuaweiMultiValueRecordSetIsNeverDeletedAsSingleHandle(t *testing.T) {
	const projectID = "0123456789abcdef0123456789abcdef"
	var deleteCalls atomic.Int32
	adapter, _ := newProviderTestAdapter(t, ProviderConfig{
		ProviderType: providerHuawei, ZoneName: testZone,
		Credentials: map[string]string{
			"access_key": "access", "secret_key": "secret", "region": "cn-north-4", "project_id": projectID,
		},
	}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			deleteCalls.Add(1)
		}
		writeTestJSON(t, w, map[string]any{
			"id": "record", "zone_id": "zone", "name": testOwner, "type": "TXT",
			"records": []string{`"` + testValue + `"`, `"` + testOtherValue + `"`},
		})
	}), time.Second)
	handle, err := encodeTestHandle(t, testChallenge(), ProviderConfig{
		ProviderType: providerHuawei, ZoneName: testZone,
		Credentials: map[string]string{
			"access_key": "access", "secret_key": "secret", "region": "cn-north-4", "project_id": projectID,
		},
	}, recordHandle{
		Provider: providerHuawei, Zone: testZone, ZoneID: "zone", RecordID: "record", Owner: testOwner,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertRemoteError(t, adapter.DeleteTXT(context.Background(), testChallengeWithHandle(handle)), CodeRecordMismatch)
	if deleteCalls.Load() != 0 {
		t.Fatalf("delete calls = %d", deleteCalls.Load())
	}
}

func TestProviderZoneMismatchIsNeverDeleted(t *testing.T) {
	tests := []struct {
		name     string
		config   ProviderConfig
		handle   recordHandle
		response map[string]any
	}{
		{
			name: "dnspod",
			config: ProviderConfig{
				ProviderType: providerDNSPodCN, ZoneName: testZone,
				Credentials: map[string]string{"dp_id": "12345", "dp_key": "secret-key"},
			},
			handle: recordHandle{
				Provider: providerDNSPodCN, Zone: testZone, ZoneID: testZone, RecordID: "record", Owner: testOwner,
			},
			response: map[string]any{
				"status": map[string]any{"code": "1"},
				"domain": map[string]any{"id": "99", "domain": "other.test"},
				"record": map[string]any{
					"id": "record", "sub_domain": testRelative, "record_type": "TXT", "value": testValue,
				},
			},
		},
		{
			name: "huawei",
			config: ProviderConfig{
				ProviderType: providerHuawei, ZoneName: testZone,
				Credentials: map[string]string{
					"access_key": "access", "secret_key": "secret", "region": "cn-north-4",
					"project_id": "0123456789abcdef0123456789abcdef",
				},
			},
			handle: recordHandle{
				Provider: providerHuawei, Zone: testZone, ZoneID: "zone", RecordID: "record", Owner: testOwner,
			},
			response: map[string]any{
				"id": "record", "zone_id": "other-zone", "name": testOwner,
				"type": "TXT", "records": []string{`"` + testValue + `"`},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var deleteCalls atomic.Int32
			adapter, _ := newProviderTestAdapter(t, test.config, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodDelete || r.URL.Path == "/Record.Remove" {
					deleteCalls.Add(1)
				}
				writeTestJSON(t, w, test.response)
			}), time.Second)
			handle, err := encodeTestHandle(t, testChallenge(), test.config, test.handle)
			if err != nil {
				t.Fatal(err)
			}
			assertRemoteError(t, adapter.DeleteTXT(context.Background(), testChallengeWithHandle(handle)), CodeInvalidResponse)
			if deleteCalls.Load() != 0 {
				t.Fatalf("delete calls = %d", deleteCalls.Load())
			}
		})
	}
}

func TestObserveMissingRecordIsRetryableAndDeleteIsIdempotent(t *testing.T) {
	adapter, _ := newProviderTestAdapter(t, ProviderConfig{
		ProviderType: providerCloudflare, ZoneName: testZone,
		Credentials: map[string]string{"api_token": "secret"},
	}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		writeTestJSON(t, w, map[string]any{
			"success": false, "result": nil, "errors": []map[string]any{{"code": 81044}},
		})
	}), time.Second)
	handle, err := encodeTestHandle(t, testChallenge(), ProviderConfig{
		ProviderType: providerCloudflare, ZoneName: testZone,
		Credentials: map[string]string{"api_token": "secret"},
	}, recordHandle{
		Provider: providerCloudflare, Zone: testZone, ZoneID: "zone", RecordID: "record", Owner: testOwner,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = adapter.ObserveTXT(context.Background(), testChallengeWithHandle(handle))
	assertRemoteError(t, err, CodeRecordNotFound)
	var remoteError *Error
	if !errors.As(err, &remoteError) || !remoteError.Temporary {
		t.Fatalf("observe error = %+v", err)
	}
	if err := adapter.DeleteTXT(context.Background(), testChallengeWithHandle(handle)); err != nil {
		t.Fatalf("DeleteTXT missing record: %v", err)
	}
}

func TestSourceErrorsAndSecretsAreDiscarded(t *testing.T) {
	source := &staticSource{err: errors.New("source-secret-value")}
	adapter := newStaticTestAdapter(t, source)
	_, err := adapter.PresentTXT(context.Background(), testChallenge())
	assertRemoteError(t, err, CodeSourceUnavailable)
	if strings.Contains(err.Error(), "source-secret-value") {
		t.Fatalf("source error leaked: %v", err)
	}
}

func TestDNSLACredentialsRemainIndependentFromDNSDun(t *testing.T) {
	credentials := map[string]string{"api_id": "DNS LA user", "api_secret": "密钥 secret"}
	if err := validateCredentials(providerDNSLA, credentials); err != nil {
		t.Fatalf("valid DNS.LA Basic credentials: %v", err)
	}
	if err := validateCredentials("dnsdun", credentials); ErrorCodeOf(err) != CodeUnsupported {
		t.Fatalf("dnsdun credentials error = %v", err)
	}
}
