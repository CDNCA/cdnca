package dnsproviderremote

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/acmeworker"
	"github.com/google/uuid"
)

var remoteProviderTestTime = time.Date(2026, time.July, 22, 3, 4, 5, 0, time.UTC)

const (
	testProviderRef = "40000000-0000-4000-8000-000000000001"
	testZone        = "example.test"
	testOwner       = "_acme-challenge.example.test."
	testRelative    = "_acme-challenge"
	testValue       = "challenge_value-1"
	testOtherValue  = "unrelated_value-2"
)

var (
	testTenantID      = uuid.MustParse("10000000-0000-4000-8000-000000000001")
	testScopeID       = uuid.MustParse("10000000-0000-4000-8000-000000000001")
	testOperationID   = uuid.MustParse("20000000-0000-4000-8000-000000000001").String()
	testAttemptID     = uuid.MustParse("30000000-0000-4000-8000-000000000001")
	testManagedZoneID = uuid.MustParse("50000000-0000-4000-8000-000000000001")
)

type staticSource struct {
	mu          sync.Mutex
	config      ProviderConfig
	err         error
	calls       []string
	resolved    []map[string]string
	outstanding []acmeworker.ChallengeIdentity
}

func (s *staticSource) revokeCredential() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.config.CredentialRevoked = true
}

var _ StartupSource = (*staticSource)(nil)

func (s *staticSource) Resolve(_ context.Context, lookup ProviderLookup) (ProviderConfig, error) {
	s.mu.Lock()
	s.calls = append(s.calls, lookup.TenantScopeID.String()+"|"+lookup.ProviderID.String()+"|"+
		lookup.ZoneID.String()+"|"+lookup.OwnerName)
	config := s.config
	config.Credentials = make(map[string]string, len(s.config.Credentials))
	for name, value := range s.config.Credentials {
		config.Credentials[name] = value
	}
	s.resolved = append(s.resolved, config.Credentials)
	s.mu.Unlock()
	return config, s.err
}

func (s *staticSource) OutstandingRemoteTXTHandles(context.Context) ([]acmeworker.ChallengeIdentity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]acmeworker.ChallengeIdentity(nil), s.outstanding...), s.err
}

func (s *staticSource) CheckCredentialFence(_ context.Context, lookup ProviderLookup, version uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil || s.config.CredentialRevoked || s.config.CredentialVersion != version ||
		s.config.TenantID != lookup.TenantID || s.config.ScopeID != lookup.ScopeID ||
		s.config.TenantScopeID != lookup.ScopeID || s.config.ProviderID != lookup.ProviderID ||
		s.config.ZoneID != lookup.ZoneID {
		return errors.New("credential fence mismatch")
	}
	return nil
}

func (s *staticSource) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

func (s *staticSource) credentialsCleared() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, credentials := range s.resolved {
		if len(credentials) != 0 {
			return false
		}
	}
	return true
}

func newProviderTestAdapter(
	t *testing.T,
	config ProviderConfig,
	handler http.Handler,
	timeout time.Duration,
) (*Adapter, *staticSource) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	source := &staticSource{config: completeTestConfig(config)}
	makeEndpoint := func(host string) endpoint { return endpoint{baseURL: server.URL, host: host} }
	endpoints := endpointSet{
		cloudflare: makeEndpoint("api.cloudflare.com"),
		aliyun:     makeEndpoint("alidns.aliyuncs.com"),
		huawei: map[string]endpoint{
			"cn-north-4":     makeEndpoint("dns.cn-north-4.myhuaweicloud.com"),
			"ap-southeast-3": makeEndpoint("dns.ap-southeast-3.myhuaweicloud.com"),
		},
		dnspod:  makeEndpoint("dnsapi.cn"),
		dnscom:  makeEndpoint("openapi.dns.com"),
		dnsla:   makeEndpoint("api.dns.la"),
		namecom: makeEndpoint("api.name.com"),
	}
	return newAdapter(
		source,
		testHandleKeyring(t),
		server.Client().Transport,
		endpoints,
		timeout,
		func() time.Time { return remoteProviderTestTime },
		func() string { return "nonce-123" },
	), source
}

func completeTestConfig(config ProviderConfig) ProviderConfig {
	if config.TenantID == uuid.Nil {
		config.TenantID = testTenantID
	}
	if config.ScopeID == uuid.Nil {
		config.ScopeID = testScopeID
	}
	if config.TenantScopeID == uuid.Nil {
		config.TenantScopeID = config.ScopeID
	}
	if config.ProviderID == uuid.Nil {
		config.ProviderID = uuid.MustParse(testProviderRef)
	}
	if config.ZoneID == uuid.Nil {
		config.ZoneID = testManagedZoneID
	}
	if config.CredentialVersion == 0 {
		config.CredentialVersion = 1
	}
	return config
}

func encodeTestHandle(
	t *testing.T,
	challenge acmeworker.ChallengeIdentity,
	config ProviderConfig,
	handle recordHandle,
) (acmeworker.RemoteTXTHandle, error) {
	t.Helper()
	return encodeHandle(challenge, completeTestConfig(config), handle, testHandleKeyring(t))
}

func newStaticTestAdapter(t *testing.T, source *staticSource) *Adapter {
	t.Helper()
	source.config = completeTestConfig(source.config)
	return newAdapter(source, testHandleKeyring(t), nil, productionEndpoints(), requestTimeout, nil, nil)
}

func testChallenge() acmeworker.ChallengeIdentity {
	return acmeworker.ChallengeIdentity{
		TenantID: testTenantID, ScopeID: testScopeID, OperationID: testOperationID, AttemptID: testAttemptID,
		ProviderID: uuid.MustParse(testProviderRef), ZoneID: testManagedZoneID,
		ProviderRef: testProviderRef, ChallengeType: acmeworker.ChallengeDNS01,
		RecordName: testOwner, ExactValue: testValue,
	}
}

func testPersistedChallenge() acmeworker.ChallengeIdentity {
	challenge := testChallenge()
	challenge.AuthorizationURL = "https://ca.example/authz/1"
	challenge.ChallengeURL = "https://ca.example/challenge/1"
	challenge.Identifier = testZone
	challenge.Token = "challenge-token-1"
	return challenge
}

func testChallengeWithHandle(handle acmeworker.RemoteTXTHandle) acmeworker.ChallengeIdentity {
	challenge := testChallenge()
	challenge.TXTHandle = handle
	return challenge
}

func writeTestJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Errorf("encode response: %v", err)
	}
}

func requireHandle(t *testing.T, handle acmeworker.RemoteTXTHandle, provider, zoneID, recordID string) handlePayload {
	t.Helper()
	if handle.ProviderRef != testProviderRef || strings.Contains(handle.RecordRef, "secret") {
		t.Fatalf("unexpected public handle: %+v", handle)
	}
	decoded, err := decodeHandle(handle.RecordRef, testHandleKeyring(t))
	if err != nil {
		t.Fatalf("decode handle: %v", err)
	}
	if decoded.ProviderType != provider || decoded.ManagedZoneID != testManagedZoneID.String() ||
		decoded.RemoteZoneID != zoneID || decoded.RemoteRecordID != recordID ||
		decoded.ZoneNameSHA256 != digestText(testZone) || decoded.OwnerSHA256 != digestText(testOwner) {
		t.Fatalf("decoded handle = %+v", decoded)
	}
	return decoded
}

func TestCloudflareLifecycleUsesExactRecordHandle(t *testing.T) {
	const token = "cloudflare-secret-token"
	targetExists := false
	otherExists := true
	deleteCalls := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "api.cloudflare.com" || r.Header.Get("Authorization") != "Bearer "+token {
			t.Errorf("unexpected Cloudflare auth or host")
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones":
			if r.URL.Query().Get("name") != testZone || r.URL.Query().Get("per_page") != "2" {
				t.Errorf("zone query = %q", r.URL.RawQuery)
			}
			writeTestJSON(t, w, map[string]any{"success": true, "result": []any{
				map[string]any{"id": "zone-cf", "name": testZone},
			}})
		case r.Method == http.MethodPost && r.URL.Path == "/zones/zone-cf/dns_records":
			var body struct {
				Type, Name, Content string
				TTL                 int
			}
			if json.NewDecoder(r.Body).Decode(&body) != nil || body.Type != "TXT" || body.Name != testOwner ||
				body.Content != testValue || body.TTL != 60 {
				t.Errorf("create body = %+v", body)
			}
			targetExists = true
			writeTestJSON(t, w, map[string]any{"success": true, "result": map[string]any{
				"id": "record-cf-target", "zone_id": "zone-cf", "name": testOwner,
				"type": "TXT", "content": testValue,
			}})
		case r.Method == http.MethodGet && r.URL.Path == "/zones/zone-cf/dns_records/record-cf-target":
			if !targetExists {
				w.WriteHeader(http.StatusNotFound)
				writeTestJSON(t, w, map[string]any{
					"success": false, "result": nil, "errors": []map[string]any{{"code": 81044}},
				})
				return
			}
			writeTestJSON(t, w, map[string]any{"success": true, "result": map[string]any{
				"id": "record-cf-target", "zone_id": "zone-cf", "name": testOwner,
				"type": "TXT", "content": testValue,
			}})
		case r.Method == http.MethodDelete && r.URL.Path == "/zones/zone-cf/dns_records/record-cf-target":
			deleteCalls++
			targetExists = false
			writeTestJSON(t, w, map[string]any{"success": true, "result": map[string]any{"id": "record-cf-target"}})
		default:
			t.Errorf("unexpected Cloudflare request %s %s", r.Method, r.URL.String())
			w.WriteHeader(http.StatusNotFound)
		}
	})
	adapter, _ := newProviderTestAdapter(t, ProviderConfig{
		ProviderType: providerCloudflare, ZoneName: testZone,
		Credentials: map[string]string{"api_token": token},
	}, handler, time.Second)

	handle, err := adapter.PresentTXT(context.Background(), testChallenge())
	if err != nil {
		t.Fatalf("PresentTXT: %v", err)
	}
	requireHandle(t, handle, providerCloudflare, "zone-cf", "record-cf-target")
	if err := adapter.ObserveTXT(context.Background(), testChallengeWithHandle(handle)); err != nil {
		t.Fatalf("ObserveTXT: %v", err)
	}
	if err := adapter.DeleteTXT(context.Background(), testChallengeWithHandle(handle)); err != nil {
		t.Fatalf("DeleteTXT: %v", err)
	}
	if err := adapter.DeleteTXT(context.Background(), testChallengeWithHandle(handle)); err != nil {
		t.Fatalf("idempotent DeleteTXT: %v", err)
	}
	if targetExists || !otherExists || deleteCalls != 1 {
		t.Fatalf("target=%v other=%v deleteCalls=%d", targetExists, otherExists, deleteCalls)
	}
}

func TestRecoverTXTRequiresOneExactRemoteRecordAndNeverMutates(t *testing.T) {
	const token = "cloudflare-recovery-secret"
	records := []cloudflareRecord(nil)
	mutations := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			t.Errorf("unexpected Cloudflare authentication")
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones":
			writeTestJSON(t, w, map[string]any{"success": true, "result": []any{
				map[string]any{"id": "zone-cf", "name": testZone},
			}})
		case r.Method == http.MethodGet && r.URL.Path == "/zones/zone-cf/dns_records":
			if r.URL.Query().Get("type") != "TXT" || r.URL.Query().Get("name") != testOwner ||
				r.URL.Query().Get("page") != "1" || r.URL.Query().Get("per_page") != "100" {
				t.Errorf("recovery query = %q", r.URL.RawQuery)
			}
			totalPages := 1
			if len(records) == 0 {
				totalPages = 0
			}
			writeTestJSON(t, w, map[string]any{
				"success": true, "result": records,
				"result_info": map[string]any{
					"page": 1, "per_page": recoveryPageSize, "count": len(records),
					"total_count": len(records), "total_pages": totalPages,
				},
			})
		default:
			mutations++
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
	adapter, source := newProviderTestAdapter(t, ProviderConfig{
		ProviderType: providerCloudflare, ZoneName: testZone,
		Credentials: map[string]string{"api_token": token},
	}, handler, time.Second)

	if handle, found, err := adapter.RecoverTXT(context.Background(), testChallenge()); err != nil || found || handle != (acmeworker.RemoteTXTHandle{}) {
		t.Fatalf("zero-match handle=%+v found=%t error=%v", handle, found, err)
	}
	records = []cloudflareRecord{
		{ID: "unrelated", ZoneID: "zone-cf", Name: testOwner, Type: "TXT", Content: "unrelated-value"},
		{ID: "target", ZoneID: "zone-cf", Name: testOwner, Type: "TXT", Content: testValue},
	}
	handle, found, err := adapter.RecoverTXT(context.Background(), testChallenge())
	if err != nil || !found {
		t.Fatalf("one-match found=%t error=%v", found, err)
	}
	requireHandle(t, handle, providerCloudflare, "zone-cf", "target")
	records = append(records, cloudflareRecord{
		ID: "duplicate-target", ZoneID: "zone-cf", Name: testOwner, Type: "TXT", Content: testValue,
	})
	if _, _, err := adapter.RecoverTXT(context.Background(), testChallenge()); !isCode(err, CodeRecordMismatch) {
		t.Fatalf("ambiguous-match error = %v", err)
	}
	if mutations != 0 {
		t.Fatalf("recovery performed %d remote mutations", mutations)
	}
	if !source.credentialsCleared() {
		t.Fatal("recovery retained decrypted credential values")
	}
}

func TestExactTXTHandleSelectionForCanonicalProviders(t *testing.T) {
	for _, provider := range []string{
		providerCloudflare, providerAliyun, providerHuawei, providerDNSPodCN, providerDNSCom, providerDNSLA,
	} {
		t.Run(provider, func(t *testing.T) {
			unrelated := txtCandidate{
				id: "unrelated", zoneID: "remote-zone", owner: testOwner,
				recordType: "TXT", value: "unrelated-value",
			}
			target := txtCandidate{
				id: "target", zoneID: "remote-zone", owner: testOwner,
				recordType: "TXT", value: testValue,
			}
			matches, err := exactTXTHandles(provider, testZone, testOwner, testValue, []txtCandidate{unrelated})
			if err != nil || len(matches) != 0 {
				t.Fatalf("zero matches = %+v, %v", matches, err)
			}
			matches, err = exactTXTHandles(provider, testZone, testOwner, testValue, []txtCandidate{unrelated, target})
			if err != nil || len(matches) != 1 || matches[0].RecordID != "target" || matches[0].Provider != provider {
				t.Fatalf("one match = %+v, %v", matches, err)
			}
			matches, err = exactTXTHandles(provider, testZone, testOwner, testValue,
				[]txtCandidate{target, {id: "duplicate", zoneID: "remote-zone", owner: testOwner, recordType: "TXT", value: testValue}})
			if err != nil || len(matches) != 2 {
				t.Fatalf("ambiguous matches = %+v, %v", matches, err)
			}
		})
	}
}

func TestRecoverTXTPaginatesCanonicalProviderResults(t *testing.T) {
	for _, provider := range []string{
		providerCloudflare, providerAliyun, providerDNSPodCN, providerDNSCom, providerDNSLA,
	} {
		for _, duplicate := range []bool{false, true} {
			name := "later unrelated"
			if duplicate {
				name = "later duplicate"
			}
			t.Run(provider+"/"+name, func(t *testing.T) {
				pageCalls := 0
				mutations := 0
				adapter, source := newRecoveryPaginationAdapter(t, provider, duplicate, false, &pageCalls, &mutations)
				handle, found, err := adapter.RecoverTXT(context.Background(), testChallenge())
				if duplicate {
					if !isCode(err, CodeRecordMismatch) {
						t.Fatalf("duplicate error = %v", err)
					}
				} else {
					if err != nil || !found {
						t.Fatalf("found=%t error=%v", found, err)
					}
					requireHandle(t, handle, provider, recoveryZoneID(provider), "target")
				}
				if pageCalls != 2 || mutations != 0 {
					t.Fatalf("pageCalls=%d mutations=%d", pageCalls, mutations)
				}
				if !source.credentialsCleared() {
					t.Fatal("recovery retained decrypted credential values")
				}
			})
		}
	}
}

func TestRecoverTXTPaginationOverflowFailsClosed(t *testing.T) {
	for _, provider := range []string{
		providerCloudflare, providerAliyun, providerDNSPodCN, providerDNSCom, providerDNSLA,
	} {
		t.Run(provider, func(t *testing.T) {
			pageCalls := 0
			mutations := 0
			adapter, source := newRecoveryPaginationAdapter(t, provider, false, true, &pageCalls, &mutations)
			if _, _, err := adapter.RecoverTXT(context.Background(), testChallenge()); !isCode(err, CodeInvalidResponse) {
				t.Fatalf("overflow error = %v", err)
			}
			wantPageCalls := 1
			if provider == providerDNSPodCN {
				wantPageCalls = recoveryMaxPages + 1
			}
			if pageCalls != wantPageCalls || mutations != 0 {
				t.Fatalf("pageCalls=%d want=%d mutations=%d", pageCalls, wantPageCalls, mutations)
			}
			if !source.credentialsCleared() {
				t.Fatal("overflow retained decrypted credential values")
			}
		})
	}
}

func TestRecoverTXTPreservesDNSPodProviderErrors(t *testing.T) {
	tests := []struct {
		code       string
		want       ErrorCode
		retryAfter string
	}{
		{code: "-1", want: CodeCredentialsRejected},
		{code: "-2", want: CodeRateLimited, retryAfter: "41"},
		{code: "-99", want: CodeUnavailable},
	}
	for _, test := range tests {
		t.Run(string(test.want), func(t *testing.T) {
			calls := 0
			adapter, source := newProviderTestAdapter(t, ProviderConfig{
				ProviderType: providerDNSPodCN, ZoneName: testZone,
				Credentials: map[string]string{"dp_id": "12345", "dp_key": "recovery-secret"},
			}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != "/Record.List" {
					t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
				}
				calls++
				w.Header().Set("Retry-After", test.retryAfter)
				writeTestJSON(t, w, map[string]any{
					"status": map[string]any{"code": test.code},
				})
			}), time.Second)
			if _, _, err := adapter.RecoverTXT(context.Background(), testChallenge()); !isCode(err, test.want) {
				t.Fatalf("error = %v", err)
			} else if test.want == CodeRateLimited {
				assertRetryAfter(t, err, 41*time.Second)
			}
			if calls != 1 {
				t.Fatalf("calls = %d", calls)
			}
			if !source.credentialsCleared() {
				t.Fatal("error path retained decrypted credential values")
			}
		})
	}
}

func TestRecoverTXTDNSPodEmptyStatusIsSuccessfulAbsence(t *testing.T) {
	adapter, source := newProviderTestAdapter(t, ProviderConfig{
		ProviderType: providerDNSPodCN, ZoneName: testZone,
		Credentials: map[string]string{"dp_id": "12345", "dp_key": "recovery-secret"},
	}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeTestJSON(t, w, map[string]any{"status": map[string]any{"code": "10"}})
	}), time.Second)
	handle, found, err := adapter.RecoverTXT(t.Context(), testChallenge())
	if err != nil || found || handle != (acmeworker.RemoteTXTHandle{}) {
		t.Fatalf("handle=%+v found=%t error=%v", handle, found, err)
	}
	if !source.credentialsCleared() {
		t.Fatal("empty recovery retained decrypted credential values")
	}
}

func TestDNSPodRecoveryBoundaryProbesBeyondTenThousand(t *testing.T) {
	for _, total := range []int{recoveryMaxItems, recoveryMaxItems + 1} {
		t.Run(strconv.Itoa(total), func(t *testing.T) {
			calls := 0
			mutations := 0
			adapter, source := newProviderTestAdapter(t, ProviderConfig{
				ProviderType: providerDNSPodCN, ZoneName: testZone,
				Credentials: map[string]string{"dp_id": "12345", "dp_key": "recovery-secret"},
			}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != "/Record.List" {
					mutations++
					w.WriteHeader(http.StatusMethodNotAllowed)
					return
				}
				calls++
				_ = r.ParseForm()
				offset, _ := strconv.Atoi(r.Form.Get("offset"))
				length, _ := strconv.Atoi(r.Form.Get("length"))
				if offset == recoveryMaxItems {
					if length != 1 {
						t.Errorf("boundary probe length=%d", length)
					}
					if total == recoveryMaxItems {
						writeTestJSON(t, w, map[string]any{"status": map[string]any{"code": "10"}})
						return
					}
					writeTestJSON(t, w, map[string]any{
						"status":  map[string]any{"code": "1"},
						"records": []any{recoveryProviderRecord(providerDNSPodCN, "overflow", "unrelated")},
						"info":    map[string]any{"records_num": "1"},
					})
					return
				}
				records := make([]map[string]any, 0, recoveryPageSize)
				for index := 0; index < recoveryPageSize; index++ {
					records = append(records, recoveryProviderRecord(providerDNSPodCN,
						fmt.Sprintf("record-%d-%d", offset, index), fmt.Sprintf("unrelated-%d-%d", offset, index)))
				}
				writeTestJSON(t, w, map[string]any{
					"status": map[string]any{"code": "1"}, "records": records,
					"info": map[string]any{"records_num": strconv.Itoa(len(records))},
				})
			}), time.Second)

			handle, found, err := adapter.RecoverTXT(t.Context(), testChallenge())
			if total == recoveryMaxItems {
				if err != nil || found || handle != (acmeworker.RemoteTXTHandle{}) {
					t.Fatalf("boundary handle=%+v found=%t error=%v", handle, found, err)
				}
			} else if !isCode(err, CodeInvalidResponse) {
				t.Fatalf("overflow error=%v", err)
			}
			if calls != recoveryMaxPages+1 || mutations != 0 {
				t.Fatalf("calls=%d mutations=%d", calls, mutations)
			}
			if !source.credentialsCleared() {
				t.Fatal("boundary recovery retained decrypted credentials")
			}
		})
	}
}

func newRecoveryPaginationAdapter(
	t *testing.T,
	provider string,
	duplicate bool,
	overflow bool,
	pageCalls, mutations *int,
) (*Adapter, *staticSource) {
	t.Helper()
	pageRecords := func(page int) []map[string]any {
		if overflow {
			records := make([]map[string]any, 0, recoveryPageSize)
			for index := 0; index < recoveryPageSize; index++ {
				records = append(records, recoveryProviderRecord(provider,
					fmt.Sprintf("overflow-%d-%d", page, index), fmt.Sprintf("overflow-value-%d-%d", page, index)))
			}
			return records
		}
		if page == 2 {
			value := "later-unrelated-value"
			if duplicate {
				value = testValue
			}
			return []map[string]any{recoveryProviderRecord(provider, "later", value)}
		}
		records := make([]map[string]any, 0, recoveryPageSize)
		records = append(records, recoveryProviderRecord(provider, "target", testValue))
		for index := 1; index < recoveryPageSize; index++ {
			records = append(records, recoveryProviderRecord(provider, fmt.Sprintf("unrelated-%d", index),
				fmt.Sprintf("unrelated-value-%d", index)))
		}
		return records
	}
	total := recoveryPageSize + 1
	if overflow {
		total = recoveryMaxItems + 1
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch provider {
		case providerCloudflare:
			if r.Method == http.MethodGet && r.URL.Path == "/zones" {
				writeTestJSON(t, w, map[string]any{"success": true, "result": []any{
					map[string]any{"id": "zone-cf", "name": testZone},
				}})
				return
			}
			if r.Method == http.MethodGet && r.URL.Path == "/zones/zone-cf/dns_records" {
				page, _ := strconv.Atoi(r.URL.Query().Get("page"))
				records := pageRecords(page)
				*pageCalls++
				writeTestJSON(t, w, map[string]any{
					"success": true, "result": records,
					"result_info": map[string]any{
						"page": page, "per_page": recoveryPageSize, "count": len(records),
						"total_count": total, "total_pages": (total + recoveryPageSize - 1) / recoveryPageSize,
					},
				})
				return
			}
		case providerAliyun:
			if r.Method == http.MethodGet && r.URL.Path == "/" && r.URL.Query().Get("Action") == "DescribeDomainRecords" {
				page, _ := strconv.Atoi(r.URL.Query().Get("PageNumber"))
				records := pageRecords(page)
				*pageCalls++
				writeTestJSON(t, w, map[string]any{
					"RequestId": "request-list", "TotalCount": total,
					"PageNumber": page, "PageSize": recoveryPageSize,
					"DomainRecords": map[string]any{"Record": records},
				})
				return
			}
		case providerHuawei:
			if r.Method == http.MethodGet && r.URL.Path == "/v2/zones" {
				writeTestJSON(t, w, map[string]any{"zones": []any{
					map[string]any{"id": "zone-hw", "name": testZone + "."},
				}})
				return
			}
			if r.Method == http.MethodGet && r.URL.Path == "/v2.1/zones/zone-hw/recordsets" {
				offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
				page := offset/recoveryPageSize + 1
				records := pageRecords(page)
				*pageCalls++
				next := ""
				if page == 1 {
					next = "https://dns.example/recordsets?offset=100"
				}
				writeTestJSON(t, w, map[string]any{
					"recordsets": records, "metadata": map[string]any{"total_count": total},
					"links": map[string]any{"next": next},
				})
				return
			}
		case providerDNSPodCN:
			if r.Method == http.MethodPost && r.URL.Path == "/Record.List" {
				_ = r.ParseForm()
				offset, _ := strconv.Atoi(r.Form.Get("offset"))
				page := offset/recoveryPageSize + 1
				records := pageRecords(page)
				*pageCalls++
				writeTestJSON(t, w, map[string]any{
					"status": map[string]any{"code": "1"}, "records": records,
					"info": map[string]any{"records_num": strconv.Itoa(len(records))},
				})
				return
			}
		case providerDNSCom:
			if r.Method == http.MethodGet && r.URL.Path == "/api/record/lists/" {
				page, _ := strconv.Atoi(r.URL.Query().Get("page"))
				records := pageRecords(page)
				*pageCalls++
				writeTestJSON(t, w, map[string]any{"code": 0, "data": map[string]any{
					"total": total, "data": records,
				}})
				return
			}
		case providerDNSLA:
			if r.Method == http.MethodGet && r.URL.Path == "/api/domain" {
				writeTestJSON(t, w, map[string]any{"code": 200, "data": map[string]any{
					"id": "zone-dnsla", "domain": testZone,
				}})
				return
			}
			if r.Method == http.MethodGet && r.URL.Path == "/api/recordList" {
				page, _ := strconv.Atoi(r.URL.Query().Get("pageIndex"))
				records := pageRecords(page)
				*pageCalls++
				writeTestJSON(t, w, map[string]any{"code": 200, "data": map[string]any{
					"total": total, "results": records,
				}})
				return
			}
		}
		*mutations++
		w.WriteHeader(http.StatusMethodNotAllowed)
	})
	config := ProviderConfig{ProviderType: provider, ZoneName: testZone}
	switch provider {
	case providerCloudflare:
		config.Credentials = map[string]string{"api_token": "recovery-token"}
	case providerAliyun:
		config.Credentials = map[string]string{"access_key_id": "recovery-key", "access_key_secret": "recovery-secret"}
	case providerHuawei:
		config.Credentials = map[string]string{
			"access_key": "recovery-key", "secret_key": "recovery-secret", "region": "cn-north-4",
			"project_id": "0123456789abcdef0123456789abcdef",
		}
	case providerDNSPodCN:
		config.Credentials = map[string]string{"dp_id": "12345", "dp_key": "recovery-secret"}
	case providerDNSCom:
		config.Credentials = map[string]string{"api_key": "recovery-key", "api_secret": "recovery-secret"}
	case providerDNSLA:
		config.Credentials = map[string]string{"api_id": "recovery-id", "api_secret": "recovery-secret"}
	}
	adapter, source := newProviderTestAdapter(t, config, handler, time.Second)
	return adapter, source
}

func recoveryProviderRecord(provider, id, value string) map[string]any {
	switch provider {
	case providerCloudflare:
		return map[string]any{"id": id, "zone_id": "zone-cf", "name": testOwner, "type": "TXT", "content": value}
	case providerAliyun:
		return map[string]any{"RecordId": id, "RR": testRelative, "Type": "TXT", "Value": value}
	case providerHuawei:
		return map[string]any{"id": id, "zone_id": "zone-hw", "name": testOwner, "type": "TXT", "records": []string{strconv.Quote(value)}}
	case providerDNSPodCN:
		return map[string]any{"id": id, "name": testRelative, "type": "TXT", "value": value, "line": "默认", "ttl": "600"}
	case providerDNSCom:
		return map[string]any{"domain_id": "zone-dnscom", "record_id": id, "record": testRelative, "type": "TXT", "value": value, "ttl": 600}
	case providerDNSLA:
		return map[string]any{"id": id, "domainId": "zone-dnsla", "host": testRelative, "type": 16, "data": value, "ttl": 600}
	default:
		return nil
	}
}

func recoveryZoneID(provider string) string {
	switch provider {
	case providerCloudflare:
		return "zone-cf"
	case providerHuawei:
		return "zone-hw"
	case providerDNSCom:
		return "zone-dnscom"
	case providerDNSLA:
		return "zone-dnsla"
	default:
		return testZone
	}
}

func TestAliyunLifecycleSignsAndDeletesOnlyRecordID(t *testing.T) {
	const accessKeyID = "test-access-key"
	const accessKeySecret = "aliyun-secret"
	targetExists := false
	otherExists := true
	deleteCalls := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "alidns.aliyuncs.com" || r.Method != http.MethodGet || r.URL.Path != "/" {
			t.Errorf("unexpected Aliyun request %s %s host=%s", r.Method, r.URL.Path, r.Host)
		}
		if !verifyAliyunTestSignature(r.URL.Query(), accessKeySecret) ||
			r.URL.Query().Get("AccessKeyId") != accessKeyID || r.URL.Query().Get("SignatureNonce") != "nonce-123" ||
			r.URL.Query().Get("Timestamp") != "2026-07-22T03:04:05Z" {
			t.Errorf("invalid Aliyun signed query: %s", r.URL.RawQuery)
		}
		switch r.URL.Query().Get("Action") {
		case "AddDomainRecord":
			if r.URL.Query().Get("DomainName") != testZone || r.URL.Query().Get("RR") != testRelative ||
				r.URL.Query().Get("Type") != "TXT" || r.URL.Query().Get("Value") != testValue {
				t.Errorf("create query = %s", r.URL.RawQuery)
			}
			targetExists = true
			writeTestJSON(t, w, map[string]any{"RequestId": "request-add", "RecordId": "record-ali-target"})
		case "DescribeDomainRecordInfo":
			if r.URL.Query().Get("RecordId") != "record-ali-target" {
				t.Errorf("describe record id = %q", r.URL.Query().Get("RecordId"))
			}
			if !targetExists {
				w.WriteHeader(http.StatusBadRequest)
				writeTestJSON(t, w, map[string]any{"RequestId": "request-missing", "Code": "InvalidRecordId.NotFound"})
				return
			}
			writeTestJSON(t, w, map[string]any{
				"RequestId": "request-get", "RecordId": "record-ali-target", "RR": testRelative,
				"Type": "TXT", "Value": testValue, "DomainName": testZone, "TTL": 60,
			})
		case "DeleteDomainRecord":
			if r.URL.Query().Get("RecordId") != "record-ali-target" {
				t.Errorf("delete record id = %q", r.URL.Query().Get("RecordId"))
			}
			deleteCalls++
			targetExists = false
			writeTestJSON(t, w, map[string]any{"RequestId": "request-delete", "RecordId": "record-ali-target"})
		default:
			t.Errorf("unexpected Aliyun action %q", r.URL.Query().Get("Action"))
			w.WriteHeader(http.StatusBadRequest)
		}
	})
	adapter, _ := newProviderTestAdapter(t, ProviderConfig{
		ProviderType: providerAliyun, ZoneName: testZone,
		Credentials: map[string]string{"access_key_id": accessKeyID, "access_key_secret": accessKeySecret},
	}, handler, time.Second)

	handle, err := adapter.PresentTXT(context.Background(), testChallenge())
	if err != nil {
		t.Fatalf("PresentTXT: %v", err)
	}
	requireHandle(t, handle, providerAliyun, testZone, "record-ali-target")
	if err := adapter.ObserveTXT(context.Background(), testChallengeWithHandle(handle)); err != nil {
		t.Fatalf("ObserveTXT: %v", err)
	}
	if err := adapter.DeleteTXT(context.Background(), testChallengeWithHandle(handle)); err != nil {
		t.Fatalf("DeleteTXT: %v", err)
	}
	if err := adapter.DeleteTXT(context.Background(), testChallengeWithHandle(handle)); err != nil {
		t.Fatalf("idempotent DeleteTXT: %v", err)
	}
	if targetExists || !otherExists || deleteCalls != 1 {
		t.Fatalf("target=%v other=%v deleteCalls=%d", targetExists, otherExists, deleteCalls)
	}
}

func verifyAliyunTestSignature(query url.Values, secret string) bool {
	provided := query.Get("Signature")
	parameters := make(map[string]string, len(query)-1)
	for name, values := range query {
		if name != "Signature" && len(values) == 1 {
			parameters[name] = values[0]
		}
	}
	canonical := aliyunCanonicalQuery(parameters)
	mac := hmac.New(sha1.New, []byte(secret+"&"))
	_, _ = mac.Write([]byte("GET&%2F&" + aliyunPercentEncode(canonical)))
	return hmac.Equal([]byte(provided), []byte(base64.StdEncoding.EncodeToString(mac.Sum(nil))))
}

func TestHuaweiLifecycleUsesSignedRecordSetID(t *testing.T) {
	const accessKey = "huawei-access-key"
	const secretKey = "huawei-secret-key"
	const projectID = "0123456789abcdef0123456789abcdef"
	targetExists := false
	otherExists := true
	listCalls := 0
	deleteCalls := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "dns.cn-north-4.myhuaweicloud.com" || r.Header.Get("X-Project-Id") != projectID ||
			r.Header.Get("X-Sdk-Date") != "20260722T030405Z" ||
			!strings.HasPrefix(r.Header.Get("Authorization"), "SDK-HMAC-SHA256 Access="+accessKey+",") {
			t.Errorf("unexpected Huawei authentication headers")
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v2/zones":
			if r.URL.Query().Get("name") != testZone+"." || r.URL.Query().Get("type") != "public" {
				t.Errorf("zone query = %q", r.URL.RawQuery)
			}
			writeTestJSON(t, w, map[string]any{"zones": []any{map[string]any{"id": "zone-hw", "name": testZone + "."}}})
		case r.Method == http.MethodGet && r.URL.Path == "/v2.1/zones/zone-hw/recordsets":
			if r.URL.Query().Get("name") != testOwner || r.URL.Query().Get("type") != "TXT" ||
				r.URL.Query().Get("limit") != strconv.Itoa(recoveryPageSize) || r.URL.Query().Get("offset") != "0" {
				t.Errorf("recordset query = %q", r.URL.RawQuery)
			}
			listCalls++
			recordsets := []any{}
			if targetExists {
				recordsets = append(recordsets, map[string]any{
					"id": "record-hw-target", "zone_id": "zone-hw", "name": testOwner,
					"type": "TXT", "records": []string{`"` + testValue + `"`},
				})
			}
			writeTestJSON(t, w, map[string]any{
				"recordsets": recordsets, "metadata": map[string]any{"total_count": len(recordsets)},
				"links": map[string]any{"next": ""},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v2.1/zones/zone-hw/recordsets":
			var body struct {
				Name    string
				Type    string
				TTL     int
				Records []string
			}
			if json.NewDecoder(r.Body).Decode(&body) != nil || body.Name != testOwner || body.Type != "TXT" ||
				body.TTL != 300 || len(body.Records) != 1 || body.Records[0] != `"`+testValue+`"` {
				t.Errorf("create body = %+v", body)
			}
			targetExists = true
			w.WriteHeader(http.StatusCreated)
			writeTestJSON(t, w, map[string]any{
				"id": "record-hw-target", "zone_id": "zone-hw", "name": testOwner,
				"type": "TXT", "records": []string{`"` + testValue + `"`},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/v2.1/zones/zone-hw/recordsets/record-hw-target":
			if !targetExists {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			writeTestJSON(t, w, map[string]any{
				"id": "record-hw-target", "zone_id": "zone-hw", "name": testOwner,
				"type": "TXT", "records": []string{`"` + testValue + `"`},
			})
		case r.Method == http.MethodDelete && r.URL.Path == "/v2.1/zones/zone-hw/recordsets/record-hw-target":
			deleteCalls++
			targetExists = false
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected Huawei request %s %s", r.Method, r.URL.String())
			w.WriteHeader(http.StatusNotFound)
		}
	})
	adapter, _ := newProviderTestAdapter(t, ProviderConfig{
		ProviderType: providerHuawei, ZoneName: testZone,
		Credentials: map[string]string{
			"access_key": accessKey, "secret_key": secretKey, "region": "cn-north-4", "project_id": projectID,
		},
	}, handler, time.Second)

	handle, err := adapter.PresentTXT(context.Background(), testChallenge())
	if err != nil {
		t.Fatalf("PresentTXT: %v", err)
	}
	payload, err := decodeHandle(handle.RecordRef, testHandleKeyring(t))
	if err != nil || payload.ProviderType != providerHuawei || payload.RemoteZoneID != "zone-hw" {
		t.Fatalf("decode Huawei handle: payload=%+v error=%v", payload, err)
	}
	remoteID, ownDigest, expectedDigest, legacy, err := decodeHuaweiRecordID(payload.RemoteRecordID)
	if err != nil || legacy || remoteID != "record-hw-target" || !digestMatches(ownDigest, testValue) ||
		!huaweiValuesDigestMatches(expectedDigest, []string{testValue}) {
		t.Fatalf("Huawei record handle id=%q legacy=%t error=%v", remoteID, legacy, err)
	}
	if err := adapter.ObserveTXT(context.Background(), testChallengeWithHandle(handle)); err != nil {
		t.Fatalf("ObserveTXT: %v", err)
	}
	if err := adapter.DeleteTXT(context.Background(), testChallengeWithHandle(handle)); err != nil {
		t.Fatalf("DeleteTXT: %v", err)
	}
	if err := adapter.DeleteTXT(context.Background(), testChallengeWithHandle(handle)); err != nil {
		t.Fatalf("idempotent DeleteTXT: %v", err)
	}
	if targetExists || !otherExists || listCalls != 6 || deleteCalls != 1 {
		t.Fatalf("target=%v other=%v listCalls=%d deleteCalls=%d", targetExists, otherExists, listCalls, deleteCalls)
	}
}

type huaweiRRSetFake struct {
	t                   *testing.T
	owner               string
	exists              bool
	values              []string
	postCalls           int
	putCalls            int
	deleteCalls         int
	listCalls           int
	duplicateList       bool
	getDrift            string
	listDrift           string
	driftAfterGet       []string
	driftAfterList      []string
	unknownNextDelete   bool
	applyUnknownDelete  bool
	unknownDeleteStatus int
	unknownNextGet      bool
	afterUnknownDelete  func()
	directGetCalls      int
}

func (f *huaweiRRSetFake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.t.Helper()
	if r.Host != "dns.cn-north-4.myhuaweicloud.com" ||
		r.Header.Get("X-Project-Id") != "0123456789abcdef0123456789abcdef" ||
		!strings.HasPrefix(r.Header.Get("Authorization"), "SDK-HMAC-SHA256 Access=huawei-access-key,") {
		f.t.Errorf("unexpected Huawei authentication")
	}
	record := func(drift string) map[string]any {
		id, zoneID, owner, recordType := "record-hw-shared", "zone-hw", f.owner, "TXT"
		switch drift {
		case "id":
			id = "record-hw-drift"
		case "zone":
			zoneID = "zone-hw-drift"
		case "owner":
			owner = "_drift.example.test."
		case "type":
			recordType = "A"
		}
		records := make([]string, 0, len(f.values))
		for _, value := range f.values {
			records = append(records, strconv.Quote(value))
		}
		return map[string]any{
			"id": id, "zone_id": zoneID, "name": owner, "type": recordType, "ttl": 300, "records": records,
		}
	}
	decodeValues := func() ([]string, bool) {
		var body struct {
			Name    string   `json:"name"`
			Type    string   `json:"type"`
			TTL     int      `json:"ttl"`
			Records []string `json:"records"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			return nil, false
		}
		if r.Method == http.MethodPost && (body.Name != f.owner || body.Type != "TXT" || body.TTL != 300) {
			return nil, false
		}
		values := make([]string, 0, len(body.Records))
		for _, encoded := range body.Records {
			value, err := strconv.Unquote(encoded)
			if err != nil {
				return nil, false
			}
			values = append(values, value)
		}
		return values, true
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/v2/zones":
		writeTestJSON(f.t, w, map[string]any{"zones": []any{
			map[string]any{"id": "zone-hw", "name": testZone + "."},
		}})
	case r.Method == http.MethodGet && r.URL.Path == "/v2.1/zones/zone-hw/recordsets":
		if r.URL.Query().Get("name") != f.owner || r.URL.Query().Get("type") != "TXT" ||
			r.URL.Query().Get("limit") != strconv.Itoa(recoveryPageSize) || r.URL.Query().Get("offset") != "0" {
			f.t.Errorf("recordset query = %q", r.URL.RawQuery)
		}
		f.listCalls++
		recordsets := []any{}
		if f.exists {
			recordsets = append(recordsets, record(f.listDrift))
			if f.duplicateList {
				duplicate := record("")
				duplicate["id"] = "record-hw-duplicate"
				recordsets = append(recordsets, duplicate)
			}
		}
		writeTestJSON(f.t, w, map[string]any{
			"recordsets": recordsets, "metadata": map[string]any{"total_count": len(recordsets)},
			"links": map[string]any{"next": ""},
		})
		if f.driftAfterList != nil {
			f.exists = true
			f.values = append([]string(nil), f.driftAfterList...)
			f.driftAfterList = nil
		}
	case r.Method == http.MethodPost && r.URL.Path == "/v2.1/zones/zone-hw/recordsets":
		f.postCalls++
		values, valid := decodeValues()
		if !valid || f.exists || len(values) != 1 {
			w.WriteHeader(http.StatusPreconditionFailed)
			return
		}
		f.exists, f.values = true, values
		w.WriteHeader(http.StatusCreated)
		writeTestJSON(f.t, w, record(""))
	case r.Method == http.MethodGet && r.URL.Path == "/v2.1/zones/zone-hw/recordsets/record-hw-shared":
		f.directGetCalls++
		if f.unknownNextGet {
			f.unknownNextGet = false
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if !f.exists {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		writeTestJSON(f.t, w, record(f.getDrift))
		if f.driftAfterGet != nil {
			f.values = append([]string(nil), f.driftAfterGet...)
			f.driftAfterGet = nil
		}
	case r.Method == http.MethodPut && r.URL.Path == "/v2.1/zones/zone-hw/recordsets/record-hw-shared":
		f.putCalls++
		w.WriteHeader(http.StatusMethodNotAllowed)
	case r.Method == http.MethodDelete && r.URL.Path == "/v2.1/zones/zone-hw/recordsets/record-hw-shared":
		f.deleteCalls++
		if !f.exists {
			w.WriteHeader(http.StatusPreconditionFailed)
			return
		}
		if f.unknownNextDelete {
			f.unknownNextDelete = false
			if f.applyUnknownDelete {
				f.exists, f.values = false, nil
			}
			if f.afterUnknownDelete != nil {
				f.afterUnknownDelete()
			}
			status := f.unknownDeleteStatus
			if status == 0 {
				status = http.StatusInternalServerError
			}
			if status == http.StatusTooManyRequests {
				w.Header().Set("Retry-After", "37")
			}
			w.WriteHeader(status)
			return
		}
		f.exists, f.values = false, nil
		w.WriteHeader(http.StatusNoContent)
	default:
		f.t.Errorf("unexpected Huawei request %s %s", r.Method, r.URL.String())
		w.WriteHeader(http.StatusNotFound)
	}
}

func newHuaweiRRSetAdapter(t *testing.T, fake *huaweiRRSetFake) *Adapter {
	t.Helper()
	fake.t = t
	fake.owner = testOwner
	adapter, _ := newProviderTestAdapter(t, ProviderConfig{
		ProviderType: providerHuawei,
		ZoneName:     testZone,
		Credentials: map[string]string{
			"access_key": "huawei-access-key", "secret_key": "huawei-secret-key", "region": "cn-north-4",
			"project_id": "0123456789abcdef0123456789abcdef",
		},
	}, fake, time.Second)
	return adapter
}

func huaweiChallenge(value string) acmeworker.ChallengeIdentity {
	challenge := testChallenge()
	challenge.ExactValue = value
	return challenge
}

func TestHuaweiLegacySingletonHandleObservesButDeleteFailsClosed(t *testing.T) {
	const value = "legacy_value"
	fake := &huaweiRRSetFake{exists: true, values: []string{value}}
	adapter := newHuaweiRRSetAdapter(t, fake)
	challenge := huaweiChallenge(value)
	handle, err := encodeTestHandle(t, challenge, ProviderConfig{
		ProviderType: providerHuawei,
		ZoneName:     testZone,
		Credentials: map[string]string{
			"access_key": "huawei-access-key", "secret_key": "huawei-secret-key", "region": "cn-north-4",
			"project_id": "0123456789abcdef0123456789abcdef",
		},
	}, recordHandle{
		Provider: providerHuawei, Zone: testZone, ZoneID: "zone-hw", RecordID: "record-hw-shared", Owner: testOwner,
	})
	if err != nil {
		t.Fatal(err)
	}
	challenge.TXTHandle = handle
	if err := adapter.ObserveTXT(t.Context(), challenge); err != nil {
		t.Fatalf("observe legacy singleton: %v", err)
	}
	fake.driftAfterGet = []string{"replacement_value"}
	if err := adapter.DeleteTXT(t.Context(), challenge); !isCode(err, CodeRecordMismatch) {
		t.Fatalf("delete legacy singleton error=%v", err)
	}
	if !fake.exists || !reflect.DeepEqual(fake.values, []string{"replacement_value"}) ||
		fake.putCalls != 0 || fake.deleteCalls != 0 {
		t.Fatalf("legacy cleanup exists=%t puts=%d deletes=%d", fake.exists, fake.putCalls, fake.deleteCalls)
	}
}

func TestHuaweiSingletonRejectsSecondValueWithoutMutation(t *testing.T) {
	fake := &huaweiRRSetFake{exists: true, values: []string{"sentinel_value"}}
	adapter := newHuaweiRRSetAdapter(t, fake)
	if _, err := adapter.PresentTXT(t.Context(), huaweiChallenge("target_value")); !isCode(err, CodeRecordMismatch) {
		t.Fatalf("second value present error=%v", err)
	}
	if !reflect.DeepEqual(fake.values, []string{"sentinel_value"}) ||
		fake.postCalls != 0 || fake.putCalls != 0 || fake.deleteCalls != 0 {
		t.Fatalf("singleton mutated values=%v post=%d put=%d delete=%d",
			fake.values, fake.postCalls, fake.putCalls, fake.deleteCalls)
	}
}

func TestHuaweiSharedRRSetIsReadOnly(t *testing.T) {
	values := []string{"sentinel_value", "target_value"}
	fake := &huaweiRRSetFake{exists: true, values: append([]string(nil), values...)}
	adapter := newHuaweiRRSetAdapter(t, fake)
	for _, value := range values {
		challenge := huaweiChallenge(value)
		handle, err := adapter.PresentTXT(t.Context(), challenge)
		if err != nil {
			t.Fatalf("read-only present %q: %v", value, err)
		}
		challenge.TXTHandle = handle
		if err := adapter.ObserveTXT(t.Context(), challenge); err != nil {
			t.Fatalf("observe %q: %v", value, err)
		}
		recovered, found, err := adapter.RecoverTXT(t.Context(), challenge)
		if err != nil || !found {
			t.Fatalf("recover %q found=%t error=%v", value, found, err)
		}
		challenge.TXTHandle = recovered
		if err := adapter.ObserveTXT(t.Context(), challenge); err != nil {
			t.Fatalf("observe recovered %q: %v", value, err)
		}
		if err := adapter.DeleteTXT(t.Context(), challenge); !isCode(err, CodeRecordMismatch) {
			t.Fatalf("delete shared value %q error=%v", value, err)
		}
	}
	if !reflect.DeepEqual(fake.values, values) || fake.postCalls != 0 || fake.putCalls != 0 || fake.deleteCalls != 0 {
		t.Fatalf("shared RRset mutated values=%v post=%d put=%d delete=%d",
			fake.values, fake.postCalls, fake.putCalls, fake.deleteCalls)
	}
}

func TestHuaweiConcurrentThirdValueCannotBeOverwritten(t *testing.T) {
	concurrent := []string{"sentinel_value", "target_value", "unexpected_value"}
	fake := &huaweiRRSetFake{
		exists: true, values: []string{"sentinel_value"}, driftAfterList: append([]string(nil), concurrent...),
	}
	adapter := newHuaweiRRSetAdapter(t, fake)
	if _, err := adapter.PresentTXT(t.Context(), huaweiChallenge("target_value")); !isCode(err, CodeRecordMismatch) {
		t.Fatalf("concurrent present error=%v", err)
	}
	if !reflect.DeepEqual(fake.values, concurrent) || fake.postCalls != 0 || fake.putCalls != 0 || fake.deleteCalls != 0 {
		t.Fatalf("concurrent RRset overwritten values=%v post=%d put=%d delete=%d",
			fake.values, fake.postCalls, fake.putCalls, fake.deleteCalls)
	}
}

func TestHuaweiSharedRRSetRejectsUnexpectedValuesWithoutMutation(t *testing.T) {
	for _, test := range []struct {
		name   string
		values []string
	}{
		{name: "third value", values: []string{"sentinel_value", "target_value", "unexpected_value"}},
		{name: "duplicate value", values: []string{"sentinel_value", "target_value", "target_value"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fake := &huaweiRRSetFake{exists: true, values: []string{"sentinel_value", "target_value"}}
			adapter := newHuaweiRRSetAdapter(t, fake)
			sentinel := huaweiChallenge("sentinel_value")
			target := huaweiChallenge("target_value")
			sentinelHandle, err := adapter.PresentTXT(t.Context(), sentinel)
			if err != nil {
				t.Fatal(err)
			}
			targetHandle, err := adapter.PresentTXT(t.Context(), target)
			if err != nil {
				t.Fatal(err)
			}
			fake.values = append([]string(nil), test.values...)
			baselinePuts, baselineDeletes := fake.putCalls, fake.deleteCalls
			target.TXTHandle = targetHandle
			if err := adapter.ObserveTXT(t.Context(), target); !isCode(err, CodeRecordMismatch) {
				t.Fatalf("observe error=%v", err)
			}
			if _, _, err := adapter.RecoverTXT(t.Context(), target); !isCode(err, CodeRecordMismatch) {
				t.Fatalf("recover error=%v", err)
			}
			if err := adapter.DeleteTXT(t.Context(), target); !isCode(err, CodeRecordMismatch) {
				t.Fatalf("delete error=%v", err)
			}
			sentinel.TXTHandle = sentinelHandle
			if err := adapter.DeleteTXT(t.Context(), sentinel); !isCode(err, CodeRecordMismatch) {
				t.Fatalf("sentinel delete error=%v", err)
			}
			if fake.putCalls != baselinePuts || fake.deleteCalls != baselineDeletes || !reflect.DeepEqual(fake.values, test.values) {
				t.Fatalf("destructive drift puts=%d deletes=%d values=%v", fake.putCalls, fake.deleteCalls, fake.values)
			}
		})
	}
}

func TestHuaweiSharedRRSetRejectsDuplicateAndIdentityDriftWithoutMutation(t *testing.T) {
	for _, drift := range []string{"id", "zone", "owner", "type"} {
		t.Run(drift, func(t *testing.T) {
			fake := &huaweiRRSetFake{}
			adapter := newHuaweiRRSetAdapter(t, fake)
			target := huaweiChallenge("target_value")
			handle, err := adapter.PresentTXT(t.Context(), target)
			if err != nil {
				t.Fatal(err)
			}
			target.TXTHandle = handle
			fake.getDrift = drift
			if err := adapter.ObserveTXT(t.Context(), target); err == nil {
				t.Fatal("identity drift observed as exact")
			}
			if err := adapter.DeleteTXT(t.Context(), target); err == nil {
				t.Fatal("identity drift deleted")
			}
			if fake.putCalls != 0 || fake.deleteCalls != 0 || !fake.exists {
				t.Fatalf("drift mutated puts=%d deletes=%d exists=%t", fake.putCalls, fake.deleteCalls, fake.exists)
			}
		})
	}

	fake := &huaweiRRSetFake{}
	adapter := newHuaweiRRSetAdapter(t, fake)
	target := huaweiChallenge("target_value")
	handle, err := adapter.PresentTXT(t.Context(), target)
	if err != nil {
		t.Fatal(err)
	}
	target.TXTHandle = handle
	fake.duplicateList = true
	if err := adapter.ObserveTXT(t.Context(), target); !isCode(err, CodeRecordMismatch) {
		t.Fatalf("duplicate observe error=%v", err)
	}
	if _, _, err := adapter.RecoverTXT(t.Context(), target); !isCode(err, CodeRecordMismatch) {
		t.Fatalf("duplicate recovery error=%v", err)
	}
	if _, err := adapter.PresentTXT(t.Context(), huaweiChallenge("third_value")); !isCode(err, CodeRecordMismatch) {
		t.Fatalf("duplicate present error=%v", err)
	}
	if fake.postCalls != 1 || fake.putCalls != 0 || fake.deleteCalls != 0 {
		t.Fatalf("duplicate mutated post=%d put=%d delete=%d", fake.postCalls, fake.putCalls, fake.deleteCalls)
	}
}

func TestHuaweiUnknownMutationOutcomesRemainReconcilable(t *testing.T) {
	for _, test := range []struct {
		name                string
		applied             bool
		deleteStatus        int
		confirmationUnknown bool
		cancelAfterDelete   bool
		revokeAfterDelete   bool
		wantCode            ErrorCode
		wantExists          bool
		wantListCalls       int
		wantGetCalls        int
	}{
		{name: "unavailable not applied", deleteStatus: http.StatusInternalServerError, wantCode: CodeUnavailable, wantExists: true, wantListCalls: 3, wantGetCalls: 2},
		{name: "unavailable applied", applied: true, deleteStatus: http.StatusInternalServerError, wantListCalls: 3, wantGetCalls: 2},
		{name: "timeout applied", applied: true, deleteStatus: http.StatusRequestTimeout, wantListCalls: 3, wantGetCalls: 2},
		{name: "rate limited not applied", deleteStatus: http.StatusTooManyRequests, wantCode: CodeRateLimited, wantExists: true, wantListCalls: 3, wantGetCalls: 2},
		{name: "confirmation unavailable fails closed", deleteStatus: http.StatusRequestTimeout, confirmationUnknown: true, wantCode: CodeUnavailable, wantExists: true, wantListCalls: 3, wantGetCalls: 2},
		{name: "credential revoked before settlement", applied: true, deleteStatus: http.StatusRequestTimeout, revokeAfterDelete: true, wantCode: CodeUnavailable, wantListCalls: 3, wantGetCalls: 2},
		{name: "caller cancellation skips confirmation", deleteStatus: http.StatusInternalServerError, cancelAfterDelete: true, wantCode: CodeCancelled, wantExists: true, wantListCalls: 2, wantGetCalls: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			fake := &huaweiRRSetFake{}
			adapter := newHuaweiRRSetAdapter(t, fake)
			sentinel := huaweiChallenge("sentinel_value")
			handle, err := adapter.PresentTXT(t.Context(), sentinel)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			source := adapter.source.(*staticSource)
			fake.unknownNextDelete = true
			fake.applyUnknownDelete = test.applied
			fake.unknownDeleteStatus = test.deleteStatus
			fake.afterUnknownDelete = func() {
				if test.confirmationUnknown {
					fake.unknownNextGet = true
				}
				if test.revokeAfterDelete {
					source.revokeCredential()
				}
				if test.cancelAfterDelete {
					cancel()
				}
			}
			baselineLists, baselineGets := fake.listCalls, fake.directGetCalls
			sentinel.TXTHandle = handle
			err = adapter.DeleteTXT(ctx, sentinel)
			if test.wantCode == "" && err != nil {
				t.Fatalf("delete error=%v, want success", err)
			}
			if test.wantCode != "" && !isCode(err, test.wantCode) {
				t.Fatalf("delete error=%v, want %s", err, test.wantCode)
			}
			if fake.exists != test.wantExists || fake.deleteCalls != 1 ||
				fake.listCalls-baselineLists != test.wantListCalls || fake.directGetCalls-baselineGets != test.wantGetCalls {
				t.Fatalf("state exists=%t delete=%d list=%d get=%d, want exists=%t delete=1 list=%d get=%d",
					fake.exists, fake.deleteCalls, fake.listCalls-baselineLists, fake.directGetCalls-baselineGets,
					test.wantExists, test.wantListCalls, test.wantGetCalls)
			}
		})
	}
}

func TestDeleteTXTUnknownOutcomeIdentityDriftFailsClosed(t *testing.T) {
	targetExists := false
	afterDelete := false
	describeCalls := 0
	deleteCalls := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("Action") {
		case "AddDomainRecord":
			targetExists = true
			writeTestJSON(t, w, map[string]any{"RequestId": "request-add", "RecordId": "record-ali-target"})
		case "DescribeDomainRecordInfo":
			describeCalls++
			relative := testRelative
			if afterDelete {
				relative = "other"
			}
			writeTestJSON(t, w, map[string]any{
				"RequestId": "request-get", "RecordId": "record-ali-target", "RR": relative,
				"Type": "TXT", "Value": testValue, "DomainName": testZone, "TTL": 60,
			})
		case "DeleteDomainRecord":
			deleteCalls++
			afterDelete = true
			w.WriteHeader(http.StatusBadGateway)
		default:
			t.Errorf("unexpected Aliyun action %q", r.URL.Query().Get("Action"))
			w.WriteHeader(http.StatusBadRequest)
		}
	})
	adapter, _ := newProviderTestAdapter(t, ProviderConfig{
		ProviderType: providerAliyun, ZoneName: testZone,
		Credentials: map[string]string{"access_key_id": "test-access-key", "access_key_secret": "aliyun-secret"},
	}, handler, time.Second)
	challenge := testChallenge()
	handle, err := adapter.PresentTXT(t.Context(), challenge)
	if err != nil {
		t.Fatal(err)
	}
	challenge.TXTHandle = handle
	baselineDescribes := describeCalls
	if err := adapter.DeleteTXT(t.Context(), challenge); !isCode(err, CodeRecordMismatch) {
		t.Fatalf("identity drift delete error=%v, want %s", err, CodeRecordMismatch)
	}
	if !targetExists || deleteCalls != 1 || describeCalls-baselineDescribes != 2 {
		t.Fatalf("identity drift state exists=%t delete=%d describe=%d, want true/1/2", targetExists, deleteCalls, describeCalls-baselineDescribes)
	}
}

func TestDNSPodLifecycleUsesRecordInfoBeforeRemove(t *testing.T) {
	const dpID = "123456"
	const dpKey = "dnspod-secret-key"
	targetExists := false
	otherExists := true
	deleteCalls := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "dnsapi.cn" || r.Method != http.MethodPost || r.ParseForm() != nil ||
			r.Form.Get("login_token") != dpID+","+dpKey || r.Form.Get("format") != "json" {
			t.Errorf("unexpected DNSPod request authentication")
		}
		switch r.URL.Path {
		case "/Record.Create":
			if r.Form.Get("domain") != testZone || r.Form.Get("sub_domain") != testRelative ||
				r.Form.Get("record_type") != "TXT" || r.Form.Get("record_line") != "默认" ||
				r.Form.Get("value") != testValue {
				t.Errorf("create form = %v", r.Form)
			}
			targetExists = true
			writeTestJSON(t, w, map[string]any{
				"status": map[string]any{"code": "1"},
				"record": map[string]any{"id": "record-dp-target", "name": testRelative, "status": "enable"},
			})
		case "/Record.Info":
			if r.Form.Get("domain") != testZone || r.Form.Get("record_id") != "record-dp-target" {
				t.Errorf("info form = %v", r.Form)
			}
			if !targetExists {
				writeTestJSON(t, w, map[string]any{"status": map[string]any{"code": "10"}})
				return
			}
			writeTestJSON(t, w, map[string]any{
				"status": map[string]any{"code": "1"},
				"domain": map[string]any{"id": "100", "domain": testZone},
				"record": map[string]any{
					"id": "record-dp-target", "sub_domain": testRelative, "record_type": "TXT", "value": testValue,
					"record_line": "默认", "ttl": "600",
				},
			})
		case "/Record.Remove":
			if r.Form.Get("record_id") != "record-dp-target" {
				t.Errorf("remove form = %v", r.Form)
			}
			deleteCalls++
			targetExists = false
			writeTestJSON(t, w, map[string]any{"status": map[string]any{"code": "1"}})
		default:
			t.Errorf("unexpected DNSPod request %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
	adapter, _ := newProviderTestAdapter(t, ProviderConfig{
		ProviderType: providerDNSPodCN, ZoneName: testZone,
		Credentials: map[string]string{"dp_id": dpID, "dp_key": dpKey},
	}, handler, time.Second)

	handle, err := adapter.PresentTXT(context.Background(), testChallenge())
	if err != nil {
		t.Fatalf("PresentTXT: %v", err)
	}
	requireHandle(t, handle, providerDNSPodCN, testZone, "record-dp-target")
	if err := adapter.ObserveTXT(context.Background(), testChallengeWithHandle(handle)); err != nil {
		t.Fatalf("ObserveTXT: %v", err)
	}
	if err := adapter.DeleteTXT(context.Background(), testChallengeWithHandle(handle)); err != nil {
		t.Fatalf("DeleteTXT: %v", err)
	}
	if err := adapter.DeleteTXT(context.Background(), testChallengeWithHandle(handle)); err != nil {
		t.Fatalf("idempotent DeleteTXT: %v", err)
	}
	if targetExists || !otherExists || deleteCalls != 1 {
		t.Fatalf("target=%v other=%v deleteCalls=%d", targetExists, otherExists, deleteCalls)
	}
}

func TestDNSComLifecycleSignsAndUsesGetOne(t *testing.T) {
	const apiKey = "dnscom-api-key"
	const apiSecret = "dnscom-secret"
	targetExists := false
	otherExists := true
	deleteCalls := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "openapi.dns.com" || r.Method != http.MethodGet ||
			!verifyDNSComTestSignature(r.URL.Query(), apiSecret) || r.URL.Query().Get("api_key") != apiKey {
			t.Errorf("unexpected DNS.COM signed request: %s", r.URL.String())
		}
		switch r.URL.Path {
		case "/api/record/create/":
			if r.URL.Query().Get("domain") != testZone || r.URL.Query().Get("record") != testRelative ||
				r.URL.Query().Get("type") != "TXT" || r.URL.Query().Get("value") != testValue {
				t.Errorf("create query = %s", r.URL.RawQuery)
			}
			targetExists = true
			writeTestJSON(t, w, map[string]any{"code": 0, "data": map[string]any{
				"domain_id": "zone-dnscom", "record_id": "record-dnscom-target", "record": testRelative,
				"type": "TXT", "value": testValue, "ttl": 600,
			}})
		case "/api/record/getOne/":
			if r.URL.Query().Get("domain") != "zone-dnscom" || r.URL.Query().Get("record_id") != "record-dnscom-target" {
				t.Errorf("getOne query = %s", r.URL.RawQuery)
			}
			if !targetExists {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			writeTestJSON(t, w, map[string]any{"code": 0, "data": map[string]any{
				"domain_id": "zone-dnscom", "record_id": "record-dnscom-target", "record": testRelative,
				"type": "TXT", "value": testValue, "ttl": 600,
			}})
		case "/api/record/operate/":
			if r.URL.Query().Get("domain") != "zone-dnscom" || r.URL.Query().Get("record_id") != "record-dnscom-target" ||
				r.URL.Query().Get("status") != "delete" {
				t.Errorf("operate query = %s", r.URL.RawQuery)
			}
			deleteCalls++
			targetExists = false
			writeTestJSON(t, w, map[string]any{"code": 0, "data": nil})
		default:
			t.Errorf("unexpected DNS.COM request %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
	adapter, _ := newProviderTestAdapter(t, ProviderConfig{
		ProviderType: providerDNSCom, ZoneName: testZone,
		Credentials: map[string]string{"api_key": apiKey, "api_secret": apiSecret},
	}, handler, time.Second)

	handle, err := adapter.PresentTXT(context.Background(), testChallenge())
	if err != nil {
		t.Fatalf("PresentTXT: %v", err)
	}
	requireHandle(t, handle, providerDNSCom, "zone-dnscom", "record-dnscom-target")
	if err := adapter.ObserveTXT(context.Background(), testChallengeWithHandle(handle)); err != nil {
		t.Fatalf("ObserveTXT: %v", err)
	}
	assertRemoteError(t, adapter.DeleteTXT(context.Background(), testChallengeWithHandle(handle)), CodeInvalidResponse)
	assertRemoteError(t, adapter.DeleteTXT(context.Background(), testChallengeWithHandle(handle)), CodeInvalidResponse)
	if targetExists || !otherExists || deleteCalls != 1 {
		t.Fatalf("target=%v other=%v deleteCalls=%d", targetExists, otherExists, deleteCalls)
	}
}

func verifyDNSComTestSignature(query url.Values, secret string) bool {
	provided := query.Get("sign")
	parameters := make(map[string]string, len(query)-1)
	for name, values := range query {
		if name != "sign" && len(values) == 1 {
			parameters[name] = values[0]
		}
	}
	return hmac.Equal([]byte(provided), []byte(signDNSCom(parameters, secret)))
}

func TestDNSLALifecycleUsesBasicAuthAndFilteredRecordList(t *testing.T) {
	const apiID = "dnsla-api-id"
	const apiSecret = "dnsla-secret"
	targetExists := false
	otherExists := true
	deleteCalls := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if r.Host != "api.dns.la" || !ok || username != apiID || password != apiSecret {
			t.Errorf("unexpected DNS.LA authentication")
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/domain":
			if r.URL.Query().Get("domain") != testZone {
				t.Errorf("domain query = %s", r.URL.RawQuery)
			}
			writeTestJSON(t, w, map[string]any{"code": 200, "data": map[string]any{
				"id": "zone-dnsla", "domain": testZone + ".",
			}})
		case r.Method == http.MethodPost && r.URL.Path == "/api/record":
			var body struct {
				DomainID string `json:"domainId"`
				Type     int    `json:"type"`
				Host     string `json:"host"`
				Data     string `json:"data"`
				TTL      int    `json:"ttl"`
			}
			if json.NewDecoder(r.Body).Decode(&body) != nil || body.DomainID != "zone-dnsla" || body.Type != 16 ||
				body.Host != testRelative || body.Data != testValue || body.TTL != 600 {
				t.Errorf("create body = %+v", body)
			}
			targetExists = true
			writeTestJSON(t, w, map[string]any{"code": 200, "data": map[string]any{"id": "record-dnsla-target"}})
		case r.Method == http.MethodGet && r.URL.Path == "/api/recordList":
			query := r.URL.Query()
			if query.Get("domainId") != "zone-dnsla" || query.Get("type") != "16" ||
				query.Get("host") != testRelative || query.Get("pageSize") != "100" ||
				(targetExists && query.Get("data") != testValue) {
				t.Errorf("record list query = %s", r.URL.RawQuery)
			}
			results := []any{}
			if targetExists {
				results = append(results, map[string]any{
					"id": "record-dnsla-target", "domainId": "zone-dnsla", "host": testRelative,
					"type": 16, "data": testValue, "ttl": 600,
				})
			}
			writeTestJSON(t, w, map[string]any{"code": 200, "data": map[string]any{
				"total": len(results), "results": results,
			}})
		case r.Method == http.MethodDelete && r.URL.Path == "/api/record":
			if r.URL.Query().Get("id") != "record-dnsla-target" {
				t.Errorf("delete query = %s", r.URL.RawQuery)
			}
			deleteCalls++
			targetExists = false
			writeTestJSON(t, w, map[string]any{"code": 200, "data": nil})
		default:
			t.Errorf("unexpected DNS.LA request %s %s", r.Method, r.URL.String())
			w.WriteHeader(http.StatusNotFound)
		}
	})
	adapter, source := newProviderTestAdapter(t, ProviderConfig{
		ProviderType: providerDNSLA, ZoneName: testZone,
		Credentials: map[string]string{"api_id": apiID, "api_secret": apiSecret},
	}, handler, time.Second)

	handle, err := adapter.PresentTXT(context.Background(), testChallenge())
	if err != nil {
		t.Fatalf("PresentTXT: %v", err)
	}
	requireHandle(t, handle, providerDNSLA, "zone-dnsla", "record-dnsla-target")
	if err := adapter.ObserveTXT(context.Background(), testChallengeWithHandle(handle)); err != nil {
		t.Fatalf("ObserveTXT: %v", err)
	}
	if err := adapter.DeleteTXT(context.Background(), testChallengeWithHandle(handle)); err != nil {
		t.Fatalf("DeleteTXT: %v", err)
	}
	if err := adapter.DeleteTXT(context.Background(), testChallengeWithHandle(handle)); err != nil {
		t.Fatalf("idempotent DeleteTXT: %v", err)
	}
	if targetExists || !otherExists || deleteCalls != 1 || source.callCount() != 4 {
		t.Fatalf("target=%v other=%v deleteCalls=%d sourceCalls=%d", targetExists, otherExists, deleteCalls, source.callCount())
	}
}

func TestOfficialSignatureVectors(t *testing.T) {
	aliyunParameters := map[string]string{
		"AccessKeyId": "test-access-key", "Action": "DescribeDomains", "Format": "JSON",
		"SignatureMethod": "HMAC-SHA1", "SignatureNonce": "nonce-123", "SignatureVersion": "1.0",
		"Timestamp": "2026-07-22T03:04:05Z", "Version": "2015-01-09",
	}
	mac := hmac.New(sha1.New, []byte("test-access-secret&"))
	canonical := aliyunCanonicalQuery(aliyunParameters)
	_, _ = mac.Write([]byte("GET&%2F&" + aliyunPercentEncode(canonical)))
	if got := base64.StdEncoding.EncodeToString(mac.Sum(nil)); got != "ds2CO9GpxNEdQzZRKiLG6Bd0aX8=" {
		t.Fatalf("Aliyun signature = %q", got)
	}

	huawei := signHuaweiRequest(
		http.MethodGet, "/path/", "limit=1", map[string]string{"X-Sdk-Date": "20060102T150405Z"},
		nil, "AccessKey", "SecretKey", "20060102T150405Z",
	)
	if huawei != "SDK-HMAC-SHA256 Access=AccessKey, SignedHeaders=x-sdk-date, "+
		"Signature=5a2ce64c865e0e6046321c6f3d5a77ba8413eeaf355c3166c03d58d02ac79624" {
		t.Fatalf("Huawei authorization = %q", huawei)
	}

	dnsComParameters := map[string]string{
		"timestamp": "1521005892", "api_key": "c7722149110b7492a2e5cf1d8f3f966b", "domain": "dns.com",
	}
	if got := signDNSCom(dnsComParameters, "ecb4ff0e877a83292b9f35067e9ae673"); got != "54fe71ca13c97703fadeed7aacc80a15" {
		t.Fatalf("DNS.COM signature = %q", got)
	}
}
