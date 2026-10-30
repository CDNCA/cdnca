package dnsproviderremote

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/acmeworker"
	"github.com/google/uuid"
)

type credentialFenceSource106 struct{ err error }

func (s credentialFenceSource106) Resolve(context.Context, ProviderLookup) (ProviderConfig, error) {
	return ProviderConfig{}, nil
}

type interleavingCredentialSource106 struct {
	*staticSource
	fenceCalls int
	failAt     int
}

func (s *interleavingCredentialSource106) CheckCredentialFence(context.Context, ProviderLookup, uint64) error {
	s.fenceCalls++
	if s.fenceCalls == s.failAt {
		return errors.New("credential fence changed")
	}
	return nil
}

func (s credentialFenceSource106) CheckCredentialFence(context.Context, ProviderLookup, uint64) error {
	return s.err
}

func TestCredentialLifecycle106FenceRejectsRotationAndRevocation(t *testing.T) {
	adapter := &Adapter{source: credentialFenceSource106{err: errors.New("revoked")}}
	config := ProviderConfig{
		TenantScopeID: uuid.New(), ProviderID: uuid.New(), ZoneID: uuid.New(),
		CredentialVersion: 4,
	}
	err := adapter.checkCredentialFence(context.Background(), config, "_acme-challenge.example.com.")
	if !isCode(err, CodeUnavailable) {
		t.Fatalf("fence error=%v, want temporary unavailable", err)
	}
	remoteErr, ok := err.(*Error)
	if !ok || !remoteErr.Temporary {
		t.Fatalf("fence error=%T %v is not temporary", err, err)
	}
}

func TestCredentialLifecycle106FenceRejectsExplicitRevocation(t *testing.T) {
	adapter := &Adapter{source: credentialFenceSource106{}}
	err := adapter.checkCredentialFence(context.Background(), ProviderConfig{
		TenantScopeID: uuid.New(), ProviderID: uuid.New(), CredentialVersion: 4,
		CredentialRevoked: true,
	}, "_acme-challenge.example.com.")
	if !isCode(err, CodeUnavailable) {
		t.Fatalf("revoked fence error=%v, want unavailable", err)
	}
	remoteErr, ok := err.(*Error)
	if !ok || !remoteErr.Temporary {
		t.Fatalf("revoked fence error=%T %v is not temporary", err, err)
	}
}

func TestCredentialLifecycle106LegacyConfigRemainsCompatible(t *testing.T) {
	adapter := &Adapter{}
	err := adapter.checkCredentialFence(context.Background(), ProviderConfig{}, "example.com.")
	if err != nil {
		t.Fatalf("legacy zero-version config fence=%v", err)
	}
}

func TestCredentialLifecycle106InterleavingPresentFailsUnknownAfterMutation(t *testing.T) {
	var creates atomic.Int32
	adapter, source := newCredentialInterleavingAdapter106(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones":
			writeTestJSON(t, w, map[string]any{"success": true, "result": []any{
				map[string]any{"id": "zone-106", "name": testZone},
			}})
		case r.Method == http.MethodPost && r.URL.Path == "/zones/zone-106/dns_records":
			creates.Add(1)
			writeTestJSON(t, w, map[string]any{"success": true, "result": map[string]any{
				"id": "record-106", "zone_id": "zone-106", "name": testOwner,
				"type": "TXT", "content": testValue,
			}})
		default:
			http.NotFound(w, r)
		}
	}), 2)
	if _, err := adapter.PresentTXT(t.Context(), testChallenge()); !isCode(err, CodeUnavailable) {
		t.Fatalf("PresentTXT interleaving error=%v", err)
	}
	if creates.Load() != 1 || source.fenceCalls != 2 {
		t.Fatalf("creates=%d fences=%d", creates.Load(), source.fenceCalls)
	}
}

func TestCredentialLifecycle106InterleavingRecoverFailsBeforeMint(t *testing.T) {
	adapter, source := newCredentialInterleavingAdapter106(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones":
			writeTestJSON(t, w, map[string]any{"success": true, "result": []any{
				map[string]any{"id": "zone-106", "name": testZone},
			}})
		case r.Method == http.MethodGet && r.URL.Path == "/zones/zone-106/dns_records":
			writeTestJSON(t, w, map[string]any{
				"success": true,
				"result": []any{map[string]any{
					"id": "record-106", "zone_id": "zone-106", "name": testOwner,
					"type": "TXT", "content": testValue,
				}},
				"result_info": map[string]any{
					"page": 1, "per_page": recoveryPageSize, "count": 1,
					"total_count": 1, "total_pages": 1,
				},
			})
		default:
			http.NotFound(w, r)
		}
	}), 2)
	handle, found, err := adapter.RecoverTXT(t.Context(), testChallenge())
	if !isCode(err, CodeUnavailable) || found || handle != (acmeworker.RemoteTXTHandle{}) {
		t.Fatalf("RecoverTXT interleaving=(%+v,%t,%v)", handle, found, err)
	}
	if source.fenceCalls != 2 {
		t.Fatalf("fences=%d", source.fenceCalls)
	}
}

func TestCredentialLifecycle106InterleavingDeleteFinalAbsenceFailsUnknown(t *testing.T) {
	var gets atomic.Int32
	var deletes atomic.Int32
	adapter, source := newCredentialInterleavingAdapter106(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones/zone-106/dns_records/record-106":
			if gets.Add(1) == 1 {
				writeTestJSON(t, w, map[string]any{"success": true, "result": map[string]any{
					"id": "record-106", "zone_id": "zone-106", "name": testOwner,
					"type": "TXT", "content": testValue,
				}})
				return
			}
			w.WriteHeader(http.StatusNotFound)
		case r.Method == http.MethodDelete && r.URL.Path == "/zones/zone-106/dns_records/record-106":
			deletes.Add(1)
			writeTestJSON(t, w, map[string]any{"success": true, "result": map[string]any{"id": "record-106"}})
		default:
			http.NotFound(w, r)
		}
	}), 3)
	handle, err := encodeTestHandle(t, testChallenge(), source.config, recordHandle{
		Provider: providerCloudflare, Zone: testZone, ZoneID: "zone-106",
		RecordID: "record-106", Owner: testOwner,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = adapter.DeleteTXT(t.Context(), testChallengeWithHandle(handle))
	if !isCode(err, CodeUnavailable) {
		t.Fatalf("DeleteTXT final fence error=%v", err)
	}
	if deletes.Load() != 1 || gets.Load() != 2 || source.fenceCalls != 3 {
		t.Fatalf("deletes=%d gets=%d fences=%d", deletes.Load(), gets.Load(), source.fenceCalls)
	}
}

func TestCredentialLifecycle106FinalFenceCoversPresentRemoteOutcomes(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		stableCode ErrorCode
	}{
		{name: "permanent rejection", status: http.StatusUnauthorized, stableCode: CodeCredentialsRejected},
		{name: "transient rate limit", status: http.StatusTooManyRequests, stableCode: CodeRateLimited},
		{name: "unknown mutation outcome", status: http.StatusBadGateway, stableCode: CodeUnavailable},
	}
	for _, test := range tests {
		for _, fenceDrifts := range []bool{false, true} {
			name := "stable"
			failAt := 0
			wantCode := test.stableCode
			if fenceDrifts {
				name = "rotated-or-revoked"
				failAt = 2
				wantCode = CodeUnavailable
			}
			t.Run(test.name+"/"+name, func(t *testing.T) {
				var creates atomic.Int32
				adapter, source := newCredentialInterleavingAdapter106(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					switch {
					case r.Method == http.MethodGet && r.URL.Path == "/zones":
						writeTestJSON(t, w, map[string]any{"success": true, "result": []any{
							map[string]any{"id": "zone-106", "name": testZone},
						}})
					case r.Method == http.MethodPost && r.URL.Path == "/zones/zone-106/dns_records":
						creates.Add(1)
						w.Header().Set("Retry-After", "11")
						w.WriteHeader(test.status)
					default:
						http.NotFound(w, r)
					}
				}), failAt)
				if _, err := adapter.PresentTXT(t.Context(), testChallenge()); !isCode(err, wantCode) {
					t.Fatalf("PresentTXT error=%v, want %s", err, wantCode)
				}
				if creates.Load() != 1 || source.fenceCalls != 2 {
					t.Fatalf("creates=%d fences=%d, want 1/2", creates.Load(), source.fenceCalls)
				}
			})
		}
	}
}

func TestCredentialLifecycle106FinalFenceCoversRecoveryAndObservationOutcomes(t *testing.T) {
	t.Run("recover remote error", func(t *testing.T) {
		adapter, source := newCredentialInterleavingAdapter106(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == http.MethodGet && r.URL.Path == "/zones":
				writeTestJSON(t, w, map[string]any{"success": true, "result": []any{
					map[string]any{"id": "zone-106", "name": testZone},
				}})
			case r.Method == http.MethodGet && r.URL.Path == "/zones/zone-106/dns_records":
				w.WriteHeader(http.StatusUnauthorized)
			default:
				http.NotFound(w, r)
			}
		}), 2)
		handle, found, err := adapter.RecoverTXT(t.Context(), testChallenge())
		if !isCode(err, CodeUnavailable) || found || handle != (acmeworker.RemoteTXTHandle{}) {
			t.Fatalf("RecoverTXT=(%+v,%t,%v), want empty/false/unavailable", handle, found, err)
		}
		if source.fenceCalls != 2 {
			t.Fatalf("fences=%d, want 2", source.fenceCalls)
		}
	})

	t.Run("observe identity mismatch", func(t *testing.T) {
		adapter, source, challenge := newCredentialCloudflareHandleAdapter106(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeTestJSON(t, w, map[string]any{"success": true, "result": map[string]any{
				"id": "record-106", "zone_id": "zone-106", "name": testOwner,
				"type": "TXT", "content": testOtherValue,
			}})
		}), 2)
		if err := adapter.ObserveTXT(t.Context(), challenge); !isCode(err, CodeUnavailable) {
			t.Fatalf("ObserveTXT error=%v, want unavailable", err)
		}
		if source.fenceCalls != 2 {
			t.Fatalf("fences=%d, want 2", source.fenceCalls)
		}
	})

	t.Run("observe not found", func(t *testing.T) {
		adapter, source, challenge := newCredentialCloudflareHandleAdapter106(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}), 2)
		if err := adapter.ObserveTXT(t.Context(), challenge); !isCode(err, CodeUnavailable) {
			t.Fatalf("ObserveTXT error=%v, want unavailable", err)
		}
		if source.fenceCalls != 2 {
			t.Fatalf("fences=%d, want 2", source.fenceCalls)
		}
	})
}

func TestCredentialLifecycle106FinalFenceCoversDeleteOutcomes(t *testing.T) {
	t.Run("mutation error is fenced without retry", func(t *testing.T) {
		var deletes atomic.Int32
		adapter, source, challenge := newCredentialCloudflareHandleAdapter106(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				writeCredentialCloudflareRecord106(t, w, testValue)
			case http.MethodDelete:
				deletes.Add(1)
				w.Header().Set("Retry-After", "13")
				w.WriteHeader(http.StatusTooManyRequests)
			default:
				http.NotFound(w, r)
			}
		}), 2)
		if err := adapter.DeleteTXT(t.Context(), challenge); !isCode(err, CodeUnavailable) {
			t.Fatalf("DeleteTXT error=%v, want unavailable", err)
		}
		if deletes.Load() != 1 || source.fenceCalls != 2 {
			t.Fatalf("deletes=%d fences=%d, want 1/2", deletes.Load(), source.fenceCalls)
		}
	})

	for _, fenceDrifts := range []bool{false, true} {
		name := "stable mismatch"
		failAt := 0
		wantCode := CodeRecordMismatch
		if fenceDrifts {
			name = "mismatch after rotation-or-revocation"
			failAt = 3
			wantCode = CodeUnavailable
		}
		t.Run(name, func(t *testing.T) {
			var gets, deletes atomic.Int32
			adapter, source, challenge := newCredentialCloudflareHandleAdapter106(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.Method {
				case http.MethodGet:
					value := testValue
					if gets.Add(1) == 2 {
						value = testOtherValue
					}
					writeCredentialCloudflareRecord106(t, w, value)
				case http.MethodDelete:
					deletes.Add(1)
					writeTestJSON(t, w, map[string]any{"success": true, "result": map[string]any{"id": "record-106"}})
				default:
					http.NotFound(w, r)
				}
			}), failAt)
			if err := adapter.DeleteTXT(t.Context(), challenge); !isCode(err, wantCode) {
				t.Fatalf("DeleteTXT error=%v, want %s", err, wantCode)
			}
			if gets.Load() != 2 || deletes.Load() != 1 || source.fenceCalls != 3 {
				t.Fatalf("gets=%d deletes=%d fences=%d, want 2/1/3", gets.Load(), deletes.Load(), source.fenceCalls)
			}
		})
	}
}

func TestCredentialLifecycle106FinalFenceCoversDNSLAConfirmation(t *testing.T) {
	const (
		zoneID   = "zone-dnsla-106"
		recordID = "record-dnsla-106"
	)
	var lists, deletes atomic.Int32
	config := ProviderConfig{
		ProviderType: providerDNSLA, ZoneName: testZone, CredentialVersion: 7,
		Credentials: map[string]string{"api_id": "credential-106-id", "api_secret": "credential-106-secret"},
	}
	adapter, source := newCredentialInterleavingAdapterWithConfig106(t, config, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/recordList":
			value := testValue
			if lists.Add(1) == 2 {
				value = testOtherValue
			}
			writeTestJSON(t, w, map[string]any{"code": http.StatusOK, "data": map[string]any{
				"total": 1, "results": []map[string]any{{
					"id": recordID, "domainId": zoneID, "host": testRelative,
					"type": 16, "data": value, "ttl": 600,
				}},
			}})
		case r.Method == http.MethodDelete && r.URL.Path == "/api/record":
			deletes.Add(1)
			writeTestJSON(t, w, map[string]any{"code": http.StatusOK, "data": nil})
		default:
			http.NotFound(w, r)
		}
	}), 3)
	handle, err := encodeTestHandle(t, testChallenge(), config, recordHandle{
		Provider: providerDNSLA, Zone: testZone, ZoneID: zoneID, RecordID: recordID, Owner: testOwner,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.DeleteTXT(t.Context(), testChallengeWithHandle(handle)); !isCode(err, CodeUnavailable) {
		t.Fatalf("DeleteTXT DNS.LA confirmation error=%v, want unavailable", err)
	}
	if lists.Load() != 2 || deletes.Load() != 1 || source.fenceCalls != 3 {
		t.Fatalf("lists=%d deletes=%d fences=%d, want 2/1/3", lists.Load(), deletes.Load(), source.fenceCalls)
	}
}

func newCredentialInterleavingAdapter106(
	t *testing.T,
	handler http.Handler,
	failAt int,
) (*Adapter, *interleavingCredentialSource106) {
	t.Helper()
	return newCredentialInterleavingAdapterWithConfig106(t, ProviderConfig{
		ProviderType: providerCloudflare, ZoneName: testZone,
		Credentials:       map[string]string{"api_token": "secret-token-106"},
		CredentialVersion: 7,
	}, handler, failAt)
}

func newCredentialInterleavingAdapterWithConfig106(
	t *testing.T,
	config ProviderConfig,
	handler http.Handler,
	failAt int,
) (*Adapter, *interleavingCredentialSource106) {
	t.Helper()
	adapter, static := newProviderTestAdapter(t, config, handler, requestTimeout)
	source := &interleavingCredentialSource106{staticSource: static, failAt: failAt}
	adapter.source = source
	return adapter, source
}

func newCredentialCloudflareHandleAdapter106(
	t *testing.T,
	handler http.Handler,
	failAt int,
) (*Adapter, *interleavingCredentialSource106, acmeworker.ChallengeIdentity) {
	t.Helper()
	adapter, source := newCredentialInterleavingAdapter106(t, handler, failAt)
	handle, err := encodeTestHandle(t, testChallenge(), source.config, recordHandle{
		Provider: providerCloudflare, Zone: testZone, ZoneID: "zone-106",
		RecordID: "record-106", Owner: testOwner,
	})
	if err != nil {
		t.Fatal(err)
	}
	return adapter, source, testChallengeWithHandle(handle)
}

func writeCredentialCloudflareRecord106(t *testing.T, w http.ResponseWriter, value string) {
	t.Helper()
	writeTestJSON(t, w, map[string]any{"success": true, "result": map[string]any{
		"id": "record-106", "zone_id": "zone-106", "name": testOwner,
		"type": "TXT", "content": value,
	}})
}
