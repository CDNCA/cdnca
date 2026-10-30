package dnsproviderremote

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/acmeworker"
	"github.com/google/uuid"
)

type outstandingOnlySource struct{}

func (outstandingOnlySource) OutstandingRemoteTXTHandles(context.Context) ([]acmeworker.ChallengeIdentity, error) {
	return nil, nil
}

func TestV2HandleBindsCompleteChallengeBeforeSourceOrHTTP(t *testing.T) {
	var requests atomic.Int32
	adapter, source := newProviderTestAdapter(t, testProviderConfig(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones":
			writeTestJSON(t, w, map[string]any{"success": true, "result": []any{
				map[string]any{"id": "remote-zone", "name": testZone},
			}})
		case r.Method == http.MethodPost:
			writeTestJSON(t, w, map[string]any{"success": true, "result": map[string]any{
				"id": "remote-record", "zone_id": "remote-zone", "name": testOwner,
				"type": "TXT", "content": testValue,
			}})
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}), requestTimeout)
	challenge := testPersistedChallenge()
	handle, err := adapter.PresentTXT(t.Context(), challenge)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(handle.RecordRef, "v2.test-active.") || len(handle.RecordRef) >= 2048 ||
		strings.Contains(handle.RecordRef, challenge.ExactValue) {
		t.Fatalf("invalid v2 handle length=%d value=%q", len(handle.RecordRef), handle.RecordRef)
	}
	challenge.TXTHandle = handle
	baselineSource := source.callCount()
	baselineHTTP := requests.Load()

	mutations := []struct {
		name   string
		mutate func(*acmeworker.ChallengeIdentity)
	}{
		{name: "tenant", mutate: func(item *acmeworker.ChallengeIdentity) { item.TenantID = uuid.New() }},
		{name: "operation", mutate: func(item *acmeworker.ChallengeIdentity) { item.OperationID = uuid.NewString() }},
		{name: "attempt", mutate: func(item *acmeworker.ChallengeIdentity) { item.AttemptID = uuid.New() }},
		{name: "provider", mutate: func(item *acmeworker.ChallengeIdentity) { item.ProviderRef = uuid.NewString() }},
		{name: "owner", mutate: func(item *acmeworker.ChallengeIdentity) { item.RecordName = "_acme-challenge.other.test." }},
		{name: "value", mutate: func(item *acmeworker.ChallengeIdentity) { item.ExactValue = testOtherValue }},
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			changed := challenge
			test.mutate(&changed)
			assertRemoteError(t, adapter.ObserveTXT(t.Context(), changed), CodeRecordMismatch)
			assertRemoteError(t, adapter.DeleteTXT(t.Context(), changed), CodeRecordMismatch)
		})
	}
	if source.callCount() != baselineSource || requests.Load() != baselineHTTP {
		t.Fatalf("unauthenticated identity reached source/http: source=%d/%d http=%d/%d",
			source.callCount(), baselineSource, requests.Load(), baselineHTTP)
	}
}

func TestV2HandleTamperingFailsBeforeSourceOrHTTP(t *testing.T) {
	keyring := testHandleKeyring(t)
	challenge := testPersistedChallenge()
	config := testProviderConfig()
	handle, err := encodeHandle(challenge, config, recordHandle{
		Provider: providerCloudflare, Zone: testZone, ZoneID: "remote-zone",
		RecordID: "remote-record", Owner: testOwner,
	}, keyring)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(handle.RecordRef, ".")
	if len(parts) != 4 {
		t.Fatalf("handle parts = %d", len(parts))
	}
	mutations := map[string]string{
		"prefix":  "v3." + strings.Join(parts[1:], "."),
		"kid":     "v2.unknown." + parts[2] + "." + parts[3],
		"payload": "v2." + parts[1] + "." + flipBase64(parts[2]) + "." + parts[3],
		"mac":     "v2." + parts[1] + "." + parts[2] + "." + flipBase64(parts[3]),
		"base64":  "v2." + parts[1] + ".not+base64." + parts[3],
		"length":  "v2." + parts[1] + "." + strings.Repeat("a", 2048) + "." + parts[3],
	}
	for name, recordRef := range mutations {
		t.Run(name, func(t *testing.T) {
			var requests atomic.Int32
			source := &staticSource{config: config}
			adapter := newAdapter(source, keyring, roundTripFunc(func(*http.Request) (*http.Response, error) {
				requests.Add(1)
				return nil, context.Canceled
			}), productionEndpoints(), requestTimeout, nil, nil)
			changed := challenge
			changed.TXTHandle = acmeworker.RemoteTXTHandle{ProviderRef: challenge.ProviderRef, RecordRef: recordRef}
			assertRemoteError(t, adapter.ObserveTXT(t.Context(), changed), CodeInvalidInput)
			assertRemoteError(t, adapter.DeleteTXT(t.Context(), changed), CodeInvalidInput)
			if source.callCount() != 0 || requests.Load() != 0 {
				t.Fatalf("tamper reached source/http: source=%d http=%d", source.callCount(), requests.Load())
			}
		})
	}
}

func TestHandleKeyringRotationValidatesOutstandingV2References(t *testing.T) {
	oldRing, err := NewHandleKeyring(HandleKey{ID: "old", Secret: bytes.Repeat([]byte{1}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	challenge := testPersistedChallenge()
	oldHandle, err := encodeHandle(challenge, testProviderConfig(), recordHandle{
		Provider: providerCloudflare, Zone: testZone, ZoneID: "zone", RecordID: "record", Owner: testOwner,
	}, oldRing)
	if err != nil {
		t.Fatal(err)
	}
	challenge.TXTHandle = oldHandle
	source := &staticSource{config: testProviderConfig(), outstanding: []acmeworker.ChallengeIdentity{challenge}}

	rotated, err := NewHandleKeyring(
		HandleKey{ID: "new", Secret: bytes.Repeat([]byte{2}, 32)},
		HandleKey{ID: "old", Secret: bytes.Repeat([]byte{1}, 32)},
	)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := Open(t.Context(), source, rotated)
	if err != nil || opened.Ready() != nil {
		t.Fatalf("active plus verify-only rotation: adapter=%v error=%v", opened, err)
	}

	for _, test := range []struct {
		name string
		key  HandleKey
	}{
		{name: "removed", key: HandleKey{ID: "new", Secret: bytes.Repeat([]byte{2}, 32)}},
		{name: "same kid changed key", key: HandleKey{ID: "old", Secret: bytes.Repeat([]byte{9}, 32)}},
	} {
		t.Run(test.name, func(t *testing.T) {
			ring, err := NewHandleKeyring(test.key)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Open(t.Context(), source, ring); err == nil {
				t.Fatal("factory accepted an unverifiable outstanding handle")
			}
		})
	}
}

func TestOpenValidatesOutstandingChallengeIdentity(t *testing.T) {
	keyring := testHandleKeyring(t)
	challenge := testPersistedChallenge()
	handle, err := encodeHandle(challenge, testProviderConfig(), recordHandle{
		Provider: providerCloudflare, Zone: testZone, ZoneID: "zone", RecordID: "record", Owner: testOwner,
	}, keyring)
	if err != nil {
		t.Fatal(err)
	}
	challenge.TXTHandle = handle

	t.Run("complete v2", func(t *testing.T) {
		source := &staticSource{config: testProviderConfig(), outstanding: []acmeworker.ChallengeIdentity{challenge}}
		adapter, err := Open(t.Context(), source, keyring)
		if err != nil || adapter.Ready() != nil || source.callCount() != 1 {
			t.Fatalf("Open() adapter=%v error=%v sourceCalls=%d", adapter, err, source.callCount())
		}
	})

	for _, test := range []struct {
		name   string
		config ProviderConfig
		err    error
		code   ErrorCode
	}{
		{name: "provider type drift", config: func() ProviderConfig {
			config := testProviderConfig()
			config.ProviderType = providerDNSLA
			config.Credentials = map[string]string{"api_id": "id", "api_secret": "secret"}
			return config
		}(), code: CodeRecordMismatch},
		{name: "managed zone id drift", config: func() ProviderConfig {
			config := testProviderConfig()
			config.ZoneID = uuid.New()
			return config
		}(), code: CodeRecordMismatch},
		{name: "managed zone name drift", config: func() ProviderConfig {
			config := testProviderConfig()
			config.ZoneName = "other.test"
			return config
		}(), code: CodeInvalidInput},
		{name: "provider no longer resolvable", config: testProviderConfig(), err: errors.New("provider disabled"), code: CodeSourceUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			var requests atomic.Int32
			source := &staticSource{config: test.config, err: test.err}
			adapter := newAdapter(source, keyring, roundTripFunc(func(*http.Request) (*http.Response, error) {
				requests.Add(1)
				return nil, context.Canceled
			}), productionEndpoints(), requestTimeout, nil, nil)
			err := adapter.validateOutstandingChallenge(t.Context(), challenge)
			assertRemoteError(t, err, test.code)
			if source.callCount() != 1 || requests.Load() != 0 {
				t.Fatalf("startup drift sourceCalls=%d httpCalls=%d", source.callCount(), requests.Load())
			}
		})
	}

	mutations := []struct {
		name   string
		mutate func(*acmeworker.ChallengeIdentity)
	}{
		{name: "missing tenant", mutate: func(item *acmeworker.ChallengeIdentity) { item.TenantID = uuid.Nil }},
		{name: "tenant", mutate: func(item *acmeworker.ChallengeIdentity) { item.TenantID = uuid.New() }},
		{name: "operation", mutate: func(item *acmeworker.ChallengeIdentity) { item.OperationID = uuid.NewString() }},
		{name: "attempt", mutate: func(item *acmeworker.ChallengeIdentity) { item.AttemptID = uuid.New() }},
		{name: "provider", mutate: func(item *acmeworker.ChallengeIdentity) { item.ProviderRef = uuid.NewString() }},
		{name: "owner", mutate: func(item *acmeworker.ChallengeIdentity) { item.RecordName = "_acme-challenge.other.test." }},
		{name: "value", mutate: func(item *acmeworker.ChallengeIdentity) { item.ExactValue = testOtherValue }},
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			changed := challenge
			test.mutate(&changed)
			source := &staticSource{config: testProviderConfig(), outstanding: []acmeworker.ChallengeIdentity{changed}}
			adapter, err := Open(t.Context(), source, keyring)
			if adapter != nil {
				t.Fatal("Open() returned an adapter for a mismatched challenge")
			}
			assertRemoteError(t, err, CodeSourceUnavailable)
			if source.callCount() != 0 {
				t.Fatalf("mismatched v2 reached Source.Resolve %d times", source.callCount())
			}
		})
	}

	t.Run("unknown kid", func(t *testing.T) {
		changed := challenge
		parts := strings.Split(changed.TXTHandle.RecordRef, ".")
		changed.TXTHandle.RecordRef = "v2.unknown." + parts[2] + "." + parts[3]
		source := &staticSource{config: testProviderConfig(), outstanding: []acmeworker.ChallengeIdentity{changed}}
		_, err := Open(t.Context(), source, keyring)
		assertRemoteError(t, err, CodeSourceUnavailable)
		if source.callCount() != 0 {
			t.Fatalf("unknown kid reached Source.Resolve %d times", source.callCount())
		}
	})
}

func TestOpenValidatesOutstandingV1AgainstAuthoritativeSource(t *testing.T) {
	challenge := testPersistedChallenge()
	legacy, err := encodeLegacyHandle(challenge.ProviderRef, recordHandle{
		Provider: providerCloudflare, Zone: testZone, ZoneID: "zone", RecordID: "record", Owner: testOwner,
	})
	if err != nil {
		t.Fatal(err)
	}
	challenge.TXTHandle = legacy

	source := &staticSource{config: testProviderConfig(), outstanding: []acmeworker.ChallengeIdentity{challenge}}
	adapter, err := Open(t.Context(), source, testHandleKeyring(t))
	if err != nil || adapter.Ready() != nil || source.callCount() != 1 {
		t.Fatalf("Open(v1) adapter=%v error=%v sourceCalls=%d", adapter, err, source.callCount())
	}

	unverifiable := &staticSource{
		config: testProviderConfig(), err: errors.New("source unavailable"),
		outstanding: []acmeworker.ChallengeIdentity{challenge},
	}
	_, err = Open(t.Context(), unverifiable, testHandleKeyring(t))
	assertRemoteError(t, err, CodeSourceUnavailable)

	tests := []struct {
		name      string
		challenge acmeworker.ChallengeIdentity
		config    ProviderConfig
	}{
		{name: "missing tenant", challenge: func() acmeworker.ChallengeIdentity {
			item := challenge
			item.TenantID = uuid.Nil
			return item
		}(), config: testProviderConfig()},
		{name: "missing operation", challenge: func() acmeworker.ChallengeIdentity {
			item := challenge
			item.OperationID = ""
			return item
		}(), config: testProviderConfig()},
		{name: "missing attempt", challenge: func() acmeworker.ChallengeIdentity {
			item := challenge
			item.AttemptID = uuid.Nil
			return item
		}(), config: testProviderConfig()},
		{name: "missing exact value", challenge: func() acmeworker.ChallengeIdentity {
			item := challenge
			item.ExactValue = ""
			return item
		}(), config: testProviderConfig()},
		{name: "missing authorization URL", challenge: func() acmeworker.ChallengeIdentity {
			item := challenge
			item.AuthorizationURL = ""
			return item
		}(), config: testProviderConfig()},
		{name: "missing challenge URL", challenge: func() acmeworker.ChallengeIdentity {
			item := challenge
			item.ChallengeURL = ""
			return item
		}(), config: testProviderConfig()},
		{name: "missing identifier", challenge: func() acmeworker.ChallengeIdentity {
			item := challenge
			item.Identifier = ""
			return item
		}(), config: testProviderConfig()},
		{name: "missing token", challenge: func() acmeworker.ChallengeIdentity {
			item := challenge
			item.Token = ""
			return item
		}(), config: testProviderConfig()},
		{name: "tenant drift", challenge: challenge, config: func() ProviderConfig {
			config := testProviderConfig()
			config.TenantScopeID = uuid.New()
			return config
		}()},
		{name: "provider id drift", challenge: challenge, config: func() ProviderConfig {
			config := testProviderConfig()
			config.ProviderID = uuid.New()
			return config
		}()},
		{name: "provider type drift", challenge: challenge, config: func() ProviderConfig {
			config := testProviderConfig()
			config.ProviderType = providerDNSLA
			config.Credentials = map[string]string{"api_id": "id", "api_secret": "secret"}
			return config
		}()},
		{name: "managed zone missing", challenge: challenge, config: func() ProviderConfig {
			config := testProviderConfig()
			config.ZoneID = uuid.Nil
			return config
		}()},
		{name: "zone drift", challenge: challenge, config: func() ProviderConfig {
			config := testProviderConfig()
			config.ZoneName = "other.test"
			return config
		}()},
		{name: "owner drift", challenge: func() acmeworker.ChallengeIdentity {
			item := challenge
			item.RecordName = "_acme-challenge.other.example.test."
			return item
		}(), config: testProviderConfig()},
		{name: "non canonical", challenge: func() acmeworker.ChallengeIdentity {
			item := challenge
			item.TXTHandle.RecordRef = legacyHandlePrefix + "not-base64!"
			return item
		}(), config: testProviderConfig()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := &staticSource{config: test.config, outstanding: []acmeworker.ChallengeIdentity{test.challenge}}
			adapter, err := Open(t.Context(), source, testHandleKeyring(t))
			if adapter != nil {
				t.Fatal("Open(v1 drift) returned an adapter")
			}
			assertRemoteError(t, err, CodeSourceUnavailable)
		})
	}
}

func TestOpenRejectsOutstandingDNSDunBeforeSource(t *testing.T) {
	legacyChallenge := testPersistedChallenge()
	raw := []byte(`{"v":1,"p":"dnsdun","z":"example.test","zi":"zone","ri":"record","o":"_acme-challenge.example.test."}`)
	legacyChallenge.TXTHandle = acmeworker.RemoteTXTHandle{
		ProviderRef: legacyChallenge.ProviderRef,
		RecordRef:   legacyHandlePrefix + base64.RawURLEncoding.EncodeToString(raw),
	}
	v2Challenge := testPersistedChallenge()
	payload := handlePayload{
		TenantID: v2Challenge.TenantID.String(), ScopeID: v2Challenge.ScopeID.String(), OperationID: v2Challenge.OperationID,
		AttemptID: v2Challenge.AttemptID.String(), ProviderID: v2Challenge.ProviderRef,
		ProviderType: "dnsdun", ManagedZoneID: testManagedZoneID.String(),
		ZoneNameSHA256: digestText(testZone), OwnerSHA256: digestText(testOwner),
		ExactValueSHA256: digestText(testValue), RemoteZoneID: "zone", RemoteRecordID: "record",
	}
	canonical, err := canonicalHandlePayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, testHandleKeySecret)
	_, _ = mac.Write(handleMACInput("test-active", canonical))
	v2Challenge.TXTHandle = acmeworker.RemoteTXTHandle{
		ProviderRef: v2Challenge.ProviderRef,
		RecordRef: "v2.test-active." + base64.RawURLEncoding.EncodeToString(canonical) + "." +
			base64.RawURLEncoding.EncodeToString(mac.Sum(nil)),
	}

	for _, challenge := range []acmeworker.ChallengeIdentity{legacyChallenge, v2Challenge} {
		source := &staticSource{config: testProviderConfig(), outstanding: []acmeworker.ChallengeIdentity{challenge}}
		_, err := Open(t.Context(), source, testHandleKeyring(t))
		assertRemoteError(t, err, CodeUnsupported)
		if source.callCount() != 0 {
			t.Fatalf("dnsdun startup reached Source.Resolve %d times", source.callCount())
		}
	}
}

func TestOpenClassifiesOutstandingSourceContextFailures(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		code ErrorCode
	}{
		{name: "unavailable", err: errors.New("source unavailable"), code: CodeSourceUnavailable},
		{name: "cancelled", err: context.Canceled, code: CodeCancelled},
		{name: "timeout", err: context.DeadlineExceeded, code: CodeTimeout},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := t.Context()
			if test.err == context.Canceled {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			} else if test.err == context.DeadlineExceeded {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 0)
				defer cancel()
			}
			source := &staticSource{config: testProviderConfig(), err: test.err}
			_, err := Open(ctx, source, testHandleKeyring(t))
			assertRemoteError(t, err, test.code)
		})
	}
}

func TestOpenRejectsSourceWithoutGlobalResolve(t *testing.T) {
	if _, err := Open(t.Context(), outstandingOnlySource{}, testHandleKeyring(t)); err == nil {
		t.Fatal("factory accepted source without global Resolve")
	}
}

func TestLegacyConstructorWithoutV2KeyringFailsClosed(t *testing.T) {
	source := &staticSource{config: testProviderConfig()}
	adapter := New(source)
	assertRemoteError(t, adapter.Ready(), CodeSourceUnavailable)
	_, err := adapter.PresentTXT(t.Context(), testChallenge())
	assertRemoteError(t, err, CodeSourceUnavailable)
	if source.callCount() != 0 {
		t.Fatalf("legacy constructor source calls = %d", source.callCount())
	}
}

func TestV1IsCleanupOnlyAndDNSDunAlwaysNetworkZero(t *testing.T) {
	challenge := testChallenge()
	config := testProviderConfig()
	legacy, err := encodeLegacyHandle(challenge.ProviderRef, recordHandle{
		Provider: providerCloudflare, Zone: testZone, ZoneID: "zone", RecordID: "record", Owner: testOwner,
	})
	if err != nil {
		t.Fatal(err)
	}
	challenge.TXTHandle = legacy
	source := &staticSource{config: config}
	adapter := newAdapter(source, testHandleKeyring(t), nil, productionEndpoints(), requestTimeout, nil, nil)
	assertRemoteError(t, adapter.ObserveTXT(t.Context(), challenge), CodeInvalidInput)
	if source.callCount() != 0 {
		t.Fatalf("v1 ObserveTXT source calls = %d", source.callCount())
	}

	dnsdun := legacy
	raw := []byte(`{"v":1,"p":"dnsdun","z":"example.test","zi":"zone","ri":"record","o":"_acme-challenge.example.test."}`)
	dnsdun.RecordRef = legacyHandlePrefix + base64.RawURLEncoding.EncodeToString(raw)
	challenge.TXTHandle = dnsdun
	assertRemoteError(t, adapter.DeleteTXT(t.Context(), challenge), CodeUnsupported)
	if source.callCount() != 0 {
		t.Fatalf("dnsdun v1 source calls = %d", source.callCount())
	}

	payload := handlePayload{
		TenantID: challenge.TenantID.String(), ScopeID: challenge.ScopeID.String(), OperationID: challenge.OperationID,
		AttemptID: challenge.AttemptID.String(), ProviderID: challenge.ProviderRef,
		ProviderType: "dnsdun", ManagedZoneID: config.ZoneID.String(),
		ZoneNameSHA256: digestText(testZone), OwnerSHA256: digestText(testOwner),
		ExactValueSHA256: digestText(testValue), RemoteZoneID: "zone", RemoteRecordID: "record",
	}
	canonical, err := canonicalHandlePayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, testHandleKeySecret)
	_, _ = mac.Write(handleMACInput("test-active", canonical))
	challenge.TXTHandle.RecordRef = "v2.test-active." + base64.RawURLEncoding.EncodeToString(canonical) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	assertRemoteError(t, adapter.DeleteTXT(t.Context(), challenge), CodeUnsupported)
	if source.callCount() != 0 {
		t.Fatalf("dnsdun v2 source calls = %d", source.callCount())
	}
}

func TestV1DeleteReadsExactRecordBeforeCleanup(t *testing.T) {
	var reads, deletes atomic.Int32
	adapter, source := newProviderTestAdapter(t, testProviderConfig(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones/remote-zone/dns_records/remote-record":
			if reads.Add(1) > 1 {
				w.WriteHeader(http.StatusNotFound)
				writeTestJSON(t, w, map[string]any{
					"success": false, "result": nil, "errors": []map[string]any{{"code": 81044}},
				})
				return
			}
			writeTestJSON(t, w, map[string]any{"success": true, "result": map[string]any{
				"id": "remote-record", "zone_id": "remote-zone", "name": testOwner,
				"type": "TXT", "content": testValue,
			}})
		case r.Method == http.MethodDelete && r.URL.Path == "/zones/remote-zone/dns_records/remote-record":
			deletes.Add(1)
			writeTestJSON(t, w, map[string]any{"success": true, "result": map[string]any{"id": "remote-record"}})
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}), requestTimeout)
	challenge := testChallenge()
	handle, err := encodeLegacyHandle(challenge.ProviderRef, recordHandle{
		Provider: providerCloudflare, Zone: testZone, ZoneID: "remote-zone",
		RecordID: "remote-record", Owner: testOwner,
	})
	if err != nil {
		t.Fatal(err)
	}
	challenge.TXTHandle = handle
	if err := adapter.DeleteTXT(t.Context(), challenge); err != nil {
		t.Fatalf("DeleteTXT(v1): %v", err)
	}
	if reads.Load() != 2 || deletes.Load() != 1 || source.callCount() != 1 {
		t.Fatalf("v1 cleanup reads=%d deletes=%d source=%d", reads.Load(), deletes.Load(), source.callCount())
	}

	challenge.TXTHandle.RecordRef = legacyHandlePrefix + "not-base64!"
	assertRemoteError(t, adapter.DeleteTXT(t.Context(), challenge), CodeInvalidInput)
	if reads.Load() != 2 || deletes.Load() != 1 || source.callCount() != 1 {
		t.Fatalf("tampered v1 reached source/http: reads=%d deletes=%d source=%d",
			reads.Load(), deletes.Load(), source.callCount())
	}
}

func TestMaximumCanonicalV2HandleFits060(t *testing.T) {
	challenge := testChallenge()
	challenge.OperationID = strings.Repeat("o", 200)
	challenge.RecordName = "_" + strings.Repeat("a", 61) + "." + strings.Repeat("b", 63) + "." +
		strings.Repeat("c", 63) + "." + strings.Repeat("d", 60) + "."
	config := testProviderConfig()
	config.ZoneName = strings.TrimSuffix(challenge.RecordName, ".")
	handle, err := encodeHandle(challenge, config, recordHandle{
		Provider: providerCloudflare, Zone: config.ZoneName, ZoneID: strings.Repeat("z", 256),
		RecordID: strings.Repeat("r", 256), Owner: challenge.RecordName,
	}, testHandleKeyring(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(handle.RecordRef) >= 2048 {
		t.Fatalf("maximum canonical v2 handle length = %d", len(handle.RecordRef))
	}
}

func testProviderConfig() ProviderConfig {
	return completeTestConfig(ProviderConfig{
		TenantScopeID: testTenantID, ProviderID: uuid.MustParse(testProviderRef),
		ProviderType: providerCloudflare, ZoneID: testManagedZoneID, ZoneName: testZone,
		Credentials: map[string]string{"api_token": "secret"},
	})
}

func testHandleKeyring(t *testing.T) *HandleKeyring {
	t.Helper()
	ring, err := NewHandleKeyring(HandleKey{ID: "test-active", Secret: testHandleKeySecret})
	if err != nil {
		t.Fatal(err)
	}
	return ring
}

var testHandleKeySecret = bytes.Repeat([]byte{7}, 32)

func flipBase64(value string) string {
	if value == "" {
		return "a"
	}
	if value[0] == 'a' {
		return "b" + value[1:]
	}
	return "a" + value[1:]
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }
