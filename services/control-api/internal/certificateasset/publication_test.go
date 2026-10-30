package certificateasset

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

var errPublicationOpaqueResolverInjected = errors.New("injected opaque publication resolver failure")

func TestUsePublicationMaterialsInTxRejectsInvalidBoundary(t *testing.T) {
	tenantScopeID := uuid.New()
	siteID := uuid.New()
	consumer := func([]PublicationMaterial) error { return nil }

	tests := []struct {
		name    string
		store   *Store
		request PublicationRequest
		use     PublicationConsumer
	}{
		{name: "nil store", request: PublicationRequest{TenantScopeID: tenantScopeID, SiteIDs: []uuid.UUID{siteID}}, use: consumer},
		{name: "missing enveloper", store: &Store{now: certificateTestClock}, request: PublicationRequest{TenantScopeID: tenantScopeID, SiteIDs: []uuid.UUID{siteID}}, use: consumer},
		{name: "missing clock", store: &Store{enveloper: &testEnvelopeCipher{}}, request: PublicationRequest{TenantScopeID: tenantScopeID, SiteIDs: []uuid.UUID{siteID}}, use: consumer},
		{name: "nil transaction", store: &Store{enveloper: &testEnvelopeCipher{}, now: certificateTestClock}, request: PublicationRequest{TenantScopeID: tenantScopeID, SiteIDs: []uuid.UUID{siteID}}, use: consumer},
		{name: "nil consumer", store: &Store{enveloper: &testEnvelopeCipher{}, now: certificateTestClock}, request: PublicationRequest{TenantScopeID: tenantScopeID, SiteIDs: []uuid.UUID{siteID}}},
		{name: "nil tenant", store: &Store{enveloper: &testEnvelopeCipher{}, now: certificateTestClock}, request: PublicationRequest{SiteIDs: []uuid.UUID{siteID}}, use: consumer},
		{name: "empty sites", store: &Store{enveloper: &testEnvelopeCipher{}, now: certificateTestClock}, request: PublicationRequest{TenantScopeID: tenantScopeID}, use: consumer},
		{name: "nil site", store: &Store{enveloper: &testEnvelopeCipher{}, now: certificateTestClock}, request: PublicationRequest{TenantScopeID: tenantScopeID, SiteIDs: []uuid.UUID{uuid.Nil}}, use: consumer},
		{name: "duplicate site", store: &Store{enveloper: &testEnvelopeCipher{}, now: certificateTestClock}, request: PublicationRequest{TenantScopeID: tenantScopeID, SiteIDs: []uuid.UUID{siteID, siteID}}, use: consumer},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.store.UsePublicationMaterialsInTx(context.Background(), nil, test.request, test.use)
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("UsePublicationMaterialsInTx() error = %v, want %v", err, ErrInvalidInput)
			}
		})
	}
}

func certificateTestClock() time.Time {
	return certificateTestNow
}

func TestResolveOpaquePublicationPrivateKeyFailsClosed(t *testing.T) {
	request := OpaquePublicationResolveRequest{
		TenantScopeID:         uuid.New(),
		PrivateKeyReference:   "acme-provider:key-1",
		OuterEnvelopeMetadata: []byte(`{"schema":"test"}`),
		WrappedKeyMaterial:    bytes.Repeat([]byte{0x41}, 32),
	}
	request.ExpectedPublicKeySHA256[0] = 0x42

	tests := []struct {
		name     string
		resolver OpaquePublicationResolver
		retained *[]byte
	}{
		{name: "missing resolver"},
		{name: "empty result", resolver: func(context.Context, OpaquePublicationResolveRequest) ([]byte, error) {
			return nil, nil
		}},
		{name: "error result", retained: new([]byte), resolver: func(_ context.Context, _ OpaquePublicationResolveRequest) ([]byte, error) {
			value := bytes.Repeat([]byte{0x51}, 32)
			return value, errPublicationOpaqueResolverInjected
		}},
		{name: "panic", resolver: func(context.Context, OpaquePublicationResolveRequest) ([]byte, error) {
			panic(errPublicationOpaqueResolverInjected)
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var returned []byte
			resolver := test.resolver
			if test.retained != nil {
				original := resolver
				resolver = func(ctx context.Context, request OpaquePublicationResolveRequest) ([]byte, error) {
					value, err := original(ctx, request)
					*test.retained = value
					return value, err
				}
			}
			returned, err := resolveOpaquePublicationPrivateKey(context.Background(), resolver, request)
			if !errors.Is(err, ErrEnvelopeUnavailable) || returned != nil {
				t.Fatalf("resolve result = %x, error = %v", returned, err)
			}
			if test.retained != nil {
				assertPublicationBytesZeroed(t, *test.retained)
			}
		})
	}
}

func TestResolveOpaquePublicationPrivateKeyForwardsBoundContext(t *testing.T) {
	request := OpaquePublicationResolveRequest{
		TenantScopeID:         uuid.New(),
		PrivateKeyReference:   "acme-provider:key-bound",
		OuterEnvelopeMetadata: []byte(`{"schema":"bound"}`),
		WrappedKeyMaterial:    bytes.Repeat([]byte{0x61}, 32),
	}
	request.ExpectedPublicKeySHA256[31] = 0x62
	want := bytes.Repeat([]byte{0x63}, 64)

	result, err := resolveOpaquePublicationPrivateKey(context.Background(),
		func(_ context.Context, got OpaquePublicationResolveRequest) ([]byte, error) {
			if got.TenantScopeID != request.TenantScopeID ||
				got.PrivateKeyReference != request.PrivateKeyReference ||
				got.ExpectedPublicKeySHA256 != request.ExpectedPublicKeySHA256 ||
				!bytes.Equal(got.OuterEnvelopeMetadata, request.OuterEnvelopeMetadata) ||
				!bytes.Equal(got.WrappedKeyMaterial, request.WrappedKeyMaterial) {
				t.Fatalf("resolver request = %#v, want %#v", got, request)
			}
			return append([]byte(nil), want...), nil
		}, request)
	if err != nil || !bytes.Equal(result, want) {
		t.Fatalf("resolve result = %x, error = %v", result, err)
	}
	zeroBytes(result)
}

func assertPublicationBytesZeroed(t *testing.T, value []byte) {
	t.Helper()
	if len(value) == 0 {
		t.Fatal("expected a retained byte slice")
	}
	for index, character := range value {
		if character != 0 {
			t.Fatalf("byte %d was not zeroed", index)
		}
	}
}
