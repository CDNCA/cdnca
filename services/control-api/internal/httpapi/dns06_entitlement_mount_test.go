package httpapi

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"reflect"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
)

func TestDNS06CertificateIssuanceEntitlementTrustIsMounted(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate entitlement key: %v", err)
	}
	trust, err := entitlementguard.NewTrustStore([]entitlementguard.VerificationKey{{
		KeyID: "dns06-mount-key-v1", PublicKey: publicKey,
	}})
	if err != nil {
		t.Fatalf("NewTrustStore() error = %v", err)
	}
	fixedNow := time.Date(2026, time.August, 7, 12, 0, 0, 0, time.UTC)
	server := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), Now: func() time.Time { return fixedNow }, EntitlementTrust: trust})
	if err := server.InitializationError(); err != nil {
		t.Fatalf("New() initialization error = %v", err)
	}

	service := reflect.ValueOf(server.dnsacme).Elem()
	store := service.FieldByName("store").Elem()
	guard := store.FieldByName("guard").Elem().Elem()
	mountedTrust := guard.FieldByName("trust")
	if mountedTrust.IsNil() || mountedTrust.Pointer() != reflect.ValueOf(trust).Pointer() {
		t.Fatal("DNS ACME store did not receive Config.EntitlementTrust")
	}
}
