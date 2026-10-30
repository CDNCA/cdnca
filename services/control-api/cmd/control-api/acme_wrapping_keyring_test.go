package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/acmeruntime"
	"github.com/cdnca/cdnca/services/control-api/internal/config"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestACMEWrappingKeyringAcceptsActiveAndPrevious(t *testing.T) {
	t.Setenv(acmePreviousWrappingKeyIDEnv, "acme-kek-v1")
	t.Setenv(acmePreviousWrappingKeyBase64Env, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x31}, 32)))

	store, err := newConfiguredACMEKeyStore(&pgxpool.Pool{}, config.Config{
		ACMEWrappingKeyID: "acme-kek-v2", ACMEWrappingKey: bytes.Repeat([]byte{0x41}, 32),
	})
	if err != nil || store == nil {
		t.Fatalf("newConfiguredACMEKeyStore() failed: %v", err)
	}
}

func TestACMEPublicationResolverKeyringAcceptsActiveAndPrevious(t *testing.T) {
	t.Setenv(acmePreviousWrappingKeyIDEnv, "acme-kek-v1")
	t.Setenv(acmePreviousWrappingKeyBase64Env, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x31}, 32)))

	resolver, err := newConfiguredACMEPublicationResolverKeyring(config.Config{
		ACMEWrappingKeyID: "acme-kek-v2", ACMEWrappingKey: bytes.Repeat([]byte{0x41}, 32),
	})
	if err != nil || resolver == nil {
		t.Fatalf("newConfiguredACMEPublicationResolverKeyring() = (%T, %v)", resolver, err)
	}
}

func TestACMEWrappingKeyringRejectsInvalidPreviousConfiguration(t *testing.T) {
	tests := []struct {
		name, id, encoded string
		wantInvalidInput  bool
	}{
		{name: "missing material", id: "acme-kek-v1"},
		{name: "missing id", encoded: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x31}, 32))},
		{name: "bad base64", id: "acme-kek-v1", encoded: "not-base64"},
		{name: "wrong length", id: "acme-kek-v1", encoded: base64.StdEncoding.EncodeToString([]byte("short"))},
		{name: "duplicate id", id: "acme-kek-v2", encoded: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x31}, 32)), wantInvalidInput: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(acmePreviousWrappingKeyIDEnv, test.id)
			t.Setenv(acmePreviousWrappingKeyBase64Env, test.encoded)
			_, err := newConfiguredACMEKeyStore(&pgxpool.Pool{}, config.Config{
				ACMEWrappingKeyID: "acme-kek-v2", ACMEWrappingKey: bytes.Repeat([]byte{0x41}, 32),
			})
			if test.wantInvalidInput {
				if !errors.Is(err, acmeruntime.ErrInvalidInput) {
					t.Fatalf("error = %v, want ErrInvalidInput", err)
				}
				return
			}
			if !errors.Is(err, errACMEPreviousWrappingKeyConfig) {
				t.Fatalf("error = %v, want stable previous-key config error", err)
			}
		})
	}
}

func TestACMEWrappingKeyringIsUsedByProductionRuntime(t *testing.T) {
	source, err := os.ReadFile("acme_runtime.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	if !strings.Contains(text, "newConfiguredACMEKeyStore(pool, cfg)") {
		t.Fatal("ACME runtime does not construct the configured keyring")
	}
	if strings.Contains(text, "acmeruntime.NewKeyStore(pool, cfg.ACMEWrappingKeyID, cfg.ACMEWrappingKey)") {
		t.Fatal("ACME runtime still constructs an active-only key store")
	}
}

func TestACMEWrappingKeyringClearsTemporaryMaterial(t *testing.T) {
	source, err := os.ReadFile("acme_wrapping_keyring.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"append([]byte(nil), cfg.ACMEWrappingKey...)",
		"clear(active.Key)",
		"clear(previous[index].Key)",
		"certificatepublish.NewACMEPublicationResolverKeyring",
		"clear(publicationActive.Material)",
		"clear(publicationPrevious[index].Material)",
	} {
		if !bytes.Contains(source, []byte(required)) {
			t.Fatalf("ACME keyring helper lacks material lifecycle %q", required)
		}
	}
}
