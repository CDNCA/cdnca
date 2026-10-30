package openrestysecurity

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestSecretCipherRoundTripUsesRandomNonceAndVersionedEnvelope(t *testing.T) {
	secret, err := NewSecretCipher(bytes.Repeat([]byte{0x31}, 32))
	if err != nil {
		t.Fatalf("NewSecretCipher() error = %v", err)
	}
	plaintext := []byte("openresty-sensitive-key")
	first, err := secret.Seal(context.Background(), plaintext)
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	second, err := secret.Seal(context.Background(), plaintext)
	if err != nil {
		t.Fatalf("second Seal() error = %v", err)
	}
	if !bytes.HasPrefix(first, []byte(secretEnvelopePrefix)) {
		t.Fatalf("envelope prefix = %x", first[:len(secretEnvelopePrefix)])
	}
	if bytes.Equal(first, second) {
		t.Fatal("two envelopes are equal; nonce was not random")
	}
	if bytes.Contains(first, plaintext) {
		t.Fatal("envelope contains plaintext")
	}
	opened, err := secret.Unseal(context.Background(), first)
	if err != nil {
		t.Fatalf("Unseal() error = %v", err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Fatalf("Unseal() = %q, want %q", opened, plaintext)
	}
}

func TestSecretCipherRejectsTamperingWrongKeyAndMalformedEnvelope(t *testing.T) {
	secret, err := NewSecretCipher(bytes.Repeat([]byte{0x41}, 32))
	if err != nil {
		t.Fatalf("NewSecretCipher() error = %v", err)
	}
	wrong, err := NewSecretCipher(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatalf("NewSecretCipher(wrong) error = %v", err)
	}
	envelope, err := secret.Seal(context.Background(), []byte("secret"))
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}

	tampered := append([]byte(nil), envelope...)
	tampered[len(tampered)-1] ^= 0x80
	for name, candidate := range map[string][]byte{
		"tampered":  tampered,
		"truncated": envelope[:len(secretEnvelopePrefix)],
		"prefix":    append([]byte("INVALID"), envelope[len(secretEnvelopePrefix):]...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := secret.Unseal(context.Background(), candidate); !errors.Is(err, ErrInvalidSecretEnvelope) {
				t.Fatalf("Unseal() error = %v, want ErrInvalidSecretEnvelope", err)
			}
		})
	}
	if _, err := wrong.Unseal(context.Background(), envelope); !errors.Is(err, ErrInvalidSecretEnvelope) {
		t.Fatalf("wrong-key Unseal() error = %v, want ErrInvalidSecretEnvelope", err)
	}
}

func TestNewSecretCipherRequiresAES256Key(t *testing.T) {
	for _, size := range []int{0, 16, 24, 31, 33} {
		if secret, err := NewSecretCipher(bytes.Repeat([]byte{1}, size)); secret != nil || !errors.Is(err, ErrInvalidSecretKey) {
			t.Fatalf("NewSecretCipher(%d bytes) = %#v, %v; want nil, ErrInvalidSecretKey", size, secret, err)
		}
	}
	if secret, err := NewSecretCipher(bytes.Repeat([]byte{1}, 32)); secret == nil || err != nil {
		t.Fatalf("NewSecretCipher(32 bytes) = %#v, %v", secret, err)
	}
}

func TestSecretCipherFormattingIsAlwaysRedacted(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	secret, err := NewSecretCipher(key)
	if err != nil {
		t.Fatalf("NewSecretCipher() error = %v", err)
	}
	for _, rendered := range []string{fmt.Sprint(secret), fmt.Sprintf("%#v", secret), fmt.Sprint(*secret), fmt.Sprintf("%#v", *secret)} {
		if rendered != "openrestysecurity.SecretCipher([REDACTED])" || strings.Contains(rendered, string(key)) {
			t.Fatalf("formatted cipher leaked implementation or key: %q", rendered)
		}
	}
}
