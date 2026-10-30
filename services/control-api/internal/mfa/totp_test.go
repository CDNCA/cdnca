package mfa

import (
	"encoding/base32"
	"testing"
	"time"
)

func TestDefaultIssuerUsesCDNCA(t *testing.T) {
	if defaultIssuer != "CDNCA" {
		t.Fatalf("default issuer = %q", defaultIssuer)
	}
}

func TestHOTPMatchesRFC6238SHA1Vectors(t *testing.T) {
	t.Parallel()
	secret := []byte("12345678901234567890")
	tests := []struct {
		at   int64
		want string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	}
	for _, test := range tests {
		counter := uint64(test.at / 30)
		if got := hotp(secret, counter, 8); got != test.want {
			t.Errorf("hotp(counter=%d) = %q, want %q", counter, got, test.want)
		}
	}
}

func TestMatchTOTPUsesBoundedWindowAndReturnsCounter(t *testing.T) {
	t.Parallel()
	secret := []byte("12345678901234567890")
	now := time.Unix(1234567890, 0).UTC()
	current := uint64(now.Unix() / 30)

	for offset := int64(-1); offset <= 1; offset++ {
		code := hotp(secret, uint64(int64(current)+offset), 6)
		counter, ok := matchTOTP(secret, code, now, 30*time.Second, 1, 6)
		if !ok || counter != uint64(int64(current)+offset) {
			t.Fatalf("match offset %d = (%d,%t)", offset, counter, ok)
		}
	}
	outside := hotp(secret, current+2, 6)
	if _, ok := matchTOTP(secret, outside, now, 30*time.Second, 1, 6); ok {
		t.Fatal("accepted TOTP outside the configured drift window")
	}
	if _, ok := matchTOTP(secret, "12345", now, 30*time.Second, 1, 6); ok {
		t.Fatal("accepted malformed TOTP")
	}
}

func TestGenerateTOTPSecretHas160Bits(t *testing.T) {
	t.Parallel()
	encoded, raw, err := generateTOTPSecret(zeroReader{})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 20 || len(decoded) != 20 {
		t.Fatalf("secret lengths raw=%d decoded=%d", len(raw), len(decoded))
	}
}

type zeroReader struct{}

func (zeroReader) Read(value []byte) (int, error) {
	clear(value)
	return len(value), nil
}
