package edgepublishhttp

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestNewCursorRuntimeConfigBuildsDeterministicRotationHandoff(t *testing.T) {
	oldSecret := bytes.Repeat([]byte{0x41}, 32)
	activeSecret := bytes.Repeat([]byte{0x42}, 64)
	verifySecret := bytes.Repeat([]byte{0x43}, 128)
	binding := CursorBinding{Audience: AudiencePlatform, ScopeID: uuid.New(), ResourceKind: CursorResourcePublications}
	oldCodec := mustCursorCodec(t, CursorKey{ID: "verify-a", Secret: oldSecret})
	oldToken, err := oldCodec.Encode(binding, "old-postgres-cursor")
	if err != nil {
		t.Fatal(err)
	}
	raw := `{"verify-z":"` + base64.StdEncoding.EncodeToString(verifySecret) +
		`","active":"` + base64.StdEncoding.EncodeToString(activeSecret) +
		`","verify-a":"` + base64.StdEncoding.EncodeToString(oldSecret) + `"}`

	config, err := NewCursorRuntimeConfig(true, "active", raw)
	if err != nil {
		t.Fatal(err)
	}
	if !config.Enabled || config.CursorActiveKey.ID != "active" ||
		!bytes.Equal(config.CursorActiveKey.Secret, activeSecret) || len(config.CursorVerificationKeys) != 2 ||
		config.CursorVerificationKeys[0].ID != "verify-a" ||
		!bytes.Equal(config.CursorVerificationKeys[0].Secret, oldSecret) ||
		config.CursorVerificationKeys[1].ID != "verify-z" ||
		!bytes.Equal(config.CursorVerificationKeys[1].Secret, verifySecret) {
		t.Fatalf("runtime cursor config enabled=%t active=%q verification_keys=%d",
			config.Enabled, config.CursorActiveKey.ID, len(config.CursorVerificationKeys))
	}
	codec, err := NewHMACCursorCodec(config.CursorActiveKey, config.CursorVerificationKeys...)
	if err != nil {
		t.Fatal(err)
	}
	token, err := codec.Encode(binding, "postgres-cursor")
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := codec.Decode(binding, token); err != nil || decoded != "postgres-cursor" {
		t.Fatalf("decoded cursor = %q, %v", decoded, err)
	}
	if decoded, err := codec.Decode(binding, oldToken); err != nil || decoded != "old-postgres-cursor" {
		t.Fatalf("decoded old cursor = %q, %v", decoded, err)
	}
	wrongSecretCodec := mustCursorCodec(t, CursorKey{ID: "verify-a", Secret: bytes.Repeat([]byte{0x44}, 32)})
	wrongSecretToken, err := wrongSecretCodec.Encode(binding, "wrong-secret-cursor")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := codec.Decode(binding, wrongSecretToken); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("wrong verification secret error = %v", err)
	}
	unknownKeyCodec := mustCursorCodec(t, CursorKey{ID: "retired", Secret: oldSecret})
	unknownKeyToken, err := unknownKeyCodec.Encode(binding, "unknown-key-cursor")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := codec.Decode(binding, unknownKeyToken); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("unknown verification key ID error = %v", err)
	}

	disabled, err := NewCursorRuntimeConfig(false, "", "")
	if err != nil || disabled.Enabled || disabled.CursorActiveKey.ID != "" || len(disabled.CursorVerificationKeys) != 0 {
		t.Fatalf("disabled runtime config enabled=%t active=%q verification_keys=%d error=%v",
			disabled.Enabled, disabled.CursorActiveKey.ID, len(disabled.CursorVerificationKeys), err)
	}
}

func TestNewCursorRuntimeConfigAcceptsKeyringSizeBoundaries(t *testing.T) {
	for _, keyCount := range []int{1, maxCursorKeyringKeys} {
		t.Run(fmt.Sprintf("%d keys", keyCount), func(t *testing.T) {
			encodedKeys := make(map[string]string, keyCount)
			for index := 0; index < keyCount; index++ {
				encodedKeys[fmt.Sprintf("key-%d", index)] = base64.StdEncoding.EncodeToString(
					bytes.Repeat([]byte{byte(index + 1)}, 32),
				)
			}
			raw, err := json.Marshal(encodedKeys)
			if err != nil {
				t.Fatal(err)
			}
			config, err := NewCursorRuntimeConfig(true, "key-0", string(raw))
			if err != nil {
				t.Fatal(err)
			}
			if !config.Enabled || config.CursorActiveKey.ID != "key-0" ||
				len(config.CursorVerificationKeys) != keyCount-1 {
				t.Fatalf("runtime cursor config enabled=%t active=%q verification_keys=%d",
					config.Enabled, config.CursorActiveKey.ID, len(config.CursorVerificationKeys))
			}
			codec, err := NewHMACCursorCodec(config.CursorActiveKey, config.CursorVerificationKeys...)
			if err != nil {
				t.Fatal(err)
			}
			binding := CursorBinding{
				Audience: AudienceTenant, ScopeID: uuid.New(), ResourceKind: CursorResourceRollouts,
			}
			token, err := codec.Encode(binding, "boundary-cursor")
			if err != nil {
				t.Fatal(err)
			}
			if decoded, err := codec.Decode(binding, token); err != nil || decoded != "boundary-cursor" {
				t.Fatalf("decoded boundary cursor = %q, %v", decoded, err)
			}
		})
	}
}

func TestNewCursorRuntimeConfigClearsDecodedKeysWhenActiveKeyIsUnknown(t *testing.T) {
	decodedSecrets := [][]byte{
		bytes.Repeat([]byte{0x71}, 32),
		bytes.Repeat([]byte{0x72}, 64),
	}
	config, err := newCursorRuntimeConfigFromKeys("missing", []CursorKey{
		{ID: "key-a", Secret: decodedSecrets[0]},
		{ID: "key-b", Secret: decodedSecrets[1]},
	})
	if config.Enabled || config.CursorActiveKey.ID != "" || len(config.CursorVerificationKeys) != 0 ||
		!errors.Is(err, ErrInvalidRuntimeConfig) {
		t.Fatalf("NewCursorRuntimeConfig() enabled=%t active=%q verification_keys=%d error=%v",
			config.Enabled, config.CursorActiveKey.ID, len(config.CursorVerificationKeys), err)
	}
	for index, secret := range decodedSecrets {
		if !bytes.Equal(secret, make([]byte, len(secret))) {
			t.Fatalf("decoded secret %d was not cleared", index)
		}
	}
}

func TestNewCursorRuntimeConfigRejectsInvalidKeyringsWithoutLeakingSecrets(t *testing.T) {
	secret32 := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x51}, 32))
	secret31 := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x52}, 31))
	secret129 := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x53}, 129))
	secretMarker := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("private-cursor-material"), 2))
	tests := map[string]struct {
		enabled bool
		active  string
		raw     string
	}{
		"enabled missing all":       {enabled: true},
		"enabled missing active":    {enabled: true, raw: `{"key":"` + secret32 + `"}`},
		"enabled missing keys":      {enabled: true, active: "key"},
		"disabled retains active":   {active: "key"},
		"disabled retains keys":     {raw: `{"key":"` + secret32 + `"}`},
		"invalid active id":         {enabled: true, active: "bad key", raw: `{"bad key":"` + secret32 + `"}`},
		"malformed object":          {enabled: true, active: "key", raw: "{"},
		"empty object":              {enabled: true, active: "key", raw: `{}`},
		"null object":               {enabled: true, active: "key", raw: `null`},
		"unknown active":            {enabled: true, active: "missing", raw: `{"key":"` + secret32 + `"}`},
		"duplicate id":              {enabled: true, active: "key", raw: `{"key":"` + secret32 + `","key":"` + secret32 + `"}`},
		"non string secret":         {enabled: true, active: "key", raw: `{"key":32}`},
		"invalid verification id":   {enabled: true, active: "key", raw: `{"key":"` + secret32 + `","bad key":"` + secret32 + `"}`},
		"invalid base64":            {enabled: true, active: "key", raw: `{"key":"not-base64"}`},
		"noncanonical base64":       {enabled: true, active: "key", raw: `{"key":"` + strings.TrimRight(secret32, "=") + `"}`},
		"short secret":              {enabled: true, active: "key", raw: `{"key":"` + secret31 + `"}`},
		"long secret":               {enabled: true, active: "key", raw: `{"key":"` + secret129 + `"}`},
		"trailing document":         {enabled: true, active: "key", raw: `{"key":"` + secret32 + `"}{}`},
		"secret marker is redacted": {enabled: true, active: "key", raw: `{"key":"` + secretMarker + `!"}`},
		"too many keys": {enabled: true, active: "key-0", raw: `{"key-0":"` + secret32 +
			`","key-1":"` + secret32 + `","key-2":"` + secret32 + `","key-3":"` + secret32 +
			`","key-4":"` + secret32 + `","key-5":"` + secret32 + `","key-6":"` + secret32 +
			`","key-7":"` + secret32 + `","key-8":"` + secret32 + `"}`},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			config, err := NewCursorRuntimeConfig(test.enabled, test.active, test.raw)
			if config.Enabled || config.CursorActiveKey.ID != "" || len(config.CursorVerificationKeys) != 0 ||
				!errors.Is(err, ErrInvalidRuntimeConfig) {
				t.Fatalf("NewCursorRuntimeConfig() enabled=%t active=%q verification_keys=%d error=%v",
					config.Enabled, config.CursorActiveKey.ID, len(config.CursorVerificationKeys), err)
			}
			if strings.Contains(err.Error(), secretMarker) || strings.Contains(err.Error(), "private-cursor-material") {
				t.Fatalf("configuration error leaked secret material: %v", err)
			}
		})
	}
}

func TestHMACCursorCodecRejectsAuthenticatedUnknownKeyID(t *testing.T) {
	secret := bytes.Repeat([]byte{0x61}, 32)
	codec := mustCursorCodec(t, CursorKey{ID: "known", Secret: secret})
	binding := CursorBinding{Audience: AudienceTenant, ScopeID: uuid.New(), ResourceKind: CursorResourceRollouts}
	payload, err := json.Marshal(cursorEnvelope{
		Version: cursorVersion, KeyID: "unknown", Audience: binding.Audience,
		ScopeID: binding.ScopeID.String(), ResourceKind: binding.ResourceKind, Inner: "postgres-cursor",
	})
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(payload)
	token := base64.RawURLEncoding.EncodeToString(append(payload, mac.Sum(nil)...))
	if _, err := codec.Decode(binding, token); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("unknown authenticated key ID error = %v", err)
	}
}
