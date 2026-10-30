package apikey

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestCredentialDerivationAndVerificationBoundaries(t *testing.T) {
	pepper := bytes.Repeat([]byte{0x5a}, 32)
	service := NewService(nil, pepper, time.Now)
	writeID := uuid.MustParse("019c7a66-4dd8-7a45-a9d1-923e9545a7e0")
	keyID := "cfk_AAAAAAAAAAAAAAAAAAAAAA"

	version, secret, good, ok := service.deriveActiveSecret(writeID, keyID)
	if !ok || version != LegacyPepperVersion {
		t.Fatalf("active derivation = (%q, %v)", version, ok)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(secret)
	if err != nil || len(decoded) != 32 {
		t.Fatalf("derived secret length/error = %d/%v", len(decoded), err)
	}
	retry, ok := service.deriveSecret(version, writeID, keyID)
	if !ok || secret != retry {
		t.Fatal("same write identity did not derive the same retry secret")
	}
	different, ok := service.deriveSecret(version, uuid.MustParse("019c7a66-4dd8-7a45-a9d1-923e9545a7e1"), keyID)
	if !ok || secret == different {
		t.Fatal("different write identities derived the same secret")
	}
	bad, ok := service.pepper.Sign(version, digestDomain, []byte(keyID), []byte{0}, []byte(secret+"x"))
	if !ok {
		t.Fatal("active digest version unavailable")
	}
	if bytes.Equal(good[:], bad[:]) || bytes.Equal(good[:], []byte(secret)) {
		t.Fatal("domain-separated credential digests were not independent")
	}
	parsedID, parsedSecret, ok := parseCredential(keyID + "." + secret)
	if !ok || parsedID != keyID || parsedSecret != secret {
		t.Fatalf("parseCredential mismatch: id=%v secret=%v valid=%v",
			parsedID == keyID, parsedSecret == secret, ok)
	}
	for index, malformed := range []string{
		"", "Bearer " + keyID + "." + secret, keyID, keyID + ".short", keyID + "." + secret + ".extra",
		" cfk_AAAAAAAAAAAAAAAAAAAAAA." + secret,
	} {
		if _, _, ok := parseCredential(malformed); ok {
			t.Fatalf("malformed credential case %d unexpectedly succeeded", index)
		}
	}
}

func TestIssuedKeyFormattingRedactsSecret(t *testing.T) {
	secret := strings.Repeat("sensitive", 8)
	formatted := fmt.Sprintf("%#v", IssuedKey{Secret: secret})
	if strings.Contains(formatted, secret) {
		t.Fatal("formatted IssuedKey exposed its one-time secret")
	}
}

func TestAuthenticateWithKeyIDRejectsMalformedCredentialBeforeDatabaseLookup(t *testing.T) {
	config, err := pgxpool.ParseConfig("postgres://cdnca:unused@127.0.0.1:1/cdnca?connect_timeout=1")
	if err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	service := NewService(pool, bytes.Repeat([]byte{0x5a}, 32), time.Now)
	_, keyID, authenticatedAt, err := service.AuthenticateWithKeyID(t.Context(), "not-a-credential")
	if !errors.Is(err, ErrInvalidCredential) || keyID != uuid.Nil || !authenticatedAt.IsZero() {
		t.Fatalf("malformed credential with unavailable database = (key=%s at=%v err=%v), want invalid credential", keyID, authenticatedAt, err)
	}
}

func TestValidateScopesRequiresSafeStrictSubset(t *testing.T) {
	permissions := []string{"api_keys.self.manage", "identity.self.read", "sites.read", "sites.manage"}
	valid := []string{"sites.manage", "sites.read"}
	if err := validateScopes(valid, permissions); err != nil {
		t.Fatalf("validateScopes(valid) error = %v", err)
	}
	if valid[0] != "sites.manage" || valid[1] != "sites.read" {
		t.Fatalf("normalized scopes = %v", valid)
	}
	for _, invalid := range [][]string{
		{},
		{"sites.read", "sites.read"},
		{"sites.delete"},
		{"identity.self.read"},
		{"api_keys.self.manage"},
		{"platform.admin"},
		permissions,
	} {
		if err := validateScopes(invalid, permissions); err == nil {
			t.Fatalf("validateScopes(%v) unexpectedly succeeded", invalid)
		}
	}
}

func TestGetSelfRejectsNilKeyIDAsInvalidInput(t *testing.T) {
	tenantID := uuid.MustParse("019c7a66-4dd8-7a45-a9d1-923e9545a7e2")
	principal := identity.Principal{
		UserID:    uuid.MustParse("019c7a66-4dd8-7a45-a9d1-923e9545a7e3"),
		ScopeID:   uuid.MustParse("019c7a66-4dd8-7a45-a9d1-923e9545a7e4"),
		ScopeKind: "tenant",
		TenantID:  &tenantID,
		Permissions: []string{
			"api_keys.self.manage",
		},
	}

	_, err := NewService(nil, bytes.Repeat([]byte{0x5a}, 32), time.Now).
		GetSelf(context.Background(), principal, uuid.Nil)
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("GetSelf(nil ID) error = %v, want %v", err, ErrInvalidInput)
	}
}

// fix-apikeysimple：简单版开关一次创建"全部权限"密钥，tenant_owner 的安全权限超过 32 个。
func TestValidateScopesAcceptsAllSafePermissionsUpTo128(t *testing.T) {
	permissions := []string{"api_keys.self.manage"}
	requested := make([]string, 0, maxKeyScopes+1)
	for index := 0; index <= maxKeyScopes; index++ {
		scope := fmt.Sprintf("module%03d.read", index)
		permissions = append(permissions, scope)
		requested = append(requested, scope)
	}
	if err := validateScopes(append([]string(nil), requested[:57]...), permissions); err != nil {
		t.Fatalf("validateScopes(57 scopes) error = %v", err)
	}
	if err := validateScopes(append([]string(nil), requested[:maxKeyScopes]...), permissions); err != nil {
		t.Fatalf("validateScopes(%d scopes) error = %v", maxKeyScopes, err)
	}
	if err := validateScopes(requested, permissions); err == nil {
		t.Fatalf("validateScopes(%d scopes) unexpectedly succeeded", len(requested))
	}
}

// fix-smallfu：简单版"重置密钥"=轮换 secret + 权限刷新为当前账号可授予的全部（与前端 safeScope 同一规则）。
func TestGrantableScopesMatchesSimpleAllPermissions(t *testing.T) {
	got := grantableScopes([]string{
		"sites.read", "api_keys.self.manage", "identity.self.read", "platform.admin",
		"billing.account.read", "sites.read", "Bad.Scope",
	})
	want := []string{"billing.account.read", "sites.read"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("grantableScopes = %v, want %v", got, want)
	}
	if err := validateScopes(got, []string{"api_keys.self.manage", "billing.account.read", "sites.read"}); err != nil {
		t.Fatalf("grantable scopes must pass validateScopes: %v", err)
	}
}

func TestIssuanceScopesRefreshesOnlyForRotate(t *testing.T) {
	permissions := []string{"api_keys.self.manage", "sites.read", "sites.manage"}
	if scopes, err := issuanceScopes("api_key.self.rotate", false, permissions); err != nil || scopes != nil {
		t.Fatalf("plain rotate scopes = (%v, %v), want keep current", scopes, err)
	}
	if scopes, err := issuanceScopes("api_key.self.rotate", true, permissions); err != nil ||
		strings.Join(scopes, ",") != "sites.manage,sites.read" {
		t.Fatalf("grant-all rotate scopes = (%v, %v)", scopes, err)
	}
	if _, err := issuanceScopes("api_key.self.activate", true, permissions); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("grant-all activate error = %v, want %v", err, ErrInvalidInput)
	}
	// 没有可授予权限时拒绝，不落到数据库。
	if _, err := issuanceScopes("api_key.self.rotate", true, []string{"api_keys.self.manage"}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("grant-all rotate with nothing grantable error = %v, want %v", err, ErrPermissionDenied)
	}
}
