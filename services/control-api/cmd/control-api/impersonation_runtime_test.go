package main

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/impersonation"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestImpersonationRuntimeConfigAndFactoryFailClosed(t *testing.T) {
	key := bytes.Repeat([]byte{0x61}, 32)
	encoded := base64.StdEncoding.EncodeToString(key)
	config, err := loadImpersonationRuntimeConfigFromEnvEntries([]string{
		impersonationHMACKeyBase64Env + "=" + encoded,
	})
	if err != nil || !bytes.Equal(config.HMACKey, key) {
		t.Fatalf("config=(%#v,%v)", config, err)
	}
	for _, environment := range [][]string{
		nil,
		{impersonationHMACKeyBase64Env + "=not-base64"},
		{impersonationHMACKeyBase64Env + "=" + base64.StdEncoding.EncodeToString(key[:31])},
		{impersonationHMACKeyBase64Env + "=" + encoded, impersonationHMACKeyBase64Env + "=" + encoded},
		{impersonationHMACKeyBase64Env + "=" + encoded, "IMPERSONATION_KEYS_JSON={}"},
	} {
		if _, err := loadImpersonationRuntimeConfigFromEnvEntries(environment); err == nil ||
			strings.Contains(err.Error(), encoded) || strings.Contains(err.Error(), "not-base64") {
			t.Fatalf("environment=%v error=%v", environment, err)
		}
	}
	retained := config.HMACKey
	if factory, readiness, err := buildAndClearImpersonationRuntime(&config, impersonationRuntimeDependencies{}); err == nil || factory != nil || readiness != nil {
		t.Fatalf("incomplete runtime=(%v,%v,%v)", factory, readiness, err)
	}
	if config.HMACKey != nil || !bytes.Equal(retained, make([]byte, len(retained))) {
		t.Fatal("runtime retained HMAC configuration")
	}
	if (&impersonationRuntimeReadiness{}).Ready() == nil {
		t.Fatal("unconfigured impersonation readiness reported healthy")
	}
}

func TestImpersonationSessionCodecAuthenticatesAndExpiresCredential(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	codec, err := newImpersonationSessionCodec(bytes.Repeat([]byte{0x62}, 32), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	tenantID, scopeID, userID := uuid.New(), uuid.New(), uuid.New()
	session := impersonation.Session{
		ID: uuid.New(), GrantID: uuid.New(), ActorUserID: uuid.New(), ActorScopeID: uuid.New(),
		SubjectUserID: userID, TenantID: tenantID, TenantScopeID: scopeID,
		CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(14 * time.Minute),
		Principal: impersonation.SubjectPrincipal{UserID: userID, ScopeID: scopeID, TenantID: tenantID,
			ScopeKind: "tenant", Username: "tenant-user", DisplayName: "Tenant User", Permissions: []string{"sites.read"}},
	}
	session.Banner = impersonation.BannerClaims{
		GrantID: session.GrantID, ActorUserID: session.ActorUserID, ActorDisplayName: "Support Admin",
		SubjectUserID: userID, SubjectDisplayName: "Tenant User", TenantID: tenantID, ExpiresAt: session.ExpiresAt,
	}
	credential, err := codec.Issue(t.Context(), session)
	if err != nil || credential == "" || strings.Contains(credential, userID.String()) {
		t.Fatalf("issued credential=(%q,%v)", credential, err)
	}
	decoded, err := codec.Decode(t.Context(), credential)
	if err != nil || decoded.ID != session.ID || decoded.Principal.UserID != userID {
		t.Fatalf("decoded session=(%#v,%v)", decoded, err)
	}
	tampered := credential[:len(credential)-1] + "A"
	if tampered == credential {
		tampered = credential[:len(credential)-1] + "B"
	}
	if _, err := codec.Decode(t.Context(), tampered); err == nil {
		t.Fatal("tampered credential decoded")
	}
	now = session.ExpiresAt
	if _, err := codec.Decode(t.Context(), credential); err == nil {
		t.Fatal("expired credential decoded")
	}
}

func TestImpersonationRuntimeBuildsProductionFactoryAndAdapter(t *testing.T) {
	poolConfig, err := pgxpool.ParseConfig("postgresql://impersonation:impersonation@127.0.0.1:1/impersonation?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.NewWithConfig(t.Context(), poolConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	tokens, err := identity.NewTokenManager(strings.Repeat("impersonation-runtime-secret-", 2), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(identity.NewStore(pool), tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	config := impersonationRuntimeConfig{HMACKey: bytes.Repeat([]byte{0x63}, 32)}
	retained := config.HMACKey
	factory, readiness, err := buildAndClearImpersonationRuntime(&config, impersonationRuntimeDependencies{
		Pool: pool, Identity: identityService, Clock: time.Now,
	})
	if err != nil || factory == nil || readiness == nil {
		t.Fatalf("production runtime=(%v,%v,%v)", factory, readiness, err)
	}
	if config.HMACKey != nil || !bytes.Equal(retained, make([]byte, len(retained))) {
		t.Fatal("production runtime retained HMAC configuration")
	}
}
