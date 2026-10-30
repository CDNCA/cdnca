package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/apikey"
	"github.com/cdnca/cdnca/services/control-api/internal/apikeycredential"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/httpapi"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/sessioncredential"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const edgePublishRuntimeSecretMarker = "edge-publish-production-secret-marker"

type edgePublishRuntimeTestSigner struct {
	public  ed25519.PublicKey
	private ed25519.PrivateKey
}

func (signer *edgePublishRuntimeTestSigner) KeyID() string { return "edge-publish-production-test" }
func (signer *edgePublishRuntimeTestSigner) PublicKey() ed25519.PublicKey {
	return append(ed25519.PublicKey(nil), signer.public...)
}
func (signer *edgePublishRuntimeTestSigner) Sign(_ context.Context, payload []byte) ([]byte, error) {
	return ed25519.Sign(signer.private, payload), nil
}

type edgePublishRuntimeTestEntitlement struct{}

func (*edgePublishRuntimeTestEntitlement) AuthorizePublication(
	context.Context,
	pgx.Tx,
	edgepublish.EntitlementRequest,
) (edgepublish.EntitlementDecision, error) {
	return edgepublish.EntitlementDecision{}, nil
}

type edgePublishRuntimeTypedNilResolver struct{}

func (*edgePublishRuntimeTypedNilResolver) ResolveTarget(
	context.Context,
	pgx.Tx,
	uuid.UUID,
	edgepublish.TargetSnapshotReference,
) (edgepublish.TargetSnapshot, error) {
	return edgepublish.TargetSnapshot{}, nil
}

func TestEdgePublishProductionEntitlementUsesRequestClockAndAcceptedRevocations(t *testing.T) {
	pool, _ := edgePublishProductionPGPool(t, &edgePublishProductionPGQueryTrace{})
	evaluatedAt := time.Now().UTC().Truncate(time.Second)
	fixture := installEdgePublishProductionEntitlement(t, pool, evaluatedAt)
	tenantID, scopeID, userID := uuid.New(), uuid.New(), uuid.New()
	// 带参数的扩展协议一次只能执行一条语句，分开插入
	if _, err := pool.Exec(t.Context(), `WITH new_tenant AS (
		INSERT INTO tenants(id,display_name) VALUES($1,'edge publish entitlement tenant')
	), new_scope AS (
		INSERT INTO access_scopes(id,kind,tenant_id) VALUES($2,'tenant',$1)
	)
	INSERT INTO users(id,username,display_name,password_hash)
	VALUES($3,$4,'edge publish entitlement actor','hash')`, tenantID, scopeID, userID,
		"edge-publish-entitlement-"+strings.ReplaceAll(userID.String(), "-", "")); err != nil {
		t.Fatal(err)
	}
	authorizer := &edgePublishEntitlementAuthorizer{
		pool: pool, trust: fixture.trust,
	}
	authorize := func(at time.Time) (edgepublish.EntitlementDecision, error) {
		t.Helper()
		tx, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		decision, authorizeErr := authorizer.AuthorizePublication(t.Context(), tx, edgepublish.EntitlementRequest{
			Actor: edgepublish.Actor{
				UserID: userID, ScopeID: scopeID, ScopeKind: edgepublish.ScopeKindTenant,
			},
			ConfigurationScopeID: scopeID, ExpectedSourceRevision: 1, NodeCount: 1, EvaluatedAt: at,
		})
		if rollbackErr := tx.Rollback(t.Context()); rollbackErr != nil {
			t.Fatal(rollbackErr)
		}
		return decision, authorizeErr
	}

	decision, err := authorize(evaluatedAt)
	if err != nil || !decision.Allowed || !decision.EvaluatedAt.Equal(evaluatedAt) {
		t.Fatalf("valid production decision=%+v err=%v", decision, err)
	}
	for name, at := range map[string]time.Time{
		"not before": evaluatedAt.Add(-2 * time.Minute),
		// 租约 ExpiresAt=+1 分钟、GraceUntil=+5 分钟；宽限期内放行发布，所以取宽限期之后
		"expired": evaluatedAt.Add(6 * time.Minute),
	} {
		t.Run(name, func(t *testing.T) {
			decision, err := authorize(at)
			if !entitlementguard.IsDenial(err) || decision.Allowed {
				t.Fatalf("production clock-skew decision=%+v err=%v", decision, err)
			}
		})
	}
	acceptEdgePublishProductionRevocation(t, pool, fixture, evaluatedAt)
	decision, err = authorize(evaluatedAt)
	if !entitlementguard.IsDenial(err) || decision.Allowed {
		t.Fatalf("accepted revocation decision=%+v err=%v", decision, err)
	}
}

type edgePublishProductionEntitlementFixture struct {
	trust      *entitlementguard.TrustStore
	signer     *edgePublishRuntimeTestSigner
	keyWindow  entitlement.RevocationKeyWindow
	customerID string
	installID  string
	licenseID  string
}

func installEdgePublishProductionEntitlement(
	t *testing.T,
	pool *pgxpool.Pool,
	now time.Time,
) edgePublishProductionEntitlementFixture {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer := &edgePublishRuntimeTestSigner{public: publicKey, private: privateKey}
	// 签名键窗口须覆盖吊销清单 [IssuedAt, IssuedAt+RevocationSetWindow]：第 2 版 IssuedAt=now-4 分钟，到期 now+11 分钟
	keyNotBefore, signUntil, verifyUntil := now.Add(-10*time.Minute), now.Add(20*time.Minute), now.Add(20*time.Minute)
	trust, err := entitlementguard.NewTrustStore([]entitlementguard.VerificationKey{{
		KeyID: signer.KeyID(), PublicKey: publicKey, NotBefore: keyNotBefore,
		SignUntil: &signUntil, VerifyUntil: &verifyUntil,
	}})
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := sha256.Sum256(publicKey)
	payload := []byte(fmt.Sprintf(`{"schema":"cdnca.signing-keyset/v2","active_key_id":%q,"keys":[{"key_id":%q,"algorithm":"Ed25519","public_key":%q,"fingerprint":%q,"status":"active","not_before":%q,"sign_until":%q,"verify_until":%q}],"rotations":[]}`,
		signer.KeyID(), signer.KeyID(), base64.RawURLEncoding.EncodeToString(publicKey),
		base64.RawURLEncoding.EncodeToString(fingerprint[:]), keyNotBefore.Format(time.RFC3339Nano),
		signUntil.Format(time.RFC3339Nano), verifyUntil.Format(time.RFC3339Nano)))
	payloadDigest := sha256.Sum256(payload)
	if _, err := pool.Exec(t.Context(), `INSERT INTO entitlement_signing_keyset_lkg(
		singleton,schema_version,etag,active_key_id,chain_depth,payload,payload_sha256,accepted_at,updated_at
	) VALUES(true,'cdnca.signing-keyset/v2',$1,$2,1,$3,$4,$5,$5)`,
		`"`+base64.RawURLEncoding.EncodeToString(payloadDigest[:])+`"`, signer.KeyID(), payload,
		payloadDigest[:], now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO entitlement_signing_keyset_current_keys(
		key_id,public_key,status,not_before,sign_until,verify_until,keyset_payload_sha256,accepted_at
	) VALUES($1,$2,'active',$3,$4,$4,$5,$6)`, signer.KeyID(), publicKey, keyNotBefore,
		signUntil, payloadDigest[:], now); err != nil {
		t.Fatal(err)
	}
	fixture := edgePublishProductionEntitlementFixture{
		trust: trust, signer: signer,
		keyWindow: entitlement.RevocationKeyWindow{
			NotBefore: keyNotBefore, SignUntil: &signUntil, VerifyUntil: &verifyUntil,
		},
		customerID: "11111111-1111-4111-8111-111111111111",
		installID:  "22222222-2222-4222-8222-222222222222",
		licenseID:  "33333333-3333-4333-8333-333333333333",
	}
	acceptEdgePublishProductionRevocationRevision(t, pool, fixture, now, 1, []uint64{})
	lease := entitlement.Lease{
		Schema: entitlement.SchemaV1, Audience: entitlement.ControlAudience,
		CustomerID: fixture.customerID, InstallationID: fixture.installID, LicenseID: fixture.licenseID, Serial: 1,
		NotBefore: now.Add(-time.Minute).Unix(), ExpiresAt: now.Add(time.Minute).Unix(),
		GraceUntil: now.Add(5 * time.Minute).Unix(),
		Version:    entitlement.VersionRange{Channel: "stable", Min: "0.1.0", Max: "1.0.0"},
		Features:   []entitlement.Feature{{Code: entitlementguard.FeatureSitesManage}},
		Quotas:     []entitlement.Quota{{Code: entitlementguard.QuotaDomainsCount, Limit: 100}},
	}
	signed, err := entitlement.Sign(t.Context(), lease, signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entitlementguard.NewService(pool, trust).Install(t.Context(), entitlementguard.InstallBundle{
		InstallationID: fixture.installID, SignedLease: signed,
	}, now); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func acceptEdgePublishProductionRevocation(
	t *testing.T,
	pool *pgxpool.Pool,
	fixture edgePublishProductionEntitlementFixture,
	now time.Time,
) {
	t.Helper()
	acceptEdgePublishProductionRevocationRevision(t, pool, fixture, now, 2, []uint64{1})
}

func acceptEdgePublishProductionRevocationRevision(
	t *testing.T,
	pool *pgxpool.Pool,
	fixture edgePublishProductionEntitlementFixture,
	now time.Time,
	revision uint64,
	revoked []uint64,
) {
	t.Helper()
	issuedAt := now.Add(time.Duration(int64(revision)-6) * time.Minute)
	signed, err := entitlement.SignRevocationSet(t.Context(), entitlement.RevocationSet{
		Schema: entitlement.RevocationSetSchemaV2, Audience: entitlement.RevocationSetAudience,
		CustomerID: fixture.customerID, InstallationID: fixture.installID, LicenseID: fixture.licenseID,
		Revision: revision, IssuedAt: issuedAt.Unix(), ExpiresAt: issuedAt.Add(entitlement.RevocationSetWindow).Unix(),
		RevokedSerials: revoked,
	}, fixture.signer, fixture.keyWindow)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := signed.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entitlementguard.NewRevocationService(pool, fixture.trust).Accept(t.Context(), artifact, now); err != nil {
		t.Fatal(err)
	}
}

func TestEdgePublishProductionRuntimeConfigurationIsStrictAndClearsSecrets(t *testing.T) {
	config, err := loadEdgePublishRuntimeConfigFromEnvEntries(edgePublishRuntimeEnvironment())
	if err != nil {
		t.Fatal(err)
	}
	if !config.Enabled || !config.Runtime.Enabled || config.Runtime.CursorActiveKey.ID != "active" ||
		len(config.Runtime.CursorVerificationKeys) != 1 || config.Runtime.CursorVerificationKeys[0].ID != "previous" {
		t.Fatalf("edge publish config enabled=%t runtime_enabled=%t active_present=%t verification_keys=%d",
			config.Enabled, config.Runtime.Enabled, config.Runtime.CursorActiveKey.ID != "",
			len(config.Runtime.CursorVerificationKeys))
	}
	retained := edgePublishRuntimeRetainedSecrets(config)
	config.clearSecrets()
	if config.Runtime.CursorActiveKey.Secret != nil ||
		config.Runtime.CursorVerificationKeys != nil {
		t.Fatalf("cleared edge publish config retained secret state: active_secret_present=%t verification_keys=%d",
			config.Runtime.CursorActiveKey.Secret != nil,
			len(config.Runtime.CursorVerificationKeys))
	}
	assertEdgePublishRuntimeSecretsCleared(t, retained)
}

func TestEdgePublishProductionRuntimeDisabledNeedsNoSecretsAndIsExact404(t *testing.T) {
	config, err := loadEdgePublishRuntimeConfigFromEnvEntries([]string{
		"EDGE_PUBLISH_RUNTIME_ENABLED=false",
	})
	if err != nil || config.Enabled {
		t.Fatalf("disabled config enabled=%t err=%v", config.Enabled, err)
	}
	factory, err := buildAndClearEdgePublishHandlerFactory(&config, edgePublishRuntimeDependencies{})
	if err != nil || factory != nil {
		t.Fatalf("disabled factory=(%v, %v), want nil", factory, err)
	}
	assertEdgePublishRuntimeStatus(t, http.NotFoundHandler(), http.MethodGet,
		"/v1/site-publications", "", http.StatusNotFound)
}

func TestEdgePublishProductionRuntimeRejectsMalformedAndPartialEnvironment(t *testing.T) {
	secret32 := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x31}, 32))
	secret31 := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x31}, 31))
	secret129 := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x31}, 129))
	valid := edgePublishRuntimeEnvironment()
	for _, test := range []struct {
		name        string
		environment []string
	}{
		{name: "empty enabled", environment: []string{"EDGE_PUBLISH_RUNTIME_ENABLED="}},
		{name: "invalid enabled", environment: []string{"EDGE_PUBLISH_RUNTIME_ENABLED=1"}},
		{name: "duplicate enabled", environment: append(append([]string(nil), valid...), "EDGE_PUBLISH_RUNTIME_ENABLED=true")},
		{name: "unknown runtime variable", environment: append(append([]string(nil), valid...), "EDGE_PUBLISH_RUNTIME_ENABLD=true")},
		{name: "missing active key", environment: edgePublishRuntimeWithout("EDGE_PUBLISH_CURSOR_ACTIVE_KEY_ID")},
		{name: "missing keyring", environment: edgePublishRuntimeWithout("EDGE_PUBLISH_CURSOR_KEYS_JSON")},
		{name: "invalid base64", environment: edgePublishRuntimeReplace(
			"EDGE_PUBLISH_CURSOR_KEYS_JSON", `{"active":"not-base64"}`)},
		{name: "short key", environment: edgePublishRuntimeReplace(
			"EDGE_PUBLISH_CURSOR_KEYS_JSON", `{"active":"`+secret31+`"}`)},
		{name: "long key", environment: edgePublishRuntimeReplace(
			"EDGE_PUBLISH_CURSOR_KEYS_JSON", `{"active":"`+secret129+`"}`)},
		{name: "unknown active", environment: edgePublishRuntimeReplace(
			"EDGE_PUBLISH_CURSOR_ACTIVE_KEY_ID", "missing")},
		{name: "duplicate key", environment: edgePublishRuntimeReplace(
			"EDGE_PUBLISH_CURSOR_KEYS_JSON", `{"active":"`+secret32+`","active":"`+secret32+`"}`)},
		{name: "empty keyring", environment: edgePublishRuntimeReplace("EDGE_PUBLISH_CURSOR_KEYS_JSON", `{}`)},
		{name: "trailing document", environment: edgePublishRuntimeReplace(
			"EDGE_PUBLISH_CURSOR_KEYS_JSON", `{"active":"`+secret32+`"}{}`)},
	} {
		t.Run(test.name, func(t *testing.T) {
			config, err := loadEdgePublishRuntimeConfigFromEnvEntries(test.environment)
			if err == nil || config.Enabled || config.Runtime.Enabled {
				t.Fatalf("invalid environment accepted: enabled=%t runtime_enabled=%t",
					config.Enabled, config.Runtime.Enabled)
			}
			if strings.Contains(err.Error(), edgePublishRuntimeSecretMarker) || strings.Contains(err.Error(), secret32) {
				t.Fatal("configuration error leaked secret material")
			}
		})
	}
}

func TestEdgePublishProductionRuntimeFactoryFailsClosedAndClearsSecrets(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*edgePublishRuntimeConfig, *edgePublishRuntimeDependencies)
	}{
		{name: "missing pool", mutate: func(_ *edgePublishRuntimeConfig, value *edgePublishRuntimeDependencies) { value.Pool = nil }},
		{name: "unconfigured pool", mutate: func(_ *edgePublishRuntimeConfig, value *edgePublishRuntimeDependencies) {
			value.Pool = new(pgxpool.Pool)
		}},
		{name: "missing identity", mutate: func(_ *edgePublishRuntimeConfig, value *edgePublishRuntimeDependencies) { value.Identity = nil }},
		{name: "unconfigured identity", mutate: func(_ *edgePublishRuntimeConfig, value *edgePublishRuntimeDependencies) {
			value.Identity = new(identity.Service)
		}},
		{name: "missing API key service", mutate: func(_ *edgePublishRuntimeConfig, value *edgePublishRuntimeDependencies) { value.APIKeys = nil }},
		{name: "missing IAM", mutate: func(_ *edgePublishRuntimeConfig, value *edgePublishRuntimeDependencies) { value.IAM = nil }},
		{name: "unconfigured IAM", mutate: func(_ *edgePublishRuntimeConfig, value *edgePublishRuntimeDependencies) {
			value.IAM = new(iamlock.Authorizer)
		}},
		{name: "missing trust", mutate: func(_ *edgePublishRuntimeConfig, value *edgePublishRuntimeDependencies) { value.Trust = nil }},
		{name: "unconfigured trust", mutate: func(_ *edgePublishRuntimeConfig, value *edgePublishRuntimeDependencies) {
			value.Trust = new(entitlementguard.TrustStore)
		}},
		{name: "missing signer", mutate: func(_ *edgePublishRuntimeConfig, value *edgePublishRuntimeDependencies) { value.Signer = nil }},
		{name: "typed nil signer", mutate: func(_ *edgePublishRuntimeConfig, value *edgePublishRuntimeDependencies) {
			var signer *edgePublishRuntimeTestSigner
			value.Signer = signer
		}},
		{name: "missing entitlement", mutate: func(_ *edgePublishRuntimeConfig, value *edgePublishRuntimeDependencies) { value.Entitlement = nil }},
		{name: "typed nil entitlement", mutate: func(_ *edgePublishRuntimeConfig, value *edgePublishRuntimeDependencies) {
			var entitlement *edgePublishRuntimeTestEntitlement
			value.Entitlement = entitlement
		}},
		{name: "missing resolver", mutate: func(_ *edgePublishRuntimeConfig, value *edgePublishRuntimeDependencies) { value.Resolver = nil }},
		{name: "typed nil resolver", mutate: func(_ *edgePublishRuntimeConfig, value *edgePublishRuntimeDependencies) {
			var resolver *edgePublishRuntimeTypedNilResolver
			value.Resolver = resolver
		}},
		{name: "missing clock", mutate: func(_ *edgePublishRuntimeConfig, value *edgePublishRuntimeDependencies) { value.Clock = nil }},
		{name: "missing active cursor", mutate: func(value *edgePublishRuntimeConfig, _ *edgePublishRuntimeDependencies) {
			value.Runtime.CursorActiveKey.Secret = nil
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			config, err := loadEdgePublishRuntimeConfigFromEnvEntries(edgePublishRuntimeEnvironment())
			if err != nil {
				t.Fatal(err)
			}
			retained := edgePublishRuntimeRetainedSecrets(config)
			dependencies := edgePublishRuntimeValidDependencies(t)
			test.mutate(&config, &dependencies)
			factory, err := buildAndClearEdgePublishHandlerFactory(&config, dependencies)
			if err == nil || factory != nil {
				t.Fatalf("factory_present=%t error_present=%t, want false/true", factory != nil, err != nil)
			}
			if strings.Contains(err.Error(), edgePublishRuntimeSecretMarker) {
				t.Fatal("factory error leaked secret material")
			}
			assertEdgePublishRuntimeSecretsCleared(t, retained)
		})
	}
}

func TestEdgePublishProductionRuntimeFactoryBuildsFrozenHandler(t *testing.T) {
	config, err := loadEdgePublishRuntimeConfigFromEnvEntries(edgePublishRuntimeEnvironment())
	if err != nil {
		t.Fatal(err)
	}
	retained := edgePublishRuntimeRetainedSecrets(config)
	factory, err := buildAndClearEdgePublishHandlerFactory(&config, edgePublishRuntimeValidDependencies(t))
	if err != nil || factory == nil {
		t.Fatalf("factory=(%v, %v)", factory, err)
	}
	assertEdgePublishRuntimeSecretsCleared(t, retained)
	handler, err := factory()
	if err != nil || handler == nil {
		t.Fatalf("handler=(%T, %v)", handler, err)
	}
	assertEdgePublishRuntimeStatus(t, handler, http.MethodGet, "/v1/site-publications", "", http.StatusUnauthorized)
	assertEdgePublishRuntimeStatus(t, handler, http.MethodGet, "/v1/site-publication", "", http.StatusNotFound)
	for _, authorization := range []string{"Bearer not-a-token", "CdncaKey not-a-key"} {
		assertEdgePublishRuntimeStatus(t, handler, http.MethodGet, "/v1/site-publications",
			authorization, http.StatusUnauthorized)
	}
}

type edgePublishProductionPGQuery struct {
	PID uint32
	SQL string
}

type edgePublishProductionPGQueryTrace struct {
	mu      sync.Mutex
	queries []edgePublishProductionPGQuery
}

func (trace *edgePublishProductionPGQueryTrace) TraceQueryStart(
	ctx context.Context,
	connection *pgx.Conn,
	data pgx.TraceQueryStartData,
) context.Context {
	query := strings.ToLower(strings.Join(strings.Fields(data.SQL), " "))
	trace.mu.Lock()
	trace.queries = append(trace.queries, edgePublishProductionPGQuery{
		PID: connection.PgConn().PID(), SQL: query,
	})
	trace.mu.Unlock()
	return ctx
}

func (*edgePublishProductionPGQueryTrace) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {
}

func (trace *edgePublishProductionPGQueryTrace) reset() {
	trace.mu.Lock()
	trace.queries = nil
	trace.mu.Unlock()
}

func (trace *edgePublishProductionPGQueryTrace) snapshot() []edgePublishProductionPGQuery {
	trace.mu.Lock()
	defer trace.mu.Unlock()
	return append([]edgePublishProductionPGQuery(nil), trace.queries...)
}

type edgePublishProductionPGHTTPResult struct {
	response *http.Response
	err      error
}

func TestEdgePublishProductionPostgresAuthenticationAndRevocation(t *testing.T) {
	queryTrace := &edgePublishProductionPGQueryTrace{}
	pool, applicationName := edgePublishProductionPGPool(t, queryTrace)
	const (
		adminUsername  = "edge-publish-pg-admin"
		adminPassword  = "EdgePublishAdmin#2026"
		tenantUsername = "edge-publish-pg-tenant"
		tenantPassword = "EdgePublishTenant#2026"
	)
	adminPasswordHash, err := identity.HashPassword(adminPassword)
	if err != nil {
		t.Fatal(err)
	}
	identityStore := identity.NewStore(pool)
	if _, err := identityStore.BootstrapPlatformUser(
		t.Context(), adminUsername, "Edge Publish PG Admin", adminPasswordHash, "edge-publish-pg-bootstrap",
	); err != nil {
		t.Fatal(err)
	}
	tokens, err := identity.NewTokenManager("edge-publish-production-pg-access-token-secret", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(identityStore, tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pepper := bytes.Repeat([]byte{0x6d}, 32)
	sessionVerifier, err := sessioncredential.NewVerifier(tokens, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	apiKeyVerifier, err := apikeycredential.NewVerifier(pepper, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	iam, err := iamlock.NewAuthorizer(sessionVerifier, apiKeyVerifier)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := entitlementguard.NewTrustStore([]entitlementguard.VerificationKey{{
		KeyID: "edge-publish-production-pg-trust", PublicKey: publicKey,
	}})
	if err != nil {
		t.Fatal(err)
	}
	signer := &edgePublishArtifactSigner{
		keyID: "edge-publish-production-pg-signer", privateKey: privateKey,
	}
	t.Cleanup(signer.Close)
	productionConfig, err := loadEdgePublishRuntimeConfigFromEnvEntries(edgePublishRuntimeEnvironment())
	if err != nil {
		t.Fatal(err)
	}
	factory, err := buildAndClearEdgePublishHandlerFactory(
		&productionConfig,
		edgePublishRuntimeDependencies{
			Pool: pool, Identity: identityService, APIKeys: apikey.NewService(pool, pepper, time.Now), IAM: iam,
			Trust: trust, Signer: signer,
			Entitlement: &edgePublishEntitlementAuthorizer{
				pool: pool, trust: trust,
			},
			Resolver: edgepublish.NewSnapshotTargetResolver(), Clock: time.Now,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	api := httpapi.New(pool, identityService, httpapi.Config{
		CookieSecure: false, APIKeyPepper: pepper, Now: time.Now,
		EntitlementTrust: trust, EdgePublishHandlerFactory: factory,
	})
	if err := api.InitializationError(); err != nil {
		t.Fatalf("initialize production HTTP composition: %v", err)
	}
	server := httptest.NewServer(api.Handler())
	t.Cleanup(server.Close)
	client := server.Client()

	adminAccess := edgePublishProductionPGLogin(
		t, client, server.URL, adminUsername, adminPassword, "edge-publish-pg-admin-login",
	)
	createTenant := edgePublishProductionPGRequest(t.Context(), t, client, http.MethodPost,
		server.URL+"/v1/admin/users", map[string]any{
			"username": tenantUsername, "password": tenantPassword,
			"display_name": "Edge Publish PG Tenant", "email": nil, "phone": nil,
			"role": identity.UserRoleOwner,
		}, "Bearer "+adminAccess, "edge-publish-pg-create-tenant", "", "edge-publish-pg-create-tenant")
	var tenant identity.ManagedUser
	edgePublishProductionPGDecode(t, createTenant, http.StatusCreated, &tenant)
	tenantAccess := edgePublishProductionPGLogin(
		t, client, server.URL, tenantUsername, tenantPassword, "edge-publish-pg-tenant-login",
	)
	var persistedSessions int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM auth_sessions
		WHERE user_id=$1 AND scope_id=$2 AND revoked_at IS NULL`, tenant.ID, tenant.ScopeID).Scan(&persistedSessions); err != nil {
		t.Fatal(err)
	}
	if persistedSessions != 1 {
		t.Fatalf("production tenant login sessions=%d, want 1", persistedSessions)
	}

	pendingResponse := edgePublishProductionPGRequest(t.Context(), t, client, http.MethodPost,
		server.URL+"/v1/admin/users/"+tenant.ID.String()+"/api-keys?tenant_scope_id="+tenant.ScopeID.String(), map[string]any{
			"name": "edge publication production reader", "scopes": []string{"sites.read"},
			"pending_ttl_seconds": 3600,
		}, "Bearer "+adminAccess, "edge-publish-pg-key-pending", `"0"`, "edge-publish-pg-key-pending")
	var pending apikey.Key
	edgePublishProductionPGDecode(t, pendingResponse, http.StatusCreated, &pending)
	if pending.Status != apikey.StatusPendingActivation || pending.Revision != 1 {
		t.Fatalf("pending production API key=%+v", pending)
	}
	activateResponse := edgePublishProductionPGRequest(t.Context(), t, client, http.MethodPost,
		server.URL+"/v1/account/api-keys/"+pending.ID.String()+"/activate", map[string]any{},
		"Bearer "+tenantAccess, "edge-publish-pg-key-activate", `"1"`, "edge-publish-pg-key-activate")
	var issued apikey.IssuedKey
	edgePublishProductionPGDecode(t, activateResponse, http.StatusOK, &issued)
	if issued.Key.Status != apikey.StatusActive || issued.Key.Revision != 2 || issued.Secret == "" {
		t.Fatalf("activated production API key=%+v secret_present=%t", issued.Key, issued.Secret != "")
	}
	apiKeyCredential := issued.Key.KeyID + "." + issued.Secret

	queryTrace.reset()
	for _, credential := range []string{"Bearer " + tenantAccess, "CdncaKey " + apiKeyCredential} {
		for _, path := range []string{"/v1/site-publications?limit=1", "/v1/site-rollouts?limit=1"} {
			response := edgePublishProductionPGRequest(t.Context(), t, client, http.MethodGet,
				server.URL+path, nil, credential, "", "", "edge-publish-pg-read")
			edgePublishProductionPGDecode(t, response, http.StatusOK, nil)
		}
	}
	successQueries := queryTrace.snapshot()
	if !edgePublishProductionPGTraceContains(successQueries, "from edge_config_publications") ||
		!edgePublishProductionPGTraceContains(successQueries, "from rollouts") {
		t.Fatalf("successful production routes did not reach frozen business reads: %v", successQueries)
	}

	lockBytes := uuid.New()
	barrierKey := int64(binary.BigEndian.Uint64(lockBytes[:8]) & uint64(^uint64(0)>>1))
	if barrierKey == 0 {
		barrierKey = 1
	}
	edgePublishProductionPGInstallRevokeBarrier(t, pool, issued.Key.ID, barrierKey)
	holder, err := pool.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Release()
	if _, err := holder.Exec(t.Context(), `SELECT pg_advisory_lock($1)`, barrierKey); err != nil {
		t.Fatal(err)
	}
	barrierLocked := true
	defer func() {
		if barrierLocked {
			_, _ = holder.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, barrierKey)
		}
	}()
	holderPID := holder.Conn().PgConn().PID()

	queryTrace.reset()
	revokeRequest := edgePublishProductionPGNewRequest(t.Context(), t, http.MethodPost,
		server.URL+"/v1/account/api-keys/"+issued.Key.ID.String()+"/revoke", map[string]any{},
		"Bearer "+tenantAccess, "edge-publish-pg-key-revoke", `"2"`, "edge-publish-pg-key-revoke")
	revokeDone := make(chan edgePublishProductionPGHTTPResult, 1)
	go func() {
		response, requestErr := client.Do(revokeRequest)
		revokeDone <- edgePublishProductionPGHTTPResult{response: response, err: requestErr}
	}()
	revokerPID := edgePublishProductionPGWaitForBlockedQuery(
		t, pool, applicationName, holderPID, "update api_keys", "formal API-key revoke barrier",
	)
	edgePublishProductionPGAssertGlobalLock(t, pool, revokerPID, "ExclusiveLock", true)

	readRequest := edgePublishProductionPGNewRequest(t.Context(), t, http.MethodGet,
		server.URL+"/v1/site-publications?limit=1", nil,
		"CdncaKey "+apiKeyCredential, "", "", "edge-publish-pg-inflight-read")
	readDone := make(chan edgePublishProductionPGHTTPResult, 1)
	go func() {
		response, requestErr := client.Do(readRequest)
		readDone <- edgePublishProductionPGHTTPResult{response: response, err: requestErr}
	}()
	readerPID := edgePublishProductionPGWaitForBlockedQuery(
		t, pool, applicationName, revokerPID, "iam_global_lock_shared_v1", "edge publication IAM shared lock",
	)
	edgePublishProductionPGAssertGlobalLock(t, pool, readerPID, "ShareLock", false)
	blockedQueries := queryTrace.snapshot()
	if !edgePublishProductionPGTraceContains(blockedQueries, "from api_keys k") {
		t.Fatal("in-flight CdncaKey request did not finish outer production authentication")
	}
	if edgePublishProductionPGTraceContains(
		blockedQueries, "select id,user_id,scope_id,tenant_id from api_keys where key_id=$1",
	) {
		t.Fatal("in-flight CdncaKey request crossed the IAM barrier before formal revocation")
	}

	if _, err := holder.Exec(t.Context(), `SELECT pg_advisory_unlock($1)`, barrierKey); err != nil {
		t.Fatal(err)
	}
	barrierLocked = false
	revokeResult := edgePublishProductionPGAwaitHTTP(t, revokeDone, "formal API-key revoke")
	var revoked apikey.Key
	edgePublishProductionPGDecode(t, revokeResult, http.StatusOK, &revoked)
	if revoked.Status != apikey.StatusRevoked || revoked.Revision != 3 {
		t.Fatalf("formally revoked production API key=%+v", revoked)
	}
	var persistedStatus string
	var persistedRevision int64
	if err := pool.QueryRow(t.Context(), `SELECT status,revision FROM api_keys WHERE id=$1`, issued.Key.ID).
		Scan(&persistedStatus, &persistedRevision); err != nil {
		t.Fatal(err)
	}
	if persistedStatus != apikey.StatusRevoked || persistedRevision != 3 {
		t.Fatalf("committed API key status/revision=%s/%d", persistedStatus, persistedRevision)
	}
	inflightResult := edgePublishProductionPGAwaitHTTP(t, readDone, "in-flight edge publication read")
	edgePublishProductionPGDecode(t, inflightResult, http.StatusUnauthorized, nil)
	revokedQueries := queryTrace.snapshot()
	if !edgePublishProductionPGTraceContains(
		revokedQueries, "select id,user_id,scope_id,tenant_id from api_keys where key_id=$1",
	) {
		t.Fatal("in-flight request did not re-check the API key after revocation commit")
	}
	edgePublishProductionPGAssertNoBusinessReads(t, revokedQueries)

	queryTrace.reset()
	postRevoke := edgePublishProductionPGRequest(t.Context(), t, client, http.MethodGet,
		server.URL+"/v1/site-publications?limit=1", nil,
		"CdncaKey "+apiKeyCredential, "", "", "edge-publish-pg-post-revoke")
	edgePublishProductionPGDecode(t, postRevoke, http.StatusUnauthorized, nil)
	edgePublishProductionPGAssertNoBusinessReads(t, queryTrace.snapshot())

	disableResponse := edgePublishProductionPGRequest(t.Context(), t, client, http.MethodPatch,
		server.URL+"/v1/admin/users/"+tenant.ID.String(), map[string]any{
			"expected_revision": tenant.Revision, "display_name": tenant.DisplayName,
			"email": nil, "phone": nil, "status": identity.UserStatusDisabled, "role": identity.UserRoleOwner,
		}, "Bearer "+adminAccess, "edge-publish-pg-disable-tenant", "", "edge-publish-pg-disable-tenant")
	var disabled identity.ManagedUser
	edgePublishProductionPGDecode(t, disableResponse, http.StatusOK, &disabled)
	if disabled.Status != identity.UserStatusDisabled {
		t.Fatalf("disabled production tenant=%+v", disabled)
	}
	queryTrace.reset()
	postDisable := edgePublishProductionPGRequest(t.Context(), t, client, http.MethodGet,
		server.URL+"/v1/site-publications?limit=1", nil,
		"Bearer "+tenantAccess, "", "", "edge-publish-pg-disabled-bearer")
	edgePublishProductionPGDecode(t, postDisable, http.StatusUnauthorized, nil)
	edgePublishProductionPGAssertNoBusinessReads(t, queryTrace.snapshot())
}

func edgePublishProductionPGPool(
	t *testing.T,
	trace *edgePublishProductionPGQueryTrace,
) (*pgxpool.Pool, string) {
	t.Helper()
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	adminConfig, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatalf("parse test database URL: %v", err)
	}
	adminConfig.MaxConns = 2
	admin, err := pgxpool.NewWithConfig(ctx, adminConfig)
	if err != nil {
		t.Fatalf("open test administration pool: %v", err)
	}
	if err := admin.Ping(ctx); err != nil {
		admin.Close()
		t.Fatalf("ping test administration pool: %v", err)
	}
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")
	schema := "edge_publish_production_pg_" + suffix
	if !regexp.MustCompile(`^edge_publish_production_pg_[a-f0-9]{32}$`).MatchString(schema) {
		admin.Close()
		t.Fatalf("refusing unsafe production integration schema %q", schema)
	}
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		admin.Close()
		t.Fatalf("create production integration schema: %v", err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE")
		admin.Close()
		t.Fatalf("parse production integration database URL: %v", err)
	}
	applicationName := "edge_publish_production_pg_" + suffix
	config.ConnConfig.RuntimeParams["search_path"] = schema
	config.ConnConfig.RuntimeParams["application_name"] = applicationName
	config.ConnConfig.Tracer = trace
	config.MaxConns = 6
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE")
		admin.Close()
		t.Fatalf("open production integration pool: %v", err)
	}
	if err := database.Migrate(ctx, pool, "up"); err != nil {
		pool.Close()
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE")
		admin.Close()
		t.Fatalf("migrate production integration schema: %v", err)
	}
	t.Cleanup(func() {
		pool.Close()
		cleanupCtx, cleanupCancel := databasetest.CleanupContext()
		defer cleanupCancel()
		if _, err := admin.Exec(cleanupCtx, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop production integration schema: %v", err)
		}
		admin.Close()
	})
	return pool, applicationName
}

func edgePublishProductionPGLogin(
	t *testing.T,
	client *http.Client,
	baseURL, username, password, requestID string,
) string {
	t.Helper()
	response := edgePublishProductionPGRequest(t.Context(), t, client, http.MethodPost,
		baseURL+"/v1/auth/login", map[string]any{"username": username, "password": password},
		"", "", "", requestID)
	var result struct {
		AccessToken string             `json:"access_token"`
		Principal   identity.Principal `json:"principal"`
	}
	edgePublishProductionPGDecode(t, response, http.StatusOK, &result)
	if result.AccessToken == "" || result.Principal.UserID == uuid.Nil || result.Principal.ScopeID == uuid.Nil {
		t.Fatalf("production login returned incomplete identity: %+v", result.Principal)
	}
	return result.AccessToken
}

func edgePublishProductionPGRequest(
	ctx context.Context,
	t *testing.T,
	client *http.Client,
	method, target string,
	body any,
	authorization, idempotencyKey, ifMatch, requestID string,
) *http.Response {
	t.Helper()
	request := edgePublishProductionPGNewRequest(
		ctx, t, method, target, body, authorization, idempotencyKey, ifMatch, requestID,
	)
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("%s %s: %v", method, target, err)
	}
	return response
}

func edgePublishProductionPGNewRequest(
	ctx context.Context,
	t *testing.T,
	method, target string,
	body any,
	authorization, idempotencyKey, ifMatch, requestID string,
) *http.Request {
	t.Helper()
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	if idempotencyKey != "" {
		request.Header.Set("Idempotency-Key", idempotencyKey)
	}
	if ifMatch != "" {
		request.Header.Set("If-Match", ifMatch)
	}
	if requestID != "" {
		request.Header.Set("X-Request-ID", requestID)
	}
	return request
}

func edgePublishProductionPGDecode(t *testing.T, response *http.Response, wantStatus int, target any) {
	t.Helper()
	if response == nil {
		t.Fatal("production HTTP response is nil")
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != wantStatus {
		t.Fatalf("production HTTP status=%d want=%d body=%s", response.StatusCode, wantStatus, body)
	}
	if target != nil {
		if err := json.Unmarshal(body, target); err != nil {
			t.Fatalf("decode production HTTP response: %v body=%s", err, body)
		}
	}
}

func edgePublishProductionPGInstallRevokeBarrier(
	t *testing.T,
	pool *pgxpool.Pool,
	apiKeyID uuid.UUID,
	barrierKey int64,
) {
	t.Helper()
	for _, statement := range []string{
		`CREATE TABLE edge_publish_production_pg_revoke_barrier (
			api_key_id uuid PRIMARY KEY,
			advisory_key bigint NOT NULL
		)`,
		`CREATE FUNCTION edge_publish_production_pg_wait_for_revoke() RETURNS trigger LANGUAGE plpgsql AS $$
		DECLARE
			barrier_key bigint;
		BEGIN
			SELECT advisory_key INTO barrier_key
			FROM edge_publish_production_pg_revoke_barrier
			WHERE api_key_id=NEW.id;
			IF FOUND AND OLD.status='active' AND NEW.status='revoked' THEN
				PERFORM pg_advisory_xact_lock(barrier_key);
			END IF;
			RETURN NEW;
		END;
		$$`,
		`CREATE TRIGGER edge_publish_production_pg_revoke_wait
			BEFORE UPDATE ON api_keys
			FOR EACH ROW EXECUTE FUNCTION edge_publish_production_pg_wait_for_revoke()`,
	} {
		if _, err := pool.Exec(t.Context(), statement); err != nil {
			t.Fatalf("install production revoke barrier: %v", err)
		}
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO edge_publish_production_pg_revoke_barrier
		(api_key_id,advisory_key) VALUES($1,$2)`, apiKeyID, barrierKey); err != nil {
		t.Fatalf("configure production revoke barrier: %v", err)
	}
}

func edgePublishProductionPGWaitForBlockedQuery(
	t *testing.T,
	pool *pgxpool.Pool,
	applicationName string,
	blockerPID uint32,
	queryFragment, description string,
) uint32 {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var pid *int32
		err := pool.QueryRow(t.Context(), `SELECT min(pid)::integer
			FROM pg_catalog.pg_stat_activity
			WHERE datname=current_database() AND application_name=$1 AND state='active'
			  AND lower(query) LIKE '%' || lower($2) || '%'
			  AND $3::integer=ANY(pg_catalog.pg_blocking_pids(pid))`,
			applicationName, queryFragment, int32(blockerPID)).Scan(&pid)
		if err != nil {
			t.Fatalf("inspect %s: %v", description, err)
		}
		if pid != nil && *pid > 0 {
			return uint32(*pid)
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("%s did not block behind backend %d", description, blockerPID)
	return 0
}

func edgePublishProductionPGAssertGlobalLock(
	t *testing.T,
	pool *pgxpool.Pool,
	pid uint32,
	mode string,
	granted bool,
) {
	t.Helper()
	var exists bool
	if err := pool.QueryRow(t.Context(), `SELECT EXISTS(
		SELECT 1 FROM pg_catalog.pg_locks
		WHERE pid=$1 AND locktype='advisory' AND classid=1229016321::oid
		  AND objid=1::oid AND objsubid=2 AND mode=$2 AND granted=$3
	)`, int32(pid), mode, granted).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatalf("backend %d missing IAM global %s granted=%t", pid, mode, granted)
	}
}

func edgePublishProductionPGAwaitHTTP(
	t *testing.T,
	results <-chan edgePublishProductionPGHTTPResult,
	description string,
) *http.Response {
	t.Helper()
	select {
	case result := <-results:
		if result.err != nil {
			t.Fatalf("%s: %v", description, result.err)
		}
		return result.response
	case <-time.After(10 * time.Second):
		t.Fatalf("%s did not finish", description)
		return nil
	}
}

func edgePublishProductionPGTraceContains(queries []edgePublishProductionPGQuery, fragment string) bool {
	fragment = strings.ToLower(fragment)
	for _, query := range queries {
		if strings.Contains(query.SQL, fragment) {
			return true
		}
	}
	return false
}

func edgePublishProductionPGAssertNoBusinessReads(
	t *testing.T,
	queries []edgePublishProductionPGQuery,
) {
	t.Helper()
	for _, table := range []string{
		"edge_config_publications", "rollouts", "node_deployments", "deployment_status_events",
	} {
		if edgePublishProductionPGTraceContains(queries, "from "+table) ||
			edgePublishProductionPGTraceContains(queries, "join "+table) {
			t.Fatalf("revoked production request crossed authorization into %s business reads: %v", table, queries)
		}
	}
}

func edgePublishRuntimeValidDependencies(t *testing.T) edgePublishRuntimeDependencies {
	t.Helper()
	pool := edgePublishRuntimeConfiguredPool(t)
	now := time.Now
	tokens, err := identity.NewTokenManager("edge-publish-production-runtime-token-secret", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(identity.NewStore(pool), tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pepper := bytes.Repeat([]byte{0x61}, 32)
	sessions, err := sessioncredential.NewVerifier(tokens, now)
	if err != nil {
		t.Fatal(err)
	}
	apiKeyVerifier, err := apikeycredential.NewVerifier(pepper, now)
	if err != nil {
		t.Fatal(err)
	}
	iam, err := iamlock.NewAuthorizer(sessions, apiKeyVerifier)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := entitlementguard.NewTrustStore([]entitlementguard.VerificationKey{{
		KeyID: "edge-publish-production-trust", PublicKey: publicKey,
	}})
	if err != nil {
		t.Fatal(err)
	}
	return edgePublishRuntimeDependencies{
		Pool: pool, Identity: identityService, APIKeys: apikey.NewService(pool, pepper, now), IAM: iam,
		Trust: trust, Signer: &edgePublishRuntimeTestSigner{public: publicKey, private: privateKey},
		Entitlement: &edgePublishRuntimeTestEntitlement{}, Resolver: edgepublish.NewSnapshotTargetResolver(), Clock: now,
	}
}

func edgePublishRuntimeConfiguredPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	config, err := pgxpool.ParseConfig("postgresql://runtime:runtime@127.0.0.1:1/runtime?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	config.MaxConns = 2
	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func edgePublishRuntimeEnvironment() []string {
	active := bytes.Repeat([]byte(edgePublishRuntimeSecretMarker), 2)[:32]
	previous := bytes.Repeat([]byte{0x42}, 32)
	return []string{
		"EDGE_PUBLISH_RUNTIME_ENABLED=true",
		"EDGE_PUBLISH_CURSOR_ACTIVE_KEY_ID=active",
		"EDGE_PUBLISH_CURSOR_KEYS_JSON={\"active\":\"" + base64.StdEncoding.EncodeToString(active) +
			"\",\"previous\":\"" + base64.StdEncoding.EncodeToString(previous) + "\"}",
	}
}

func edgePublishRuntimeWithout(name string) []string {
	result := make([]string, 0, len(edgePublishRuntimeEnvironment()))
	for _, entry := range edgePublishRuntimeEnvironment() {
		if !strings.HasPrefix(entry, name+"=") {
			result = append(result, entry)
		}
	}
	return result
}

func edgePublishRuntimeReplace(name, value string) []string {
	result := edgePublishRuntimeWithout(name)
	return append(result, name+"="+value)
}

func edgePublishRuntimeRetainedSecrets(config edgePublishRuntimeConfig) [][]byte {
	result := make([][]byte, 0, 1+len(config.Runtime.CursorVerificationKeys))
	result = append(result, config.Runtime.CursorActiveKey.Secret)
	for _, key := range config.Runtime.CursorVerificationKeys {
		result = append(result, key.Secret)
	}
	return result
}

func assertEdgePublishRuntimeSecretsCleared(t *testing.T, retained [][]byte) {
	t.Helper()
	for index, secret := range retained {
		if !bytes.Equal(secret, make([]byte, len(secret))) {
			t.Fatalf("edge publish secret %d was not cleared", index)
		}
	}
}

func assertEdgePublishRuntimeStatus(
	t *testing.T,
	handler http.Handler,
	method, target, authorization string,
	want int,
) {
	t.Helper()
	request := httptest.NewRequest(method, target, nil)
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != want {
		t.Fatalf("%s %s authorization=%q status=%d want=%d body=%s",
			method, target, authorization, response.Code, want, response.Body)
	}
}
