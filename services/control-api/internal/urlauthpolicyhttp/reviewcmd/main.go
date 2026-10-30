package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/apikey"
	"github.com/cdnca/cdnca/services/control-api/internal/apikeycredential"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/cdnca/cdnca/services/control-api/internal/httpapi"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/sessioncredential"
	"github.com/cdnca/cdnca/services/control-api/internal/urlauthpolicy"
	"github.com/cdnca/cdnca/services/control-api/internal/urlauthpolicyhttp"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const reviewPassword = "UrlAuth-Stage1-Review!"

var schemaPattern = regexp.MustCompile(`^sec09_review_[a-z0-9]+$`)

type fixture struct {
	Schema           string      `json:"schema"`
	TenantID         uuid.UUID   `json:"tenant_id"`
	TenantScopeID    uuid.UUID   `json:"tenant_scope_id"`
	ManagerUserID    uuid.UUID   `json:"manager_user_id"`
	EmptyUserID      uuid.UUID   `json:"empty_user_id"`
	NoReadUserID     uuid.UUID   `json:"no_read_user_id"`
	PlatformScopeID  uuid.UUID   `json:"platform_scope_id"`
	PlatformUserID   uuid.UUID   `json:"platform_user_id"`
	PolicySiteID     uuid.UUID   `json:"policy_site_id"`
	UnboundSiteID    uuid.UUID   `json:"unbound_site_id"`
	PolicySiteIDs    []uuid.UUID `json:"-"`
	ManagerUsername  string      `json:"manager_username"`
	EmptyUsername    string      `json:"empty_username"`
	NoReadUsername   string      `json:"no_read_username"`
	PlatformUsername string      `json:"platform_username"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	databaseURL := strings.TrimSpace(os.Getenv("DATABASE_URL"))
	schema := strings.TrimSpace(os.Getenv("SEC09_REVIEW_SCHEMA"))
	address := strings.TrimSpace(os.Getenv("SEC09_REVIEW_ADDR"))
	manifestPath := strings.TrimSpace(os.Getenv("SEC09_REVIEW_MANIFEST"))
	if databaseURL == "" || !schemaPattern.MatchString(schema) || address == "" || manifestPath == "" {
		return errors.New("DATABASE_URL, safe SEC09_REVIEW_SCHEMA, SEC09_REVIEW_ADDR, and SEC09_REVIEW_MANIFEST are required")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return err
	}
	defer admin.Close()
	var exists bool
	if err := admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname=$1)`, schema).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("review schema %q already exists", schema)
	}
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		return err
	}
	cleanupSchema := true
	defer func() {
		if cleanupSchema {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			_, _ = admin.Exec(cleanupCtx, "DROP SCHEMA "+identifier+" CASCADE")
		}
	}()

	poolConfig, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return err
	}
	poolConfig.MaxConns = 10
	poolConfig.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := database.Migrate(ctx, pool, "up"); err != nil {
		return err
	}

	passwordHash, err := identity.HashPassword(reviewPassword)
	if err != nil {
		return err
	}
	data := newFixture(schema)
	if err := seedIdentityAndSites(ctx, pool, data, passwordHash); err != nil {
		return err
	}

	tokens, err := identity.NewTokenManager(strings.Repeat("sec09-review-access-secret-", 2), time.Hour)
	if err != nil {
		return err
	}
	identityService, err := identity.NewService(identity.NewStore(pool), tokens, 24*time.Hour)
	if err != nil {
		return err
	}
	pepper := bytes.Repeat([]byte{0x91}, 32)
	apiKeys := apikey.NewService(pool, pepper, time.Now)
	sessionVerifier, err := sessioncredential.NewVerifier(tokens, time.Now)
	if err != nil {
		return err
	}
	apiKeyVerifier, err := apikeycredential.NewVerifier(pepper, time.Now)
	if err != nil {
		return err
	}
	iam, err := iamlock.NewAuthorizer(sessionVerifier, apiKeyVerifier)
	if err != nil {
		return err
	}
	secretCipher, err := urlauthpolicy.NewAESGCMSecretCipher("sec09-review-url-auth-kek-v1", bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		return err
	}
	if err := seedPolicies(ctx, pool, identityService, iam, secretCipher, data); err != nil {
		return err
	}
	urlAuthHandler, err := urlauthpolicyhttp.NewRuntimeHandler(
		urlauthpolicyhttp.RuntimeConfig{Enabled: true},
		urlauthpolicyhttp.RuntimeDependencies{
			Pool: pool, Identity: identityService, APIKeys: apiKeys, IAM: iam, Cipher: secretCipher, Now: time.Now,
		},
	)
	if err != nil {
		return err
	}
	dnsCipher, err := dnsacme.NewAESGCMCredentialCipher("sec09-review-dns-kek-v1", bytes.Repeat([]byte{0x43}, 32))
	if err != nil {
		return err
	}
	sharedHandler := httpapi.New(pool, identityService, httpapi.Config{
		CookieSecure: false, DNSCredentialCipher: dnsCipher, APIKeyPepper: pepper,
	}).Handler()
	mux := http.NewServeMux()
	mux.Handle("/v1/url-auth-policies", urlAuthHandler)
	mux.Handle("/v1/url-auth-policies/", urlAuthHandler)
	mux.Handle("/", sharedHandler)

	manifest, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(manifestPath, append(manifest, '\n'), 0o600); err != nil {
		return err
	}
	defer os.Remove(manifestPath)

	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	fmt.Printf("SEC09_REVIEW_READY http://%s schema=%s\n", listener.Addr(), schema)
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return err
		}
		if err := <-done; !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case err := <-done:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	pool.Close()
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := admin.Exec(cleanupCtx, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
		return err
	}
	cleanupSchema = false
	return nil
}

func newFixture(schema string) fixture {
	policySiteIDs := make([]uuid.UUID, 21)
	for index := range policySiteIDs {
		policySiteIDs[index] = uuid.New()
	}
	return fixture{
		Schema: schema, TenantID: uuid.New(), TenantScopeID: uuid.New(), ManagerUserID: uuid.New(),
		EmptyUserID: uuid.New(), NoReadUserID: uuid.New(), PlatformScopeID: uuid.New(), PlatformUserID: uuid.New(),
		PolicySiteID: policySiteIDs[0], PolicySiteIDs: policySiteIDs, UnboundSiteID: uuid.New(), ManagerUsername: "sec09-manager",
		EmptyUsername: "sec09-empty", NoReadUsername: "sec09-no-read", PlatformUsername: "sec09-platform",
	}
}

func seedIdentityAndSites(ctx context.Context, pool *pgxpool.Pool, data fixture, passwordHash string) error {
	managerRole, emptyRole, noReadRole, platformRole := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	now := time.Now().UTC()
	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		statements := []struct {
			query string
			args  []any
		}{
			{`INSERT INTO tenants(id,display_name,created_at,updated_at) VALUES($1,'SEC09 Review Tenant',$2,$2)`, []any{data.TenantID, now}},
			{`INSERT INTO access_scopes(id,kind,tenant_id,created_at) VALUES($1,'tenant',$2,$4),($3,'platform',NULL,$4)`, []any{data.TenantScopeID, data.TenantID, data.PlatformScopeID, now}},
			{`INSERT INTO users(id,username,display_name,password_hash,created_at,updated_at) VALUES
				($1,$2,'URL Auth Manager',$9,$10,$10),($3,$4,'URL Auth Empty',$9,$10,$10),
				($5,$6,'URL Auth No Read',$9,$10,$10),($7,$8,'URL Auth Platform',$9,$10,$10)`,
				[]any{data.ManagerUserID, data.ManagerUsername, data.EmptyUserID, data.EmptyUsername, data.NoReadUserID, data.NoReadUsername, data.PlatformUserID, data.PlatformUsername, passwordHash, now}},
			{`INSERT INTO memberships(scope_id,user_id,created_at) VALUES($1,$2,$7),($1,$3,$7),($1,$4,$7),($5,$6,$7)`,
				[]any{data.TenantScopeID, data.ManagerUserID, data.EmptyUserID, data.NoReadUserID, data.PlatformScopeID, data.PlatformUserID, now}},
			{`INSERT INTO roles(id,scope_id,name,description,system_role,created_at) VALUES
				($1,$2,'sec09_manager','manager',true,$7),($3,$2,'sec09_empty','empty',true,$7),
				($4,$2,'sec09_no_read','no read',true,$7),($5,$6,'sec09_platform','platform',true,$7)`,
				[]any{managerRole, data.TenantScopeID, emptyRole, noReadRole, platformRole, data.PlatformScopeID, now}},
			{`INSERT INTO role_permissions(role_id,permission_name) VALUES
				($1,'identity.self.read'),($1,'url_auth_policies.read'),($1,'url_auth_policies.manage'),($1,'sites.read'),
				($2,'identity.self.read'),($2,'url_auth_policies.read'),($2,'url_auth_policies.manage'),($2,'sites.read'),
				($3,'identity.self.read'),($3,'sites.read'),($4,'platform.admin')`, []any{managerRole, emptyRole, noReadRole, platformRole}},
			{`INSERT INTO role_assignments(scope_id,user_id,role_id,assigned_at) VALUES
				($1,$2,$3,$8),($1,$4,$5,$8),($1,$6,$7,$8),($9,$10,$11,$8)`,
				[]any{data.TenantScopeID, data.ManagerUserID, managerRole, data.EmptyUserID, emptyRole, data.NoReadUserID, noReadRole, now, data.PlatformScopeID, data.PlatformUserID, platformRole}},
		}
		for _, statement := range statements {
			if _, err := tx.Exec(ctx, statement.query, statement.args...); err != nil {
				return err
			}
		}
		siteIDs := append(append([]uuid.UUID(nil), data.PolicySiteIDs...), data.UnboundSiteID)
		for index, siteID := range siteIDs {
			domain := fmt.Sprintf("downloads-%02d.sec09.example", index+1)
			if index == 0 {
				domain = "downloads.sec09.example"
			} else if siteID == data.UnboundSiteID {
				domain = "unbound-long-domain-for-url-auth-review.sec09.example"
			}
			host := fmt.Sprintf("192.0.2.%d", index+10)
			if _, err := tx.Exec(ctx, `INSERT INTO sites(id,scope_id,owner_user_id,domain,http_ports,https_ports,origins,origin_hosts,cname,https_enabled,enabled,status,is_default,revision,created_by_user_id,updated_by_user_id,created_at,updated_at)
				VALUES($1,$2,$3,$4,ARRAY['80'],ARRAY[]::text[],ARRAY[$5 || ':80'],ARRAY[$5],'',false,true,'active',false,1,$3,$3,$6,$6)`,
				siteID, data.TenantScopeID, data.ManagerUserID, domain, host, now); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO site_origin_pools(site_id,updated_at) VALUES($1,$2)`, siteID, now); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO site_origins(site_id,position,host,port,weight,enabled) VALUES($1,1,$2,80,1,true)`, siteID, host); err != nil {
				return err
			}
		}
		return nil
	})
}

func seedPolicies(
	ctx context.Context,
	pool *pgxpool.Pool,
	identityService *identity.Service,
	iam *iamlock.Authorizer,
	cipher urlauthpolicy.SecretCipher,
	data fixture,
) error {
	login, err := identityService.Login(ctx, identity.LoginInput{Username: data.ManagerUsername, Password: reviewPassword}, identity.RequestInfo{
		RequestID: "sec09-review-seed-login", UserAgent: "sec09-review-seeder", SourceIP: "127.0.0.1",
	})
	if err != nil {
		return err
	}
	session, err := identityService.AuthenticateSession(ctx, login.AccessToken)
	if err != nil {
		return err
	}
	txAuthorizer, err := urlauthpolicy.NewIAMTxAuthorizer(iam)
	if err != nil {
		return err
	}
	store, err := urlauthpolicy.NewStoreWithAuthorizer(pool, time.Now, txAuthorizer)
	if err != nil {
		return err
	}
	service := urlauthpolicy.NewService(store, cipher)
	tenantID := data.TenantID
	actor := urlauthpolicy.Actor{UserID: data.ManagerUserID, ScopeID: data.TenantScopeID, ScopeKind: "tenant"}.
		WithCredential(urlauthpolicy.CredentialSession, session.SessionID, login.AccessToken, &tenantID)
	var first urlauthpolicy.SecretWriteResult
	for index := 1; index <= 21; index++ {
		name := fmt.Sprintf("Protected download rule %02d", index)
		if index == 1 {
			name = "Long English URL authentication policy for protected downloads and customer assets"
		}
		result, err := service.Create(ctx, actor, urlauthpolicy.CreateRequest{
			Fields: urlauthpolicy.PolicyFields{
				SiteID: data.PolicySiteIDs[index-1], Name: name, Enabled: index%3 != 0,
				Algorithm: urlauthpolicy.AlgorithmHMACSHA256, SignatureParameter: "sig", ExpirationParameter: "exp", KeyIDParameter: "kid",
				BindClientIP: index == 1, MaxClockSkewSeconds: 30, MaxValiditySeconds: 600, MaxSignatureUses: 1,
				ExcludedQueryParameters: []string{"utm_source"}, TrustedProxyCIDRs: []string{"192.0.2.0/24", "2001:db8::/32"},
			},
			IdempotencyKey: fmt.Sprintf("sec09-review-create-%02d", index), RequestID: fmt.Sprintf("sec09-review-create-%02d", index),
		})
		if err != nil {
			return err
		}
		result.Secret = ""
		if index == 1 {
			first = result
		}
	}
	rotated, err := service.Rotate(ctx, actor, urlauthpolicy.RotateRequest{
		ID: first.Policy.ID, ExpectedRevision: first.Policy.Revision,
		IdempotencyKey: "sec09-review-rotate-01", RequestID: "sec09-review-rotate-01",
	})
	rotated.Secret = ""
	return err
}
