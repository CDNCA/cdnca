package site

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/cachecontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/certificateasset"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/httppolicycontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/securitybinding"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// fix-transfer S2/S3: the old site's HTTP policy, cache policy, uploaded
// certificate (sealed again under the new tenant's AAD) and ACL library are
// carried to the new site; auto defense and the JS challenge are released
// and named in the result.
func TestSiteTransferCopiesSettingsAndReleasesDefenses(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required")
	}
	admin, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "site_transfer_copy_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(t.Context(), "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec(context.Background(), "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := database.Migrate(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	manager := addonSiteInsertPlatformActor(t, pool, "transfer-copy-admin")
	addonSiteAssignSubscriptionRole(t, pool, manager.ScopeID, manager.UserID, "platform-site-admin", "platform.admin",
		"sites.manage", "http_policies.manage")
	from := addonSiteInsertSubscriptionTenant(t, pool, "Transfer copy from", "transfer-copy-from")
	addonSiteAssignSubscriptionRole(t, pool, from.scopeID, from.userID, "site-owner", "sites.manage")
	to := addonSiteInsertSubscriptionTenant(t, pool, "Transfer copy to", "transfer-copy-to")
	addonSiteAssignSubscriptionRole(t, pool, to.scopeID, to.userID, "site-owner", "sites.manage")

	keyring, err := certificateasset.NewAESGCMPrivateKeyEnvelopeKeyring(certificateasset.PrivateKeyWrappingKey{
		ID: "transfer-test", Material: bytes.Repeat([]byte{0x42}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	certificates, err := certificateasset.NewStoreWithDependencies(pool, keyring, audit.New(pool), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	store := NewStoreWithClock(pool, func() time.Time { return now }, nil).WithTransferCertificates(certificates)
	store.guard = installAddonSiteEntitlement(t, pool, now, time.Hour)
	service := NewService(store)
	platform := Actor{UserID: manager.UserID, ScopeID: manager.ScopeID, ScopeKind: "platform", SessionID: manager.SessionID}

	created, err := service.Create(t.Context(), platform, CreateRequest{TargetScopeID: from.scopeID, OwnerUserID: from.userID,
		Fields: SiteFields{Domains: []string{"copy.example.com"}, HTTPPorts: []string{"80"},
			Origins: []string{"192.0.2.9:8080"}, Enabled: false, Status: StatusDisabled},
		IdempotencyKey: "transfer-copy-create", RequestID: "transfer-copy-create"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	old := created.Site

	// The old site's state, through the modules' own write paths.
	certificatePEM, privateKeyPEM := transferTestKeypair(t, now, "copy.example.com")
	certActor := certificateasset.Actor{UserID: manager.UserID, ScopeID: manager.ScopeID, ScopeKind: "platform",
		SessionID: manager.SessionID}
	owner := from.userID
	imported, err := certificates.Import(t.Context(), certActor, certificateasset.ImportRequest{TenantScopeID: from.scopeID,
		OwnerUserID: &owner, Name: "copy-cert", Source: certificateasset.SourceUploaded, CertificatePEM: certificatePEM,
		PrivateKeyPEM: privateKeyPEM, IdempotencyKey: "transfer-copy-cert", RequestID: "transfer-copy-cert"})
	if err != nil {
		t.Fatalf("import certificate: %v", err)
	}
	if _, err := certificates.Activate(t.Context(), certActor, certificateasset.ActivateRequest{TenantScopeID: from.scopeID,
		AssetID: imported.Asset.ID, VersionID: imported.Version.ID, ExpectedRevision: imported.Asset.Revision,
		IdempotencyKey: "transfer-copy-act", RequestID: "transfer-copy-act"}); err != nil {
		t.Fatalf("activate certificate: %v", err)
	}
	if _, err := certificates.Bind(t.Context(), certActor, certificateasset.BindRequest{TenantScopeID: from.scopeID,
		SiteID: old.ID, AssetID: imported.Asset.ID, VersionID: imported.Version.ID, Default: true,
		IdempotencyKey: "transfer-copy-bind", RequestID: "transfer-copy-bind"}); err != nil {
		t.Fatalf("bind certificate: %v", err)
	}
	var fromTenant uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT tenant_id FROM access_scopes WHERE id=$1`, from.scopeID).Scan(&fromTenant); err != nil {
		t.Fatal(err)
	}
	headers := []httppolicycontrol.HeaderAction{{Kind: "set", Name: "X-Transfer", Values: []string{"kept"}}}
	httpConfig, err := httppolicycontrol.NewSitePolicyConfig(4<<20, headers)
	if err != nil {
		t.Fatal(err)
	}
	cacheDocument := cachecontrol.PolicyDocument{Mode: cachecontrol.PolicyOverride,
		Rules:     []cachecontrol.Rule{{Order: 1, Extensions: []string{".js"}, StatusCodes: []int{200}, TTLSeconds: 600}},
		QueryMode: cachecontrol.QueryPreserve, QueryNames: []string{}, VaryHeaders: []string{"accept-encoding"}, DiskQuotaBytes: 64 << 20}
	acl, err := securitypolicy.NewService(securitypolicy.NewStoreWithClock(pool, func() time.Time { return now })).Create(t.Context(),
		securitypolicy.Actor{UserID: from.userID, ScopeID: from.scopeID, ScopeKind: "tenant"}, securitypolicy.CreateRequest{
			TargetScopeID: from.scopeID, OwnerUserID: from.userID, Fields: securitypolicy.PolicyFields{Kind: securitypolicy.KindACL,
				Name: "office", Enabled: true, DefaultAction: securitypolicy.ActionAllow, Rules: []securitypolicy.Rule{{Name: "office",
					Priority: 1, Enabled: true, Conditions: []securitypolicy.Condition{{Field: "client_ip", Operator: "ip_in_cidr",
						Values: []string{"192.0.2.0/24"}}}, Action: securitypolicy.ActionAllow, Flow: securitypolicy.FlowStop}}},
			IdempotencyKey: "transfer-copy-acl", RequestID: "transfer-copy-acl"})
	if err != nil {
		t.Fatalf("create ACL: %v", err)
	}
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := httppolicycontrol.CreateForNewSiteTx(t.Context(), tx, manager.ScopeID, manager.UserID, from.scopeID,
			fromTenant, old.ID, from.userID, httpConfig, now); err != nil {
			return err
		}
		if _, err := cachecontrol.CreateForNewSiteTx(t.Context(), tx, audit.New(nil), cachecontrol.Actor{UserID: manager.UserID,
			ScopeID: from.scopeID, ActorScopeID: manager.ScopeID}, fromTenant, old.ID, cacheDocument, "transfer-copy-cache", now); err != nil {
			return err
		}
		if err := securitybinding.AttachNewSiteTx(t.Context(), tx, from.scopeID, old.ID, acl.Policy.ID, securitypolicy.KindACL, now); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO autodefense_sites(tenant_scope_id,site_id,mode,sensitivity,maturity,
			cross_site,circuit_state,circuit_manual_resume,max_level,modules,revision,updated_at)
			VALUES($1,$2,'protect','medium','prior',false,'closed',false,'{"field":"site.max_level"}','[]',1,$3)
			ON CONFLICT (tenant_scope_id,site_id) DO UPDATE SET mode='protect'`, // site creation stored it as follow (fix-adglobal)
			from.scopeID, old.ID, now); err != nil {
			return err
		}
		// Fixture only: the projection row is revision-managed; the transfer
		// reads whether one exists.
		if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role=replica`); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO challenge_policies(id,tenant_scope_id,tenant_id,site_id,host,current_revision,
			current_enabled,current_document,created_by_user_id,created_at,updated_at)
			VALUES($1,$2,$3,$4,'copy.example.com',1,true,'{}',$5,$6,$6)`,
			uuid.New(), from.scopeID, fromTenant, old.ID, from.userID, now)
		return err
	}); err != nil {
		t.Fatalf("old site state: %v", err)
	}
	if err := pool.QueryRow(t.Context(), `SELECT revision FROM sites WHERE id=$1`, old.ID).Scan(&old.Revision); err != nil {
		t.Fatal(err)
	}

	moved, err := service.Transfer(t.Context(), platform, TransferRequest{ID: old.ID, ExpectedRevision: old.Revision,
		TargetUserID: to.userID, IdempotencyKey: "transfer-copy-1", RequestID: "transfer-copy-1"})
	if err != nil {
		t.Fatalf("transfer: %v", err)
	}
	slices.Sort(moved.Copied)
	slices.Sort(moved.Released)
	if strings.Join(moved.Copied, ",") != "acl_policy,cache_policy,certificate,http_policy" ||
		strings.Join(moved.Released, ",") != "auto_defense,js_challenge" {
		t.Fatalf("copied=%v released=%v", moved.Copied, moved.Released)
	}
	newID := moved.Site.ID

	got, found, err := pgxTxValue(t, pool, func(tx pgx.Tx) (httppolicycontrol.Config, bool, error) {
		return httppolicycontrol.SiteConfigTx(t.Context(), tx, to.scopeID, newID)
	})
	if err != nil || !found || got.MaxUploadBytes != 4<<20 || len(got.RequestHeaders) != 1 || got.RequestHeaders[0].Name != "x-transfer" {
		t.Fatalf("HTTP policy not copied: %+v %v %v", got, found, err)
	}
	document, found, err := pgxTxValue(t, pool, func(tx pgx.Tx) (cachecontrol.PolicyDocument, bool, error) {
		return cachecontrol.SiteDocumentTx(t.Context(), tx, to.scopeID, newID)
	})
	if err != nil || !found || len(document.Rules) != 1 || document.Rules[0].TTLSeconds != 600 {
		t.Fatalf("cache policy not copied: %+v %v %v", document, found, err)
	}
	var aclCopies int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM security_policy_site_bindings binding
		JOIN security_policies policy ON policy.id=binding.policy_id
		WHERE binding.tenant_scope_id=$1 AND binding.site_id=$2 AND binding.policy_kind='acl'
		  AND policy.scope_id=$1 AND policy.owner_user_id=$3 AND policy.id<>$4`,
		to.scopeID, newID, to.userID, acl.Policy.ID).Scan(&aclCopies); err != nil || aclCopies != 1 {
		t.Fatalf("ACL copy: %d %v", aclCopies, err)
	}
	// The certificate is a new asset of the new owner in the new tenant whose
	// private key unseals under that tenant's AAD (publication material).
	binding, _, err := certificates.GetSiteBinding(t.Context(), certActor, to.scopeID, newID)
	if err != nil || !binding.Bound || binding.AssetID == imported.Asset.ID || !binding.Default {
		t.Fatalf("certificate binding: %+v %v", binding, err)
	}
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		return certificates.UsePublicationMaterialsInTx(t.Context(), tx, certificateasset.PublicationRequest{
			TenantScopeID: to.scopeID, SiteIDs: []uuid.UUID{newID}, AssetID: binding.AssetID, VersionID: binding.VersionID,
			BindingRevision: binding.Revision}, func(materials []certificateasset.PublicationMaterial) error {
			if len(materials) != 1 || !bytes.Equal(materials[0].PrivateKeyPEM, privateKeyPEM) {
				t.Errorf("re-sealed private key differs")
			}
			return nil
		})
	}); err != nil {
		t.Fatalf("new certificate material: %v", err)
	}
	if moved.Site.HTTPSEnabled {
		t.Fatalf("old site had HTTPS off, new one turned it on")
	}
	var autoDefense, challenge bool
	if err := pool.QueryRow(t.Context(), `SELECT
		EXISTS(SELECT 1 FROM autodefense_sites WHERE site_id=$1 AND mode='protect'),
		EXISTS(SELECT 1 FROM challenge_policies WHERE site_id=$1)`, newID).Scan(&autoDefense, &challenge); err != nil ||
		autoDefense || challenge {
		t.Fatalf("defenses carried: auto=%v challenge=%v %v", autoDefense, challenge, err)
	}

	replayed, err := service.Transfer(t.Context(), platform, TransferRequest{ID: old.ID, ExpectedRevision: old.Revision,
		TargetUserID: to.userID, IdempotencyKey: "transfer-copy-1", RequestID: "transfer-copy-1"})
	slices.Sort(replayed.Copied)
	if err != nil || !replayed.Replayed || strings.Join(replayed.Copied, ",") != strings.Join(moved.Copied, ",") {
		t.Fatalf("replay: %+v %v", replayed, err)
	}
}

func pgxTxValue[T any](t *testing.T, pool *pgxpool.Pool, read func(pgx.Tx) (T, bool, error)) (T, bool, error) {
	t.Helper()
	var value T
	var found bool
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		var err error
		value, found, err = read(tx)
		return err
	})
	return value, found, err
}

func transferTestKeypair(t *testing.T, now time.Time, domain string) ([]byte, []byte) {
	t.Helper()
	issuerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	issuerTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Transfer Test Issuer"},
		NotBefore: now.Add(-48 * time.Hour), NotAfter: now.Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, issuerKey.Public(), issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: domain}, DNSNames: []string{domain},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(90 * 24 * time.Hour), BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, key.Public(), issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuerDER})...)
	return chain, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
}
