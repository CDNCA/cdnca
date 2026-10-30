//go:build integration

package dnsproviderremotesource

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/acmeworker"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestMigration060AppliesFromEmptyPG17(t *testing.T) {
	pool := openSourcePG17(t)
	applySourceMigrationsThrough(t, pool, 60)
	assertSourceMigrationVersion(t, pool, 60)
	var constraint string
	if err := pool.QueryRow(t.Context(), `SELECT pg_get_constraintdef(oid)
		FROM pg_constraint
		WHERE conname='acme_issuance_challenge_publication_shape_048'
		  AND conrelid='acme_issuance_challenge_events'::regclass`).Scan(&constraint); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(constraint, "2048") {
		t.Fatalf("060 constraint = %s", constraint)
	}
}

func TestOutstandingRemoteTXTHandlesReturnsCompleteUncleanedIdentity(t *testing.T) {
	pool := openSourcePG17(t)
	applySourceMigrationsThrough(t, pool, 60)
	tenant := seedSourceTenant(t, pool, "outstanding-handles")
	cipher := mustSourceCipher(t, "outstanding-key", 17)
	providerID := insertSourceProvider(t, pool, tenant, "dns_la", "verified", cipher,
		`{"api_id":"outstanding-id","api_secret":"outstanding-secret"}`)
	zoneID := insertSourceZone(t, pool, tenant, providerID, "example.test")

	request := acmeworker.IssueRequest{
		TenantID: tenant.tenantID, ScopeID: tenant.scopeID, OperationID: uuid.NewString(), ActorUserID: tenant.userID,
		ProviderID: providerID, ZoneID: zoneID,
		ProviderRef: providerID.String(), DirectoryURL: "https://ca.example/directory",
		AccountKeyRef: "kms/account", CertificateKeyRef: "kms/certificate",
		Contacts: []string{"mailto:ops@example.test"}, AcceptTerms: true,
		Domains: []string{"example.test"}, ChallengeType: acmeworker.ChallengeDNS01,
	}
	request.CertificateOrderID = uuid.MustParse(request.OperationID)
	seedSourceACMERequestFacts(t, pool, tenant, request)
	store, err := acmeworker.NewPGOperationStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	claim, err := store.Claim(t.Context(), request, sourceIssueRequestDigest(request), now, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	authorizationURLs := []string{
		"https://ca.example/authz/0", "https://ca.example/authz/1", "https://ca.example/authz/2",
	}
	lease := advanceSourceToAuthorizing(t, pool, store, claim.Lease, now, authorizationURLs)

	want := make(map[uuid.UUID]acmeworker.ChallengeIdentity)
	for index, recordRef := range []string{"v1.legacy-record", "v2.signed-record", "v2.cleaned-record"} {
		// Like the worker (acmeworker/worker.go authorize), the challenge carries the
		// request identity; PrepareChallenge rejects one that does not match the lease.
		challenge, prepareErr := store.PrepareChallenge(t.Context(), lease, acmeworker.ChallengeIdentity{
			TenantID: request.TenantID, ScopeID: request.ScopeID, OperationID: request.OperationID,
			ProviderID: request.ProviderID, ZoneID: request.ZoneID,
			ProviderRef:      request.ProviderRef,
			AuthorizationURL: authorizationURLs[index],
			ChallengeURL:     fmt.Sprintf("https://ca.example/challenge/%d", index),
			ChallengeType:    acmeworker.ChallengeDNS01,
			Identifier:       "example.test",
			RecordName:       "_acme-challenge.example.test.",
			Token:            fmt.Sprintf("token-%d", index),
			ExactValue:       fmt.Sprintf("exact-value-%d", index),
		}, now)
		if prepareErr != nil {
			t.Fatal(prepareErr)
		}
		challenge.TXTHandle = acmeworker.RemoteTXTHandle{ProviderRef: request.ProviderRef, RecordRef: recordRef}
		if err := store.MarkChallenge(t.Context(), lease, challenge, "published", now); err != nil {
			t.Fatal(err)
		}
		if index == 2 {
			cleanup, err := store.ClaimChallengeCleanup(t.Context(), lease, challenge, now)
			if err != nil {
				t.Fatal(err)
			}
			if err := cleanup.Complete(t.Context(), now); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want[challenge.AttemptID] = challenge
	}

	got, err := New(pool, cipher).OutstandingRemoteTXTHandles(t.Context())
	if err != nil || len(got) != len(want) {
		t.Fatalf("OutstandingRemoteTXTHandles()=%+v error=%v", got, err)
	}
	for _, challenge := range got {
		expected, ok := want[challenge.AttemptID]
		if !ok || challenge != expected {
			t.Fatalf("outstanding challenge=%+v want=%+v", challenge, expected)
		}
	}
}

func TestSourceResolveRejectsInvalidContextWithoutDatabaseAccess(t *testing.T) {
	source := New(&pgxpool.Pool{}, &sourceKeyring{})
	lookup := sourceLookup(sourceTenant{tenantID: uuid.New(), scopeID: uuid.New()}, uuid.New(), uuid.Nil, "_acme-challenge.example.test.")
	contexts := []struct {
		name string
		ctx  context.Context
	}{
		{name: "nil", ctx: nil},
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	contexts = append(contexts, struct {
		name string
		ctx  context.Context
	}{name: "cancelled", ctx: cancelled})
	deadline, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	contexts = append(contexts, struct {
		name string
		ctx  context.Context
	}{name: "deadline", ctx: deadline})

	for _, testCase := range contexts {
		t.Run(testCase.name, func(t *testing.T) {
			config, err, panicValue := callSourceResolve(source, testCase.ctx, lookup)
			if panicValue != nil {
				t.Fatalf("Resolve() panicked for %s context: %v", testCase.name, panicValue)
			}
			if !errors.Is(err, ErrUnavailable) {
				t.Fatalf("Resolve() error = %v, want ErrUnavailable", err)
			}
			if config.TenantScopeID != uuid.Nil || config.ProviderID != uuid.Nil || config.ProviderType != "" ||
				config.ZoneID != uuid.Nil || config.ZoneName != "" || config.Credentials != nil {
				t.Fatalf("Resolve() config = %+v, want zero value", config)
			}
		})
	}
}

func TestSourceOutstandingRemoteTXTHandlesRejectsInvalidContextWithoutDatabaseAccess(t *testing.T) {
	source := New(&pgxpool.Pool{}, &sourceKeyring{})
	contexts := []struct {
		name string
		ctx  context.Context
	}{
		{name: "nil", ctx: nil},
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	contexts = append(contexts, struct {
		name string
		ctx  context.Context
	}{name: "cancelled", ctx: cancelled})
	deadline, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	contexts = append(contexts, struct {
		name string
		ctx  context.Context
	}{name: "deadline", ctx: deadline})

	for _, testCase := range contexts {
		t.Run(testCase.name, func(t *testing.T) {
			got, err, panicValue := callOutstandingRemoteTXTHandles(source, testCase.ctx)
			if panicValue != nil {
				t.Fatalf("OutstandingRemoteTXTHandles() panicked for %s context: %v", testCase.name, panicValue)
			}
			if !errors.Is(err, ErrUnavailable) {
				t.Fatalf("OutstandingRemoteTXTHandles() error = %v, want ErrUnavailable", err)
			}
			if got != nil {
				t.Fatalf("OutstandingRemoteTXTHandles() = %+v, want nil", got)
			}
		})
	}
}

func callSourceResolve(source *Source, ctx context.Context, lookup dnsproviderremote.ProviderLookup) (config dnsproviderremote.ProviderConfig, err error, panicValue any) {
	defer func() {
		panicValue = recover()
	}()
	config, err = source.Resolve(ctx, lookup)
	return config, err, nil
}

func callOutstandingRemoteTXTHandles(source *Source, ctx context.Context) (handles []acmeworker.ChallengeIdentity, err error, panicValue any) {
	defer func() {
		panicValue = recover()
	}()
	handles, err = source.OutstandingRemoteTXTHandles(ctx)
	return handles, err, nil
}

// TestDNSLAProviderServicePersistence covers DNS.LA through the service on the release
// schema: legacy dnsdun cannot be created (service and database), DNS.LA credentials are
// validated, verified with the entered secret and never reach the audit trail.
func TestDNSLAProviderServicePersistence(t *testing.T) {
	pool := openSourcePG17(t)
	if err := database.Migrate(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	tenant := seedSourceTenant(t, pool, "dns-la-service")
	cipher := mustSourceCipher(t, "dns-la-key-v1", 11)
	verifier := &sourceVerifier{}
	service := dnsacme.NewServiceWithClockAndVerifier(dnsacme.NewStore(pool), cipher, verifier, time.Now)
	actor := dnsacme.Actor{UserID: tenant.userID, ScopeID: tenant.scopeID, ScopeKind: "tenant"}

	if _, err := service.CreateProvider(t.Context(), actor, dnsacme.CreateProviderRequest{
		Name: "Legacy create", ProviderType: "dnsdun",
		Credentials:    map[string]string{"api_id": "legacy-id", "api_secret": "legacy-secret"},
		IdempotencyKey: "legacy-create", RequestID: "legacy-create",
	}); !errors.Is(err, dnsacme.ErrInvalidInput) {
		t.Fatalf("CreateProvider(dnsdun) error = %v", err)
	}
	_, legacyCiphertext, err := cipher.Encrypt([]byte(`{"api_id":"new-legacy","api_secret":"new-legacy-secret"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO dns_providers(
		id,scope_id,name,provider_type,credential_key_id,credential_ciphertext,status,
		created_by_user_id,updated_by_user_id
	) VALUES($1,$2,'Blocked legacy','dnsdun','dns-la-key-v1',$3,'disabled',$4,$4)`,
		uuid.New(), tenant.scopeID, legacyCiphertext, tenant.userID); err == nil ||
		!strings.Contains(err.Error(), "new legacy dnsdun providers are disabled") {
		t.Fatalf("database insert of a legacy dnsdun provider error = %v", err)
	}

	provider, err := service.CreateProvider(t.Context(), actor, dnsacme.CreateProviderRequest{
		Name: "DNS.LA", ProviderType: "dns_la",
		Credentials:    map[string]string{"api_id": "dnsla-id-a", "api_secret": "dnsla-secret-a"},
		IdempotencyKey: "dnsla-create", RequestID: "dnsla-create",
	})
	if err != nil || provider.ProviderType != "dns_la" || provider.Status != dnsacme.ProviderStatusUnverified {
		t.Fatalf("CreateProvider(dns_la) = %+v, %v", provider, err)
	}
	if _, err := service.CreateProvider(t.Context(), actor, dnsacme.CreateProviderRequest{
		Name: "DNS.LA invalid", ProviderType: "dns_la",
		Credentials:    map[string]string{"api_id": "id", "api_secret": "secret", "extra": "rejected"},
		IdempotencyKey: "dnsla-invalid", RequestID: "dnsla-invalid",
	}); !errors.Is(err, dnsacme.ErrInvalidInput) {
		t.Fatalf("CreateProvider(dns_la extra field) error = %v", err)
	}
	if _, err := service.UpdateProvider(t.Context(), actor, dnsacme.UpdateProviderRequest{
		ID: provider.ID, ExpectedRevision: provider.Revision, Name: provider.Name,
		Status:         dnsacme.ProviderStatusUnverified,
		Credentials:    map[string]string{"api_id": "id", "api_secret": "secret", "extra": "rejected"},
		IdempotencyKey: "dnsla-invalid-update", RequestID: "dnsla-invalid-update",
	}); !errors.Is(err, dnsacme.ErrInvalidInput) {
		t.Fatalf("UpdateProvider(dns_la extra field) error = %v", err)
	}
	provider, err = service.UpdateProvider(t.Context(), actor, dnsacme.UpdateProviderRequest{
		ID: provider.ID, ExpectedRevision: provider.Revision, Name: provider.Name,
		Status:         dnsacme.ProviderStatusUnverified,
		Credentials:    map[string]string{"api_id": "dnsla-id-b", "api_secret": "dnsla-secret-b"},
		IdempotencyKey: "dnsla-update", RequestID: "dnsla-update",
	})
	if err != nil {
		t.Fatalf("UpdateProvider(dns_la) error = %v", err)
	}
	provider, err = service.VerifyProvider(t.Context(), actor, dnsacme.VerifyProviderRequest{
		ID: provider.ID, ExpectedRevision: provider.Revision,
		IdempotencyKey: "dnsla-verify", RequestID: "dnsla-verify",
	})
	if err != nil || provider.Status != dnsacme.ProviderStatusVerified || verifier.calls.Load() != 1 ||
		verifier.providerType != "dns_la" || verifier.apiID != "dnsla-id-b" || verifier.apiSecret != "dnsla-secret-b" {
		t.Fatalf("VerifyProvider(dns_la) = %+v, %v, verifier=%+v", provider, err, verifier)
	}
	var auditPayload string
	if err := pool.QueryRow(t.Context(), `SELECT COALESCE(string_agg(payload::text,''),'') FROM audit_events
		WHERE resource_id=$1`, provider.ID.String()).Scan(&auditPayload); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"dnsla-id-b", "dnsla-secret-b", "api_secret", "credential_ciphertext"} {
		if strings.Contains(auditPayload, forbidden) {
			t.Fatalf("audit payload leaked %q: %s", forbidden, auditPayload)
		}
	}

	if err := service.DeleteProvider(t.Context(), actor, dnsacme.DeleteRequest{
		ID: provider.ID, ExpectedRevision: provider.Revision,
		IdempotencyKey: "dnsla-delete", RequestID: "dnsla-delete",
	}); err != nil {
		t.Fatal(err)
	}
}

func TestSourceResolveFailClosedAndCredentialRotation(t *testing.T) {
	pool := openSourcePG17(t)
	if err := database.Migrate(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	tenantA := seedSourceTenant(t, pool, "source-a")
	tenantB := seedSourceTenant(t, pool, "source-b")
	keyA := mustSourceCipher(t, "source-key-a", 21)
	keyB := mustSourceCipher(t, "source-key-b", 22)
	keyring := &sourceKeyring{primary: keyA, byID: map[string]*dnsacme.AESGCMCredentialCipher{
		"source-key-a": keyA, "source-key-b": keyB,
	}}
	providerID := insertSourceProvider(t, pool, tenantA, "dns_la", "verified", keyA,
		`{"api_id":"dnsla-id-a","api_secret":"dnsla-secret-a"}`)
	rootZoneID := insertSourceZone(t, pool, tenantA, providerID, "example.test")
	subZoneID := insertSourceZone(t, pool, tenantA, providerID, "sub.example.test")
	providerBID := insertSourceProvider(t, pool, tenantB, "dns_la", "verified", keyB,
		`{"api_id":"dnsla-id-b","api_secret":"dnsla-secret-b"}`)
	zoneBID := insertSourceZone(t, pool, tenantB, providerBID, "tenant-b.test")

	source := New(pool, keyring)
	// Resolve only serves credentials to a live ACME operation bound to the provider and
	// an explicit zone, so every lookup comes from a claimed issuance operation.
	opSub := sourceOperationLookup(t, pool, tenantA, providerID, subZoneID, "sub.example.test",
		"_acme-challenge.sub.example.test.")
	opRoot := sourceOperationLookup(t, pool, tenantA, providerID, rootZoneID, "example.test",
		"_acme-challenge.example.test.")
	opB := sourceOperationLookup(t, pool, tenantB, providerBID, zoneBID, "tenant-b.test",
		"_acme-challenge.tenant-b.test.")
	withOwner := func(lookup dnsproviderremote.ProviderLookup, owner string) dnsproviderremote.ProviderLookup {
		lookup.OwnerName = owner
		return lookup
	}
	lookup := opSub
	config, err := source.Resolve(t.Context(), lookup)
	if err != nil || config.ProviderType != "dns_la" || config.ZoneName != "sub.example.test" ||
		config.TenantScopeID != tenantA.scopeID || config.ProviderID != providerID || config.ZoneID != subZoneID ||
		config.Credentials["api_id"] != "dnsla-id-a" || config.Credentials["api_secret"] != "dnsla-secret-a" {
		t.Fatalf("Resolve() = %+v, %v", config, err)
	}
	config.Credentials["api_secret"] = "mutated-by-caller"
	second, err := source.Resolve(t.Context(), lookup)
	if err != nil || second.Credentials["api_secret"] != "dnsla-secret-a" {
		t.Fatalf("Resolve() retained caller mutation: %+v, %v", second, err)
	}
	bound, err := source.Resolve(t.Context(), withOwner(opRoot, "_acme-challenge.sub.example.test."))
	if err != nil || bound.ZoneID != rootZoneID || bound.ZoneName != "example.test" {
		t.Fatalf("bound zone was longest-matched again: %+v, %v", bound, err)
	}
	unbound := opSub
	unbound.ZoneID = uuid.Nil
	assertSourceFailure(t, sourceResolveError(source, t.Context(), unbound), "dnsla-secret-a")
	crossTenant := opSub
	crossTenant.TenantID, crossTenant.ScopeID, crossTenant.TenantScopeID = tenantB.tenantID, tenantB.scopeID, tenantB.scopeID

	concurrentErrs := make(chan error, 16)
	var concurrent sync.WaitGroup
	for index := range 16 {
		concurrent.Add(1)
		go func() {
			defer concurrent.Done()
			for range 100 {
				var lookup dnsproviderremote.ProviderLookup
				var wantScope, wantProvider, wantZone uuid.UUID
				var wantSecret string
				if index%2 == 0 {
					lookup = opRoot
					wantScope, wantProvider, wantZone, wantSecret = tenantA.scopeID, providerID, rootZoneID, "dnsla-secret-a"
				} else {
					lookup = opB
					wantScope, wantProvider, wantZone, wantSecret = tenantB.scopeID, providerBID, zoneBID, "dnsla-secret-b"
				}
				resolved, resolveErr := source.Resolve(context.Background(), lookup)
				if resolveErr != nil || resolved.TenantScopeID != wantScope || resolved.ProviderID != wantProvider ||
					resolved.ZoneID != wantZone || resolved.Credentials["api_secret"] != wantSecret {
					concurrentErrs <- fmt.Errorf("global source cross-talk: config=%+v error=%v", resolved, resolveErr)
					return
				}
			}
		}()
	}
	concurrent.Wait()
	close(concurrentErrs)
	for err := range concurrentErrs {
		t.Fatal(err)
	}

	assertSourceFailure(t, sourceResolveError(source, t.Context(), withOwner(opRoot, "_acme.other.test.")),
		providerID.String(), "_acme.other.test", "dnsla-secret-a")
	assertSourceFailure(t, sourceResolveError(source, t.Context(), crossTenant),
		providerID.String(), tenantA.scopeID.String(), "dnsla-secret-a")
	assertSourceFailure(t, sourceResolveError(New(nil, keyring), t.Context(), opRoot), "SELECT", providerID.String())
	closedPool, err := pgxpool.NewWithConfig(t.Context(), pool.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	closedPool.Close()
	assertSourceFailure(t, sourceResolveError(New(closedPool, keyring), t.Context(), opRoot), "closed pool", "SELECT")

	keyID, ciphertextA := sealSourceCredentials(t, keyA, tenantA, providerID, `{"api_id":"dnsla-id-a","api_secret":"dnsla-secret-a"}`)
	setSourceCredentials(t, pool, providerID, keyID, ciphertextA)
	t.Run("disabled provider", func(t *testing.T) {
		setSourceProviderStatus(t, pool, providerID, "disabled")
		assertSourceFailure(t, sourceResolveError(source, t.Context(), opRoot), "dnsla-secret-a")
		setSourceProviderStatus(t, pool, providerID, "verified")
	})
	t.Run("tampered ciphertext", func(t *testing.T) {
		tampered := append([]byte(nil), ciphertextA...)
		tampered[len(tampered)-1] ^= 0xff
		setSourceCredentials(t, pool, providerID, keyID, tampered)
		assertSourceFailure(t, sourceResolveError(source, t.Context(), opRoot), "dnsla-secret-a")
		setSourceCredentials(t, pool, providerID, keyID, ciphertextA)
	})
	t.Run("bad and extra JSON", func(t *testing.T) {
		for _, raw := range []string{
			`{"api_id":`,
			`{"api_id":"dnsla-id-a","api_secret":"dnsla-secret-a","extra":"secret-extra"}`,
		} {
			badKey, badCiphertext := sealSourceCredentials(t, keyA, tenantA, providerID, raw)
			setSourceCredentials(t, pool, providerID, badKey, badCiphertext)
			assertSourceFailure(t, sourceResolveError(source, t.Context(), opRoot),
				"dnsla-secret-a", "secret-extra")
		}
		setSourceCredentials(t, pool, providerID, keyID, ciphertextA)
	})
	t.Run("unknown key", func(t *testing.T) {
		setSourceCredentials(t, pool, providerID, "unknown-sensitive-key", ciphertextA)
		assertSourceFailure(t, sourceResolveError(source, t.Context(), opRoot),
			"unknown-sensitive-key", "dnsla-secret-a")
		setSourceCredentials(t, pool, providerID, keyID, ciphertextA)
	})
	t.Run("inactive actor and tenant", func(t *testing.T) {
		if _, err := pool.Exec(t.Context(), `UPDATE users SET status='disabled' WHERE id=$1`, tenantA.userID); err != nil {
			t.Fatal(err)
		}
		assertSourceFailure(t, sourceResolveError(source, t.Context(), opRoot), "dnsla-secret-a")
		if _, err := pool.Exec(t.Context(), `UPDATE users SET status='active' WHERE id=$1`, tenantA.userID); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(t.Context(), `UPDATE memberships SET status='suspended' WHERE scope_id=$1 AND user_id=$2`, tenantA.scopeID, tenantA.userID); err != nil {
			t.Fatal(err)
		}
		assertSourceFailure(t, sourceResolveError(source, t.Context(), opRoot), "dnsla-secret-a")
		if _, err := pool.Exec(t.Context(), `UPDATE memberships SET status='active' WHERE scope_id=$1 AND user_id=$2`, tenantA.scopeID, tenantA.userID); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(t.Context(), `UPDATE tenants SET status='suspended' WHERE id=$1`, tenantA.tenantID); err != nil {
			t.Fatal(err)
		}
		assertSourceFailure(t, sourceResolveError(source, t.Context(), opRoot), "dnsla-secret-a")
		if _, err := pool.Exec(t.Context(), `UPDATE tenants SET status='active' WHERE id=$1`, tenantA.tenantID); err != nil {
			t.Fatal(err)
		}
	})

	keyBID, ciphertextB := sealSourceCredentials(t, keyB, tenantA, providerID, `{"api_id":"dnsla-id-b","api_secret":"dnsla-secret-b"}`)
	rotationErrs := make(chan error, 8)
	var wait sync.WaitGroup
	for range 8 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for range 150 {
				resolved, resolveErr := source.Resolve(context.Background(), opRoot)
				if resolveErr != nil {
					rotationErrs <- resolveErr
					return
				}
				pair := resolved.Credentials["api_id"] + "/" + resolved.Credentials["api_secret"]
				if pair != "dnsla-id-a/dnsla-secret-a" && pair != "dnsla-id-b/dnsla-secret-b" {
					rotationErrs <- fmt.Errorf("mixed credential pair")
					return
				}
			}
		}()
	}
	for index := range 300 {
		if index%2 == 0 {
			setSourceCredentials(t, pool, providerID, keyBID, ciphertextB)
		} else {
			setSourceCredentials(t, pool, providerID, keyID, ciphertextA)
		}
	}
	wait.Wait()
	close(rotationErrs)
	for err := range rotationErrs {
		t.Fatalf("concurrent credential rotation: %v", err)
	}
}

func TestReconcileProviderIOHoldsNoPostgresLockAndRevisionDriftFailsClosed(t *testing.T) {
	pool := openSourcePG17(t)
	if err := database.Migrate(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	tenant := seedSourceTenant(t, pool, "reconcile-lock-boundary")
	cipher := mustSourceCipher(t, "reconcile-key", 31)
	providerID := insertSourceProvider(t, pool, tenant, "cloudflare", "verified", cipher,
		`{"api_token":"sensitive-reconcile-token"}`)
	zoneID := insertSourceZone(t, pool, tenant, providerID, "example.test")
	siteID := insertSourceReconcileSite(t, pool, tenant, "reconcile.example.test")

	for _, test := range []struct {
		name      string
		requestID string
		drift     bool
	}{
		{name: "unrelated concurrent row update is not blocked", requestID: "reconcile-lock-boundary-unrelated"},
		{name: "revision drift fails closed", requestID: "reconcile-lock-boundary-revision", drift: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := pool.Exec(t.Context(), `UPDATE dns_zones SET revision=1 WHERE id=$1`, zoneID); err != nil {
				t.Fatal(err)
			}
			mutation := dnscheck.ProviderMutation{
				ClientRequestID: test.requestID, TenantID: tenant.tenantID, SiteID: siteID, ZoneID: zoneID,
				ExpectedRevision: 1,
				Operation: dnscheck.ProviderOperation{
					Sequence: 1, Action: dnscheck.ProviderCreate, Name: "www.example.test.", Type: dnscheck.RecordA,
					Value: "192.0.2.10", TTL: 300, Reason: "missing_record",
				},
			}
			insertSourceReconcileOperation(t, pool, tenant, siteID, zoneID, mutation)
			remote := &blockingSourceReconcileRemote{started: make(chan struct{}, 1), release: make(chan struct{})}
			resolver, err := NewReconcileResolver(New(pool, cipher), remote)
			if err != nil {
				t.Fatal(err)
			}
			adapter, err := resolver.ResolveProvider(t.Context(), tenant.tenantID, siteID, zoneID)
			if err != nil {
				t.Fatal(err)
			}
			result := make(chan struct {
				value dnscheck.ProviderMutationResult
				err   error
			}, 1)
			go func() {
				value, mutateErr := adapter.Mutate(context.Background(), mutation)
				result <- struct {
					value dnscheck.ProviderMutationResult
					err   error
				}{value: value, err: mutateErr}
			}()
			select {
			case <-remote.started:
			case early := <-result:
				t.Fatalf("Mutate() returned before provider I/O: (%+v,%v)", early.value, early.err)
			case <-time.After(10 * time.Second):
				t.Fatal("timed out waiting for provider I/O")
			}
			writeCtx, cancel := context.WithTimeout(t.Context(), time.Second)
			if test.drift {
				_, err = pool.Exec(writeCtx, `UPDATE dns_zones SET revision=revision+1 WHERE id=$1`, zoneID)
				assertSourcePGCode(t, err, "P8903")
			} else {
				_, err = pool.Exec(writeCtx, `UPDATE dns_zones SET updated_at=clock_timestamp() WHERE id=$1`, zoneID)
				if err != nil {
					close(remote.release)
					t.Fatalf("concurrent PostgreSQL write was blocked by remote I/O: %v", err)
				}
			}
			cancel()
			close(remote.release)
			got := <-result
			if got.err != nil || got.value.Revision != 2 {
				t.Fatalf("Mutate()=(%+v,%v), want revision=2", got.value, got.err)
			}
		})
	}
}

func TestReconcileMutationClaimBlocksAuthorityWithoutHoldingNetworkTransaction(t *testing.T) {
	pool := openSourcePG17(t)
	if err := database.Migrate(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	tenant := seedSourceTenant(t, pool, "reconcile-claim")
	cipher := mustSourceCipher(t, "reconcile-claim-key", 41)
	providerID := insertSourceProvider(t, pool, tenant, "cloudflare", "verified", cipher,
		`{"api_token":"sensitive-reconcile-token"}`)
	zoneID := insertSourceZone(t, pool, tenant, providerID, "example.test")
	siteID := insertSourceReconcileSite(t, pool, tenant, "claim.example.test")
	mutation := dnscheck.ProviderMutation{
		ClientRequestID: "reconcile-claim-operation", TenantID: tenant.tenantID,
		SiteID: siteID, ZoneID: zoneID, ExpectedRevision: 1,
		Operation: dnscheck.ProviderOperation{
			Sequence: 1, Action: dnscheck.ProviderCreate, Name: "www.example.test.", Type: dnscheck.RecordA,
			Value: "192.0.2.10", TTL: 300, Reason: "missing_record",
		},
	}
	insertSourceReconcileOperation(t, pool, tenant, siteID, zoneID, mutation)
	remote := &claimBoundaryRemote{started: make(chan struct{}, 1), release: make(chan struct{})}
	resolver, err := NewReconcileResolver(New(pool, cipher), remote)
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := resolver.ResolveProvider(t.Context(), tenant.tenantID, siteID, zoneID)
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, mutateErr := adapter.Mutate(context.Background(), mutation)
		result <- mutateErr
	}()
	select {
	case <-remote.started:
	case early := <-result:
		t.Fatalf("Mutate() returned before provider I/O: %v", early)
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for provider I/O")
	}
	writeCtx, cancel := context.WithTimeout(t.Context(), time.Second)
	_, err = pool.Exec(writeCtx, `UPDATE dns_providers SET revision=revision+1 WHERE id=$1`, providerID)
	cancel()
	assertSourcePGCode(t, err, "P8903")
	close(remote.release)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	var state string
	if err := pool.QueryRow(t.Context(), `SELECT state FROM dns_reconcile_provider_mutation_claims
		WHERE tenant_id=$1 AND client_request_id=$2`, tenant.tenantID, mutation.ClientRequestID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "succeeded" {
		t.Fatalf("claim state=%s, want succeeded", state)
	}
}

func TestReconcileUnknownResponsePersistsUncertainAndRecoversByLookup(t *testing.T) {
	pool := openSourcePG17(t)
	if err := database.Migrate(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	tenant := seedSourceTenant(t, pool, "reconcile-uncertain")
	cipher := mustSourceCipher(t, "reconcile-uncertain-key", 42)
	providerID := insertSourceProvider(t, pool, tenant, "cloudflare", "verified", cipher,
		`{"api_token":"sensitive-reconcile-token"}`)
	zoneID := insertSourceZone(t, pool, tenant, providerID, "example.test")
	siteID := insertSourceReconcileSite(t, pool, tenant, "uncertain.example.test")
	mutation := dnscheck.ProviderMutation{
		ClientRequestID: "reconcile-uncertain-operation", TenantID: tenant.tenantID,
		SiteID: siteID, ZoneID: zoneID, ExpectedRevision: 1,
		Operation: dnscheck.ProviderOperation{
			Sequence: 1, Action: dnscheck.ProviderCreate, Name: "www.example.test.", Type: dnscheck.RecordA,
			Value: "192.0.2.10", TTL: 300, Reason: "missing_record",
		},
	}
	insertSourceReconcileOperation(t, pool, tenant, siteID, zoneID, mutation)
	remote := &responseLossSourceRemote{}
	source := New(pool, cipher)
	resolver, err := NewReconcileResolver(source, remote)
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := resolver.ResolveProvider(t.Context(), tenant.tenantID, siteID, zoneID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Mutate(t.Context(), mutation); err == nil {
		t.Fatal("response-loss mutation succeeded")
	}
	var state string
	if err := pool.QueryRow(t.Context(), `SELECT state FROM dns_reconcile_provider_mutation_claims
		WHERE tenant_id=$1 AND client_request_id=$2`, tenant.tenantID, mutation.ClientRequestID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "uncertain" {
		t.Fatalf("claim state=%s, want uncertain", state)
	}
	var remaining float64
	if err := pool.QueryRow(t.Context(), `SELECT extract(epoch FROM recovery_not_before-clock_timestamp())
		FROM dns_reconcile_provider_mutation_claims
		WHERE tenant_id=$1 AND client_request_id=$2`, tenant.tenantID, mutation.ClientRequestID).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining < 119 || remaining > 121 {
		t.Fatalf("caller-controlled recovery window remaining=%f seconds", remaining)
	}
	if _, err := adapter.Mutate(t.Context(), mutation); err == nil || remote.mutations.Load() != 1 {
		t.Fatalf("early recovery error=%v mutations=%d", err, remote.mutations.Load())
	}
	wrongSite := mutation
	wrongSite.SiteID = uuid.New()
	if _, err := adapter.Mutate(t.Context(), wrongSite); !errors.Is(err, dnscheck.ErrProviderRevisionConflict) ||
		remote.mutations.Load() != 1 {
		t.Fatalf("wrong-site replay error=%v mutations=%d", err, remote.mutations.Load())
	}
	wrongRevision := mutation
	wrongRevision.ExpectedRevision++
	if _, err := adapter.Mutate(t.Context(), wrongRevision); !errors.Is(err, dnscheck.ErrProviderRevisionConflict) ||
		remote.mutations.Load() != 1 {
		t.Fatalf("wrong-revision replay error=%v mutations=%d", err, remote.mutations.Load())
	}
	if _, err := pool.Exec(t.Context(), `UPDATE dns_zones SET revision=revision+1 WHERE id=$1`, zoneID); err == nil {
		t.Fatal("uncertain mutation claim permitted zone revision drift")
	}
	if _, err := adapter.Mutate(t.Context(), mutation); err == nil || remote.mutations.Load() != 1 {
		t.Fatalf("pending recovery error=%v mutations=%d", err, remote.mutations.Load())
	}
}

func TestReconcileUncertainPersistenceFailureStaysLookupOnlyAcrossLeaseAndRestart(t *testing.T) {
	pool := openSourcePG17(t)
	if err := database.Migrate(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	tenant := seedSourceTenant(t, pool, "reconcile-persistence-failure-restart")
	cipher := mustSourceCipher(t, "reconcile-persistence-failure-restart-key", 46)
	providerID := insertSourceProvider(t, pool, tenant, "cloudflare", "verified", cipher,
		`{"api_token":"sensitive-reconcile-token"}`)
	zoneID := insertSourceZone(t, pool, tenant, providerID, "example.test")
	siteID := insertSourceReconcileSite(t, pool, tenant, "persistence-failure.example.test")
	mutation := dnscheck.ProviderMutation{
		ClientRequestID: "reconcile-persistence-failure-restart-operation", TenantID: tenant.tenantID,
		SiteID: siteID, ZoneID: zoneID, ExpectedRevision: 1,
		Operation: dnscheck.ProviderOperation{
			Sequence: 1, Action: dnscheck.ProviderCreate, Name: "www.example.test.", Type: dnscheck.RecordA,
			Value: "192.0.2.10", TTL: 300, Reason: "missing_record",
		},
	}
	insertSourceReconcileOperation(t, pool, tenant, siteID, zoneID, mutation)
	source := New(pool, cipher)
	authority := &uncertainPersistenceFailureSource{Source: source}
	authority.fail.Store(true)
	remote := &responseLossSourceRemote{}
	adapter, err := dnsproviderremote.NewReconcileAdapter(authority, remote)
	if err != nil {
		t.Fatal(err)
	}
	_, err = adapter.Mutate(t.Context(), mutation)
	assertSourceRecoveryError(t, err, "provider_recovery_persistence_failed")
	if remote.mutations.Load() != 1 {
		t.Fatalf("provider mutations=%d, want 1", remote.mutations.Load())
	}
	var originalClaimID uuid.UUID
	var state, providerRequestID string
	if err := pool.QueryRow(t.Context(), `SELECT claim_id,state,provider_request_id
		FROM dns_reconcile_provider_mutation_claims
		WHERE tenant_id=$1 AND client_request_id=$2`, tenant.tenantID, mutation.ClientRequestID).
		Scan(&originalClaimID, &state, &providerRequestID); err != nil {
		t.Fatal(err)
	}
	if state != "claimed" || providerRequestID != dnsproviderremote.ProviderMutationRequestID(mutation.ClientRequestID) {
		t.Fatalf("claim state=%s provider_request_id=%s", state, providerRequestID)
	}
	lookups := remote.lookups.Load()
	_, err = adapter.Mutate(t.Context(), mutation)
	assertSourceRecoveryError(t, err, "provider_recovery_pending")
	if remote.mutations.Load() != 1 || remote.lookups.Load() != lookups {
		t.Fatalf("active-lease retry used provider: mutations=%d lookups=%d/%d",
			remote.mutations.Load(), remote.lookups.Load(), lookups)
	}

	connection, err := pool.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(t.Context(), `SET session_replication_role=replica`); err != nil {
		connection.Release()
		t.Fatal(err)
	}
	_, updateErr := connection.Exec(t.Context(), `UPDATE dns_reconcile_provider_mutation_claims
		SET lease_expires_at=clock_timestamp()-interval '1 microsecond'
		WHERE tenant_id=$1 AND client_request_id=$2`, tenant.tenantID, mutation.ClientRequestID)
	_, resetErr := connection.Exec(t.Context(), `SET session_replication_role=origin`)
	connection.Release()
	if updateErr != nil || resetErr != nil {
		t.Fatalf("advance test lease=(%v,%v)", updateErr, resetErr)
	}

	restarted, err := dnsproviderremote.NewReconcileAdapter(New(pool, cipher), remote)
	if err != nil {
		t.Fatal(err)
	}
	_, err = restarted.Mutate(t.Context(), mutation)
	assertSourceRecoveryError(t, err, "provider_recovery_pending")
	var recoveredClaimID uuid.UUID
	var uncertainState, recoveryPending bool
	if err := pool.QueryRow(t.Context(), `SELECT claim_id,state='uncertain',
		recovery_not_before>clock_timestamp()
		FROM dns_reconcile_provider_mutation_claims
		WHERE tenant_id=$1 AND client_request_id=$2`, tenant.tenantID, mutation.ClientRequestID).
		Scan(&recoveredClaimID, &uncertainState, &recoveryPending); err != nil {
		t.Fatal(err)
	}
	if recoveredClaimID != originalClaimID || !uncertainState || !recoveryPending || remote.mutations.Load() != 1 ||
		remote.lookups.Load() != lookups {
		t.Fatalf("restart claim=%s/%s pending=%t mutations=%d lookups=%d/%d",
			recoveredClaimID, originalClaimID, recoveryPending, remote.mutations.Load(), remote.lookups.Load(), lookups)
	}
}

func TestReconcileClaimAuthorityPersistenceRollbackStaysRecoverableAcrossRestart(t *testing.T) {
	for _, test := range []struct {
		name          string
		failValidate  bool
		failFinalize  bool
		wantMutations int32
		wantTerminal  bool
	}{
		{name: "validate", failValidate: true},
		{name: "finalize", failFinalize: true, wantMutations: 1, wantTerminal: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			pool := openSourcePG17(t)
			if err := database.Migrate(t.Context(), pool, "up"); err != nil {
				t.Fatal(err)
			}
			tenant := seedSourceTenant(t, pool, "reconcile-claim-persistence-"+test.name)
			cipher := mustSourceCipher(t, "reconcile-claim-persistence-"+test.name+"-key", 47)
			providerID := insertSourceProvider(t, pool, tenant, "cloudflare", "verified", cipher,
				`{"api_token":"sensitive-reconcile-token"}`)
			zoneID := insertSourceZone(t, pool, tenant, providerID, "example.test")
			siteID := insertSourceReconcileSite(t, pool, tenant, test.name+"-persistence.example.test")
			mutation := dnscheck.ProviderMutation{
				ClientRequestID: "reconcile-claim-persistence-" + test.name, TenantID: tenant.tenantID,
				SiteID: siteID, ZoneID: zoneID, ExpectedRevision: 1,
				Operation: dnscheck.ProviderOperation{
					Sequence: 1, Action: dnscheck.ProviderCreate, Name: "www.example.test.", Type: dnscheck.RecordA,
					Value: "192.0.2.10", TTL: 300, Reason: "missing_record",
				},
			}
			insertSourceReconcileOperation(t, pool, tenant, siteID, zoneID, mutation)
			source := New(pool, cipher)
			authority := &claimPersistenceRollbackSource{Source: source}
			authority.failValidate.Store(test.failValidate)
			authority.failFinalize.Store(test.failFinalize)
			remote := &claimPersistenceSourceRemote{}
			adapter, err := dnsproviderremote.NewReconcileAdapter(authority, remote)
			if err != nil {
				t.Fatal(err)
			}
			providerRequestID := dnsproviderremote.ProviderMutationRequestID(mutation.ClientRequestID)
			_, err = adapter.Mutate(t.Context(), mutation)
			assertSourceRecoveryErrorID(t, err, "provider_recovery_persistence_failed", providerRequestID)
			if remote.mutations.Load() != test.wantMutations {
				t.Fatalf("provider mutations=%d, want %d", remote.mutations.Load(), test.wantMutations)
			}
			var state, storedRequestID string
			if err := pool.QueryRow(t.Context(), `SELECT state,provider_request_id
				FROM dns_reconcile_provider_mutation_claims
				WHERE tenant_id=$1 AND client_request_id=$2`, tenant.tenantID, mutation.ClientRequestID).
				Scan(&state, &storedRequestID); err != nil {
				t.Fatal(err)
			}
			if state != "claimed" || storedRequestID != providerRequestID {
				t.Fatalf("claim state=%s provider_request_id=%s", state, storedRequestID)
			}
			lookups := remote.lookups.Load()
			_, err = adapter.Mutate(t.Context(), mutation)
			assertSourceRecoveryErrorID(t, err, "provider_recovery_pending", providerRequestID)
			if remote.mutations.Load() != test.wantMutations || remote.lookups.Load() != lookups {
				t.Fatalf("active retry used provider: mutations=%d lookups=%d/%d",
					remote.mutations.Load(), remote.lookups.Load(), lookups)
			}

			forceSourceClaimRecoveryTime(t, pool, tenant.tenantID, mutation.ClientRequestID, false)
			restarted, err := dnsproviderremote.NewReconcileAdapter(New(pool, cipher), remote)
			if err != nil {
				t.Fatal(err)
			}
			_, err = restarted.Mutate(t.Context(), mutation)
			assertSourceRecoveryErrorID(t, err, "provider_recovery_pending", providerRequestID)
			if remote.mutations.Load() != test.wantMutations || remote.lookups.Load() != lookups {
				t.Fatalf("restart before recovery window used provider: mutations=%d lookups=%d/%d",
					remote.mutations.Load(), remote.lookups.Load(), lookups)
			}

			forceSourceClaimRecoveryTime(t, pool, tenant.tenantID, mutation.ClientRequestID, true)
			result, recoveryErr := restarted.Mutate(t.Context(), mutation)
			if test.wantTerminal {
				if recoveryErr != nil || result.ProviderRequestID != providerRequestID || result.Revision != 2 {
					t.Fatalf("terminal recovery=(%+v,%v)", result, recoveryErr)
				}
				state = ""
				if err := pool.QueryRow(t.Context(), `SELECT state FROM dns_reconcile_provider_mutation_claims
					WHERE tenant_id=$1 AND client_request_id=$2`, tenant.tenantID, mutation.ClientRequestID).
					Scan(&state); err != nil {
					t.Fatal(err)
				}
				if state != "succeeded" {
					t.Fatalf("terminal claim state=%s", state)
				}
			} else {
				assertSourceRecoveryErrorID(t, recoveryErr, "provider_recovery_pending", providerRequestID)
				state = ""
				if err := pool.QueryRow(t.Context(), `SELECT state FROM dns_reconcile_provider_mutation_claims
					WHERE tenant_id=$1 AND client_request_id=$2`, tenant.tenantID, mutation.ClientRequestID).
					Scan(&state); err != nil {
					t.Fatal(err)
				}
				if state != "not_applied" || remote.lookups.Load() != lookups+2 {
					t.Fatalf("validate recovery state=%s lookups=%d, want terminal not_applied after %d",
						state, remote.lookups.Load(), lookups+2)
				}
			}
			if remote.mutations.Load() != test.wantMutations {
				t.Fatalf("recovery provider mutations=%d, want %d", remote.mutations.Load(), test.wantMutations)
			}
		})
	}
}

func TestReconcileUncertainVisibilityWindowBlocksImmediateReplay(t *testing.T) {
	pool := openSourcePG17(t)
	if err := database.Migrate(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	tenant := seedSourceTenant(t, pool, "reconcile-visibility-window")
	cipher := mustSourceCipher(t, "reconcile-visibility-window-key", 44)
	providerID := insertSourceProvider(t, pool, tenant, "cloudflare", "verified", cipher,
		`{"api_token":"sensitive-reconcile-token"}`)
	zoneID := insertSourceZone(t, pool, tenant, providerID, "example.test")
	siteID := insertSourceReconcileSite(t, pool, tenant, "visibility.example.test")
	mutation := dnscheck.ProviderMutation{
		ClientRequestID: "reconcile-visibility-window-operation", TenantID: tenant.tenantID,
		SiteID: siteID, ZoneID: zoneID, ExpectedRevision: 1,
		Operation: dnscheck.ProviderOperation{
			Sequence: 1, Action: dnscheck.ProviderCreate, Name: "www.example.test.", Type: dnscheck.RecordA,
			Value: "192.0.2.10", TTL: 300, Reason: "missing_record",
		},
	}
	insertSourceReconcileOperation(t, pool, tenant, siteID, zoneID, mutation)
	remote := &responseLossSourceRemote{}
	resolver, err := NewReconcileResolver(New(pool, cipher), remote)
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := resolver.ResolveProvider(t.Context(), tenant.tenantID, siteID, zoneID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Mutate(t.Context(), mutation); err == nil {
		t.Fatal("response-loss mutation succeeded")
	}
	lookups, mutations := remote.lookups.Load(), remote.mutations.Load()
	var state string
	var durableWindow bool
	if err := pool.QueryRow(t.Context(), `SELECT state,recovery_not_before>statement_timestamp()
		FROM dns_reconcile_provider_mutation_claims
		WHERE tenant_id=$1 AND client_request_id=$2`, tenant.tenantID, mutation.ClientRequestID).
		Scan(&state, &durableWindow); err != nil {
		t.Fatal(err)
	}
	if state != "uncertain" || !durableWindow {
		t.Fatalf("claim state=%s durable_window=%t", state, durableWindow)
	}
	if _, err := adapter.Mutate(t.Context(), mutation); err == nil ||
		remote.lookups.Load() != lookups || remote.mutations.Load() != mutations {
		t.Fatalf("immediate replay error=%v lookups=%d/%d mutations=%d/%d", err,
			remote.lookups.Load(), lookups, remote.mutations.Load(), mutations)
	}
}

func TestReconcileUncertainCannotFinalizeNotAppliedBeforeServerWindow(t *testing.T) {
	pool := openSourcePG17(t)
	if err := database.Migrate(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	tenant := seedSourceTenant(t, pool, "reconcile-early-not-applied")
	cipher := mustSourceCipher(t, "reconcile-early-not-applied-key", 45)
	providerID := insertSourceProvider(t, pool, tenant, "cloudflare", "verified", cipher,
		`{"api_token":"sensitive-reconcile-token"}`)
	zoneID := insertSourceZone(t, pool, tenant, providerID, "example.test")
	siteID := insertSourceReconcileSite(t, pool, tenant, "early-not-applied.example.test")
	mutation := dnscheck.ProviderMutation{
		ClientRequestID: "reconcile-early-not-applied-operation", TenantID: tenant.tenantID,
		SiteID: siteID, ZoneID: zoneID, ExpectedRevision: 1,
		Operation: dnscheck.ProviderOperation{
			Sequence: 1, Action: dnscheck.ProviderCreate, Name: "www.example.test.", Type: dnscheck.RecordA,
			Value: "192.0.2.10", TTL: 300, Reason: "missing_record",
		},
	}
	insertSourceReconcileOperation(t, pool, tenant, siteID, zoneID, mutation)
	source := New(pool, cipher)
	claim, err := source.AcquireMutationClaim(t.Context(), mutation)
	if err != nil {
		t.Fatal(err)
	}
	if err := source.MarkMutationUncertain(t.Context(), mutation, claim, claim.ProviderRequestID); err != nil {
		t.Fatal(err)
	}
	recoveryClaim, err := source.AcquireMutationClaim(t.Context(), mutation)
	if err != nil {
		t.Fatal(err)
	}
	if recoveryClaim.State != dnsproviderremote.MutationUncertain || recoveryClaim.RecoveryReady {
		t.Fatalf("recovery claim state=%s ready=%t", recoveryClaim.State, recoveryClaim.RecoveryReady)
	}
	if _, err := source.FinalizeMutationClaim(t.Context(), mutation, recoveryClaim,
		dnsproviderremote.MutationNotApplied, recoveryClaim.ProviderRequestID, ""); !errors.Is(err, dnscheck.ErrProviderRevisionConflict) {
		t.Fatalf("early not-applied finalize error=%v", err)
	}
	var state string
	var recoveryPending bool
	if err := pool.QueryRow(t.Context(), `SELECT state,recovery_not_before>statement_timestamp()
		FROM dns_reconcile_provider_mutation_claims
		WHERE tenant_id=$1 AND client_request_id=$2`, tenant.tenantID, mutation.ClientRequestID).
		Scan(&state, &recoveryPending); err != nil {
		t.Fatal(err)
	}
	if state != "uncertain" || !recoveryPending {
		t.Fatalf("claim state=%s recovery_pending=%t", state, recoveryPending)
	}
}

func TestReconcileMutationLeaseFencesSecondWorkerAcrossBoundedProviderIO(t *testing.T) {
	pool := openSourcePG17(t)
	if err := database.Migrate(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	tenant := seedSourceTenant(t, pool, "reconcile-lease-fence")
	cipher := mustSourceCipher(t, "reconcile-lease-fence-key", 43)
	providerID := insertSourceProvider(t, pool, tenant, "cloudflare", "verified", cipher,
		`{"api_token":"sensitive-reconcile-token"}`)
	zoneID := insertSourceZone(t, pool, tenant, providerID, "example.test")
	siteID := insertSourceReconcileSite(t, pool, tenant, "lease.example.test")
	mutation := dnscheck.ProviderMutation{
		ClientRequestID: "reconcile-lease-fence-operation", TenantID: tenant.tenantID,
		SiteID: siteID, ZoneID: zoneID, ExpectedRevision: 1,
		Operation: dnscheck.ProviderOperation{
			Sequence: 1, Action: dnscheck.ProviderCreate, Name: "www.example.test.", Type: dnscheck.RecordA,
			Value: "192.0.2.10", TTL: 300, Reason: "missing_record",
		},
	}
	insertSourceReconcileOperation(t, pool, tenant, siteID, zoneID, mutation)
	remote := &leaseFenceSourceRemote{mutationStarted: make(chan struct{}, 1), release: make(chan struct{})}
	resolver, err := NewReconcileResolver(New(pool, cipher), remote)
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := resolver.ResolveProvider(t.Context(), tenant.tenantID, siteID, zoneID)
	if err != nil {
		t.Fatal(err)
	}
	first := make(chan error, 1)
	go func() {
		_, mutateErr := adapter.Mutate(context.Background(), mutation)
		first <- mutateErr
	}()
	<-remote.mutationStarted
	// The lease is extended to the bounded I/O budget inside the credential-fence
	// transaction that stays open across provider I/O (reconcile.go
	// AcquireMutationCredentialLease), so other sessions still read the claimed lease.
	// That transaction holds the claim row: nobody can expire or take over the claim
	// until the provider call finished, whatever lease value is committed.
	takeover, err := pool.Begin(t.Context())
	if err != nil {
		close(remote.release)
		t.Fatal(err)
	}
	if _, err := takeover.Exec(t.Context(), `SET LOCAL lock_timeout='200ms'`); err != nil {
		close(remote.release)
		t.Fatal(err)
	}
	_, takeoverErr := takeover.Exec(t.Context(), `UPDATE dns_reconcile_provider_mutation_claims
		SET lease_expires_at=statement_timestamp() WHERE tenant_id=$1 AND client_request_id=$2`,
		tenant.tenantID, mutation.ClientRequestID)
	_ = takeover.Rollback(context.WithoutCancel(t.Context()))
	var lockErr *pgconn.PgError
	if !errors.As(takeoverErr, &lockErr) || lockErr.Code != "55P03" {
		close(remote.release)
		t.Fatalf("claim row was not held across provider I/O: %v", takeoverErr)
	}
	// The second worker must back off at once instead of waiting on the claim row for the
	// whole provider call (up to MutationClaimLeaseMinimum).
	secondCtx, cancelSecond := context.WithTimeout(t.Context(), 10*time.Second)
	_, secondErr := adapter.Mutate(secondCtx, mutation)
	cancelSecond()
	if secondErr == nil {
		close(remote.release)
		t.Fatal("second worker unexpectedly acquired the active provider claim")
	}
	var pending *dnscheck.ProviderError
	if !errors.As(secondErr, &pending) || pending.Code != "provider_recovery_pending" {
		close(remote.release)
		t.Fatalf("second worker error = %v, want immediate provider_recovery_pending", secondErr)
	}
	assertSourceRecoveryErrorID(t, secondErr, "provider_recovery_pending",
		dnsproviderremote.ProviderMutationRequestID(mutation.ClientRequestID))
	if remote.mutations.Load() != 1 {
		close(remote.release)
		t.Fatalf("provider mutations=%d before release", remote.mutations.Load())
	}
	close(remote.release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
}

type claimBoundaryRemote struct {
	started chan struct{}
	release chan struct{}
	lookups atomic.Int32
}

func (remote *claimBoundaryRemote) Lookup(ctx context.Context, _ dnsproviderremote.ProviderConfig,
	_ dnscheck.ProviderOperation) (dnsproviderremote.ReconcileLookup, error) {
	switch remote.lookups.Add(1) {
	case 1:
		remote.started <- struct{}{}
		select {
		case <-remote.release:
		case <-ctx.Done():
			return dnsproviderremote.ReconcileLookup{}, ctx.Err()
		}
		return dnsproviderremote.ReconcileLookup{}, nil
	case 2:
		return dnsproviderremote.ReconcileLookup{}, nil
	default:
		return dnsproviderremote.ReconcileLookup{TargetComplete: true, RecordID: "record-1"}, nil
	}
}

func (*claimBoundaryRemote) Mutate(context.Context, dnsproviderremote.ProviderConfig,
	dnscheck.ProviderOperation) (string, error) {
	return "record-1", nil
}

type responseLossSourceRemote struct {
	lookups   atomic.Int32
	mutations atomic.Int32
}

type uncertainPersistenceFailureSource struct {
	*Source
	fail atomic.Bool
}

type claimPersistenceRollbackSource struct {
	*Source
	failValidate atomic.Bool
	failFinalize atomic.Bool
}

func (source *claimPersistenceRollbackSource) ValidateMutationClaim(_ context.Context,
	mutation dnscheck.ProviderMutation, claim dnsproviderremote.MutationClaim) error {
	if source.failValidate.CompareAndSwap(true, false) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		return source.Source.ValidateMutationClaim(ctx, mutation, claim)
	}
	return source.Source.ValidateMutationClaim(context.Background(), mutation, claim)
}

// The adapter validates the claim through the credential lease when the authority offers
// one (dnsproviderremote ReconcileAdapter.acquireMutationCredentialLease), so the injected
// validation failure has to reach that path too.
func (source *claimPersistenceRollbackSource) AcquireMutationCredentialLease(_ context.Context,
	mutation dnscheck.ProviderMutation, claim dnsproviderremote.MutationClaim,
) (dnsproviderremote.MutationCredentialLease, error) {
	if source.failValidate.CompareAndSwap(true, false) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		return source.Source.AcquireMutationCredentialLease(ctx, mutation, claim)
	}
	return source.Source.AcquireMutationCredentialLease(context.Background(), mutation, claim)
}

func (source *claimPersistenceRollbackSource) FinalizeMutationClaim(_ context.Context,
	mutation dnscheck.ProviderMutation, claim dnsproviderremote.MutationClaim,
	outcome dnsproviderremote.MutationClaimState, providerRequestID, providerRecordID string,
) (int64, error) {
	if source.failFinalize.CompareAndSwap(true, false) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		return source.Source.FinalizeMutationClaim(
			ctx, mutation, claim, outcome, providerRequestID, providerRecordID,
		)
	}
	return source.Source.FinalizeMutationClaim(
		context.Background(), mutation, claim, outcome, providerRequestID, providerRecordID,
	)
}

type claimPersistenceSourceRemote struct {
	lookups   atomic.Int32
	mutations atomic.Int32
	applied   atomic.Bool
}

func (remote *claimPersistenceSourceRemote) Lookup(context.Context, dnsproviderremote.ProviderConfig,
	dnscheck.ProviderOperation) (dnsproviderremote.ReconcileLookup, error) {
	remote.lookups.Add(1)
	if remote.applied.Load() {
		return dnsproviderremote.ReconcileLookup{TargetComplete: true, RecordID: "record-1"}, nil
	}
	return dnsproviderremote.ReconcileLookup{}, nil
}

func (remote *claimPersistenceSourceRemote) Mutate(context.Context, dnsproviderremote.ProviderConfig,
	dnscheck.ProviderOperation) (string, error) {
	remote.mutations.Add(1)
	remote.applied.Store(true)
	return "record-1", nil
}

func (source *uncertainPersistenceFailureSource) MarkMutationUncertain(ctx context.Context,
	mutation dnscheck.ProviderMutation, claim dnsproviderremote.MutationClaim, providerRequestID string) error {
	if source.fail.CompareAndSwap(true, false) {
		return errors.New("injected uncertain persistence failure")
	}
	return source.Source.MarkMutationUncertain(ctx, mutation, claim, providerRequestID)
}

func assertSourceRecoveryError(t *testing.T, err error, code string) {
	t.Helper()
	var providerErr *dnscheck.ProviderError
	if !errors.As(err, &providerErr) || providerErr.Class != dnscheck.ProviderErrorTransient ||
		providerErr.Code != code || providerErr.ProviderRequestID == "" {
		t.Fatalf("provider recovery error=%v, want transient %s", err, code)
	}
}

func assertSourceRecoveryErrorID(t *testing.T, err error, code, providerRequestID string) {
	t.Helper()
	assertSourceRecoveryError(t, err, code)
	var providerErr *dnscheck.ProviderError
	if !errors.As(err, &providerErr) || providerErr.ProviderRequestID != providerRequestID {
		t.Fatalf("provider recovery request id=%q, want %q", providerErr.ProviderRequestID, providerRequestID)
	}
}

func forceSourceClaimRecoveryTime(t *testing.T, pool *pgxpool.Pool,
	tenantID uuid.UUID, clientRequestID string, ready bool,
) {
	t.Helper()
	connection, err := pool.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Release()
	if _, err := connection.Exec(t.Context(), `SET session_replication_role=replica`); err != nil {
		t.Fatal(err)
	}
	query := `UPDATE dns_reconcile_provider_mutation_claims
		SET lease_expires_at=GREATEST(claimed_at,clock_timestamp()-interval '1 microsecond')
		WHERE tenant_id=$1 AND client_request_id=$2`
	if ready {
		query = `UPDATE dns_reconcile_provider_mutation_claims
			SET lease_expires_at=GREATEST(claimed_at,clock_timestamp()-interval '1 microsecond'),
			    recovery_not_before=clock_timestamp()-interval '1 microsecond'
			WHERE tenant_id=$1 AND client_request_id=$2 AND state='uncertain'`
	}
	command, updateErr := connection.Exec(t.Context(), query, tenantID, clientRequestID)
	_, resetErr := connection.Exec(t.Context(), `SET session_replication_role=origin`)
	if updateErr != nil || resetErr != nil || command.RowsAffected() != 1 {
		t.Fatalf("force recovery time rows=%d errors=(%v,%v)", command.RowsAffected(), updateErr, resetErr)
	}
}

type leaseFenceSourceRemote struct {
	lookups         atomic.Int32
	mutations       atomic.Int32
	mutationStarted chan struct{}
	release         chan struct{}
}

func (remote *leaseFenceSourceRemote) Lookup(context.Context, dnsproviderremote.ProviderConfig,
	dnscheck.ProviderOperation) (dnsproviderremote.ReconcileLookup, error) {
	if remote.lookups.Add(1) >= 3 {
		return dnsproviderremote.ReconcileLookup{TargetComplete: true, RecordID: "record-1"}, nil
	}
	return dnsproviderremote.ReconcileLookup{}, nil
}

func (remote *leaseFenceSourceRemote) Mutate(ctx context.Context, _ dnsproviderremote.ProviderConfig,
	_ dnscheck.ProviderOperation) (string, error) {
	remote.mutations.Add(1)
	remote.mutationStarted <- struct{}{}
	select {
	case <-remote.release:
		return "record-1", nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func (remote *responseLossSourceRemote) Lookup(context.Context, dnsproviderremote.ProviderConfig,
	dnscheck.ProviderOperation) (dnsproviderremote.ReconcileLookup, error) {
	if remote.mutations.Load() > 0 {
		return dnsproviderremote.ReconcileLookup{TargetComplete: true, RecordID: "record-1"}, nil
	}
	remote.lookups.Add(1)
	return dnsproviderremote.ReconcileLookup{}, nil
}

func (remote *responseLossSourceRemote) Mutate(context.Context, dnsproviderremote.ProviderConfig,
	dnscheck.ProviderOperation) (string, error) {
	remote.mutations.Add(1)
	return "", &dnsproviderremote.Error{Code: dnsproviderremote.CodeTimeout, Temporary: true}
}

type blockingSourceReconcileRemote struct {
	started   chan struct{}
	release   chan struct{}
	lookups   atomic.Int32
	mutations atomic.Int32
}

func (remote *blockingSourceReconcileRemote) Lookup(ctx context.Context, config dnsproviderremote.ProviderConfig,
	_ dnscheck.ProviderOperation) (dnsproviderremote.ReconcileLookup, error) {
	if remote.lookups.Add(1) == 1 {
		remote.started <- struct{}{}
		select {
		case <-remote.release:
		case <-ctx.Done():
			return dnsproviderremote.ReconcileLookup{}, ctx.Err()
		}
	}
	if config.Credentials["api_token"] != "sensitive-reconcile-token" {
		return dnsproviderremote.ReconcileLookup{}, errors.New("credentials unavailable")
	}
	if remote.mutations.Load() == 0 {
		return dnsproviderremote.ReconcileLookup{}, nil
	}
	return dnsproviderremote.ReconcileLookup{TargetComplete: true, RecordID: "record-1"}, nil
}

func (remote *blockingSourceReconcileRemote) Mutate(context.Context, dnsproviderremote.ProviderConfig,
	dnscheck.ProviderOperation) (string, error) {
	remote.mutations.Add(1)
	return "record-1", nil
}

type sourceVerifier struct {
	calls        atomic.Int32
	providerType string
	apiID        string
	apiSecret    string
}

func (v *sourceVerifier) Verify(context.Context, string, string) error {
	v.calls.Add(1)
	return errors.New("legacy verifier path used")
}

func (v *sourceVerifier) VerifyCredentials(_ context.Context, providerType string, credentials map[string]string) error {
	v.calls.Add(1)
	v.providerType = providerType
	v.apiID = credentials["api_id"]
	v.apiSecret = credentials["api_secret"]
	return nil
}

type sourceKeyring struct {
	primary *dnsacme.AESGCMCredentialCipher
	byID    map[string]*dnsacme.AESGCMCredentialCipher
}

func (k *sourceKeyring) Encrypt(plaintext []byte) (string, []byte, error) {
	return k.primary.Encrypt(plaintext)
}

func (k *sourceKeyring) Decrypt(keyID string, ciphertext []byte) ([]byte, error) {
	cipher, exists := k.byID[keyID]
	if !exists {
		return nil, dnsacme.ErrCredentialUnavailable
	}
	return cipher.Decrypt(keyID, ciphertext)
}

func (k *sourceKeyring) IdempotencyDigest(plaintext []byte) [32]byte {
	return sha256.Sum256(plaintext)
}

// The source only decrypts credentials bound to tenant/scope/provider
// (dnsacme.BoundCredentialCipher, source.go Resolve); the keyring routes by key ID.
func (k *sourceKeyring) EncryptCredential(binding dnsacme.CredentialBinding, plaintext []byte) (string, []byte, error) {
	return k.primary.EncryptCredential(binding, plaintext)
}

func (k *sourceKeyring) DecryptCredential(binding dnsacme.CredentialBinding, keyID string, ciphertext []byte) ([]byte, error) {
	cipher, exists := k.byID[keyID]
	if !exists {
		return nil, dnsacme.ErrCredentialUnavailable
	}
	return cipher.DecryptCredential(binding, keyID, ciphertext)
}

func (k *sourceKeyring) RewrapCredential(binding dnsacme.CredentialBinding, keyID string, ciphertext []byte) (string, []byte, error) {
	cipher, exists := k.byID[keyID]
	if !exists {
		return "", nil, dnsacme.ErrCredentialUnavailable
	}
	return cipher.RewrapCredential(binding, keyID, ciphertext)
}

type sourceTenant struct {
	tenantID uuid.UUID
	scopeID  uuid.UUID
	userID   uuid.UUID
}

func seedSourceTenant(t *testing.T, pool *pgxpool.Pool, name string) sourceTenant {
	t.Helper()
	fixture := sourceTenant{tenantID: uuid.New(), scopeID: uuid.New(), userID: uuid.New()}
	username := strings.ReplaceAll(name+"-"+fixture.userID.String(), "-", "")[:24]
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO tenants(id,display_name) VALUES($1,$2)`, []any{fixture.tenantID, name}},
		{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, []any{fixture.scopeID, fixture.tenantID}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,$3,'test-hash')`, []any{fixture.userID, username, name}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{fixture.scopeID, fixture.userID}},
	}
	for _, statement := range statements {
		if _, err := pool.Exec(t.Context(), statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	return fixture
}

func insertSourceReconcileSite(t *testing.T, pool *pgxpool.Pool, tenant sourceTenant, domain string) uuid.UUID {
	t.Helper()
	siteID := uuid.New()
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `INSERT INTO sites(
			id,scope_id,owner_user_id,domain,origins,origin_hosts,created_by_user_id,updated_by_user_id,display_id
		) VALUES($1,$2,$3,$4,ARRAY['origin.example.test:80'],ARRAY['origin.example.test'],$3,$3,
			(SELECT COALESCE(max(display_id),0)+1 FROM sites WHERE scope_id=$2))`,
			siteID, tenant.scopeID, tenant.userID, domain); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO site_origin_pools(site_id) VALUES($1)`, siteID); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO site_origins(site_id,position,host,port)
			VALUES($1,1,'origin.example.test',80)`, siteID)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return siteID
}

func insertSourceReconcileOperation(t *testing.T, pool *pgxpool.Pool, tenant sourceTenant,
	siteID, zoneID uuid.UUID, mutation dnscheck.ProviderMutation,
) {
	t.Helper()
	jobID := uuid.New()
	now := time.Now().UTC().Truncate(time.Microsecond)
	digest := sha256.Sum256([]byte(mutation.ClientRequestID))
	operation, err := json.Marshal(mutation.Operation)
	if err != nil {
		t.Fatal(err)
	}
	phase := "apply"
	if mutation.Operation.Action == dnscheck.ProviderDelete {
		phase = "commit"
	}
	err = pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `INSERT INTO background_jobs(
			id,tenant_id,kind,subject,idempotency_key,request_digest,request_id,trace_id,
			state,attempt,max_attempts,claimable_at,total_count,created_at,updated_at
		) VALUES($1,$2,'dns_reconcile','dns_reconcile/site',$3,$4,$3,'','queued',0,20,$5,1,$5,$5)`,
			jobID, tenant.tenantID, "job-"+mutation.ClientRequestID, digest[:], now); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO background_job_items(
			tenant_id,job_id,ordinal,item_id,state) VALUES($1,$2,1,'reconcile','pending')`,
			tenant.tenantID, jobID); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO dns_reconcile_tasks(
			tenant_id,tenant_scope_id,job_id,site_id,zone_id,idempotency_key,job_idempotency_key,
			payload_digest,job_request_digest,canonical_request,plan_digest,deterministic_plan,
			initial_provider_revision,required_consecutive,created_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$8,'{}'::jsonb,$8,'{}'::jsonb,$9,3,$10)`,
			tenant.tenantID, tenant.scopeID, jobID, siteID, zoneID, mutation.ClientRequestID,
			"job-"+mutation.ClientRequestID, digest[:], mutation.ExpectedRevision, now); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO dns_reconcile_operations(
			tenant_id,job_id,phase,ordinal,source_sequence,action,client_request_id,operation,created_at
		) VALUES($1,$2,$3,1,1,$4,$5,$6,$7)`, tenant.tenantID, jobID, phase,
			mutation.Operation.Action, mutation.ClientRequestID, operation, now)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func assertSourcePGCode(t *testing.T, err error, want string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != want {
		t.Fatalf("PostgreSQL error=%v, want SQLSTATE %s", err, want)
	}
}

func insertSourceProvider(
	t *testing.T,
	pool *pgxpool.Pool,
	tenant sourceTenant,
	providerType, status string,
	cipher *dnsacme.AESGCMCredentialCipher,
	raw string,
) uuid.UUID {
	t.Helper()
	id := uuid.New()
	keyID, ciphertext := sealSourceCredentials(t, cipher, tenant, id, raw)
	if _, err := pool.Exec(t.Context(), `INSERT INTO dns_providers(
		id,scope_id,name,provider_type,credential_key_id,credential_ciphertext,status,
		created_by_user_id,updated_by_user_id
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$8)`, id, tenant.scopeID,
		providerType+"-"+id.String()[:8], providerType, keyID, ciphertext, status, tenant.userID); err != nil {
		t.Fatal(err)
	}
	return id
}

func insertSourceZone(t *testing.T, pool *pgxpool.Pool, tenant sourceTenant, providerID uuid.UUID, name string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	// Since migration 473 a zone saved through the API carries the hosted
	// domain the provider's domain list reported (dnsacme.Service.CreateZone);
	// these zones are hosted domains themselves. The legacy NULL lazy fill is
	// covered by dnsacme TestEnsureZoneApexFillsLegacyZoneOnce and httpapi
	// TestDNSZoneSaveStoresProviderApex. Tests pinned to an older schema
	// (applySourceMigrationsThrough) have no such column.
	var hasApex bool
	if err := pool.QueryRow(t.Context(), `SELECT EXISTS (SELECT 1 FROM information_schema.columns
		WHERE table_schema=current_schema() AND table_name='dns_zones' AND column_name='provider_zone_apex')`).Scan(&hasApex); err != nil {
		t.Fatal(err)
	}
	insert := `INSERT INTO dns_zones(id,scope_id,provider_id,name,created_by_user_id,updated_by_user_id)
		VALUES($1,$2,$3,$4,$5,$5)`
	if hasApex {
		insert = `INSERT INTO dns_zones(id,scope_id,provider_id,name,created_by_user_id,updated_by_user_id,provider_zone_apex)
		VALUES($1,$2,$3,$4,$5,$5,$4)`
	}
	if _, err := pool.Exec(t.Context(), insert, id, tenant.scopeID, providerID, name, tenant.userID); err != nil {
		t.Fatal(err)
	}
	return id
}

func seedSourceACMERequestFacts(
	t *testing.T,
	pool *pgxpool.Pool,
	tenant sourceTenant,
	request acmeworker.IssueRequest,
) {
	t.Helper()
	for _, key := range []struct {
		ref     string
		purpose string
	}{
		{ref: request.AccountKeyRef, purpose: "account"},
		{ref: request.CertificateKeyRef, purpose: "certificate"},
	} {
		// Public keys are unique per tenant; derive one per key ref so a tenant can hold
		// several issuance operations.
		publicKeyDigest := sha256.Sum256([]byte(key.ref))
		if _, err := pool.Exec(t.Context(), `INSERT INTO acme_tenant_key_facts(
			tenant_scope_id,id,key_ref,purpose,algorithm,public_key_spki_sha256,
			external_key_reference,created_by_user_id
		) VALUES($1,$2,$3,$4,'ecdsa',$5,$6,$7)`, tenant.scopeID, uuid.New(), key.ref,
			key.purpose, publicKeyDigest[:], "kms://source/"+key.ref, tenant.userID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO certificate_orders(
		id,scope_id,dns_provider_id,domains,challenge_type,auto_renew,
		created_by_user_id,updated_by_user_id
	) VALUES($1,$2,$3,$4,$5,true,$6,$6)`, request.CertificateOrderID, tenant.scopeID,
		request.ProviderID, request.Domains, request.ChallengeType, tenant.userID); err != nil {
		t.Fatal(err)
	}
}

func advanceSourceToAuthorizing(
	t *testing.T,
	pool *pgxpool.Pool,
	store acmeworker.OperationStore,
	lease acmeworker.OperationLease,
	now time.Time,
	authorizationURLs []string,
) acmeworker.OperationLease {
	t.Helper()
	var accountKeyID uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT id FROM acme_tenant_key_facts
		WHERE tenant_scope_id=$1 AND key_ref=$2`, lease.ScopeID, lease.Request.AccountKeyRef).Scan(&accountKeyID); err != nil {
		t.Fatal(err)
	}
	accountURI := "https://ca.example/account/1"
	if _, err := pool.Exec(t.Context(), `INSERT INTO acme_account_registration_facts(
		tenant_scope_id,id,account_key_id,directory_url,account_uri,contacts,
		terms_agreed_at,registered_at,created_by_user_id
	) VALUES($1,$2,$3,$4,$5,$6,statement_timestamp()-interval '1 second',statement_timestamp(),$7)`,
		lease.ScopeID, uuid.New(), accountKeyID, lease.Request.DirectoryURL, accountURI,
		lease.Request.Contacts, lease.Request.ActorUserID); err != nil {
		t.Fatal(err)
	}
	advance := func(event string, next acmeworker.OperationState) {
		var err error
		lease, err = store.Advance(t.Context(), lease, event, next, now)
		if err != nil {
			t.Fatalf("Advance(%s): %v", event, err)
		}
	}
	next := lease.State
	next.AccountURI = accountURI
	advance("account_registered", next)
	next = lease.State
	next.OrderIntentPending = true
	advance("order_intent", next)
	next = lease.State
	next.Phase = acmeworker.PhaseOrdered
	next.OrderIntentPending = false
	next.OrderURL = "https://ca.example/order/1"
	next.FinalizeURL = "https://ca.example/finalize/1"
	next.AuthorizationURLs = append([]string(nil), authorizationURLs...)
	advance("order_created", next)
	next = lease.State
	next.Phase = acmeworker.PhaseAuthorizing
	advance("authorizing", next)
	return lease
}

func sourceIssueRequestDigest(request acmeworker.IssueRequest) string {
	hash := sha256.New()
	for _, value := range []string{
		request.TenantID.String(), request.ScopeID.String(), request.OperationID, request.CertificateOrderID.String(),
		request.ActorUserID.String(), request.DirectoryURL, request.ProviderID.String(), request.ZoneID.String(), request.ProviderRef,
		request.AccountKeyRef, request.CertificateKeyRef, string(request.ChallengeType),
		strings.Join(request.Contacts, "\x00"), strconv.FormatBool(request.AcceptTerms),
		strings.Join(request.Domains, "\x00"),
	} {
		_, _ = hash.Write([]byte(value))
		_, _ = hash.Write([]byte{0xff})
	}
	return fmt.Sprintf("sha256:%x", hash.Sum(nil))
}

func mustSourceCipher(t *testing.T, keyID string, fill byte) *dnsacme.AESGCMCredentialCipher {
	t.Helper()
	cipher, err := dnsacme.NewAESGCMCredentialCipher(keyID, bytes.Repeat([]byte{fill}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return cipher
}

// sealSourceCredentials seals like the provider store: bound to tenant, scope
// and provider (dnsacme.EncryptCredential). Production decrypts only bound
// envelopes (source.go/reconcile.go boundCredentialDecryptor).
func sealSourceCredentials(t *testing.T, cipher *dnsacme.AESGCMCredentialCipher, tenant sourceTenant,
	providerID uuid.UUID, raw string) (string, []byte) {
	t.Helper()
	keyID, ciphertext, err := cipher.EncryptCredential(dnsacme.CredentialBinding{
		TenantID: tenant.tenantID, ScopeID: tenant.scopeID, ProviderID: providerID,
	}, []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return keyID, ciphertext
}

func setSourceCredentials(t *testing.T, pool *pgxpool.Pool, providerID uuid.UUID, keyID string, ciphertext []byte) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), `UPDATE dns_providers SET credential_key_id=$2,
		credential_ciphertext=$3,revision=revision+1 WHERE id=$1`, providerID, keyID, ciphertext); err != nil {
		t.Fatal(err)
	}
}

func setSourceProviderStatus(t *testing.T, pool *pgxpool.Pool, providerID uuid.UUID, status string) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), `UPDATE dns_providers SET status=$2,revision=revision+1 WHERE id=$1`, providerID, status); err != nil {
		t.Fatal(err)
	}
}

// sourceOperationLookup claims an ACME DNS-01 issuance operation for the provider and zone
// and returns the lookup the DNS-01 runtime resolves credentials with.
func sourceOperationLookup(
	t *testing.T,
	pool *pgxpool.Pool,
	tenant sourceTenant,
	providerID, zoneID uuid.UUID,
	domain, owner string,
) dnsproviderremote.ProviderLookup {
	t.Helper()
	operationID := uuid.New()
	suffix := operationID.String()[:8]
	request := acmeworker.IssueRequest{
		TenantID: tenant.tenantID, ScopeID: tenant.scopeID, OperationID: operationID.String(),
		ActorUserID: tenant.userID, ProviderID: providerID, ZoneID: zoneID,
		ProviderRef: providerID.String(), DirectoryURL: "https://ca.example/directory",
		AccountKeyRef: "kms/account-" + suffix, CertificateKeyRef: "kms/certificate-" + suffix,
		Contacts: []string{"mailto:ops@example.test"}, AcceptTerms: true,
		Domains: []string{domain}, ChallengeType: acmeworker.ChallengeDNS01, CertificateOrderID: operationID,
	}
	seedSourceACMERequestFacts(t, pool, tenant, request)
	store, err := acmeworker.NewPGOperationStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := store.Claim(t.Context(), request, sourceIssueRequestDigest(request), now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	return dnsproviderremote.ProviderLookup{
		TenantID: tenant.tenantID, ScopeID: tenant.scopeID, TenantScopeID: tenant.scopeID,
		OperationID: request.OperationID, ActorUserID: tenant.userID,
		ProviderID: providerID, ZoneID: zoneID, OwnerName: owner,
	}
}

func sourceResolveError(source *Source, ctx context.Context, lookup dnsproviderremote.ProviderLookup) error {
	_, err := source.Resolve(ctx, lookup)
	return err
}

func sourceLookup(tenant sourceTenant, providerID, zoneID uuid.UUID, owner string) dnsproviderremote.ProviderLookup {
	return dnsproviderremote.ProviderLookup{
		TenantID: tenant.tenantID, ScopeID: tenant.scopeID, TenantScopeID: tenant.scopeID,
		ProviderID: providerID, ZoneID: zoneID, OwnerName: owner,
	}
}

func assertSourceFailure(t *testing.T, err error, forbidden ...string) {
	t.Helper()
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Resolve() error = %v, want ErrUnavailable", err)
	}
	message := err.Error()
	for _, value := range forbidden {
		if value != "" && strings.Contains(message, value) {
			t.Fatalf("source error leaked %q: %q", value, message)
		}
	}
}

func openSourcePG17(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	var version string
	if err := admin.QueryRow(ctx, `SHOW server_version`).Scan(&version); err != nil || !strings.HasPrefix(version, "17.") {
		admin.Close()
		t.Fatalf("PostgreSQL version = %q, error = %v, want 17.x", version, err)
	}
	schema := "dns_provider_source_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^dns_provider_source_[a-f0-9]{32}$`).MatchString(schema) {
		admin.Close()
		t.Fatalf("unsafe test schema %q", schema)
	}
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE")
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		cleanupCtx, cleanupCancel := databasetest.CleanupContext()
		defer cleanupCancel()
		if _, err := admin.Exec(cleanupCtx, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop source test schema: %v", err)
		}
		admin.Close()
	})
	return pool
}

func applySourceMigrationsThrough(t *testing.T, pool *pgxpool.Pool, target int) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), `CREATE TABLE schema_migrations(
		version bigint PRIMARY KEY,applied_at timestamptz NOT NULL DEFAULT statement_timestamp()
	)`); err != nil {
		t.Fatal(err)
	}
	for version := 1; version <= target; version++ {
		if err := applySourceMigration(pool, version, "up"); err != nil {
			t.Fatalf("apply migration %03d: %v", version, err)
		}
	}
}

func applySourceMigration(pool *pgxpool.Pool, version int, direction string) error {
	matches, err := fs.Glob(controlmigrations.FS, fmt.Sprintf("%03d_*.%s.sql", version, direction))
	if err != nil || len(matches) != 1 {
		return fmt.Errorf("migration %03d %s match count=%d: %w", version, direction, len(matches), err)
	}
	script, err := fs.ReadFile(controlmigrations.FS, matches[0])
	if err != nil {
		return err
	}
	return pgx.BeginFunc(context.Background(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(context.Background(), string(script)); err != nil {
			return err
		}
		if direction == "up" {
			_, err = tx.Exec(context.Background(), `INSERT INTO schema_migrations(version) VALUES($1)`, version)
		} else {
			_, err = tx.Exec(context.Background(), `DELETE FROM schema_migrations WHERE version=$1`, version)
		}
		return err
	})
}

func assertSourceMigrationVersion(t *testing.T, pool *pgxpool.Pool, want int64) {
	t.Helper()
	var got int64
	if err := pool.QueryRow(t.Context(), `SELECT COALESCE(max(version),0) FROM schema_migrations`).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("migration version = %d, want %d", got, want)
	}
}

var _ dnsacme.ProviderVerifier = (*sourceVerifier)(nil)
var _ dnsacme.CredentialProviderVerifier = (*sourceVerifier)(nil)
var _ dnsacme.CredentialCipher = (*sourceKeyring)(nil)
