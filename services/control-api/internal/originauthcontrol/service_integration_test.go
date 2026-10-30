package originauthcontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var originAuthTestNow = time.Date(2026, 7, 23, 5, 0, 0, 0, time.UTC)

type allowEntitlement struct{}

func (allowEntitlement) Check(context.Context, pgx.Tx, EntitlementCheck) error { return nil }

type allowTxAuthorizer struct{}

func (allowTxAuthorizer) Authorize(_ context.Context, _ pgx.Tx, actor Actor, _ uuid.UUID, permission string) error {
	for _, candidate := range actor.Permissions {
		if candidate == permission || candidate == "platform.admin" {
			return nil
		}
	}
	return ErrPermissionDenied
}

type unavailableEntitlement struct{}

func (unavailableEntitlement) Check(context.Context, pgx.Tx, EntitlementCheck) error {
	return entitlementguard.ErrUnavailable
}

type integrationFixture struct {
	pool          *pgxpool.Pool
	tenantID      uuid.UUID
	tenantScopeID uuid.UUID
	otherScopeID  uuid.UUID
	platform      Actor
	owner         Actor
	viewer        Actor
	siteA         uuid.UUID
	siteB         uuid.UUID
}

func TestMigration055UpDownUpAndFactsFailClosed(t *testing.T) {
	pool := isolatedOriginAuthPool(t, migrateOriginAuthThrough055)
	// Today's audit writer (the fact below) needs 361's unified-log columns.
	databasetest.AddUnifiedAuditColumns(t, pool)
	down := migrationScript(t, "055_origin_auth_control.down.sql")
	up := migrationScript(t, "055_origin_auth_control.up.sql")
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		_, err := tx.Exec(t.Context(), down)
		return err
	}); err != nil {
		t.Fatalf("055 down on empty schema: %v", err)
	}
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		_, err := tx.Exec(t.Context(), up)
		return err
	}); err != nil {
		t.Fatalf("055 second up: %v", err)
	}
	fixture := seedOriginAuthFixture(t, pool)
	service := fixtureService(t, fixture, "old", nil, nil)
	credential := createCredential(t, service, fixture.owner, "migration-fact", "migration-create")
	if credential.Status != StatusPending {
		t.Fatalf("credential status = %s", credential.Status)
	}
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		_, err := tx.Exec(t.Context(), down)
		return err
	})
	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) || postgresError.Code != "P0001" ||
		!strings.Contains(postgresError.Message, "facts exist") {
		t.Fatalf("055 down with facts error = %v", err)
	}
	if !relationExists(t, pool, "origin_auth_credentials") {
		t.Fatal("055 schema was partially removed after fail-closed down")
	}
}

func TestCredentialRulePublicationHTTPAndTamperFlow(t *testing.T) {
	fixture := newOriginAuthFixture(t)
	oldService := fixtureService(t, fixture, "old", nil, nil)
	created := createCredential(t, oldService, fixture.owner, "primary", "credential-create")
	if created.Status != StatusPending || created.Revision != 1 {
		t.Fatalf("created credential = %+v", created)
	}
	assertPublicCredentialJSON(t, created)
	replay := createCredential(t, oldService, fixture.owner, "primary", "credential-create")
	if replay.ID != created.ID {
		t.Fatalf("create replay ID = %s, want %s", replay.ID, created.ID)
	}
	conflictRequest := createCredentialRequest(fixture.owner, fixture.tenantScopeID, "different", "credential-create")
	if _, err := oldService.CreateCredential(t.Context(), fixture.owner, conflictRequest); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("different payload replay error = %v", err)
	}
	verifyRequest := mutationRequest(fixture.tenantScopeID, created.ID, 1, "credential-verify")
	if _, err := oldService.VerifyCredential(t.Context(), fixture.owner, verifyRequest); !errors.Is(err, ErrVerifierUnavailable) {
		t.Fatalf("verify without injected verifier error = %v", err)
	}
	if current, err := oldService.GetCredential(t.Context(), fixture.owner, fixture.tenantScopeID, created.ID); err != nil || current.Status != StatusPending {
		t.Fatalf("pending state after unavailable verifier = %+v, %v", current, err)
	}
	unknownKeyring, err := NewKeyring("new", map[string][]byte{"new": bytes.Repeat([]byte{0x22}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	unknownKeyService, err := newService(fixture.pool, unknownKeyring, Config{
		Clock:       func() time.Time { return originAuthTestNow },
		Verifier:    CredentialVerifierFunc(func(context.Context, VerificationRequest) error { return nil }),
		Entitlement: allowEntitlement{},
	}, allowTxAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	unknownKeyRequest := mutationRequest(fixture.tenantScopeID, created.ID, 1, "credential-unknown-key")
	if _, err := unknownKeyService.VerifyCredential(t.Context(), fixture.owner, unknownKeyRequest); !errors.Is(err, ErrEncryptionUnavailable) {
		t.Fatalf("unknown envelope key error = %v", err)
	}
	rejectingService := fixtureService(t, fixture, "new",
		CredentialVerifierFunc(func(context.Context, VerificationRequest) error { return ErrVerificationRejected }), nil)
	rejectedRequest := mutationRequest(fixture.tenantScopeID, created.ID, 1, "credential-rejected")
	if _, err := rejectingService.VerifyCredential(t.Context(), fixture.owner, rejectedRequest); !errors.Is(err, ErrVerificationRejected) {
		t.Fatalf("rejected verification error = %v", err)
	}
	if current, err := oldService.GetCredential(t.Context(), fixture.owner, fixture.tenantScopeID, created.ID); err != nil || current.Status != StatusPending {
		t.Fatalf("pending state after failed decrypt and rejected verifier = %+v, %v", current, err)
	}

	verifierCalls := 0
	newService := fixtureService(t, fixture, "new", CredentialVerifierFunc(func(_ context.Context, request VerificationRequest) error {
		verifierCalls++
		if request.Provider != ProviderS3 || request.Credential.AccessKeyID != "AK-primary" ||
			request.Credential.SecretAccessKey != "SK-primary" {
			return ErrVerificationRejected
		}
		return nil
	}), nil)
	verifiedResult, err := newService.VerifyCredential(t.Context(), fixture.owner, verifyRequest)
	if err != nil || verifiedResult.Credential.Status != StatusVerified || verifiedResult.Credential.Revision != 2 {
		t.Fatalf("VerifyCredential() = %+v, %v", verifiedResult, err)
	}
	verifyReplay, err := newService.VerifyCredential(t.Context(), fixture.owner, verifyRequest)
	if err != nil || !verifyReplay.Replayed || verifierCalls != 1 {
		t.Fatalf("verify replay = %+v, calls=%d, err=%v", verifyReplay, verifierCalls, err)
	}

	replacement := credentialSecret("replacement")
	replaced, err := newService.ReplaceCredential(t.Context(), fixture.owner, ReplaceCredentialRequest{
		TargetScopeID: fixture.tenantScopeID, CredentialID: created.ID, ExpectedRevision: 2,
		Secret: replacement, WriteMetadata: metadata("credential-replace"),
	})
	if err != nil || replaced.Credential.Status != StatusPending || replaced.Credential.Revision != 3 {
		t.Fatalf("ReplaceCredential() = %+v, %v", replaced, err)
	}
	replaceReplay, err := newService.ReplaceCredential(t.Context(), fixture.owner, ReplaceCredentialRequest{
		TargetScopeID: fixture.tenantScopeID, CredentialID: created.ID, ExpectedRevision: 2,
		Secret: credentialSecret("replacement"), WriteMetadata: metadata("credential-replace"),
	})
	if err != nil || !replaceReplay.Replayed {
		t.Fatalf("replace replay = %+v, %v", replaceReplay, err)
	}
	newService.verifier = CredentialVerifierFunc(func(_ context.Context, request VerificationRequest) error {
		if request.Credential.AccessKeyID != "AK-replacement" {
			return ErrVerificationRejected
		}
		return nil
	})
	verifiedReplacement, err := newService.VerifyCredential(t.Context(), fixture.owner,
		mutationRequest(fixture.tenantScopeID, created.ID, 3, "replacement-verify"))
	if err != nil || verifiedReplacement.Credential.Revision != 4 {
		t.Fatalf("verify replacement = %+v, %v", verifiedReplacement, err)
	}
	assertEnvelopeRotation(t, fixture.pool, created.ID)

	second := createCredential(t, newService, fixture.owner, "secondary", "secondary-create")
	newService.verifier = CredentialVerifierFunc(func(context.Context, VerificationRequest) error { return nil })
	secondVerified, err := newService.VerifyCredential(t.Context(), fixture.owner,
		mutationRequest(fixture.tenantScopeID, second.ID, 1, "secondary-verify"))
	if err != nil {
		t.Fatal(err)
	}
	pending := createCredential(t, newService, fixture.owner, "pending", "pending-create")
	platformCredential, err := newService.CreateCredential(t.Context(), fixture.platform,
		createCredentialRequest(fixture.platform, fixture.tenantScopeID, "platform-explicit", "platform-create"))
	if err != nil || platformCredential.Credential.TenantScope != fixture.tenantScopeID {
		t.Fatalf("platform explicit tenant create = %+v, %v", platformCredential, err)
	}

	if _, err := newService.CreateCredential(t.Context(), fixture.viewer,
		createCredentialRequest(fixture.viewer, fixture.tenantScopeID, "denied", "denied-create")); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("viewer create error = %v", err)
	}
	if _, err := newService.GetCredential(t.Context(), fixture.owner, fixture.otherScopeID, created.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant get error = %v", err)
	}

	ruleConfig := s3RuleConfig(created.ID, verifiedReplacement.Credential.Revision)
	ruleRequest := CreateRuleRequest{
		TargetScopeID: fixture.tenantScopeID, SiteID: fixture.siteA, SourcePosition: 1,
		Config: ruleConfig, Enabled: true, WriteMetadata: metadata("rule-create"),
	}
	ruleResult, err := newService.CreateRule(t.Context(), fixture.owner, ruleRequest)
	if err != nil || !ruleResult.Rule.Enabled || ruleResult.Rule.Revision != 1 {
		t.Fatalf("CreateRule() = %+v, %v", ruleResult, err)
	}
	ruleReplay, err := newService.CreateRule(t.Context(), fixture.owner, ruleRequest)
	if err != nil || !ruleReplay.Replayed || ruleReplay.Rule.ID != ruleResult.Rule.ID {
		t.Fatalf("rule replay = %+v, %v", ruleReplay, err)
	}
	conflictingRuleRequest := ruleRequest
	conflictingRuleRequest.SiteID = fixture.siteB
	if _, err := newService.CreateRule(t.Context(), fixture.owner, conflictingRuleRequest); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("rule idempotency conflict error = %v", err)
	}
	if _, err := newService.CreateRule(t.Context(), fixture.owner, CreateRuleRequest{
		TargetScopeID: fixture.tenantScopeID, SiteID: uuid.New(), SourcePosition: 1,
		Config: ruleConfig, Enabled: false, WriteMetadata: metadata("unknown-site"),
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown site rule error = %v", err)
	}
	if _, err := newService.CreateRule(t.Context(), fixture.owner, CreateRuleRequest{
		TargetScopeID: fixture.tenantScopeID, SiteID: fixture.siteA, SourcePosition: 2,
		Config: ruleConfig, Enabled: false, WriteMetadata: metadata("unknown-source"),
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown source rule error = %v", err)
	}
	if _, err := newService.CreateRule(t.Context(), fixture.platform, CreateRuleRequest{
		TargetScopeID: fixture.otherScopeID, SiteID: fixture.siteA, SourcePosition: 1,
		Config: ruleConfig, Enabled: false, WriteMetadata: metadata("cross-tenant-site"),
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant site rule error = %v", err)
	}
	if _, err := newService.CreateRule(t.Context(), fixture.owner, CreateRuleRequest{
		TargetScopeID: fixture.tenantScopeID, SiteID: fixture.siteB, SourcePosition: 1,
		Config: s3RuleConfig(pending.ID, 1), Enabled: true, WriteMetadata: metadata("pending-rule"),
	}); !errors.Is(err, ErrCredentialUnverified) {
		t.Fatalf("pending credential active rule error = %v", err)
	}
	disabledRule, err := newService.CreateRule(t.Context(), fixture.owner, CreateRuleRequest{
		TargetScopeID: fixture.tenantScopeID, SiteID: fixture.siteB, SourcePosition: 1,
		Config: s3RuleConfig(pending.ID, 1), Enabled: false, WriteMetadata: metadata("disabled-rule"),
	})
	if err != nil || disabledRule.Rule.Enabled {
		t.Fatalf("disabled rule with pending credential = %+v, %v", disabledRule, err)
	}
	updatedConfig := ruleResult.Rule.RuleConfig
	updatedConfig.SignatureTTLSeconds = 301
	updated, err := newService.UpdateRule(t.Context(), fixture.owner, UpdateRuleRequest{
		TargetScopeID: fixture.tenantScopeID, RuleID: ruleResult.Rule.ID, ExpectedRevision: 1,
		Config: updatedConfig, WriteMetadata: metadata("rule-update"),
	})
	if err != nil || updated.Rule.Revision != 2 || updated.Rule.SignatureTTLSeconds != 301 {
		t.Fatalf("UpdateRule() = %+v, %v", updated, err)
	}
	updateReplay, err := newService.UpdateRule(t.Context(), fixture.owner, UpdateRuleRequest{
		TargetScopeID: fixture.tenantScopeID, RuleID: ruleResult.Rule.ID, ExpectedRevision: 1,
		Config: updatedConfig, WriteMetadata: metadata("rule-update"),
	})
	if err != nil || !updateReplay.Replayed || updateReplay.Rule.Revision != 2 {
		t.Fatalf("rule update replay = %+v, %v", updateReplay, err)
	}

	activateAt := originAuthTestNow.Add(time.Hour)
	rotated, err := newService.RotateRule(t.Context(), fixture.owner, RotateRuleRequest{
		TargetScopeID: fixture.tenantScopeID, RuleID: ruleResult.Rule.ID, ExpectedRevision: updated.Rule.Revision,
		CurrentCredential: CredentialReference{CredentialID: second.ID, Revision: secondVerified.Credential.Revision},
		ActivateCurrentAt: activateAt, WriteMetadata: metadata("rule-rotate"),
	})
	if err != nil || rotated.Rule.Revision != 3 || rotated.Rule.PreviousCredential == nil ||
		rotated.Rule.PreviousCredential.CredentialID != created.ID {
		t.Fatalf("RotateRule() = %+v, %v", rotated, err)
	}
	assertConcurrentRuleCAS(t, newService, fixture.owner, fixture.tenantScopeID,
		rotated.Rule.ID, rotated.Rule.Revision)
	current, err := newService.GetRule(t.Context(), fixture.owner, fixture.tenantScopeID, rotated.Rule.ID)
	if err != nil || current.Revision != 4 || current.Enabled {
		t.Fatalf("concurrent CAS result = %+v, %v", current, err)
	}
	enabled, err := newService.EnableRule(t.Context(), fixture.owner, RuleMutationRequest{
		TargetScopeID: fixture.tenantScopeID, RuleID: current.ID, ExpectedRevision: current.Revision,
		WriteMetadata: metadata("rule-enable"),
	})
	if err != nil || !enabled.Rule.Enabled || enabled.Rule.Revision != 5 {
		t.Fatalf("EnableRule() = %+v, %v", enabled, err)
	}

	assertStableSnapshot(t, fixture.pool, fixture.tenantScopeID)
	publicationRequest := CreatePublicationRequest{
		TargetScopeID: fixture.tenantScopeID, ExpectedRevision: 0,
		WriteMetadata: metadata("publication-create"),
	}
	publication, err := newService.CreatePublication(t.Context(), fixture.owner, publicationRequest)
	if err != nil || publication.Publication.Revision != 1 || len(publication.Publication.Snapshot.Rules) != 1 {
		t.Fatalf("CreatePublication() = %+v, %v", publication, err)
	}
	publicationReplay, err := newService.CreatePublication(t.Context(), fixture.owner, publicationRequest)
	if err != nil || !publicationReplay.Replayed ||
		publicationReplay.Publication.SnapshotHash != publication.Publication.SnapshotHash {
		t.Fatalf("publication replay = %+v, %v", publicationReplay, err)
	}
	latest, err := newService.GetLatestPublication(t.Context(), fixture.owner, fixture.tenantScopeID)
	if err != nil || latest.SnapshotHash != publication.Publication.SnapshotHash {
		t.Fatalf("latest publication = %+v, %v", latest, err)
	}

	assertPagination(t, newService, fixture.owner, fixture.tenantScopeID)
	assertHTTPRedactionAndStrictBody(t, newService, fixture.owner, created.ID, enabled.Rule.ID)
	assertAuditRedaction(t, fixture.pool)
	assertDirectSQLTamperRejected(t, fixture, created.ID, enabled.Rule.ID, enabled.Rule.Revision)
	assertReductionBypassesUnavailableEntitlement(t, fixture, created.ID, enabled.Rule.ID, enabled.Rule.Revision)

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := newService.ListCredentials(canceled, fixture.owner, CredentialListFilter{
		TargetScopeID: fixture.tenantScopeID, Limit: 10,
	}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled query error = %v", err)
	}
}

func TestAuditFailureRollsBackCredentialAndIdempotencyFact(t *testing.T) {
	fixture := newOriginAuthFixture(t)
	keyring := testKeyring(t, "new")
	service, err := newService(fixture.pool, keyring, Config{
		Clock: func() time.Time { return originAuthTestNow }, Auditor: failingAuditAdapter{},
		Entitlement: allowEntitlement{},
	}, allowTxAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.CreateCredential(t.Context(), fixture.owner,
		createCredentialRequest(fixture.owner, fixture.tenantScopeID, "audit-failure", "audit-failure"))
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("CreateCredential() error = %v", err)
	}
	var credentialCount, writeCount int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM origin_auth_credentials),
		(SELECT count(*) FROM origin_auth_write_requests)`).Scan(&credentialCount, &writeCount); err != nil {
		t.Fatal(err)
	}
	if credentialCount != 0 || writeCount != 0 {
		t.Fatalf("rolled-back counts = credentials %d writes %d", credentialCount, writeCount)
	}
}

func TestDatabaseUnavailableIsStable(t *testing.T) {
	fixture := newOriginAuthFixture(t)
	service := fixtureService(t, fixture, "new", nil, nil)
	fixture.pool.Close()
	_, err := service.GetCredential(t.Context(), fixture.owner, fixture.tenantScopeID, uuid.New())
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("closed database error = %v", err)
	}
}

type failingAuditAdapter struct{}

func (failingAuditAdapter) Append(context.Context, pgx.Tx, audit.Event) error {
	return errors.New("injected audit failure")
}

func assertConcurrentRuleCAS(
	t *testing.T,
	service *Service,
	actor Actor,
	scopeID, ruleID uuid.UUID,
	expectedRevision int64,
) {
	t.Helper()
	start := make(chan struct{})
	errorsByCall := make([]error, 2)
	var wait sync.WaitGroup
	for index := range errorsByCall {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			_, errorsByCall[index] = service.DisableRule(context.Background(), actor, RuleMutationRequest{
				TargetScopeID: scopeID, RuleID: ruleID, ExpectedRevision: expectedRevision,
				WriteMetadata: metadata(fmt.Sprintf("rule-disable-%d", index)),
			})
		}(index)
	}
	close(start)
	wait.Wait()
	successes, conflicts := 0, 0
	for _, err := range errorsByCall {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrRevisionConflict):
			conflicts++
		default:
			t.Fatalf("concurrent disable error = %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("concurrent results = success %d conflict %d", successes, conflicts)
	}
}

func assertStableSnapshot(t *testing.T, pool *pgxpool.Pool, scopeID uuid.UUID) {
	t.Helper()
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	first, firstBytes, err := buildPublicationSnapshot(t.Context(), tx, scopeID, 1)
	if err != nil {
		t.Fatal(err)
	}
	second, secondBytes, err := buildPublicationSnapshot(t.Context(), tx, scopeID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstBytes, secondBytes) || len(first.Rules) != len(second.Rules) || len(first.Rules) != 1 {
		t.Fatalf("snapshot drift: %s != %s", firstBytes, secondBytes)
	}
	if strings.Contains(string(firstBytes), "AK-") || strings.Contains(string(firstBytes), "SK-") ||
		strings.Contains(string(firstBytes), "envelope_key_id") || strings.Contains(string(firstBytes), "ciphertext") {
		t.Fatalf("snapshot contains secret metadata: %s", firstBytes)
	}
}

func assertEnvelopeRotation(t *testing.T, pool *pgxpool.Pool, credentialID uuid.UUID) {
	t.Helper()
	rows, err := pool.Query(t.Context(), `SELECT revision,envelope_key_id FROM origin_auth_credential_revisions
		WHERE credential_id=$1 ORDER BY revision`, credentialID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	keys := map[int64]string{}
	for rows.Next() {
		var revision int64
		var key string
		if err := rows.Scan(&revision, &key); err != nil {
			t.Fatal(err)
		}
		keys[revision] = key
	}
	if keys[1] != "old" || keys[2] != "old" || keys[3] != "new" || keys[4] != "new" {
		t.Fatalf("envelope key rotation facts = %#v", keys)
	}
}

func assertPagination(t *testing.T, service *Service, actor Actor, scopeID uuid.UUID) {
	t.Helper()
	first, err := service.ListCredentials(t.Context(), actor, CredentialListFilter{TargetScopeID: scopeID, Limit: 1})
	if err != nil || len(first.Items) != 1 || first.NextCursor == "" {
		t.Fatalf("first credential page = %+v, %v", first, err)
	}
	second, err := service.ListCredentials(t.Context(), actor, CredentialListFilter{
		TargetScopeID: scopeID, Limit: 1, Cursor: first.NextCursor,
	})
	if err != nil || len(second.Items) != 1 || second.Items[0].ID == first.Items[0].ID {
		t.Fatalf("second credential page = %+v, %v", second, err)
	}
	firstRules, err := service.ListRules(t.Context(), actor, RuleListFilter{TargetScopeID: scopeID, Limit: 1})
	if err != nil || len(firstRules.Items) != 1 || firstRules.NextCursor == "" {
		t.Fatalf("first rule page = %+v, %v", firstRules, err)
	}
	secondRules, err := service.ListRules(t.Context(), actor, RuleListFilter{
		TargetScopeID: scopeID, Limit: 1, Cursor: firstRules.NextCursor,
	})
	if err != nil || len(secondRules.Items) != 1 || secondRules.Items[0].ID == firstRules.Items[0].ID {
		t.Fatalf("second rule page = %+v, %v", secondRules, err)
	}
}

func assertHTTPRedactionAndStrictBody(
	t *testing.T,
	service *Service,
	actor Actor,
	credentialID, ruleID uuid.UUID,
) {
	t.Helper()
	handler, err := NewHandler(service, AuthenticatorFunc(func(*http.Request) (Actor, error) { return actor, nil }), HandlerConfig{})
	if err != nil {
		t.Fatal(err)
	}
	path := "/v1/tenant-scopes/" + actor.ScopeID.String() + "/origin-auth/credentials/" + credentialID.String()
	request := httptest.NewRequest(http.MethodGet, path, nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("GET credential HTTP = %d %s", response.Code, response.Body.String())
	}
	for _, forbidden := range []string{"AK-", "SK-", "ciphertext", "envelope_key_id", "sha256"} {
		if strings.Contains(response.Body.String(), forbidden) {
			t.Fatalf("credential response leaked %q: %s", forbidden, response.Body.String())
		}
	}
	request = httptest.NewRequest(http.MethodPost,
		"/v1/tenant-scopes/"+actor.ScopeID.String()+"/origin-auth/credentials",
		strings.NewReader(`{"provider":"s3","name":"bad","secret":{},"extra":"forbidden"}`))
	request.Header.Set("Idempotency-Key", "http-extra")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"code":"invalid_request"`) {
		t.Fatalf("extra-field HTTP = %d %s", response.Code, response.Body.String())
	}
	request = httptest.NewRequest(http.MethodGet,
		"/v1/tenant-scopes/"+actor.ScopeID.String()+"/origin-auth/credentials?cursor=*", nil)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("malformed cursor HTTP = %d %s", response.Code, response.Body.String())
	}
	request = httptest.NewRequest(http.MethodPost,
		"/v1/tenant-scopes/"+actor.ScopeID.String()+"/origin-auth/rules/"+ruleID.String()+"/rotate",
		strings.NewReader(`{"current_credential":{"credential_id":"`+credentialID.String()+`","revision":1},"activate_current_at":"not-a-time"}`))
	request.Header.Set("Idempotency-Key", "http-bad-time")
	request.Header.Set("If-Match", `"1"`)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("malformed time HTTP = %d %s", response.Code, response.Body.String())
	}
	bounded, err := NewHandler(service,
		AuthenticatorFunc(func(*http.Request) (Actor, error) { return actor, nil }),
		HandlerConfig{MaxResponseBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	request = httptest.NewRequest(http.MethodGet,
		"/v1/tenant-scopes/"+actor.ScopeID.String()+"/origin-auth/credentials", nil)
	response = httptest.NewRecorder()
	bounded.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "AK-") {
		t.Fatalf("bounded response HTTP = %d %s", response.Code, response.Body.String())
	}
}

func assertAuditRedaction(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	var auditText string
	if err := pool.QueryRow(t.Context(), `SELECT COALESCE(string_agg(payload::text || action, E'\n'), '')
		FROM audit_events WHERE action LIKE 'origin_auth.%'`).Scan(&auditText); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"AK-", "SK-", "session-", "ciphertext", "envelope_key_id",
		"bucket.s3.us-east-1.amazonaws.com", "/objects/"} {
		if strings.Contains(auditText, forbidden) {
			t.Fatalf("audit leaked %q: %s", forbidden, auditText)
		}
	}
}

func assertDirectSQLTamperRejected(
	t *testing.T,
	fixture integrationFixture,
	credentialID, ruleID uuid.UUID,
	ruleRevision int64,
) {
	t.Helper()
	pool := fixture.pool
	directCredentialID := uuid.New()
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		actorUserID := fixture.owner.UserID
		if err := audit.New(pool).Append(t.Context(), tx, audit.Event{
			ScopeID: fixture.tenantScopeID, ActorUserID: &actorUserID,
			Action: "origin_auth.credential.create", ResourceType: "origin_auth_credential",
			ResourceID: directCredentialID.String(), RequestID: "direct-credential",
			Result: "success", Payload: map[string]any{"trace_id": "trace-direct-credential"},
		}); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO origin_auth_credentials(
			id,tenant_scope_id,tenant_id,provider,name,created_by_scope_id,created_by_user_id,
			request_id,trace_id,created_at)
			SELECT $1,tenant_scope_id,tenant_id,provider,name || '-direct',created_by_scope_id,
			created_by_user_id,'direct-credential','trace-direct-credential',created_at
			FROM origin_auth_credentials WHERE id=$2`, directCredentialID, credentialID)
		return err
	})
	requirePostgresCode(t, err, "P0001")
	directRuleID := uuid.New()
	err = pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		actorUserID := fixture.owner.UserID
		if err := audit.New(pool).Append(t.Context(), tx, audit.Event{
			ScopeID: fixture.tenantScopeID, ActorUserID: &actorUserID,
			Action: "origin_auth.rule.create", ResourceType: "origin_auth_rule",
			ResourceID: directRuleID.String(), RequestID: "direct-rule", Result: "success",
			Payload: map[string]any{"trace_id": "trace-direct-rule"},
		}); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO origin_auth_rules(
			id,tenant_scope_id,tenant_id,site_id,source_position,created_by_scope_id,created_by_user_id,
			request_id,trace_id,created_at)
			SELECT $1,tenant_scope_id,tenant_id,site_id,source_position,created_by_scope_id,
			created_by_user_id,'direct-rule','trace-direct-rule',created_at
			FROM origin_auth_rules WHERE id=$2`, directRuleID, ruleID)
		return err
	})
	requirePostgresCode(t, err, "P0001")
	service := fixtureService(t, fixture, "new", nil, nil)
	regionMetadata := metadata("direct-region-mismatch")
	err = pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		var digest [32]byte
		digest[0] = 1
		if _, err := service.claimWrite(t.Context(), tx, fixture.owner, fixture.tenantScopeID,
			"origin_auth.rule.update", regionMetadata, digest); err != nil {
			return err
		}
		if err := service.appendAudit(t.Context(), tx, fixture.owner, fixture.tenantScopeID, ruleID,
			regionMetadata, "origin_auth.rule.update", "origin_auth_rule",
			map[string]any{"revision": ruleRevision + 1}); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO origin_auth_rule_revisions(
			rule_id,revision,operation,provider,algorithm,endpoint,bucket,path_prefix,region,service,
			signature_ttl_seconds,egress_policy_reference,current_credential_id,current_credential_revision,
			current_credential_revision_ref,previous_credential_id,previous_credential_revision,
			previous_credential_revision_ref,activate_current_at,enabled,deleted,created_by_scope_id,
			created_by_user_id,request_id,trace_id,created_at)
			SELECT rule_id,revision+1,'update',provider,algorithm,endpoint,bucket,path_prefix,
			'us-west-2',service,signature_ttl_seconds,egress_policy_reference,current_credential_id,
			current_credential_revision,current_credential_revision_ref,previous_credential_id,
			previous_credential_revision,previous_credential_revision_ref,activate_current_at,enabled,
			deleted,$1,$2,$3,$4,$5 FROM origin_auth_rule_revisions
			WHERE rule_id=$6 AND revision=$7`, fixture.owner.ScopeID, fixture.owner.UserID,
			regionMetadata.RequestID, regionMetadata.TraceID, originAuthTestNow, ruleID, ruleRevision)
		return err
	})
	requirePostgresCode(t, err, "P0001")
	_, err = pool.Exec(t.Context(), `UPDATE origin_auth_credential_revisions
		SET secret_ciphertext=decode('00','hex') WHERE credential_id=$1 AND revision=1`, credentialID)
	requirePostgresCode(t, err, "P0001")
	_, err = pool.Exec(t.Context(), `UPDATE origin_auth_rule_revisions SET enabled=false
		WHERE rule_id=$1 AND revision=$2`, ruleID, ruleRevision)
	requirePostgresCode(t, err, "P0001")
	_, err = pool.Exec(t.Context(), `TRUNCATE origin_auth_publications`)
	requirePostgresCode(t, err, "P0001")
}

func assertReductionBypassesUnavailableEntitlement(
	t *testing.T,
	fixture integrationFixture,
	credentialID, ruleID uuid.UUID,
	ruleRevision int64,
) {
	t.Helper()
	service, err := newService(fixture.pool, testKeyring(t, "new"), Config{
		Clock: func() time.Time { return originAuthTestNow }, Entitlement: unavailableEntitlement{},
		EgressPolicies: map[string][]string{"minio-prod": {"objects.example.test"}},
	}, allowTxAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.CreateCredential(t.Context(), fixture.owner,
		createCredentialRequest(fixture.owner, fixture.tenantScopeID, "entitlement-blocked", "entitlement-blocked")); !errors.Is(err, ErrEntitlementUnavailable) {
		t.Fatalf("expansion with unavailable entitlement error = %v", err)
	}
	disabled, err := service.DisableRule(t.Context(), fixture.owner, RuleMutationRequest{
		TargetScopeID: fixture.tenantScopeID, RuleID: ruleID, ExpectedRevision: ruleRevision,
		WriteMetadata: metadata("entitlement-rule-disable"),
	})
	if err != nil || disabled.Rule.Enabled {
		t.Fatalf("disable rule with unavailable entitlement = %+v, %v", disabled, err)
	}
	deleted, err := service.DeleteRule(t.Context(), fixture.owner, RuleMutationRequest{
		TargetScopeID: fixture.tenantScopeID, RuleID: ruleID, ExpectedRevision: disabled.Rule.Revision,
		WriteMetadata: metadata("entitlement-rule-delete"),
	})
	if err != nil || !deleted.Rule.Deleted {
		t.Fatalf("delete rule with unavailable entitlement = %+v, %v", deleted, err)
	}
	credential, err := service.GetCredential(t.Context(), fixture.owner, fixture.tenantScopeID, credentialID)
	if err != nil {
		t.Fatal(err)
	}
	disabledCredential, err := service.DisableCredential(t.Context(), fixture.owner,
		mutationRequest(fixture.tenantScopeID, credentialID, credential.Revision, "entitlement-credential-disable"))
	if err != nil || disabledCredential.Credential.Status != StatusDisabled {
		t.Fatalf("disable credential with unavailable entitlement = %+v, %v", disabledCredential, err)
	}
	deletedCredential, err := service.DeleteCredential(t.Context(), fixture.owner,
		mutationRequest(fixture.tenantScopeID, credentialID, disabledCredential.Credential.Revision,
			"entitlement-credential-delete"))
	if err != nil || deletedCredential.Credential.Status != StatusDeleted {
		t.Fatalf("delete credential with unavailable entitlement = %+v, %v", deletedCredential, err)
	}
}

func newOriginAuthFixture(t *testing.T) integrationFixture {
	t.Helper()
	// The service, its audit writer and site lock read today's schema.
	return newRuntimeOriginAuthFixture(t)
}

func seedOriginAuthFixture(t *testing.T, pool *pgxpool.Pool) integrationFixture {
	t.Helper()
	fixture := integrationFixture{pool: pool, tenantID: uuid.New(), tenantScopeID: uuid.New(), otherScopeID: uuid.New()}
	platformScope, platformUser := uuid.New(), uuid.New()
	ownerUser, viewerUser, otherTenant, otherUser := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	fixture.siteA, fixture.siteB = uuid.New(), uuid.New()
	fixture.platform = Actor{UserID: platformUser, ScopeID: platformScope, ScopeKind: "platform",
		Permissions: []string{PermissionRead, PermissionManage}}
	fixture.owner = Actor{UserID: ownerUser, ScopeID: fixture.tenantScopeID, ScopeKind: "tenant",
		Permissions: []string{PermissionRead, PermissionManage}}
	fixture.viewer = Actor{UserID: viewerUser, ScopeID: fixture.tenantScopeID, ScopeKind: "tenant",
		Permissions: []string{PermissionRead}}
	ctx := t.Context()
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO tenants(id,display_name) VALUES($1,'tenant-a'),($2,'tenant-b')`,
			fixture.tenantID, otherTenant); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES
			($1,'platform',NULL),($2,'tenant',$3),($4,'tenant',$5)`, platformScope,
			fixture.tenantScopeID, fixture.tenantID, fixture.otherScopeID, otherTenant); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO users(id,username,display_name,password_hash) VALUES
			($1,'platform-owner','platform','hash'),($2,'tenant-owner','owner','hash'),
			($3,'tenant-viewer','viewer','hash'),($4,'other-owner','other','hash')`,
			platformUser, ownerUser, viewerUser, otherUser); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO memberships(scope_id,user_id) VALUES
			($1,$2),($3,$4),($3,$5),($6,$7)`, platformScope, platformUser,
			fixture.tenantScopeID, ownerUser, viewerUser, fixture.otherScopeID, otherUser); err != nil {
			return err
		}
		platformRole, ownerRole, viewerRole := uuid.New(), uuid.New(), uuid.New()
		if _, err := tx.Exec(ctx, `INSERT INTO roles(id,scope_id,name,description,system_role) VALUES
			($1,$2,'platform_owner','',true),($3,$4,'tenant_owner','',true),
			($5,$4,'tenant_viewer','',true)`, platformRole, platformScope, ownerRole,
			fixture.tenantScopeID, viewerRole); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES
			($1,$2,$3),($4,$5,$6),($4,$7,$8)`, platformScope, platformUser, platformRole,
			fixture.tenantScopeID, ownerUser, ownerRole, viewerUser, viewerRole); err != nil {
			return err
		}
		// sites.display_id is NOT NULL from 210 on; the 055-only schema does not have it.
		var siteDisplayIDs bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM information_schema.columns
			WHERE table_schema=current_schema() AND table_name='sites' AND column_name='display_id')`).
			Scan(&siteDisplayIDs); err != nil {
			return err
		}
		for index, siteID := range []uuid.UUID{fixture.siteA, fixture.siteB} {
			domain := fmt.Sprintf("site-%d.example.test", index+1)
			insertSite := `INSERT INTO sites(
				id,scope_id,owner_user_id,domain,http_ports,https_ports,origins,origin_hosts,
				https_enabled,enabled,status,revision,created_by_user_id,updated_by_user_id,
				created_at,updated_at)
				VALUES($1,$2,$3,$4,ARRAY['80'],ARRAY['443'],ARRAY['bucket.s3.us-east-1.amazonaws.com:443'],
				ARRAY['bucket.s3.us-east-1.amazonaws.com'],true,true,'active',1,$3,$3,$5,$5)`
			args := []any{siteID, fixture.tenantScopeID, ownerUser, domain, originAuthTestNow}
			if siteDisplayIDs {
				insertSite = strings.Replace(insertSite, "created_at,updated_at)", "created_at,updated_at,display_id)", 1)
				insertSite = strings.Replace(insertSite, "$3,$3,$5,$5)", "$3,$3,$5,$5,$6)", 1)
				args = append(args, index+1)
			}
			if _, err := tx.Exec(ctx, insertSite, args...); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO site_origin_pools(site_id) VALUES($1)`, siteID); err != nil {
				return err
			}
			// From 376 on, a signed bucket must be an HTTPS origin.
			var originScheme bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM information_schema.columns
				WHERE table_schema=current_schema() AND table_name='site_origin_pools' AND column_name='origin_scheme')`).
				Scan(&originScheme); err != nil {
				return err
			}
			if originScheme {
				if _, err := tx.Exec(ctx, `UPDATE site_origin_pools SET origin_scheme='https' WHERE site_id=$1`, siteID); err != nil {
					return err
				}
			}
			if _, err := tx.Exec(ctx, `INSERT INTO site_origins(site_id,position,host,port,weight,enabled)
				VALUES($1,1,'bucket.s3.us-east-1.amazonaws.com',443,1,true)`, siteID); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed origin auth fixture: %v", err)
	}
	return fixture
}

func fixtureService(
	t *testing.T,
	fixture integrationFixture,
	activeKey string,
	verifier CredentialVerifier,
	auditor AuditAppender,
) *Service {
	t.Helper()
	config := Config{
		Clock: func() time.Time { return originAuthTestNow }, Verifier: verifier,
		Auditor: auditor, Entitlement: allowEntitlement{},
		EgressPolicies: map[string][]string{"minio-prod": {"objects.example.test"}},
	}
	service, err := newService(fixture.pool, testKeyring(t, activeKey), config, allowTxAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func testKeyring(t *testing.T, active string) *Keyring {
	t.Helper()
	keyring, err := NewKeyring(active, map[string][]byte{
		"old": bytes.Repeat([]byte{0x11}, 32), "new": bytes.Repeat([]byte{0x22}, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	return keyring
}

func createCredential(t *testing.T, service *Service, actor Actor, name, key string) Credential {
	t.Helper()
	result, err := service.CreateCredential(t.Context(), actor,
		createCredentialRequest(actor, actor.ScopeID, name, key))
	if err != nil {
		t.Fatalf("create credential %s: %v", name, err)
	}
	return result.Credential
}

func createCredentialRequest(_ Actor, scopeID uuid.UUID, name, key string) CreateCredentialRequest {
	return CreateCredentialRequest{
		TargetScopeID: scopeID, Provider: ProviderS3, Name: name,
		Secret: credentialSecret(name), WriteMetadata: metadata(key),
	}
}

func credentialSecret(suffix string) CredentialSecret {
	return CredentialSecret{
		AccessKeyID: "AK-" + suffix, SecretAccessKey: "SK-" + suffix,
		SessionToken: "session-" + suffix, NotBefore: originAuthTestNow.Add(-time.Hour),
		ExpiresAt: originAuthTestNow.Add(30 * 24 * time.Hour),
	}
}

func mutationRequest(scopeID, credentialID uuid.UUID, revision int64, key string) CredentialMutationRequest {
	return CredentialMutationRequest{
		TargetScopeID: scopeID, CredentialID: credentialID, ExpectedRevision: revision,
		WriteMetadata: metadata(key),
	}
}

func s3RuleConfig(credentialID uuid.UUID, revision int64) RuleConfig {
	return RuleConfig{
		Provider: ProviderS3, Algorithm: AlgorithmS3,
		Endpoint: "https://bucket.s3.us-east-1.amazonaws.com", PathPrefix: "/objects/",
		Region: "us-east-1", Service: "s3", SignatureTTLSeconds: 300,
		CurrentCredential: CredentialReference{CredentialID: credentialID, Revision: revision},
	}
}

func metadata(key string) WriteMetadata {
	return WriteMetadata{IdempotencyKey: key, RequestID: "req-" + key, TraceID: "trace-" + key}
}

func isolatedOriginAuthPool(t *testing.T, migrate func(context.Context, *pgxpool.Pool) error) *pgxpool.Pool {
	t.Helper()
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "origin_auth_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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
		admin.Close()
		t.Fatal(err)
	}
	if err := migrate(ctx, pool); err != nil {
		pool.Close()
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE")
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		cleanupCtx, cleanupCancel := databasetest.CleanupContext()
		defer cleanupCancel()
		_, _ = admin.Exec(cleanupCtx, "DROP SCHEMA "+identifier+" CASCADE")
		admin.Close()
	})
	return pool
}

func migrateOriginAuthThrough055(ctx context.Context, pool *pgxpool.Pool) error {
	if _, err := pool.Exec(ctx, `CREATE TABLE schema_migrations(
		version bigint PRIMARY KEY,applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	entries, err := fs.ReadDir(controlmigrations.FS, ".")
	if err != nil {
		return err
	}
	type item struct {
		version int
		name    string
	}
	items := make([]item, 0, 55)
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".up.sql") {
			continue
		}
		separator := strings.IndexByte(name, '_')
		version, err := strconv.Atoi(name[:separator])
		if err != nil {
			return err
		}
		if version <= 55 {
			items = append(items, item{version: version, name: name})
		}
	}
	sort.Slice(items, func(left, right int) bool { return items[left].version < items[right].version })
	if len(items) != 55 {
		return fmt.Errorf("migration count through 055 = %d, want 55", len(items))
	}
	for index, migration := range items {
		if migration.version != index+1 {
			return fmt.Errorf("migration gap at %d", index+1)
		}
		script, err := fs.ReadFile(controlmigrations.FS, migration.name)
		if err != nil {
			return err
		}
		if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, string(script)); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO schema_migrations(version) VALUES($1)`, migration.version)
			return err
		}); err != nil {
			return fmt.Errorf("apply %s: %w", migration.name, err)
		}
	}
	return nil
}

func migrationScript(t *testing.T, name string) string {
	t.Helper()
	value, err := fs.ReadFile(controlmigrations.FS, name)
	if err != nil {
		t.Fatal(err)
	}
	return string(value)
}

func relationExists(t *testing.T, pool *pgxpool.Pool, relation string) bool {
	t.Helper()
	var exists bool
	if err := pool.QueryRow(t.Context(), `SELECT to_regclass($1) IS NOT NULL`, relation).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	return exists
}

func requirePostgresCode(t *testing.T, err error, code string) {
	t.Helper()
	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) || postgresError.Code != code {
		t.Fatalf("PostgreSQL error = %v, want SQLSTATE %s", err, code)
	}
}

func assertPublicCredentialJSON(t *testing.T, credential Credential) {
	t.Helper()
	encoded, err := json.Marshal(credential)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"access_key", "secret", "ciphertext", "key_id", "sha256", "digest"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("public credential JSON leaked %q: %s", forbidden, encoded)
		}
	}
}
