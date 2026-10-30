//go:build integration

package identityverificationhttp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/identityverification"
	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var errInjectedEvidenceSourceAudit = errors.New("injected evidence source audit failure")

type failingEvidenceSourceAudit struct{}

func (failingEvidenceSourceAudit) Append(context.Context, pgx.Tx, audit.Event) error {
	return errInjectedEvidenceSourceAudit
}

func TestPostgresRuntimeEvidenceSourceIssuePrincipalBindsWorkloadReplayAndSession(t *testing.T) {
	pool := isolatedHTTPPool(t)
	now := time.Date(2036, 7, 26, 8, 30, 0, 0, time.UTC)
	clock := &integrationClock{value: now}
	tokens := evidenceSourceTokenManager(t)
	actor := insertHTTPActor(t, pool, tokens,
		insertHTTPScope(t, pool, "Evidence Issuer Tenant"), "evidence-issuer-owner")
	source := newPostgresEvidenceSource(t, pool, audit.New(pool), clock.now)
	principal := RuntimeEvidencePrincipal{TenantScopeID: actor.ScopeID, ActorUserID: actor.UserID,
		SessionID: actor.SessionID()}
	request := RuntimeEvidenceIssueRequest{
		Kind:                   identityverification.KindPersonalInitial,
		PrivateObjectReference: "identity/private/kyc/issuer-principal",
		PrivateEnvelopeDigest:  sha256.Sum256([]byte("issuer-private-envelope")),
		EvidenceClaimDigest:    sha256.Sum256([]byte("issuer-evidence-claim")),
		Evidence: integrationPersonalEvidence(identityverification.KindPersonalInitial,
			bytesOf(32, 0x21), 0x22),
		ExpiresAt:                    now.Add(15 * time.Minute),
		RequestID:                    "issuer-request-1",
		IssuerWorkloadID:             "kyc-issuer-1",
		IssuerCertificateFingerprint: sha256.Sum256([]byte("issuer-certificate")),
		IssuerIdempotencyKey:         "issuer-idempotency-secret-1",
		IssuerRequestDigest:          sha256.Sum256([]byte("issuer-http-request")),
	}

	issued, err := source.IssuePrincipal(t.Context(), principal, request)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := source.IssuePrincipal(t.Context(), principal, request)
	if err != nil || replayed != issued {
		t.Fatalf("principal issue replay = %#v, %v; want %#v", replayed, err, issued)
	}

	var workload string
	var certificateDigest, idempotencyDigest, issuerRequestDigest, tokenDigest []byte
	if err := pool.QueryRow(t.Context(), `SELECT workload_id,certificate_fingerprint,idempotency_digest,
		issuer_request_digest,token_digest FROM identity_verification_evidence_issue_bindings_v1`).Scan(
		&workload, &certificateDigest, &idempotencyDigest, &issuerRequestDigest, &tokenDigest); err != nil {
		t.Fatal(err)
	}
	expectedIdempotency := evidenceIssueIdempotencyDigest(request.IssuerIdempotencyKey)
	expectedToken := sha256.Sum256([]byte(issued.Token))
	if workload != request.IssuerWorkloadID || !bytes.Equal(certificateDigest, request.IssuerCertificateFingerprint[:]) ||
		!bytes.Equal(idempotencyDigest, expectedIdempotency[:]) ||
		!bytes.Equal(issuerRequestDigest, request.IssuerRequestDigest[:]) || !bytes.Equal(tokenDigest, expectedToken[:]) {
		t.Fatalf("persisted issuer binding is incomplete")
	}
	var reservations, bindings, audits int
	if err := pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM identity_verification_evidence_reservations),
		(SELECT count(*) FROM identity_verification_evidence_issue_bindings_v1),
		(SELECT count(*) FROM audit_events WHERE action='identity_verification.evidence_reservation.issued')`).Scan(
		&reservations, &bindings, &audits); err != nil || reservations != 1 || bindings != 1 || audits != 1 {
		t.Fatalf("principal issue facts = reservations:%d bindings:%d audits:%d err:%v", reservations, bindings, audits, err)
	}
	var leaked bool
	if err := pool.QueryRow(t.Context(), `SELECT EXISTS(
		SELECT 1 FROM identity_verification_evidence_issue_bindings_v1 binding
		WHERE row_to_json(binding)::text LIKE '%' || $1 || '%'
		UNION ALL SELECT 1 FROM audit_events WHERE payload::text LIKE '%' || $1 || '%' OR request_id=$1
	)`, request.IssuerIdempotencyKey).Scan(&leaked); err != nil || leaked {
		t.Fatalf("raw issuer idempotency key leaked = %t, %v", leaked, err)
	}

	conflict := request
	conflict.IssuerRequestDigest[0] ^= 0xff
	if _, err := source.IssuePrincipal(t.Context(), principal, conflict); !errors.Is(err, ErrEvidenceReservationConflict) {
		t.Fatalf("conflicting principal replay error = %v", err)
	}
	if err := pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM identity_verification_evidence_reservations),
		(SELECT count(*) FROM identity_verification_evidence_issue_bindings_v1),
		(SELECT count(*) FROM audit_events WHERE action='identity_verification.evidence_reservation.issued')`).Scan(
		&reservations, &bindings, &audits); err != nil || reservations != 1 || bindings != 1 || audits != 1 {
		t.Fatalf("conflicting replay wrote facts = reservations:%d bindings:%d audits:%d err:%v", reservations, bindings, audits, err)
	}

	if _, err := pool.Exec(t.Context(), `UPDATE auth_sessions SET revoked_at=$2,revocation_reason='test' WHERE id=$1`,
		principal.SessionID, now); err != nil {
		t.Fatal(err)
	}
	request.IssuerIdempotencyKey = "issuer-idempotency-secret-2"
	request.RequestID = "issuer-request-2"
	request.IssuerRequestDigest = sha256.Sum256([]byte("issuer-http-request-2"))
	if _, err := source.IssuePrincipal(t.Context(), principal, request); !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("revoked principal issue error = %v", err)
	}
	if err := pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM identity_verification_evidence_reservations),
		(SELECT count(*) FROM identity_verification_evidence_issue_bindings_v1),
		(SELECT count(*) FROM audit_events WHERE action='identity_verification.evidence_reservation.issued')`).Scan(
		&reservations, &bindings, &audits); err != nil || reservations != 1 || bindings != 1 || audits != 1 {
		t.Fatalf("revoked principal wrote facts = reservations:%d bindings:%d audits:%d err:%v", reservations, bindings, audits, err)
	}
}

func TestPostgresRuntimeEvidenceSourceIssueReserveReplayAndIsolation(t *testing.T) {
	pool := isolatedHTTPPool(t)
	now := time.Date(2036, 7, 26, 9, 0, 0, 0, time.UTC)
	clock := &integrationClock{value: now}
	tokens := evidenceSourceTokenManager(t)
	scope := insertHTTPScope(t, pool, "Evidence Source Tenant")
	otherScope := insertHTTPScope(t, pool, "Other Evidence Source Tenant")
	actor := insertHTTPActor(t, pool, tokens, scope, "evidence-owner")
	otherUser := insertHTTPActor(t, pool, tokens, scope, "other-evidence-user")
	otherTenant := insertHTTPActor(t, pool, tokens, otherScope, "other-evidence-tenant")
	source := newPostgresEvidenceSource(t, pool, audit.New(pool), clock.now)

	issued := issuePersonalEvidence(t, source, actor.Actor, now, "issue-primary", 0x31)
	issuedReplay := issuePersonalEvidence(t, source, actor.Actor, now, "issue-primary", 0x31)
	if issuedReplay != issued {
		t.Fatalf("issue replay changed result: first=%#v replay=%#v", issued, issuedReplay)
	}
	claimConflict := sha256.Sum256([]byte("different-claim"))
	if _, err := source.Issue(t.Context(), actor.Actor, RuntimeEvidenceIssueRequest{
		Kind: identityverification.KindPersonalInitial, PrivateObjectReference: "identity/private/kyc/issue-primary",
		PrivateEnvelopeDigest: sha256.Sum256([]byte("envelope-issue-primary")), EvidenceClaimDigest: claimConflict,
		Evidence:  integrationPersonalEvidence(identityverification.KindPersonalInitial, bytesOf(32, 0x31), 0x32),
		ExpiresAt: now.Add(time.Hour), RequestID: "issue-primary",
	}); !errors.Is(err, ErrEvidenceReservationConflict) {
		t.Fatalf("conflicting issue replay error=%v", err)
	}
	var issueAuditCount int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events
		WHERE action='identity_verification.evidence_reservation.issued' AND request_id='issue-primary'`).Scan(&issueAuditCount); err != nil || issueAuditCount != 1 {
		t.Fatalf("issue audit count=%d err=%v", issueAuditCount, err)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(issued.Token)
	if err != nil || len(decoded) < 32 {
		t.Fatalf("issued token entropy = %d bytes, %v", len(decoded), err)
	}
	tokenDigest := sha256.Sum256([]byte(issued.Token))
	var storedDigest []byte
	var state string
	var revision int64
	if err := pool.QueryRow(t.Context(), `SELECT token_digest,state,revision
		FROM identity_verification_evidence_reservations WHERE resolver_reference=$1`,
		issued.ResolverReference).Scan(&storedDigest, &state, &revision); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(storedDigest, tokenDigest[:]) || state != EvidenceStateIssued || revision != 1 {
		t.Fatalf("issued fact digest/state/revision = %x/%s/%d", storedDigest, state, revision)
	}
	var leaked bool
	if err := pool.QueryRow(t.Context(), `SELECT EXISTS (
		SELECT 1 FROM audit_events
		WHERE resource_id=$1 OR payload::text LIKE '%' || $1 || '%'
	)`, issued.Token).Scan(&leaked); err != nil || leaked {
		t.Fatalf("raw token leaked to audit = %t, %v", leaked, err)
	}

	request := RuntimeEvidenceReserveRequest{TenantScopeID: actor.ScopeID, ActorUserID: actor.UserID,
		SessionID: actor.SessionID(), Kind: identityverification.KindPersonalInitial, Token: issued.Token,
		IdempotencyKey: "create-primary", EvidenceRequestDigest: issued.EvidenceRequestDigest}
	reserved, err := source.Reserve(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	var storedIdempotencyDigest []byte
	var reservedAuditRequestID string
	if err := pool.QueryRow(t.Context(), `SELECT idempotency_digest
		FROM identity_verification_evidence_reservations WHERE resolver_reference=$1`,
		issued.ResolverReference).Scan(&storedIdempotencyDigest); err != nil {
		t.Fatal(err)
	}
	expectedIdempotencyDigest := evidenceReservationIdempotencyDigest(request.IdempotencyKey)
	if !bytes.Equal(storedIdempotencyDigest, expectedIdempotencyDigest[:]) {
		t.Fatalf("stored idempotency digest = %x", storedIdempotencyDigest)
	}
	if err := pool.QueryRow(t.Context(), `SELECT request_id FROM audit_events
		WHERE action='identity_verification.evidence_reservation.reserved'
		  AND resource_id=(SELECT id::text FROM identity_verification_evidence_reservations
		                   WHERE resolver_reference=$1)`, issued.ResolverReference).Scan(&reservedAuditRequestID); err != nil {
		t.Fatal(err)
	}
	if reservedAuditRequestID != evidenceReservationAuditRequestID(expectedIdempotencyDigest) {
		t.Fatalf("reserved audit request ID = %q", reservedAuditRequestID)
	}
	replayed, err := source.Reserve(t.Context(), request)
	if err != nil || replayed.ReservationID != reserved.ReservationID ||
		replayed.ResolverReference != reserved.ResolverReference ||
		replayed.EvidenceClaimDigest != reserved.EvidenceClaimDigest {
		t.Fatalf("reserve replay = %#v, %v", replayed, err)
	}
	if !equalRuntimeEvidence(replayed.Evidence, reserved.Evidence) || reserved.ReservationID != issued.Token {
		t.Fatal("reserve replay changed trusted evidence or reservation token")
	}
	conflict := request
	conflict.IdempotencyKey = "create-conflict"
	if _, err := source.Reserve(t.Context(), conflict); !errors.Is(err, ErrEvidenceReservationConflict) {
		t.Fatalf("different idempotency reserve error = %v", err)
	}
	duplicateKeyIssued := issuePersonalEvidence(t, source, actor.Actor, now, "issue-duplicate-key", 0x39)
	duplicateKey := request
	duplicateKey.Token = duplicateKeyIssued.Token
	duplicateKey.EvidenceRequestDigest = duplicateKeyIssued.EvidenceRequestDigest
	if _, err := source.Reserve(t.Context(), duplicateKey); !errors.Is(err, ErrEvidenceReservationConflict) {
		t.Fatalf("duplicate idempotency digest reserve error = %v", err)
	}
	wrongKind := request
	wrongKind.Kind = identityverification.KindPersonalReverification
	wrongDigest := request
	wrongDigest.EvidenceRequestDigest[0] ^= 0xff
	for name, wrong := range map[string]RuntimeEvidenceReserveRequest{
		"kind":   wrongKind,
		"digest": wrongDigest,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := source.Reserve(t.Context(), wrong); !errors.Is(err, ErrEvidenceReservationConflict) {
				t.Fatalf("different binding reserve error = %v", err)
			}
		})
	}
	wrongSession := request
	wrongSession.SessionID = otherUser.SessionID()
	if _, err := source.Reserve(t.Context(), wrongSession); !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("wrong session reserve error = %v", err)
	}
	secondSessionID := uuid.New()
	secondSessionHash := sha256.Sum256(secondSessionID[:])
	if _, err := pool.Exec(t.Context(), `INSERT INTO auth_sessions(
		id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at
	) VALUES($1,$1,$2,$3,$4,$5,$6)`, secondSessionID, actor.UserID, actor.ScopeID,
		secondSessionHash[:], now.Add(-time.Hour), now.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	otherValidSession := request
	otherValidSession.SessionID = secondSessionID
	if _, err := source.Reserve(t.Context(), otherValidSession); !errors.Is(err, ErrEvidenceReservationConflict) {
		t.Fatalf("other valid session reserve error = %v", err)
	}
	for name, wrong := range map[string]RuntimeEvidenceReserveRequest{
		"user":   withEvidenceActor(request, otherUser),
		"tenant": withEvidenceActor(request, otherTenant),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := source.Reserve(t.Context(), wrong); !errors.Is(err, ErrInvalidEvidence) {
				t.Fatalf("cross principal reserve error = %v", err)
			}
		})
	}
	if err := pool.QueryRow(t.Context(), `SELECT state,revision FROM identity_verification_evidence_reservations
		WHERE resolver_reference=$1`, issued.ResolverReference).Scan(&state, &revision); err != nil {
		t.Fatal(err)
	}
	if state != EvidenceStateReserved || revision != 2 {
		t.Fatalf("reserved state/revision = %s/%d", state, revision)
	}

	expiring := issuePersonalEvidence(t, source, actor.Actor, now, "issue-expiring", 0x41)
	clock.set(expiring.ExpiresAt)
	expiredRequest := request
	expiredRequest.Token = expiring.Token
	expiredRequest.EvidenceRequestDigest = expiring.EvidenceRequestDigest
	expiredRequest.IdempotencyKey = "create-expired"
	if _, err := source.Reserve(t.Context(), expiredRequest); !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("expired reserve error = %v", err)
	}
	clock.set(now)
}

func TestPostgresRuntimeEvidenceSourceDoesNotPersistSensitiveIdempotencyKeys(t *testing.T) {
	pool := isolatedHTTPPool(t)
	now := time.Date(2036, 7, 26, 9, 30, 0, 0, time.UTC)
	clock := &integrationClock{value: now}
	tokens := evidenceSourceTokenManager(t)
	actor := insertHTTPActor(t, pool, tokens,
		insertHTTPScope(t, pool, "Evidence Secret Tenant"), "evidence-secret-owner")
	source := newPostgresEvidenceSource(t, pool, audit.New(pool), clock.now)

	for name, keyFor := range map[string]func(RuntimeEvidenceIssueResult, RuntimeEvidenceIssueResult) string{
		"raw reservation token":          func(issued, _ RuntimeEvidenceIssueResult) string { return issued.Token },
		"another reservation token":      func(_, other RuntimeEvidenceIssueResult) string { return other.Token },
		"key containing token":           func(issued, _ RuntimeEvidenceIssueResult) string { return "secret-" + issued.Token },
		"arbitrary long sensitive value": func(_, _ RuntimeEvidenceIssueResult) string { return "secret-" + strings.Repeat("x", 121) },
	} {
		t.Run(name, func(t *testing.T) {
			issued := issuePersonalEvidence(t, source, actor.Actor, now, "issue-sensitive-"+strings.ReplaceAll(name, " ", "-"), 0xb1)
			other := issuePersonalEvidence(t, source, actor.Actor, now, "issue-other-"+strings.ReplaceAll(name, " ", "-"), 0xb2)
			key := keyFor(issued, other)
			request := RuntimeEvidenceReserveRequest{TenantScopeID: actor.ScopeID,
				ActorUserID: actor.UserID, SessionID: actor.SessionID(),
				Kind: identityverification.KindPersonalInitial, Token: issued.Token,
				IdempotencyKey: key, EvidenceRequestDigest: issued.EvidenceRequestDigest}
			if _, err := source.Reserve(t.Context(), request); err != nil {
				t.Fatal(err)
			}

			var reservationText, auditText string
			if err := pool.QueryRow(t.Context(), `SELECT row_to_json(reservation)::text
				FROM identity_verification_evidence_reservations reservation
				WHERE resolver_reference=$1`, issued.ResolverReference).Scan(&reservationText); err != nil {
				t.Fatal(err)
			}
			if err := pool.QueryRow(t.Context(), `SELECT string_agg(concat_ws('|',
				request_id,action,resource_type,resource_id,payload::text), '|')
				FROM audit_events WHERE resource_type='identity_verification_evidence_reservation'
				  AND resource_id=(SELECT id::text FROM identity_verification_evidence_reservations
				                   WHERE resolver_reference=$1)`, issued.ResolverReference).Scan(&auditText); err != nil {
				t.Fatal(err)
			}
			for label, secret := range map[string]string{"raw token": issued.Token, "raw key": key} {
				if strings.Contains(reservationText, secret) {
					t.Errorf("reservation contains %s", label)
				}
				if strings.Contains(auditText, secret) {
					t.Errorf("audit contains %s", label)
				}
			}
		})
	}
}

func TestPostgresRuntimeEvidenceSourceConcurrentReservationAndTerminalCAS(t *testing.T) {
	pool := isolatedHTTPPool(t)
	now := time.Date(2036, 7, 26, 10, 0, 0, 0, time.UTC)
	clock := &integrationClock{value: now}
	tokens := evidenceSourceTokenManager(t)
	actor := insertHTTPActor(t, pool, tokens, insertHTTPScope(t, pool, "Evidence CAS Tenant"), "cas-owner")
	source := newPostgresEvidenceSource(t, pool, audit.New(pool), clock.now)
	issued := issuePersonalEvidence(t, source, actor.Actor, now, "issue-race", 0x51)

	base := RuntimeEvidenceReserveRequest{TenantScopeID: actor.ScopeID, ActorUserID: actor.UserID,
		SessionID: actor.SessionID(), Kind: identityverification.KindPersonalInitial,
		Token: issued.Token, EvidenceRequestDigest: issued.EvidenceRequestDigest}
	start := make(chan struct{})
	results := make(chan string, 2)
	var wait sync.WaitGroup
	for _, key := range []string{"race-a", "race-b"} {
		wait.Add(1)
		go func(key string) {
			defer wait.Done()
			<-start
			request := base
			request.IdempotencyKey = key
			_, err := source.Reserve(context.Background(), request)
			switch {
			case err == nil:
				results <- "success:" + key
			case errors.Is(err, ErrEvidenceReservationConflict):
				results <- "conflict:" + key
			default:
				results <- fmt.Sprintf("unexpected:%s:%v", key, err)
			}
		}(key)
	}
	close(start)
	wait.Wait()
	close(results)
	counts := map[string]int{}
	for result := range results {
		counts[result[:bytes.IndexByte([]byte(result), ':')]]++
	}
	if counts["success"] != 1 || counts["conflict"] != 1 || counts["unexpected"] != 0 {
		t.Fatalf("concurrent reserve outcomes = %#v", counts)
	}

	terminalIssued := issuePersonalEvidence(t, source, actor.Actor, now, "issue-terminal-race", 0x59)
	terminalRequest := base
	terminalRequest.Token = terminalIssued.Token
	terminalRequest.EvidenceRequestDigest = terminalIssued.EvidenceRequestDigest
	terminalRequest.IdempotencyKey = "terminal-race"
	if _, err := source.Reserve(t.Context(), terminalRequest); err != nil {
		t.Fatal(err)
	}
	terminalStart := make(chan struct{})
	terminalResults := make(chan error, 2)
	for _, transition := range []func(context.Context, string) error{source.Abort, source.Quarantine} {
		wait.Add(1)
		go func(transition func(context.Context, string) error) {
			defer wait.Done()
			<-terminalStart
			terminalResults <- transition(context.Background(), terminalIssued.Token)
		}(transition)
	}
	close(terminalStart)
	wait.Wait()
	close(terminalResults)
	terminalSuccess, terminalInvalid := 0, 0
	for err := range terminalResults {
		switch {
		case err == nil:
			terminalSuccess++
		case errors.Is(err, ErrInvalidEvidence):
			terminalInvalid++
		default:
			t.Fatalf("unexpected terminal race error = %v", err)
		}
	}
	if terminalSuccess != 1 || terminalInvalid != 1 {
		t.Fatalf("terminal race outcomes = success:%d invalid:%d", terminalSuccess, terminalInvalid)
	}

	abortIssued := issuePersonalEvidence(t, source, actor.Actor, now, "issue-abort", 0x61)
	abortRequest := base
	abortRequest.Token, abortRequest.EvidenceRequestDigest = abortIssued.Token, abortIssued.EvidenceRequestDigest
	abortRequest.IdempotencyKey = "abort-key"
	if _, err := source.Reserve(t.Context(), abortRequest); err != nil {
		t.Fatal(err)
	}
	if err := source.Abort(t.Context(), abortIssued.Token); err != nil {
		t.Fatal(err)
	}
	if err := source.Abort(t.Context(), abortIssued.Token); err != nil {
		t.Fatalf("abort replay = %v", err)
	}
	if err := source.Quarantine(t.Context(), abortIssued.Token); !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("abort to quarantine error = %v", err)
	}

	quarantineIssued := issuePersonalEvidence(t, source, actor.Actor, now, "issue-quarantine", 0x71)
	quarantineRequest := base
	quarantineRequest.Token = quarantineIssued.Token
	quarantineRequest.EvidenceRequestDigest = quarantineIssued.EvidenceRequestDigest
	quarantineRequest.IdempotencyKey = "quarantine-key"
	if _, err := source.Reserve(t.Context(), quarantineRequest); err != nil {
		t.Fatal(err)
	}
	if err := source.Quarantine(t.Context(), quarantineIssued.Token); err != nil {
		t.Fatal(err)
	}
	if err := source.Quarantine(t.Context(), quarantineIssued.Token); err != nil {
		t.Fatalf("quarantine replay = %v", err)
	}
	if err := source.Abort(t.Context(), quarantineIssued.Token); !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("quarantine to abort error = %v", err)
	}
}

func TestPostgresRuntimeEvidenceSourcePublishTamperAndAuditRollback(t *testing.T) {
	fixture := newHTTPIntegrationFixture(t)
	now := fixture.clock.now()
	source := newPostgresEvidenceSource(t, fixture.pool, audit.New(fixture.pool), fixture.clock.now)
	failing := newPostgresEvidenceSource(t, fixture.pool, failingEvidenceSourceAudit{}, fixture.clock.now)
	rollbackIssued := issuePersonalEvidence(t, source, fixture.applicant.Actor, now, "issue-rollback", 0x91)
	rollbackRequest := RuntimeEvidenceReserveRequest{TenantScopeID: fixture.applicant.ScopeID,
		ActorUserID: fixture.applicant.UserID, SessionID: fixture.applicant.SessionID(),
		Kind: identityverification.KindPersonalInitial, Token: rollbackIssued.Token,
		IdempotencyKey: "rollback-key", EvidenceRequestDigest: rollbackIssued.EvidenceRequestDigest}
	if _, err := failing.Reserve(t.Context(), rollbackRequest); !errors.Is(err, ErrEvidenceUnavailable) {
		t.Fatalf("audit failure reserve = %v", err)
	}
	var state string
	var revision int64
	if err := fixture.pool.QueryRow(t.Context(), `SELECT state,revision
		FROM identity_verification_evidence_reservations WHERE resolver_reference=$1`,
		rollbackIssued.ResolverReference).Scan(&state, &revision); err != nil {
		t.Fatal(err)
	}
	if state != EvidenceStateIssued || revision != 1 {
		t.Fatalf("audit rollback state/revision = %s/%d", state, revision)
	}

	issued := issuePersonalEvidence(t, source, fixture.applicant.Actor, now, "issue-publish", 0x81)
	reserveRequest := RuntimeEvidenceReserveRequest{TenantScopeID: fixture.applicant.ScopeID,
		ActorUserID: fixture.applicant.UserID, SessionID: fixture.applicant.SessionID(),
		Kind: identityverification.KindPersonalInitial, Token: issued.Token,
		IdempotencyKey: "publish-create", EvidenceRequestDigest: issued.EvidenceRequestDigest}
	reservation, err := source.Reserve(t.Context(), reserveRequest)
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := fixture.core.CreateDraftWithSettlement(t.Context(), fixture.applicant.Actor,
		identityverification.CreateDraftRequest{Kind: reservation.Evidence.Kind,
			SubjectFingerprint: reservation.Evidence.SubjectFingerprint,
			Materials:          reservation.Evidence.Materials, ResolverName: "trusted-kyc",
			ResolverReference:   reservation.ResolverReference,
			EvidenceClaimDigest: reservation.EvidenceClaimDigest,
			IdempotencyKey:      "publish-create", RequestID: "request-publish-create"})
	if err != nil {
		t.Fatal(err)
	}
	var coreDigest []byte
	if err := fixture.pool.QueryRow(t.Context(), `SELECT request_digest
		FROM identity_verification_evidence_settlements WHERE case_id=$1`,
		outcome.Case.ID).Scan(&coreDigest); err != nil {
		t.Fatal(err)
	}
	request := RuntimeEvidencePublishRequest{ResolverReference: reservation.ResolverReference,
		TenantScopeID: fixture.applicant.ScopeID, ActorUserID: fixture.applicant.UserID,
		CaseID: outcome.Case.ID, IdempotencyKey: "publish-create",
		EvidenceClaimDigest: reservation.EvidenceClaimDigest}
	copy(request.CoreRequestDigest[:], coreDigest)
	if err := failing.Publish(t.Context(), request); !errors.Is(err, ErrEvidenceUnavailable) {
		t.Fatalf("audit failure publish = %v", err)
	}
	if err := fixture.pool.QueryRow(t.Context(), `SELECT state,revision
		FROM identity_verification_evidence_reservations WHERE resolver_reference=$1`,
		reservation.ResolverReference).Scan(&state, &revision); err != nil {
		t.Fatal(err)
	}
	if state != EvidenceStateReserved || revision != 2 {
		t.Fatalf("publish audit rollback state/revision = %s/%d", state, revision)
	}
	if err := source.Publish(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	if err := source.Publish(t.Context(), request); err != nil {
		t.Fatalf("publish replay = %v", err)
	}
	for name, mutate := range map[string]func(*RuntimeEvidencePublishRequest){
		"case":  func(value *RuntimeEvidencePublishRequest) { value.CaseID = uuid.New() },
		"core":  func(value *RuntimeEvidencePublishRequest) { value.CoreRequestDigest[0] ^= 0xff },
		"claim": func(value *RuntimeEvidencePublishRequest) { value.EvidenceClaimDigest[0] ^= 0xff },
	} {
		t.Run(name, func(t *testing.T) {
			conflict := request
			mutate(&conflict)
			if err := source.Publish(t.Context(), conflict); !errors.Is(err, ErrEvidenceReservationConflict) {
				t.Fatalf("publish conflict = %v", err)
			}
		})
	}
	if _, err := fixture.pool.Exec(t.Context(), `UPDATE identity_verification_evidence_reservations
		SET private_envelope_digest=$2 WHERE resolver_reference=$1`,
		reservation.ResolverReference, bytesOf(32, 0xee)); err == nil {
		t.Fatal("immutable evidence payload tamper succeeded")
	}
}

func TestPostgresRuntimeEvidenceSourceReadinessAndMigration075Guards(t *testing.T) {
	// Migration 268's down is a deliberate one-way gate (P2682): seed at 075,
	// round-trip 075 with only 1..075 loaded, then roll forward to the head.
	pool := isolatedHTTPSchema(t, false)
	if err := databasetest.MigrateThrough(t.Context(), pool, "up", 75); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2036, 7, 26, 11, 0, 0, 0, time.UTC)
	tokens := evidenceSourceTokenManager(t)
	actor := insertHTTPActor(t, pool, tokens, insertHTTPScope(t, pool, "Evidence Migration Tenant"), "migration-owner")

	if err := databasetest.MigrateThrough(t.Context(), pool, "down", 75); err != nil {
		t.Fatal(err)
	}
	if source, err := NewPostgresRuntimeEvidenceSource(t.Context(), pool, audit.New(pool),
		PostgresRuntimeEvidenceSourceConfig{ResolverName: "trusted-kyc", IssueTokenKey: bytes.Repeat([]byte{0x71}, 32), Clock: func() time.Time { return now }}); source != nil ||
		!errors.Is(err, ErrTrustedEvidenceSourceRequired) {
		t.Fatalf("missing schema constructor = (%T,%v)", source, err)
	}
	if err := database.Migrate(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	var legacyMembership bool
	if err := pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM memberships
		WHERE scope_id=$1 AND user_id=$2)`, actor.ScopeID, actor.UserID).Scan(&legacyMembership); err != nil ||
		!legacyMembership {
		t.Fatalf("legacy membership retained = %t, %v", legacyMembership, err)
	}
	source := newPostgresEvidenceSource(t, pool, audit.New(pool), func() time.Time { return now })
	if err := source.Ready(t.Context()); err != nil || source.Capabilities() != productionEvidenceCapabilities() {
		t.Fatalf("ready/capabilities = %v/%#v", err, source.Capabilities())
	}
	if _, err := pool.Exec(t.Context(), `ALTER TABLE identity_verification_evidence_reservations
		ADD COLUMN unexpected_legacy_key text`); err != nil {
		t.Fatal(err)
	}
	if err := source.Ready(t.Context()); !errors.Is(err, ErrTrustedEvidenceSourceRequired) {
		t.Fatalf("extra reservation column ready = %v", err)
	}
	if _, err := pool.Exec(t.Context(), `ALTER TABLE identity_verification_evidence_reservations
		DROP COLUMN unexpected_legacy_key`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `ALTER TABLE identity_verification_evidence_reservations
		RENAME COLUMN idempotency_digest TO idempotency_key`); err != nil {
		t.Fatal(err)
	}
	if err := source.Ready(t.Context()); !errors.Is(err, ErrTrustedEvidenceSourceRequired) {
		t.Fatalf("legacy idempotency column ready = %v", err)
	}
	if _, err := pool.Exec(t.Context(), `ALTER TABLE identity_verification_evidence_reservations
		RENAME COLUMN idempotency_key TO idempotency_digest`); err != nil {
		t.Fatal(err)
	}
	if err := source.Ready(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `ALTER TABLE identity_verification_evidence_reservations
		DISABLE TRIGGER identity_verification_evidence_reservations_require_audit_075`); err != nil {
		t.Fatal(err)
	}
	if err := source.Ready(t.Context()); !errors.Is(err, ErrTrustedEvidenceSourceRequired) ||
		source.Capabilities() != (RuntimeEvidenceSourceCapabilities{}) {
		t.Fatalf("disabled audit trigger ready/capabilities = %v/%#v", err, source.Capabilities())
	}
	if _, err := pool.Exec(t.Context(), `ALTER TABLE identity_verification_evidence_reservations
		ENABLE ALWAYS TRIGGER identity_verification_evidence_reservations_require_audit_075`); err != nil {
		t.Fatal(err)
	}
	if err := source.Ready(t.Context()); err != nil {
		t.Fatal(err)
	}
	issued := issuePersonalEvidence(t, source, actor.Actor, now, "issue-down-guard", 0xa1)
	if _, err := pool.Exec(t.Context(), `UPDATE identity_verification_evidence_reservations
		SET idempotency_digest=$2,state='reserved',revision=2,updated_at=$3
		WHERE resolver_reference=$1`, issued.ResolverReference, bytesOf(31, 0xa2), now); err == nil {
		t.Fatal("direct SQL accepted a non-SHA-256 idempotency digest")
	}
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role='replica'`); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `UPDATE identity_verification_evidence_reservations
			SET idempotency_digest=$2,state='reserved',revision=2,updated_at=$3
			WHERE resolver_reference=$1`, issued.ResolverReference, bytesOf(32, 0xa3), now)
		return err
	}); err == nil {
		t.Fatal("replica mode bypassed the deferred audit trigger")
	}
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role='replica'`); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `UPDATE identity_verification_evidence_reservations
			SET private_envelope_digest=$2 WHERE resolver_reference=$1`,
			issued.ResolverReference, bytesOf(32, 0xa4))
		return err
	}); err == nil {
		t.Fatal("replica mode bypassed the immutable reservation trigger")
	}
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role='replica'`); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `TRUNCATE identity_verification_evidence_reservations`)
		return err
	}); err == nil {
		t.Fatal("replica mode bypassed the no-truncate trigger")
	}
	// At the release head, run 075's down script itself: it must refuse while
	// evidence facts exist.
	downScript, err := fs.ReadFile(controlmigrations.FS, "075_identity_verification_evidence_reservations.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		_, execErr := tx.Exec(t.Context(), string(downScript))
		return execErr
	}); err == nil || !strings.Contains(err.Error(), "while facts exist") {
		t.Fatalf("migration 075 down with evidence facts error = %v", err)
	}
	var version bool
	if err := pool.QueryRow(t.Context(), `SELECT EXISTS(
		SELECT 1 FROM schema_migrations WHERE version=75)`).Scan(&version); err != nil || !version {
		t.Fatalf("migration 075 retained = %t, %v", version, err)
	}
	if _, err := pool.Exec(t.Context(), `SELECT token_digest FROM identity_verification_evidence_reservations
		WHERE resolver_reference=$1`, issued.ResolverReference); err != nil {
		t.Fatal(err)
	}
	source.Close()
	if err := source.Ready(t.Context()); !errors.Is(err, ErrTrustedEvidenceSourceRequired) ||
		source.Capabilities() != (RuntimeEvidenceSourceCapabilities{}) {
		t.Fatalf("closed source ready/capabilities = %v/%#v", err, source.Capabilities())
	}
}

func newPostgresEvidenceSource(t *testing.T, pool *pgxpool.Pool, auditor identityverification.AuditAppender,
	clock identityverification.Clock,
) *PostgresRuntimeEvidenceSource {
	t.Helper()
	source, err := NewPostgresRuntimeEvidenceSource(t.Context(), pool, auditor,
		PostgresRuntimeEvidenceSourceConfig{ResolverName: "trusted-kyc", IssueTokenKey: bytes.Repeat([]byte{0x71}, 32), Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	return source
}

func evidenceSourceTokenManager(t *testing.T) *identity.TokenManager {
	t.Helper()
	tokens, err := identity.NewTokenManager("identity-evidence-source-session-secret-2026", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return tokens
}

func issuePersonalEvidence(t *testing.T, source *PostgresRuntimeEvidenceSource,
	actor identityverification.Actor, now time.Time, requestID string, marker byte,
) RuntimeEvidenceIssueResult {
	t.Helper()
	claimDigest := sha256.Sum256([]byte("claim-" + requestID))
	result, err := source.Issue(t.Context(), actor, RuntimeEvidenceIssueRequest{
		Kind:                   identityverification.KindPersonalInitial,
		PrivateObjectReference: "identity/private/kyc/" + requestID,
		PrivateEnvelopeDigest:  sha256.Sum256([]byte("envelope-" + requestID)),
		EvidenceClaimDigest:    claimDigest,
		Evidence: integrationPersonalEvidence(identityverification.KindPersonalInitial,
			bytesOf(32, marker), marker+1),
		ExpiresAt: now.Add(time.Hour), RequestID: requestID,
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func withEvidenceActor(request RuntimeEvidenceReserveRequest, actor integrationActor) RuntimeEvidenceReserveRequest {
	request.TenantScopeID = actor.ScopeID
	request.ActorUserID = actor.UserID
	request.SessionID = actor.SessionID()
	return request
}

func equalRuntimeEvidence(left, right ResolvedEvidence) bool {
	return left.Kind == right.Kind && bytes.Equal(left.SubjectFingerprint, right.SubjectFingerprint) &&
		left.OrganizationName == right.OrganizationName &&
		bytes.Equal(left.LegalPersonFingerprint, right.LegalPersonFingerprint) &&
		bytes.Equal(left.AgentFingerprint, right.AgentFingerprint) &&
		left.AgentRelationship == right.AgentRelationship && fmt.Sprintf("%#v", left.Materials) == fmt.Sprintf("%#v", right.Materials)
}
