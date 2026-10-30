package mfa

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/iamstage2b"
	"github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var mfaTestNow = time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)

type testClock struct {
	mu  sync.RWMutex
	now time.Time
}

func (clock *testClock) Now() time.Time {
	clock.mu.RLock()
	defer clock.mu.RUnlock()
	return clock.now
}

func (clock *testClock) Add(duration time.Duration) {
	clock.mu.Lock()
	clock.now = clock.now.Add(duration)
	clock.mu.Unlock()
}

type keyringCipher struct {
	mu      sync.RWMutex
	active  string
	keyring map[string]cipher.AEAD
}

type countingCipher struct {
	inner        EnvelopeCipher
	decryptCalls int
}

func (cipher *countingCipher) Encrypt(plaintext []byte) (string, []byte, error) {
	return cipher.inner.Encrypt(plaintext)
}

func (cipher *countingCipher) Decrypt(keyID string, ciphertext []byte) ([]byte, error) {
	cipher.decryptCalls++
	return cipher.inner.Decrypt(keyID, ciphertext)
}

func newKeyringCipher(t *testing.T) *keyringCipher {
	t.Helper()
	result := &keyringCipher{keyring: make(map[string]cipher.AEAD)}
	result.Add(t, "mfa-kek-v1", bytes.Repeat([]byte{1}, 32), true)
	return result
}

func (ring *keyringCipher) Add(t *testing.T, keyID string, key []byte, active bool) {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	ring.mu.Lock()
	defer ring.mu.Unlock()
	ring.keyring[keyID] = aead
	if active {
		ring.active = keyID
	}
}

func (ring *keyringCipher) Encrypt(plaintext []byte) (string, []byte, error) {
	ring.mu.RLock()
	defer ring.mu.RUnlock()
	aead := ring.keyring[ring.active]
	if aead == nil {
		return "", nil, errors.New("test cipher unavailable")
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", nil, err
	}
	return ring.active, append(nonce, aead.Seal(nil, nonce, plaintext, []byte(ring.active))...), nil
}

func (ring *keyringCipher) Decrypt(keyID string, ciphertext []byte) ([]byte, error) {
	ring.mu.RLock()
	defer ring.mu.RUnlock()
	aead := ring.keyring[keyID]
	if aead == nil || len(ciphertext) <= aead.NonceSize() {
		return nil, errors.New("test cipher unavailable")
	}
	return aead.Open(nil, ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():], []byte(keyID))
}

func (ring *keyringCipher) Remove(keyID string) {
	ring.mu.Lock()
	defer ring.mu.Unlock()
	delete(ring.keyring, keyID)
}

type tenantRecord struct {
	id      uuid.UUID
	scopeID uuid.UUID
}

type mfaFixture struct {
	pool          *pgxpool.Pool
	clock         *testClock
	cipher        *keyringCipher
	service       *Service
	actor         Actor
	roleID        uuid.UUID
	tenantA       tenantRecord
	tenantB       tenantRecord
	permissionTwo string
}

func TestMigration041RoundTrip(t *testing.T) {
	pool := isolatedMFAPool(t, false)
	migrateMFAThrough41(t, pool)
	assertMFAMigrationVersion(t, pool, 41)
	assertMFATable(t, pool, "mfa_credentials", true)
	assertMFATrigger(t, pool, "mfa_step_up_uses", "mfa_step_up_uses_append_only", true)

	applyMFAMigrationFile(t, pool, "041_mfa.down.sql", 41, false)
	assertMFATable(t, pool, "mfa_credentials", false)
	applyMFAMigrationFile(t, pool, "041_mfa.up.sql", 41, true)
	assertMFAMigrationApplied(t, pool, 41, true)
	assertMFATable(t, pool, "mfa_step_up_proofs", true)
}

func TestStatusUsesLivePrincipalAndImmutableCredentialFacts(t *testing.T) {
	t.Run("inactive pending expired", func(t *testing.T) {
		fixture := newMFAFixture(t)
		status, err := fixture.service.Status(t.Context(), fixture.actor)
		if err != nil || status.Status != StatusInactive || status.CredentialID != uuid.Nil ||
			status.Method != "" || status.EnrollmentExpiresAt != nil {
			t.Fatalf("initial Status = (%+v,%v)", status, err)
		}
		enrollment := fixture.begin(t, "status-pending")
		status, err = fixture.service.Status(t.Context(), fixture.actor)
		if err != nil || status.Status != StatusPending || status.CredentialID != enrollment.CredentialID ||
			status.Method != MethodTOTP || status.EnrollmentExpiresAt == nil ||
			!status.EnrollmentExpiresAt.Equal(enrollment.ExpiresAt) {
			t.Fatalf("pending Status = (%+v,%v)", status, err)
		}
		fixture.clock.Add(defaultEnrollmentTTL)
		status, err = fixture.service.Status(t.Context(), fixture.actor)
		if err != nil || status.Status != StatusInactive || status.CredentialID != uuid.Nil ||
			status.Method != "" || status.EnrollmentExpiresAt != nil {
			t.Fatalf("expired Status = (%+v,%v)", status, err)
		}
	})

	t.Run("active disabled reset", func(t *testing.T) {
		for _, eventType := range []string{"disabled", "reset"} {
			t.Run(eventType, func(t *testing.T) {
				fixture := newMFAFixture(t)
				enrollment, recoveryCodes := fixture.activate(t, "status-"+eventType)
				status, err := fixture.service.Status(t.Context(), fixture.actor)
				if err != nil || status.Status != StatusActive ||
					status.CredentialID != enrollment.CredentialID || status.Method != MethodTOTP ||
					status.EnrollmentExpiresAt != nil {
					t.Fatalf("active Status = (%+v,%v)", status, err)
				}
				request := DeactivateRequest{Authentication: Authentication{
					Method: MethodRecoveryCode, Code: recoveryCodes[0]}, Reason: "status test",
					IdempotencyKey: "status-" + eventType, Context: requestContext("status-" + eventType)}
				if eventType == "disabled" {
					err = fixture.service.Disable(t.Context(), fixture.actor, request)
				} else {
					err = fixture.service.Reset(t.Context(), fixture.actor, request)
				}
				if err != nil {
					t.Fatal(err)
				}
				status, err = fixture.service.Status(t.Context(), fixture.actor)
				if err != nil || status.Status != StatusInactive || status.CredentialID != uuid.Nil ||
					status.Method != "" || status.EnrollmentExpiresAt != nil {
					t.Fatalf("terminal Status = (%+v,%v)", status, err)
				}
			})
		}
	})

	t.Run("revocation and scope binding", func(t *testing.T) {
		tests := []struct {
			name    string
			mutate  func(*testing.T, mfaFixture) Actor
			wantErr error
		}{
			{"session", func(t *testing.T, fixture mfaFixture) Actor {
				_, err := fixture.pool.Exec(t.Context(), `UPDATE auth_sessions
					SET revoked_at=$2,revocation_reason='status-test' WHERE id=$1`,
					fixture.actor.SessionID, fixture.clock.Now())
				if err != nil {
					t.Fatal(err)
				}
				return fixture.actor
			}, ErrInvalidSession},
			{"user", func(t *testing.T, fixture mfaFixture) Actor {
				if _, err := fixture.pool.Exec(t.Context(), `UPDATE users
					SET status='disabled',revision=revision+1 WHERE id=$1`, fixture.actor.UserID); err != nil {
					t.Fatal(err)
				}
				return fixture.actor
			}, ErrPrincipalChanged},
			{"membership", func(t *testing.T, fixture mfaFixture) Actor {
				if _, err := fixture.pool.Exec(t.Context(), `UPDATE memberships
					SET status='suspended' WHERE scope_id=$1 AND user_id=$2`,
					fixture.actor.ScopeID, fixture.actor.UserID); err != nil {
					t.Fatal(err)
				}
				return fixture.actor
			}, ErrPrincipalChanged},
			{"scope", func(_ *testing.T, fixture mfaFixture) Actor {
				actor := fixture.actor
				actor.ScopeID = fixture.tenantA.scopeID
				return actor
			}, ErrInvalidSession},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				fixture := newMFAFixture(t)
				actor := test.mutate(t, fixture)
				if _, err := fixture.service.Status(t.Context(), actor); !errors.Is(err, test.wantErr) {
					t.Fatalf("Status error = %v, want %v", err, test.wantErr)
				}
			})
		}
	})
}

func TestEnrollActivateVerifyDriftReplayAndSecretHandling(t *testing.T) {
	fixture := newMFAFixture(t)
	enrollment := fixture.begin(t, "enroll-main")
	if enrollment.Secret == "" || !strings.HasPrefix(enrollment.ProvisioningURI, "otpauth://totp/") {
		t.Fatal("enrollment omitted one-time setup material")
	}
	replayedEnrollment := fixture.begin(t, "enroll-main")
	if !replayedEnrollment.Replayed || replayedEnrollment.CredentialID != enrollment.CredentialID ||
		!replayedEnrollment.ExpiresAt.Equal(enrollment.ExpiresAt) || replayedEnrollment.Secret != "" ||
		replayedEnrollment.ProvisioningURI != "" {
		t.Fatal("BeginEnrollment replay contract mismatch")
	}

	secret := decodeTOTPSecret(enrollment.Secret)
	var keyID string
	var ciphertext []byte
	if err := fixture.pool.QueryRow(t.Context(), `SELECT secret_key_id,secret_ciphertext
		FROM mfa_credentials WHERE id=$1`, enrollment.CredentialID).Scan(&keyID, &ciphertext); err != nil {
		t.Fatal(err)
	}
	if keyID != "mfa-kek-v1" || bytes.Contains(ciphertext, secret) || bytes.Contains(ciphertext, []byte(enrollment.Secret)) {
		t.Fatalf("seed persistence contract mismatch: ciphertext_contains_secret=%t", bytes.Contains(ciphertext, secret))
	}

	code := currentCode(secret, fixture.clock.Now())
	if _, err := fixture.service.CreateStepUp(t.Context(), fixture.actor, StepUpRequest{
		TenantID: fixture.tenantA.id, Audience: "impersonation", Action: "grant.create",
		Authentication: Authentication{Method: MethodTOTP, Code: code}, TTL: time.Minute,
		MaxUses: 1, IdempotencyKey: "pending-proof", Context: requestContext("pending-proof"),
	}); !errors.Is(err, ErrNotActive) {
		t.Fatalf("pending credential CreateStepUp error = %v", err)
	}

	if _, err := fixture.service.Activate(t.Context(), fixture.actor, ActivationRequest{
		CredentialID: enrollment.CredentialID, Code: "000000", IdempotencyKey: "activate-bad",
		Context: requestContext("activate-bad"),
	}); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("Activate(invalid challenge) error = %v", err)
	}
	assertCount(t, fixture.pool, "mfa_recovery_codes", 0)

	activated, err := fixture.service.Activate(t.Context(), fixture.actor, ActivationRequest{
		CredentialID: enrollment.CredentialID, Code: code, IdempotencyKey: "activate-main",
		Context: requestContext("activate-main"),
	})
	if err != nil {
		t.Fatal(err)
	}
	assertRecoveryCodes(t, activated.RecoveryCodes, RecoveryCodeCount)
	replayed, err := fixture.service.Activate(t.Context(), fixture.actor, ActivationRequest{
		CredentialID: enrollment.CredentialID, Code: code, IdempotencyKey: "activate-main",
		Context: requestContext("activate-main"),
	})
	if err != nil || !replayed.Replayed || len(replayed.RecoveryCodes) != 0 {
		t.Fatalf("Activate replay contract mismatch: error=%v", err)
	}

	if _, err := fixture.service.CreateStepUp(t.Context(), fixture.actor, fixture.proofRequest(
		"proof-counter-replay", Authentication{Method: MethodTOTP, Code: code}, 1)); !errors.Is(err, ErrCodeReplayed) {
		t.Fatalf("activation counter replay error = %v", err)
	}

	fixture.clock.Add(2 * TOTPPeriod)
	current := uint64(fixture.clock.Now().Unix() / int64(TOTPPeriod/time.Second))
	previousWindowCode := hotp(secret, current-1, TOTPDigits)
	proofRequest := fixture.proofRequest(
		"proof-drift", Authentication{Method: MethodTOTP, Code: previousWindowCode}, 1)
	proof, err := fixture.service.CreateStepUp(t.Context(), fixture.actor, proofRequest)
	if err != nil || proof.Token == "" || proof.Method != MethodTOTP {
		t.Fatalf("CreateStepUp drift contract mismatch: error=%v", err)
	}
	replayedProof, err := fixture.service.CreateStepUp(t.Context(), fixture.actor, proofRequest)
	if err != nil || !replayedProof.Replayed || replayedProof.ProofID != proof.ProofID || replayedProof.Token != "" {
		t.Fatalf("CreateStepUp replay contract mismatch: error=%v", err)
	}
	if _, err := fixture.service.CreateStepUp(t.Context(), fixture.actor, StepUpRequest{
		TenantID: fixture.tenantA.id, Audience: "impersonation", Action: "grant.create",
		Authentication: Authentication{Method: "step_up", Code: proof.Token}, TTL: time.Minute,
		MaxUses: 1, IdempotencyKey: "nested-proof", Context: requestContext("nested-proof"),
	}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("nested proof authentication error = %v", err)
	}
	if _, err := fixture.service.CreateStepUp(t.Context(), fixture.actor, fixture.proofRequest(
		"proof-drift-replay", Authentication{Method: MethodTOTP, Code: previousWindowCode}, 1)); !errors.Is(err, ErrCodeReplayed) {
		t.Fatalf("drift counter replay error = %v", err)
	}
	outOfWindowCode := hotp(secret, current+2, TOTPDigits)
	if _, err := fixture.service.CreateStepUp(t.Context(), fixture.actor, fixture.proofRequest(
		"proof-outside-window", Authentication{Method: MethodTOTP, Code: outOfWindowCode}, 1)); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("out-of-window code error = %v", err)
	}

	consumeRequest := ConsumeStepUpRequest{
		Token: proof.Token, TenantID: fixture.tenantA.id, Audience: "impersonation",
		Action: "grant.create", Context: requestContext("consume-drift"),
	}
	evidence, err := fixture.service.ConsumeStepUp(t.Context(), fixture.actor, consumeRequest)
	if err != nil || evidence.UseOrdinal != 1 || evidence.SessionID != fixture.actor.SessionID {
		t.Fatalf("ConsumeStepUp = (%+v,%v)", evidence, err)
	}
	replayedEvidence, err := fixture.service.ConsumeStepUp(t.Context(), fixture.actor, consumeRequest)
	if err != nil || replayedEvidence.UseOrdinal != evidence.UseOrdinal {
		t.Fatalf("ConsumeStepUp(idempotent replay) = (%+v,%v)", replayedEvidence, err)
	}
	if _, err := fixture.service.ConsumeStepUp(t.Context(), fixture.actor, ConsumeStepUpRequest{
		Token: proof.Token, TenantID: fixture.tenantA.id, Audience: "impersonation",
		Action: "grant.create", Context: requestContext("consume-replay"),
	}); !errors.Is(err, ErrProofConsumed) {
		t.Fatalf("proof replay error = %v", err)
	}
	assertNoSensitiveAuditData(t, fixture.pool, enrollment.Secret, code, activated.RecoveryCodes)
	if err := audit.New(fixture.pool).VerifyScope(t.Context(), fixture.actor.ScopeID); err != nil {
		t.Fatalf("verify MFA audit chain: %v", err)
	}
	fixture.clock.Add(TOTPPeriod)
	fixture.cipher.Remove("mfa-kek-v1")
	_, err = fixture.service.CreateStepUp(t.Context(), fixture.actor, fixture.proofRequest(
		"missing-kek", Authentication{Method: MethodTOTP, Code: currentCode(secret, fixture.clock.Now())}, 1))
	if !errors.Is(err, ErrEncryptionUnavailable) || strings.Contains(fmt.Sprint(err), "mfa-kek-v1") ||
		strings.Contains(fmt.Sprint(err), enrollment.Secret) {
		t.Fatalf("envelope failure leaked sensitive detail: %v", err)
	}
}

func TestBeginEnrollmentReplayNeverDecryptsOrReturnsSetupMaterial(t *testing.T) {
	fixture := newMFAFixture(t)
	enrollment := fixture.begin(t, "enroll-no-secret-replay")
	if enrollment.Secret == "" || enrollment.ProvisioningURI == "" {
		t.Fatal("first enrollment omitted setup material")
	}

	counting := &countingCipher{inner: fixture.cipher}
	fixture.service.cipher = counting
	fixture.cipher.Remove("mfa-kek-v1")
	replayed := fixture.begin(t, "enroll-no-secret-replay")
	if replayed.CredentialID != enrollment.CredentialID || !replayed.ExpiresAt.Equal(enrollment.ExpiresAt) ||
		!replayed.Replayed || replayed.Secret != "" || replayed.ProvisioningURI != "" {
		t.Fatal("pending replay contract mismatch")
	}
	if counting.decryptCalls != 0 {
		t.Fatalf("pending replay decrypt calls = %d, want 0", counting.decryptCalls)
	}

	if _, err := fixture.service.BeginEnrollment(t.Context(), fixture.actor, EnrollmentRequest{
		AccountLabel: "different@example.invalid", IdempotencyKey: "enroll-no-secret-replay",
		Context: requestContext("enroll-no-secret-replay"),
	}); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("conflicting replay error = %v", err)
	}
	if counting.decryptCalls != 0 {
		t.Fatalf("conflicting replay decrypt calls = %d, want 0", counting.decryptCalls)
	}

	t.Run("expired", func(t *testing.T) {
		fixture := newMFAFixture(t)
		enrollment := fixture.begin(t, "enroll-expired-replay")
		fixture.clock.Add(defaultEnrollmentTTL)
		counting := &countingCipher{inner: fixture.cipher}
		fixture.service.cipher = counting
		fixture.cipher.Remove("mfa-kek-v1")
		replayed := fixture.begin(t, "enroll-expired-replay")
		if replayed.CredentialID != enrollment.CredentialID || !replayed.ExpiresAt.Equal(enrollment.ExpiresAt) ||
			!replayed.Replayed || replayed.Secret != "" || replayed.ProvisioningURI != "" {
			t.Fatal("expired replay contract mismatch")
		}
		if counting.decryptCalls != 0 {
			t.Fatalf("expired replay decrypt calls = %d, want 0", counting.decryptCalls)
		}
	})

	t.Run("activated", func(t *testing.T) {
		fixture := newMFAFixture(t)
		enrollment, _ := fixture.activate(t, "activated-replay")
		counting := &countingCipher{inner: fixture.cipher}
		fixture.service.cipher = counting
		fixture.cipher.Remove("mfa-kek-v1")
		replayed := fixture.begin(t, "enroll-activated-replay")
		if replayed.CredentialID != enrollment.CredentialID || !replayed.ExpiresAt.Equal(enrollment.ExpiresAt) ||
			!replayed.Replayed || replayed.Secret != "" || replayed.ProvisioningURI != "" {
			t.Fatal("activated replay contract mismatch")
		}
		if counting.decryptCalls != 0 {
			t.Fatalf("activated replay decrypt calls = %d, want 0", counting.decryptCalls)
		}
	})
}

func TestConsumeStepUpTxRollbackAndResourceBinding(t *testing.T) {
	fixture := newMFAFixture(t)
	_, recoveryCodes := fixture.activate(t, "tx-binding")
	proof, err := fixture.service.CreateStepUp(t.Context(), fixture.actor, fixture.proofRequest(
		"tx-binding-proof", Authentication{Method: MethodRecoveryCode, Code: recoveryCodes[0]}, 1))
	if err != nil {
		t.Fatal(err)
	}
	binding := bytes.Repeat([]byte{0x42}, 32)
	request := ConsumeStepUpRequest{
		Token: proof.Token, TenantID: fixture.tenantA.id, Audience: "impersonation",
		Action: "grant.create", ResourceBindingDigest: binding,
		Context: requestContext("tx-binding-use"),
	}

	tx, err := fixture.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.ConsumeStepUpTx(t.Context(), tx, fixture.actor, request); !errors.Is(err, ErrUnavailable) {
		_ = tx.Rollback(t.Context())
		t.Fatalf("legacy ConsumeStepUpTx error = %v, want unavailable", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	assertCount(t, fixture.pool, "mfa_step_up_uses", 0)
	assertAuditCount(t, fixture.pool, request.Context.RequestID, "mfa.step_up.consume", 0)

	authorityScopes := []uuid.UUID{fixture.actor.ScopeID, fixture.tenantA.scopeID}
	tx, err = fixture.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	lockedScopes, err := iamstage2b.BeginAuthorityMutation(t.Context(), tx,
		iamstage2b.OperationMFAConsumeStepUp, authorityScopes)
	if err != nil {
		_ = tx.Rollback(t.Context())
		t.Fatal(err)
	}
	evidence, err := fixture.service.ConsumeStepUpTxWithScopes(
		t.Context(), tx, fixture.actor, lockedScopes, request)
	if err != nil || evidence.ActorScopeID != fixture.actor.ScopeID ||
		!bytes.Equal(evidence.ResourceBindingDigest, binding) {
		_ = tx.Rollback(t.Context())
		t.Fatalf("ConsumeStepUpTxWithScopes = (%+v,%v)", evidence, err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	assertCount(t, fixture.pool, "mfa_step_up_uses", 0)
	assertAuditCount(t, fixture.pool, request.Context.RequestID, "mfa.step_up.consume", 0)

	tx, err = fixture.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	lockedScopes, err = iamstage2b.BeginAuthorityMutation(t.Context(), tx,
		iamstage2b.OperationMFAConsumeStepUp, authorityScopes)
	if err != nil {
		_ = tx.Rollback(t.Context())
		t.Fatal(err)
	}
	if _, err := fixture.service.ConsumeStepUpTxWithScopes(
		t.Context(), tx, fixture.actor, lockedScopes, request); err != nil {
		_ = tx.Rollback(t.Context())
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	assertCount(t, fixture.pool, "mfa_step_up_uses", 1)
	assertAuditCount(t, fixture.pool, request.Context.RequestID, "mfa.step_up.consume", 1)

	changedTrace := request
	changedTrace.Context.TraceID += "-changed"
	if _, err := fixture.service.ConsumeStepUp(t.Context(), fixture.actor, changedTrace); !errors.Is(err, ErrProofBinding) {
		t.Fatalf("trace binding error = %v", err)
	}
	changedBinding := request
	changedBinding.ResourceBindingDigest = bytes.Repeat([]byte{0x43}, 32)
	if _, err := fixture.service.ConsumeStepUp(t.Context(), fixture.actor, changedBinding); !errors.Is(err, ErrProofBinding) {
		t.Fatalf("resource binding error = %v", err)
	}
	if _, err := fixture.service.ConsumeStepUp(t.Context(), fixture.actor, request); err != nil {
		t.Fatalf("idempotent bound replay error = %v", err)
	}
}

func TestConcurrentTOTPAndRecoveryCodeHaveSingleWinner(t *testing.T) {
	fixture := newMFAFixture(t)
	enrollment, recoveryCodes := fixture.activate(t, "concurrent")
	secret := decodeTOTPSecret(enrollment.Secret)
	fixture.clock.Add(TOTPPeriod)
	code := currentCode(secret, fixture.clock.Now())

	const workers = 12
	errorsSeen := concurrentProofAttempts(t, workers, func(index int) (StepUpResult, error) {
		return fixture.service.CreateStepUp(t.Context(), fixture.actor, fixture.proofRequest(
			fmt.Sprintf("totp-race-%d", index), Authentication{Method: MethodTOTP, Code: code}, 1))
	})
	assertSingleWinner(t, errorsSeen, ErrCodeReplayed)

	errorsSeen = concurrentProofAttempts(t, workers, func(index int) (StepUpResult, error) {
		return fixture.service.CreateStepUp(t.Context(), fixture.actor, fixture.proofRequest(
			fmt.Sprintf("recovery-race-%d", index), Authentication{Method: MethodRecoveryCode, Code: recoveryCodes[0]}, 1))
	})
	assertSingleWinner(t, errorsSeen, ErrRecoveryCodeUsed)
	var consumptions int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM mfa_recovery_code_consumptions`).Scan(&consumptions); err != nil {
		t.Fatal(err)
	}
	if consumptions != 1 {
		t.Fatalf("recovery consumptions = %d, want 1", consumptions)
	}

	useProof, err := fixture.service.CreateStepUp(t.Context(), fixture.actor, fixture.proofRequest(
		"proof-use-race", Authentication{Method: MethodRecoveryCode, Code: recoveryCodes[1]}, 1))
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	useErrors := make([]error, workers)
	var wait sync.WaitGroup
	for index := range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, useErrors[index] = fixture.service.ConsumeStepUp(t.Context(), fixture.actor, ConsumeStepUpRequest{
				Token: useProof.Token, TenantID: fixture.tenantA.id, Audience: "impersonation",
				Action: "grant.create", Context: requestContext(fmt.Sprintf("proof-use-race-%d", index)),
			})
		}()
	}
	close(start)
	wait.Wait()
	assertSingleWinner(t, useErrors, ErrProofConsumed)
}

func TestStepUpBindingExpiryBoundedUseAndPrincipalChanges(t *testing.T) {
	fixture := newMFAFixture(t)
	enrollment, recoveryCodes := fixture.activate(t, "bindings")
	_ = enrollment

	tooLong := fixture.proofRequest("too-long", Authentication{Method: MethodRecoveryCode, Code: recoveryCodes[0]}, 1)
	tooLong.TTL = MaxStepUpTTL + time.Microsecond
	if _, err := fixture.service.CreateStepUp(t.Context(), fixture.actor, tooLong); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("long TTL error = %v", err)
	}
	tooMany := fixture.proofRequest("too-many", Authentication{Method: MethodRecoveryCode, Code: recoveryCodes[0]}, MaxProofUses+1)
	if _, err := fixture.service.CreateStepUp(t.Context(), fixture.actor, tooMany); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("excess max uses error = %v", err)
	}

	proof, err := fixture.service.CreateStepUp(t.Context(), fixture.actor, fixture.proofRequest(
		"bound-proof", Authentication{Method: MethodRecoveryCode, Code: recoveryCodes[0]}, 2))
	if err != nil {
		t.Fatal(err)
	}
	assertConsumeError(t, fixture, proof.Token, fixture.actor, fixture.tenantA.id, "other", "grant.create", ErrProofBinding)
	assertConsumeError(t, fixture, proof.Token, fixture.actor, fixture.tenantA.id, "impersonation", "grant.revoke", ErrProofBinding)
	assertConsumeError(t, fixture, proof.Token, fixture.actor, fixture.tenantB.id, "impersonation", "grant.create", ErrProofBinding)
	otherSession := fixture.actor
	otherSession.SessionID = uuid.New()
	assertConsumeError(t, fixture, proof.Token, otherSession, fixture.tenantA.id, "impersonation", "grant.create", ErrProofBinding)

	for ordinal := 1; ordinal <= 2; ordinal++ {
		evidence, err := fixture.service.ConsumeStepUp(t.Context(), fixture.actor, ConsumeStepUpRequest{
			Token: proof.Token, TenantID: fixture.tenantA.id, Audience: "impersonation",
			Action: "grant.create", Context: requestContext(fmt.Sprintf("bound-use-%d", ordinal)),
		})
		if err != nil || evidence.UseOrdinal != ordinal {
			t.Fatalf("bounded use %d = (%+v,%v)", ordinal, evidence, err)
		}
	}
	assertConsumeError(t, fixture, proof.Token, fixture.actor, fixture.tenantA.id,
		"impersonation", "grant.create", ErrProofConsumed)

	expiring, err := fixture.service.CreateStepUp(t.Context(), fixture.actor, fixture.proofRequest(
		"expiring", Authentication{Method: MethodRecoveryCode, Code: recoveryCodes[1]}, 1))
	if err != nil {
		t.Fatal(err)
	}
	fixture.clock.Add(MaxStepUpTTL)
	assertConsumeError(t, fixture, expiring.Token, fixture.actor, fixture.tenantA.id,
		"impersonation", "grant.create", ErrProofExpired)

	fixture.clock.Add(-MaxStepUpTTL)
	permissionProof, err := fixture.service.CreateStepUp(t.Context(), fixture.actor, fixture.proofRequest(
		"permission-change", Authentication{Method: MethodRecoveryCode, Code: recoveryCodes[2]}, 1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO role_permissions(role_id,permission_name) VALUES($1,$2)`,
		fixture.roleID, fixture.permissionTwo); err != nil {
		t.Fatal(err)
	}
	assertConsumeError(t, fixture, permissionProof.Token, fixture.actor, fixture.tenantA.id,
		"impersonation", "grant.create", ErrPrincipalChanged)

	disabledProof, err := fixture.service.CreateStepUp(t.Context(), fixture.actor, fixture.proofRequest(
		"disabled-user", Authentication{Method: MethodRecoveryCode, Code: recoveryCodes[3]}, 1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(t.Context(), `UPDATE users SET status='disabled',revision=revision+1 WHERE id=$1`, fixture.actor.UserID); err != nil {
		t.Fatal(err)
	}
	assertConsumeError(t, fixture, disabledProof.Token, fixture.actor, fixture.tenantA.id,
		"impersonation", "grant.create", ErrPrincipalChanged)
	if _, err := fixture.pool.Exec(t.Context(), `UPDATE users SET status='active',revision=revision+1 WHERE id=$1`, fixture.actor.UserID); err != nil {
		t.Fatal(err)
	}

	revokedProof, err := fixture.service.CreateStepUp(t.Context(), fixture.actor, fixture.proofRequest(
		"revoked-session", Authentication{Method: MethodRecoveryCode, Code: recoveryCodes[4]}, 1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(t.Context(), `UPDATE auth_sessions SET revoked_at=$2,revocation_reason='test' WHERE id=$1`,
		fixture.actor.SessionID, fixture.clock.Now()); err != nil {
		t.Fatal(err)
	}
	assertConsumeError(t, fixture, revokedProof.Token, fixture.actor, fixture.tenantA.id,
		"impersonation", "grant.create", ErrInvalidSession)
}

func TestDisableResetRequireStrongAuthenticationAndTrackKeyRotation(t *testing.T) {
	fixture := newMFAFixture(t)
	first, recoveryCodes := fixture.activate(t, "lifecycle")
	issuedBeforeDisable, err := fixture.service.CreateStepUp(t.Context(), fixture.actor, fixture.proofRequest(
		"pre-disable", Authentication{Method: MethodRecoveryCode, Code: recoveryCodes[0]}, 1))
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.service.Disable(t.Context(), fixture.actor, DeactivateRequest{
		Authentication: Authentication{Method: MethodTOTP, Code: "000000"}, Reason: "operator request",
		IdempotencyKey: "disable-invalid", Context: requestContext("disable-invalid"),
	}); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("Disable(invalid) error = %v", err)
	}
	if err := fixture.service.Disable(t.Context(), fixture.actor, DeactivateRequest{
		Authentication: Authentication{Method: MethodRecoveryCode, Code: recoveryCodes[1]},
		Reason:         "operator request", IdempotencyKey: strings.Repeat("a", 128), Context: requestContext("disable-valid"),
	}); err != nil {
		t.Fatal(err)
	}
	assertConsumeError(t, fixture, issuedBeforeDisable.Token, fixture.actor, fixture.tenantA.id,
		"impersonation", "grant.create", ErrPrincipalChanged)
	if _, err := fixture.service.CreateStepUp(t.Context(), fixture.actor, fixture.proofRequest(
		"disabled-proof", Authentication{Method: MethodRecoveryCode, Code: recoveryCodes[2]}, 1)); !errors.Is(err, ErrNotActive) {
		t.Fatalf("disabled credential proof error = %v", err)
	}

	fixture.cipher.Add(t, "mfa-kek-v2", bytes.Repeat([]byte{2}, 32), true)
	second := fixture.begin(t, "enroll-v2")
	var firstKey, secondKey string
	if err := fixture.pool.QueryRow(t.Context(), `SELECT secret_key_id FROM mfa_credentials WHERE id=$1`, first.CredentialID).Scan(&firstKey); err != nil {
		t.Fatal(err)
	}
	if err := fixture.pool.QueryRow(t.Context(), `SELECT secret_key_id FROM mfa_credentials WHERE id=$1`, second.CredentialID).Scan(&secondKey); err != nil {
		t.Fatal(err)
	}
	if firstKey != "mfa-kek-v1" || secondKey != "mfa-kek-v2" {
		t.Fatal("rotation metadata contract mismatch")
	}
	secondSecret := decodeTOTPSecret(second.Secret)
	secondActivation, err := fixture.service.Activate(t.Context(), fixture.actor, ActivationRequest{
		CredentialID: second.CredentialID, Code: currentCode(secondSecret, fixture.clock.Now()),
		IdempotencyKey: "activate-v2", Context: requestContext("activate-v2"),
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.clock.Add(TOTPPeriod)
	if err := fixture.service.Reset(t.Context(), fixture.actor, DeactivateRequest{
		Authentication: Authentication{Method: MethodTOTP, Code: currentCode(secondSecret, fixture.clock.Now())},
		Reason:         "credential recovery", IdempotencyKey: "reset-v2", Context: requestContext("reset-v2"),
	}); err != nil {
		t.Fatal(err)
	}
	if len(secondActivation.RecoveryCodes) != RecoveryCodeCount {
		t.Fatalf("second recovery code count = %d", len(secondActivation.RecoveryCodes))
	}
}

func TestProofConsumptionAndAuditFailureRollback(t *testing.T) {
	beginFixture := newMFAFixture(t)
	auditFailure := errors.New("injected MFA audit failure")
	failingBegin, err := NewServiceWithDependencies(beginFixture.pool, beginFixture.cipher, failingMFAAuditor{auditFailure}, Config{
		Clock: beginFixture.clock.Now, Random: rand.Reader, Issuer: "CDNCA Test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := failingBegin.BeginEnrollment(t.Context(), beginFixture.actor, EnrollmentRequest{
		AccountLabel: "audit@example.invalid", IdempotencyKey: "audit-begin-failure",
		Context: requestContext("audit-begin-failure"),
	}); !errors.Is(err, auditFailure) {
		t.Fatalf("BeginEnrollment(audit failure) error = %v", err)
	}
	var failedEnrollment int
	if err := beginFixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM mfa_credentials WHERE idempotency_key='audit-begin-failure'`).Scan(&failedEnrollment); err != nil {
		t.Fatal(err)
	}
	if failedEnrollment != 0 {
		t.Fatal("audit failure committed enrollment")
	}
	pending := beginFixture.begin(t, "audit-activation")
	pendingSecret := decodeTOTPSecret(pending.Secret)
	if _, err := failingBegin.Activate(t.Context(), beginFixture.actor, ActivationRequest{
		CredentialID: pending.CredentialID, Code: currentCode(pendingSecret, beginFixture.clock.Now()),
		IdempotencyKey: "audit-activation", Context: requestContext("audit-activation"),
	}); !errors.Is(err, auditFailure) {
		t.Fatalf("Activate(audit failure) error = %v", err)
	}
	assertCount(t, beginFixture.pool, "mfa_credential_events", 0)
	assertCount(t, beginFixture.pool, "mfa_recovery_codes", 0)
	if _, err := beginFixture.service.Activate(t.Context(), beginFixture.actor, ActivationRequest{
		CredentialID: pending.CredentialID, Code: currentCode(pendingSecret, beginFixture.clock.Now()),
		IdempotencyKey: "audit-activation", Context: requestContext("audit-activation"),
	}); err != nil {
		t.Fatalf("activation state was not rolled back after audit failure: %v", err)
	}

	fixture := newMFAFixture(t)
	_, recoveryCodes := fixture.activate(t, "audit")
	failing, err := NewServiceWithDependencies(fixture.pool, fixture.cipher, failingMFAAuditor{auditFailure}, Config{
		Clock: fixture.clock.Now, Random: rand.Reader, Issuer: "CDNCA Test",
	})
	if err != nil {
		t.Fatal(err)
	}
	request := fixture.proofRequest("audit-proof-failure",
		Authentication{Method: MethodRecoveryCode, Code: recoveryCodes[0]}, 1)
	if _, err := failing.CreateStepUp(t.Context(), fixture.actor, request); !errors.Is(err, auditFailure) {
		t.Fatalf("CreateStepUp(audit failure) error = %v", err)
	}
	var consumed int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM mfa_recovery_code_consumptions`).Scan(&consumed); err != nil {
		t.Fatal(err)
	}
	if consumed != 0 {
		t.Fatal("audit failure consumed recovery code")
	}
	if _, err := fixture.service.CreateStepUp(t.Context(), fixture.actor, request); err != nil {
		t.Fatalf("recovery code was not rolled back after audit failure: %v", err)
	}
}

func TestMFAFactsRejectDirectMutationDeleteAndTruncate(t *testing.T) {
	fixture := newMFAFixture(t)
	_, recoveryCodes := fixture.activate(t, "tamper")
	proof, err := fixture.service.CreateStepUp(t.Context(), fixture.actor, fixture.proofRequest(
		"tamper-proof", Authentication{Method: MethodRecoveryCode, Code: recoveryCodes[0]}, 1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.ConsumeStepUp(t.Context(), fixture.actor, ConsumeStepUpRequest{
		Token: proof.Token, TenantID: fixture.tenantA.id, Audience: "impersonation",
		Action: "grant.create", Context: requestContext("tamper-use"),
	}); err != nil {
		t.Fatal(err)
	}

	tables := []string{
		"mfa_credentials", "mfa_credential_events", "mfa_recovery_codes",
		"mfa_recovery_code_consumptions", "mfa_step_up_proofs", "mfa_step_up_uses",
	}
	for _, table := range tables {
		table := table
		t.Run(table, func(t *testing.T) {
			identifier := pgx.Identifier{table}.Sanitize()
			for _, statement := range []string{
				"UPDATE " + identifier + " SET id=id",
				"DELETE FROM " + identifier,
				"TRUNCATE " + identifier + " CASCADE",
			} {
				if _, err := fixture.pool.Exec(t.Context(), statement); err == nil || !strings.Contains(err.Error(), "MFA facts are append-only") {
					t.Errorf("direct SQL %q error = %v", statement, err)
				}
			}
		})
	}
	for _, statement := range []string{
		"UPDATE audit_events SET id=id",
		"DELETE FROM audit_events",
		"TRUNCATE audit_events CASCADE",
	} {
		if _, err := fixture.pool.Exec(t.Context(), statement); err == nil {
			t.Errorf("audit mutation %q unexpectedly succeeded", statement)
		}
	}
}

type failingMFAAuditor struct{ err error }

func (auditor failingMFAAuditor) Append(context.Context, pgx.Tx, audit.Event) error {
	return auditor.err
}

func newMFAFixture(t *testing.T) mfaFixture {
	t.Helper()
	pool := isolatedMFAPool(t, true)
	clock := &testClock{now: mfaTestNow}
	fixture := mfaFixture{
		pool: pool, clock: clock, cipher: newKeyringCipher(t), roleID: uuid.New(),
		tenantA:       tenantRecord{id: uuid.New(), scopeID: uuid.New()},
		tenantB:       tenantRecord{id: uuid.New(), scopeID: uuid.New()},
		permissionTwo: "identity.users.manage",
	}
	platformScopeID, actorUserID, sessionID := uuid.New(), uuid.New(), uuid.New()
	ctx := context.Background()
	for _, tenant := range []tenantRecord{fixture.tenantA, fixture.tenantB} {
		if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,display_name) VALUES($1,$2)`, tenant.id, "MFA test tenant"); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, tenant.scopeID, tenant.id); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platformScopeID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,username,display_name,password_hash)
		VALUES($1,'mfa-platform-admin','MFA platform administrator','test-password-hash')`, actorUserID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, platformScopeID, actorUserID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO roles(id,scope_id,name,description,system_role)
		VALUES($1,$2,'mfa_test_role','MFA test role',true)`, fixture.roleID, platformScopeID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO role_permissions(role_id,permission_name)
		VALUES($1,'identity.impersonation.manage')`, fixture.roleID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`,
		platformScopeID, actorUserID, fixture.roleID); err != nil {
		t.Fatal(err)
	}
	refreshHash := bytes.Repeat([]byte{3}, 32)
	if _, err := pool.Exec(ctx, `INSERT INTO auth_sessions(
		id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at
	) VALUES($1,$2,$3,$4,$5,$6,$7)`, sessionID, uuid.New(), actorUserID, platformScopeID,
		refreshHash, clock.Now().Add(-time.Minute), clock.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	fixture.actor = Actor{UserID: actorUserID, ScopeID: platformScopeID, SessionID: sessionID}
	service, err := NewServiceWithDependencies(pool, fixture.cipher, audit.New(pool), Config{
		Clock: clock.Now, Random: rand.Reader, Issuer: "CDNCA Test",
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.service = service
	return fixture
}

func (fixture mfaFixture) begin(t *testing.T, key string) EnrollmentResult {
	t.Helper()
	result, err := fixture.service.BeginEnrollment(t.Context(), fixture.actor, EnrollmentRequest{
		AccountLabel: "mfa-platform-admin@example.invalid", IdempotencyKey: key,
		Context: requestContext(key),
	})
	if err != nil {
		t.Fatalf("BeginEnrollment(%s): %v", key, err)
	}
	return result
}

func (fixture mfaFixture) activate(t *testing.T, key string) (EnrollmentResult, []string) {
	t.Helper()
	enrollment := fixture.begin(t, "enroll-"+key)
	secret := decodeTOTPSecret(enrollment.Secret)
	result, err := fixture.service.Activate(t.Context(), fixture.actor, ActivationRequest{
		CredentialID: enrollment.CredentialID, Code: currentCode(secret, fixture.clock.Now()),
		IdempotencyKey: "activate-" + key, Context: requestContext("activate-" + key),
	})
	if err != nil {
		t.Fatalf("Activate(%s): %v", key, err)
	}
	return enrollment, result.RecoveryCodes
}

func (fixture mfaFixture) proofRequest(key string, authentication Authentication, maxUses int) StepUpRequest {
	return StepUpRequest{
		TenantID: fixture.tenantA.id, Audience: "impersonation", Action: "grant.create",
		Authentication: authentication, TTL: MaxStepUpTTL, MaxUses: maxUses,
		IdempotencyKey: key, Context: requestContext(key),
	}
}

func requestContext(key string) RequestContext {
	return RequestContext{RequestID: "request-" + key, TraceID: "trace-" + key}
}

func currentCode(secret []byte, now time.Time) string {
	return hotp(secret, uint64(now.Unix()/int64(TOTPPeriod/time.Second)), TOTPDigits)
}

func assertRecoveryCodes(t *testing.T, codes []string, want int) {
	t.Helper()
	if len(codes) != want {
		t.Fatalf("recovery code count = %d, want %d", len(codes), want)
	}
	seen := make(map[string]struct{}, len(codes))
	for _, code := range codes {
		compact := strings.ReplaceAll(code, "-", "")
		if len(compact) < 24 {
			t.Fatalf("recovery code has insufficient entropy encoding: length=%d", len(compact))
		}
		if _, exists := seen[code]; exists {
			t.Fatal("duplicate recovery code")
		}
		seen[code] = struct{}{}
	}
}

func concurrentProofAttempts(t *testing.T, workers int, call func(int) (StepUpResult, error)) []error {
	t.Helper()
	start := make(chan struct{})
	errorsSeen := make([]error, workers)
	var wait sync.WaitGroup
	for index := range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, errorsSeen[index] = call(index)
		}()
	}
	close(start)
	wait.Wait()
	return errorsSeen
}

func assertSingleWinner(t *testing.T, errorsSeen []error, loser error) {
	t.Helper()
	winners := 0
	for _, err := range errorsSeen {
		if err == nil {
			winners++
			continue
		}
		if !errors.Is(err, loser) {
			t.Errorf("concurrent loser error = %v, want %v", err, loser)
		}
	}
	if winners != 1 {
		t.Fatalf("concurrent winners = %d, want 1", winners)
	}
}

func assertConsumeError(t *testing.T, fixture mfaFixture, token string, actor Actor, tenantID uuid.UUID,
	audience, action string, want error,
) {
	t.Helper()
	_, err := fixture.service.ConsumeStepUp(t.Context(), actor, ConsumeStepUpRequest{
		Token: token, TenantID: tenantID, Audience: audience, Action: action,
		Context: requestContext("consume-error-" + uuid.NewString()),
	})
	if !errors.Is(err, want) {
		t.Fatalf("ConsumeStepUp error = %v, want %v", err, want)
	}
}

func assertNoSensitiveAuditData(t *testing.T, pool *pgxpool.Pool, secret, totp string, recoveryCodes []string) {
	t.Helper()
	var payloads string
	if err := pool.QueryRow(t.Context(), `SELECT COALESCE(string_agg(payload::text,' '),'')
		FROM audit_events WHERE action LIKE 'mfa.%'`).Scan(&payloads); err != nil {
		t.Fatal(err)
	}
	for _, sensitive := range append([]string{secret, totp}, recoveryCodes...) {
		if sensitive != "" && strings.Contains(payloads, sensitive) {
			t.Fatalf("sensitive MFA material leaked into audit payload")
		}
	}
}

func assertCount(t *testing.T, pool *pgxpool.Pool, table string, want int) {
	t.Helper()
	var got int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM `+pgx.Identifier{table}.Sanitize()).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("%s count = %d, want %d", table, got, want)
	}
}

func assertAuditCount(t *testing.T, pool *pgxpool.Pool, requestID, action string, want int) {
	t.Helper()
	var got int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events
		WHERE request_id=$1 AND action=$2`, requestID, action).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("audit count for request=%s action=%s got=%d want=%d", requestID, action, got, want)
	}
}

func isolatedMFAPool(t *testing.T, migrate bool) *pgxpool.Pool {
	t.Helper()
	if migrate {
		// The service under test runs against the release head.
		return databasetest.MigratedPool(t, nil)
	}
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	if err := admin.Ping(ctx); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	schema := "mfa_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^mfa_test_[a-f0-9]{32}$`).MatchString(schema) {
		t.Fatalf("unsafe MFA test schema %q", schema)
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
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		cleanupCtx, cleanupCancel := databasetest.CleanupContext()
		defer cleanupCancel()
		if _, err := admin.Exec(cleanupCtx, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop MFA test schema: %v", err)
		}
		admin.Close()
	})
	return pool
}

type mfaMigration struct {
	version int64
	name    string
}

func migrateMFAThrough41(t *testing.T, pool *pgxpool.Pool) {
	migrateMFAThrough(t, pool, 41)
}

func migrateMFAThrough(t *testing.T, pool *pgxpool.Pool, target int64) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), `CREATE TABLE IF NOT EXISTS schema_migrations(
		version bigint PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		t.Fatal(err)
	}
	entries, err := fs.ReadDir(migrations.FS, ".")
	if err != nil {
		t.Fatal(err)
	}
	items := make([]mfaMigration, 0, target)
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".up.sql") {
			continue
		}
		separator := strings.IndexByte(name, '_')
		if separator < 1 {
			t.Fatalf("invalid migration filename %q", name)
		}
		version, err := strconv.ParseInt(name[:separator], 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		if version <= target {
			items = append(items, mfaMigration{version: version, name: name})
		}
	}
	sort.Slice(items, func(left, right int) bool { return items[left].version < items[right].version })
	if len(items) != int(target) {
		t.Fatalf("migration count through %03d = %d, want %d", target, len(items), target)
	}
	for index, item := range items {
		if item.version != int64(index+1) {
			t.Fatalf("migration gap through %03d: index=%d version=%d", target, index, item.version)
		}
		applyMFAMigrationFile(t, pool, item.name, item.version, true)
	}
}

func applyMFAMigrationFile(t *testing.T, pool *pgxpool.Pool, name string, version int64, up bool) {
	t.Helper()
	script, err := fs.ReadFile(migrations.FS, name)
	if err != nil {
		t.Fatal(err)
	}
	err = pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), string(script)); err != nil {
			return err
		}
		if up {
			_, err = tx.Exec(t.Context(), `INSERT INTO schema_migrations(version) VALUES($1)`, version)
		} else {
			_, err = tx.Exec(t.Context(), `DELETE FROM schema_migrations WHERE version=$1`, version)
		}
		return err
	})
	if err != nil {
		t.Fatalf("apply migration %s: %v", name, err)
	}
}

func assertMFAMigrationVersion(t *testing.T, pool *pgxpool.Pool, want int64) {
	t.Helper()
	var got int64
	if err := pool.QueryRow(t.Context(), `SELECT COALESCE(max(version),0) FROM schema_migrations`).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("migration version = %d, want %d", got, want)
	}
}

func assertMFAMigrationApplied(t *testing.T, pool *pgxpool.Pool, version int64, want bool) {
	t.Helper()
	var got bool
	if err := pool.QueryRow(t.Context(), `SELECT EXISTS(
		SELECT 1 FROM schema_migrations WHERE version=$1)`, version).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("migration %d applied = %t, want %t", version, got, want)
	}
}

func assertMFATable(t *testing.T, pool *pgxpool.Pool, table string, want bool) {
	t.Helper()
	var got bool
	if err := pool.QueryRow(t.Context(), `SELECT to_regclass($1) IS NOT NULL`, table).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("table %s exists = %t, want %t", table, got, want)
	}
}

func assertMFATrigger(t *testing.T, pool *pgxpool.Pool, table, trigger string, want bool) {
	t.Helper()
	var got bool
	if err := pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM pg_trigger trigger
		JOIN pg_class relation ON relation.oid=trigger.tgrelid
		WHERE relation.relname=$1 AND trigger.tgname=$2 AND NOT trigger.tgisinternal)`, table, trigger).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("trigger %s.%s exists = %t, want %t", table, trigger, got, want)
	}
}
