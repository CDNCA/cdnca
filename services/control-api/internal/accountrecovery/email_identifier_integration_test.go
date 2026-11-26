package accountrecovery

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/accountregistration"
	"github.com/cdnca/cdnca/services/control-api/internal/accountregistrationproof"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

// with the username optional at sign-up,
// the reset page also takes the email the registration verified.

var testRegistrationProofKey = bytes.Repeat([]byte{0x6c}, 32)

type registeredAccount struct {
	userID   uuid.UUID
	username string
	tenantID uuid.UUID
	scopeID  uuid.UUID
}

func TestRequestRecoveryByVerifiedRegistrationEmail(t *testing.T) {
	f := newFixture(t, 20, 20)
	service := emailRecoveryService(t, f)
	ctx := t.Context()
	verified := seedRegisteredAccount(t, f, f.tenantID, f.scopeID, "dana@example.test", "email")
	smsOnly := seedRegisteredAccount(t, f, f.tenantID, f.scopeID, "erin@example.test", "sms")
	captchaOnly := seedRegisteredAccount(t, f, f.tenantID, f.scopeID, "fay@example.test", "")
	before := tableCounts(t, f.pool)[1]

	results := make([]RequestResult, 0, 5)
	for index, identifier := range []string{
		"  Dana@Example.test ", "erin@example.test", "fay@example.test", "nobody@example.test", verified.username,
	} {
		result, err := service.Request(ctx, requestInput(f, identifier, "email-request-"+string(rune('a'+index)), "198.51.100.40"))
		if err != nil {
			t.Fatalf("request %q: %v", identifier, err)
		}
		results = append(results, result)
	}
	for _, result := range results[1:] {
		if result != results[0] {
			t.Fatalf("enumerable responses: %+v", results)
		}
	}
	if events, outbox, _ := recoveryDispatchCounts(t, f.pool); events != 5 || outbox != 5 {
		t.Fatalf("dispatch events/outbox = %d/%d, want one per request", events, outbox)
	}
	if got := claimsFor(t, f, verified.userID); got != 2 {
		t.Fatalf("verified email + generated username claims = %d, want 2", got)
	}
	if got := claimsFor(t, f, smsOnly.userID) + claimsFor(t, f, captchaOnly.userID); got != 0 {
		t.Fatalf("unverified email claims = %d, want 0", got)
	}
	if got := tableCounts(t, f.pool)[1] - before; got != 2 {
		t.Fatalf("new dispatch claims = %d, want 2", got)
	}

	// the link the email request sent resets the password; the generated username signs in with it
	if _, err := service.Request(ctx, requestInput(f, "dana@example.test", "email-request-reset", "198.51.100.41")); err != nil {
		t.Fatal(err)
	}
	account := *f
	account.userID = verified.userID
	delivery := recoveryDeliveryForRequest(t, &account, "email-request-reset")
	if _, err := service.Reset(ctx, resetInput(f, delivery.Token, "email-reset", "Fresh-password-5678")); err != nil {
		t.Fatalf("reset by the email link: %v", err)
	}
	for _, name := range []string{verified.username, "dana@example.test"} {
		login, err := identity.NewStore(f.pool).FindLoginIdentity(ctx, name, nil)
		if err != nil || login.UserID != verified.userID || !identity.VerifyPassword(login.PasswordHash, "Fresh-password-5678") {
			t.Fatalf("login %q after reset: user=%s err=%v", name, login.UserID, err)
		}
	}
	assertNoSecretsInRecoveryAudit(t, f.pool, []string{delivery.Token, "dana@example.test", "Fresh-password-5678"})

	// a username spelled like an email still wins, as at sign-in
	if _, err := service.Request(ctx, requestInput(f, f.username, "email-request-username", "198.51.100.42")); err != nil {
		t.Fatal(err)
	}
	if got := claimsFor(t, f, f.userID); got != 1 {
		t.Fatalf("username containing @ claims = %d, want 1", got)
	}

	// without registration proof keys the email is looked up as a username only
	plain, err := NewServiceWithDependencies(f.pool, testConfig(f), audit.New(f.pool))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plain.Request(ctx, requestInput(f, "dana@example.test", "email-request-plain", "198.51.100.43")); err != nil {
		t.Fatal(err)
	}
	if got := claimsFor(t, f, verified.userID); got != 3 {
		t.Fatalf("claims without proof keys = %d, want unchanged 3", got)
	}
}

func TestRequestRecoveryByEmailRefusesChangedHistoricalAndOtherScopeAccounts(t *testing.T) {
	f := newFixture(t, 20, 20)
	service := emailRecoveryService(t, f)
	ctx := t.Context()
	request := func(input RequestInput) {
		t.Helper()
		if _, err := service.Request(ctx, input); err != nil {
			t.Fatalf("request %q: %v", input.Username, err)
		}
	}

	// A verified gina@ at sign-up, then moved to a new address; B took gina@
	// later without a code. Neither address now names an account.
	first := seedRegisteredAccount(t, f, f.tenantID, f.scopeID, "gina@example.test", "email")
	setEmail(t, f, first.userID, "gina.new@example.test")
	second := seedRegisteredAccount(t, f, f.tenantID, f.scopeID, "hal@example.test", "email")
	setEmail(t, f, second.userID, "gina@example.test")
	request(requestInput(f, "gina@example.test", "history-old", "198.51.100.50"))
	request(requestInput(f, "gina.new@example.test", "history-new", "198.51.100.51"))
	request(requestInput(f, "hal@example.test", "history-released", "198.51.100.52"))
	if got := claimsFor(t, f, first.userID) + claimsFor(t, f, second.userID); got != 0 {
		t.Fatalf("changed or historical email claims = %d, want 0", got)
	}

	// verified in another tenant: not on this tenant's host
	otherTenant, otherScope := seedTenant(t, f.pool, "Other recovery tenant")
	other := seedRegisteredAccount(t, f, otherTenant, otherScope, "ivy@example.test", "email")
	request(requestInput(f, "ivy@example.test", "other-tenant-host", "198.51.100.53"))
	if got := claimsFor(t, f, other.userID); got != 0 {
		t.Fatalf("other tenant host claims = %d, want 0", got)
	}

	// the platform host follows the registration's tenant
	platformScope := seedPlatformScope(t, f.pool)
	platform := func(identifier, key string) RequestInput {
		input := requestInput(f, identifier, key, "198.51.100.54")
		input.TenantID, input.ScopeID = uuid.Nil, platformScope
		return input
	}
	request(platform("ivy@example.test", "platform-registered"))
	var challengeScope uuid.UUID
	if err := f.pool.QueryRow(ctx, `SELECT scope_id FROM account_recovery_challenges WHERE user_id=$1`, other.userID).
		Scan(&challengeScope); err != nil || challengeScope != otherScope {
		t.Fatalf("platform host challenge scope = %s (%v), want %s", challengeScope, err, otherScope)
	}

	// sign-in on the platform host would pick another scope: ambiguous, nothing sent
	staff := seedRegisteredAccount(t, f, f.tenantID, f.scopeID, "jo@example.test", "email")
	seedMembership(t, f.pool, platformScope, staff.userID)
	request(platform("jo@example.test", "platform-ambiguous"))
	if got := claimsFor(t, f, staff.userID); got != 0 {
		t.Fatalf("ambiguous scope claims = %d, want 0", got)
	}
	// on its tenant's host the same account is unambiguous
	request(requestInput(f, "jo@example.test", "tenant-unambiguous", "198.51.100.55"))
	if got := claimsFor(t, f, staff.userID); got != 1 {
		t.Fatalf("tenant host claims = %d, want 1", got)
	}

	// a disabled account answers alike and sends nothing
	setUserStatus(t, f.pool, other.userID, "disabled")
	request(platform("ivy@example.test", "platform-disabled"))
	if got := claimsFor(t, f, other.userID); got != 1 {
		t.Fatalf("disabled account claims = %d, want unchanged 1", got)
	}
}

func emailRecoveryService(t *testing.T, f *fixture) *Service {
	t.Helper()
	config := testConfig(f)
	config.RegistrationProofKeys = [][]byte{bytes.Repeat([]byte{0x01}, 32), testRegistrationProofKey}
	service, err := NewServiceWithDependencies(f.pool, config, audit.New(f.pool))
	if err != nil {
		t.Fatal(err)
	}
	return service
}

// seedRegisteredAccount writes what a registration leaves: the user with its
// generated username, the membership and the completed receipt, and the
// proof it consumed on proof ("email", "sms", or "" for the image CAPTCHA).
func seedRegisteredAccount(t *testing.T, f *fixture, tenantID, scopeID uuid.UUID, email, proof string) registeredAccount {
	t.Helper()
	ctx := t.Context()
	account := registeredAccount{userID: uuid.New(), tenantID: tenantID, scopeID: scopeID}
	account.username = strings.SplitN(email, "@", 2)[0] + "-" + account.userID.String()[:6]
	phone := fmt.Sprintf("+86138%08d", binary.BigEndian.Uint32(account.userID[:4])%100000000)
	hash, err := identity.HashPassword(f.password)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `INSERT INTO users(id,username,display_name,email,phone,password_hash,status,revision,created_at,updated_at)
		VALUES($1,$2,$2,$3,$4,$5,'active',1,now(),now())`, account.userID, account.username, email, phone, hash); err != nil {
		t.Fatal(err)
	}
	seedMembership(t, f.pool, scopeID, account.userID)
	key := "registration-" + account.userID.String()
	var subject [32]byte
	copy(subject[:], bytes.Repeat([]byte{0x2d}, 32))
	if _, err := f.pool.Exec(ctx, `INSERT INTO account_registration_requests_159(
		id,idempotency_key,request_id,request_digest,subject_digest,state,outcome,tenant_id,scope_id,user_id,
		response_status,created_at,completed_at
	) VALUES($1,$2,$2,$3,$4,'completed','created',$5,$6,$7,202,now(),now())`, uuid.New(), key,
		bytes.Repeat([]byte{0x3e}, 32), subject[:], tenantID, scopeID, account.userID); err != nil {
		t.Fatal(err)
	}
	if proof == "" {
		return account
	}
	destination := email
	if proof == accountregistration.VerificationSMS {
		destination = phone
	}
	authority, err := accountregistrationproof.NewAuthority(f.pool, accountregistrationproof.Config{DigestKey: testRegistrationProofKey})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Add(-time.Second)
	issued, err := authority.Issue(ctx, accountregistrationproof.IssueRequest{
		Channel: proof, Destination: destination, Source: "203.0.113.7", SubjectDigest: subject,
		HumanVerifiedAt: now, ContactVerifiedAt: now, ExpiresAt: now.Add(5 * time.Minute),
		AttemptRevision: 1, RiskContext: accountregistrationproof.RiskContextNormal,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authority.VerifyAndConsume(ctx, accountregistration.RegistrationProofRequest{
		Reference: issued.Reference, Channel: proof, Destination: destination, IdempotencyKey: key, SubjectDigest: subject,
	}); err != nil {
		t.Fatal(err)
	}
	return account
}

func setEmail(t *testing.T, f *fixture, userID uuid.UUID, email string) {
	t.Helper()
	if _, err := f.pool.Exec(t.Context(), `UPDATE users SET email=$2,revision=revision+1 WHERE id=$1`, userID, email); err != nil {
		t.Fatal(err)
	}
}

func claimsFor(t *testing.T, f *fixture, userID uuid.UUID) int {
	t.Helper()
	var count int
	if err := f.pool.QueryRow(t.Context(), `SELECT count(*) FROM account_recovery_dispatch_claims WHERE user_id=$1`, userID).
		Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}
