package accountregistrationproof

import (
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/accountregistration"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
)

// A proof is stamped and checked with the authority clock only. With the
// database clock running behind it (Docker on macOS, or NTP skew between the
// application and database hosts), a proof consumed right after it was issued
// used to be refused because its contact_verified_at was "in the future" for
// clock_timestamp. Expiry, one-time use and the binding still hold.
func TestAuthorityConsumesWithItsOwnClockPostgres(t *testing.T) {
	pool := databasetest.MigratedPool(t, nil)
	ctx := t.Context()
	var databaseNow time.Time
	if err := pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&databaseNow); err != nil {
		t.Fatal(err)
	}
	now := canonicalTime(databaseNow.Add(2 * time.Minute)) // the application clock is ahead
	authority, err := NewAuthority(pool, Config{DigestKey: proofTestKey, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	const email = "clock@example.com"
	issue := func() string {
		t.Helper()
		issued, err := authority.Issue(ctx, IssueRequest{
			Channel: accountregistration.VerificationEmail, Destination: email, Source: "203.0.113.9",
			SubjectDigest: proofTestSubject, HumanVerifiedAt: now.Add(-time.Minute), ContactVerifiedAt: now,
			ExpiresAt: now.Add(5 * time.Minute), AttemptRevision: 1, RiskContext: RiskContextNormal,
		})
		if err != nil {
			t.Fatal(err)
		}
		return issued.Reference
	}
	consume := func(reference, key string) (accountregistration.RegistrationProof, error) {
		return authority.VerifyAndConsume(ctx, accountregistration.RegistrationProofRequest{
			Reference: reference, Channel: accountregistration.VerificationEmail, Destination: email,
			IdempotencyKey: key, SubjectDigest: proofTestSubject,
		})
	}

	fresh := issue()
	first, err := consume(fresh, "register-1")
	if err != nil {
		t.Fatalf("fresh proof: %v", err)
	}
	if replayed, err := consume(fresh, "register-1"); err != nil || replayed.EvidenceID != first.EvidenceID {
		t.Fatalf("replay: %+v %v", replayed, err)
	}
	if _, err := consume(fresh, "register-2"); !errors.Is(err, accountregistration.ErrProofInvalid) {
		t.Fatalf("second use: %v", err)
	}

	stale := issue()
	now = now.Add(5 * time.Minute) // expired for the authority, still minutes away for the database
	if _, err := consume(stale, "register-3"); !errors.Is(err, accountregistration.ErrProofInvalid) {
		t.Fatalf("expired proof: %v", err)
	}
}
