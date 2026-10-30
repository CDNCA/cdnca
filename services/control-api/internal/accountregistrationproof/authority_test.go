package accountregistrationproof

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/accountregistration"
	"github.com/cdnca/cdnca/services/control-api/internal/accountregistrationhttp"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	_                accountregistration.ProofAuthority             = (*Authority)(nil)
	_                accountregistrationhttp.ProofReferenceResolver = CookieReferenceResolver{}
	proofTestKey                                                    = bytes.Repeat([]byte{0x42}, 32)
	proofTestNow                                                    = time.Date(2026, 8, 8, 8, 0, 0, 0, time.UTC)
	proofTestSubject                                                = [32]byte{1, 2, 3, 4}
)

func TestNewAuthorityRejectsInvalidDependencies(t *testing.T) {
	t.Parallel()

	for name, testCase := range map[string]struct {
		pool *pgxpool.Pool
		key  []byte
	}{
		"nil pool":  {nil, proofTestKey},
		"short key": {&pgxpool.Pool{}, bytes.Repeat([]byte{1}, 31)},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewAuthority(testCase.pool, Config{DigestKey: testCase.key}); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("NewAuthority error = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

func TestIssueRejectsUnsafeClaimsBeforeDatabase(t *testing.T) {
	t.Parallel()

	authority := mustTestAuthority(t)
	valid := IssueRequest{
		Channel: accountregistration.VerificationEmail, Destination: "owner@example.com",
		Source: "2001:db8::1", SubjectDigest: proofTestSubject,
		HumanVerifiedAt: proofTestNow.Add(-time.Minute), ContactVerifiedAt: proofTestNow.Add(-30 * time.Second),
		ExpiresAt: proofTestNow.Add(5 * time.Minute), AttemptRevision: 1, RiskContext: RiskContextNormal,
	}
	for name, mutate := range map[string]func(*IssueRequest){
		"unknown channel":        func(request *IssueRequest) { request.Channel = "push" },
		"noncanonical email":     func(request *IssueRequest) { request.Destination = " OWNER@example.com " },
		"noncanonical source":    func(request *IssueRequest) { request.Source = "2001:0db8::1" },
		"zero subject":           func(request *IssueRequest) { request.SubjectDigest = [32]byte{} },
		"future human proof":     func(request *IssueRequest) { request.HumanVerifiedAt = proofTestNow.Add(time.Second) },
		"future contact proof":   func(request *IssueRequest) { request.ContactVerifiedAt = proofTestNow.Add(time.Second) },
		"expired proof":          func(request *IssueRequest) { request.ExpiresAt = proofTestNow },
		"excessive ttl":          func(request *IssueRequest) { request.ExpiresAt = proofTestNow.Add(31 * time.Minute) },
		"missing attempt":        func(request *IssueRequest) { request.AttemptRevision = 0 },
		"unbounded risk context": func(request *IssueRequest) { request.RiskContext = "raw-device-fingerprint" },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			request := valid
			mutate(&request)
			if _, err := authority.Issue(context.Background(), request); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("Issue error = %v, want ErrInvalidInput", err)
			}
		})
	}
}

func TestVerifyRejectsUnsafeBindingsBeforeDatabase(t *testing.T) {
	t.Parallel()

	authority := mustTestAuthority(t)
	valid := accountregistration.RegistrationProofRequest{
		Reference: strings.Repeat("A", ReferenceEncodedLength), Channel: accountregistration.VerificationSMS,
		Destination: "+8613812345678", Source: "192.0.2.8", IdempotencyKey: "register-1",
		SubjectDigest: proofTestSubject,
	}
	for name, mutate := range map[string]func(*accountregistration.RegistrationProofRequest){
		"malformed reference": func(request *accountregistration.RegistrationProofRequest) { request.Reference = "secret" },
		"unknown channel":     func(request *accountregistration.RegistrationProofRequest) { request.Channel = "push" },
		"destination":         func(request *accountregistration.RegistrationProofRequest) { request.Destination = "138 1234" },
		"noncanonical source": func(request *accountregistration.RegistrationProofRequest) { request.Source = "::ffff:192.0.2.8" },
		"idempotency":         func(request *accountregistration.RegistrationProofRequest) { request.IdempotencyKey = "contains space" },
		"zero subject":        func(request *accountregistration.RegistrationProofRequest) { request.SubjectDigest = [32]byte{} },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			request := valid
			mutate(&request)
			if _, err := authority.VerifyAndConsume(context.Background(), request); !errors.Is(err, accountregistration.ErrProofInvalid) {
				t.Fatalf("VerifyAndConsume error = %v, want ErrProofInvalid", err)
			}
		})
	}
}

func TestReferenceDigestUsesSeparatedKeyedDomains(t *testing.T) {
	t.Parallel()

	value := []byte(strings.Repeat("A", ReferenceEncodedLength))
	reference := authorityDigest(proofTestKey, referenceDigestDomain, value)
	destination := authorityDigest(proofTestKey, destinationDigestDomain, value)
	source := authorityDigest(proofTestKey, sourceDigestDomain, value)
	idempotency := authorityDigest(proofTestKey, idempotencyDigestDomain, value)
	for name, digest := range map[string][32]byte{
		"destination": destination,
		"source":      source,
		"idempotency": idempotency,
	} {
		if bytes.Equal(reference[:], digest[:]) {
			t.Fatalf("reference digest collides with %s digest", name)
		}
		if bytes.Contains(digest[:], value) {
			t.Fatalf("%s digest contains raw secret", name)
		}
	}
}

func TestAuthoritySourceLocksAndConsumesExactlyOnce(t *testing.T) {
	t.Parallel()

	source, err := os.ReadFile("authority.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, required := range []string{
		"pgx.BeginTxFunc", "pgx.Serializable", "account_registration_proofs_162", "FOR UPDATE",
		"use_revision", "consumed_idempotency_digest", "consumed_binding_digest",
		"UPDATE account_registration_proofs_162", "use_revision=1", "WHERE evidence_id=$1 AND use_revision=0",
		"hmac.Equal", "clock_timestamp()",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("authority source missing %q", required)
		}
	}
	for _, forbidden := range []string{"reference text", "destination text", "source text", "log.", "slog."} {
		if strings.Contains(text, forbidden) {
			t.Errorf("authority source contains raw-secret/logging marker %q", forbidden)
		}
	}
}

func TestCookieReferenceResolverUsesSingleHostCookie(t *testing.T) {
	t.Parallel()

	reference := strings.Repeat("A", ReferenceEncodedLength)
	request := httptest.NewRequest(http.MethodPost, "https://control.example/v1/auth/register", nil)
	request.AddCookie(&http.Cookie{Name: CookieName, Value: reference})
	resolved, err := (CookieReferenceResolver{}).ResolveProofReference(request)
	if err != nil || resolved != reference {
		t.Fatalf("ResolveProofReference = %q, %v", resolved, err)
	}

	duplicate := request.Clone(request.Context())
	duplicate.Header.Add("Cookie", CookieName+"="+reference)
	if _, err := (CookieReferenceResolver{}).ResolveProofReference(duplicate); !errors.Is(err, ErrInvalidReference) {
		t.Fatalf("duplicate cookie error = %v, want ErrInvalidReference", err)
	}

	headerOnly := httptest.NewRequest(http.MethodPost, "https://control.example/v1/auth/register", nil)
	headerOnly.Header.Set("X-Registration-Proof", reference)
	if _, err := (CookieReferenceResolver{}).ResolveProofReference(headerOnly); !errors.Is(err, ErrInvalidReference) {
		t.Fatalf("header-only error = %v, want ErrInvalidReference", err)
	}
}

func TestReferenceCookieIsHostOnlyAndStrict(t *testing.T) {
	t.Parallel()

	reference := strings.Repeat("A", ReferenceEncodedLength)
	cookie, err := NewReferenceCookie(reference, proofTestNow.Add(5*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if cookie.Name != CookieName || cookie.Value != reference || cookie.Path != "/" || cookie.Domain != "" ||
		!cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.MaxAge != 0 {
		t.Fatalf("unsafe proof cookie: %#v", cookie)
	}
	if !cookie.Expires.Equal(proofTestNow.Add(5 * time.Minute)) {
		t.Fatalf("cookie expiry = %s", cookie.Expires)
	}

	cleared := ClearReferenceCookie()
	if cleared.Name != CookieName || cleared.Value != "" || cleared.Path != "/" || cleared.Domain != "" ||
		!cleared.Secure || !cleared.HttpOnly || cleared.SameSite != http.SameSiteStrictMode || cleared.MaxAge != -1 {
		t.Fatalf("unsafe cleared proof cookie: %#v", cleared)
	}
}

func mustTestAuthority(t *testing.T) *Authority {
	t.Helper()
	authority, err := NewAuthority(&pgxpool.Pool{}, Config{
		DigestKey: proofTestKey, Clock: func() time.Time { return proofTestNow }, MaxTTL: 30 * time.Minute,
		NextID: func() (uuid.UUID, error) { return uuid.MustParse("0198-7f12-a800-7000-8000-000000000001"), nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return authority
}
