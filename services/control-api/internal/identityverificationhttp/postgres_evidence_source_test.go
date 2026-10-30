package identityverificationhttp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/identityverification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestEvidenceReservationIdempotencyDigestAndAuditRequestID(t *testing.T) {
	key := "0123456789abcdef0123456789abcdef0123456789a"
	digest := evidenceReservationIdempotencyDigest(key)
	if digest != evidenceReservationIdempotencyDigest(key) {
		t.Fatal("idempotency digest is not stable")
	}
	if digest == sha256.Sum256([]byte(key)) {
		t.Fatal("idempotency digest is not domain separated")
	}
	if digest == evidenceReservationIdempotencyDigest(key+"b") {
		t.Fatal("different idempotency keys have the same digest")
	}
	requestID := evidenceReservationAuditRequestID(digest)
	if !strings.HasPrefix(requestID, evidenceReservationAuditRequestPrefix) ||
		len(requestID) != len(evidenceReservationAuditRequestPrefix)+sha256.Size*2 ||
		strings.Contains(requestID, key) {
		t.Fatalf("audit request ID = %q", requestID)
	}
}

func TestPostgresRuntimeEvidenceSourceConstructionFailsClosed(t *testing.T) {
	var typedNilAudit *audit.Log
	var typedNilPool *pgxpool.Pool
	for name, test := range map[string]struct {
		pool    *pgxpool.Pool
		auditor any
	}{
		"nil pool":        {auditor: typedNilAudit},
		"typed nil pool":  {pool: typedNilPool, auditor: typedNilAudit},
		"typed nil audit": {pool: &pgxpool.Pool{}, auditor: typedNilAudit},
	} {
		t.Run(name, func(t *testing.T) {
			auditor, _ := test.auditor.(*audit.Log)
			source, err := NewPostgresRuntimeEvidenceSource(context.Background(), test.pool, auditor,
				PostgresRuntimeEvidenceSourceConfig{ResolverName: "trusted-kyc"})
			if source != nil || !errors.Is(err, ErrTrustedEvidenceSourceRequired) {
				t.Fatalf("constructor = (%T,%v)", source, err)
			}
		})
	}
	var zero *PostgresRuntimeEvidenceSource
	if zero.Capabilities() != (RuntimeEvidenceSourceCapabilities{}) {
		t.Fatalf("typed nil capabilities = %#v", zero.Capabilities())
	}
	zero = &PostgresRuntimeEvidenceSource{}
	if zero.Capabilities() != (RuntimeEvidenceSourceCapabilities{}) {
		t.Fatalf("zero capabilities = %#v", zero.Capabilities())
	}
	if adapter, err := NewRuntimeEvidenceAdapter(RuntimeEvidenceConfig{ResolverName: "trusted-kyc"}, zero); adapter != nil ||
		!errors.Is(err, ErrTrustedEvidenceSourceRequired) {
		t.Fatalf("zero source adapter = (%T,%v)", adapter, err)
	}
	if _, err := zero.Reserve(context.Background(), RuntimeEvidenceReserveRequest{}); !errors.Is(err, ErrEvidenceUnavailable) {
		t.Fatalf("zero source reserve = %v", err)
	}
}

func TestEvidenceIssueBindingMatchesJSONBNormalizedPayload(t *testing.T) {
	principal := RuntimeEvidencePrincipal{TenantScopeID: uuid.New(), ActorUserID: uuid.New(), SessionID: uuid.New()}
	request := RuntimeEvidenceIssueRequest{
		Kind: identityverification.KindPersonalInitial, IssuerWorkloadID: "kyc-issuer-1",
		IssuerCertificateFingerprint: sha256.Sum256([]byte("certificate")),
		IssuerIdempotencyKey:         "issuer-idempotency-key",
		IssuerRequestDigest:          sha256.Sum256([]byte("issuer-request")),
		EvidenceClaimDigest:          sha256.Sum256([]byte("claim")),
		Evidence: ResolvedEvidence{Kind: identityverification.KindPersonalInitial,
			SubjectFingerprint: bytes.Repeat([]byte{0x21}, 32),
			Materials: []identityverification.MaterialInput{{Kind: identityverification.MaterialIdentityDocument,
				EncryptedEnvelope: []byte("envelope"), ObjectSHA256: bytes.Repeat([]byte{0x22}, 32), SizeBytes: 7}}},
	}
	payload, err := json.Marshal(cloneRuntimeEvidence(request.Evidence))
	if err != nil {
		t.Fatal(err)
	}
	// PostgreSQL returns jsonb in its own normal form (keys sorted by length
	// then bytes, ", " and ": " separators), never the bytes json.Marshal wrote.
	var object map[string]any
	if err := json.Unmarshal(payload, &object); err != nil {
		t.Fatal(err)
	}
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if len(keys[i]) != len(keys[j]) {
			return len(keys[i]) < len(keys[j])
		}
		return keys[i] < keys[j]
	})
	var stored bytes.Buffer
	stored.WriteByte('{')
	for index, key := range keys {
		if index > 0 {
			stored.WriteString(", ")
		}
		name, _ := json.Marshal(key)
		value, _ := json.Marshal(object[key])
		stored.Write(name)
		stored.WriteString(": ")
		stored.Write(value)
	}
	stored.WriteByte('}')
	if bytes.Equal(stored.Bytes(), payload) {
		t.Fatal("test payload is already in jsonb normal form")
	}
	expiresAt := time.Date(2036, 7, 26, 8, 45, 0, 0, time.UTC)
	tokenDigest := sha256.Sum256([]byte("token"))
	requestDigest := sha256.Sum256([]byte("request"))
	record := postgresEvidenceIssueBinding{
		Principal: principal, Kind: request.Kind, WorkloadID: request.IssuerWorkloadID,
		CertificateFingerprint: request.IssuerCertificateFingerprint,
		IdempotencyDigest:      evidenceIssueIdempotencyDigest(request.IssuerIdempotencyKey),
		IssuerRequestDigest:    request.IssuerRequestDigest, EvidenceClaimDigest: request.EvidenceClaimDigest,
		ReservationEvidenceClaimDigest: request.EvidenceClaimDigest, TokenDigest: tokenDigest,
		EvidenceRequestDigest: requestDigest, EvidencePayload: stored.Bytes(),
		ExpiresAt: expiresAt, ReservationExpiresAt: expiresAt,
	}
	if !record.matches(principal, request, tokenDigest, requestDigest, payload, expiresAt) {
		t.Fatal("same issue request read back from jsonb does not match its binding")
	}
	changed := request
	changed.Evidence = cloneRuntimeEvidence(request.Evidence)
	changed.Evidence.SubjectFingerprint = bytes.Repeat([]byte{0x23}, 32)
	changedPayload, err := json.Marshal(changed.Evidence)
	if err != nil {
		t.Fatal(err)
	}
	if record.matches(principal, changed, tokenDigest, requestDigest, changedPayload, expiresAt) {
		t.Fatal("different evidence payload matches the binding")
	}
}

func TestEvidenceIssueTokenAlwaysMatchesTokenPattern(t *testing.T) {
	source := &PostgresRuntimeEvidenceSource{issueTokenKey: bytes.Repeat([]byte{0x5a}, 32)}
	principal := RuntimeEvidencePrincipal{TenantScopeID: uuid.New(), ActorUserID: uuid.New(), SessionID: uuid.New()}
	// base64url output starts with '-' or '_' for 1 in 32 digests; every
	// issued token must still be accepted where it is presented (Reserve,
	// the create request body).
	for index := range 2048 {
		request := RuntimeEvidenceIssueRequest{Kind: identityverification.KindPersonalInitial,
			IssuerWorkloadID: "kyc-issuer", IssuerIdempotencyKey: "issue-" + strconv.Itoa(index)}
		if token := source.issueToken(principal, request); !tokenPattern.MatchString(token) {
			t.Fatalf("issued token %q does not match tokenPattern", token)
		}
	}
}
