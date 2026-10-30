package identityverificationissuerhttp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/identityverification"
	identityverificationhttp "github.com/cdnca/cdnca/services/control-api/internal/identityverificationhttp"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	materialEnvelopeAADDomain   = "cdnca.identity-verification.material-envelope.aad.v1\x00"
	materialEnvelopeClaimDomain = "cdnca.identity-verification.evidence-claim.v1\x00"
	privateEnvelopeDigestDomain = "cdnca.identity-verification.private-envelope.v1\x00"
)

type WorkloadIdentity struct {
	URI        string
	WorkloadID string
}

type MTLSAuthenticator struct {
	identities map[string]string
	now        Clock
}

func NewMTLSAuthenticator(identities []WorkloadIdentity, now Clock) (*MTLSAuthenticator, error) {
	if len(identities) == 0 || len(identities) > 1024 {
		return nil, ErrInvalidConfig
	}
	if now == nil {
		now = time.Now
	}
	authenticator := &MTLSAuthenticator{identities: make(map[string]string, len(identities)), now: now}
	for _, identity := range identities {
		uri, ok := canonicalWorkloadURI(identity.URI)
		if !ok || !validMetadata(identity.WorkloadID) {
			return nil, ErrInvalidConfig
		}
		if _, duplicate := authenticator.identities[uri]; duplicate {
			return nil, ErrInvalidConfig
		}
		authenticator.identities[uri] = identity.WorkloadID
	}
	return authenticator, nil
}

func (authenticator *MTLSAuthenticator) Authenticate(request *http.Request) (WorkloadPrincipal, error) {
	if authenticator == nil || authenticator.now == nil || request == nil || request.TLS == nil ||
		len(request.Header.Values("Authorization")) != 0 || len(request.Header.Values("Cookie")) != 0 ||
		len(request.TLS.VerifiedChains) == 0 || len(request.TLS.VerifiedChains[0]) == 0 {
		return WorkloadPrincipal{}, ErrUnauthenticated
	}
	leaf := request.TLS.VerifiedChains[0][0]
	if leaf == nil || len(leaf.Raw) == 0 || len(leaf.URIs) != 1 || leaf.URIs[0] == nil ||
		len(leaf.DNSNames) != 0 || len(leaf.EmailAddresses) != 0 || len(leaf.IPAddresses) != 0 ||
		!emptyCertificateSubject(leaf.Subject) || !clientAuthCertificate(leaf) {
		return WorkloadPrincipal{}, ErrUnauthenticated
	}
	now := authenticator.now().UTC()
	if leaf.NotBefore.IsZero() || leaf.NotAfter.IsZero() || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return WorkloadPrincipal{}, ErrUnauthenticated
	}
	for _, chain := range request.TLS.VerifiedChains {
		if len(chain) == 0 || chain[0] == nil || !bytes.Equal(chain[0].Raw, leaf.Raw) {
			return WorkloadPrincipal{}, ErrUnauthenticated
		}
	}
	uri, ok := canonicalWorkloadURI(leaf.URIs[0].String())
	if !ok || uri != leaf.URIs[0].String() {
		return WorkloadPrincipal{}, ErrUnauthenticated
	}
	workloadID, ok := authenticator.identities[uri]
	if !ok {
		return WorkloadPrincipal{}, ErrUnauthenticated
	}
	principal := WorkloadPrincipal{WorkloadID: workloadID, Audience: WorkloadAudience,
		Permissions: []string{IssuePermission}, CertificateFingerprint: sha256.Sum256(leaf.Raw)}
	if !principal.Valid() {
		return WorkloadPrincipal{}, ErrUnauthenticated
	}
	return principal, nil
}

func canonicalWorkloadURI(raw string) (string, bool) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "spiffe" || parsed.User != nil || parsed.Host == "" ||
		parsed.Host != parsed.Hostname() || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" ||
		parsed.Opaque != "" || parsed.RawPath != "" || !strings.HasPrefix(parsed.Path, "/") {
		return "", false
	}
	for _, segment := range strings.Split(parsed.Path[1:], "/") {
		if segment == "" || segment == "." || segment == ".." {
			return "", false
		}
	}
	canonical := parsed.String()
	return canonical, canonical == raw
}

func emptyCertificateSubject(subject pkix.Name) bool {
	return len(subject.Country) == 0 && len(subject.Organization) == 0 && len(subject.OrganizationalUnit) == 0 &&
		len(subject.Locality) == 0 && len(subject.Province) == 0 && len(subject.StreetAddress) == 0 &&
		len(subject.PostalCode) == 0 && subject.SerialNumber == "" && subject.CommonName == "" &&
		len(subject.Names) == 0 && len(subject.ExtraNames) == 0
}

func clientAuthCertificate(certificate *x509.Certificate) bool {
	if certificate == nil {
		return false
	}
	for _, usage := range certificate.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth {
			return true
		}
	}
	return false
}

type MaterialEnvelopeSealRequest struct {
	TenantScopeID   uuid.UUID
	ActorUserID     uuid.UUID
	SessionID       uuid.UUID
	UploadID        uuid.UUID
	MaterialKind    string
	ObjectKey       string
	ObjectVersion   string
	ObjectSHA256    [sha256.Size]byte
	MIMEType        string
	SizeBytes       int64
	EncryptionKeyID string
}

type MaterialEnvelopeSealResult struct {
	Provider   string
	KeyID      string
	Ciphertext []byte
	AADSHA256  [sha256.Size]byte
}

type MaterialEnvelopeSealer interface {
	Seal(context.Context, MaterialEnvelopeSealRequest) (MaterialEnvelopeSealResult, error)
}

type kmsEncryptClient interface {
	Encrypt(context.Context, *kms.EncryptInput, ...func(*kms.Options)) (*kms.EncryptOutput, error)
}

type KMSMaterialEnvelopeSealer struct {
	client kmsEncryptClient
}

func NewKMSMaterialEnvelopeSealer(client kmsEncryptClient) (*KMSMaterialEnvelopeSealer, error) {
	if nilInterface(client) {
		return nil, ErrInvalidConfig
	}
	return &KMSMaterialEnvelopeSealer{client: client}, nil
}

func (sealer *KMSMaterialEnvelopeSealer) Seal(ctx context.Context,
	request MaterialEnvelopeSealRequest,
) (MaterialEnvelopeSealResult, error) {
	plaintext, aad, encryptionContext, err := materialEnvelopePayload(request)
	if err != nil || sealer == nil || nilInterface(sealer.client) || ctx == nil {
		clear(plaintext)
		return MaterialEnvelopeSealResult{}, ErrEvidenceInvalid
	}
	defer clear(plaintext)
	output, err := sealer.client.Encrypt(ctx, &kms.EncryptInput{KeyId: aws.String(request.EncryptionKeyID),
		Plaintext: plaintext, EncryptionContext: encryptionContext})
	if err != nil || output == nil || output.KeyId == nil || !validOpaque(*output.KeyId) ||
		len(output.CiphertextBlob) < 16 || len(output.CiphertextBlob) > 16384 {
		return MaterialEnvelopeSealResult{}, ErrEvidenceUnavailable
	}
	return MaterialEnvelopeSealResult{Provider: "aws-kms", KeyID: *output.KeyId,
		Ciphertext: append([]byte(nil), output.CiphertextBlob...), AADSHA256: sha256.Sum256(aad)}, nil
}

type providerEvidenceUpload struct {
	ID              uuid.UUID
	MaterialKind    string
	ObjectKey       string
	ObjectVersion   string
	ObjectSHA256    [sha256.Size]byte
	SizeBytes       int64
	MIMEType        string
	EncryptionKeyID string
}

type providerEvidenceSnapshot struct {
	Principal              identityverificationhttp.RuntimeEvidencePrincipal
	SessionID              uuid.UUID
	Kind                   string
	SubjectFingerprint     [sha256.Size]byte
	OrganizationName       string
	LegalPersonFingerprint [sha256.Size]byte
	AgentFingerprint       [sha256.Size]byte
	AgentRelationship      string
	NormalizedDigest       [sha256.Size]byte
	RetentionUntil         time.Time
	Uploads                []providerEvidenceUpload
}

type persistedMaterialEnvelope struct {
	UploadID   uuid.UUID
	Provider   string
	KeyID      string
	Ciphertext []byte
	AADSHA256  [sha256.Size]byte
}

type PostgresEvidenceResolver struct {
	pool    *pgxpool.Pool
	sealer  MaterialEnvelopeSealer
	auditor identityverification.AuditAppender
}

func NewPostgresEvidenceResolver(pool *pgxpool.Pool, sealer MaterialEnvelopeSealer,
	auditor identityverification.AuditAppender,
) (*PostgresEvidenceResolver, error) {
	if pool == nil || nilInterface(sealer) || nilInterface(auditor) {
		return nil, ErrInvalidConfig
	}
	return &PostgresEvidenceResolver{pool: pool, sealer: sealer, auditor: auditor}, nil
}

func (resolver *PostgresEvidenceResolver) Resolve(ctx context.Context,
	request EvidenceResolveRequest,
) (ResolvedEvidence, error) {
	if resolver == nil || resolver.pool == nil || nilInterface(resolver.sealer) || nilInterface(resolver.auditor) || ctx == nil ||
		!validMetadata(request.WorkloadID) || request.Audience != WorkloadAudience || !validKind(request.Kind) ||
		!validOpaque(request.EvidenceReference) || !validMetadata(request.IdempotencyKey) ||
		!validMetadata(request.RequestID) || request.RequestDigest == ([sha256.Size]byte{}) || request.ExpiresAt.IsZero() {
		return ResolvedEvidence{}, ErrEvidenceInvalid
	}
	tokenDigest := sha256.Sum256([]byte(request.EvidenceReference))
	snapshot, err := resolver.readSnapshot(ctx, tokenDigest, request.Kind, request.ExpiresAt)
	if err != nil {
		return ResolvedEvidence{}, mapResolverError(ctx, err)
	}
	envelopes := make([]persistedMaterialEnvelope, len(snapshot.Uploads))
	for index, upload := range snapshot.Uploads {
		envelopes[index], err = resolver.materialEnvelope(ctx, snapshot, upload)
		if err != nil {
			clearMaterialEnvelopes(envelopes)
			return ResolvedEvidence{}, mapResolverError(ctx, err)
		}
	}
	stable, err := resolver.readSnapshot(ctx, tokenDigest, request.Kind, request.ExpiresAt)
	if err != nil || !equalProviderEvidenceSnapshot(snapshot, stable) {
		clearMaterialEnvelopes(envelopes)
		if err != nil {
			return ResolvedEvidence{}, mapResolverError(ctx, err)
		}
		return ResolvedEvidence{}, ErrEvidenceInvalid
	}
	result, err := resolvedProviderEvidence(snapshot, envelopes, request)
	clearMaterialEnvelopes(envelopes)
	if err != nil {
		return ResolvedEvidence{}, err
	}
	return result, nil
}

func (resolver *PostgresEvidenceResolver) readSnapshot(ctx context.Context, tokenDigest [sha256.Size]byte,
	kind string, expiresAt time.Time,
) (providerEvidenceSnapshot, error) {
	var snapshot providerEvidenceSnapshot
	err := pgx.BeginFunc(ctx, resolver.pool, func(tx pgx.Tx) error {
		var subject, legalPerson, agent, normalized []byte
		var organization, relationship *string
		err := tx.QueryRow(ctx, `SELECT session.tenant_scope_id,session.actor_user_id,session.actor_session_id,
			       session.id,session.kind,settlement.subject_fingerprint,settlement.organization_name,
			       settlement.legal_person_fingerprint,settlement.agent_fingerprint,settlement.agent_relationship,
			       settlement.normalized_evidence_sha256,settlement.retention_until
			FROM identity_verification_provider_sessions_v1 session
			JOIN identity_verification_provider_settlements_v1 settlement
			  ON settlement.session_id=session.id AND settlement.tenant_scope_id=session.tenant_scope_id
			 AND settlement.actor_user_id=session.actor_user_id AND settlement.kind=session.kind
			JOIN auth_sessions auth_session ON auth_session.id=session.actor_session_id
			 AND auth_session.scope_id=session.tenant_scope_id AND auth_session.user_id=session.actor_user_id
			JOIN users user_account ON user_account.id=session.actor_user_id
			JOIN memberships membership ON membership.scope_id=session.tenant_scope_id
			 AND membership.user_id=session.actor_user_id
			JOIN access_scopes access_scope ON access_scope.id=session.tenant_scope_id AND access_scope.kind='tenant'
			JOIN tenants tenant ON tenant.id=access_scope.tenant_id
			WHERE session.evidence_token_digest=$1 AND session.kind=$2 AND session.state='succeeded'
			  AND user_account.status='active' AND membership.status='active' AND tenant.status='active'
			  AND auth_session.revoked_at IS NULL AND auth_session.expires_at>clock_timestamp()
			  AND $3>clock_timestamp() AND $3<=settlement.retention_until
			FOR SHARE OF session,settlement,auth_session,user_account,membership,access_scope,tenant`,
			tokenDigest[:], kind, expiresAt).Scan(&snapshot.Principal.TenantScopeID,
			&snapshot.Principal.ActorUserID, &snapshot.Principal.SessionID, &snapshot.SessionID, &snapshot.Kind,
			&subject, &organization, &legalPerson, &agent, &relationship, &normalized, &snapshot.RetentionUntil)
		if err != nil {
			return err
		}
		if len(subject) != sha256.Size || len(normalized) != sha256.Size ||
			(legalPerson != nil && len(legalPerson) != sha256.Size) || (agent != nil && len(agent) != sha256.Size) {
			return ErrEvidenceInvalid
		}
		copy(snapshot.SubjectFingerprint[:], subject)
		copy(snapshot.NormalizedDigest[:], normalized)
		if organization != nil {
			snapshot.OrganizationName = *organization
		}
		if legalPerson != nil {
			copy(snapshot.LegalPersonFingerprint[:], legalPerson)
		}
		if agent != nil {
			copy(snapshot.AgentFingerprint[:], agent)
		}
		if relationship != nil {
			snapshot.AgentRelationship = *relationship
		}
		rows, err := tx.Query(ctx, `SELECT id,material_kind,object_key,object_version,object_sha256,
			       size_bytes,content_type,encryption_key_id
			FROM identity_verification_provider_uploads_v1
			WHERE session_id=$1 AND tenant_scope_id=$2 AND actor_user_id=$3 AND state='finalized'
			ORDER BY material_kind,id FOR SHARE`, snapshot.SessionID, snapshot.Principal.TenantScopeID,
			snapshot.Principal.ActorUserID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var upload providerEvidenceUpload
			var digest []byte
			if err := rows.Scan(&upload.ID, &upload.MaterialKind, &upload.ObjectKey, &upload.ObjectVersion,
				&digest, &upload.SizeBytes, &upload.MIMEType, &upload.EncryptionKeyID); err != nil {
				return err
			}
			if len(digest) != sha256.Size {
				return ErrEvidenceInvalid
			}
			copy(upload.ObjectSHA256[:], digest)
			snapshot.Uploads = append(snapshot.Uploads, upload)
		}
		return rows.Err()
	})
	return snapshot, err
}

func (resolver *PostgresEvidenceResolver) materialEnvelope(ctx context.Context, snapshot providerEvidenceSnapshot,
	upload providerEvidenceUpload,
) (persistedMaterialEnvelope, error) {
	existing, err := resolver.readMaterialEnvelope(ctx, upload.ID)
	if err == nil {
		return existing, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return persistedMaterialEnvelope{}, err
	}
	sealed, err := resolver.sealer.Seal(ctx, MaterialEnvelopeSealRequest{TenantScopeID: snapshot.Principal.TenantScopeID,
		ActorUserID: snapshot.Principal.ActorUserID, SessionID: snapshot.SessionID, UploadID: upload.ID,
		MaterialKind: upload.MaterialKind, ObjectKey: upload.ObjectKey, ObjectVersion: upload.ObjectVersion,
		ObjectSHA256: upload.ObjectSHA256, MIMEType: upload.MIMEType, SizeBytes: upload.SizeBytes,
		EncryptionKeyID: upload.EncryptionKeyID})
	if err != nil || !validMaterialEnvelope(sealed) {
		clear(sealed.Ciphertext)
		return persistedMaterialEnvelope{}, ErrEvidenceUnavailable
	}
	envelopeID := uuid.New()
	err = pgx.BeginFunc(ctx, resolver.pool, func(tx pgx.Tx) error {
		var inserted uuid.UUID
		err := tx.QueryRow(ctx, `INSERT INTO identity_verification_provider_material_envelopes_v1(
			id,upload_id,session_id,tenant_scope_id,actor_user_id,envelope_provider,envelope_key_id,
			encrypted_envelope,envelope_aad_sha256,created_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,clock_timestamp()) ON CONFLICT(upload_id) DO NOTHING RETURNING id`,
			envelopeID, upload.ID, snapshot.SessionID, snapshot.Principal.TenantScopeID, snapshot.Principal.ActorUserID,
			sealed.Provider, sealed.KeyID, sealed.Ciphertext, sealed.AADSHA256[:]).Scan(&inserted)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		return resolver.auditor.Append(ctx, tx, audit.Event{ScopeID: snapshot.Principal.TenantScopeID,
			ActorUserID: &snapshot.Principal.ActorUserID, Action: "identity_verification.material_envelope.created",
			ResourceType: "identity_verification_material_envelope", ResourceID: inserted.String(),
			RequestID: "identity-material-envelope-" + inserted.String(), Result: "success",
			Payload: map[string]any{"session_id": snapshot.SessionID.String(), "upload_id": upload.ID.String()}})
	})
	clear(sealed.Ciphertext)
	if err != nil {
		return persistedMaterialEnvelope{}, err
	}
	return resolver.readMaterialEnvelope(ctx, upload.ID)
}

func (resolver *PostgresEvidenceResolver) readMaterialEnvelope(ctx context.Context,
	uploadID uuid.UUID,
) (persistedMaterialEnvelope, error) {
	var result persistedMaterialEnvelope
	var aad []byte
	err := resolver.pool.QueryRow(ctx, `SELECT upload_id,envelope_provider,envelope_key_id,encrypted_envelope,envelope_aad_sha256
		FROM identity_verification_provider_material_envelopes_v1 WHERE upload_id=$1`, uploadID).Scan(
		&result.UploadID, &result.Provider, &result.KeyID, &result.Ciphertext, &aad)
	if err != nil {
		return persistedMaterialEnvelope{}, err
	}
	if len(aad) != sha256.Size || result.UploadID != uploadID || len(result.Ciphertext) < 16 || len(result.Ciphertext) > 16384 ||
		!validOpaque(result.Provider) || !validOpaque(result.KeyID) {
		clear(result.Ciphertext)
		return persistedMaterialEnvelope{}, ErrEvidenceInvalid
	}
	copy(result.AADSHA256[:], aad)
	return result, nil
}

func resolvedProviderEvidence(snapshot providerEvidenceSnapshot, envelopes []persistedMaterialEnvelope,
	request EvidenceResolveRequest,
) (ResolvedEvidence, error) {
	if len(snapshot.Uploads) != len(envelopes) || len(snapshot.Uploads) < 2 || len(snapshot.Uploads) > 16 {
		return ResolvedEvidence{}, ErrEvidenceInvalid
	}
	evidence := identityverificationhttp.ResolvedEvidence{Kind: snapshot.Kind,
		SubjectFingerprint: append([]byte(nil), snapshot.SubjectFingerprint[:]...),
		OrganizationName:   snapshot.OrganizationName, AgentRelationship: snapshot.AgentRelationship}
	if snapshot.LegalPersonFingerprint != ([sha256.Size]byte{}) {
		evidence.LegalPersonFingerprint = append([]byte(nil), snapshot.LegalPersonFingerprint[:]...)
	}
	if snapshot.AgentFingerprint != ([sha256.Size]byte{}) {
		evidence.AgentFingerprint = append([]byte(nil), snapshot.AgentFingerprint[:]...)
	}
	privateDigest := sha256.New()
	_, _ = privateDigest.Write([]byte(privateEnvelopeDigestDomain))
	for index, upload := range snapshot.Uploads {
		if envelopes[index].UploadID != upload.ID {
			return ResolvedEvidence{}, ErrEvidenceInvalid
		}
		wire, err := json.Marshal(struct {
			Version    int    `json:"version"`
			Provider   string `json:"provider"`
			KeyID      string `json:"key_id"`
			AADSHA256  string `json:"aad_sha256"`
			Ciphertext string `json:"ciphertext"`
		}{1, envelopes[index].Provider, envelopes[index].KeyID,
			hex.EncodeToString(envelopes[index].AADSHA256[:]), base64.RawURLEncoding.EncodeToString(envelopes[index].Ciphertext)})
		if err != nil || len(wire) < 16 || len(wire) > 16384 {
			clear(wire)
			return ResolvedEvidence{}, ErrEvidenceInvalid
		}
		_, _ = privateDigest.Write(wire)
		evidence.Materials = append(evidence.Materials, identityverification.MaterialInput{Kind: upload.MaterialKind,
			EnvelopeProvider: envelopes[index].Provider, EnvelopeKeyID: envelopes[index].KeyID,
			EncryptedEnvelope: wire, ObjectReference: upload.ObjectKey,
			ObjectSHA256: append([]byte(nil), upload.ObjectSHA256[:]...), MIMEType: upload.MIMEType,
			SizeBytes: upload.SizeBytes})
	}
	var privateEnvelopeDigest [sha256.Size]byte
	copy(privateEnvelopeDigest[:], privateDigest.Sum(nil))
	claimDigest, err := providerEvidenceClaimDigest(snapshot, evidence)
	if err != nil {
		clearResolvedEvidenceValue(&evidence)
		return ResolvedEvidence{}, err
	}
	return ResolvedEvidence{Principal: snapshot.Principal, Kind: snapshot.Kind,
		PrivateObjectReference: "identity-verification/provider-session/" + snapshot.SessionID.String(),
		PrivateEnvelopeDigest:  privateEnvelopeDigest, EvidenceClaimDigest: claimDigest, Evidence: evidence,
		ExpiresAt: request.ExpiresAt.UTC().Truncate(time.Microsecond), RequestDigest: request.RequestDigest}, nil
}

func materialEnvelopePayload(request MaterialEnvelopeSealRequest) ([]byte, []byte, map[string]string, error) {
	if request.TenantScopeID == uuid.Nil || request.ActorUserID == uuid.Nil || request.SessionID == uuid.Nil ||
		request.UploadID == uuid.Nil || !validMaterialKind(request.MaterialKind) || !validOpaque(request.ObjectKey) ||
		!validOpaque(request.ObjectVersion) || request.ObjectSHA256 == ([sha256.Size]byte{}) ||
		!validMIME(request.MIMEType) || request.SizeBytes < 1 || request.SizeBytes > 20*1024*1024 ||
		!validOpaque(request.EncryptionKeyID) {
		return nil, nil, nil, ErrEvidenceInvalid
	}
	contextValues := map[string]string{"tenant_scope_id": request.TenantScopeID.String(),
		"actor_user_id": request.ActorUserID.String(), "session_id": request.SessionID.String(),
		"upload_id": request.UploadID.String(), "material_kind": request.MaterialKind,
		"object_sha256": hex.EncodeToString(request.ObjectSHA256[:])}
	aad, err := json.Marshal(struct {
		Domain string            `json:"domain"`
		Values map[string]string `json:"values"`
	}{materialEnvelopeAADDomain, contextValues})
	if err != nil {
		return nil, nil, nil, ErrEvidenceInvalid
	}
	plaintext, err := json.Marshal(struct {
		ObjectKey, ObjectVersion, ObjectSHA256, MIMEType string
		SizeBytes                                        int64
	}{request.ObjectKey, request.ObjectVersion, hex.EncodeToString(request.ObjectSHA256[:]), request.MIMEType, request.SizeBytes})
	if err != nil || len(plaintext) == 0 || len(plaintext) > 4096 {
		clear(plaintext)
		return nil, nil, nil, ErrEvidenceInvalid
	}
	return plaintext, aad, contextValues, nil
}

func providerEvidenceClaimDigest(snapshot providerEvidenceSnapshot,
	evidence identityverificationhttp.ResolvedEvidence,
) ([sha256.Size]byte, error) {
	payload, err := json.Marshal(struct {
		Domain           string                                    `json:"domain"`
		TenantScopeID    uuid.UUID                                 `json:"tenant_scope_id"`
		ActorUserID      uuid.UUID                                 `json:"actor_user_id"`
		SessionID        uuid.UUID                                 `json:"session_id"`
		NormalizedDigest string                                    `json:"normalized_digest"`
		Evidence         identityverificationhttp.ResolvedEvidence `json:"evidence"`
	}{materialEnvelopeClaimDomain, snapshot.Principal.TenantScopeID, snapshot.Principal.ActorUserID,
		snapshot.SessionID, hex.EncodeToString(snapshot.NormalizedDigest[:]), evidence})
	if err != nil {
		return [sha256.Size]byte{}, ErrEvidenceInvalid
	}
	return sha256.Sum256(payload), nil
}

func validMaterialEnvelope(value MaterialEnvelopeSealResult) bool {
	return validOpaque(value.Provider) && validOpaque(value.KeyID) && len(value.Ciphertext) >= 16 &&
		len(value.Ciphertext) <= 16384 && value.AADSHA256 != ([sha256.Size]byte{})
}

func validMaterialKind(value string) bool {
	switch value {
	case identityverification.MaterialIdentityDocument, identityverification.MaterialLivenessEvidence,
		identityverification.MaterialBusinessLicense, identityverification.MaterialLegalIdentity,
		identityverification.MaterialAgentIdentity, identityverification.MaterialAuthorization,
		identityverification.MaterialSupplementary:
		return true
	}
	return false
}

func validMIME(value string) bool {
	switch value {
	case "image/jpeg", "image/png", "application/pdf", "video/mp4":
		return true
	}
	return false
}

func equalProviderEvidenceSnapshot(left, right providerEvidenceSnapshot) bool {
	if left.Principal != right.Principal || left.SessionID != right.SessionID || left.Kind != right.Kind ||
		left.SubjectFingerprint != right.SubjectFingerprint || left.OrganizationName != right.OrganizationName ||
		left.LegalPersonFingerprint != right.LegalPersonFingerprint || left.AgentFingerprint != right.AgentFingerprint ||
		left.AgentRelationship != right.AgentRelationship || left.NormalizedDigest != right.NormalizedDigest ||
		!left.RetentionUntil.Equal(right.RetentionUntil) || len(left.Uploads) != len(right.Uploads) {
		return false
	}
	for index := range left.Uploads {
		if left.Uploads[index] != right.Uploads[index] {
			return false
		}
	}
	return true
}

func mapResolverError(ctx context.Context, err error) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, ErrEvidenceInvalid) || errors.Is(err, ErrReplayConflict) {
		return ErrEvidenceInvalid
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return ErrEvidenceUnavailable
}

func clearMaterialEnvelopes(values []persistedMaterialEnvelope) {
	for index := range values {
		clear(values[index].Ciphertext)
	}
}

func clearResolvedEvidenceValue(value *identityverificationhttp.ResolvedEvidence) {
	if value == nil {
		return
	}
	for index := range value.Materials {
		clear(value.Materials[index].EncryptedEnvelope)
		clear(value.Materials[index].ObjectSHA256)
	}
	clear(value.SubjectFingerprint)
	clear(value.LegalPersonFingerprint)
	clear(value.AgentFingerprint)
}
