package originauthcontrol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type ProductionCredentialMaterial struct {
	RevisionRef uuid.UUID
	Provider    string
	Secret      CredentialSecret `json:"-"`
}

type ProductionMaterial struct {
	PublicationID       uuid.UUID
	TenantID            uuid.UUID
	TenantScopeID       uuid.UUID
	PublicationRevision uint64
	Snapshot            PublicationSnapshot
	CanonicalSnapshot   []byte
	Credentials         []ProductionCredentialMaterial
}

type ProductionSource struct{ service *Service }

func NewProductionSource(service *Service) (*ProductionSource, error) {
	if service == nil || service.keyring == nil || !service.keyring.configured() {
		return nil, ErrInvalidInput
	}
	return &ProductionSource{service: service}, nil
}

func (source *ProductionSource) Build(ctx context.Context, tx pgx.Tx, targetScopeID uuid.UUID) (ProductionMaterial, error) {
	if source == nil || source.service == nil || ctx == nil || tx == nil || targetScopeID == uuid.Nil {
		return ProductionMaterial{}, ErrInvalidInput
	}
	var material ProductionMaterial
	var revision int64
	var storedHash []byte
	err := tx.QueryRow(ctx, `SELECT id,tenant_id,tenant_scope_id,revision,canonical_snapshot,snapshot_sha256
		FROM origin_auth_publications WHERE tenant_scope_id=$1
		ORDER BY revision DESC LIMIT 1 FOR SHARE`, targetScopeID).Scan(
		&material.PublicationID, &material.TenantID, &material.TenantScopeID, &revision,
		&material.CanonicalSnapshot, &storedHash,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return ProductionMaterial{}, ErrNotFound
	}
	if err != nil || revision < 1 || revision > maxSafeRevision || len(storedHash) != sha256.Size {
		return ProductionMaterial{}, ErrUnavailable
	}
	material.PublicationRevision = uint64(revision)
	digest := sha256.Sum256(material.CanonicalSnapshot)
	if !bytes.Equal(digest[:], storedHash) || json.Unmarshal(material.CanonicalSnapshot, &material.Snapshot) != nil {
		return ProductionMaterial{}, ErrUnavailable
	}
	refs := publicationCredentialRefs(material.Snapshot)
	if len(refs) == 0 {
		return ProductionMaterial{}, ErrValidation
	}
	rows, err := tx.Query(ctx, `SELECT identity.id,identity.tenant_scope_id,identity.provider,
		`+sealedRevisionColumn+`,revision.revision_ref,revision.status,revision.envelope_key_id,
		revision.secret_ciphertext,revision.secret_ciphertext_sha256,revision.not_before,revision.expires_at
		FROM origin_auth_credential_revisions revision
		JOIN origin_auth_credentials identity ON identity.id=revision.credential_id
		WHERE identity.tenant_scope_id=$1 AND revision.revision_ref = ANY($2)
		ORDER BY revision.revision_ref`, targetScopeID, refs)
	if err != nil {
		return ProductionMaterial{}, ErrUnavailable
	}
	defer rows.Close()
	for rows.Next() {
		var stored storedCredential
		var revisionRef uuid.UUID
		var status string
		var cipherDigest []byte
		if err := rows.Scan(&stored.ID, &stored.TenantScope, &stored.Provider, &stored.Revision, &revisionRef,
			&status, &stored.keyID, &stored.ciphertext, &cipherDigest, &stored.NotBefore, &stored.ExpiresAt); err != nil {
			clearProductionMaterial(&material)
			return ProductionMaterial{}, ErrUnavailable
		}
		cipherHash := sha256.Sum256(stored.ciphertext)
		if stored.TenantScope != targetScopeID || status != StatusVerified || revisionRef == uuid.Nil ||
			len(cipherDigest) != sha256.Size || !bytes.Equal(cipherHash[:], cipherDigest) {
			clearProductionMaterial(&material)
			return ProductionMaterial{}, ErrUnavailable
		}
		secret, err := source.decryptProductionCredential(stored)
		clearBytes(stored.ciphertext)
		if err != nil || !storeTime(secret.NotBefore).Equal(storeTime(stored.NotBefore)) ||
			!storeTime(secret.ExpiresAt).Equal(storeTime(stored.ExpiresAt)) {
			clearSecret(&secret)
			clearProductionMaterial(&material)
			return ProductionMaterial{}, ErrEncryptionUnavailable
		}
		material.Credentials = append(material.Credentials, ProductionCredentialMaterial{
			RevisionRef: revisionRef, Provider: stored.Provider, Secret: secret,
		})
	}
	if rows.Err() != nil {
		clearProductionMaterial(&material)
		return ProductionMaterial{}, ErrUnavailable
	}
	if err := validateProductionMaterial(&material); err != nil {
		clearProductionMaterial(&material)
		return ProductionMaterial{}, err
	}
	return material, nil
}

func (source *ProductionSource) decryptProductionCredential(stored storedCredential) (CredentialSecret, error) {
	plaintext, err := source.service.keyring.open(stored.keyID, stored.ciphertext,
		credentialAAD(stored.ID, stored.Revision, stored.Provider))
	if err != nil {
		return CredentialSecret{}, ErrEncryptionUnavailable
	}
	defer clearBytes(plaintext)
	return decodeSecret(plaintext, stored.Provider)
}

func validateProductionMaterial(material *ProductionMaterial) error {
	if material == nil || material.PublicationID == uuid.Nil || material.TenantID == uuid.Nil || material.TenantScopeID == uuid.Nil ||
		material.PublicationRevision == 0 || material.PublicationRevision > uint64(maxSafeRevision) ||
		material.Snapshot.SchemaVersion != publicationSchema || material.Snapshot.TenantScopeID != material.TenantScopeID ||
		material.Snapshot.PublicationRevision != int64(material.PublicationRevision) || len(material.Snapshot.Rules) == 0 ||
		len(material.Snapshot.Rules) > maximumPublicationRules {
		return ErrValidation
	}
	canonical, err := encodeJSON(material.Snapshot)
	if err != nil || !bytes.Equal(canonical, material.CanonicalSnapshot) {
		return ErrUnavailable
	}
	wanted := make(map[uuid.UUID]string)
	origins := make(map[string]struct{}, len(material.Snapshot.Rules))
	for _, rule := range material.Snapshot.Rules {
		origin := fmt.Sprintf("%s/%d", rule.SiteID, rule.SourcePosition)
		if rule.RuleID == uuid.Nil || rule.SiteID == uuid.Nil || rule.SourcePosition < 1 || rule.SourcePosition > 32 ||
			rule.CurrentCredentialRevisionRef == uuid.Nil || !productionProviderAlgorithm(rule.Provider, rule.Algorithm) {
			return ErrValidation
		}
		if _, duplicate := origins[origin]; duplicate {
			return ErrValidation
		}
		origins[origin] = struct{}{}
		for _, ref := range []*uuid.UUID{&rule.CurrentCredentialRevisionRef, rule.PreviousCredentialRevisionRef} {
			if ref == nil {
				continue
			}
			if *ref == uuid.Nil || wanted[*ref] != "" && wanted[*ref] != rule.Provider {
				return ErrValidation
			}
			wanted[*ref] = rule.Provider
		}
	}
	if len(material.Credentials) != len(wanted) {
		return ErrValidation
	}
	seen := make(map[uuid.UUID]struct{}, len(material.Credentials))
	for _, credential := range material.Credentials {
		if credential.RevisionRef == uuid.Nil || wanted[credential.RevisionRef] != credential.Provider ||
			!validSecret(credential.Secret.AccessKeyID, 256) || !validSecret(credential.Secret.SecretAccessKey, 512) ||
			credential.Secret.SessionToken != "" && !validSecret(credential.Secret.SessionToken, 4096) ||
			credential.Secret.NotBefore.IsZero() || !credential.Secret.ExpiresAt.After(credential.Secret.NotBefore) {
			return ErrValidation
		}
		if _, duplicate := seen[credential.RevisionRef]; duplicate {
			return ErrValidation
		}
		seen[credential.RevisionRef] = struct{}{}
	}
	return nil
}

func publicationCredentialRefs(snapshot PublicationSnapshot) []uuid.UUID {
	unique := make(map[uuid.UUID]struct{})
	for _, rule := range snapshot.Rules {
		unique[rule.CurrentCredentialRevisionRef] = struct{}{}
		if rule.PreviousCredentialRevisionRef != nil {
			unique[*rule.PreviousCredentialRevisionRef] = struct{}{}
		}
	}
	refs := make([]uuid.UUID, 0, len(unique))
	for ref := range unique {
		refs = append(refs, ref)
	}
	sort.Slice(refs, func(i, j int) bool { return bytes.Compare(refs[i][:], refs[j][:]) < 0 })
	return refs
}

func productionProviderAlgorithm(provider, algorithm string) bool {
	return provider == ProviderS3 && algorithm == AlgorithmS3 || provider == ProviderOSS && algorithm == AlgorithmOSS || provider == ProviderCOS && algorithm == AlgorithmCOS
}

func cloneProductionMaterial(material ProductionMaterial) ProductionMaterial {
	result := material
	result.CanonicalSnapshot = bytes.Clone(material.CanonicalSnapshot)
	result.Snapshot.Rules = append([]PublicationRule(nil), material.Snapshot.Rules...)
	result.Credentials = append([]ProductionCredentialMaterial(nil), material.Credentials...)
	return result
}

func clearProductionMaterial(material *ProductionMaterial) {
	if material == nil {
		return
	}
	clearBytes(material.CanonicalSnapshot)
	for index := range material.Credentials {
		clearSecret(&material.Credentials[index].Secret)
	}
}
