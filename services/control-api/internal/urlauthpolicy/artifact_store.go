package urlauthpolicy

import (
	"context"
	"crypto/hmac"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type ArtifactPublicationService struct {
	store    *Store
	cipher   BoundSecretCipher
	producer *ArtifactProducer
}

func NewArtifactPublicationService(store *Store, cipher BoundSecretCipher, producer *ArtifactProducer) (*ArtifactPublicationService, error) {
	if store == nil || store.pool == nil || store.authorizer == nil || cipher == nil || producer == nil {
		return nil, ErrUnavailable
	}
	return &ArtifactPublicationService{store: store, cipher: cipher, producer: producer}, nil
}

func (service *ArtifactPublicationService) Build(
	ctx context.Context,
	actor Actor,
	policyID uuid.UUID,
	requestID string,
	request ArtifactBuildRequest,
) (edgedeployment.ArtifactInput, error) {
	if service == nil || service.store == nil || service.cipher == nil || service.producer == nil ||
		!validActor(actor) || policyID == uuid.Nil || strings.TrimSpace(requestID) == "" || strings.TrimSpace(requestID) != requestID || len(requestID) > 256 {
		return edgedeployment.ArtifactInput{}, ErrInvalidInput
	}
	material, err := service.loadMaterial(ctx, actor, policyID, request.ConfigurationScopeID, requestID)
	if err != nil {
		return edgedeployment.ArtifactInput{}, err
	}
	defer clearArtifactSecrets(material.Keys)
	return service.producer.Build(ctx, request, material)
}

func (service *ArtifactPublicationService) loadMaterial(
	ctx context.Context,
	actor Actor,
	policyID, configurationScopeID uuid.UUID,
	requestID string,
) (ArtifactMaterial, error) {
	var material ArtifactMaterial
	err := pgx.BeginFunc(ctx, service.store.pool, func(tx pgx.Tx) error {
		var targetScopeID uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT scope_id FROM url_auth_policies WHERE id=$1`, policyID).Scan(&targetScopeID); errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		authorizedTenantID, err := service.store.authorizer.Authorize(ctx, tx, actor, targetScopeID, PermissionManage)
		if err != nil {
			return err
		}
		// The artifact rides the deployment command of the scope that owns
		// the policy; the agent compares the activation against that scope.
		if configurationScopeID != targetScopeID {
			return ErrConflict
		}
		var raw []byte
		var revision int64
		var enabled bool
		err = tx.QueryRow(ctx, `SELECT p.tenant_id,p.site_id,p.revision,p.enabled,v.edge_snapshot
			FROM url_auth_policies p JOIN url_auth_policy_versions v ON v.policy_id=p.id AND v.revision=p.revision
			WHERE p.id=$1 FOR SHARE OF p`, policyID).Scan(
			&material.TenantID, &material.SiteID, &revision, &enabled, &raw,
		)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if !enabled || revision <= 0 || material.TenantID != authorizedTenantID {
			return ErrConflict
		}
		material.PolicyID, material.Revision = policyID, uint64(revision)
		if err := json.Unmarshal(raw, &material.Snapshot); err != nil {
			return ErrUnavailable
		}
		rows, err := tx.Query(ctx, `SELECT key_id,role,kek_key_id,ciphertext,secret_digest
			FROM url_auth_policy_keys WHERE policy_id=$1 AND role IN ('current','previous')
			ORDER BY CASE role WHEN 'current' THEN 0 ELSE 1 END`, policyID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var keyID, role, kekID string
			var ciphertext, digest []byte
			if err := rows.Scan(&keyID, &role, &kekID, &ciphertext, &digest); err != nil {
				return err
			}
			associatedData := []byte("cdnca-control-url-auth/key-envelope/v1\x00" + policyID.String() + "\x00" + keyID + "\x00current")
			secret, err := service.cipher.DecryptBound(kekID, ciphertext, associatedData)
			zeroBytes(ciphertext)
			if err != nil {
				zeroBytes(secret)
				return ErrEncryptionUnavailable
			}
			calculated := service.cipher.SecretDigest(secret)
			if len(digest) != len(calculated) || !hmac.Equal(digest, calculated[:]) {
				zeroBytes(secret)
				return ErrEncryptionUnavailable
			}
			keyFile, ok := artifactKeyFile(material.Snapshot, role, keyID)
			if !ok {
				zeroBytes(secret)
				return ErrConflict
			}
			material.Keys = append(material.Keys, ArtifactSecret{KeyID: keyID, KeyFile: keyFile, Secret: secret})
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if len(material.Keys) == 0 || len(material.Keys) > 2 {
			return ErrConflict
		}
		item, err := selectPolicy(ctx, tx, policyID)
		if err != nil {
			return err
		}
		return service.store.appendAudit(ctx, tx, actor, item, requestID, "url_auth_policy.publish_material", map[string]any{
			"revision": revision, "artifact_media_type": ArtifactMediaType,
		})
	})
	if err != nil {
		clearArtifactSecrets(material.Keys)
		return ArtifactMaterial{}, fmt.Errorf("load URL auth publication material: %w", err)
	}
	return material, nil
}

func artifactKeyFile(snapshot EdgePolicy, role, keyID string) (string, bool) {
	switch role {
	case "current":
		return snapshot.CurrentKey.KeyFile, snapshot.CurrentKey.KeyID == keyID
	case "previous":
		if snapshot.PreviousKey != nil && snapshot.PreviousKey.KeyID == keyID {
			return snapshot.PreviousKey.KeyFile, true
		}
	}
	return "", false
}
