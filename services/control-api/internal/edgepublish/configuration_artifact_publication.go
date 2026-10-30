package edgepublish

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type configurationArtifactRecipientBinding struct {
	NodeID    uuid.UUID
	KeyID     string
	PublicKey []byte
}

func lockConfigurationArtifactRecipients(
	ctx context.Context,
	tx pgx.Tx,
	scopeID uuid.UUID,
	nodeIDs []uuid.UUID,
	now time.Time,
) ([]configurationArtifactRecipientBinding, error) {
	if ctx == nil || tx == nil || scopeID == uuid.Nil || len(nodeIDs) == 0 {
		return nil, ErrInvalidInput
	}
	sortedNodeIDs := slices.Clone(nodeIDs)
	sort.Slice(sortedNodeIDs, func(i, j int) bool { return bytes.Compare(sortedNodeIDs[i][:], sortedNodeIDs[j][:]) < 0 })
	rows, err := tx.Query(ctx, `SELECT node.id,node.scope_id,node_scope.kind,node.admin_state,state.configuration_scope_id
		FROM nodes node
		JOIN access_scopes node_scope ON node_scope.id=node.scope_id
		JOIN node_config_state state ON state.node_id=node.id AND state.configuration_scope_id=$2
		WHERE node.id=ANY($1::uuid[])
		ORDER BY node.id
		FOR UPDATE OF node,state`, sortedNodeIDs, scopeID)
	if err != nil {
		return nil, fmt.Errorf("lock configuration artifact nodes: %w", err)
	}
	locked := 0
	for rows.Next() {
		var nodeID, nodeScopeID uuid.UUID
		var nodeScopeKind, adminState string
		var configurationScopeID *uuid.UUID
		if err := rows.Scan(&nodeID, &nodeScopeID, &nodeScopeKind, &adminState, &configurationScopeID); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan configuration artifact node: %w", err)
		}
		if locked >= len(sortedNodeIDs) || nodeID != sortedNodeIDs[locked] {
			rows.Close()
			return nil, edgedeployment.ErrNodeNotFound
		}
		if (nodeScopeKind != ScopeKindPlatform && nodeScopeID != scopeID) ||
			configurationScopeID == nil || *configurationScopeID != scopeID {
			rows.Close()
			return nil, edgedeployment.ErrConfigurationScopeConflict
		}
		if adminState != "active" {
			rows.Close()
			return nil, edgedeployment.ErrNodeRecipientKeyUnavailable
		}
		locked++
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("iterate configuration artifact nodes: %w", err)
	}
	rows.Close()
	if locked != len(sortedNodeIDs) {
		return nil, edgedeployment.ErrNodeNotFound
	}

	rows, err = tx.Query(ctx, `SELECT identity_state.node_id,key.id,key.public_key,key.public_key_sha256,key.activated_at
		FROM node_identity_state identity_state
		JOIN node_artifact_encryption_keys key
		  ON key.node_id=identity_state.node_id AND key.id=identity_state.active_artifact_key_id
		WHERE identity_state.node_id=ANY($1::uuid[]) AND key.status='active' AND key.deactivated_at IS NULL
		ORDER BY identity_state.node_id FOR UPDATE OF identity_state,key`, sortedNodeIDs)
	if err != nil {
		return nil, fmt.Errorf("lock configuration artifact recipients: %w", err)
	}
	defer rows.Close()
	recipients := make([]configurationArtifactRecipientBinding, 0, len(sortedNodeIDs))
	for rows.Next() {
		var recipient configurationArtifactRecipientBinding
		var storedDigest []byte
		var activatedAt *time.Time
		if err := rows.Scan(&recipient.NodeID, &recipient.KeyID, &recipient.PublicKey, &storedDigest, &activatedAt); err != nil {
			return nil, fmt.Errorf("scan configuration artifact recipient: %w", err)
		}
		digest := sha256.Sum256(recipient.PublicKey)
		if len(recipient.PublicKey) != 32 || len(storedDigest) != sha256.Size || !bytes.Equal(storedDigest, digest[:]) ||
			recipient.KeyID != "x25519:"+hex.EncodeToString(digest[:]) || activatedAt == nil || activatedAt.After(now) {
			return nil, edgedeployment.ErrNodeRecipientKeyUnavailable
		}
		recipients = append(recipients, recipient)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate configuration artifact recipients: %w", err)
	}
	if len(recipients) != len(sortedNodeIDs) {
		return nil, edgedeployment.ErrNodeRecipientKeyUnavailable
	}
	for index := range recipients {
		if recipients[index].NodeID != sortedNodeIDs[index] {
			return nil, edgedeployment.ErrNodeRecipientKeyUnavailable
		}
	}
	return recipients, nil
}

func configurationArtifactSetDigest(
	bindings []edgedeployment.NodeArtifactBinding,
	artifacts []edgedeployment.ArtifactInput,
) ([sha256.Size]byte, error) {
	if len(bindings) == 0 || len(bindings) != len(artifacts) {
		return [sha256.Size]byte{}, ErrInvalidInput
	}
	if len(bindings) == 1 && bindings[0].ArtifactID == artifacts[0].ID && len(artifacts[0].SHA256) == sha256.Size &&
		artifacts[0].RecipientKeyID != nil && *artifacts[0].RecipientKeyID == bindings[0].RecipientKeyID {
		var digest [sha256.Size]byte
		copy(digest[:], artifacts[0].SHA256)
		return digest, nil
	}
	values := make([]struct {
		NodeID, ArtifactID, RecipientKeyID string
		SHA256                             string
	}, len(bindings))
	for index := range bindings {
		if bindings[index].ArtifactID != artifacts[index].ID || len(artifacts[index].SHA256) != sha256.Size ||
			artifacts[index].RecipientKeyID == nil || *artifacts[index].RecipientKeyID != bindings[index].RecipientKeyID {
			return [sha256.Size]byte{}, ErrInvalidInput
		}
		values[index].NodeID = bindings[index].NodeID.String()
		values[index].ArtifactID = artifacts[index].ID.String()
		values[index].RecipientKeyID = bindings[index].RecipientKeyID
		values[index].SHA256 = hex.EncodeToString(artifacts[index].SHA256)
	}
	encoded, err := json.Marshal(values)
	if err != nil {
		return [sha256.Size]byte{}, errors.New("encode configuration artifact set digest")
	}
	return sha256.Sum256(encoded), nil
}
