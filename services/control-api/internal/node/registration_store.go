package node

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type registrationKeyRecord struct {
	keyID     uuid.UUID
	digest    []byte
	issuerID  uuid.UUID
	issuedAt  time.Time
	available bool
}

// currentRegistrationKey reads the latest credential issuance from the
// append-only audit stream; that event is the single source of truth.
func currentRegistrationKey(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID) (registrationKeyRecord, error) {
	var record registrationKeyRecord
	var keyID, digest string
	var issuer *uuid.UUID
	err := tx.QueryRow(ctx, `
		SELECT resource_id, payload->>'credential_sha256', actor_user_id, occurred_at
		FROM audit_events
		WHERE scope_id = $1 AND action = $2 AND resource_type = $3 AND result = 'success'
		ORDER BY occurred_at DESC, stream_position DESC
		LIMIT 1`, scopeID, auditActionRegistrationCredential, auditResourceRegistrationKey).Scan(
		&keyID, &digest, &issuer, &record.issuedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return registrationKeyRecord{}, nil
	}
	if err != nil {
		return registrationKeyRecord{}, fmt.Errorf("read node registration credential: %w", err)
	}
	parsed, parseErr := uuid.Parse(keyID)
	decoded, decodeErr := decodeHexDigest(digest)
	if parseErr != nil || decodeErr != nil || issuer == nil {
		return registrationKeyRecord{}, fmt.Errorf("node registration credential audit record is malformed")
	}
	record.keyID, record.digest, record.issuerID, record.available = parsed, decoded, *issuer, true
	return record, nil
}

// accepts reports whether a MAC-verified credential is the scope's current
// one: a reset (new key ID) or a changed server secret invalidates it.
func (r registrationKeyRecord) accepts(keyID uuid.UUID, credential string) error {
	if !r.available || r.keyID != keyID ||
		subtle.ConstantTimeCompare(credentialDigest(credential), r.digest) != 1 {
		return ErrInvalidRegistrationCredential
	}
	return nil
}

func (s *Store) registrationCredential(
	ctx context.Context, keys registrationKeys, actor Actor, requestID string, reset bool,
) (RegistrationCredential, error) {
	var result RegistrationCredential
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := requirePlatformScope(ctx, tx, actor.ScopeID); err != nil {
			return err
		}
		if err := lockNodeScope(ctx, tx, actor.ScopeID); err != nil {
			return err
		}
		current, err := currentRegistrationKey(ctx, tx, actor.ScopeID)
		if err != nil {
			return err
		}
		if !reset && current.available {
			credential := keys.credential(actor.ScopeID, current.keyID)
			// A changed server secret silently invalidates the stored key; issue
			// a new one instead of showing a command that cannot work.
			if subtle.ConstantTimeCompare(credentialDigest(credential), current.digest) == 1 {
				result = RegistrationCredential{KeyID: current.keyID, Credential: credential, IssuedAt: current.issuedAt}
				return nil
			}
		}
		keyID, err := newID()
		if err != nil {
			return err
		}
		credential := keys.credential(actor.ScopeID, keyID)
		reason := "initial"
		if reset {
			reason = "reset"
		} else if current.available {
			reason = "secret_rotated"
		}
		payload := map[string]any{"credential_sha256": fmt.Sprintf("%x", credentialDigest(credential)), "reason": reason}
		if current.available {
			payload["previous_key_id"] = current.keyID.String()
		}
		if err := s.auditor.Append(ctx, tx, audit.Event{
			ScopeID: actor.ScopeID, ActorUserID: &actor.UserID,
			Action: auditActionRegistrationCredential, ResourceType: auditResourceRegistrationKey,
			ResourceID: keyID.String(), RequestID: requestID, Result: "success", Payload: payload,
		}); err != nil {
			return err
		}
		issued, err := currentRegistrationKey(ctx, tx, actor.ScopeID)
		if err != nil || issued.keyID != keyID {
			return fmt.Errorf("confirm node registration credential: %w", errors.Join(err, errors.New("key mismatch")))
		}
		result = RegistrationCredential{KeyID: keyID, Credential: credential, IssuedAt: issued.issuedAt}
		return nil
	})
	if err != nil {
		return RegistrationCredential{}, fmt.Errorf("node registration credential: %w", err)
	}
	return result, nil
}

func (s *Store) register(
	ctx context.Context, keys registrationKeys, request RegisterRequest, normalized normalizedRegistration,
) (RegisterResult, error) {
	var result RegisterResult
	var rawToken string
	var denial error
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		scopeID, err := platformScopeID(ctx, tx)
		if err != nil {
			return err
		}
		keyID, err := keys.verifyCredential(scopeID, request.Credential)
		if err != nil {
			return err
		}
		// Serialises registration with credential resets and with other
		// registrations of the same scope, so dedupe below is race-free.
		if err := lockNodeScope(ctx, tx, scopeID); err != nil {
			return err
		}
		current, err := currentRegistrationKey(ctx, tx, scopeID)
		if err != nil {
			return err
		}
		if err := current.accepts(keyID, request.Credential); err != nil {
			return err
		}
		issuer := Actor{UserID: current.issuerID, ScopeID: scopeID}

		existing, freeID, err := findRegisteredNode(ctx, tx, keys, scopeID, normalized.fingerprint)
		if err != nil {
			return err
		}
		if existing != nil {
			if existing.AdminState != StatePending {
				return ErrNodeAlreadyRegistered
			}
			live, err := nodeHasLiveCertificate(ctx, tx, existing.ID, s.now().UTC())
			if err != nil {
				return err
			}
			if live {
				return ErrNodeAlreadyRegistered
			}
			result.Node, result.Reused = *existing, true
		} else {
			if freeID == uuid.Nil {
				return ErrRegistrationLimit
			}
			var pending int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM nodes WHERE scope_id = $1 AND admin_state = 'pending'`,
				scopeID).Scan(&pending); err != nil {
				return fmt.Errorf("count pending nodes: %w", err)
			}
			if pending >= MaxPendingRegistrations {
				return ErrRegistrationLimit
			}
			if err := s.guard.CheckNodeCreate(ctx, tx, entitlementguard.NodeCheck{
				AuditScopeID: scopeID, ActorUserID: issuer.UserID, ResourceID: freeID,
				RequestID: request.RequestID, Operation: auditActionNodeRegister,
			}); err != nil {
				if !entitlementguard.IsDenial(err) {
					return err
				}
				denial = err
				return nil
			}
			created, err := s.insertRegisteredNode(ctx, tx, issuer, freeID, keyID, request, normalized)
			if err != nil {
				return err
			}
			result.Node = created
		}
		metadata, raw, tokenHash, err := newToken(result.Node.ID, PurposeInitial, RegistrationTokenTTL, s.now)
		if err != nil {
			return err
		}
		issued, err := s.insertToken(ctx, tx, issuer, issueStoreInput{Metadata: metadata, TokenHash: tokenHash}, request.RequestID)
		if err != nil {
			return err
		}
		result.EnrollmentToken, rawToken = issued, raw
		return nil
	})
	if err != nil {
		return RegisterResult{}, fmt.Errorf("register node: %w", err)
	}
	if denial != nil {
		return RegisterResult{}, fmt.Errorf("register node: %w", denial)
	}
	result.EnrollmentToken.Token = rawToken
	return result, nil
}

// findRegisteredNode applies the dedupe rule: the first non-retired node among
// this machine's derived IDs is the existing registration; otherwise the
// first unused ID is returned for a new node. An ID is used while its node
// row exists (legacy retired rows included) and forever once that node was
// deleted (node_purged_ids), so a re-registration after deletion takes the
// next generation and never inherits per-node state kept outside the
// database under the old ID.
func findRegisteredNode(
	ctx context.Context, tx pgx.Tx, keys registrationKeys, scopeID uuid.UUID, fingerprint []byte,
) (*Node, uuid.UUID, error) {
	candidates := make([]uuid.UUID, registeredNodeGenerations)
	for generation := range candidates {
		candidates[generation] = keys.registeredNodeID(scopeID, fingerprint, generation)
	}
	rows, err := tx.Query(ctx, `
		SELECT id, display_id::text, name, description, region, host(ipv4), host(ipv6),
		       admin_state, management_settings, revision, created_at, updated_at, scope_id
		FROM nodes WHERE id = ANY($1::uuid[])
		FOR UPDATE`, candidates)
	if err != nil {
		return nil, uuid.Nil, fmt.Errorf("find registered node: %w", err)
	}
	defer rows.Close()
	found := map[uuid.UUID]Node{}
	for rows.Next() {
		var item Node
		var owner uuid.UUID
		if err := rows.Scan(append(nodeScanTargets(&item), &owner)...); err != nil {
			return nil, uuid.Nil, fmt.Errorf("scan registered node: %w", err)
		}
		if owner != scopeID {
			return nil, uuid.Nil, fmt.Errorf("registered node ID collides with another scope")
		}
		found[item.ID] = item
	}
	if err := rows.Err(); err != nil {
		return nil, uuid.Nil, fmt.Errorf("find registered node: %w", err)
	}
	rows.Close()
	purgedRows, err := tx.Query(ctx, `SELECT node_id FROM node_purged_ids WHERE node_id = ANY($1::uuid[])`, candidates)
	if err != nil {
		return nil, uuid.Nil, fmt.Errorf("find purged node IDs: %w", err)
	}
	purged, err := pgx.CollectRows(purgedRows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return nil, uuid.Nil, fmt.Errorf("find purged node IDs: %w", err)
	}
	free := uuid.Nil
	for _, id := range candidates {
		item, exists := found[id]
		if exists && item.AdminState != StateRetired {
			return &item, uuid.Nil, nil
		}
		if !exists && free == uuid.Nil && !slices.Contains(purged, id) {
			free = id
		}
	}
	return nil, free, nil
}

func (s *Store) insertRegisteredNode(
	ctx context.Context, tx pgx.Tx, issuer Actor, nodeID, keyID uuid.UUID,
	request RegisterRequest, normalized normalizedRegistration,
) (Node, error) {
	now := s.now().UTC()
	displayID, err := allocateNodeDisplayID(ctx, tx, issuer.ScopeID, now)
	if err != nil {
		return Node{}, err
	}
	name, err := availableNodeName(ctx, tx, issuer.ScopeID, normalized.hostname, displayID)
	if err != nil {
		return Node{}, err
	}
	// The install script sends no region; with a single catalogued region the
	// node joins it so it can be added to line groups (D8).
	region, err := onlyCatalogRegion(ctx, tx, issuer.ScopeID)
	if err != nil {
		return Node{}, err
	}
	var item Node
	err = tx.QueryRow(ctx, `
		INSERT INTO nodes (
			id, display_id, scope_id, name, description, region, ipv4, ipv6, created_by_user_id
		) VALUES ($1, $2, $3, $4, $5, $9, $6, $7, $8)
		RETURNING id, display_id::text, name, description, region, host(ipv4), host(ipv6),
		          admin_state, management_settings, revision, created_at, updated_at`,
		nodeID, displayID, issuer.ScopeID, name, normalized.description,
		nullable(normalized.ipv4), nullable(normalized.ipv6), issuer.UserID, region,
	).Scan(nodeScanTargets(&item)...)
	if err != nil {
		if isUniqueViolation(err) {
			return Node{}, ErrDuplicateName
		}
		return Node{}, fmt.Errorf("insert registered node: %w", err)
	}
	if err := s.auditor.Append(ctx, tx, audit.Event{
		ScopeID: issuer.ScopeID, Action: auditActionNodeRegister, ResourceType: "node",
		ResourceID: nodeID.String(), RequestID: request.RequestID, Result: "success",
		Payload: map[string]any{
			"admin_state": StatePending, "name": name, "registration_key_id": keyID.String(),
			"source_ip": strings.TrimSpace(request.SourceIP), "hostname": normalized.hostname,
		},
	}); err != nil {
		return Node{}, err
	}
	return item, nil
}

// availableNodeName keeps the host name when free, otherwise appends the
// display ID (names are unique per scope, case-insensitively).
func availableNodeName(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, hostname string, displayID int64) (string, error) {
	var taken bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM nodes WHERE scope_id = $1 AND lower(name) = lower($2))`,
		scopeID, hostname).Scan(&taken); err != nil {
		return "", fmt.Errorf("check node name: %w", err)
	}
	if !taken {
		return hostname, nil
	}
	suffix := fmt.Sprintf("-%d", displayID)
	for utf8.RuneCountInString(hostname)+len(suffix) > 128 {
		_, size := utf8.DecodeLastRuneInString(hostname)
		hostname = hostname[:len(hostname)-size]
	}
	return strings.TrimSpace(hostname) + suffix, nil
}

// nodeHasLiveCertificate is the initialization precondition: the host has
// completed enrollment and still holds an unexpired current certificate.
func nodeHasLiveCertificate(ctx context.Context, tx pgx.Tx, nodeID uuid.UUID, now time.Time) (bool, error) {
	var live bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(
		SELECT 1 FROM node_certificates
		WHERE node_id = $1 AND status = 'active' AND rotation_status IN ('current','overlap') AND not_after > $2
	)`, nodeID, now).Scan(&live)
	if err != nil {
		return false, fmt.Errorf("check node certificate: %w", err)
	}
	return live, nil
}

func decodeHexDigest(value string) ([]byte, error) {
	if !machineFingerprintPattern.MatchString(value) {
		return nil, errors.New("invalid digest")
	}
	return hex.DecodeString(value)
}
