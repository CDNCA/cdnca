package originauthcontrol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// System site origin auth for market sites (fix-mktsiteconf5). The subscriber
// reads a site's live rules with their credentials in clear only to seal them
// to each leaf (SiteRulesSystem); the leaf writes what it opened as its own
// site's rules under its own keyring (SetSiteSystem) and publishes them. The
// leaf has no IAM session: it writes as the tenant owner (the triggers check
// that account's origin_auth.manage; a tenant_owner holds it), without the
// session authorizer, the entitlement gate and the cloud verifier (the
// subscriber verified the credential when it was saved; delivery does not
// depend on the internet, 10-28 decision). Every fact has its write request
// and success audit event, with actor kind system.

var ErrSystemWrite = errors.New("origin authentication system write target is invalid")

// SiteKey is one credential of a rule; Secret is in clear. Seed is a
// keyring-keyed digest of the credential: a sender derives deterministic
// boxes from it (equal revisions keep their digest) without anyone able to
// recompute it from a guessed secret.
type SiteKey struct {
	RevisionRef          uuid.UUID
	NotBefore, ExpiresAt time.Time
	Secret               CredentialSecret `json:"-"`
	Seed                 [32]byte         `json:"-"`
}

// SiteRule is one live rule of a site.
type SiteRule struct {
	RuleID                uuid.UUID
	SourcePosition        int
	Provider, Algorithm   string
	Endpoint, Bucket      string
	PathPrefix, Region    string
	Service               string
	SignatureTTLSeconds   int
	EgressPolicyReference string
	Current               SiteKey
	Previous              *SiteKey
	ActivateCurrentAt     *time.Time
}

// ClearSiteRules wipes the credentials of rules.
func ClearSiteRules(rules []SiteRule) {
	for i := range rules {
		clearSecret(&rules[i].Current.Secret)
		if rules[i].Previous != nil {
			clearSecret(&rules[i].Previous.Secret)
		}
	}
}

// SiteRulesSystem reads the site's enabled rules with their verified
// credentials decrypted; the caller clears them (ClearSiteRules).
func (service *Service) SiteRulesSystem(ctx context.Context, siteID uuid.UUID) ([]SiteRule, error) {
	if service == nil || service.keyring == nil || siteID == uuid.Nil {
		return nil, ErrInvalidInput
	}
	var rules []SiteRule
	err := pgx.BeginTxFunc(ctx, service.pool, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT identity.id,identity.source_position,r.provider,r.algorithm,r.endpoint,
			r.bucket,r.path_prefix,r.region,r.service,r.signature_ttl_seconds,COALESCE(r.egress_policy_reference,''),
			r.current_credential_id,r.current_credential_revision,r.previous_credential_id,r.previous_credential_revision,
			r.activate_current_at
			FROM origin_auth_rules identity
			JOIN LATERAL (SELECT * FROM origin_auth_rule_revisions latest WHERE latest.rule_id=identity.id
				ORDER BY latest.revision DESC LIMIT 1) r ON true
			WHERE identity.site_id=$1 AND r.enabled AND NOT r.deleted ORDER BY identity.source_position`, siteID)
		if err != nil {
			return err
		}
		type refs struct {
			current          CredentialReference
			previousID       *uuid.UUID
			previousRevision *int64
		}
		var pending []refs
		for rows.Next() {
			var rule SiteRule
			var ref refs
			if err := rows.Scan(&rule.RuleID, &rule.SourcePosition, &rule.Provider, &rule.Algorithm, &rule.Endpoint,
				&rule.Bucket, &rule.PathPrefix, &rule.Region, &rule.Service, &rule.SignatureTTLSeconds,
				&rule.EgressPolicyReference, &ref.current.CredentialID, &ref.current.Revision, &ref.previousID,
				&ref.previousRevision, &rule.ActivateCurrentAt); err != nil {
				rows.Close()
				return err
			}
			rules, pending = append(rules, rule), append(pending, ref)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for i, ref := range pending {
			if rules[i].Current, err = service.siteKey(ctx, tx, ref.current); err != nil {
				return err
			}
			if ref.previousID != nil && ref.previousRevision != nil {
				previous, err := service.siteKey(ctx, tx, CredentialReference{CredentialID: *ref.previousID,
					Revision: *ref.previousRevision})
				if err != nil {
					return err
				}
				rules[i].Previous = &previous
			}
		}
		return nil
	})
	if err != nil {
		ClearSiteRules(rules)
		return nil, err
	}
	return rules, nil
}

func (service *Service) siteKey(ctx context.Context, tx pgx.Tx, reference CredentialReference) (SiteKey, error) {
	var stored storedCredential
	var key SiteKey
	var status string
	err := tx.QueryRow(ctx, `SELECT identity.id,identity.provider,`+sealedRevisionColumn+`,revision.revision_ref,
		revision.status,revision.envelope_key_id,revision.secret_ciphertext,revision.secret_ciphertext_sha256,
		revision.not_before,revision.expires_at
		FROM origin_auth_credential_revisions revision
		JOIN origin_auth_credentials identity ON identity.id=revision.credential_id
		WHERE revision.credential_id=$1 AND revision.revision=$2`, reference.CredentialID, reference.Revision).Scan(
		&stored.ID, &stored.Provider, &stored.Revision, &key.RevisionRef, &status, &stored.keyID, &stored.ciphertext,
		&stored.cipherDigest, &key.NotBefore, &key.ExpiresAt)
	if err != nil {
		return SiteKey{}, err
	}
	defer clearBytes(stored.ciphertext)
	digest := sha256.Sum256(stored.ciphertext)
	if status != StatusVerified || !bytes.Equal(digest[:], stored.cipherDigest) {
		return SiteKey{}, ErrCredentialUnverified
	}
	if key.Secret, err = service.decryptCredential(stored); err != nil {
		return SiteKey{}, err
	}
	if key.Seed, err = service.keyring.seed(stored.ciphertext); err != nil {
		clearSecret(&key.Secret)
		return SiteKey{}, err
	}
	return key, nil
}

// ValidateSiteRule checks rule as a write on this controller would (its
// egress policies decide a non-AWS S3 endpoint).
func (service *Service) ValidateSiteRule(rule SiteRule) error {
	if service == nil {
		return ErrInvalidInput
	}
	config := RuleConfig{Provider: rule.Provider, Algorithm: rule.Algorithm, Endpoint: rule.Endpoint, Bucket: rule.Bucket,
		PathPrefix: rule.PathPrefix, Region: rule.Region, Service: rule.Service,
		SignatureTTLSeconds: rule.SignatureTTLSeconds, EgressPolicyReference: rule.EgressPolicyReference,
		CurrentCredential: CredentialReference{CredentialID: rule.Current.RevisionRef, Revision: 1}}
	if rule.Previous != nil {
		config.PreviousCredential = &CredentialReference{CredentialID: rule.Previous.RevisionRef, Revision: 1}
		config.ActivateCurrentAt = rule.ActivateCurrentAt
	}
	if err := validateRuleConfig(&config, service.egressPolicies); err != nil {
		return err
	}
	if config.Endpoint != rule.Endpoint || config.PathPrefix != rule.PathPrefix || config.Region != rule.Region ||
		config.Service != rule.Service || config.Bucket != rule.Bucket {
		return ErrValidation // not in the canonical form a write stores
	}
	// What the rule revision trigger requires of an enabled rule written now.
	now, ttl := storeTime(service.now()), time.Duration(rule.SignatureTTLSeconds)*time.Second
	if rule.ActivateCurrentAt != nil && !storeTime(*rule.ActivateCurrentAt).After(now) {
		rule.Previous, rule.ActivateCurrentAt = nil, nil // SetSiteSystem drops a finished rotation
	}
	effectiveAt := now
	if rule.ActivateCurrentAt != nil {
		effectiveAt = storeTime(*rule.ActivateCurrentAt)
		if effectiveAt.After(now.Add(30 * 24 * time.Hour)) {
			return ErrValidation
		}
		if rule.Previous.NotBefore.After(now) || !rule.Previous.ExpiresAt.After(effectiveAt.Add(ttl)) {
			return ErrCredentialUnverified
		}
	}
	if rule.Current.NotBefore.After(effectiveAt) || !rule.Current.ExpiresAt.After(effectiveAt.Add(ttl)) {
		return ErrCredentialUnverified
	}
	return nil
}

// SystemSiteWrite is the rules wanted on a site: its live rules become
// exactly Rules (RuleID is the sender's; a key is reused by its sender
// RevisionRef). PruneOnly only deletes the rules no wanted rule keeps at the
// same source position and endpoint (before the site's origins change: a
// rule's revision must match its source).
type SystemSiteWrite struct {
	ScopeID, SiteID, OwnerUserID uuid.UUID
	Rules                        []SiteRule
	PruneOnly                    bool
	// RequestID ties the audit events to the caller; ActorRef names the
	// system actor ("job:<name>").
	RequestID, ActorRef string
}

// marketCredentialName names the leaf credential holding a sender key.
func marketCredentialName(ref uuid.UUID) string { return "market " + ref.String() }

type liveSiteRule struct {
	Rule
	currentRef, previousRef *uuid.UUID
	currentName             string
	previousName            *string
}

// SetSiteSystem makes the site's rules what request says and publishes them
// when anything changed (reported).
func (service *Service) SetSiteSystem(ctx context.Context, request SystemSiteWrite) (bool, error) {
	if service == nil || service.keyring == nil || request.ScopeID == uuid.Nil || request.SiteID == uuid.Nil ||
		request.OwnerUserID == uuid.Nil || !metadataPattern.MatchString(request.RequestID) || request.ActorRef == "" {
		return false, ErrSystemWrite
	}
	now := storeTime(service.now())
	wanted := map[int]SiteRule{}
	for _, rule := range request.Rules {
		if rule.ActivateCurrentAt != nil && !storeTime(*rule.ActivateCurrentAt).After(now) {
			rule.Previous, rule.ActivateCurrentAt = nil, nil // the rotation is over
		}
		if _, dup := wanted[rule.SourcePosition]; dup || rule.SourcePosition < 1 || rule.SourcePosition > 32 {
			return false, ErrValidation
		}
		wanted[rule.SourcePosition] = rule
	}
	changed := false
	err := pgx.BeginFunc(ctx, service.pool, func(tx pgx.Tx) error {
		var tenantID, ownerID uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT scope.tenant_id, site.owner_user_id FROM sites site
			JOIN access_scopes scope ON scope.id=site.scope_id AND scope.kind='tenant'
			WHERE site.id=$1 AND site.scope_id=$2 AND site.deleted_at IS NULL FOR SHARE OF site`,
			request.SiteID, request.ScopeID).Scan(&tenantID, &ownerID); errors.Is(err, pgx.ErrNoRows) {
			return ErrSystemWrite
		} else if err != nil {
			return err
		}
		if ownerID != request.OwnerUserID {
			return ErrSystemWrite
		}
		w := systemWriter{service: service, tx: tx, request: request, tenantID: tenantID, now: now,
			actor: Actor{UserID: ownerID, ScopeID: request.ScopeID, ScopeKind: "tenant"}}
		live, err := w.liveRules(ctx)
		if err != nil {
			return err
		}
		kept := map[int]bool{}
		for _, rule := range live {
			want, found := wanted[rule.SourcePosition]
			keep := found && (request.PruneOnly && want.Endpoint == rule.Endpoint || !request.PruneOnly && sameSiteRule(rule, want))
			if keep {
				kept[rule.SourcePosition] = true
				continue
			}
			if err := w.deleteRule(ctx, rule); err != nil {
				return err
			}
			changed = true
		}
		if !request.PruneOnly {
			for position, rule := range wanted {
				if kept[position] {
					continue
				}
				if err := w.createRule(ctx, rule); err != nil {
					return err
				}
				changed = true
			}
		}
		if !changed {
			return nil
		}
		return w.publish(ctx)
	})
	if err != nil {
		return false, fmt.Errorf("set site origin auth: %w", err)
	}
	return changed, nil
}

func sameSiteRule(live liveSiteRule, want SiteRule) bool {
	previousSame := live.previousName == nil && want.Previous == nil ||
		live.previousName != nil && want.Previous != nil && *live.previousName == marketCredentialName(want.Previous.RevisionRef)
	return live.Enabled && live.Provider == want.Provider && live.Algorithm == want.Algorithm &&
		live.Endpoint == want.Endpoint && live.Bucket == want.Bucket && live.PathPrefix == want.PathPrefix &&
		live.Region == want.Region && live.Service == want.Service && live.SignatureTTLSeconds == want.SignatureTTLSeconds &&
		live.EgressPolicyReference == want.EgressPolicyReference &&
		live.currentName == marketCredentialName(want.Current.RevisionRef) && previousSame &&
		sameTime(live.ActivateCurrentAt, want.ActivateCurrentAt)
}

type systemWriter struct {
	service  *Service
	tx       pgx.Tx
	request  SystemSiteWrite
	actor    Actor
	tenantID uuid.UUID
	now      time.Time
}

func (w systemWriter) liveRules(ctx context.Context) ([]liveSiteRule, error) {
	rows, err := w.tx.Query(ctx, ruleSelect+`WHERE identity.tenant_scope_id=$1 AND identity.site_id=$2
		AND NOT revision.deleted FOR UPDATE OF identity`, w.request.ScopeID, w.request.SiteID)
	if err != nil {
		return nil, err
	}
	var out []liveSiteRule
	for rows.Next() {
		rule, err := scanRule(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, liveSiteRule{Rule: rule})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		rule := &out[i]
		var currentRef uuid.UUID
		var previousRef *uuid.UUID
		if err := w.tx.QueryRow(ctx, `SELECT r.current_credential_revision_ref,r.previous_credential_revision_ref,
			current_identity.name,previous_identity.name
			FROM origin_auth_rule_revisions r
			JOIN origin_auth_credentials current_identity ON current_identity.id=r.current_credential_id
			LEFT JOIN origin_auth_credentials previous_identity ON previous_identity.id=r.previous_credential_id
			WHERE r.rule_id=$1 AND r.revision=$2`, rule.ID, rule.Revision).Scan(&currentRef, &previousRef,
			&rule.currentName, &rule.previousName); err != nil {
			return nil, err
		}
		rule.currentRef, rule.previousRef = &currentRef, previousRef
	}
	return out, nil
}

// fact writes one fact as the triggers require: a pending write request and
// its success audit event, the fact, then the write completed.
func (w systemWriter) fact(ctx context.Context, operation, resourceType string, resourceID uuid.UUID, revision int64,
	payload map[string]any, insert func(WriteMetadata) error) error {
	ref := fmt.Sprintf("%s:%s:%d", operation, resourceID, revision)
	metadata := WriteMetadata{IdempotencyKey: ref, RequestID: w.request.RequestID, TraceID: ref}
	digest := sha256.Sum256([]byte(ref))
	if _, err := w.tx.Exec(ctx, `INSERT INTO origin_auth_write_requests(
		id,actor_scope_id,actor_user_id,target_scope_id,operation,idempotency_key,request_digest,request_id,trace_id,created_at)
		VALUES($1,$2,$3,$2,$4,$5,$6,$7,$8,$9)`, uuid.Must(uuid.NewV7()), w.actor.ScopeID, w.actor.UserID, operation,
		metadata.IdempotencyKey, digest[:], metadata.RequestID, metadata.TraceID, w.now); err != nil {
		return err
	}
	if payload == nil {
		payload = map[string]any{}
	}
	payload["trace_id"], payload["source"] = metadata.TraceID, "market_leaf_sync"
	if err := w.service.auditor.Append(ctx, w.tx, audit.Event{
		ScopeID: w.actor.ScopeID, ActorUserID: &w.actor.UserID, ActorKind: audit.ActorSystem, ActorRef: w.request.ActorRef,
		Action: operation, ResourceType: resourceType, ResourceID: resourceID.String(), RequestID: metadata.RequestID,
		Result: "success", Payload: payload,
	}); err != nil {
		return err
	}
	if err := insert(metadata); err != nil {
		return err
	}
	_, err := w.tx.Exec(ctx, `UPDATE origin_auth_write_requests SET resource_id=$4,response_status=201,
		response_body='{"source":"market_leaf_sync"}',completed_at=$5
		WHERE actor_scope_id=$1 AND actor_user_id=$2 AND operation=$3 AND idempotency_key=$6 AND completed_at IS NULL`,
		w.actor.ScopeID, w.actor.UserID, operation, resourceID, w.now, metadata.IdempotencyKey)
	return err
}

func (w systemWriter) deleteRule(ctx context.Context, rule liveSiteRule) error {
	rule.Enabled, rule.Deleted, rule.UpdatedAt = false, true, w.now
	rule.Revision++
	return w.fact(ctx, "origin_auth.rule.delete", "origin_auth_rule", rule.ID, rule.Revision, ruleAuditPayload(rule.Rule),
		func(metadata WriteMetadata) error {
			return insertRuleRevision(ctx, w.tx, w.actor, rule.Rule, "delete", *rule.currentRef, rule.previousRef, metadata)
		})
}

func (w systemWriter) createRule(ctx context.Context, want SiteRule) error {
	current, err := w.ensureCredential(ctx, want.Provider, want.Current)
	if err != nil {
		return err
	}
	rule := Rule{ID: uuid.Must(uuid.NewV7()), TenantScopeID: w.request.ScopeID, SiteID: w.request.SiteID,
		SourcePosition: want.SourcePosition, Enabled: true, Revision: 1, CreatedAt: w.now, UpdatedAt: w.now,
		RuleConfig: RuleConfig{Provider: want.Provider, Algorithm: want.Algorithm, Endpoint: want.Endpoint,
			Bucket: want.Bucket, PathPrefix: want.PathPrefix, Region: want.Region, Service: want.Service,
			SignatureTTLSeconds: want.SignatureTTLSeconds, EgressPolicyReference: want.EgressPolicyReference,
			CurrentCredential: current.reference, ActivateCurrentAt: want.ActivateCurrentAt}}
	var previousRef *uuid.UUID
	if want.Previous != nil {
		previous, err := w.ensureCredential(ctx, want.Provider, *want.Previous)
		if err != nil {
			return err
		}
		rule.PreviousCredential, previousRef = &previous.reference, &previous.ref
	}
	return w.fact(ctx, "origin_auth.rule.create", "origin_auth_rule", rule.ID, 1, ruleAuditPayload(rule),
		func(metadata WriteMetadata) error {
			if _, err := w.tx.Exec(ctx, `INSERT INTO origin_auth_rules(
				id,tenant_scope_id,tenant_id,site_id,source_position,created_by_scope_id,created_by_user_id,
				request_id,trace_id,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, rule.ID, rule.TenantScopeID,
				w.tenantID, rule.SiteID, rule.SourcePosition, w.actor.ScopeID, w.actor.UserID, metadata.RequestID,
				metadata.TraceID, w.now); err != nil {
				return err
			}
			return insertRuleRevision(ctx, w.tx, w.actor, rule, "create", current.ref, previousRef, metadata)
		})
}

type leafCredential struct {
	reference CredentialReference
	ref       uuid.UUID
}

// ensureCredential returns the verified leaf credential holding key, stored
// on first use under this controller's keyring (create, then verify without
// the cloud verifier).
func (w systemWriter) ensureCredential(ctx context.Context, provider string, key SiteKey) (leafCredential, error) {
	name := marketCredentialName(key.RevisionRef)
	var found leafCredential
	var status string
	err := w.tx.QueryRow(ctx, `SELECT identity.id,latest.revision,latest.revision_ref,latest.status
		FROM origin_auth_credentials identity
		JOIN LATERAL (SELECT * FROM origin_auth_credential_revisions r WHERE r.credential_id=identity.id
			ORDER BY r.revision DESC LIMIT 1) latest ON true
		WHERE identity.tenant_scope_id=$1 AND identity.provider=$2 AND lower(identity.name)=lower($3)`,
		w.request.ScopeID, provider, name).Scan(&found.reference.CredentialID, &found.reference.Revision, &found.ref, &status)
	if err == nil {
		if status != StatusVerified {
			return leafCredential{}, ErrCredentialUnverified // a tenant disabled it on the leaf
		}
		return found, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return leafCredential{}, err
	}
	secret := key.Secret
	secret.NotBefore, secret.ExpiresAt = storeTime(key.NotBefore), storeTime(key.ExpiresAt)
	if !validSecret(secret.AccessKeyID, 256) || !validSecret(secret.SecretAccessKey, 512) ||
		secret.SessionToken != "" && !validSecret(secret.SessionToken, 4096) || !secret.ExpiresAt.After(secret.NotBefore) {
		return leafCredential{}, ErrValidation
	}
	plaintext, err := encodeSecret(provider, secret)
	clearSecret(&secret)
	if err != nil {
		return leafCredential{}, ErrEncryptionUnavailable
	}
	id, createdRef, verifiedRef := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	sealed, err := w.service.keyring.seal(plaintext, credentialAAD(id, 1, provider))
	clearBytes(plaintext)
	if err != nil {
		return leafCredential{}, err
	}
	defer clearBytes(sealed.ciphertext)
	cipherDigest := digestCiphertext(sealed.ciphertext)
	insertRevision := func(metadata WriteMetadata, revision int64, ref uuid.UUID, operation, status string) error {
		var verifiedAt, code any
		if status == StatusVerified {
			verifiedAt, code = w.now, "verified"
		}
		_, err := w.tx.Exec(ctx, `INSERT INTO origin_auth_credential_revisions(
			credential_id,revision,revision_ref,operation,status,envelope_key_id,secret_ciphertext,
			secret_ciphertext_sha256,not_before,expires_at,verified_at,verification_code,created_by_scope_id,
			created_by_user_id,request_id,trace_id,created_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`, id, revision, ref, operation, status,
			sealed.keyID, sealed.ciphertext, cipherDigest[:], storeTime(key.NotBefore), storeTime(key.ExpiresAt),
			verifiedAt, code, w.actor.ScopeID, w.actor.UserID, metadata.RequestID, metadata.TraceID, w.now)
		return err
	}
	if err := w.fact(ctx, "origin_auth.credential.create", "origin_auth_credential", id, 1,
		map[string]any{"provider": provider, "revision": 1, "status": StatusPending},
		func(metadata WriteMetadata) error {
			if _, err := w.tx.Exec(ctx, `INSERT INTO origin_auth_credentials(
				id,tenant_scope_id,tenant_id,provider,name,created_by_scope_id,created_by_user_id,request_id,trace_id,created_at)
				VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, id, w.request.ScopeID, w.tenantID, provider, name,
				w.actor.ScopeID, w.actor.UserID, metadata.RequestID, metadata.TraceID, w.now); err != nil {
				return err
			}
			return insertRevision(metadata, 1, createdRef, "create", StatusPending)
		}); err != nil {
		return leafCredential{}, err
	}
	if err := w.fact(ctx, "origin_auth.credential.verify", "origin_auth_credential", id, 2,
		map[string]any{"provider": provider, "revision": 2, "status": StatusVerified, "verifier": "market_subscriber"},
		func(metadata WriteMetadata) error {
			return insertRevision(metadata, 2, verifiedRef, "verify", StatusVerified)
		}); err != nil {
		return leafCredential{}, err
	}
	return leafCredential{reference: CredentialReference{CredentialID: id, Revision: 2}, ref: verifiedRef}, nil
}

// publish stores the scope's next publication (as CreatePublication does).
func (w systemWriter) publish(ctx context.Context) error {
	if _, err := w.tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('origin-auth-publication:' || $1::text,0))`,
		w.request.ScopeID); err != nil {
		return err
	}
	var previousRevision int64
	var previousHash []byte
	err := w.tx.QueryRow(ctx, `SELECT revision,snapshot_sha256 FROM origin_auth_publications
		WHERE tenant_scope_id=$1 ORDER BY revision DESC LIMIT 1`, w.request.ScopeID).Scan(&previousRevision, &previousHash)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	next := previousRevision + 1
	snapshot, canonical, err := buildPublicationSnapshot(ctx, w.tx, w.request.ScopeID, next)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(canonical)
	id := uuid.Must(uuid.NewV7())
	if err := w.fact(ctx, "origin_auth.publication.create", "origin_auth_publication", id, next,
		map[string]any{"revision": next, "rule_count": len(snapshot.Rules)}, func(metadata WriteMetadata) error {
			_, err := w.tx.Exec(ctx, `INSERT INTO origin_auth_publications(
				id,tenant_scope_id,tenant_id,revision,schema_version,canonical_snapshot,snapshot_sha256,
				previous_sha256,created_by_scope_id,created_by_user_id,request_id,trace_id,created_at)
				VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, id, w.request.ScopeID, w.tenantID, next,
				publicationSchema, canonical, hash[:], nullableDigest(previousHash), w.actor.ScopeID, w.actor.UserID,
				metadata.RequestID, metadata.TraceID, w.now)
			return err
		}); err != nil {
		return err
	}
	if w.service.published != nil {
		return w.service.published(ctx, w.tx, w.request.ScopeID)
	}
	return nil
}
