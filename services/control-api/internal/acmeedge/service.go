package acmeedge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	idempotencyKeyPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$`)
	labelPattern          = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	failureCodePattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	challengeTokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{22,256}$`)
	thumbprintPattern     = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	domainLabelPattern    = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
)

type Service struct {
	pool       *pgxpool.Pool
	cipher     TokenCipher
	authorizer EntitlementAuthorizer
	resolver   TargetResolver
	auditor    AuditAppender
	clock      func() time.Time
	subject    string
	retryDelay time.Duration
}

type normalizedPublishRequest struct {
	PublishRequest
	RequestUUID uuid.UUID
}

type challengeSecret struct {
	Reference ChallengeReference
	Domain    string
	Token     string
	Value     string
}

type aadDocument struct {
	Schema             string `json:"schema"`
	TenantScopeID      string `json:"tenant_scope_id"`
	SiteID             string `json:"site_id"`
	OperationID        string `json:"operation_id"`
	ChallengeAttemptID string `json:"challenge_attempt_id"`
	TokenSHA256        string `json:"token_sha256"`
}

type snapshotDocument struct {
	Schema        string          `json:"schema"`
	Mode          string          `json:"mode"`
	TenantScopeID string          `json:"tenant_scope_id"`
	SiteID        string          `json:"site_id"`
	Revision      int64           `json:"revision"`
	Tokens        []snapshotToken `json:"tokens"`
	NodeIDs       []string        `json:"node_ids"`
}

type snapshotToken struct {
	OperationID        string `json:"operation_id"`
	ChallengeAttemptID string `json:"challenge_attempt_id"`
	Domain             string `json:"domain"`
	TokenSHA256        string `json:"token_sha256"`
	ValueSHA256        string `json:"value_sha256"`
	KeyID              string `json:"key_id"`
	Nonce              []byte `json:"nonce"`
	Ciphertext         []byte `json:"ciphertext"`
	AADSHA256          string `json:"aad_sha256"`
}

func NewService(pool *pgxpool.Pool, config Config) (*Service, error) {
	if pool == nil || config.Clock == nil || config.Cipher == nil || config.EntitlementAuthorizer == nil ||
		!labelPattern.MatchString(config.SubjectPrefix) || config.RetryDelay <= 0 {
		return nil, ErrInvalidInput
	}
	auditor := config.Auditor
	if auditor == nil {
		auditor = audit.New(pool)
	}
	return &Service{
		pool: pool, cipher: config.Cipher, authorizer: config.EntitlementAuthorizer,
		resolver: config.TargetResolver, auditor: auditor, clock: config.Clock,
		subject: config.SubjectPrefix, retryDelay: config.RetryDelay,
	}, nil
}

func (s *Service) PublishSnapshot(ctx context.Context, request PublishRequest) (Publication, error) {
	if ctx == nil {
		return Publication{}, ErrInvalidInput
	}
	var publication Publication
	var committedRejection error
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		publication, err = s.PublishSnapshotTx(ctx, tx, request)
		if errors.Is(err, ErrEntitlementDenied) {
			committedRejection = err
			return nil
		}
		return err
	})
	if err != nil {
		return Publication{}, err
	}
	if committedRejection != nil {
		return Publication{}, committedRejection
	}
	return publication, nil
}

func (s *Service) PublishSnapshotTx(ctx context.Context, tx pgx.Tx, request PublishRequest) (Publication, error) {
	if ctx == nil || tx == nil {
		return Publication{}, ErrInvalidInput
	}
	now := s.clock().UTC().Truncate(time.Microsecond)
	normalized, err := normalizePublishRequest(request, now)
	if err != nil {
		return Publication{}, err
	}
	digest, err := publishRequestDigest(normalized.PublishRequest)
	if err != nil {
		return Publication{}, ErrInvalidInput
	}
	currentRevision, err := lockOverlayState(ctx, tx, normalized.TenantScopeID, normalized.SiteID, now)
	if err != nil {
		return Publication{}, err
	}
	if existing, found, err := loadPublicationByKey(ctx, tx, normalized.TenantScopeID, normalized.SiteID, normalized.IdempotencyKey); err != nil {
		return Publication{}, err
	} else if found {
		if !bytes.Equal(existing.requestDigest, digest[:]) {
			return Publication{}, ErrIdempotencyConflict
		}
		existing.Publication.Replayed = true
		return existing.Publication, nil
	}
	if currentRevision != normalized.ExpectedRevision {
		return Publication{}, ErrRevisionConflict
	}

	var decision EntitlementDecision
	var nodes []uuid.UUID
	var currentChallenges []ChallengeReference
	if normalized.Mode == ModeCleanup {
		var currentNodes []uuid.UUID
		currentChallenges, currentNodes, err = loadCurrentOverlaySnapshot(
			ctx, tx, normalized.TenantScopeID, normalized.SiteID, normalized.ExpectedRevision,
		)
		if err != nil {
			return Publication{}, err
		}
		if !challengeSubset(normalized.Challenges, currentChallenges) {
			return Publication{}, ErrChallengeIneligible
		}
		nodes, err = s.resolveCleanupTarget(ctx, tx, normalized, currentNodes)
		if err != nil {
			return Publication{}, err
		}
	} else {
		if err := validateApplySite(ctx, tx, normalized.TenantScopeID, normalized.SiteID); err != nil {
			return Publication{}, err
		}
		nodes, err = s.resolveTarget(ctx, tx, normalized)
		if err != nil {
			return Publication{}, err
		}
		decision, authorizationErr := s.authorizer.AuthorizeOverlay(ctx, tx, EntitlementRequest{
			TenantScopeID: normalized.TenantScopeID, SiteID: normalized.SiteID,
			TokenCount: len(normalized.Challenges), NodeCount: len(nodes),
		})
		if authorizationErr != nil || !validEntitlementDecision(decision, now) {
			reason := "decision_rejected"
			if authorizationErr != nil {
				reason = "decision_unavailable"
			}
			if err := s.auditor.Append(ctx, tx, audit.Event{
				ScopeID: normalized.TenantScopeID, ActorUserID: nil,
				Action: "acme_http01_overlay.entitlement_check", ResourceType: "site",
				ResourceID: normalized.SiteID.String(), RequestID: normalized.RequestID, Result: "denied",
				Payload: map[string]any{
					"reason": reason, "token_count": len(normalized.Challenges), "node_count": len(nodes),
					"locally_verified": decision.LocallyVerified, "in_grace": decision.InGrace,
					"status": decision.Status, "lease_serial": decision.LeaseSerial,
				},
			}); err != nil {
				return Publication{}, err
			}
			return Publication{}, ErrEntitlementDenied
		}
	}

	secrets, err := loadChallengeSecrets(ctx, tx, normalized.TenantScopeID, normalized.SiteID, normalized.Challenges)
	if err != nil {
		return Publication{}, err
	}
	revision := normalized.ExpectedRevision + 1
	sealed, err := s.sealChallenges(ctx, normalized.TenantScopeID, normalized.SiteID, secrets)
	if err != nil {
		return Publication{}, err
	}
	snapshotDigest, err := sealedSnapshotDigest(normalized.Mode, normalized.TenantScopeID, normalized.SiteID, revision, sealed, nodes)
	if err != nil {
		return Publication{}, ErrInvalidInput
	}
	publicationID := uuid.NewSHA1(normalized.SiteID, []byte("acme-http01-publication/"+normalized.IdempotencyKey))
	versionID := uuid.NewSHA1(publicationID, []byte("version"))
	publication := Publication{
		ID: publicationID, VersionID: versionID, Mode: normalized.Mode, TenantScopeID: normalized.TenantScopeID,
		SiteID: normalized.SiteID, Revision: revision, SealedSnapshotSHA256: snapshotDigest,
		TokenCount: len(sealed), NodeCount: len(nodes), CreatedAt: now,
	}
	if err := insertPublicationChain(ctx, tx, publication, normalized, digest, sealed, nodes, s.subject); err != nil {
		return Publication{}, err
	}
	action := "acme_http01_overlay.publish"
	payload := map[string]any{
		"site_id": normalized.SiteID.String(), "revision": revision,
		"sealed_snapshot_sha256": fmt.Sprintf("%x", snapshotDigest[:]),
		"token_count":            len(sealed), "node_count": len(nodes),
	}
	if normalized.Mode == ModeApply {
		payload["entitlement_lease_serial"] = decision.LeaseSerial
	} else {
		action = "acme_http01_overlay.cleanup"
		payload["reason"] = "token_set_shrunk"
		payload["removed_token_count"] = len(currentChallenges) - len(normalized.Challenges)
	}
	if err := s.auditor.Append(ctx, tx, audit.Event{
		ScopeID: normalized.TenantScopeID, ActorUserID: nil,
		Action: action, ResourceType: "acme_http01_overlay_version",
		ResourceID: versionID.String(), RequestID: normalized.RequestID, Result: "success",
		Payload: payload,
	}); err != nil {
		return Publication{}, err
	}
	return publication, nil
}

func (s *Service) resolveTarget(ctx context.Context, tx pgx.Tx, request normalizedPublishRequest) ([]uuid.UUID, error) {
	if request.TargetSnapshot == nil {
		if err := validateEligibleNodes(ctx, tx, request.TenantScopeID, request.NodeIDs); err != nil {
			return nil, err
		}
		return slices.Clone(request.NodeIDs), nil
	}
	if s.resolver == nil {
		return nil, ErrTargetIneligible
	}
	resolved, err := s.resolver.ResolveOverlayTarget(ctx, tx, request.TenantScopeID, request.SiteID, *request.TargetSnapshot)
	if err != nil || resolved.Reference != *request.TargetSnapshot {
		return nil, ErrTargetIneligible
	}
	nodes, err := normalizeNodeIDs(resolved.NodeIDs)
	if err != nil {
		return nil, err
	}
	if err := validateEligibleNodes(ctx, tx, request.TenantScopeID, nodes); err != nil {
		return nil, err
	}
	return nodes, nil
}

func (s *Service) resolveCleanupTarget(
	ctx context.Context,
	tx pgx.Tx,
	request normalizedPublishRequest,
	currentNodes []uuid.UUID,
) ([]uuid.UUID, error) {
	if len(request.NodeIDs) == 0 && request.TargetSnapshot == nil {
		return slices.Clone(currentNodes), nil
	}
	nodes := request.NodeIDs
	if request.TargetSnapshot != nil {
		if s.resolver == nil {
			return nil, ErrTargetIneligible
		}
		resolved, err := s.resolver.ResolveOverlayTarget(ctx, tx, request.TenantScopeID, request.SiteID, *request.TargetSnapshot)
		if err != nil || resolved.Reference != *request.TargetSnapshot {
			return nil, ErrTargetIneligible
		}
		nodes, err = normalizeNodeIDs(resolved.NodeIDs)
		if err != nil {
			return nil, err
		}
	}
	if !sameNodeIDs(nodes, currentNodes) {
		return nil, ErrTargetIneligible
	}
	return slices.Clone(nodes), nil
}

func challengeSubset(candidate, current []ChallengeReference) bool {
	allowed := make(map[ChallengeReference]struct{}, len(current))
	for _, reference := range current {
		allowed[reference] = struct{}{}
	}
	for _, reference := range candidate {
		if _, found := allowed[reference]; !found {
			return false
		}
	}
	return true
}

func sameNodeIDs(first, second []uuid.UUID) bool {
	if len(first) != len(second) {
		return false
	}
	for index := range first {
		if first[index] != second[index] {
			return false
		}
	}
	return true
}

func (s *Service) sealChallenges(
	ctx context.Context,
	tenantScopeID uuid.UUID,
	siteID uuid.UUID,
	secrets []challengeSecret,
) ([]SealedToken, error) {
	sealed := make([]SealedToken, 0, len(secrets))
	for index, secret := range secrets {
		if !validDomain(secret.Domain) || !challengeTokenPattern.MatchString(secret.Token) ||
			!strings.HasPrefix(secret.Value, secret.Token+".") ||
			!thumbprintPattern.MatchString(strings.TrimPrefix(secret.Value, secret.Token+".")) {
			return nil, ErrChallengeIneligible
		}
		tokenDigest := sha256.Sum256([]byte(secret.Token))
		valueDigest := sha256.Sum256([]byte(secret.Value))
		aad, err := json.Marshal(aadDocument{
			Schema: "cdnca.acme.http01-overlay-aad/v1", TenantScopeID: tenantScopeID.String(),
			SiteID: siteID.String(), OperationID: secret.Reference.OperationID,
			ChallengeAttemptID: secret.Reference.AttemptID.String(), TokenSHA256: fmt.Sprintf("%x", tokenDigest[:]),
		})
		if err != nil {
			return nil, ErrEncryptionFailed
		}
		result, err := s.cipher.Seal(ctx, SealRequest{
			TenantScopeID: tenantScopeID, SiteID: siteID, OperationID: secret.Reference.OperationID,
			ChallengeAttemptID: secret.Reference.AttemptID, Domain: secret.Domain,
			Token: secret.Token, ExactValue: secret.Value, AAD: slices.Clone(aad),
		})
		if err != nil || !labelPattern.MatchString(result.KeyID) || len(result.Nonce) < 12 || len(result.Nonce) > 64 ||
			len(result.Ciphertext) == 0 || len(result.Ciphertext) > 16384 {
			return nil, ErrEncryptionFailed
		}
		sealed = append(sealed, SealedToken{
			Ordinal: index + 1, OperationID: secret.Reference.OperationID,
			ChallengeAttemptID: secret.Reference.AttemptID, Domain: secret.Domain,
			TokenSHA256: tokenDigest, ValueSHA256: valueDigest, KeyID: result.KeyID,
			Nonce: slices.Clone(result.Nonce), Ciphertext: slices.Clone(result.Ciphertext),
			AADSHA256: sha256.Sum256(aad),
		})
	}
	return sealed, nil
}

func normalizePublishRequest(request PublishRequest, now time.Time) (normalizedPublishRequest, error) {
	requestID, requestErr := uuid.Parse(request.RequestID)
	if request.TenantScopeID == uuid.Nil || request.SiteID == uuid.Nil || request.ExpectedRevision < 0 ||
		(request.Mode != ModeApply && request.Mode != ModeCleanup) || len(request.Challenges) > 1000 ||
		request.MaxAttempts < 1 || request.MaxAttempts > 10 || !request.Deadline.After(now) ||
		request.Deadline.Sub(now) > 24*time.Hour || !idempotencyKeyPattern.MatchString(request.IdempotencyKey) ||
		requestErr != nil || requestID.String() != request.RequestID {
		return normalizedPublishRequest{}, ErrInvalidInput
	}
	if request.Mode == ModeApply && (len(request.Challenges) == 0 || (len(request.NodeIDs) == 0) == (request.TargetSnapshot == nil)) {
		return normalizedPublishRequest{}, ErrInvalidInput
	}
	if request.Mode == ModeCleanup && (request.ExpectedRevision == 0 || (len(request.NodeIDs) > 0 && request.TargetSnapshot != nil)) {
		return normalizedPublishRequest{}, ErrInvalidInput
	}
	challenges := slices.Clone(request.Challenges)
	for _, challenge := range challenges {
		if challenge.AttemptID == uuid.Nil || strings.TrimSpace(challenge.OperationID) != challenge.OperationID ||
			len(challenge.OperationID) == 0 || len(challenge.OperationID) > 200 {
			return normalizedPublishRequest{}, ErrInvalidInput
		}
	}
	sort.Slice(challenges, func(i, j int) bool {
		if challenges[i].OperationID != challenges[j].OperationID {
			return challenges[i].OperationID < challenges[j].OperationID
		}
		return bytes.Compare(challenges[i].AttemptID[:], challenges[j].AttemptID[:]) < 0
	})
	for index := 1; index < len(challenges); index++ {
		if challenges[index] == challenges[index-1] {
			return normalizedPublishRequest{}, ErrInvalidInput
		}
	}
	request.Challenges = challenges
	if len(request.NodeIDs) > 0 {
		nodes, err := normalizeNodeIDs(request.NodeIDs)
		if err != nil {
			return normalizedPublishRequest{}, err
		}
		request.NodeIDs = nodes
	} else if request.TargetSnapshot != nil {
		if request.TargetSnapshot.ID == uuid.Nil || request.TargetSnapshot.Revision <= 0 ||
			request.TargetSnapshot.SHA256 == ([32]byte{}) {
			return normalizedPublishRequest{}, ErrInvalidInput
		}
		reference := *request.TargetSnapshot
		request.TargetSnapshot = &reference
	} else if request.Mode != ModeCleanup {
		return normalizedPublishRequest{}, ErrInvalidInput
	}
	request.Deadline = request.Deadline.UTC().Truncate(time.Microsecond)
	return normalizedPublishRequest{PublishRequest: request, RequestUUID: requestID}, nil
}

func normalizeNodeIDs(nodeIDs []uuid.UUID) ([]uuid.UUID, error) {
	if len(nodeIDs) == 0 || len(nodeIDs) > 10000 {
		return nil, ErrInvalidInput
	}
	nodes := slices.Clone(nodeIDs)
	for _, nodeID := range nodes {
		if nodeID == uuid.Nil {
			return nil, ErrInvalidInput
		}
	}
	sort.Slice(nodes, func(i, j int) bool { return bytes.Compare(nodes[i][:], nodes[j][:]) < 0 })
	for index := 1; index < len(nodes); index++ {
		if nodes[index] == nodes[index-1] {
			return nil, ErrInvalidInput
		}
	}
	return nodes, nil
}

func publishRequestDigest(request PublishRequest) ([32]byte, error) {
	type targetDocument struct {
		NodeIDs  []uuid.UUID              `json:"node_ids,omitempty"`
		Snapshot *TargetSnapshotReference `json:"snapshot,omitempty"`
	}
	document := struct {
		Mode             string               `json:"mode"`
		TenantScopeID    uuid.UUID            `json:"tenant_scope_id"`
		SiteID           uuid.UUID            `json:"site_id"`
		ExpectedRevision int64                `json:"expected_revision"`
		Challenges       []ChallengeReference `json:"challenges"`
		Target           targetDocument       `json:"target"`
		MaxAttempts      int                  `json:"max_attempts"`
		Deadline         time.Time            `json:"deadline"`
	}{
		Mode: request.Mode, TenantScopeID: request.TenantScopeID, SiteID: request.SiteID,
		ExpectedRevision: request.ExpectedRevision, Challenges: request.Challenges,
		Target:      targetDocument{NodeIDs: request.NodeIDs, Snapshot: request.TargetSnapshot},
		MaxAttempts: request.MaxAttempts, Deadline: request.Deadline,
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

func sealedSnapshotDigest(
	mode string,
	tenantScopeID uuid.UUID,
	siteID uuid.UUID,
	revision int64,
	tokens []SealedToken,
	nodeIDs []uuid.UUID,
) ([32]byte, error) {
	document := snapshotDocument{
		Schema: "cdnca.acme.http01-overlay/v1", Mode: mode, TenantScopeID: tenantScopeID.String(),
		SiteID: siteID.String(), Revision: revision, Tokens: make([]snapshotToken, 0, len(tokens)),
		NodeIDs: make([]string, 0, len(nodeIDs)),
	}
	for _, token := range tokens {
		document.Tokens = append(document.Tokens, snapshotToken{
			OperationID: token.OperationID, ChallengeAttemptID: token.ChallengeAttemptID.String(),
			Domain: token.Domain, TokenSHA256: fmt.Sprintf("%x", token.TokenSHA256[:]),
			ValueSHA256: fmt.Sprintf("%x", token.ValueSHA256[:]), KeyID: token.KeyID,
			Nonce: token.Nonce, Ciphertext: token.Ciphertext, AADSHA256: fmt.Sprintf("%x", token.AADSHA256[:]),
		})
	}
	for _, nodeID := range nodeIDs {
		document.NodeIDs = append(document.NodeIDs, nodeID.String())
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

func validDomain(domain string) bool {
	if len(domain) < 3 || len(domain) > 253 || domain != strings.ToLower(domain) ||
		strings.TrimSpace(domain) != domain || strings.HasSuffix(domain, ".") || !strings.Contains(domain, ".") {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if !domainLabelPattern.MatchString(label) {
			return false
		}
	}
	return true
}

func validEntitlementDecision(decision EntitlementDecision, now time.Time) bool {
	return decision.Allowed && decision.LocallyVerified &&
		(decision.Status == EntitlementStatusValid || decision.Status == EntitlementStatusGrace) &&
		decision.LeaseSerial > 0 && !decision.EvaluatedAt.After(now)
}
