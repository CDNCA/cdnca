package identityverificationhttp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"reflect"
	"regexp"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identityverification"
	"github.com/google/uuid"
)

const (
	defaultPageLimit          = 20
	maximumPageLimit          = 100
	reservationReleaseTimeout = 2 * time.Second
)

var (
	metadataPattern          = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	tokenPattern             = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._~-]{31,511}$`)
	resolverNamePattern      = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)
	resolverReferencePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$`)
)

type Service struct {
	core     CoreService
	reader   ReviewReadStore
	resolver TrustedEvidenceResolver
	cursor   cursorCodec
}

type ServiceConfig struct {
	CursorKey []byte
}

func NewService(core CoreService, reader ReviewReadStore, resolver TrustedEvidenceResolver, config ServiceConfig) (*Service, error) {
	return nil, ErrInvalidService
}

// newService is a package-local test seam. Production assembly uses NewRuntimeHandler.
func newService(core CoreService, reader ReviewReadStore, resolver TrustedEvidenceResolver, config ServiceConfig) (*Service, error) {
	if isNilDependency(core) || isNilDependency(reader) {
		return nil, ErrInvalidService
	}
	if isNilDependency(resolver) {
		return nil, ErrTrustedEvidenceResolverRequired
	}
	cursor, err := newCursorCodec(config.CursorKey)
	if err != nil {
		return nil, err
	}
	return &Service{core: core, reader: reader, resolver: resolver, cursor: cursor}, nil
}

func (service *Service) CreateDraft(ctx context.Context, actor identityverification.Actor, input CreateDraftInput, metadata WriteMetadata) (CaseView, error) {
	if !validActor(actor) || !validKind(input.Kind) || !tokenPattern.MatchString(input.EvidenceToken) ||
		!validMetadata(metadata) {
		return CaseView{}, ErrInvalidRequest
	}
	digest := evidenceRequestDigest(input)
	if err := service.core.AuthorizeCreateDraft(ctx, actor); err != nil {
		return CaseView{}, normalizeCoreError(ctx, err)
	}
	reservation, err := service.resolver.Reserve(ctx, actor,
		EvidenceReference{Kind: input.Kind, Token: input.EvidenceToken}, metadata.IdempotencyKey, digest)
	if err != nil {
		return CaseView{}, normalizeResolverError(ctx, err)
	}
	releaseReservation := func(quarantine bool) error {
		base := context.Background()
		if ctx != nil {
			base = context.WithoutCancel(ctx)
		}
		cleanupCtx, cancel := context.WithTimeout(base, reservationReleaseTimeout)
		defer cancel()
		if quarantine {
			return service.resolver.Quarantine(cleanupCtx, reservation.ID)
		}
		return service.resolver.Abort(cleanupCtx, reservation.ID)
	}
	if !tokenPattern.MatchString(reservation.ID) || reservation.Evidence.Kind != input.Kind ||
		!resolverNamePattern.MatchString(reservation.ResolverName) ||
		!resolverReferencePattern.MatchString(reservation.ResolverReference) ||
		reservation.EvidenceClaimDigest == ([32]byte{}) {
		if tokenPattern.MatchString(reservation.ID) {
			if err := releaseReservation(false); err != nil {
				return CaseView{}, normalizeResolverError(ctx, err)
			}
		}
		return CaseView{}, ErrInvalidEvidence
	}
	resolved := reservation.Evidence
	outcome, err := service.core.CreateDraftWithSettlement(ctx, actor, identityverification.CreateDraftRequest{
		Kind: resolved.Kind, SubjectFingerprint: resolved.SubjectFingerprint,
		OrganizationName: resolved.OrganizationName, LegalPersonFingerprint: resolved.LegalPersonFingerprint,
		AgentFingerprint: resolved.AgentFingerprint, AgentRelationship: resolved.AgentRelationship,
		Materials: resolved.Materials, ResolverName: reservation.ResolverName,
		ResolverReference: reservation.ResolverReference, EvidenceClaimDigest: reservation.EvidenceClaimDigest,
		IdempotencyKey: metadata.IdempotencyKey, RequestID: metadata.RequestID,
	})
	if err != nil {
		if outcome.SettlementBound || errors.Is(err, identityverification.ErrCommitOutcomeUnknown) {
			return CaseView{}, normalizeCoreError(ctx, err)
		}
		releaseErr := releaseReservation(outcome.AuthorizationPassed)
		if releaseErr != nil {
			return CaseView{}, normalizeResolverError(ctx, releaseErr)
		}
		return CaseView{}, normalizeCoreError(ctx, err)
	}
	if !outcome.TransactionStarted || !outcome.AuthorizationPassed || !outcome.SettlementBound {
		if outcome.SettlementBound {
			return CaseView{}, ErrStoreUnavailable
		}
		releaseErr := releaseReservation(outcome.AuthorizationPassed)
		if releaseErr != nil {
			return CaseView{}, normalizeResolverError(ctx, releaseErr)
		}
		return CaseView{}, ErrStoreUnavailable
	}
	return caseView(actor, outcome.Case, true)
}

func (service *Service) GetSelf(ctx context.Context, actor identityverification.Actor, caseID uuid.UUID) (CaseView, error) {
	if !validActor(actor) || caseID == uuid.Nil {
		return CaseView{}, ErrInvalidRequest
	}
	item, err := service.core.Get(ctx, actor, caseID)
	if err != nil {
		return CaseView{}, normalizeResourceCoreError(ctx, err)
	}
	if item.ApplicantUserID != actor.UserID {
		return CaseView{}, ErrNotFound
	}
	return caseView(actor, item, true)
}

// GetSelfStatus derives the profile badge: an approved person stays verified;
// otherwise an in-flight case is pending, a rejected latest case is rejected,
// and drafts, withdrawn or expired cases count as unverified.
func (service *Service) GetSelfStatus(ctx context.Context, actor identityverification.Actor) (StatusView, error) {
	if !validActor(actor) {
		return StatusView{}, ErrInvalidRequest
	}
	current, err := service.core.CurrentStatus(ctx, actor)
	if err != nil {
		return StatusView{}, normalizeCoreError(ctx, err)
	}
	if current.PersonVerified != (current.VerifiedAt != nil) ||
		(current.VerifiedAt != nil && current.VerifiedAt.IsZero()) {
		return StatusView{}, ErrInvalidStoreResponse
	}
	view := StatusView{Status: SelfStatusUnverified, VerifiedAt: current.VerifiedAt}
	if item := current.LatestCase; item != nil {
		if item.ID == uuid.Nil || item.TenantScopeID != actor.ScopeID || item.ApplicantUserID != actor.UserID ||
			item.Revision < 1 || !validKind(item.Kind) || !validStatus(item.Status) ||
			!validCaseDecisionReason(item.Status, item.DecisionReasonCode) {
			return StatusView{}, ErrInvalidStoreResponse
		}
		view.LatestCase = &StatusCaseView{ID: item.ID, Kind: item.Kind, Status: item.Status,
			DecisionReasonCode: item.DecisionReasonCode, Revision: item.Revision,
			CreatedAt: item.CreatedAt, StateChangedAt: item.StateChangedAt, SubmittedAt: item.SubmittedAt}
		switch item.Status {
		case identityverification.StatusSubmitted, identityverification.StatusReviewing:
			view.Status = SelfStatusPending
		case identityverification.StatusRejected:
			view.Status = SelfStatusRejected
		}
	}
	if current.PersonVerified {
		view.Status = SelfStatusVerified
	}
	return view, nil
}

func (service *Service) GetReviewer(ctx context.Context, actor identityverification.Actor, caseID uuid.UUID) (CaseView, error) {
	if !validActor(actor) || caseID == uuid.Nil {
		return CaseView{}, ErrInvalidRequest
	}
	item, err := service.core.GetForReview(ctx, actor, caseID)
	if err != nil {
		return CaseView{}, normalizeCoreError(ctx, err)
	}
	return caseView(actor, item, false)
}

func evidenceRequestDigest(input CreateDraftInput) [32]byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte("identity-verification-create-v1\x00"))
	_, _ = hash.Write([]byte(input.Kind))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(input.EvidenceToken))
	var digest [32]byte
	copy(digest[:], hash.Sum(nil))
	return digest
}

func (service *Service) Submit(ctx context.Context, actor identityverification.Actor, input MutationInput) (CaseView, error) {
	return service.mutate(ctx, actor, input, service.core.Submit)
}

func (service *Service) Withdraw(ctx context.Context, actor identityverification.Actor, input MutationInput) (CaseView, error) {
	return service.mutate(ctx, actor, input, service.core.Withdraw)
}

// ExpireSelf mirrors the current core contract. It must not be used to
// impersonate an applicant from reviewer or scheduler credentials.
func (service *Service) ExpireSelf(ctx context.Context, actor identityverification.Actor, input MutationInput) (CaseView, error) {
	return service.mutate(ctx, actor, input, service.core.Expire)
}

func (service *Service) Claim(ctx context.Context, actor identityverification.Actor, input MutationInput) (CaseView, error) {
	return service.mutate(ctx, actor, input, service.core.StartReview)
}

func (service *Service) Decide(ctx context.Context, actor identityverification.Actor, input DecisionInput) (CaseView, error) {
	if !validActor(actor) || input.CaseID == uuid.Nil || input.ExpectedRevision < 1 ||
		!validMetadata(input.WriteMetadata) {
		return CaseView{}, ErrInvalidRequest
	}
	item, err := service.core.Review(ctx, actor, identityverification.ReviewRequest{
		CaseID: input.CaseID, ExpectedRevision: input.ExpectedRevision, Decision: input.Decision,
		ReasonCode: input.ReasonCode, IdempotencyKey: input.IdempotencyKey, RequestID: input.RequestID,
	})
	if err != nil {
		return CaseView{}, normalizeResourceCoreError(ctx, err)
	}
	return caseView(actor, item, false)
}

func (service *Service) mutate(ctx context.Context, actor identityverification.Actor, input MutationInput,
	operation func(context.Context, identityverification.Actor, identityverification.MutationRequest) (identityverification.Case, error),
) (CaseView, error) {
	if !validActor(actor) || input.CaseID == uuid.Nil || input.ExpectedRevision < 1 ||
		!validMetadata(input.WriteMetadata) {
		return CaseView{}, ErrInvalidRequest
	}
	item, err := operation(ctx, actor, identityverification.MutationRequest{
		CaseID: input.CaseID, ExpectedRevision: input.ExpectedRevision,
		IdempotencyKey: input.IdempotencyKey, RequestID: input.RequestID,
	})
	if err != nil {
		return CaseView{}, normalizeResourceCoreError(ctx, err)
	}
	return caseView(actor, item, false)
}

func (service *Service) ListReviewerCases(ctx context.Context, actor identityverification.Actor, input PageInput) (PageView, error) {
	if !validActor(actor) || !validKindFilter(input.Kind) || !validStatusFilter(input.Status) {
		return PageView{}, ErrInvalidRequest
	}
	limit := input.Limit
	if limit == 0 {
		limit = defaultPageLimit
	}
	if limit < 1 || limit > maximumPageLimit || len(input.Cursor) > maxCursorBytes {
		return PageView{}, ErrInvalidRequest
	}
	query := CasePageQuery{Limit: limit + 1, Kind: input.Kind, Status: input.Status}
	if input.Cursor != "" {
		var cursor pageCursor
		if err := service.cursor.decode(input.Cursor, &cursor); err != nil ||
			cursor.ScopeBinding != service.cursor.scopeBinding(actor.TenantScopeID()) ||
			cursor.Kind != input.Kind || cursor.Status != input.Status {
			return PageView{}, ErrInvalidRequest
		}
		query.AfterCreatedAt, query.AfterID = &cursor.CreatedAt, &cursor.ID
	}
	items, err := service.reader.ListCases(ctx, actor, query)
	if err != nil {
		return PageView{}, normalizeReadError(ctx, err)
	}
	if err := validateSummaries(items, query); err != nil {
		return PageView{}, err
	}
	page := PageView{Items: items}
	if len(items) > limit {
		last := items[limit-1]
		page.Items = items[:limit]
		page.NextCursor, err = service.cursor.encode(pageCursor{Version: cursorVersion,
			ScopeBinding: service.cursor.scopeBinding(actor.TenantScopeID()), Kind: input.Kind, Status: input.Status,
			CreatedAt: last.CreatedAt, ID: last.ID})
		if err != nil {
			return PageView{}, err
		}
	}
	if page.Items == nil {
		page.Items = []CaseSummary{}
	}
	return page, nil
}

// ListAdminCases is the platform administrator's cross-tenant list; the
// cursor is bound to the platform scope.
func (service *Service) ListAdminCases(ctx context.Context, admin identityverification.PlatformAdmin,
	input PageInput,
) (AdminPageView, error) {
	if !admin.Valid() || !validKindFilter(input.Kind) || !validStatusFilter(input.Status) {
		return AdminPageView{}, ErrInvalidRequest
	}
	limit := input.Limit
	if limit == 0 {
		limit = defaultPageLimit
	}
	if limit < 1 || limit > maximumPageLimit || len(input.Cursor) > maxCursorBytes {
		return AdminPageView{}, ErrInvalidRequest
	}
	query := CasePageQuery{Limit: limit + 1, Kind: input.Kind, Status: input.Status}
	if input.Cursor != "" {
		var cursor pageCursor
		if err := service.cursor.decode(input.Cursor, &cursor); err != nil ||
			cursor.ScopeBinding != service.cursor.scopeBinding(admin.ScopeID) ||
			cursor.Kind != input.Kind || cursor.Status != input.Status {
			return AdminPageView{}, ErrInvalidRequest
		}
		query.AfterCreatedAt, query.AfterID = &cursor.CreatedAt, &cursor.ID
	}
	items, err := service.reader.ListAdminCases(ctx, admin, query)
	if err != nil {
		return AdminPageView{}, normalizeReadError(ctx, err)
	}
	summaries := make([]CaseSummary, len(items))
	for index := range items {
		if items[index].TenantScopeID == uuid.Nil || items[index].TenantName == "" || items[index].ApplicantUsername == "" {
			return AdminPageView{}, ErrInvalidStoreResponse
		}
		summaries[index] = items[index].CaseSummary
	}
	if err := validateSummaries(summaries, query); err != nil {
		return AdminPageView{}, err
	}
	page := AdminPageView{Items: items}
	if len(items) > limit {
		last := items[limit-1]
		page.Items = items[:limit]
		page.NextCursor, err = service.cursor.encode(pageCursor{Version: cursorVersion,
			ScopeBinding: service.cursor.scopeBinding(admin.ScopeID), Kind: input.Kind, Status: input.Status,
			CreatedAt: last.CreatedAt, ID: last.ID})
		if err != nil {
			return AdminPageView{}, err
		}
	}
	if page.Items == nil {
		page.Items = []AdminCaseSummary{}
	}
	return page, nil
}

func caseView(actor identityverification.Actor, item identityverification.Case, requireSelf bool) (CaseView, error) {
	if item.ID == uuid.Nil || item.TenantScopeID != actor.TenantScopeID() || item.ApplicantUserID == uuid.Nil ||
		item.Revision < 1 || !validKind(item.Kind) || !validStatus(item.Status) ||
		!validCaseDecisionReason(item.Status, item.DecisionReasonCode) ||
		(requireSelf && item.ApplicantUserID != actor.UserID) ||
		(item.AgentRelationship != "" && !validRelationship(item.AgentRelationship)) {
		return CaseView{}, ErrInvalidStoreResponse
	}
	materials := make([]MaterialView, len(item.Materials))
	for index, material := range item.Materials {
		if material.ID == uuid.Nil || !validMaterialKind(material.Kind) || !validMIME(material.MIMEType) ||
			material.SizeBytes < 1 || material.CreatedAt.IsZero() {
			return CaseView{}, ErrInvalidStoreResponse
		}
		materials[index] = MaterialView{ID: material.ID, Kind: material.Kind,
			EncryptedEnvelopePresent: material.EncryptedEnvelopePresent, MIMEType: material.MIMEType,
			SizeBytes: material.SizeBytes, CreatedAt: material.CreatedAt}
	}
	return CaseView{ID: item.ID, ApplicantUserID: item.ApplicantUserID, Kind: item.Kind, Status: item.Status,
		DecisionReasonCode: item.DecisionReasonCode,
		AgentRelationship:  item.AgentRelationship, ReviewerUserID: item.ReviewerUserID,
		Revision: item.Revision, CreatedAt: item.CreatedAt, StateChangedAt: item.StateChangedAt,
		SubmittedAt: item.SubmittedAt, ExpiresAt: item.ExpiresAt, TerminalAt: item.TerminalAt,
		Retention: RetentionView{Eligible: item.Retention.Eligible, EligibleAt: item.Retention.EligibleAt,
			ReasonCode: item.Retention.ReasonCode}, Materials: materials, Replayed: item.Replayed}, nil
}

func validCaseDecisionReason(status, reason string) bool {
	switch status {
	case identityverification.StatusApproved:
		return reason == identityverification.ReasonEvidenceVerified
	case identityverification.StatusRejected:
		switch reason {
		case identityverification.ReasonIdentityMismatch, identityverification.ReasonEvidenceIncomplete,
			identityverification.ReasonEvidenceUnreadable, identityverification.ReasonOrganizationMismatch,
			identityverification.ReasonAuthorizationInvalid, identityverification.ReasonSuspectedFraud:
			return true
		default:
			return false
		}
	default:
		return reason == ""
	}
}

func validateSummaries(items []CaseSummary, query CasePageQuery) error {
	if len(items) > query.Limit {
		return ErrInvalidStoreResponse
	}
	for index := range items {
		item := items[index]
		if item.ID == uuid.Nil || item.ApplicantUserID == uuid.Nil || item.Revision < 1 ||
			!validKind(item.Kind) || !validStatus(item.Status) || !validCursorTime(item.CreatedAt) ||
			(query.Kind != "" && item.Kind != query.Kind) || (query.Status != "" && item.Status != query.Status) ||
			(item.ReviewerUserID != nil && *item.ReviewerUserID == item.ApplicantUserID) {
			return ErrInvalidStoreResponse
		}
		if index > 0 {
			previous := items[index-1]
			if item.CreatedAt.After(previous.CreatedAt) ||
				(item.CreatedAt.Equal(previous.CreatedAt) && bytes.Compare(item.ID[:], previous.ID[:]) >= 0) {
				return ErrInvalidStoreResponse
			}
		}
	}
	return nil
}

func validActor(actor identityverification.Actor) bool {
	return actor.Valid()
}

func isNilDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func validMetadata(metadata WriteMetadata) bool {
	return metadataPattern.MatchString(metadata.IdempotencyKey) && metadataPattern.MatchString(metadata.RequestID)
}

func validKind(value string) bool {
	return value == identityverification.KindPersonalInitial ||
		value == identityverification.KindPersonalReverification || value == identityverification.KindEnterprise
}

func validKindFilter(value string) bool {
	return value == "" || validKind(value)
}

func validStatus(value string) bool {
	switch value {
	case identityverification.StatusDraft, identityverification.StatusSubmitted, identityverification.StatusReviewing,
		identityverification.StatusApproved, identityverification.StatusRejected,
		identityverification.StatusWithdrawn, identityverification.StatusExpired:
		return true
	default:
		return false
	}
}

func validStatusFilter(value string) bool {
	return value == "" || validStatus(value)
}

func validMaterialKind(value string) bool {
	switch value {
	case identityverification.MaterialIdentityDocument, identityverification.MaterialLivenessEvidence,
		identityverification.MaterialBusinessLicense, identityverification.MaterialLegalIdentity,
		identityverification.MaterialAgentIdentity, identityverification.MaterialAuthorization,
		identityverification.MaterialSupplementary:
		return true
	default:
		return false
	}
}

func validMIME(value string) bool {
	return value == "image/jpeg" || value == "image/png" || value == "application/pdf"
}

func validRelationship(value string) bool {
	return value == identityverification.RelationshipLegalPerson ||
		value == identityverification.RelationshipEmployee ||
		value == identityverification.RelationshipAuthorizedRepresentative
}

func normalizeResolverError(ctx context.Context, err error) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	switch {
	case errors.Is(err, ErrEvidenceReservationConflict):
		return identityverification.ErrIdempotencyConflict
	case errors.Is(err, ErrInvalidEvidence), errors.Is(err, ErrEvidenceUnavailable):
		return err
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	default:
		return ErrEvidenceUnavailable
	}
}

func normalizeReadError(ctx context.Context, err error) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	err = mapReaderNoRows(err)
	switch {
	case errors.Is(err, ErrInvalidRequest), errors.Is(err, ErrPermissionDenied), errors.Is(err, ErrNotFound),
		errors.Is(err, ErrInvalidStoreResponse):
		return err
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	default:
		return ErrStoreUnavailable
	}
}

func normalizeCoreError(ctx context.Context, err error) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	known := []error{
		identityverification.ErrInvalidInput, identityverification.ErrPermissionDenied,
		identityverification.ErrNotFound, identityverification.ErrRevisionConflict,
		identityverification.ErrInvalidTransition, identityverification.ErrIdempotencyConflict,
		identityverification.ErrActiveReview, identityverification.ErrInitialApprovalRequired,
		identityverification.ErrIdentityMismatch, identityverification.ErrAlreadyVerified,
		identityverification.ErrSelfReview, identityverification.ErrReviewAssignment,
		identityverification.ErrExpired, identityverification.ErrNotExpired,
		identityverification.ErrEvidenceSettlementPending,
	}
	for _, candidate := range known {
		if errors.Is(err, candidate) {
			return candidate
		}
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return ErrStoreUnavailable
}

func normalizeResourceCoreError(ctx context.Context, err error) error {
	normalized := normalizeCoreError(ctx, err)
	if errors.Is(normalized, identityverification.ErrPermissionDenied) {
		return ErrNotFound
	}
	return normalized
}
