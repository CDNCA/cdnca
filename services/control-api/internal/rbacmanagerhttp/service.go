package rbacmanagerhttp

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/cdnca/cdnca/services/control-api/internal/rbacmanager"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	defaultPageLimit = 20
	maximumPageLimit = 100
)

var permissionPattern = regexp.MustCompile(`^[a-z][a-z0-9._:-]{0,127}$`)

type ServiceConfig struct {
	CursorKey []byte
}

type Service struct {
	commands Commands
	reader   ReadStore
	cursor   cursorCodec
}

func NewService(
	pool *pgxpool.Pool,
	verifier rbacmanager.StepUpVerifier,
	config ServiceConfig,
) (*Service, error) {
	if pool == nil {
		return nil, ErrInvalidRequest
	}
	if verifier == nil {
		return nil, ErrStepUpUnavailable
	}
	commands, err := rbacmanager.NewService(pool, verifier)
	if err != nil {
		return nil, ErrStepUpUnavailable
	}
	return newService(commands, newPostgresReadStore(pool), config)
}

func newService(commands Commands, reader ReadStore, config ServiceConfig) (*Service, error) {
	if commands == nil || reader == nil {
		return nil, ErrInvalidRequest
	}
	cursor, err := newCursorCodec(config.CursorKey)
	if err != nil {
		return nil, err
	}
	return &Service{commands: commands, reader: reader, cursor: cursor}, nil
}

func (service *Service) ListRoles(
	ctx context.Context,
	session AuthenticatedSession,
	input RoleListInput,
) (RolePageView, error) {
	actor, err := actorFromSession(session)
	if err != nil {
		return RolePageView{}, err
	}
	limit, err := normalizePage(input.PageInput)
	if err != nil {
		return RolePageView{}, err
	}
	filterDigest := cursorFilterDigest(struct {
		IncludeDeactivated bool `json:"include_deactivated"`
	}{input.IncludeDeactivated})
	query := RolePageQuery{Limit: limit + 1, IncludeDeactivated: input.IncludeDeactivated}
	if input.Cursor != "" {
		var cursor pageCursor
		if err := service.cursor.decode(input.Cursor, &cursor); err != nil || cursor.Kind != "roles" ||
			cursor.ScopeID != actor.ScopeID || cursor.FilterDigest != filterDigest {
			return RolePageView{}, ErrInvalidRequest
		}
		query.SnapshotVersion = &cursor.SnapshotVersion
		query.AfterVersion, query.AfterID = &cursor.AfterVersion, &cursor.AfterID
	}
	facts, err := service.reader.ListRoles(ctx, actor, query)
	if err != nil {
		return RolePageView{}, normalizeReadError(ctx, err)
	}
	if err := validateRolePageFacts(facts, query); err != nil {
		return RolePageView{}, err
	}
	result := RolePageView{Data: facts.Items}
	if len(result.Data) > limit {
		last := result.Data[limit-1]
		result.Data = result.Data[:limit]
		result.Page.NextCursor, err = service.cursor.encode(pageCursor{
			Version: cursorVersion, Kind: "roles", ScopeID: actor.ScopeID, FilterDigest: filterDigest,
			SnapshotVersion: *facts.SnapshotVersion,
			AfterVersion:    last.StateVersion, AfterID: last.ID,
		})
		if err != nil {
			return RolePageView{}, err
		}
	}
	if result.Data == nil {
		result.Data = []RoleView{}
	}
	return result, nil
}

func (service *Service) GetRole(
	ctx context.Context,
	session AuthenticatedSession,
	roleID uuid.UUID,
) (RoleView, error) {
	actor, err := actorFromSession(session)
	if err != nil {
		return RoleView{}, err
	}
	if roleID == uuid.Nil {
		return RoleView{}, ErrInvalidRequest
	}
	role, err := service.reader.GetRole(ctx, actor, roleID)
	if err != nil {
		return RoleView{}, normalizeReadError(ctx, err)
	}
	if err := validateRole(role); err != nil {
		return RoleView{}, err
	}
	return normalizeRoleTimes(role), nil
}

func (service *Service) PermissionCatalog(
	ctx context.Context,
	session AuthenticatedSession,
) ([]PermissionView, error) {
	actor, err := actorFromSession(session)
	if err != nil {
		return nil, err
	}
	permissions, err := service.reader.PermissionCatalog(ctx, actor)
	if err != nil {
		return nil, normalizeReadError(ctx, err)
	}
	if len(permissions) > 1024 {
		return nil, ErrInvalidStoreResponse
	}
	for index, permission := range permissions {
		if !permissionPattern.MatchString(permission.Name) ||
			(index > 0 && permissions[index-1].Name >= permission.Name) {
			return nil, ErrInvalidStoreResponse
		}
	}
	if permissions == nil {
		permissions = []PermissionView{}
	}
	return permissions, nil
}

func (service *Service) ListGrants(
	ctx context.Context,
	session AuthenticatedSession,
	input GrantListInput,
) (GrantPageView, error) {
	actor, err := actorFromSession(session)
	if err != nil {
		return GrantPageView{}, err
	}
	limit, err := normalizePage(input.PageInput)
	if err != nil || (input.RoleID != nil && *input.RoleID == uuid.Nil) ||
		(input.SubjectUserID != nil && *input.SubjectUserID == uuid.Nil) ||
		(input.State != "all" && input.State != "active" && input.State != "revoked") {
		return GrantPageView{}, ErrInvalidRequest
	}
	filterDigest := cursorFilterDigest(struct {
		RoleID        *uuid.UUID `json:"role_id,omitempty"`
		SubjectUserID *uuid.UUID `json:"subject_user_id,omitempty"`
		State         string     `json:"state"`
	}{input.RoleID, input.SubjectUserID, input.State})
	query := GrantPageQuery{Limit: limit + 1, RoleID: input.RoleID,
		SubjectUserID: input.SubjectUserID, State: input.State}
	if input.Cursor != "" {
		var cursor pageCursor
		if err := service.cursor.decode(input.Cursor, &cursor); err != nil || cursor.Kind != "grants" ||
			cursor.ScopeID != actor.ScopeID || cursor.FilterDigest != filterDigest {
			return GrantPageView{}, ErrInvalidRequest
		}
		query.SnapshotVersion = &cursor.SnapshotVersion
		query.AfterVersion, query.AfterID = &cursor.AfterVersion, &cursor.AfterID
	}
	facts, err := service.reader.ListGrants(ctx, actor, query)
	if err != nil {
		return GrantPageView{}, normalizeReadError(ctx, err)
	}
	if err := validateGrantPageFacts(facts, query); err != nil {
		return GrantPageView{}, err
	}
	result := GrantPageView{Data: facts.Items}
	if len(result.Data) > limit {
		last := result.Data[limit-1]
		result.Data = result.Data[:limit]
		result.Page.NextCursor, err = service.cursor.encode(pageCursor{
			Version: cursorVersion, Kind: "grants", ScopeID: actor.ScopeID, FilterDigest: filterDigest,
			SnapshotVersion: *facts.SnapshotVersion,
			AfterVersion:    last.StateVersion, AfterID: last.ID,
		})
		if err != nil {
			return GrantPageView{}, err
		}
	}
	if result.Data == nil {
		result.Data = []GrantView{}
	}
	return result, nil
}

func (service *Service) CreateRole(
	ctx context.Context,
	session AuthenticatedSession,
	name string,
	permissions []string,
	metadata WriteMetadata,
) (RoleView, error) {
	actor, err := actorFromSession(session)
	if err != nil {
		return RoleView{}, err
	}
	role, err := service.commands.CreateRole(ctx, actor, rbacmanager.CreateRoleRequest{
		Name: name, Permissions: permissions, Mutation: mutationContext(metadata),
	})
	return roleViewFromCore(actor, role, err)
}

func (service *Service) RenameRole(
	ctx context.Context,
	session AuthenticatedSession,
	roleID uuid.UUID,
	expectedRevision int64,
	name string,
	metadata WriteMetadata,
) (RoleView, error) {
	actor, err := actorFromSession(session)
	if err != nil {
		return RoleView{}, err
	}
	role, err := service.commands.RenameRole(ctx, actor, rbacmanager.RenameRoleRequest{
		RoleID: roleID, ExpectedRevision: expectedRevision, Name: name, Mutation: mutationContext(metadata),
	})
	result, err := roleViewFromCore(actor, role, err)
	if err == nil && (result.ID != roleID || result.CurrentRevision != expectedRevision+1) {
		return RoleView{}, ErrInvalidStoreResponse
	}
	return result, err
}

func (service *Service) PublishRole(
	ctx context.Context,
	session AuthenticatedSession,
	roleID uuid.UUID,
	expectedRevision int64,
	permissions []string,
	metadata WriteMetadata,
) (RoleView, error) {
	actor, err := actorFromSession(session)
	if err != nil {
		return RoleView{}, err
	}
	role, err := service.commands.PublishRevision(ctx, actor, rbacmanager.PublishRevisionRequest{
		RoleID: roleID, ExpectedRevision: expectedRevision, Permissions: permissions,
		Mutation: mutationContext(metadata),
	})
	result, err := roleViewFromCore(actor, role, err)
	if err == nil && (result.ID != roleID || result.CurrentRevision != expectedRevision+1) {
		return RoleView{}, ErrInvalidStoreResponse
	}
	return result, err
}

func (service *Service) DeactivateRole(
	ctx context.Context,
	session AuthenticatedSession,
	roleID uuid.UUID,
	expectedRevision int64,
	metadata WriteMetadata,
) (RoleView, error) {
	actor, err := actorFromSession(session)
	if err != nil {
		return RoleView{}, err
	}
	role, err := service.commands.DeactivateRole(ctx, actor, rbacmanager.DeactivateRoleRequest{
		RoleID: roleID, ExpectedRevision: expectedRevision, Mutation: mutationContext(metadata),
	})
	result, err := roleViewFromCore(actor, role, err)
	if err == nil && (result.ID != roleID || result.CurrentRevision != expectedRevision || result.DeactivatedAt == nil) {
		return RoleView{}, ErrInvalidStoreResponse
	}
	return result, err
}

func (service *Service) AssignRole(
	ctx context.Context,
	session AuthenticatedSession,
	roleID uuid.UUID,
	expectedRevision int64,
	subjectUserID uuid.UUID,
	metadata WriteMetadata,
) (GrantView, error) {
	actor, err := actorFromSession(session)
	if err != nil {
		return GrantView{}, err
	}
	grant, err := service.commands.AssignRole(ctx, actor, rbacmanager.AssignRoleRequest{
		RoleID: roleID, ExpectedRoleRevision: expectedRevision, SubjectUserID: subjectUserID,
		Mutation: mutationContext(metadata),
	})
	if err != nil {
		return GrantView{}, err
	}
	if grant.ID == uuid.Nil || grant.TenantID == uuid.Nil || grant.RoleID != roleID ||
		grant.RoleRevision != expectedRevision || grant.SubjectUserID != subjectUserID ||
		grant.GrantedByUserID != actor.UserID || grant.GrantedAt.IsZero() ||
		grant.TenantScopeID != actor.ScopeID {
		return GrantView{}, ErrInvalidStoreResponse
	}
	return GrantView{ID: grant.ID, RoleID: grant.RoleID, RoleRevision: grant.RoleRevision,
		SubjectUserID: grant.SubjectUserID, GrantedByUserID: grant.GrantedByUserID,
		GrantedAt: grant.GrantedAt.UTC(), Replayed: grant.Replayed}, nil
}

func (service *Service) RevokeGrant(
	ctx context.Context,
	session AuthenticatedSession,
	grantID uuid.UUID,
	metadata WriteMetadata,
) (RevocationView, error) {
	actor, err := actorFromSession(session)
	if err != nil {
		return RevocationView{}, err
	}
	revocation, err := service.commands.RevokeGrant(ctx, actor, rbacmanager.RevokeGrantRequest{
		GrantID: grantID, Mutation: mutationContext(metadata),
	})
	if err != nil {
		return RevocationView{}, err
	}
	if revocation.ID == uuid.Nil || revocation.GrantID != grantID ||
		revocation.RevokedByUserID != actor.UserID || revocation.RevokedAt.IsZero() {
		return RevocationView{}, ErrInvalidStoreResponse
	}
	return RevocationView{ID: revocation.ID, GrantID: revocation.GrantID,
		RevokedByUserID: revocation.RevokedByUserID, RevokedAt: revocation.RevokedAt.UTC(),
		Replayed: revocation.Replayed}, nil
}

func actorFromSession(session AuthenticatedSession) (rbacmanager.Actor, error) {
	if session.UserID == uuid.Nil || session.ScopeID == uuid.Nil || session.SessionID == uuid.Nil ||
		session.ScopeKind != "tenant" || session.IdentityDomain != rbacmanager.CustomerControlIdentityDomain {
		return rbacmanager.Actor{}, ErrPermissionDenied
	}
	return rbacmanager.Actor{UserID: session.UserID, ScopeID: session.ScopeID,
		SessionID: session.SessionID, ScopeKind: session.ScopeKind,
		IdentityDomain: session.IdentityDomain}, nil
}

func mutationContext(metadata WriteMetadata) rbacmanager.MutationContext {
	return rbacmanager.MutationContext{IdempotencyKey: metadata.IdempotencyKey,
		RequestID: metadata.RequestID, TraceID: metadata.TraceID,
		StepUp: rbacmanager.StepUpProof{Token: metadata.StepUpToken}}
}

func roleViewFromCore(actor rbacmanager.Actor, role rbacmanager.Role, err error) (RoleView, error) {
	if err != nil {
		return RoleView{}, err
	}
	result := RoleView{ID: role.ID, Name: role.Name, CurrentRevision: role.CurrentRevision,
		Permissions: role.Permissions, DeactivatedAt: role.DeactivatedAt,
		CreatedAt: role.CreatedAt, Replayed: role.Replayed}
	if role.TenantScopeID != actor.ScopeID {
		return RoleView{}, ErrInvalidStoreResponse
	}
	if err := validateRole(result); err != nil {
		return RoleView{}, err
	}
	return normalizeRoleTimes(result), nil
}

func validateRolePageFacts(facts RolePageFacts, query RolePageQuery) error {
	if len(facts.Items) > query.Limit || facts.SnapshotVersion == nil || *facts.SnapshotVersion < 0 {
		return ErrInvalidStoreResponse
	}
	if query.SnapshotVersion != nil && *facts.SnapshotVersion != *query.SnapshotVersion {
		return ErrInvalidStoreResponse
	}
	for index, role := range facts.Items {
		if err := validateRole(role); err != nil || role.StateVersion < 1 ||
			role.StateVersion > *facts.SnapshotVersion ||
			(!query.IncludeDeactivated && role.DeactivatedAt != nil) {
			return ErrInvalidStoreResponse
		}
		if query.AfterVersion != nil && !beforeVersion(role.StateVersion, role.ID,
			*query.AfterVersion, *query.AfterID) {
			return ErrInvalidStoreResponse
		}
		if index > 0 && !beforeVersion(role.StateVersion, role.ID,
			facts.Items[index-1].StateVersion, facts.Items[index-1].ID) {
			return ErrInvalidStoreResponse
		}
		facts.Items[index] = normalizeRoleTimes(role)
	}
	return nil
}

func validateGrantPageFacts(facts GrantPageFacts, query GrantPageQuery) error {
	if len(facts.Items) > query.Limit || facts.SnapshotVersion == nil || *facts.SnapshotVersion < 0 {
		return ErrInvalidStoreResponse
	}
	if query.SnapshotVersion != nil && *facts.SnapshotVersion != *query.SnapshotVersion {
		return ErrInvalidStoreResponse
	}
	for index, grant := range facts.Items {
		if grant.ID == uuid.Nil || grant.RoleID == uuid.Nil || grant.RoleRevision < 1 ||
			grant.SubjectUserID == uuid.Nil || grant.GrantedByUserID == uuid.Nil || grant.GrantedAt.IsZero() ||
			grant.StateVersion < 1 || grant.StateVersion > *facts.SnapshotVersion ||
			(query.RoleID != nil && grant.RoleID != *query.RoleID) ||
			(query.SubjectUserID != nil && grant.SubjectUserID != *query.SubjectUserID) ||
			(query.State == "active" && grant.RevokedAt != nil) ||
			(query.State == "revoked" && grant.RevokedAt == nil) {
			return ErrInvalidStoreResponse
		}
		if query.AfterVersion != nil && !beforeVersion(grant.StateVersion, grant.ID,
			*query.AfterVersion, *query.AfterID) {
			return ErrInvalidStoreResponse
		}
		if grant.RevokedAt != nil && grant.RevokedAt.Before(grant.GrantedAt) {
			return ErrInvalidStoreResponse
		}
		if index > 0 && !beforeVersion(grant.StateVersion, grant.ID,
			facts.Items[index-1].StateVersion, facts.Items[index-1].ID) {
			return ErrInvalidStoreResponse
		}
		facts.Items[index].GrantedAt = grant.GrantedAt.UTC()
		if grant.RevokedAt != nil {
			value := grant.RevokedAt.UTC()
			facts.Items[index].RevokedAt = &value
		}
	}
	return nil
}

func validateRole(role RoleView) error {
	if role.ID == uuid.Nil || role.CurrentRevision < 1 || role.CreatedAt.IsZero() ||
		role.Name != strings.ToLower(strings.TrimSpace(role.Name)) || !validPublicText(role.Name, 1, 128) ||
		len(role.Permissions) < 1 || len(role.Permissions) > 128 || !slices.IsSorted(role.Permissions) {
		return ErrInvalidStoreResponse
	}
	if role.DeactivatedAt != nil && role.DeactivatedAt.Before(role.CreatedAt) {
		return ErrInvalidStoreResponse
	}
	for index, permission := range role.Permissions {
		if !permissionPattern.MatchString(permission) ||
			(index > 0 && role.Permissions[index-1] == permission) {
			return ErrInvalidStoreResponse
		}
	}
	return nil
}

func normalizeRoleTimes(role RoleView) RoleView {
	role.CreatedAt = role.CreatedAt.UTC()
	if role.DeactivatedAt != nil {
		value := role.DeactivatedAt.UTC()
		role.DeactivatedAt = &value
	}
	return role
}

func normalizePage(input PageInput) (int, error) {
	if len(input.Cursor) > maxCursorBytes {
		return 0, ErrInvalidRequest
	}
	if input.Limit == 0 {
		return defaultPageLimit, nil
	}
	if input.Limit < 1 || input.Limit > maximumPageLimit {
		return 0, ErrInvalidRequest
	}
	return input.Limit, nil
}

func normalizeReadError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, ErrPermissionDenied) || errors.Is(err, ErrNotFound) ||
		errors.Is(err, ErrInvalidStoreResponse) {
		return err
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	return ErrStoreUnavailable
}

func beforeVersion(version int64, id uuid.UUID, previousVersion int64, previousID uuid.UUID) bool {
	return version < previousVersion || (version == previousVersion && id.String() < previousID.String())
}

func validPublicText(value string, minimum, maximum int) bool {
	if value != strings.TrimSpace(value) || !utf8.ValidString(value) {
		return false
	}
	length := utf8.RuneCountInString(value)
	if length < minimum || length > maximum {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f || character == '\u2028' || character == '\u2029' {
			return false
		}
	}
	return true
}
