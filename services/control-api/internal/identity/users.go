package identity

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/cdnca/cdnca/services/control-api/internal/bridgeauth"
	"net/mail"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
	"github.com/cdnca/cdnca/services/control-api/internal/phonenumber"
	"github.com/cdnca/cdnca/services/control-api/internal/systemusersettings"
	"github.com/google/uuid"
)

const (
	UserStatusActive   = "active"
	UserStatusDisabled = "disabled"
	UserRoleOwner      = "tenant_owner"
	UserRoleViewer     = "tenant_viewer"
	// Platform-scope administrators are listed alongside tenant users but are
	// never created, re-typed or grouped through the managed user endpoints.
	UserRolePlatformOwner = "platform_owner"
	UserRolePlatformAdmin = "platform_admin"
)

var (
	ErrInvalidUserInput                   = errors.New("invalid user input")
	ErrUserNotFound                       = errors.New("user not found")
	ErrUserGroupNotFound                  = errors.New("user group not found")
	ErrUserGroupConflict                  = errors.New("user group name conflict")
	ErrUserGroupInUse                     = errors.New("user group is in use")
	ErrRevisionConflict                   = errors.New("user revision conflict")
	ErrIdempotencyConflict                = errors.New("identity idempotency conflict")
	ErrManagedPasswordResetStepUpRequired = errors.New("managed password reset step-up required")
	ErrManagedPasswordResetUnavailable    = errors.New("managed password reset unavailable")
	// ErrUserProtected rejects a mutation that would delete the acting
	// administrator, leave the platform without an active platform_owner, or
	// change a platform administrator's type or group through this endpoint.
	ErrUserProtected   = errors.New("managed user is protected")
	usernamePattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)
	idempotencyPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
	displayIDPattern   = regexp.MustCompile(`^[1-9][0-9]{0,18}$`)
)

type Actor struct {
	UserID    uuid.UUID
	ScopeID   uuid.UUID
	ScopeKind string
	SessionID uuid.UUID
	// bridge is the billing bridge credential (ADR 0019 §4.4); only
	// NewBridgeActor sets it.
	bridge *bridgeauth.Grant
}

type UserMetadata struct {
	Remark *string `json:"remark"`
	QQ     *string `json:"qq"`
}

type UserVerification struct {
	PersonalVerified bool `json:"personal_verified"`
	CompanyVerified  bool `json:"company_verified"`
}

type ManagedUser struct {
	ID          uuid.UUID     `json:"id"`
	DisplayID   string        `json:"display_id"`
	ScopeID     uuid.UUID     `json:"scope_id"`
	TenantID    *uuid.UUID    `json:"tenant_id"` // nil for platform-scope administrators
	Username    string        `json:"username"`
	DisplayName string        `json:"display_name"`
	Email       *string       `json:"email"`
	Phone       *string       `json:"phone"`
	Status      string        `json:"status"`
	Role        string        `json:"role"`
	GroupID     *uuid.UUID    `json:"group_id"`
	GroupName   *string       `json:"group_name"`
	Revision    int64         `json:"revision"`
	CreatedAt   time.Time     `json:"created_at"`
	UpdatedAt   time.Time     `json:"updated_at"`
	Metadata    *UserMetadata `json:"metadata,omitempty"`

	Verification *UserVerification `json:"verification,omitempty"`
	Reseller     *UserReseller     `json:"reseller,omitempty"`
}

// UserReseller is the ADR 0018 reseller projection of a managed user's tenant
// (include=reseller). Platform administrators carry is_reseller=false and no parent.
type UserReseller struct {
	IsReseller bool `json:"is_reseller"`
	// Status is the reseller profile status (active/suspended); nil when not a reseller.
	Status        *string    `json:"status"`
	ParentScopeID *uuid.UUID `json:"parent_scope_id"`
	ParentName    *string    `json:"parent_name"`
}

type AccountProfile struct {
	ID          uuid.UUID `json:"id"`
	Username    string    `json:"username"`
	DisplayName string    `json:"display_name"`
	Email       *string   `json:"email"`
	Phone       *string   `json:"phone"`
	Revision    int64     `json:"revision"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type ListUsersInput struct {
	Page        int
	Limit       int
	DisplayID   string
	Search      string
	Remark      string
	QQ          string
	Status      string
	Role        string
	GroupID     *uuid.UUID
	Username    string
	DisplayName string
	Email       string
	Phone       string

	RealNameStatus      string
	IncludeVerification bool
	// IncludePlatformAdmins adds platform-scope administrators to the list.
	IncludePlatformAdmins bool
	// IncludeReseller adds the reseller projection to every item.
	IncludeReseller bool
	// Type filters tenant users (ADR 0018): "" all, "reseller" tenants with a
	// reseller profile, "customer" tenants owned by a reseller, "direct" neither.
	// Any nonempty value excludes platform administrators.
	Type string
	// Parent filters like ListTenantScopesInput.Parent: "" all, "none"
	// platform customers, else a reseller scope UUID (its customers).
	Parent string
}

type UserList struct {
	Items []ManagedUser `json:"items"`
	Page  int           `json:"page"`
	Limit int           `json:"limit"`
	Total int64         `json:"total"`
}

type UserFields struct {
	DisplayName string
	Email       string
	Phone       string
}

type CreateUserInput struct {
	Username       string
	Password       string
	Fields         UserFields
	Role           string
	GroupID        *uuid.UUID
	IdempotencyKey string
	RequestID      string
	Remark         *string
	QQ             *string
}

type UpdateUserInput struct {
	ID               uuid.UUID
	ExpectedRevision int64
	Fields           UserFields
	Status           string
	Role             string
	GroupID          *uuid.UUID
	GroupSet         bool
	IdempotencyKey   string
	RequestID        string
	Remark           *string
	QQ               *string
}

// DeleteUserInput permanently revokes a managed user's access while retaining
// the immutable user and audit facts for operators. Deletion is guarded by the
// current user revision and an idempotent request identity.
type DeleteUserInput struct {
	ID               uuid.UUID
	ExpectedRevision int64
	IdempotencyKey   string
	RequestID        string
}

type ResetManagedUserPasswordInput struct {
	ID               uuid.UUID
	TenantScopeID    uuid.UUID
	ExpectedRevision int64
	NewPassword      string
	StepUpToken      string
	IdempotencyKey   string
	RequestID        string
}

type BatchUpdateUserItem struct {
	ID               uuid.UUID  `json:"id"`
	ExpectedRevision int64      `json:"expected_revision"`
	Fields           UserFields `json:"fields"`
	Status           string     `json:"status"`
	Role             string     `json:"role"`
	GroupID          *uuid.UUID `json:"group_id,omitempty"`
	GroupSet         bool       `json:"-"`
	Remark           *string    `json:"remark,omitempty"`
	QQ               *string    `json:"qq,omitempty"`
}

type BatchUpdateUsersInput struct {
	Items          []BatchUpdateUserItem
	IdempotencyKey string
	RequestID      string
}

type BatchUpdateUsersResult struct {
	Items []ManagedUser `json:"items"`
}

type UserGroup struct {
	ID          uuid.UUID `json:"id"`
	ScopeID     uuid.UUID `json:"scope_id"`
	Name        string    `json:"name"`
	Revision    int64     `json:"revision"`
	MemberCount int64     `json:"member_count"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type UserGroupList struct {
	Items []UserGroup `json:"items"`
	Page  int         `json:"page"`
	Limit int         `json:"limit"`
	Total int64       `json:"total"`
}

type ListUserGroupsInput struct {
	Page   int
	Limit  int
	Search string
}

type CreateUserGroupInput struct {
	Name           string
	IdempotencyKey string
	RequestID      string
}

type UpdateUserGroupInput struct {
	ID               uuid.UUID
	ExpectedRevision int64
	Name             string
	IdempotencyKey   string
	RequestID        string
}

type DeleteUserGroupInput struct {
	ID               uuid.UUID
	ExpectedRevision int64
	IdempotencyKey   string
	RequestID        string
}

type UpdateProfileInput struct {
	ExpectedRevision int64
	Fields           UserFields
	CurrentPassword  string              `json:"-"`
	Credential       *PasswordCredential `json:"-"`
	IdempotencyKey   string
	RequestID        string
}

type ChangePasswordInput struct {
	CurrentPassword string
	NewPassword     string
	RequestID       string
}

type createUserRecord struct {
	CreateUserInput
	UserID       uuid.UUID
	TenantID     uuid.UUID
	ScopeID      uuid.UUID
	OwnerRoleID  uuid.UUID
	ViewerRoleID uuid.UUID
	PasswordHash string
	Digest       [32]byte
	// ParentScopeID: a reseller opens the tenant as its customer (ADR 0018 RS-05).
	ParentScopeID *uuid.UUID
}

func (s *Service) ListUsers(ctx context.Context, actor Actor, input ListUsersInput) (UserList, error) {
	for _, field := range []*string{&input.Username, &input.DisplayName, &input.Email, &input.Phone} {
		if !validUserMetadataText(*field, 128, false) {
			return UserList{}, ErrInvalidUserInput
		}
		*field = strings.TrimSpace(*field)
	}
	if !validAdminActor(actor) || input.Page < 1 || input.Page > 1_000_000 || input.Limit < 1 || input.Limit > 100 ||
		(input.DisplayID != "" && !displayIDPattern.MatchString(input.DisplayID)) ||
		utf8.RuneCountInString(input.Search) > 128 || (input.Status != "" && !validUserStatus(input.Status)) ||
		(input.Role != "" && !validManagedUserRole(input.Role)) ||
		(input.RealNameStatus != "" && input.RealNameStatus != "verified" && input.RealNameStatus != "unverified") ||
		!validUserMetadataText(input.Remark, 512, true) || !validUserMetadataText(input.QQ, 32, false) ||
		!validUserTypeFilter(input.Type) || !validParentFilter(input.Parent) {
		return UserList{}, ErrInvalidUserInput
	}
	input.Search = strings.TrimSpace(input.Search)
	input.Remark, input.QQ = strings.TrimSpace(input.Remark), strings.TrimSpace(input.QQ)
	return s.store.ListManagedUsers(ctx, input)
}

func validUserTypeFilter(value string) bool {
	return value == "" || value == "reseller" || value == "customer" || value == "direct"
}

func (s *Service) ListUserGroups(ctx context.Context, actor Actor, input ListUserGroupsInput) (UserGroupList, error) {
	input.Search = strings.TrimSpace(input.Search)
	if !validAdminActor(actor) || input.Page < 1 || input.Page > 1_000_000 || input.Limit < 1 || input.Limit > 100 ||
		utf8.RuneCountInString(input.Search) > 128 {
		return UserGroupList{}, ErrInvalidUserInput
	}
	return s.store.ListUserGroups(ctx, actor, input)
}

func (s *Service) CreateUserGroup(ctx context.Context, actor Actor, input CreateUserGroupInput) (UserGroup, error) {
	input.Name = strings.TrimSpace(input.Name)
	if !validAdminActor(actor) || !validWriteMetadata(input.IdempotencyKey, input.RequestID) {
		return UserGroup{}, ErrInvalidUserInput
	}
	if err := userGroupNameField(input.Name); err != nil {
		return UserGroup{}, err
	}
	digest, err := digestIdentityRequest(struct {
		Name string `json:"name"`
	}{input.Name})
	if err != nil {
		return UserGroup{}, err
	}
	return s.store.CreateUserGroup(ctx, actor, input, digest)
}

func (s *Service) UpdateUserGroup(ctx context.Context, actor Actor, input UpdateUserGroupInput) (UserGroup, error) {
	input.Name = strings.TrimSpace(input.Name)
	if !validAdminActor(actor) || input.ID == uuid.Nil || input.ExpectedRevision < 1 ||
		!validWriteMetadata(input.IdempotencyKey, input.RequestID) {
		return UserGroup{}, ErrInvalidUserInput
	}
	if err := userGroupNameField(input.Name); err != nil {
		return UserGroup{}, err
	}
	digest, err := digestIdentityRequest(struct {
		ID               uuid.UUID `json:"id"`
		ExpectedRevision int64     `json:"expected_revision"`
		Name             string    `json:"name"`
	}{input.ID, input.ExpectedRevision, input.Name})
	if err != nil {
		return UserGroup{}, err
	}
	return s.store.UpdateUserGroup(ctx, actor, input, digest)
}

func (s *Service) DeleteUserGroup(ctx context.Context, actor Actor, input DeleteUserGroupInput) error {
	if !validAdminActor(actor) || input.ID == uuid.Nil || input.ExpectedRevision < 1 ||
		!validWriteMetadata(input.IdempotencyKey, input.RequestID) {
		return ErrInvalidUserInput
	}
	digest, err := digestIdentityRequest(struct {
		ID               uuid.UUID `json:"id"`
		ExpectedRevision int64     `json:"expected_revision"`
	}{input.ID, input.ExpectedRevision})
	if err != nil {
		return err
	}
	return s.store.DeleteUserGroup(ctx, actor, input, digest)
}

func (s *Service) GetUser(ctx context.Context, actor Actor, id uuid.UUID) (ManagedUser, error) {
	if !validAdminActor(actor) || id == uuid.Nil {
		return ManagedUser{}, ErrInvalidUserInput
	}
	return s.store.GetManagedUser(ctx, id)
}

func (s *Service) CreateUser(ctx context.Context, actor Actor, input CreateUserInput) (ManagedUser, error) {
	input.Username = strings.ToLower(strings.TrimSpace(input.Username))
	if !validAdminActor(actor) || !validWriteMetadata(input.IdempotencyKey, input.RequestID) {
		return ManagedUser{}, ErrInvalidUserInput
	}
	if err := usernameField(input.Username); err != nil {
		return ManagedUser{}, err
	}
	if !validUserRole(input.Role) {
		return ManagedUser{}, invalidUserField("role", fielderr.Invalid)
	}
	if err := normalizeUserMetadata(input.Remark, input.QQ); err != nil {
		return ManagedUser{}, err
	}
	if err := CheckNewPassword(input.Password); err != nil {
		return ManagedUser{}, err
	}
	if err := s.normalizeUserFieldsFor(ctx, actor, &input.Fields); err != nil {
		return ManagedUser{}, err
	}
	passwordHash, err := HashPassword(input.Password)
	if err != nil {
		return ManagedUser{}, ErrInvalidUserInput
	}
	digest, err := digestIdentityRequest(struct {
		Username string     `json:"username"`
		Fields   UserFields `json:"fields"`
		Role     string     `json:"role"`
		GroupID  *uuid.UUID `json:"group_id,omitempty"`
		Remark   *string    `json:"remark,omitempty"`
		QQ       *string    `json:"qq,omitempty"`
	}{input.Username, input.Fields, input.Role, input.GroupID, input.Remark, input.QQ})
	if err != nil {
		return ManagedUser{}, err
	}
	ids := make([]uuid.UUID, 5)
	for index := range ids {
		ids[index], err = newUUID()
		if err != nil {
			return ManagedUser{}, err
		}
	}
	return s.store.CreateManagedUser(ctx, actor, createUserRecord{
		CreateUserInput: input,
		UserID:          ids[0], TenantID: ids[1], ScopeID: ids[2], OwnerRoleID: ids[3], ViewerRoleID: ids[4],
		PasswordHash: passwordHash, Digest: digest,
	})
}

func (s *Service) UpdateUser(ctx context.Context, actor Actor, input UpdateUserInput) (ManagedUser, error) {
	if !validAdminActor(actor) || input.ID == uuid.Nil || input.ExpectedRevision < 1 ||
		!validWriteMetadata(input.IdempotencyKey, input.RequestID) {
		return ManagedUser{}, ErrInvalidUserInput
	}
	if !validUserStatus(input.Status) {
		return ManagedUser{}, invalidUserField("status", fielderr.Invalid)
	}
	if !validManagedUserRole(input.Role) {
		return ManagedUser{}, invalidUserField("role", fielderr.Invalid)
	}
	if err := normalizeUserMetadata(input.Remark, input.QQ); err != nil {
		return ManagedUser{}, err
	}
	if err := s.normalizeUserFieldsFor(ctx, actor, &input.Fields); err != nil {
		return ManagedUser{}, err
	}
	digest, err := digestIdentityRequest(struct {
		ID               uuid.UUID  `json:"id"`
		ExpectedRevision int64      `json:"expected_revision"`
		Fields           UserFields `json:"fields"`
		Status           string     `json:"status"`
		Role             string     `json:"role"`
		GroupID          *uuid.UUID `json:"group_id,omitempty"`
		GroupSet         bool       `json:"group_set,omitempty"`
		Remark           *string    `json:"remark,omitempty"`
		QQ               *string    `json:"qq,omitempty"`
	}{input.ID, input.ExpectedRevision, input.Fields, input.Status, input.Role, input.GroupID, input.GroupSet, input.Remark, input.QQ})
	if err != nil {
		return ManagedUser{}, err
	}
	return s.store.UpdateManagedUser(ctx, actor, input, digest)
}

func (s *Service) DeleteUser(ctx context.Context, actor Actor, input DeleteUserInput) error {
	if !validAdminActor(actor) || input.ID == uuid.Nil || input.ExpectedRevision < 1 ||
		!validWriteMetadata(input.IdempotencyKey, input.RequestID) {
		return ErrInvalidUserInput
	}
	digest, err := digestIdentityRequest(struct {
		ID               uuid.UUID `json:"id"`
		ExpectedRevision int64     `json:"expected_revision"`
	}{input.ID, input.ExpectedRevision})
	if err != nil {
		return err
	}
	return s.store.DeleteManagedUser(ctx, actor, input, digest)
}

func (s *Service) BatchUpdateUsers(
	ctx context.Context,
	actor Actor,
	input BatchUpdateUsersInput,
) (BatchUpdateUsersResult, error) {
	if !validAdminActor(actor) || len(input.Items) < 1 || len(input.Items) > 100 ||
		!validWriteMetadata(input.IdempotencyKey, input.RequestID) {
		return BatchUpdateUsersResult{}, ErrInvalidUserInput
	}
	seen := make(map[uuid.UUID]struct{}, len(input.Items))
	for index := range input.Items {
		item := &input.Items[index]
		if item.ID == uuid.Nil || item.ExpectedRevision < 1 || !validUserStatus(item.Status) ||
			!validManagedUserRole(item.Role) || normalizeUserMetadata(item.Remark, item.QQ) != nil {
			return BatchUpdateUsersResult{}, ErrInvalidUserInput
		}
		if err := s.normalizeUserFieldsFor(ctx, actor, &item.Fields); err != nil {
			return BatchUpdateUsersResult{}, err
		}
		if _, duplicate := seen[item.ID]; duplicate {
			return BatchUpdateUsersResult{}, ErrInvalidUserInput
		}
		seen[item.ID] = struct{}{}
	}
	digest, err := digestIdentityRequest(input.Items)
	if err != nil {
		return BatchUpdateUsersResult{}, err
	}
	return s.store.BatchUpdateManagedUsers(ctx, actor, input, digest)
}

func (s *Service) GetProfile(ctx context.Context, actor Actor) (AccountProfile, error) {
	if !validSelfScopeActor(actor) {
		return AccountProfile{}, ErrPermissionDenied
	}
	return s.store.GetAccountProfile(ctx, actor)
}

func (s *Service) UpdateProfile(ctx context.Context, actor Actor, input UpdateProfileInput) (AccountProfile, error) {
	if !validSelfScopeActor(actor) || input.ExpectedRevision < 1 ||
		len(input.CurrentPassword) > 1024 || !validWriteMetadata(input.IdempotencyKey, input.RequestID) {
		return AccountProfile{}, ErrInvalidUserInput
	}
	if err := s.normalizeUserFieldsFor(ctx, actor, &input.Fields); err != nil {
		return AccountProfile{}, err
	}
	current, err := s.store.GetAccountProfile(ctx, actor)
	if err != nil {
		return AccountProfile{}, err
	}
	currentEmail, currentPhone := "", ""
	if current.Email != nil {
		currentEmail = *current.Email
	}
	if current.Phone != nil {
		currentPhone = *current.Phone
	}
	if input.Fields.Email != currentEmail || input.Fields.Phone != currentPhone {
		if input.CurrentPassword == "" {
			return AccountProfile{}, ErrInvalidCredentials
		}
		credential, credentialErr := s.store.PasswordCredential(ctx, actor)
		if credentialErr != nil {
			return AccountProfile{}, credentialErr
		}
		if !VerifyPassword(credential.PasswordHash, input.CurrentPassword) {
			return AccountProfile{}, ErrInvalidCredentials
		}
		input.Credential = &credential
		input.CurrentPassword = ""
	}
	digest, err := digestIdentityRequest(struct {
		ExpectedRevision int64      `json:"expected_revision"`
		Fields           UserFields `json:"fields"`
	}{input.ExpectedRevision, input.Fields})
	if err != nil {
		return AccountProfile{}, err
	}
	return s.store.UpdateAccountProfile(ctx, actor, input, digest)
}

func (s *Service) ChangePassword(ctx context.Context, actor Actor, input ChangePasswordInput) error {
	if !validSelfScopeActor(actor) || strings.TrimSpace(input.RequestID) == "" {
		return ErrInvalidUserInput
	}
	if len(input.CurrentPassword) == 0 {
		return invalidUserField("current_password", fielderr.Required)
	}
	if len(input.CurrentPassword) > 1024 {
		return invalidUserField("current_password", fielderr.TooLong)
	}
	if err := CheckNewPassword(input.NewPassword); err != nil {
		return err
	}
	credential, err := s.store.PasswordCredential(ctx, actor)
	if err != nil {
		return err
	}
	if !VerifyPassword(credential.PasswordHash, input.CurrentPassword) {
		return ErrInvalidCredentials
	}
	if VerifyPassword(credential.PasswordHash, input.NewPassword) {
		return invalidUserField("new_password", fielderr.Invalid) // the same as the current one
	}
	newHash, err := HashPassword(input.NewPassword)
	if err != nil {
		return ErrInvalidUserInput
	}
	return s.store.ChangePassword(ctx, actor, credential, newHash, input.RequestID)
}

// normalizeUserFieldsFor completes a bare phone number with the platform
// default calling code (FX38) before validating the fields.
func (s *Service) normalizeUserFieldsFor(ctx context.Context, actor Actor, fields *UserFields) error {
	var reader systemusersettings.PublicSettingsReader
	if s.publicSettings != nil {
		reader = s.publicSettings
	}
	phoneCode, err := systemusersettings.PhoneCountryCode(ctx, reader, actor.ScopeID, fields.Phone)
	if err != nil {
		return fmt.Errorf("load default phone country code: %w", err)
	}
	return normalizeUserFields(fields, phoneCode)
}

// invalidUserField is ErrInvalidUserInput naming the refused user request field
// (fix-fielderr-be; the user, profile and user group bodies are flat).
func invalidUserField(field, reason string) error {
	return fielderr.New(ErrInvalidUserInput, field, reason)
}

func usernameField(value string) error {
	switch {
	case value == "":
		return invalidUserField("username", fielderr.Required)
	case len(value) < 3:
		return invalidUserField("username", fielderr.TooShort)
	case len(value) > 128:
		return invalidUserField("username", fielderr.TooLong)
	case !validUsername(value):
		return invalidUserField("username", fielderr.InvalidFormat)
	}
	return nil
}

func userGroupNameField(value string) error {
	switch {
	case value == "":
		return invalidUserField("name", fielderr.Required)
	case utf8.RuneCountInString(value) > 128:
		return invalidUserField("name", fielderr.TooLong)
	case !validUserGroupName(value):
		return invalidUserField("name", fielderr.InvalidFormat)
	}
	return nil
}

func normalizeUserFields(fields *UserFields, phoneCode string) error {
	fields.DisplayName = strings.TrimSpace(fields.DisplayName)
	if utf8.RuneCountInString(fields.DisplayName) < 1 {
		return invalidUserField("display_name", fielderr.Required)
	}
	if utf8.RuneCountInString(fields.DisplayName) > 128 {
		return invalidUserField("display_name", fielderr.TooLong)
	}
	fields.Email = strings.ToLower(strings.TrimSpace(fields.Email))
	if fields.Email != "" {
		address, err := mail.ParseAddress(fields.Email)
		if err != nil || address.Address != fields.Email || len(fields.Email) > 254 {
			return invalidUserField("email", fielderr.InvalidFormat)
		}
	}
	fields.Phone = strings.TrimSpace(fields.Phone)
	if fields.Phone != "" {
		phone, err := phonenumber.Normalize(fields.Phone, phoneCode)
		if err != nil {
			return invalidUserField("phone", fielderr.InvalidFormat)
		}
		fields.Phone = phone
	}
	return nil
}

func validUsername(value string) bool {
	return len(value) >= 3 && len(value) <= 128 && usernamePattern.MatchString(value)
}

func validUserStatus(value string) bool {
	return value == UserStatusActive || value == UserStatusDisabled
}

func validUserRole(value string) bool {
	return value == UserRoleOwner || value == UserRoleViewer
}

func validPlatformUserRole(value string) bool {
	return value == UserRolePlatformOwner || value == UserRolePlatformAdmin
}

// validManagedUserRole accepts every role the managed user list projects. The
// store still pins each target to the role family of its own scope.
func validManagedUserRole(value string) bool {
	return validUserRole(value) || validPlatformUserRole(value)
}

func validUserGroupName(value string) bool {
	return value != "" && value == strings.TrimSpace(value) && utf8.RuneCountInString(value) <= 128 &&
		strings.IndexFunc(value, unicode.IsControl) == -1
}

func validAdminActor(actor Actor) bool {
	return actor.UserID != uuid.Nil && actor.ScopeID != uuid.Nil && actor.ScopeKind == "platform"
}

func validTenantActor(actor Actor) bool {
	return actor.UserID != uuid.Nil && actor.ScopeID != uuid.Nil && actor.ScopeKind == "tenant"
}

// validSelfScopeActor widens validTenantActor for the self-service account endpoints:
// a platform-scope administrator reads and edits its own profile, not another scope's.
func validSelfScopeActor(actor Actor) bool {
	return validTenantActor(actor) || validAdminActor(actor)
}

func validWriteMetadata(key, requestID string) bool {
	return idempotencyPattern.MatchString(key) && strings.TrimSpace(requestID) != ""
}

func digestIdentityRequest(value any) ([32]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

func normalizeUserMetadata(remark, qq *string) error {
	if remark != nil {
		if !validUserMetadataText(*remark, 512, true) {
			return metadataField("remark", *remark, 512)
		}
		*remark = strings.TrimSpace(*remark)
	}
	if qq != nil {
		if !validUserMetadataText(*qq, 32, false) {
			return metadataField("qq", *qq, 32)
		}
		*qq = strings.TrimSpace(*qq)
	}
	return nil
}

func metadataField(field, value string, limit int) error {
	if utf8.ValidString(value) && utf8.RuneCountInString(strings.TrimSpace(value)) > limit {
		return invalidUserField(field, fielderr.TooLong)
	}
	return invalidUserField(field, fielderr.InvalidFormat)
}

func validUserMetadataText(value string, limit int, multiline bool) bool {
	return utf8.ValidString(value) && utf8.RuneCountInString(strings.TrimSpace(value)) <= limit && strings.IndexFunc(value, func(r rune) bool {
		return unicode.IsControl(r) && !(multiline && (r == '\t' || r == '\n' || r == '\r'))
	}) == -1
}
