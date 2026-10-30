package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

type nullableTextField struct {
	Set   bool
	Value string
}

func (f *nullableTextField) UnmarshalJSON(encoded []byte) error {
	f.Set = true
	if bytes.Equal(encoded, []byte("null")) {
		f.Value = ""
		return nil
	}
	return json.Unmarshal(encoded, &f.Value)
}

type createManagedUserRequest struct {
	Username    string            `json:"username"`
	Password    string            `json:"password"`
	DisplayName string            `json:"display_name"`
	Email       nullableTextField `json:"email"`
	Phone       nullableTextField `json:"phone"`
	Role        string            `json:"role"`
	GroupID     nullableTextField `json:"group_id"`
	Remark      nullableTextField `json:"remark"`
	QQ          nullableTextField `json:"qq"`
}

type updateManagedUserRequest struct {
	ExpectedRevision int64                        `json:"expected_revision"`
	DisplayName      string                       `json:"display_name"`
	Email            nullableTextField            `json:"email"`
	Phone            nullableTextField            `json:"phone"`
	Status           string                       `json:"status"`
	Role             string                       `json:"role"`
	GroupID          nullableTextField            `json:"group_id"`
	PasswordReset    *managedPasswordResetRequest `json:"password_reset"`
	Remark           nullableTextField            `json:"remark"`
	QQ               nullableTextField            `json:"qq"`
}

type managedPasswordResetRequest struct {
	TenantScopeID string `json:"tenant_scope_id"`
	NewPassword   string `json:"new_password"`
	StepUpToken   string `json:"step_up_token"`
}

type batchUpdateManagedUserRequest struct {
	ID               string            `json:"id"`
	ExpectedRevision int64             `json:"expected_revision"`
	DisplayName      string            `json:"display_name"`
	Email            nullableTextField `json:"email"`
	Phone            nullableTextField `json:"phone"`
	Status           string            `json:"status"`
	Role             string            `json:"role"`
	GroupID          nullableTextField `json:"group_id"`
	Remark           nullableTextField `json:"remark"`
	QQ               nullableTextField `json:"qq"`
}

type createUserGroupRequest struct {
	Name string `json:"name"`
}

type updateUserGroupRequest struct {
	ExpectedRevision int64  `json:"expected_revision"`
	Name             string `json:"name"`
}

type deleteUserGroupRequest struct {
	ExpectedRevision int64 `json:"expected_revision"`
}

type deleteManagedUserRequest struct {
	ExpectedRevision int64 `json:"expected_revision"`
}

type updateAccountProfileRequest struct {
	ExpectedRevision int64             `json:"expected_revision"`
	DisplayName      string            `json:"display_name"`
	Email            nullableTextField `json:"email"`
	Phone            nullableTextField `json:"phone"`
	CurrentPassword  string            `json:"current_password"`
}

type changeAccountPasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

func (s *Server) handleListManagedUsers(w http.ResponseWriter, r *http.Request) {
	includeMetadata, includeVerification, includePlatformAdmins, includeReseller, valid := s.userListProjection(w, r)
	if !valid {
		return
	}
	principal, ok := s.requireUserManager(w, r)
	if !ok {
		return
	}
	allowed := map[string]bool{"page": true, "limit": true, "display_id": true, "search": true, "status": true, "role": true, "group_id": true, "include": true, "remark": true, "qq": true, "username": true, "display_name": true, "email": true, "phone": true, "real_name_status": true, "type": true, "parent": true}
	for key, values := range r.URL.Query() {
		if !allowed[key] || len(values) != 1 {
			s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "query parameters are invalid")
			return
		}
	}
	if r.URL.Query().Has("real_name_status") && r.URL.Query().Get("real_name_status") == "" {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "real name status is invalid")
		return
	}
	page, err := positiveQueryInt(r, "page", 1)
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "page must be a positive integer")
		return
	}
	limit, err := positiveQueryInt(r, "limit", 20)
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "limit must be a positive integer")
		return
	}
	groupID, valid := optionalIdentityUserGroupUUID(bodylessNullableText(r.URL.Query().Get("group_id")))
	if !valid {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "group ID must be a UUID")
		return
	}
	result, err := s.identity.ListUsers(r.Context(), identityActor(principal), identity.ListUsersInput{
		Page: page, Limit: limit, DisplayID: r.URL.Query().Get("display_id"), Search: r.URL.Query().Get("search"),
		Status: r.URL.Query().Get("status"), Role: r.URL.Query().Get("role"), GroupID: groupID,
		Remark: r.URL.Query().Get("remark"), QQ: r.URL.Query().Get("qq"),
		Username: r.URL.Query().Get("username"), DisplayName: r.URL.Query().Get("display_name"),
		Email: r.URL.Query().Get("email"), Phone: r.URL.Query().Get("phone"),
		RealNameStatus: r.URL.Query().Get("real_name_status"), IncludeVerification: includeVerification,
		IncludePlatformAdmins: includePlatformAdmins, IncludeReseller: includeReseller,
		Type: r.URL.Query().Get("type"), Parent: r.URL.Query().Get("parent"),
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	for index := range result.Items {
		result.Items[index] = managedUserProjection(result.Items[index], includeMetadata)
	}
	writeJSON(w, http.StatusOK, result)
}

// userListProjection parses the list include tokens. platform_admins opts the
// management user list into platform-scope administrator rows; owner pickers
// that omit it keep receiving tenant users only. reseller adds the ADR 0018
// reseller projection (is_reseller, parent reseller scope and name).
func (s *Server) userListProjection(w http.ResponseWriter, r *http.Request) (bool, bool, bool, bool, bool) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	values, supplied := query["include"]
	if err != nil || (supplied && len(values) != 1) {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "query parameters are invalid")
		return false, false, false, false, false
	}
	if !supplied {
		return false, false, false, false, true
	}
	metadata, verification, platformAdmins, reseller := false, false, false, false
	for _, token := range strings.Split(values[0], ",") {
		switch {
		case token == "user_metadata" && !metadata:
			metadata = true
		case token == "user_verification" && !verification:
			verification = true
		case token == "platform_admins" && !platformAdmins:
			platformAdmins = true
		case token == "reseller" && !reseller:
			reseller = true
		default:
			s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "include is invalid")
			return false, false, false, false, false
		}
	}
	return metadata, verification, platformAdmins, reseller, true
}

func (s *Server) handleCreateManagedUser(w http.ResponseWriter, r *http.Request) {
	includeMetadata, valid := s.userMetadataProjection(w, r)
	if !valid {
		return
	}
	principal, ok := s.requireUserManager(w, r)
	if !ok {
		return
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return
	}
	var body createManagedUserRequest
	if err := decodeJSON(w, r, &body); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	groupID, valid := optionalIdentityUserGroupUUID(body.GroupID)
	if !valid {
		s.writeFieldError(w, r, "group_id", fielderr.InvalidFormat)
		return
	}
	result, err := s.identity.CreateUser(r.Context(), identityActor(principal), identity.CreateUserInput{
		Username: body.Username, Password: body.Password,
		Fields: identity.UserFields{DisplayName: body.DisplayName, Email: body.Email.Value, Phone: body.Phone.Value},
		Role:   body.Role, GroupID: groupID, IdempotencyKey: key, RequestID: requestID(r.Context()),
		Remark: body.Remark.optionalValue(), QQ: body.QQ.optionalValue(),
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSONStatus(w, http.StatusCreated, managedUserProjection(result, includeMetadata))
}

func (s *Server) handleBatchUpdateManagedUsers(w http.ResponseWriter, r *http.Request) {
	includeMetadata, valid := s.userMetadataProjection(w, r)
	if !valid {
		return
	}
	principal, ok := s.requireUserManager(w, r)
	if !ok {
		return
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return
	}
	var body []batchUpdateManagedUserRequest
	if err := decodeJSON(w, r, &body); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	input := identity.BatchUpdateUsersInput{
		Items:          make([]identity.BatchUpdateUserItem, 0, len(body)),
		IdempotencyKey: key,
		RequestID:      requestID(r.Context()),
	}
	for _, item := range body {
		id, err := uuid.Parse(item.ID)
		groupID, groupValid := optionalIdentityUserGroupUUID(item.GroupID)
		if err != nil || !item.Email.Set || !item.Phone.Set || !item.GroupID.Set || !groupValid {
			s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "batch user is invalid")
			return
		}
		input.Items = append(input.Items, identity.BatchUpdateUserItem{
			ID: id, ExpectedRevision: item.ExpectedRevision,
			Fields: identity.UserFields{DisplayName: item.DisplayName, Email: item.Email.Value, Phone: item.Phone.Value},
			Status: item.Status, Role: item.Role, GroupID: groupID, GroupSet: true,
			Remark: item.Remark.optionalValue(), QQ: item.QQ.optionalValue(),
		})
	}
	result, err := s.identity.BatchUpdateUsers(r.Context(), identityActor(principal), input)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	for index := range result.Items {
		result.Items[index] = managedUserProjection(result.Items[index], includeMetadata)
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleGetManagedUser(w http.ResponseWriter, r *http.Request) {
	includeMetadata, valid := s.userMetadataProjection(w, r)
	if !valid {
		return
	}
	principal, ok := s.requireUserManager(w, r)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "user ID must be a UUID")
		return
	}
	result, err := s.identity.GetUser(r.Context(), identityActor(principal), id)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, managedUserProjection(result, includeMetadata))
}

func (s *Server) handleUpdateManagedUser(w http.ResponseWriter, r *http.Request) {
	includeMetadata, valid := s.userMetadataProjection(w, r)
	if !valid {
		return
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "user ID must be a UUID")
		return
	}
	var body updateManagedUserRequest
	if err := decodeJSON(w, r, &body); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	if body.PasswordReset != nil {
		if body.DisplayName != "" || body.Email.Set || body.Phone.Set || body.Status != "" ||
			body.Role != "" || body.GroupID.Set || body.Remark.Set || body.QQ.Set {
			s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "password reset cannot be combined with user updates")
			return
		}
		tenantScopeID, parseErr := uuid.Parse(body.PasswordReset.TenantScopeID)
		if parseErr != nil || tenantScopeID == uuid.Nil {
			s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "tenant scope ID must be a UUID")
			return
		}
		session, authenticated := s.requireManagedPasswordResetSession(w, r)
		if !authenticated {
			return
		}
		result, resetErr := s.identity.ResetManagedUserPassword(r.Context(), identity.Actor{
			UserID: session.Principal.UserID, ScopeID: session.Principal.ScopeID,
			ScopeKind: session.Principal.ScopeKind, SessionID: session.SessionID,
		}, identity.ResetManagedUserPasswordInput{
			ID: id, TenantScopeID: tenantScopeID, ExpectedRevision: body.ExpectedRevision,
			NewPassword: body.PasswordReset.NewPassword, StepUpToken: body.PasswordReset.StepUpToken,
			IdempotencyKey: key, RequestID: requestID(r.Context()),
		})
		if resetErr != nil {
			s.writeManagedPasswordResetError(w, r, resetErr)
			return
		}
		writeJSON(w, http.StatusOK, managedUserProjection(result, includeMetadata))
		return
	}
	principal, ok := s.requireUserManager(w, r)
	if !ok {
		return
	}
	groupID, groupValid := optionalIdentityUserGroupUUID(body.GroupID)
	switch {
	case !body.Email.Set:
		s.writeFieldError(w, r, "email", fielderr.Required)
		return
	case !body.Phone.Set:
		s.writeFieldError(w, r, "phone", fielderr.Required)
		return
	case !groupValid:
		s.writeFieldError(w, r, "group_id", fielderr.InvalidFormat)
		return
	}
	result, err := s.identity.UpdateUser(r.Context(), identityActor(principal), identity.UpdateUserInput{
		ID: id, ExpectedRevision: body.ExpectedRevision,
		Fields: identity.UserFields{DisplayName: body.DisplayName, Email: body.Email.Value, Phone: body.Phone.Value},
		Status: body.Status, Role: body.Role, GroupID: groupID, GroupSet: body.GroupID.Set,
		Remark: body.Remark.optionalValue(), QQ: body.QQ.optionalValue(),
		IdempotencyKey: key, RequestID: requestID(r.Context()),
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, managedUserProjection(result, includeMetadata))
}

func (s *Server) handleDeleteManagedUser(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireUserManager(w, r)
	if !ok {
		return
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "user ID must be a UUID")
		return
	}
	var body deleteManagedUserRequest
	if err := decodeJSON(w, r, &body); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	if err := s.identity.DeleteUser(r.Context(), identityActor(principal), identity.DeleteUserInput{
		ID: id, ExpectedRevision: body.ExpectedRevision, IdempotencyKey: key, RequestID: requestID(r.Context()),
	}); err != nil {
		s.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) requireManagedPasswordResetSession(
	w http.ResponseWriter,
	r *http.Request,
) (identity.AuthenticatedSession, bool) {
	authorization := strings.TrimSpace(r.Header.Get("Authorization"))
	scheme, rawToken, found := strings.Cut(authorization, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(rawToken) == "" {
		s.writeError(w, r, identity.ErrInvalidSession)
		return identity.AuthenticatedSession{}, false
	}
	session, err := s.identity.AuthenticateSession(r.Context(), strings.TrimSpace(rawToken))
	if err == nil && session.Principal.ScopeKind != "platform" {
		err = identity.ErrPermissionDenied
	}
	if err == nil {
		err = identity.Authorize(session.Principal, "identity.users.manage")
	}
	if err != nil {
		s.writeError(w, r, err)
		return identity.AuthenticatedSession{}, false
	}
	return session, true
}

func (s *Server) writeManagedPasswordResetError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, identity.ErrManagedPasswordResetStepUpRequired):
		s.writeAPIError(w, r, http.StatusPreconditionRequired, "mfa_step_up_required", "a valid MFA step-up proof is required")
	case errors.Is(err, identity.ErrManagedPasswordResetUnavailable):
		s.writeAPIError(w, r, http.StatusServiceUnavailable, "managed_password_reset_unavailable", "managed password reset is unavailable")
	default:
		s.writeError(w, r, err)
	}
}

func (s *Server) handleListUserGroups(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireUserManager(w, r)
	if !ok {
		return
	}
	allowed := map[string]bool{"page": true, "limit": true, "search": true}
	for key, values := range r.URL.Query() {
		if !allowed[key] || len(values) != 1 {
			s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "query parameters are invalid")
			return
		}
	}
	page, err := positiveQueryInt(r, "page", 1)
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "page must be a positive integer")
		return
	}
	limit, err := positiveQueryInt(r, "limit", 20)
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "limit must be a positive integer")
		return
	}
	result, err := s.identity.ListUserGroups(r.Context(), identityActor(principal), identity.ListUserGroupsInput{
		Page: page, Limit: limit, Search: r.URL.Query().Get("search"),
	})
	if err != nil {
		s.writeUserGroupError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleCreateUserGroup(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireUserManager(w, r)
	if !ok {
		return
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return
	}
	var body createUserGroupRequest
	if err := decodeJSON(w, r, &body); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	result, err := s.identity.CreateUserGroup(r.Context(), identityActor(principal), identity.CreateUserGroupInput{
		Name: body.Name, IdempotencyKey: key, RequestID: requestID(r.Context()),
	})
	if err != nil {
		s.writeUserGroupError(w, r, err)
		return
	}
	writeJSONStatus(w, http.StatusCreated, result)
}

func (s *Server) handleUpdateUserGroup(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireUserManager(w, r)
	if !ok {
		return
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "group ID must be a UUID")
		return
	}
	var body updateUserGroupRequest
	if err := decodeJSON(w, r, &body); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	result, err := s.identity.UpdateUserGroup(r.Context(), identityActor(principal), identity.UpdateUserGroupInput{
		ID: id, ExpectedRevision: body.ExpectedRevision, Name: body.Name,
		IdempotencyKey: key, RequestID: requestID(r.Context()),
	})
	if err != nil {
		s.writeUserGroupError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleDeleteUserGroup(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireUserManager(w, r)
	if !ok {
		return
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "group ID must be a UUID")
		return
	}
	var body deleteUserGroupRequest
	if err := decodeJSON(w, r, &body); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	if err := s.identity.DeleteUserGroup(r.Context(), identityActor(principal), identity.DeleteUserGroupInput{
		ID: id, ExpectedRevision: body.ExpectedRevision, IdempotencyKey: key, RequestID: requestID(r.Context()),
	}); err != nil {
		s.writeUserGroupError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) writeUserGroupError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, identity.ErrUserGroupNotFound):
		s.writeAPIError(w, r, http.StatusNotFound, "user_group_not_found", "user group was not found")
	case errors.Is(err, identity.ErrUserGroupConflict):
		s.writeAPIError(w, r, http.StatusConflict, "user_group_name_conflict", "user group name already exists")
	case errors.Is(err, identity.ErrUserGroupInUse):
		s.writeAPIError(w, r, http.StatusConflict, "user_group_in_use", "user group still has members")
	default:
		s.writeError(w, r, err)
	}
}

func bodylessNullableText(value string) nullableTextField {
	return nullableTextField{Set: value != "", Value: value}
}

func optionalIdentityUserGroupUUID(field nullableTextField) (*uuid.UUID, bool) {
	if field.Value == "" {
		return nil, true
	}
	parsed, err := uuid.Parse(field.Value)
	if err != nil || parsed == uuid.Nil {
		return nil, false
	}
	return &parsed, true
}

func (s *Server) handleGetAccountProfile(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireTenantIdentity(w, r, "identity.self.read")
	if !ok {
		return
	}
	result, err := s.identity.GetProfile(r.Context(), identityActor(principal))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleUpdateAccountProfile(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireTenantIdentity(w, r, "identity.self.update")
	if !ok {
		return
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return
	}
	var body updateAccountProfileRequest
	if err := decodeJSON(w, r, &body); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	// 2026-09-19：联系方式按「部分更新」处理 —— 只有请求里显式出现的字段才被改写，
	// 未出现的字段沿用现值，避免省略 phone 时把已绑定的手机号清空。
	current, err := s.identity.GetProfile(r.Context(), identityActor(principal))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	fields := identity.UserFields{DisplayName: body.DisplayName}
	if current.Email != nil {
		fields.Email = *current.Email
	}
	if current.Phone != nil {
		fields.Phone = *current.Phone
	}
	if body.Email.Set {
		fields.Email = body.Email.Value
	}
	if body.Phone.Set {
		fields.Phone = body.Phone.Value
	}
	if !body.Email.Set && !body.Phone.Set && fields.DisplayName == current.DisplayName {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "no account field to update")
		return
	}
	result, err := s.identity.UpdateProfile(r.Context(), identityActor(principal), identity.UpdateProfileInput{
		ExpectedRevision: body.ExpectedRevision,
		Fields:           fields,
		CurrentPassword:  body.CurrentPassword,
		IdempotencyKey:   key, RequestID: requestID(r.Context()),
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleChangeAccountPassword(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireSelfSession(w, r, "identity.password.change")
	if !ok {
		return
	}
	var body changeAccountPasswordRequest
	if err := decodeJSON(w, r, &body); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	if err := s.identity.ChangePassword(r.Context(), identityActor(principal), identity.ChangePasswordInput{
		CurrentPassword: body.CurrentPassword, NewPassword: body.NewPassword, RequestID: requestID(r.Context()),
	}); err != nil {
		s.writeError(w, r, err)
		return
	}
	s.clearRefreshCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) requireUserManager(w http.ResponseWriter, r *http.Request) (identity.Principal, bool) {
	principal, err := s.authenticatedPrincipal(r)
	if err == nil && principal.ScopeKind != "platform" {
		err = identity.ErrPermissionDenied
	}
	if err == nil {
		err = identity.Authorize(principal, "identity.users.manage")
	}
	if err != nil {
		s.writeError(w, r, err)
		return identity.Principal{}, false
	}
	return principal, true
}

// platformScopeReadsOwnScope reports whether a platform-scope principal may use the
// self-service account endpoints. The platform scope has no tenant, so those endpoints
// treat it as the administrator's own account rather than a cross-tenant view.
func platformScopeReadsOwnScope(principal identity.Principal) bool {
	return principal.ScopeKind == "platform" && principal.TenantID == nil
}

func (s *Server) requireTenantIdentity(w http.ResponseWriter, r *http.Request, permission string) (identity.Principal, bool) {
	principal, err := s.authenticatedPrincipal(r)
	if err == nil && principal.ScopeKind != "tenant" && !platformScopeReadsOwnScope(principal) {
		err = identity.ErrPermissionDenied
	}
	if err == nil {
		err = identity.Authorize(principal, permission)
	}
	if err != nil {
		s.writeError(w, r, err)
		return identity.Principal{}, false
	}
	return principal, true
}

// requireSelfSession gates a browser-session-only change to the caller's own
// account (fp-role ID-04): a tenant session, or a platform administrator's own
// scope (no tenant). API keys are refused like requireSessionPermission.
func (s *Server) requireSelfSession(w http.ResponseWriter, r *http.Request, permission string) (identity.Principal, bool) {
	principal, err := s.authenticatedSessionPrincipal(r)
	if err == nil && principal.ScopeKind != "tenant" && !platformScopeReadsOwnScope(principal) {
		err = identity.ErrPermissionDenied
	}
	if err == nil {
		err = identity.Authorize(principal, permission)
	}
	if err != nil {
		s.writeError(w, r, err)
		return identity.Principal{}, false
	}
	return principal, true
}

func identityActor(principal identity.Principal) identity.Actor {
	return identity.Actor{UserID: principal.UserID, ScopeID: principal.ScopeID, ScopeKind: principal.ScopeKind}
}

func positiveQueryInt(r *http.Request, name string, fallback int) (int, error) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 1 {
		return 0, identity.ErrInvalidUserInput
	}
	return value, nil
}

func (field nullableTextField) optionalValue() *string {
	if !field.Set {
		return nil
	}
	return &field.Value
}

func (s *Server) userMetadataProjection(w http.ResponseWriter, r *http.Request) (bool, bool) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "query parameters are invalid")
		return false, false
	}
	values, supplied := query["include"]
	if !supplied {
		return false, true
	}
	if len(values) != 1 || values[0] != "user_metadata" {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "include must be user_metadata")
		return false, false
	}
	return true, true
}

func managedUserProjection(item identity.ManagedUser, includeMetadata bool) identity.ManagedUser {
	if !includeMetadata {
		item.Metadata = nil
	}
	return item
}
