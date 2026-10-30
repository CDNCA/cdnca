package accountloginchallengehttp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/accountloginchallenge"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

var captchaAnswerPattern = regexp.MustCompile(`^[A-Za-z0-9]{1,8}$`)

func (body *challengeBody) UnmarshalJSON(raw []byte) error {
	type fields challengeBody
	var value fields
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return err
	}
	var present map[string]json.RawMessage
	if err := json.Unmarshal(raw, &present); err != nil {
		return err
	}
	passwordShape := present["username"] != nil || present["password"] != nil || present["scope_id"] != nil
	legacyShape := present["identifier"] != nil || present["channel"] != nil
	if present["captcha"] != nil && !passwordShape {
		return accountloginchallenge.ErrInvalidInput
	}
	if passwordShape && (legacyShape || value.Username == nil || value.Password == nil || (present["scope_id"] != nil && value.ScopeID == nil)) {
		return accountloginchallenge.ErrInvalidInput
	}
	*body = challengeBody(value)
	return nil
}

func (handler *Handler) servePasswordChallenge(writer http.ResponseWriter, request *http.Request, requestID, key string, body challengeBody) {
	if body.Username == nil || body.Password == nil || body.Identifier != nil || body.Channel != nil {
		handler.writeServiceError(writer, requestID, accountloginchallenge.ErrInvalidInput)
		return
	}
	var scopeID *uuid.UUID
	if body.ScopeID != nil {
		parsed, err := uuid.Parse(*body.ScopeID)
		if err != nil || parsed == uuid.Nil || parsed.String() != *body.ScopeID {
			handler.writeServiceError(writer, requestID, accountloginchallenge.ErrInvalidInput)
			return
		}
		scopeID = &parsed
	}
	var captcha *identity.LoginCaptchaProof
	if body.Captcha != nil {
		id, err := uuid.Parse(body.Captcha.ID)
		if err != nil || id == uuid.Nil || id.String() != body.Captcha.ID || !captchaAnswerPattern.MatchString(body.Captcha.Answer) {
			handler.writeServiceError(writer, requestID, accountloginchallenge.ErrInvalidInput)
			return
		}
		captcha = &identity.LoginCaptchaProof{ID: id, Answer: body.Captcha.Answer}
	}
	creator, ok := handler.service.(interface {
		CreatePassword(context.Context, accountloginchallenge.PasswordCreateInput) (accountloginchallenge.CreateResult, error)
	})
	if !ok || handler.config.SourceIPResolver == nil {
		handler.writeServiceError(writer, requestID, accountloginchallenge.ErrUnavailable)
		return
	}
	source, err := handler.config.SourceIPResolver.ResolveSourceIP(request)
	if err != nil {
		handler.writeServiceError(writer, requestID, identity.ErrLoginSourceDenied)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), handler.config.Timeout)
	defer cancel()
	result, err := creator.CreatePassword(ctx, accountloginchallenge.PasswordCreateInput{
		Login:   identity.LoginInput{Username: *body.Username, Password: *body.Password, ScopeID: scopeID, Captcha: captcha},
		Request: identity.RequestInfo{RequestID: requestID, UserAgent: request.UserAgent(), SourceIP: source.Unmap().String()},
		Source:  source.Unmap().String(), HumanToken: body.HumanToken, IdempotencyKey: key, RequestID: requestID,
	})
	if err != nil {
		handler.writeServiceError(writer, requestID, err)
		return
	}
	handler.writeJSON(writer, http.StatusAccepted, map[string]any{"data": map[string]any{
		"accepted": true, "challenge_id": result.ChallengeID, "expires_at": result.ExpiresAt.UTC().Format(time.RFC3339Nano), "replayed": result.Replayed,
	}})
}
