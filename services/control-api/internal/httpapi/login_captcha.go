package httpapi

import (
	"encoding/base64"
	"errors"
	"net/http"
	"regexp"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/logincaptcha"
	"github.com/google/uuid"
)

// Built-in sign-in CAPTCHA (identity login throttle): the browser asks for a
// challenge after login_captcha_required and sends {id, answer} back with the
// next password attempt. The answer is never stored or returned as text.

var loginCaptchaAnswerPattern = regexp.MustCompile(`^[A-Za-z0-9]{1,8}$`)

type loginCaptchaRequest struct {
	ID     string `json:"id"`
	Answer string `json:"answer"`
}

type loginCaptchaResponse struct {
	ID        uuid.UUID `json:"id"`
	Image     string    `json:"image"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (s *Server) handleIssueLoginCaptcha(w http.ResponseWriter, r *http.Request) {
	if s.identity == nil {
		s.writeAPIError(w, r, http.StatusServiceUnavailable, "login_security_unavailable", "login security is unavailable")
		return
	}
	captcha, err := s.identity.IssueLoginCaptcha(r.Context(), s.requestInfo(r).SourceIP)
	if err != nil {
		if errors.Is(err, identity.ErrLoginCaptchaRateLimited) {
			w.Header().Set("Retry-After", "3600")
		}
		if !s.writeLoginSecurityError(w, r, err) {
			s.writeAPIError(w, r, http.StatusServiceUnavailable, "login_security_unavailable", "login security is unavailable")
		}
		return
	}
	image, err := logincaptcha.RenderPNG(captcha.Answer)
	if err != nil {
		s.writeAPIError(w, r, http.StatusServiceUnavailable, "login_security_unavailable", "login security is unavailable")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSONStatus(w, http.StatusCreated, loginCaptchaResponse{
		ID: captcha.ID, Image: "data:image/png;base64," + base64.StdEncoding.EncodeToString(image),
		ExpiresAt: captcha.ExpiresAt.UTC(),
	})
}

// loginCaptchaProof validates the optional captcha field of a password login.
func (s *Server) loginCaptchaProof(w http.ResponseWriter, r *http.Request, body *loginCaptchaRequest) (*identity.LoginCaptchaProof, bool) {
	if body == nil {
		return nil, true
	}
	id, err := uuid.Parse(body.ID)
	if err != nil || id == uuid.Nil || id.String() != body.ID || !loginCaptchaAnswerPattern.MatchString(body.Answer) {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "captcha is invalid")
		return nil, false
	}
	return &identity.LoginCaptchaProof{ID: id, Answer: body.Answer}, true
}
