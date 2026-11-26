package httpapi

import (
	"context"
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
//
// the CAPTCHA is bound to the browser, not to the source
// address (behind a CDN without origin authentication issue and spend come
// from different edges). Issuing sets identity.LoginCaptchaBindingCookie,
// one value per browser reused by its later images;
// every spend (sign-in, password login challenges, POST /v1/auth/register,
// registration code challenges) passes it on. The browser sends it itself.

// identity.LoginCaptchaBindingCookie covers every /v1/auth route.
const loginCaptchaBindingPath = "/v1/auth"

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
	captcha, err := s.identity.IssueLoginCaptcha(r.Context(), s.requestInfo(r).SourceIP, loginCaptchaBinding(r))
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
	// The same browser binding is set again (reused),
	// now expiring with the newest CAPTCHA bound to it. A freshly minted one
	// also goes into this image's own cookie: another tab fetching its first
	// image at the same time mints another and may replace the browser cookie.
	names := []string{identity.LoginCaptchaBindingCookie}
	if captcha.Minted {
		names = append(names, identity.LoginCaptchaImageBindingCookie(captcha.ID))
	}
	for _, name := range names {
		http.SetCookie(w, &http.Cookie{
			Name: name, Value: captcha.Binding, Path: loginCaptchaBindingPath,
			Expires: captcha.ExpiresAt.UTC(), MaxAge: max(int(time.Until(captcha.ExpiresAt).Seconds()), 1),
			HttpOnly: true, Secure: s.cookieSecure, SameSite: http.SameSiteLaxMode,
		})
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
	return &identity.LoginCaptchaProof{ID: id, Answer: body.Answer, Binding: loginCaptchaBindingFor(r, id)}, true
}

// loginCaptchaBinding is the request's browser binding cookie, "" when absent.
func loginCaptchaBinding(r *http.Request) string {
	cookie, err := r.Cookie(identity.LoginCaptchaBindingCookie)
	if err != nil {
		return ""
	}
	return cookie.Value
}

// loginCaptchaBindingFor is the binding a spend of image id carries: the
// image's own cookie when its issue minted the browser binding, otherwise
// the browser cookie.
func loginCaptchaBindingFor(r *http.Request, id uuid.UUID) string {
	if cookie, err := r.Cookie(identity.LoginCaptchaImageBindingCookie(id)); err == nil {
		return cookie.Value
	}
	return loginCaptchaBinding(r)
}

// withLoginCaptchaBinding records the request's binding cookies for a
// CAPTCHA spent from a human token (accountregistrationchallenge.CaptchaHumanVerifier).
func withLoginCaptchaBinding(r *http.Request) context.Context {
	return identity.WithLoginCaptchaBinding(r.Context(), func(id uuid.UUID) string { return loginCaptchaBindingFor(r, id) })
}

// WithLoginCaptchaBinding passes the binding cookies to a CAPTCHA spent from a
// human token (accountregistrationchallenge.CaptchaHumanVerifier).
func WithLoginCaptchaBinding(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(withLoginCaptchaBinding(r)))
	})
}
