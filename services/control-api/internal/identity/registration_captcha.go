package identity

import (
	"context"

	"github.com/cdnca/cdnca/services/control-api/internal/refusalreason"
	"github.com/google/uuid"
)

// ConsumeCaptcha spends one built-in CAPTCHA (POST /v1/auth/login-captchas)
// outside the sign-in path: direct registration on an installation without
// an external human-verification service. Like the sign-in
// check, the CAPTCHA is bound to its browser binding and burned whether or not the
// answer matches, so it cannot be brute forced. The request source is not a
// spend condition.
func (s *Service) ConsumeCaptcha(ctx context.Context, captcha LoginCaptchaProof) error {
	if !s.loginThrottleEnabled() {
		return ErrLoginSecurityUnavailable
	}
	if captcha.ID == uuid.Nil || captcha.Answer == "" {
		return refusalreason.Wrap(ErrLoginCaptchaInvalid, CaptchaReasonMissing)
	}
	return s.spendLoginCaptcha(ctx, s.store.pool, captcha, s.now().UTC())
}
