package identity

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

// ConsumeCaptcha spends one built-in CAPTCHA (POST /v1/auth/login-captchas)
// outside the sign-in path: direct registration on an installation without
// an external human-verification service. Like the sign-in
// check, the CAPTCHA is bound to its source and burned whether or not the
// answer matches, so it cannot be brute forced.
func (s *Service) ConsumeCaptcha(ctx context.Context, captcha LoginCaptchaProof, sourceIP string) error {
	if !s.loginThrottleEnabled() {
		return ErrLoginSecurityUnavailable
	}
	if captcha.ID == uuid.Nil || captcha.Answer == "" {
		return ErrLoginCaptchaInvalid
	}
	source, now := throttleSource(sourceIP), s.now().UTC()
	tag, err := s.store.pool.Exec(ctx, `UPDATE identity_login_captchas SET consumed_at=$4
		WHERE id=$1 AND consumed_at IS NULL AND expires_at > $4 AND source_ip=$3 AND answer_digest=$2`,
		captcha.ID, s.captchaDigest(captcha.ID, captcha.Answer), source, now)
	if err != nil {
		return fmt.Errorf("consume captcha: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	if _, err := s.store.pool.Exec(ctx, `UPDATE identity_login_captchas SET consumed_at=$2 WHERE id=$1 AND consumed_at IS NULL`,
		captcha.ID, now); err != nil {
		return fmt.Errorf("burn captcha: %w", err)
	}
	return ErrLoginCaptchaInvalid
}
