package accountregistrationchallenge

import (
	"context"
	"errors"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

// without Turnstile the registration code is sent after
// the built-in image CAPTCHA (POST /v1/auth/login-captchas). The browser
// sends human_token = CaptchaTokenPrefix + "<captcha id>:<answer>"; the
// CAPTCHA is spent bound to the request source like the sign-in one.

const CaptchaTokenPrefix = "captcha:"

// CaptchaConsumer spends one built-in CAPTCHA (identity.Service).
type CaptchaConsumer interface {
	ConsumeCaptcha(context.Context, identity.LoginCaptchaProof, string) error
}

// CaptchaHumanVerifier is the HumanVerifier of built-in registration.
type CaptchaHumanVerifier struct {
	Captcha CaptchaConsumer
}

// ParseCaptchaToken splits a captcha human token; ok is false when malformed.
func ParseCaptchaToken(token string) (identity.LoginCaptchaProof, bool) {
	rest, found := strings.CutPrefix(token, CaptchaTokenPrefix)
	if !found {
		return identity.LoginCaptchaProof{}, false
	}
	idText, answer, found := strings.Cut(rest, ":")
	id, err := uuid.Parse(idText)
	if !found || err != nil || id == uuid.Nil || answer == "" || len(answer) > 32 {
		return identity.LoginCaptchaProof{}, false
	}
	return identity.LoginCaptchaProof{ID: id, Answer: answer}, true
}

func (verifier CaptchaHumanVerifier) Verify(ctx context.Context, verification HumanVerification) error {
	if verifier.Captcha == nil {
		return ErrHumanUnavailable
	}
	proof, ok := ParseCaptchaToken(verification.Token)
	if !ok {
		return ErrHumanInvalid
	}
	if err := verifier.Captcha.ConsumeCaptcha(ctx, proof, verification.Source); err != nil {
		if errors.Is(err, identity.ErrLoginCaptchaInvalid) {
			return ErrHumanInvalid
		}
		return ErrHumanUnavailable
	}
	return nil
}

var _ HumanVerifier = CaptchaHumanVerifier{}
