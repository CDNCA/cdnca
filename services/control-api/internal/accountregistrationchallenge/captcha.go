package accountregistrationchallenge

import (
	"context"
	"errors"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/refusalreason"
	"github.com/google/uuid"
)

// without Turnstile the registration code is sent after
// the built-in image CAPTCHA (POST /v1/auth/login-captchas). The browser
// sends human_token = CaptchaTokenPrefix + "<captcha id>:<answer>"; the
// CAPTCHA is spent with the browser binding cookie the HTTP layer recorded
// (httpapi.WithLoginCaptchaBinding) like the sign-in one.

const CaptchaTokenPrefix = "captcha:"

// Internal reasons for ErrHumanInvalid beyond the identity.CaptchaReason*
// ones; they reach only the "request refused" log line (problem 28).
const (
	HumanReasonCaptchaMalformed = "captcha_malformed"
	// HumanReasonRejectedReplay: the idempotency key was already rejected.
	HumanReasonRejectedReplay = "human_rejected_replay"
	// HumanReasonTokenReused: the same human token was already submitted.
	HumanReasonTokenReused = "human_token_reused"
	// HumanReasonWriteConflict: a parallel request with the same key won.
	HumanReasonWriteConflict = "human_write_conflict"
)

// CaptchaConsumer spends one built-in CAPTCHA (identity.Service).
type CaptchaConsumer interface {
	ConsumeCaptcha(context.Context, identity.LoginCaptchaProof) error
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
		return refusalreason.Wrap(ErrHumanInvalid, HumanReasonCaptchaMalformed)
	}
	proof.Binding = identity.LoginCaptchaBindingFrom(ctx, proof.ID)
	if err := verifier.Captcha.ConsumeCaptcha(ctx, proof); err != nil {
		if errors.Is(err, identity.ErrLoginCaptchaInvalid) {
			return refusalreason.Wrap(ErrHumanInvalid, refusalreason.Of(err))
		}
		return ErrHumanUnavailable
	}
	return nil
}

var _ HumanVerifier = CaptchaHumanVerifier{}
