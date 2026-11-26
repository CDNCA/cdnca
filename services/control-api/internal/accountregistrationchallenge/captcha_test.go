package accountregistrationchallenge

import (
	"context"
	"errors"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/refusalreason"
	"github.com/google/uuid"
)

type captchaConsumerStub struct {
	err    error
	proofs []identity.LoginCaptchaProof
}

func (stub *captchaConsumerStub) ConsumeCaptcha(_ context.Context, proof identity.LoginCaptchaProof) error {
	stub.proofs = append(stub.proofs, proof)
	return stub.err
}

// built-in registration sends codes behind the image CAPTCHA.
func TestCaptchaHumanVerifier(t *testing.T) {
	good := CaptchaTokenPrefix + "22222222-2222-4222-8222-222222222222:AB2CD"
	stub := &captchaConsumerStub{}
	if err := (CaptchaHumanVerifier{Captcha: stub}).Verify(context.Background(), HumanVerification{Token: good, Source: "203.0.113.9"}); err != nil {
		t.Fatal(err)
	}
	if len(stub.proofs) != 1 || stub.proofs[0].Answer != "AB2CD" {
		t.Fatalf("consumed %#v", stub.proofs)
	}
	// the binding cookie the HTTP layer recorded goes with the proof
	stub = &captchaConsumerStub{}
	if err := (CaptchaHumanVerifier{Captcha: stub}).Verify(identity.WithLoginCaptchaBinding(context.Background(), func(uuid.UUID) string { return "browser-binding" }),
		HumanVerification{Token: good}); err != nil || len(stub.proofs) != 1 || stub.proofs[0].Binding != "browser-binding" {
		t.Fatalf("binding: err=%v consumed %#v", err, stub.proofs)
	}
	for _, token := range []string{"", "turnstile-token-000000000000", CaptchaTokenPrefix + "not-a-uuid:AB", CaptchaTokenPrefix + "22222222-2222-4222-8222-222222222222:"} {
		stub := &captchaConsumerStub{}
		if err := (CaptchaHumanVerifier{Captcha: stub}).Verify(context.Background(), HumanVerification{Token: token}); !errors.Is(err, ErrHumanInvalid) || len(stub.proofs) != 0 {
			t.Fatalf("token %q: err=%v consumed=%d", token, err, len(stub.proofs))
		}
	}
	if err := (CaptchaHumanVerifier{Captcha: &captchaConsumerStub{err: identity.ErrLoginCaptchaInvalid}}).Verify(context.Background(), HumanVerification{Token: good}); !errors.Is(err, ErrHumanInvalid) {
		t.Fatalf("wrong answer: %v", err)
	}
	if err := (CaptchaHumanVerifier{Captcha: &captchaConsumerStub{err: errors.New("db down")}}).Verify(context.Background(), HumanVerification{Token: good}); !errors.Is(err, ErrHumanUnavailable) {
		t.Fatalf("store failure: %v", err)
	}
}

// Problem 28: a refused CAPTCHA keeps the identity reason (or
// captcha_malformed) for the refusal log; the error stays ErrHumanInvalid.
func TestCaptchaHumanVerifierKeepsRefusalReason(t *testing.T) {
	good := CaptchaTokenPrefix + "22222222-2222-4222-8222-222222222222:AB2CD"
	for _, reason := range []string{
		identity.CaptchaReasonNotFound, identity.CaptchaReasonConsumed, identity.CaptchaReasonExpired,
		identity.CaptchaReasonBindingMismatch, identity.CaptchaReasonAnswerMismatch,
	} {
		stub := &captchaConsumerStub{err: refusalreason.Wrap(identity.ErrLoginCaptchaInvalid, reason)}
		err := (CaptchaHumanVerifier{Captcha: stub}).Verify(context.Background(), HumanVerification{Token: good})
		if !errors.Is(err, ErrHumanInvalid) || refusalreason.Of(err) != reason {
			t.Fatalf("%s: err=%v reason=%q", reason, err, refusalreason.Of(err))
		}
	}
	err := (CaptchaHumanVerifier{Captcha: &captchaConsumerStub{}}).Verify(context.Background(), HumanVerification{Token: CaptchaTokenPrefix + "x:"})
	if !errors.Is(err, ErrHumanInvalid) || refusalreason.Of(err) != HumanReasonCaptchaMalformed {
		t.Fatalf("malformed: err=%v reason=%q", err, refusalreason.Of(err))
	}
}
