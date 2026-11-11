package accountregistrationchallenge

import (
	"context"
	"errors"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
)

type captchaConsumerStub struct {
	err    error
	proofs []identity.LoginCaptchaProof
	source string
}

func (stub *captchaConsumerStub) ConsumeCaptcha(_ context.Context, proof identity.LoginCaptchaProof, source string) error {
	stub.proofs, stub.source = append(stub.proofs, proof), source
	return stub.err
}

// built-in registration sends codes behind the image CAPTCHA.
func TestCaptchaHumanVerifier(t *testing.T) {
	good := CaptchaTokenPrefix + "22222222-2222-4222-8222-222222222222:AB2CD"
	stub := &captchaConsumerStub{}
	if err := (CaptchaHumanVerifier{Captcha: stub}).Verify(context.Background(), HumanVerification{Token: good, Source: "203.0.113.9"}); err != nil {
		t.Fatal(err)
	}
	if len(stub.proofs) != 1 || stub.proofs[0].Answer != "AB2CD" || stub.source != "203.0.113.9" {
		t.Fatalf("consumed %#v from %q", stub.proofs, stub.source)
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
