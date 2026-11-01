//go:build integration

package identity_test

import (
	"errors"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

// builtin registration: built-in registration spends a sign-in CAPTCHA once, bound to
// its source; a wrong answer burns it too.
func TestConsumeCaptchaSpendsOnceForItsSource(t *testing.T) {
	fixture := seedThrottleFixture(t, 30, 3)
	issued, err := fixture.service.IssueLoginCaptcha(t.Context(), "203.0.113.9")
	if err != nil {
		t.Fatal(err)
	}
	proof := identity.LoginCaptchaProof{ID: issued.ID, Answer: issued.Answer}
	if err := fixture.service.ConsumeCaptcha(t.Context(), proof, "203.0.113.10"); !errors.Is(err, identity.ErrLoginCaptchaInvalid) {
		t.Fatalf("other source: %v", err)
	}
	if err := fixture.service.ConsumeCaptcha(t.Context(), proof, "203.0.113.9"); !errors.Is(err, identity.ErrLoginCaptchaInvalid) {
		t.Fatalf("burned by a wrong attempt must not be reusable: %v", err)
	}
	second, err := fixture.service.IssueLoginCaptcha(t.Context(), "203.0.113.9")
	if err != nil {
		t.Fatal(err)
	}
	good := identity.LoginCaptchaProof{ID: second.ID, Answer: second.Answer}
	if err := fixture.service.ConsumeCaptcha(t.Context(), good, "203.0.113.9"); err != nil {
		t.Fatalf("right answer: %v", err)
	}
	if err := fixture.service.ConsumeCaptcha(t.Context(), good, "203.0.113.9"); !errors.Is(err, identity.ErrLoginCaptchaInvalid) {
		t.Fatalf("second use: %v", err)
	}
	if err := fixture.service.ConsumeCaptcha(t.Context(), identity.LoginCaptchaProof{ID: uuid.New(), Answer: "AAAAA"}, "203.0.113.9"); !errors.Is(err, identity.ErrLoginCaptchaInvalid) {
		t.Fatalf("unknown id: %v", err)
	}
}
