//go:build integration

package identity_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/refusalreason"
	"github.com/google/uuid"
)

// The built-in registration spends a sign-in
// CAPTCHA once, bound to the browser binding it was issued with, whatever
// source address the spend comes from (a CDN edge other than the issuing
// one); a refused attempt burns it too.
func TestConsumeCaptchaSpendsOnceForItsBinding(t *testing.T) {
	fixture := seedThrottleFixture(t, 30, 3)
	const issueEdge, spendEdge = "104.23.1.10", "162.159.2.20"
	issued := fixture.captcha(t, issueEdge)
	if len(issued.Binding) != 43 {
		t.Fatalf("binding = %q", issued.Binding)
	}
	var stored []byte
	var source string
	if err := fixture.pool.QueryRow(t.Context(), `SELECT binding_digest, source_ip FROM identity_login_captchas WHERE id=$1`,
		issued.ID).Scan(&stored, &source); err != nil {
		t.Fatal(err)
	}
	if len(stored) != 32 || string(stored) == issued.Binding || source != issueEdge {
		t.Fatalf("stored binding digest %x source %q", stored, source)
	}
	proof := identity.LoginCaptchaProof{ID: issued.ID, Answer: issued.Answer, Binding: issued.Binding}
	if err := fixture.service.ConsumeCaptcha(t.Context(), proof); err != nil {
		t.Fatalf("same browser, other edge: %v", err)
	}
	if err := fixture.service.ConsumeCaptcha(t.Context(), proof); !errors.Is(err, identity.ErrLoginCaptchaInvalid) {
		t.Fatalf("second use: %v", err)
	}
	if err := fixture.service.ConsumeCaptcha(t.Context(), identity.LoginCaptchaProof{ID: uuid.New(), Answer: "AAAAA", Binding: issued.Binding}); !errors.Is(err, identity.ErrLoginCaptchaInvalid) {
		t.Fatalf("unknown id: %v", err)
	}
}

// a CAPTCHA sent without its binding cookie, with the
// cookie of another CAPTCHA, or issued before migration 683 (no binding) is
// refused as captcha_binding_mismatch even from the issuing source, and is
// burned: the right binding afterwards finds it consumed.
// an image fetched with a binding this
// service signed reuses it (every tab of the browser keeps its image); an
// absent, forged or pre-change value gets a fresh one. Each image passes with
// the shared binding.
func TestLoginCaptchaReusesTheBrowserBinding(t *testing.T) {
	fixture := seedThrottleFixture(t, 30, 3)
	const source = "203.0.113.9"
	first := fixture.captcha(t, source)
	if len(first.Binding) != 43 {
		t.Fatalf("binding %q", first.Binding)
	}
	second, err := fixture.service.IssueLoginCaptcha(t.Context(), source, first.Binding)
	if err != nil || second.Binding != first.Binding {
		t.Fatalf("reuse: %q %v", second.Binding, err)
	}
	// tampered: one character of the MAC part changed (the last character
	// partly encodes padding bits, so a change there may decode the same)
	flip := map[bool]string{true: "B", false: "A"}[first.Binding[30] == 'A']
	tampered := first.Binding[:30] + flip + first.Binding[31:]
	for _, value := range []string{strings.Repeat("A", 43), "short", tampered} {
		fresh, err := fixture.service.IssueLoginCaptcha(t.Context(), source, value)
		if err != nil || fresh.Binding == value || fresh.Binding == first.Binding || len(fresh.Binding) != 43 {
			t.Fatalf("%q: got %q %v", value, fresh.Binding, err)
		}
	}
	for _, captcha := range []identity.LoginCaptcha{first, second} {
		if err := fixture.service.ConsumeCaptcha(t.Context(),
			identity.LoginCaptchaProof{ID: captcha.ID, Answer: captcha.Answer, Binding: first.Binding}); err != nil {
			t.Fatalf("spend %s with the shared binding: %v", captcha.ID, err)
		}
	}
}

func TestConsumeCaptchaRefusesAWrongBinding(t *testing.T) {
	fixture := seedThrottleFixture(t, 30, 3)
	const source = "203.0.113.9"
	expect := func(name string, err error, reason string) {
		t.Helper()
		if !errors.Is(err, identity.ErrLoginCaptchaInvalid) || refusalreason.Of(err) != reason {
			t.Fatalf("%s: err=%v reason=%q, want %q", name, err, refusalreason.Of(err), reason)
		}
	}
	bound := func(captcha identity.LoginCaptcha) identity.LoginCaptchaProof {
		return identity.LoginCaptchaProof{ID: captcha.ID, Answer: captcha.Answer, Binding: captcha.Binding}
	}

	missing := fixture.captcha(t, source)
	expect("no cookie", fixture.service.ConsumeCaptcha(t.Context(),
		identity.LoginCaptchaProof{ID: missing.ID, Answer: missing.Answer}), identity.CaptchaReasonBindingMismatch)
	expect("no cookie burned", fixture.service.ConsumeCaptcha(t.Context(), bound(missing)), identity.CaptchaReasonConsumed)

	// another signed binding (another
	// browser, or this one's replaced cookie) is refused without burning;
	// a forged one burns the image.
	mine, other := fixture.captcha(t, source), fixture.captcha(t, source)
	expect("other cookie", fixture.service.ConsumeCaptcha(t.Context(),
		identity.LoginCaptchaProof{ID: mine.ID, Answer: mine.Answer, Binding: other.Binding}), identity.CaptchaReasonBindingSuperseded)
	if err := fixture.service.ConsumeCaptcha(t.Context(), bound(mine)); err != nil {
		t.Fatalf("the CAPTCHA with its own cookie after another was refused: %v", err)
	}
	if err := fixture.service.ConsumeCaptcha(t.Context(), bound(other)); err != nil {
		t.Fatalf("the other CAPTCHA with its own cookie: %v", err)
	}
	forged := fixture.captcha(t, source)
	expect("forged cookie", fixture.service.ConsumeCaptcha(t.Context(),
		identity.LoginCaptchaProof{ID: forged.ID, Answer: forged.Answer, Binding: strings.Repeat("A", 43)}), identity.CaptchaReasonBindingMismatch)
	expect("forged cookie burned", fixture.service.ConsumeCaptcha(t.Context(), bound(forged)), identity.CaptchaReasonConsumed)

	legacy := fixture.captcha(t, source)
	if _, err := fixture.pool.Exec(t.Context(), `UPDATE identity_login_captchas SET binding_digest=NULL WHERE id=$1`, legacy.ID); err != nil {
		t.Fatal(err)
	}
	expect("issued before 693", fixture.service.ConsumeCaptcha(t.Context(), bound(legacy)), identity.CaptchaReasonBindingSuperseded)
	expect("issued before 693, no cookie", fixture.service.ConsumeCaptcha(t.Context(),
		identity.LoginCaptchaProof{ID: legacy.ID, Answer: legacy.Answer}), identity.CaptchaReasonBindingMismatch)
	expect("issued before 693, burned", fixture.service.ConsumeCaptcha(t.Context(), bound(legacy)), identity.CaptchaReasonConsumed)
}

// Problem 28: every refusal carries a stable internal reason for the refusal
// log, and the CAPTCHA is still burned whatever the reason.
func TestConsumeCaptchaRefusalReasons(t *testing.T) {
	fixture := seedThrottleFixture(t, 30, 3)
	const source = "203.0.113.9"
	issue := func() identity.LoginCaptchaProof {
		issued := fixture.captcha(t, source)
		return identity.LoginCaptchaProof{ID: issued.ID, Answer: issued.Answer, Binding: issued.Binding}
	}
	expect := func(name string, err error, reason string) {
		t.Helper()
		if !errors.Is(err, identity.ErrLoginCaptchaInvalid) || refusalreason.Of(err) != reason {
			t.Fatalf("%s: err=%v reason=%q, want %q", name, err, refusalreason.Of(err), reason)
		}
	}
	expect("missing", fixture.service.ConsumeCaptcha(t.Context(), identity.LoginCaptchaProof{ID: uuid.New()}), identity.CaptchaReasonMissing)
	expect("not found", fixture.service.ConsumeCaptcha(t.Context(), identity.LoginCaptchaProof{ID: uuid.New(), Answer: "AAAAA"}), identity.CaptchaReasonNotFound)

	wrong := issue()
	expect("answer", fixture.service.ConsumeCaptcha(t.Context(), identity.LoginCaptchaProof{ID: wrong.ID, Answer: "00000", Binding: wrong.Binding}), identity.CaptchaReasonAnswerMismatch)
	// Burned by the wrong answer: the right one now finds it consumed.
	expect("burned", fixture.service.ConsumeCaptcha(t.Context(), wrong), identity.CaptchaReasonConsumed)

	used := issue()
	if err := fixture.service.ConsumeCaptcha(t.Context(), used); err != nil {
		t.Fatal(err)
	}
	expect("consumed", fixture.service.ConsumeCaptcha(t.Context(), used), identity.CaptchaReasonConsumed)

	foreign := issue()
	expect("binding", fixture.service.ConsumeCaptcha(t.Context(), identity.LoginCaptchaProof{ID: foreign.ID, Answer: foreign.Answer}),
		identity.CaptchaReasonBindingMismatch)
	expect("binding burned", fixture.service.ConsumeCaptcha(t.Context(), foreign), identity.CaptchaReasonConsumed)

	expired := issue()
	if _, err := fixture.pool.Exec(t.Context(), `UPDATE identity_login_captchas
		SET created_at=now()-interval '10 minutes', expires_at=now()-interval '5 minutes' WHERE id=$1`, expired.ID); err != nil {
		t.Fatal(err)
	}
	expect("expired", fixture.service.ConsumeCaptcha(t.Context(), expired), identity.CaptchaReasonExpired)
	expect("expired burned", fixture.service.ConsumeCaptcha(t.Context(), expired), identity.CaptchaReasonConsumed)
}

// The sign-in CAPTCHA check (password login past the threshold) shares the
// same spend and reasons; the binding, not the source, decides.
func TestLoginCaptchaRefusalReasons(t *testing.T) {
	fixture := seedThrottleFixture(t, 30, 1)
	const source = "203.0.113.11"
	if err := fixture.login(t, "wrong", source, nil); !errors.Is(err, identity.ErrInvalidCredentials) {
		t.Fatalf("first failure: %v", err)
	}
	unbound := fixture.captcha(t, source)
	err := fixture.login(t, fixture.password, source, &identity.LoginCaptchaProof{ID: unbound.ID, Answer: unbound.Answer})
	if !errors.Is(err, identity.ErrLoginCaptchaInvalid) || refusalreason.Of(err) != identity.CaptchaReasonBindingMismatch {
		t.Fatalf("no cookie: err=%v reason=%q", err, refusalreason.Of(err))
	}
	wrong := fixture.captcha(t, source)
	err = fixture.login(t, fixture.password, source, &identity.LoginCaptchaProof{ID: wrong.ID, Answer: "00000", Binding: wrong.Binding})
	if !errors.Is(err, identity.ErrLoginCaptchaInvalid) || refusalreason.Of(err) != identity.CaptchaReasonAnswerMismatch {
		t.Fatalf("wrong: err=%v reason=%q", err, refusalreason.Of(err))
	}
	// issued through another CDN edge than the sign-in comes from
	solved := fixture.captcha(t, "198.51.100.7")
	if err := fixture.login(t, fixture.password, source, &identity.LoginCaptchaProof{ID: solved.ID, Answer: solved.Answer, Binding: solved.Binding}); err != nil {
		t.Fatalf("solved: %v", err)
	}
}
