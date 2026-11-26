//go:build integration

package main

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/accountregistration"
	"github.com/cdnca/cdnca/services/control-api/internal/httpapi"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/systemusersettings"
	"github.com/google/uuid"
)

type acceptingRegistrationCaptcha struct{}

func (acceptingRegistrationCaptcha) ConsumeCaptcha(context.Context, identity.LoginCaptchaProof) error {
	return nil
}

// end to end on the built-in flow:
// saving new terms changes the public version and the terms the page shows,
// the old version is refused and the new one accepted; the QQ requirement
// is public and enforced, the QQ is stored; a username left empty is
// generated and signs in, as does the email.
func TestRegistrationTermsQQAndUsernamePostgres(t *testing.T) {
	pool, settings := registrationReadyTestPool(t)
	saveRegistrationSettings(t, pool, func(*systemusersettings.Settings) {})
	store, err := accountregistration.NewPostgresStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	builtIn, err := accountregistration.NewBuiltInService(store, settings, acceptingRegistrationCaptcha{}, bytes.Repeat([]byte{0x41}, 32))
	if err != nil {
		t.Fatal(err)
	}
	source := newRegistrationConfigSource(pool, settings, accountRegistrationRuntimeConfig{}, false, builtIn,
		&liveTestChannels{}, registrationNotificationView{requested: true}, accountRecoveryRuntimeConfig{})
	builtIn.RequireTermsWhen(source.terms.Required)
	defaults := systemusersettings.DefaultSettings()
	before, err := source.RegistrationConfig(t.Context())
	if err != nil || before.TermsVersion != systemusersettings.TermsVersion(defaults.TermsTitle, defaults.TermsBody) ||
		before.QQRequired || !before.UsernameRequired {
		t.Fatalf("before: %+v %v", before, err)
	}
	// a new install has no terms; sign-up stays open and the
	// unpublished terms still have a version (TermsVersion of an empty body)
	if before.TermsPublished || before.TermsRequired || !before.Ready {
		t.Fatalf("unpublished: %+v", before)
	}
	if _, err := source.RegistrationTerms(t.Context()); !errors.Is(err, httpapi.ErrRegistrationTermsNotConfigured) {
		t.Fatalf("unpublished terms: %v", err)
	}
	// no website terms page (no website here) and none published: no terms
	// are asked for, and none is recorded as accepted
	unrequired := accountregistration.BuiltInInput{RegisterInput: accountregistration.RegisterInput{Username: "terms-none",
		Password: "Correct-horse-battery-staple", DisplayName: "terms-none", Email: "none@example.com",
		IdempotencyKey: "reg-no-terms", RequestID: "request-reg-no-terms", Source: "203.0.113.9"},
		Captcha: identity.LoginCaptchaProof{ID: uuid.NewSHA1(uuid.NameSpaceOID, []byte("reg-no-terms")), Answer: "AB2CD"}}
	if result, err := builtIn.Register(t.Context(), unrequired); err != nil || !result.Accepted {
		t.Fatalf("no terms required: %#v %v", result, err)
	}
	var acceptances int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM account_registration_terms_159 t JOIN users u ON u.id=t.user_id
		WHERE u.username='terms-none'`).Scan(&acceptances); err != nil || acceptances != 0 {
		t.Fatalf("acceptances=%d err=%v", acceptances, err)
	}
	// terms published: required now; the registration taken without them replays
	saveRegistrationSettings(t, pool, func(value *systemusersettings.Settings) {
		value.TermsTitle, value.TermsBody = "注册协议", "第零条 先发布的协议"
	})
	if config, err := source.RegistrationConfig(t.Context()); err != nil || !config.TermsRequired {
		t.Fatalf("published: %+v %v", config, err)
	}
	if replay, err := builtIn.Register(t.Context(), unrequired); err != nil || !replay.Replayed {
		t.Fatalf("replay of the unrequired registration: %#v %v", replay, err)
	}

	saveRegistrationSettings(t, pool, func(value *systemusersettings.Settings) {
		value.TermsTitle, value.TermsBody, value.QQRequired = "注册协议", "第一条 新的协议正文", true
	})
	after, err := source.RegistrationConfig(t.Context())
	if err != nil || after.TermsVersion == before.TermsVersion || !after.TermsPublished || !after.TermsRequired || !after.QQRequired || !after.Ready {
		t.Fatalf("after: %+v %v", after, err)
	}
	terms, err := source.RegistrationTerms(t.Context())
	if err != nil || terms.Title != "注册协议" || terms.Body != "第一条 新的协议正文" || terms.Version != after.TermsVersion {
		t.Fatalf("terms: %+v %v", terms, err)
	}

	register := func(key, username, email, qq, version string) (accountregistration.RegisterResult, error) {
		return builtIn.Register(t.Context(), accountregistration.BuiltInInput{
			RegisterInput: accountregistration.RegisterInput{Username: username, Password: "Correct-horse-battery-staple",
				DisplayName: username, Email: email, QQ: qq, TermsAccepted: true, TermsVersion: version,
				IdempotencyKey: key, RequestID: "request-" + key, Source: "203.0.113.9"},
			// an exact retry carries the same image code (one per idempotency key here)
			Captcha: identity.LoginCaptchaProof{ID: uuid.NewSHA1(uuid.NameSpaceOID, []byte(key)), Answer: "AB2CD"},
		})
	}
	if _, err := register("reg-old-terms", "terms-old", "old@example.com", "123456", before.TermsVersion); !errors.Is(err, accountregistration.ErrTermsOutdated) {
		t.Fatalf("old terms version: %v", err)
	}
	if _, err := register("reg-no-qq", "terms-no-qq", "noqq@example.com", "", after.TermsVersion); !errors.Is(err, accountregistration.ErrInvalidInput) {
		t.Fatalf("required QQ left empty: %v", err)
	}
	if _, err := register("reg-bad-qq", "terms-bad-qq", "badqq@example.com", "12ab5", after.TermsVersion); !errors.Is(err, accountregistration.ErrInvalidInput) {
		t.Fatalf("invalid QQ: %v", err)
	}
	if result, err := register("reg-new-terms", "terms-new", "new@example.com", "123456789", after.TermsVersion); err != nil || !result.Accepted || result.Username != "" {
		t.Fatalf("new terms version: %#v %v", result, err)
	}
	var qq, accepted string
	if err := pool.QueryRow(t.Context(), `SELECT u.qq,t.terms_version FROM users u
		JOIN account_registration_terms_159 t ON t.user_id=u.id WHERE u.username='terms-new'`).Scan(&qq, &accepted); err != nil ||
		qq != "123456789" || accepted != after.TermsVersion {
		t.Fatalf("stored qq=%q terms=%q err=%v", qq, accepted, err)
	}
	// terms B are another version; the registration accepted
	// under A, retried unchanged, replays its receipt
	saveRegistrationSettings(t, pool, func(value *systemusersettings.Settings) {
		value.TermsTitle, value.TermsBody, value.QQRequired = "注册协议", "第二条 改过的协议正文", true
	})
	changed, err := source.RegistrationConfig(t.Context())
	if err != nil || changed.TermsVersion == after.TermsVersion || changed.TermsVersion == before.TermsVersion || !changed.TermsPublished {
		t.Fatalf("terms B: %+v %v", changed, err)
	}
	if replay, err := register("reg-new-terms", "terms-new", "new@example.com", "123456789", after.TermsVersion); err != nil || !replay.Replayed {
		t.Fatalf("replay after terms B: %#v %v", replay, err)
	}

	// username optional: left empty, one is generated, kept on a retry, and signs in
	saveRegistrationSettings(t, pool, func(value *systemusersettings.Settings) {
		value.TermsTitle, value.TermsBody, value.UsernameRequired = "注册协议", "第一条 新的协议正文", false
	})
	if config, err := source.RegistrationConfig(t.Context()); err != nil || config.UsernameRequired || config.QQRequired {
		t.Fatalf("username optional: %+v %v", config, err)
	}
	generated, err := register("reg-generated", "", "Carol.Lee@Example.com", "", after.TermsVersion)
	if err != nil || !generatedUsernamePattern(generated.Username) {
		t.Fatalf("generated: %#v %v", generated, err)
	}
	if replay, err := register("reg-generated", "", "Carol.Lee@Example.com", "", after.TermsVersion); err != nil || !replay.Replayed || replay.Username != generated.Username {
		t.Fatalf("retry: %#v %v", replay, err)
	}
	if kept, err := register("reg-typed", "typed-name", "typed@example.com", "", after.TermsVersion); err != nil || kept.Username != "" {
		t.Fatalf("typed username: %#v %v", kept, err)
	}
	tokens, err := identity.NewTokenManager("registration-fields-integration-secret-32b", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	logins, err := identity.NewService(identity.NewStore(pool), tokens, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{generated.Username, "carol.lee@example.com", "typed-name"} {
		if _, err := logins.Login(t.Context(), identity.LoginInput{Username: name, Password: "Correct-horse-battery-staple"},
			identity.RequestInfo{SourceIP: "203.0.113.9", RequestID: "login-" + name[:5]}); err != nil {
			t.Fatalf("login %q: %v", name, err)
		}
	}
}

func generatedUsernamePattern(name string) bool {
	return len(name) > 9 && name[:len("carol.lee-")] == "carol.lee-"
}
