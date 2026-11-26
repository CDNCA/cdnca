package accountrecoveryhttp

import (
	"bytes"
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/accountrecovery"
	"github.com/cdnca/cdnca/services/control-api/internal/accountregistration"
	"github.com/cdnca/cdnca/services/control-api/internal/accountregistrationproof"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/systemusersettings"
	"github.com/google/uuid"
)

// sign up without a
// username while the email must be verified, sign out, ask for a reset with
// the verified email on the platform host, follow the link, sign in with the
// new password.

type optionalUsernamePolicy struct{}

func (optionalUsernamePolicy) GetPublic(context.Context, uuid.UUID) (systemusersettings.PublicSettings, error) {
	return systemusersettings.PublicSettings{
		RegistrationEnabled: true, EmailRequired: true, EmailVerificationRequired: true,
		UsernameRequired: false, TermsVersion: "terms-v1",
	}, nil
}

type acceptingCaptcha struct{}

func (acceptingCaptcha) ConsumeCaptcha(context.Context, identity.LoginCaptchaProof) error { return nil }

// emailCodeProofs stands in for the code step: the visitor received the
// code for this address, so a proof is issued and then consumed as the
// registration presents it.
type emailCodeProofs struct {
	authority *accountregistrationproof.Authority
}

func (proofs emailCodeProofs) VerifyAndConsume(
	ctx context.Context,
	request accountregistration.RegistrationProofRequest,
) (accountregistration.RegistrationProof, error) {
	now := time.Now().UTC().Add(-time.Second)
	issued, err := proofs.authority.Issue(ctx, accountregistrationproof.IssueRequest{
		Channel: request.Channel, Destination: request.Destination, Source: "203.0.113.9",
		SubjectDigest: request.SubjectDigest, HumanVerifiedAt: now, ContactVerifiedAt: now,
		ExpiresAt: now.Add(5 * time.Minute), AttemptRevision: 1, RiskContext: accountregistrationproof.RiskContextNormal,
	})
	if err != nil {
		return accountregistration.RegistrationProof{}, err
	}
	request.Reference = issued.Reference
	return proofs.authority.VerifyAndConsume(ctx, request)
}

func TestRegisterWithoutUsernameThenRecoverByVerifiedEmail(t *testing.T) {
	fixture := newIntegrationFixture(t)
	ctx := t.Context()
	registrationKey := bytes.Repeat([]byte{0x41}, 32)
	store, err := accountregistration.NewPostgresStore(fixture.pool)
	if err != nil {
		t.Fatal(err)
	}
	registration, err := accountregistration.NewBuiltInService(store, optionalUsernamePolicy{}, acceptingCaptcha{}, registrationKey)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := accountregistrationproof.NewAuthority(fixture.pool, accountregistrationproof.Config{DigestKey: registrationKey})
	if err != nil {
		t.Fatal(err)
	}
	registration.EnableContactVerification(emailCodeProofs{authority: authority})
	const password = "Correct-horse-battery-staple-1"
	registered, err := registration.Register(ctx, accountregistration.BuiltInInput{RegisterInput: accountregistration.RegisterInput{
		Password: password, Email: "Kim.Lee@Example.test", ProofReference: "proof-reference-presented-by-page",
		TermsAccepted: true, TermsVersion: "terms-v1", IdempotencyKey: "reg-kim", RequestID: "request-reg-kim",
		Source: "203.0.113.9",
	}})
	if err != nil || !registered.Accepted || registered.Username == "" {
		t.Fatalf("register without username: %+v %v", registered, err)
	}

	tokens, err := identity.NewTokenManager("registration-email-recovery-secret-32b", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	logins, err := identity.NewService(identity.NewStore(fixture.pool), tokens, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	signIn := func(name, secret, requestID string) error {
		_, err := logins.Login(ctx, identity.LoginInput{Username: name, Password: secret},
			identity.RequestInfo{SourceIP: "203.0.113.9", RequestID: requestID})
		return err
	}
	session, err := logins.Login(ctx, identity.LoginInput{Username: registered.Username, Password: password},
		identity.RequestInfo{SourceIP: "203.0.113.9", RequestID: "login-registered"})
	if err != nil {
		t.Fatalf("login with the generated username: %v", err)
	}
	if err := logins.Logout(ctx, session.RefreshToken, "logout-registered"); err != nil {
		t.Fatal(err)
	}

	config := integrationServiceConfig(fixture, fixture.store)
	config.RegistrationProofKeys = [][]byte{registrationKey}
	fixture.service, err = accountrecovery.NewServiceWithDependencies(fixture.pool, config, audit.New(fixture.pool))
	if err != nil {
		t.Fatal(err)
	}
	platformHandler := newTrustedHandler(t, fixture, uuid.Nil, integrationSeedPlatformScope(t, fixture))
	unknown := postRecoveryRequest(t, platformHandler, "nobody@example.test", "email-unknown")
	link := requestAndDispatchLinkVia(t, fixture, platformHandler, " Kim.Lee@example.test ", "email-registered")
	if unknown.Code != http.StatusAccepted {
		t.Fatalf("unknown email status=%d body=%s", unknown.Code, unknown.Body.String())
	}
	response := postRecoveryConfirmationWithPassword(t, platformHandler, link.token, link.recoveryContext,
		"email-registered-confirm", "Recovered-password-5678")
	if response.Code != http.StatusNoContent {
		t.Fatalf("confirmation status=%d body=%s", response.Code, response.Body.String())
	}
	for _, name := range []string{registered.Username, "kim.lee@example.test"} {
		if err := signIn(name, "Recovered-password-5678", "login-new-"+name[:3]); err != nil {
			t.Fatalf("login %q with the new password: %v", name, err)
		}
	}
	if err := signIn(registered.Username, password, "login-old"); err == nil {
		t.Fatal("the old password still signs in")
	}
}
