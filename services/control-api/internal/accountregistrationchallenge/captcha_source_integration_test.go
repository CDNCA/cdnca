package accountregistrationchallenge

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/accountregistrationproof"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/refusalreason"
	"github.com/cdnca/cdnca/services/control-api/internal/systemusersettings"
	"github.com/google/uuid"
)

// email verification
// with the built-in image CAPTCHA behind a proxy chain. POST
// /v1/auth/login-captchas issued the CAPTCHA through the Cloudflare edge
// 172.71.95.136; the Turnstile registration runtime resolves the browser
// 203.0.113.50 with the ACCOUNT_RECOVERY_* proxies, and without origin
// authentication the code request can come through another edge. The
// CAPTCHA is spent with its browser binding cookie whatever the source. The
// code request leaves the phone empty (the page shows no phone field without SMS).
func TestCaptchaChallengeBehindProxyChainPostgres(t *testing.T) {
	pool := databasetest.MigratedPool(t, nil)
	ctx := t.Context()
	scope := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, scope); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE notification_channel_settings SET email_enabled=true WHERE singleton`); err != nil {
		t.Fatal(err)
	}
	tokens, err := identity.NewTokenManager(strings.Repeat("t", 32), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	captchas, err := identity.NewService(identity.NewStore(pool), tokens, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := captchas.SetLoginThrottleKey(bytes.Repeat([]byte{0x6b}, 32)); err != nil {
		t.Fatal(err)
	}
	store, err := notification.NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	dispatch, err := NewEnvelopeKeyring("dispatch-v1", map[string][]byte{"dispatch-v1": bytes.Repeat([]byte{0x42}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	proofKeys, err := NewEnvelopeKeyring("proof-v1", map[string][]byte{"proof-v1": bytes.Repeat([]byte{0x43}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	sender, err := NewNotificationContactSender(store, dispatch, map[notification.Channel]notification.TemplateRef{
		notification.ChannelEmail: {ID: "account_registration_verification", Version: 1, Channel: notification.ChannelEmail},
	})
	if err != nil {
		t.Fatal(err)
	}
	digestKey := bytes.Repeat([]byte{0x41}, 32)
	authority, err := accountregistrationproof.NewAuthority(pool, accountregistrationproof.Config{DigestKey: digestKey})
	if err != nil {
		t.Fatal(err)
	}
	policy := fixedPolicy{systemusersettings.PublicSettings{RegistrationEnabled: true, EmailRequired: true, EmailVerificationRequired: true}}
	service := func(human HumanVerifier) *Service {
		challenges, err := NewService(pool, human, sender, authority, proofKeys,
			Config{DigestKey: digestKey, PublicSettings: policy})
		if err != nil {
			t.Fatal(err)
		}
		return challenges
	}
	edge := netip.MustParseAddr("172.71.95.136")
	requestCtx := audit.WithSourceIP(ctx, edge)
	attempt := 0
	// create issues a CAPTCHA through the edge and spends it with the binding
	// cookie bind picks (the HTTP layer records it, httpapi.WithLoginCaptchaBinding).
	create := func(challenges *Service, ctx context.Context, answer func(string) string, bind func(identity.LoginCaptcha) string) error {
		attempt++
		issued, err := captchas.IssueLoginCaptcha(ctx, edge.String(), "")
		if err != nil {
			t.Fatal(err)
		}
		_, err = challenges.Create(identity.WithLoginCaptchaBinding(ctx, func(uuid.UUID) string { return bind(issued) }), CreateInput{ScopeID: scope, Username: "proxied-owner", Email: "proxied@example.com",
			Channel: "email", Source: "203.0.113.50",
			HumanToken:     CaptchaTokenPrefix + issued.ID.String() + ":" + answer(issued.Answer),
			IdempotencyKey: "create-" + uuid.NewString(), RequestID: "request-" + uuid.NewString()})
		return err
	}
	right := func(answer string) string { return answer }
	own := func(issued identity.LoginCaptcha) string { return issued.Binding }
	fixed := service(CaptchaHumanVerifier{Captcha: captchas})

	// no binding cookie, or another browser's (signed by
	// this service: refused as superseded, ;
	// a forged one: httpapi TestBuiltInRegisterSpendsCaptchaByBrowserBindingAcrossEdges).
	// Five creates per subject in the window, so no further case fits here.
	other, err := captchas.IssueLoginCaptcha(ctx, edge.String(), "")
	if err != nil {
		t.Fatal(err)
	}
	for name, test := range map[string]struct {
		bind   func(identity.LoginCaptcha) string
		reason string
	}{
		"no cookie":    {func(identity.LoginCaptcha) string { return "" }, identity.CaptchaReasonBindingMismatch},
		"other cookie": {func(identity.LoginCaptcha) string { return other.Binding }, identity.CaptchaReasonBindingSuperseded},
	} {
		if err := create(fixed, requestCtx, right, test.bind); !errors.Is(err, ErrHumanInvalid) ||
			refusalreason.Of(err) != test.reason {
			t.Fatalf("%s = %v (%q), want ErrHumanInvalid %s", name, err, refusalreason.Of(err), test.reason)
		}
	}
	if err := create(fixed, requestCtx, func(string) string { return "WRONG" }, own); !errors.Is(err, ErrHumanInvalid) ||
		refusalreason.Of(err) != identity.CaptchaReasonAnswerMismatch {
		t.Fatalf("wrong answer = %v (%q)", err, refusalreason.Of(err))
	}
	// the code request reaches control-api through another CDN edge than the
	// CAPTCHA did: the binding cookie decides, not the source
	if err := create(fixed, audit.WithSourceIP(ctx, netip.MustParseAddr("162.159.2.20")), right, own); err != nil {
		t.Fatalf("right answer, other edge: %v", err)
	}
	// problem 28: the same rejected request again (same key) says it is a replay
	rejected, err := captchas.IssueLoginCaptcha(ctx, edge.String(), "")
	if err != nil {
		t.Fatal(err)
	}
	again := CreateInput{ScopeID: scope, Username: "proxied-owner", Email: "proxied@example.com", Channel: "email",
		Source: "203.0.113.50", HumanToken: CaptchaTokenPrefix + rejected.ID.String() + ":WRONG",
		IdempotencyKey: "create-" + uuid.NewString(), RequestID: "request-" + uuid.NewString()}
	boundCtx := identity.WithLoginCaptchaBinding(requestCtx, func(uuid.UUID) string { return rejected.Binding })
	if _, err := fixed.Create(boundCtx, again); refusalreason.Of(err) != identity.CaptchaReasonAnswerMismatch {
		t.Fatalf("first rejection = %v (%q)", err, refusalreason.Of(err))
	}
	if _, err := fixed.Create(boundCtx, again); !errors.Is(err, ErrHumanInvalid) || refusalreason.Of(err) != HumanReasonRejectedReplay {
		t.Fatalf("rejected replay = %v (%q)", err, refusalreason.Of(err))
	}
	var queued int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM notification_outbox WHERE template_id='account_registration_verification'`).Scan(&queued); err != nil || queued != 1 {
		t.Fatalf("queued codes = %d (%v) after %d attempts", queued, err, attempt)
	}
}

// The unique human_token_digest (23505 -> ErrHumanInvalid) only refuses a
// token sent again under a new Idempotency-Key: that CAPTCHA is spent.
func TestReusedHumanTokenIsRefusedPostgres(t *testing.T) {
	pool := databasetest.MigratedPool(t, nil)
	ctx := t.Context()
	scope := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, scope); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE notification_channel_settings SET email_enabled=true WHERE singleton`); err != nil {
		t.Fatal(err)
	}
	store, err := notification.NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	dispatch, err := NewEnvelopeKeyring("dispatch-v1", map[string][]byte{"dispatch-v1": bytes.Repeat([]byte{0x42}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	proofKeys, err := NewEnvelopeKeyring("proof-v1", map[string][]byte{"proof-v1": bytes.Repeat([]byte{0x43}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	sender, err := NewNotificationContactSender(store, dispatch, map[notification.Channel]notification.TemplateRef{
		notification.ChannelEmail: {ID: "account_registration_verification", Version: 1, Channel: notification.ChannelEmail},
	})
	if err != nil {
		t.Fatal(err)
	}
	digestKey := bytes.Repeat([]byte{0x41}, 32)
	authority, err := accountregistrationproof.NewAuthority(pool, accountregistrationproof.Config{DigestKey: digestKey})
	if err != nil {
		t.Fatal(err)
	}
	policy := fixedPolicy{systemusersettings.PublicSettings{RegistrationEnabled: true, EmailRequired: true, EmailVerificationRequired: true}}
	challenges, err := NewService(pool, &acceptHuman{}, sender, authority, proofKeys,
		Config{DigestKey: digestKey, PublicSettings: policy})
	if err != nil {
		t.Fatal(err)
	}
	input := CreateInput{ScopeID: scope, Username: "reuse-owner", Email: "reuse@example.com", Channel: "email",
		Source: "203.0.113.50", HumanToken: CaptchaTokenPrefix + uuid.NewString() + ":AB2CD",
		IdempotencyKey: "create-1", RequestID: "request-1"}
	first, err := challenges.Create(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := challenges.Create(ctx, input)
	if err != nil || !replay.Replayed || replay.ChallengeID != first.ChallengeID {
		t.Fatalf("same request again = %#v %v, want the replay", replay, err)
	}
	input.IdempotencyKey, input.RequestID = "create-2", "request-2"
	if _, err := challenges.Create(ctx, input); !errors.Is(err, ErrHumanInvalid) || refusalreason.Of(err) != HumanReasonTokenReused {
		t.Fatalf("spent token, new key = %v (%q)", err, refusalreason.Of(err))
	}
}
