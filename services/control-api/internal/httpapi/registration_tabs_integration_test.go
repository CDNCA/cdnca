package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/accountregistration"
	"github.com/cdnca/cdnca/services/control-api/internal/accountregistrationchallenge"
	"github.com/cdnca/cdnca/services/control-api/internal/accountregistrationchallengehttp"
	"github.com/cdnca/cdnca/services/control-api/internal/accountregistrationproof"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/systemusersettings"
	"github.com/google/uuid"
)

type tabsZeroEntropy struct{}

func (tabsZeroEntropy) Read(buffer []byte) (int, error) { clear(buffer); return len(buffer), nil }

type tabsEmailPolicy struct{}

func (tabsEmailPolicy) GetPublic(context.Context, uuid.UUID) (systemusersettings.PublicSettings, error) {
	return systemusersettings.PublicSettings{RegistrationEnabled: true, EmailRequired: true, EmailVerificationRequired: true}, nil
}

// tabsFixture is the built-in registration with email verification behind a
// TLS test server, so browsers are cookie jars with real cookie semantics
// (Secure, Path, __Host-). Codes are "000000" (zero entropy).
type tabsFixture struct {
	t           *testing.T
	server      *httptest.Server
	store       *termsRegistrationStore
	throttleKey []byte
	plant       func(uuid.UUID)
}

func newTabsFixture(t *testing.T) *tabsFixture {
	t.Helper()
	pool := isolatedTestPool(t)
	ctx := context.Background()
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
	identityService, err := identity.NewService(identity.NewStore(pool), tokens, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	throttleKey := bytes.Repeat([]byte{0x6b}, 32)
	if err := identityService.SetLoginThrottleKey(throttleKey); err != nil {
		t.Fatal(err)
	}
	keys := func(id string, value byte) *accountregistrationchallenge.EnvelopeKeyring {
		keyring, err := accountregistrationchallenge.NewEnvelopeKeyring(id, map[string][]byte{id: bytes.Repeat([]byte{value}, 32)})
		if err != nil {
			t.Fatal(err)
		}
		return keyring
	}
	outbox, err := notification.NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	sender, err := accountregistrationchallenge.NewNotificationContactSender(outbox, keys("dispatch-v1", 0x42),
		map[notification.Channel]notification.TemplateRef{
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
	challenges, err := accountregistrationchallenge.NewService(pool, accountregistrationchallenge.CaptchaHumanVerifier{Captcha: identityService},
		sender, authority, keys("proof-v1", 0x43),
		accountregistrationchallenge.Config{DigestKey: digestKey, PublicSettings: tabsEmailPolicy{}, Entropy: tabsZeroEntropy{}})
	if err != nil {
		t.Fatal(err)
	}
	challengeHandler, err := accountregistrationchallengehttp.NewHandler(challenges,
		accountregistrationchallengehttp.TrustedContextResolverFunc(func(request *http.Request) (accountregistrationchallengehttp.TrustedContext, error) {
			return accountregistrationchallengehttp.TrustedContext{ScopeID: scope, SourceIP: BuiltInRegistrationSource(request.Context())}, nil
		}), accountregistrationchallengehttp.Config{})
	if err != nil {
		t.Fatal(err)
	}
	store := &termsRegistrationStore{}
	registration, err := accountregistration.NewBuiltInService(store, tabsEmailPolicy{}, identityService, digestKey)
	if err != nil {
		t.Fatal(err)
	}
	registration.RequireTermsWhen(func(context.Context) (bool, error) { return false, nil })
	registration.EnableContactVerification(authority)
	api := New(pool, identityService, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), CookieSecure: true,
		BuiltInRegistration: registration, BuiltInRegistrationChallengeHandler: challengeHandler}).Handler()
	server := httptest.NewTLSServer(api)
	t.Cleanup(server.Close)
	return &tabsFixture{t: t, server: server, store: store, throttleKey: throttleKey, plant: func(id uuid.UUID) {
		// The planted answer is in logincaptcha.Alphabet, which the look-alike mapping leaves as is (normalizeCaptchaAnswer).
		if _, err := pool.Exec(ctx, `UPDATE identity_login_captchas SET answer_digest=$2 WHERE id=$1`,
			id, captchaTestDigest(throttleKey, "answer", id, "A72CD")); err != nil {
			t.Error(err)
		}
	}}
}

// browser is one cookie jar: every tab of a browser shares it.
func (fixture *tabsFixture) browser() *http.Client {
	jar, err := cookiejar.New(nil)
	if err != nil {
		fixture.t.Fatal(err)
	}
	return &http.Client{Transport: fixture.server.Client().Transport, Jar: jar}
}

// post sends one JSON request; the answer is the status and the error code.
// post, captcha and send report with Errorf: tabs call them in parallel.
func (fixture *tabsFixture) post(browser *http.Client, path string, body any) (int, string, []byte) {
	fixture.t.Helper()
	raw, _ := json.Marshal(body)
	request, err := http.NewRequest(http.MethodPost, fixture.server.URL+path, bytes.NewReader(raw))
	if err != nil {
		fixture.t.Error(err)
		return 0, "", nil
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "key-"+uuid.NewString())
	request.Header.Set("X-Request-ID", "request-"+uuid.NewString())
	response, err := browser.Do(request)
	if err != nil {
		fixture.t.Error(err)
		return 0, "", nil
	}
	defer response.Body.Close()
	payload, _ := io.ReadAll(response.Body)
	var envelope struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(payload, &envelope)
	return response.StatusCode, envelope.Error.Code, payload
}

// captcha fetches an image in browser and plants the answer A72CD.
func (fixture *tabsFixture) captcha(browser *http.Client) uuid.UUID {
	fixture.t.Helper()
	status, code, payload := fixture.post(browser, "/v1/auth/login-captchas", map[string]any{})
	var issued loginCaptchaResponse
	if status != http.StatusCreated || json.Unmarshal(payload, &issued) != nil {
		fixture.t.Errorf("captcha: %d %s %s", status, code, payload)
		return uuid.Nil
	}
	fixture.plant(issued.ID)
	return issued.ID
}

// send asks for an email code with a solved image; the challenge id.
func (fixture *tabsFixture) send(browser *http.Client, username string, captcha uuid.UUID) uuid.UUID {
	fixture.t.Helper()
	status, code, payload := fixture.post(browser, "/v1/auth/registration-challenges", map[string]any{
		"username": username, "email": username + "@example.com", "phone": "", "verification_channel": "email",
		"human_token": "captcha:" + captcha.String() + ":A72CD"})
	var created struct {
		Data struct {
			ChallengeID uuid.UUID `json:"challenge_id"`
		} `json:"data"`
	}
	if status != http.StatusAccepted || json.Unmarshal(payload, &created) != nil || created.Data.ChallengeID == uuid.Nil {
		fixture.t.Errorf("send %s: %d %s %s", username, status, code, payload)
	}
	return created.Data.ChallengeID
}

func (fixture *tabsFixture) verify(browser *http.Client, username string, challenge uuid.UUID) (int, string) {
	status, code, _ := fixture.post(browser, "/v1/auth/registration-challenge-verifications", map[string]any{
		"challenge_id": challenge, "username": username, "email": username + "@example.com", "phone": "",
		"verification_channel": "email", "otp": "000000"})
	return status, code
}

func (fixture *tabsFixture) register(browser *http.Client, username string, challenge uuid.UUID) (int, string) {
	status, code, _ := fixture.post(browser, "/v1/auth/register", map[string]any{
		"username": username, "password": "Correct-horse-battery-1", "display_name": username,
		"email": username + "@example.com", "phone": "", "verification_channel": "email",
		"verification_challenge_ids": map[string]uuid.UUID{"email": challenge}})
	return status, code
}

// inTabs runs one step in two tabs of a browser at the same time.
func inTabs[T any](step func(tab string) T) map[string]T {
	results := map[string]T{}
	var lock sync.Mutex
	var group sync.WaitGroup
	for _, tab := range []string{"a", "b"} {
		group.Go(func() {
			result := step(tab)
			lock.Lock()
			results[tab] = result
			lock.Unlock()
		})
	}
	group.Wait()
	return results
}

// (reproduced on real SMTP) and
// two sign-up tabs of one browser with
// different emails. A clean browser's tabs fetch their first image at once
// (neither request carries a binding cookie), then send, check and register
// at once or one after the other, in either order. The image, code binding
// and registration proof cookies of one tab never replace the other's; each
// tab registers with its own proof. Another browser holds none of them.
func TestBuiltInRegistrationTabsOfOneBrowserKeepTheirCodes(t *testing.T) {
	fixture := newTabsFixture(t)
	browser := fixture.browser()
	user := func(round, tab string) string { return "tab-" + round + "-" + tab }
	verified := func(round string, sent map[string]uuid.UUID, tab string) bool {
		status, code := fixture.verify(browser, user(round, tab), sent[tab])
		if status != http.StatusNoContent {
			t.Errorf("verify %s: %d %s", user(round, tab), status, code)
		}
		return status == http.StatusNoContent
	}
	rounds := map[string]map[string]uuid.UUID{}

	// round 1, clean browser: first images at once, codes sent at once, checked at once
	images := inTabs(func(string) uuid.UUID { return fixture.captcha(browser) })
	rounds["1"] = inTabs(func(tab string) uuid.UUID { return fixture.send(browser, user("1", tab), images[tab]) })
	inTabs(func(tab string) bool { return verified("1", rounds["1"], tab) })

	// round 2, stable binding: images at once, codes one after the other,
	// checked in the reverse order
	images = inTabs(func(string) uuid.UUID { return fixture.captcha(browser) })
	rounds["2"] = map[string]uuid.UUID{"a": fixture.send(browser, user("2", "a"), images["a"])}
	rounds["2"]["b"] = fixture.send(browser, user("2", "b"), images["b"])
	verified("2", rounds["2"], "b")
	verified("2", rounds["2"], "a")
	if t.Failed() {
		t.FailNow()
	}

	// each tab registers in turn with its own proof
	for _, round := range []string{"1", "2"} {
		for _, tab := range []string{"b", "a"} {
			if status, code := fixture.register(browser, user(round, tab), rounds[round][tab]); status != http.StatusAccepted {
				t.Fatalf("register %s: %d %s", user(round, tab), status, code)
			}
		}
	}
	if len(fixture.store.records) != 4 {
		t.Fatalf("records = %d", len(fixture.store.records))
	}

	// another browser: the code cannot be checked there, nor the proof spent
	other := fixture.browser()
	challengeE := fixture.send(browser, "tab-e", fixture.captcha(browser))
	if status, code := fixture.verify(other, "tab-e", challengeE); status != http.StatusUnprocessableEntity ||
		code != "account_registration_challenge_invalid" {
		t.Fatalf("verify in another browser: %d %s", status, code)
	}
	if status, code := fixture.verify(browser, "tab-e", challengeE); status != http.StatusNoContent {
		t.Fatalf("verify tab-e: %d %s", status, code)
	}
	if status, code := fixture.register(other, "tab-e", challengeE); status != http.StatusUnprocessableEntity ||
		code != "account_registration_verification_required" {
		t.Fatalf("register in another browser: %d %s", status, code)
	}
	// a tab naming another tab's challenge spends no proof (the proof is bound to its own details)
	if status, code := fixture.register(browser, "tab-f", challengeE); status != http.StatusUnprocessableEntity ||
		code != "account_registration_verification_required" {
		t.Fatalf("register with another tab's challenge: %d %s", status, code)
	}
	if status, code := fixture.register(browser, "tab-e", challengeE); status != http.StatusAccepted {
		t.Fatalf("register tab-e: %d %s", status, code)
	}
}
