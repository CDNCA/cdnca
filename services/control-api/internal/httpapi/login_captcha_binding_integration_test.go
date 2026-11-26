package httpapi

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/accountregistration"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// captchaTestDigest is identity's keyed digest (login-captcha/v1 domains);
// the test knows the throttle key, so it can check what is stored and plant
// a known answer for an image it cannot read.
func captchaTestDigest(key []byte, domain string, id uuid.UUID, value string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("cdnca/identity/login-captcha/v1/" + domain + "\x00"))
	_, _ = mac.Write([]byte(id.String()))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(value))
	return mac.Sum(nil)
}

// newCaptchaRegisterAPI is built-in registration with the image CAPTCHA only
// (no verification code required) on an isolated schema.
func newCaptchaRegisterAPI(t *testing.T) (*pgxpool.Pool, http.Handler, *termsRegistrationStore, []byte) {
	t.Helper()
	pool := isolatedTestPool(t)
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
	store := &termsRegistrationStore{}
	registration, err := accountregistration.NewBuiltInService(store, termsRegistrationPolicy{}, identityService, bytes.Repeat([]byte{0x41}, 32))
	if err != nil {
		t.Fatal(err)
	}
	registration.RequireTermsWhen(func(context.Context) (bool, error) { return false, nil })
	api := New(pool, identityService, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), CookieSecure: true,
		BuiltInRegistration: registration}).Handler()
	return pool, api, store, throttleKey
}

// Behind a CDN (behind Cloudflare, no origin authentication): the
// image comes through edge 104.23.x and the sign-up through edge 162.159.x.
// POST /v1/auth/login-captchas sets the binding cookie, POST /v1/auth/register
// from the other edge with that cookie succeeds; without it, or with the
// cookie of another browser, it is refused (burned only without a signed cookie).
func TestBuiltInRegisterSpendsCaptchaByBrowserBindingAcrossEdges(t *testing.T) {
	pool, api, store, throttleKey := newCaptchaRegisterAPI(t)
	ctx := context.Background()

	// issue returns the image id and its binding cookie, with a known answer planted.
	issue := func(edge string) (uuid.UUID, *http.Cookie) {
		t.Helper()
		request := httptest.NewRequest(http.MethodPost, "/v1/auth/login-captchas", nil)
		request.RemoteAddr = edge + ":443"
		response := httptest.NewRecorder()
		api.ServeHTTP(response, request)
		if response.Code != http.StatusCreated {
			t.Fatalf("issue: status=%d body=%s", response.Code, response.Body)
		}
		var body loginCaptchaResponse
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		var binding *http.Cookie
		for _, cookie := range response.Result().Cookies() {
			if cookie.Name == identity.LoginCaptchaBindingCookie {
				binding = cookie
			}
		}
		if binding == nil || len(binding.Value) != 43 || binding.Path != "/v1/auth" || !binding.HttpOnly || !binding.Secure ||
			binding.SameSite != http.SameSiteLaxMode || binding.MaxAge < 290 || binding.MaxAge > 300 {
			t.Fatalf("binding cookie = %#v", binding)
		}
		var stored []byte
		var source string
		if err := pool.QueryRow(ctx, `SELECT binding_digest, source_ip FROM identity_login_captchas WHERE id=$1`, body.ID).
			Scan(&stored, &source); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(stored, captchaTestDigest(throttleKey, "binding", body.ID, binding.Value)) || source != edge {
			t.Fatalf("stored binding %x source %q", stored, source)
		}
		// The planted answer is in logincaptcha.Alphabet, which the look-alike mapping leaves as is (normalizeCaptchaAnswer).
		if _, err := pool.Exec(ctx, `UPDATE identity_login_captchas SET answer_digest=$2 WHERE id=$1`,
			body.ID, captchaTestDigest(throttleKey, "answer", body.ID, "A72CD")); err != nil {
			t.Fatal(err)
		}
		return body.ID, binding
	}
	register := func(edge, username string, id uuid.UUID, cookie *http.Cookie) *httptest.ResponseRecorder {
		t.Helper()
		body := `{"username":"` + username + `","password":"Correct-horse-battery-1","display_name":"` + username + `",` +
			`"email":"` + username + `@example.com","verification_channel":"email","captcha":{"id":"` + id.String() + `","answer":"A72CD"}}`
		request := httptest.NewRequest(http.MethodPost, "/v1/auth/register", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Idempotency-Key", "register-"+uuid.NewString())
		request.RemoteAddr = edge + ":443"
		if cookie != nil {
			request.AddCookie(&http.Cookie{Name: cookie.Name, Value: cookie.Value})
		}
		response := httptest.NewRecorder()
		api.ServeHTTP(response, request)
		return response
	}
	consumed := func(id uuid.UUID) bool {
		t.Helper()
		var spent bool
		if err := pool.QueryRow(ctx, `SELECT consumed_at IS NOT NULL FROM identity_login_captchas WHERE id=$1`, id).Scan(&spent); err != nil {
			t.Fatal(err)
		}
		return spent
	}
	const issueEdge, submitEdge = "104.23.1.10", "162.159.2.20"

	id, cookie := issue(issueEdge)
	if response := register(submitEdge, "bind-across-edges", id, cookie); response.Code != http.StatusAccepted {
		t.Fatalf("other edge, same browser: status=%d body=%s", response.Code, response.Body)
	}
	if len(store.records) != 1 || !consumed(id) {
		t.Fatalf("records=%d consumed=%v", len(store.records), consumed(id))
	}
	if response := register(submitEdge, "bind-replay", id, cookie); response.Code != http.StatusUnprocessableEntity ||
		!strings.Contains(response.Body.String(), "account_registration_captcha_invalid") {
		t.Fatalf("second use: status=%d body=%s", response.Code, response.Body)
	}

	missing, _ := issue(issueEdge)
	if response := register(issueEdge, "bind-no-cookie", missing, nil); response.Code != http.StatusUnprocessableEntity ||
		!strings.Contains(response.Body.String(), "account_registration_captcha_invalid") || !consumed(missing) {
		t.Fatalf("no cookie: status=%d body=%s consumed=%v", response.Code, response.Body, consumed(missing))
	}

	// the cookie of another browser (both
	// fetched without one, so each got its own binding) is refused, and the
	// image is not burned: it was not looked at, and only its own browser can
	// spend it.
	mine, mineCookie := issue(issueEdge)
	_, other := issue(issueEdge)
	if response := register(issueEdge, "bind-other-cookie", mine, other); response.Code != http.StatusUnprocessableEntity ||
		!strings.Contains(response.Body.String(), "account_registration_captcha_invalid") || consumed(mine) {
		t.Fatalf("other browser's cookie: status=%d body=%s consumed=%v", response.Code, response.Body, consumed(mine))
	}
	forged := &http.Cookie{Name: identity.LoginCaptchaBindingCookie, Value: strings.Repeat("A", 43)}
	if response := register(issueEdge, "bind-forged-cookie", mine, forged); response.Code != http.StatusUnprocessableEntity || !consumed(mine) {
		t.Fatalf("forged cookie: status=%d body=%s consumed=%v", response.Code, response.Body, consumed(mine))
	}
	if response := register(issueEdge, "bind-burned", mine, mineCookie); response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("burned image: status=%d body=%s", response.Code, response.Body)
	}
	if len(store.records) != 1 {
		t.Fatalf("refused sign-ups were stored: %d", len(store.records))
	}
}

// captchaBrowser is one browser's cookie jar (every cookie here has Path=/v1/auth).
type captchaBrowser map[string]string

func (browser captchaBrowser) send(request *http.Request) {
	for name, value := range browser {
		request.AddCookie(&http.Cookie{Name: name, Value: value})
	}
}

// keep stores the cookies a response set, as the browser does when it arrives.
func (browser captchaBrowser) keep(response *httptest.ResponseRecorder) {
	for _, cookie := range response.Result().Cookies() {
		browser[cookie.Name] = cookie.Value
	}
}

// two tabs of one browser share its cookies.
// An image fetched with the browser binding cookie reuses it; an image whose
// fetch minted the binding also gets its own short-lived cookie, so when two
// tabs of a clean browser fetch their first image at once (neither request
// carries a cookie) and the later response replaces the browser cookie, both
// images still pass, whichever response arrives first. Another browser is refused.
func TestBuiltInRegisterCaptchaTabsOfOneBrowser(t *testing.T) {
	pool, api, store, throttleKey := newCaptchaRegisterAPI(t)
	ctx := context.Background()
	// fetch sends the request with the browser's cookies as they are now; the
	// caller keeps the response when it "arrives"
	fetch := func(browser captchaBrowser) (uuid.UUID, *httptest.ResponseRecorder) {
		t.Helper()
		request := httptest.NewRequest(http.MethodPost, "/v1/auth/login-captchas", nil)
		request.RemoteAddr = "104.23.1.10:443"
		browser.send(request)
		response := httptest.NewRecorder()
		api.ServeHTTP(response, request)
		var body loginCaptchaResponse
		if response.Code != http.StatusCreated || json.Unmarshal(response.Body.Bytes(), &body) != nil {
			t.Fatalf("issue: status=%d body=%s", response.Code, response.Body)
		}
		if _, err := pool.Exec(ctx, `UPDATE identity_login_captchas SET answer_digest=$2 WHERE id=$1`,
			body.ID, captchaTestDigest(throttleKey, "answer", body.ID, "A72CD")); err != nil {
			t.Fatal(err)
		}
		return body.ID, response
	}
	issue := func(browser captchaBrowser) uuid.UUID {
		t.Helper()
		id, response := fetch(browser)
		browser.keep(response)
		return id
	}
	register := func(username string, id uuid.UUID, browser captchaBrowser) int {
		t.Helper()
		body := `{"username":"` + username + `","password":"Correct-horse-battery-1","display_name":"` + username + `",` +
			`"email":"` + username + `@example.com","verification_channel":"email","captcha":{"id":"` + id.String() + `","answer":"A72CD"}}`
		request := httptest.NewRequest(http.MethodPost, "/v1/auth/register", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Idempotency-Key", "register-"+uuid.NewString())
		request.RemoteAddr = "162.159.2.20:443"
		browser.send(request)
		response := httptest.NewRecorder()
		api.ServeHTTP(response, request)
		return response.Code
	}
	registered := 0
	pass := func(name, username string, id uuid.UUID, browser captchaBrowser) {
		t.Helper()
		if code := register(username, id, browser); code != http.StatusAccepted {
			t.Fatalf("%s: %d", name, code)
		}
		registered++
	}

	// clean browser, both tabs fetch their first image at once; the responses
	// arrive in order (B's replaces the browser cookie) or in reverse order
	for _, reverse := range []bool{false, true} {
		browser := captchaBrowser{}
		tabA, responseA := fetch(browser)
		tabB, responseB := fetch(browser)
		if reverse {
			browser.keep(responseB)
			browser.keep(responseA)
		} else {
			browser.keep(responseA)
			browser.keep(responseB)
		}
		images := 0
		for name := range browser {
			if name != identity.LoginCaptchaBindingCookie {
				images++
			}
		}
		if images != 2 {
			t.Fatalf("image cookies = %v", browser)
		}
		pass("tab A, first fetch at once", "tabs-a"+map[bool]string{false: "", true: "-r"}[reverse], tabA, browser)
		pass("tab B, first fetch at once", "tabs-b"+map[bool]string{false: "", true: "-r"}[reverse], tabB, browser)
		// the next image reuses the browser cookie and sets no image cookie
		before := len(browser)
		tabA = issue(browser)
		if len(browser) != before {
			t.Fatalf("a reused binding set an image cookie: %v", browser)
		}
		pass("tab A, next image", "tabs-n"+map[bool]string{false: "", true: "-r"}[reverse], tabA, browser)
	}

	// stable binding, then both tabs fetch at once: one value, both pass
	browser := captchaBrowser{}
	issue(browser)
	stable := browser[identity.LoginCaptchaBindingCookie]
	tabC, responseC := fetch(browser)
	tabD, responseD := fetch(browser)
	browser.keep(responseD)
	browser.keep(responseC)
	if browser[identity.LoginCaptchaBindingCookie] != stable || len(browser) != 2 {
		t.Fatalf("stable binding changed: %v", browser)
	}
	pass("tab C, stable binding", "tabs-c", tabC, browser)
	pass("tab D, stable binding", "tabs-d", tabD, browser)

	// another browser: no cookie, or its own (it fetched an image too)
	other := captchaBrowser{}
	issue(other)
	for name, cookies := range map[string]captchaBrowser{"no cookie": {}, "its own cookies": other} {
		mine := issue(browser)
		if code := register("tabs-other", mine, cookies); code != http.StatusUnprocessableEntity {
			t.Fatalf("another browser, %s: %d", name, code)
		}
	}
	// a cookie of another image is not this image's
	mine := issue(browser)
	stray := captchaBrowser{identity.LoginCaptchaImageBindingCookie(mine): other[identity.LoginCaptchaBindingCookie]}
	if code := register("tabs-stray", mine, stray); code != http.StatusUnprocessableEntity {
		t.Fatalf("another browser's binding under this image's cookie name: %d", code)
	}
	if len(store.records) != registered {
		t.Fatalf("records = %d, want %d", len(store.records), registered)
	}
}
