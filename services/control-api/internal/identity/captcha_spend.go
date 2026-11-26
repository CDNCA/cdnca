package identity

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/refusalreason"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Internal reasons for ErrLoginCaptchaInvalid (problem 28). They reach only
// the "request refused" log line, never the response or the audit row.
const (
	CaptchaReasonMissing         = "captcha_missing"
	CaptchaReasonNotFound        = "captcha_not_found"
	CaptchaReasonConsumed        = "captcha_consumed"
	CaptchaReasonExpired         = "captcha_expired"
	CaptchaReasonBindingMismatch = "captcha_binding_mismatch"
	// CaptchaReasonBindingSuperseded: sent with another signed binding than
	// it was issued with (two tabs of one browser fetched their first image
	// at once, or another browser); refused, not burned.
	CaptchaReasonBindingSuperseded = "captcha_binding_superseded"
	CaptchaReasonAnswerMismatch    = "captcha_answer_mismatch"
)

type captchaDB interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

// LoginCaptchaBindingCookie is the HttpOnly cookie POST /v1/auth/login-captchas
// sets to LoginCaptcha.Binding; every HTTP adapter that spends a CAPTCHA
// passes its value on as LoginCaptchaProof.Binding.
const LoginCaptchaBindingCookie = "cdnca_captcha_bind"

// The browser binding is minted once and
// reused by every later image of that browser: 16 random bytes and a
// truncated HMAC over them under the throttle key, so it is recognised
// without a lookup. Each CAPTCHA stores the keyed digest of (its id, this value).
const (
	loginCaptchaBindingRandom = 16
	loginCaptchaBindingMAC    = 16
)

func (s *Service) newBrowserBinding() (string, error) {
	raw := make([]byte, loginCaptchaBindingRandom, loginCaptchaBindingRandom+loginCaptchaBindingMAC)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate login captcha binding: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(append(raw, s.browserBindingMAC(raw)...)), nil
}

func (s *Service) browserBindingMAC(random []byte) []byte {
	mac := hmac.New(sha256.New, s.throttleKey)
	_, _ = mac.Write(loginCaptchaBrowserDomain)
	_, _ = mac.Write(random)
	return mac.Sum(nil)[:loginCaptchaBindingMAC]
}

// signedBrowserBinding: binding is one this service minted (not absent,
// malformed, under another key, or the unsigned value of).
func (s *Service) signedBrowserBinding(binding string) bool {
	raw, err := base64.RawURLEncoding.DecodeString(binding)
	return err == nil && len(raw) == loginCaptchaBindingRandom+loginCaptchaBindingMAC &&
		hmac.Equal(raw[loginCaptchaBindingRandom:], s.browserBindingMAC(raw[:loginCaptchaBindingRandom]))
}

// LoginCaptchaImageBindingCookie is the short-lived cookie of one image,
// set (besides LoginCaptchaBindingCookie) only when its issue minted the
// browser binding: two tabs fetching their first image at once each mint
// one and the later response replaces the browser cookie, so each image
// keeps its own here. A spend reads it first, then the browser cookie.
func LoginCaptchaImageBindingCookie(id uuid.UUID) string {
	return LoginCaptchaBindingCookie + "_" + id.String()
}

type loginCaptchaBindingKey struct{}

// WithLoginCaptchaBinding records how to read the binding cookie of the
// request for an image (LoginCaptchaImageBindingCookie, else the browser
// cookie), for a CAPTCHA spent behind an interface that only carries a
// token (accountregistrationchallenge.CaptchaHumanVerifier).
func WithLoginCaptchaBinding(ctx context.Context, binding func(id uuid.UUID) string) context.Context {
	return context.WithValue(ctx, loginCaptchaBindingKey{}, binding)
}

// LoginCaptchaBindingFrom is the binding WithLoginCaptchaBinding records for image id.
func LoginCaptchaBindingFrom(ctx context.Context, id uuid.UUID) string {
	binding, _ := ctx.Value(loginCaptchaBindingKey{}).(func(uuid.UUID) string)
	if binding == nil {
		return ""
	}
	return binding(id)
}

// spendLoginCaptcha consumes one built-in CAPTCHA (the caller has checked ID
// and answer are present). It is spent only when it is unused, unexpired,
// sent with the browser binding it was issued with and the answer matches;
// the request source is not compared (behind a CDN without
// origin authentication issue and spend come from different edges). A
// CAPTCHA issued before migration 683 has no binding and never matches.
// Otherwise it is burned all the same (except when it comes with another
// signed binding: CaptchaReasonBindingSuperseded), so it cannot be brute forced, and
// ErrLoginCaptchaInvalid carries why (refusalreason). The why is read before
// the burn without a lock: a concurrent spend can make it say answer mismatch
// for one that was just consumed, which only affects the log line.
func (s *Service) spendLoginCaptcha(ctx context.Context, db captchaDB, captcha LoginCaptchaProof, now time.Time) error {
	binding := s.captchaBindingDigest(captcha.ID, captcha.Binding)
	tag, err := db.Exec(ctx, `UPDATE identity_login_captchas SET consumed_at=$4
		WHERE id=$1 AND consumed_at IS NULL AND expires_at > $4 AND binding_digest=$3 AND answer_digest=$2`,
		captcha.ID, s.captchaDigest(captcha.ID, captcha.Answer), binding, now)
	if err != nil {
		return fmt.Errorf("consume captcha: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	var consumed, expired, otherBinding bool
	reason := CaptchaReasonAnswerMismatch
	err = db.QueryRow(ctx, `SELECT consumed_at IS NOT NULL, expires_at <= $2, binding_digest IS DISTINCT FROM $3::bytea OR $3::bytea IS NULL
		FROM identity_login_captchas WHERE id=$1`, captcha.ID, now, binding).Scan(&consumed, &expired, &otherBinding)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		reason = CaptchaReasonNotFound
	case err != nil:
		return fmt.Errorf("classify captcha: %w", err)
	case consumed:
		reason = CaptchaReasonConsumed
	case expired:
		reason = CaptchaReasonExpired
	case otherBinding:
		// Another binding this service signed: typically two tabs of this
		// browser fetched their first image at once, each minted one and the
		// later response replaced the cookie. Refused without burning: the
		// answer was not compared, so leaving the image unspent tells nothing
		// and cannot be brute forced (it is spent only with its own binding);
		// the page fetches a new image, which reuses the cookie now set.
		if s.signedBrowserBinding(captcha.Binding) {
			return refusalreason.Wrap(ErrLoginCaptchaInvalid, CaptchaReasonBindingSuperseded)
		}
		reason = CaptchaReasonBindingMismatch
	}
	if _, err := db.Exec(ctx, `UPDATE identity_login_captchas SET consumed_at=$2 WHERE id=$1 AND consumed_at IS NULL`,
		captcha.ID, now); err != nil {
		return fmt.Errorf("burn captcha: %w", err)
	}
	return refusalreason.Wrap(ErrLoginCaptchaInvalid, reason)
}
