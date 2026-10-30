package identity

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/netip"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Password sign-in throttle. The platform settings login_failure_limit_per_hour and
// login_captcha_threshold_per_hour are enforced here for every password
// attempt (POST /v1/auth/login and the password form of
// POST /v1/auth/login-challenges):
//
//   - account+source: once an account has `limit` credential failures from one
//     source address in the last hour, that pair is locked until the oldest
//     failure leaves the window (Retry-After tells when). Another address can
//     still sign in, so an attacker cannot lock the real user out.
//   - source: once one address has `limit`*sourceLimitFactor failures across
//     all accounts in the hour, it is locked (password spraying).
//   - CAPTCHA: once an account+source pair, or a source across accounts, has
//     `threshold` failures, the next attempt must carry a solved built-in
//     CAPTCHA (POST /v1/auth/login-captchas). A wrong CAPTCHA does not count
//     as a credential failure and the password is not checked.
//
// The attempt row is written (and the limit checked) before the password hash
// is compared, under a per-account advisory lock, so parallel requests cannot
// pass the limit together. Rows of attempts that were not credential failures
// are removed again; a successful sign-in clears the pair's failures.

const (
	loginThrottleWindow   = time.Hour
	sourceLimitFactor     = 5
	loginCaptchaTTL       = 5 * time.Minute
	loginCaptchaLength    = 5
	loginCaptchaPerSource = 30 // CAPTCHA images per source per window
	loginCaptchaAlphabet  = "23456789ABCDEFGHJKMNPQRSTUVWXZ"
)

var (
	// ErrLoginCaptchaRequired: the next password attempt needs a solved built-in CAPTCHA.
	ErrLoginCaptchaRequired = errors.New("login captcha required")
	// ErrLoginCaptchaInvalid: the CAPTCHA was wrong, expired or already used.
	ErrLoginCaptchaInvalid = errors.New("login captcha invalid")
	// ErrLoginCaptchaRateLimited: too many CAPTCHA images requested from one source.
	ErrLoginCaptchaRateLimited = errors.New("login captcha rate limited")

	// errPasswordAccepted settles an attempt whose password was right but that
	// did not (yet) create a session: the attempt is forgotten, the earlier
	// failures stay.
	errPasswordAccepted = errors.New("password accepted")

	loginThrottleAccountDomain = []byte("cdnca/identity/login-throttle/v1/account\x00")
	loginCaptchaAnswerDomain   = []byte("cdnca/identity/login-captcha/v1/answer\x00")
)

// LoginThrottled is returned when an account+source pair or a source is locked.
type LoginThrottled struct {
	RetryAfter time.Duration
}

func (*LoginThrottled) Error() string { return "login throttled" }

// LoginCaptchaProof is the built-in CAPTCHA the client solved.
type LoginCaptchaProof struct {
	ID     uuid.UUID
	Answer string
}

// LoginCaptcha is a freshly issued challenge; Answer is rendered into the
// image by the HTTP adapter and never stored.
type LoginCaptcha struct {
	ID        uuid.UUID
	Answer    string
	ExpiresAt time.Time
}

type loginThrottlePolicy struct {
	limit     int
	threshold int
}

// loginThrottle is the per-attempt reservation; release forgets the attempt
// when it was not a credential failure.
type loginThrottle struct {
	store   *Store
	id      int64
	account []byte
	source  string
}

// SetLoginThrottleKey enables the throttle. The key keys the account digests
// and CAPTCHA answer digests; it must be at least 32 bytes.
func (s *Service) SetLoginThrottleKey(key []byte) error {
	if s == nil || len(key) < 32 {
		return errors.New("login throttle key must be at least 32 bytes")
	}
	s.throttleKey = append([]byte(nil), key...)
	return nil
}

func (s *Service) loginThrottleEnabled() bool {
	return s != nil && len(s.throttleKey) >= 32 && s.store != nil && s.store.pool != nil
}

func (s *Service) throttlePolicy(ctx context.Context) (loginThrottlePolicy, error) {
	policy := loginThrottlePolicy{limit: 30, threshold: 3}
	if s.publicSettings == nil {
		return policy, nil
	}
	settings, err := s.publicSettings.GetPublic(ctx, uuid.Nil)
	if err != nil {
		return loginThrottlePolicy{}, fmt.Errorf("read login throttle policy: %w", err)
	}
	if settings.LoginFailureLimitPerHour >= 1 {
		policy.limit = settings.LoginFailureLimitPerHour
	}
	if settings.LoginCaptchaThresholdPerHour >= 1 && settings.LoginCaptchaThresholdPerHour <= policy.limit {
		policy.threshold = settings.LoginCaptchaThresholdPerHour
	}
	return policy, nil
}

func throttleSource(raw string) string {
	address, err := netip.ParseAddr(raw)
	if err != nil || address.Zone() != "" {
		return "unknown"
	}
	return address.Unmap().String()
}

func (s *Service) accountDigest(username string) []byte {
	mac := hmac.New(sha256.New, s.throttleKey)
	_, _ = mac.Write(loginThrottleAccountDomain)
	_, _ = mac.Write([]byte(strings.ToLower(strings.TrimSpace(username))))
	return mac.Sum(nil)
}

func (s *Service) captchaDigest(id uuid.UUID, answer string) []byte {
	mac := hmac.New(sha256.New, s.throttleKey)
	_, _ = mac.Write(loginCaptchaAnswerDomain)
	_, _ = mac.Write([]byte(id.String()))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(strings.ToUpper(strings.TrimSpace(answer))))
	return mac.Sum(nil)
}

// reserveLoginAttempt checks the throttle for one password attempt and, when
// it may proceed, records it. A nil reservation means the throttle is off.
func (s *Service) reserveLoginAttempt(ctx context.Context, username string, request RequestInfo, captcha *LoginCaptchaProof) (*loginThrottle, error) {
	if !s.loginThrottleEnabled() {
		return nil, nil
	}
	policy, err := s.throttlePolicy(ctx)
	if err != nil {
		return nil, err
	}
	account, source := s.accountDigest(username), throttleSource(request.SourceIP)
	now := s.now().UTC()
	since := now.Add(-loginThrottleWindow)
	var reservation *loginThrottle
	var outcome error
	err = pgx.BeginFunc(ctx, s.store.pool, func(tx pgx.Tx) error {
		// One lock per account and one per source serialize the count+insert.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('identity-login-throttle:account:' || encode($1::bytea,'hex'),0)),
			pg_advisory_xact_lock(hashtextextended('identity-login-throttle:source:' || $2,0))`, account, source); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM identity_login_attempts WHERE occurred_at < $1`, since); err != nil {
			return err
		}
		var pairCount, sourceCount int
		var pairOldest, sourceOldest *time.Time
		if err := tx.QueryRow(ctx, `SELECT
			count(*) FILTER (WHERE account_digest=$1 AND source_ip=$2),
			min(occurred_at) FILTER (WHERE account_digest=$1 AND source_ip=$2),
			count(*) FILTER (WHERE source_ip=$2),
			min(occurred_at) FILTER (WHERE source_ip=$2)
			FROM identity_login_attempts WHERE occurred_at >= $3 AND (account_digest=$1 OR source_ip=$2)`,
			account, source, since).Scan(&pairCount, &pairOldest, &sourceCount, &sourceOldest); err != nil {
			return err
		}
		switch {
		case pairCount >= policy.limit:
			outcome = &LoginThrottled{RetryAfter: retryAfter(now, pairOldest)}
			return nil
		case sourceCount >= policy.limit*sourceLimitFactor:
			outcome = &LoginThrottled{RetryAfter: retryAfter(now, sourceOldest)}
			return nil
		}
		if pairCount >= policy.threshold || sourceCount >= policy.threshold*sourceLimitFactor {
			if captcha == nil || captcha.ID == uuid.Nil || captcha.Answer == "" {
				outcome = ErrLoginCaptchaRequired
				return nil
			}
			// The CAPTCHA is consumed whether or not it matches, so it cannot
			// be brute forced; a wrong answer is not a credential failure.
			tag, err := tx.Exec(ctx, `UPDATE identity_login_captchas SET consumed_at=$4
				WHERE id=$1 AND consumed_at IS NULL AND expires_at > $4 AND source_ip=$3 AND answer_digest=$2`,
				captcha.ID, s.captchaDigest(captcha.ID, captcha.Answer), source, now)
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 1 {
				if _, err := tx.Exec(ctx, `UPDATE identity_login_captchas SET consumed_at=$2 WHERE id=$1 AND consumed_at IS NULL`, captcha.ID, now); err != nil {
					return err
				}
				outcome = ErrLoginCaptchaInvalid
				return nil
			}
		}
		var id int64
		if err := tx.QueryRow(ctx, `INSERT INTO identity_login_attempts(account_digest,source_ip,occurred_at) VALUES($1,$2,$3) RETURNING id`,
			account, source, now).Scan(&id); err != nil {
			return err
		}
		reservation = &loginThrottle{store: s.store, id: id, account: account, source: source}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("reserve login attempt: %w", err)
	}
	if outcome != nil {
		s.auditThrottleDenial(ctx, source, request.RequestID, outcome)
	}
	return reservation, outcome
}

// auditThrottleDenial records a refused attempt on the platform scope. The
// account is identified only by its keyed digest: the username may not exist.
func (s *Service) auditThrottleDenial(ctx context.Context, source, requestID string, outcome error) {
	reason := "captcha_required"
	var throttled *LoginThrottled
	switch {
	case errors.As(outcome, &throttled):
		reason = "throttled"
	case errors.Is(outcome, ErrLoginCaptchaInvalid):
		reason = "captcha_invalid"
	}
	address := source
	if address == "unknown" {
		address = ""
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	err := pgx.BeginFunc(ctx, s.store.pool, func(tx pgx.Tx) error {
		var scopeID uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform' ORDER BY created_at, id LIMIT 1`).Scan(&scopeID); err != nil {
			return err
		}
		return s.store.auditor.Append(ctx, tx, audit.Event{
			ScopeID: scopeID, Action: "auth.login.throttled", ResourceType: "login_source", ResourceID: source, RequestID: requestID,
			Result: "denied", ReasonCode: reason, SourceIP: address,
			Payload: map[string]any{"reason_code": reason, "source_ip": source},
		})
	})
	if err != nil {
		// The refusal itself stands; a lost audit row must not turn it into a 500.
		slog.WarnContext(ctx, "sign-in throttle audit failed", "reason_code", reason, "error", err)
	}
}

func retryAfter(now time.Time, oldest *time.Time) time.Duration {
	if oldest == nil {
		return loginThrottleWindow
	}
	wait := oldest.Add(loginThrottleWindow).Sub(now)
	if wait < time.Second {
		return time.Second
	}
	return wait.Truncate(time.Second) + time.Second
}

// settle keeps the attempt when it was a credential failure, forgets it
// otherwise, and clears the account+source failures after a successful sign-in.
func (reservation *loginThrottle) settle(ctx context.Context, err error) {
	if reservation == nil {
		return
	}
	// The request may already be cancelled; the bookkeeping must still land.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	switch {
	case errors.Is(err, ErrInvalidCredentials):
		return
	case err == nil:
		_, _ = reservation.store.pool.Exec(ctx, `DELETE FROM identity_login_attempts WHERE account_digest=$1 AND source_ip=$2`,
			reservation.account, reservation.source)
	default:
		_, _ = reservation.store.pool.Exec(ctx, `DELETE FROM identity_login_attempts WHERE id=$1`, reservation.id)
	}
}

// IssueLoginCaptcha creates a one-time built-in CAPTCHA bound to the source.
func (s *Service) IssueLoginCaptcha(ctx context.Context, sourceIP string) (LoginCaptcha, error) {
	if !s.loginThrottleEnabled() {
		return LoginCaptcha{}, ErrLoginSecurityUnavailable
	}
	source := throttleSource(sourceIP)
	answer, err := randomCaptchaAnswer()
	if err != nil {
		return LoginCaptcha{}, err
	}
	id, err := newUUID()
	if err != nil {
		return LoginCaptcha{}, err
	}
	now := s.now().UTC()
	result := LoginCaptcha{ID: id, Answer: answer, ExpiresAt: now.Add(loginCaptchaTTL)}
	var limited bool
	err = pgx.BeginFunc(ctx, s.store.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('identity-login-captcha:source:' || $1,0))`, source); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM identity_login_captchas WHERE expires_at < $1`, now.Add(-loginThrottleWindow)); err != nil {
			return err
		}
		var issued int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM identity_login_captchas WHERE source_ip=$1 AND created_at >= $2`,
			source, now.Add(-loginThrottleWindow)).Scan(&issued); err != nil {
			return err
		}
		if issued >= loginCaptchaPerSource {
			limited = true
			return nil
		}
		_, err := tx.Exec(ctx, `INSERT INTO identity_login_captchas(id,answer_digest,source_ip,created_at,expires_at) VALUES($1,$2,$3,$4,$5)`,
			id, s.captchaDigest(id, answer), source, now, result.ExpiresAt)
		return err
	})
	if err != nil {
		return LoginCaptcha{}, fmt.Errorf("issue login captcha: %w", err)
	}
	if limited {
		return LoginCaptcha{}, ErrLoginCaptchaRateLimited
	}
	return result, nil
}

func randomCaptchaAnswer() (string, error) {
	var builder strings.Builder
	limit := big.NewInt(int64(len(loginCaptchaAlphabet)))
	for range loginCaptchaLength {
		index, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return "", fmt.Errorf("generate login captcha: %w", err)
		}
		builder.WriteByte(loginCaptchaAlphabet[index.Int64()])
	}
	return builder.String(), nil
}
