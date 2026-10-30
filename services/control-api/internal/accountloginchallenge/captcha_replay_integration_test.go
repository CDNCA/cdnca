package accountloginchallenge

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/systemusersettings"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type externalLoginPolicy struct{}

func (externalLoginPolicy) GetPublic(context.Context, uuid.UUID) (systemusersettings.PublicSettings, error) {
	return systemusersettings.PublicSettings{EmailCodeLoginEnabled: true, EmailAntiAbuseMode: "tencent"}, nil
}

type acceptingHumanVerifier struct{ calls int }

func (verifier *acceptingHumanVerifier) Verify(context.Context, string, string, string) error {
	verifier.calls++
	return nil
}

// fix-smallfu：服务商二次校验通过之后，同一外部验证码票据第二次新建登录挑战被本地拒绝；
// 同一幂等键的重试按原结果返回；过期后摘要行可被覆盖并被清理。
func TestPostgresLoginChallengeRejectsReusedExternalCaptchaTicket(t *testing.T) {
	pool := accountLoginChallengePool(t)
	scopeID, userID := uuid.New(), uuid.New()
	if _, err := pool.Exec(t.Context(), `
		INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'platform',NULL);
		INSERT INTO users(id,username,display_name,email,phone,password_hash,status)
			VALUES($2,'captcha-replay-owner','Captcha replay owner','replay@example.test','+8613812345679','not-used','active');
		INSERT INTO memberships(scope_id,user_id,status) VALUES($1,$2,'active')`,
		pgx.QueryExecModeSimpleProtocol, scopeID, userID); err != nil {
		t.Fatal(err)
	}
	tokens, err := identity.NewTokenManager(strings.Repeat("l", 32), 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := identity.NewService(identity.NewStore(pool), tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	human := new(acceptingHumanVerifier)
	service, err := NewService(pool, Config{
		DigestKey: []byte(strings.Repeat("d", 32)), Policy: externalLoginPolicy{}, Human: human, Issuer: issuer,
		Contacts: new(capturingLoginContacts), Clock: func() time.Time { return now },
		Entropy: strings.NewReader(strings.Repeat("\x00", 256)), SourceLimit: 1000, SubjectLimit: 1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	create := func(key, token string) (CreateResult, error) {
		return service.Create(t.Context(), CreateInput{
			ScopeID: scopeID, Identifier: "replay@example.test", Channel: notification.ChannelEmail, Source: "192.0.2.45",
			HumanToken: token, IdempotencyKey: key, RequestID: key,
		})
	}
	ticket := `{"ticket":"ticket-replay-1","randstr":"rand-1"}`
	first, err := create("captcha-replay-1", ticket)
	if err != nil || first.ChallengeID == uuid.Nil {
		t.Fatalf("first use = (%+v, %v)", first, err)
	}
	if retried, err := create("captcha-replay-1", ticket); err != nil || !retried.Replayed || retried.ChallengeID != first.ChallengeID {
		t.Fatalf("same idempotency retry = (%+v, %v)", retried, err)
	}
	// 改写 JSON（键序、randstr）也是同一票据。
	if _, err := create("captcha-replay-2", `{"randstr":"rand-2","ticket":"ticket-replay-1"}`); !errors.Is(err, ErrHumanInvalid) {
		t.Fatalf("reused ticket error = %v, want %v", err, ErrHumanInvalid)
	}
	if _, err := create("captcha-replay-3", `{"ticket":"ticket-replay-2","randstr":"rand-1"}`); err != nil {
		t.Fatalf("fresh ticket error = %v", err)
	}
	var rows int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM account_login_captcha_replay_568 WHERE provider='tencent'`).Scan(&rows); err != nil || rows != 2 {
		t.Fatalf("replay rows = %d err %v", rows, err)
	}
	var stored int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM account_login_captcha_replay_568
		WHERE position('ticket-replay' in encode(token_digest,'escape')) > 0`).Scan(&stored); err != nil || stored != 0 {
		t.Fatalf("raw ticket persisted: %d err %v", stored, err)
	}

	now = now.Add(captchaReplayTTL + time.Second)
	if _, err := create("captcha-replay-4", ticket); err != nil {
		t.Fatalf("expired ticket digest must be reclaimable, error = %v", err)
	}
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM account_login_captcha_replay_568`).Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("expired rows were not cleaned: rows=%d err=%v", rows, err)
	}
}
