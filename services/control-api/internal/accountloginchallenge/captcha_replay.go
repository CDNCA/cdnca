package accountloginchallenge

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// fix-smallfu：外部验证码（腾讯 / 极验 v4）本地防重放。服务商侧的一次性校验之外，
// 主控按"服务商 + 一次性票据"的 HMAC 摘要记一行（迁移 568 account_login_captcha_replay），
// 同一票据第二次用于新建登录挑战一律拒绝；行按 TTL 过期，过期行允许被覆盖并在提交后有界清理。
const (
	captchaReplayTTL          = 30 * time.Minute
	captchaReplayCleanupBatch = 256
)

var captchaReplayDigestDomain = []byte("account-login-challenge:v1:captcha-replay\x00")

// captchaReplayDigest 只取服务商的一次性票据（腾讯 ticket、极验 lot_number）：
// 改写 JSON 空白、键序或其它字段都映射到同一摘要。校验边界与服务端二次校验一致。
func captchaReplayDigest(key []byte, mode, token string) ([32]byte, bool) {
	var ticket string
	switch mode {
	case "tencent":
		var proof struct {
			Ticket  string `json:"ticket"`
			Randstr string `json:"randstr"`
		}
		if !decodeCaptchaProof(token, &proof) || !boundedCaptchaValue(proof.Ticket, 2048) || !boundedCaptchaValue(proof.Randstr, 512) {
			return [32]byte{}, false
		}
		ticket = proof.Ticket
	case "geetest_v4":
		var proof struct {
			LotNumber     string `json:"lot_number"`
			CaptchaOutput string `json:"captcha_output"`
			PassToken     string `json:"pass_token"`
			GenTime       string `json:"gen_time"`
		}
		if !decodeCaptchaProof(token, &proof) || !boundedCaptchaValue(proof.LotNumber, 256) ||
			!boundedCaptchaValue(proof.CaptchaOutput, 2048) || !boundedCaptchaValue(proof.PassToken, 512) ||
			!boundedCaptchaValue(proof.GenTime, 32) {
			return [32]byte{}, false
		}
		ticket = proof.LotNumber
	default:
		return [32]byte{}, false
	}
	return digestParts(key, captchaReplayDigestDomain, []byte(mode), []byte(ticket)), true
}

// claimCaptchaReplay 在登录挑战写事务里占用票据摘要；返回 false 表示该票据已在 TTL 内用过。
// 只有已过期的旧行可以被覆盖，所以并发的两次使用至多一次成功（另一次看到冲突或可串行化失败）。
func claimCaptchaReplay(ctx context.Context, tx pgx.Tx, digest [32]byte, provider string, now time.Time) (bool, error) {
	tag, err := tx.Exec(ctx, `INSERT INTO account_login_captcha_replay_568(token_digest,provider,used_at,expires_at)
		VALUES($1,$2,$3,$4)
		ON CONFLICT(token_digest) DO UPDATE SET provider=EXCLUDED.provider,used_at=EXCLUDED.used_at,expires_at=EXCLUDED.expires_at
		WHERE account_login_captcha_replay_568.expires_at<=EXCLUDED.used_at`,
		digest[:], provider, now, now.Add(captchaReplayTTL))
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// cleanupCaptchaReplay 有界删除已过期的摘要行；在写事务提交后单独执行，失败只留到下次。
func cleanupCaptchaReplay(ctx context.Context, pool *pgxpool.Pool, now time.Time) (int64, error) {
	tag, err := pool.Exec(ctx, `DELETE FROM account_login_captcha_replay_568 WHERE token_digest IN (
		SELECT token_digest FROM account_login_captcha_replay_568 WHERE expires_at<=$1
		ORDER BY expires_at LIMIT $2)`, now, captchaReplayCleanupBatch)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
