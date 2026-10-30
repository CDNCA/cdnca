package accountloginchallenge

import (
	"testing"
	"time"
)

// fix-smallfu：外部验证码本地防重放按服务商的一次性票据计算摘要，改写 JSON（空白、键序）也绕不过。
func TestCaptchaReplayKeyUsesProviderTicket(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	tencent, ok := captchaReplayDigest(key, "tencent", `{"ticket":"ticket-1","randstr":"rand-1"}`)
	if !ok {
		t.Fatal("valid tencent proof has no replay digest")
	}
	reformatted, ok := captchaReplayDigest(key, "tencent", "{ \"randstr\":\"rand-2\",\n \"ticket\":\"ticket-1\" }")
	if !ok || reformatted != tencent {
		t.Fatal("reformatted tencent proof with the same ticket must map to the same digest")
	}
	other, _ := captchaReplayDigest(key, "tencent", `{"ticket":"ticket-2","randstr":"rand-1"}`)
	if other == tencent {
		t.Fatal("different tickets share a digest")
	}
	geetest, ok := captchaReplayDigest(key, "geetest_v4",
		`{"lot_number":"ticket-1","captcha_output":"o","pass_token":"p","gen_time":"1"}`)
	if !ok || geetest == tencent {
		t.Fatal("geetest digest must exist and be separated from tencent by provider")
	}
	again, _ := captchaReplayDigest(key, "geetest_v4",
		`{"gen_time":"2","pass_token":"q","captcha_output":"x","lot_number":"ticket-1"}`)
	if again != geetest {
		t.Fatal("geetest replay digest must follow lot_number only")
	}
	for _, invalid := range []struct{ mode, token string }{
		{"tencent", `{"ticket":"","randstr":"r"}`},
		{"tencent", `{"ticket":"t","randstr":"r","extra":1}`},
		{"geetest_v4", `{"lot_number":"l"}`},
		{"native", `{"ticket":"t","randstr":"r"}`},
	} {
		if _, ok := captchaReplayDigest(key, invalid.mode, invalid.token); ok {
			t.Fatalf("captchaReplayDigest(%s, %s) unexpectedly ok", invalid.mode, invalid.token)
		}
	}
	if captchaReplayTTL < 5*time.Minute {
		t.Fatalf("replay TTL %v must outlive provider ticket validity", captchaReplayTTL)
	}
}
