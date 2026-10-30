package accountloginchallenge

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/systemusersettings"
)

const (
	captchaTestSecretID  = "AKIDcaptchatestsecretid000001"
	captchaTestSecretKey = "captcha-test-secret-key-0123456789"
	captchaTestAppSecret = "captcha-test-app-secret-0123456789"
)

type captchaSettingsStub struct {
	runtime systemusersettings.CaptchaRuntime
}

func (stub captchaSettingsStub) CaptchaRuntime(context.Context) (systemusersettings.CaptchaRuntime, error) {
	return stub.runtime, nil
}

func captchaTestSecrets() StaticSecretResolver {
	return StaticSecretResolver{
		"vault://captcha/secret-id": captchaTestSecretID, "vault://captcha/secret-key": captchaTestSecretKey,
		"vault://captcha/app-secret": captchaTestAppSecret,
	}
}

func captchaTestRuntime(provider, appID string) systemusersettings.CaptchaRuntime {
	return systemusersettings.CaptchaRuntime{Provider: provider, SecretIDReference: "vault://captcha/secret-id",
		SecretKeyReference: "vault://captcha/secret-key", AppID: appID, AppSecretReference: "vault://captcha/app-secret"}
}

func newCaptchaTestVerifier(t *testing.T, server *httptest.Server, runtime systemusersettings.CaptchaRuntime, secrets SecretResolver) *ExternalCaptchaVerifier {
	t.Helper()
	verifier, err := NewExternalCaptchaVerifier(ExternalCaptchaConfig{
		Settings: captchaSettingsStub{runtime: runtime}, Secrets: secrets, Client: server.Client(),
		TencentEndpoint: server.URL + "/", GeetestEndpoint: server.URL + "/validate",
		Clock: func() time.Time { return time.Unix(1760662800, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}
	return verifier
}

// The canonical request and string-to-sign match Tencent Cloud's published
// signature v3 example (cloud.tencent.com/document/product/362/32489).
func TestTC3CanonicalRequestMatchesTencentPublishedExample(t *testing.T) {
	t.Parallel()

	payload := []byte(`{"Limit": 1, "Filters": [{"Values": ["\u672a\u547d\u540d"], "Name": "instance-name"}]}`)
	if got := sha256Hex(payload); got != "35e9c5b0e3ae67532d3c9f17ead6c90222632e5b1ff7f6e89887f1398934f064" {
		t.Fatalf("hashed payload = %s", got)
	}
	canonical := tc3CanonicalRequest("cvm.tencentcloudapi.com", "DescribeInstances", payload)
	if got := sha256Hex([]byte(canonical)); got != "7019a55be8395899b900fb5564e4200d984910f34794a27cb3fb7d10ff6a1e84" {
		t.Fatalf("hashed canonical request = %s\n%s", got, canonical)
	}
	want := "TC3-HMAC-SHA256\n1551113065\n2019-02-25/cvm/tc3_request\n7019a55be8395899b900fb5564e4200d984910f34794a27cb3fb7d10ff6a1e84"
	if got := tc3StringToSign(1551113065, "cvm", canonical); got != want {
		t.Fatalf("string to sign = %q", got)
	}
}

func TestTencentCaptchaUsesDescribeCaptchaResultWithCaptchaAppID(t *testing.T) {
	t.Parallel()

	var code atomic.Int64
	code.Store(1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		var payload map[string]any
		if json.Unmarshal(body, &payload) != nil || request.Method != http.MethodPost ||
			request.Header.Get("X-TC-Action") != "DescribeCaptchaResult" || request.Header.Get("X-TC-Version") != "2019-07-22" ||
			request.Header.Get("X-TC-Timestamp") != "1760662800" ||
			payload["CaptchaType"] != float64(9) || payload["CaptchaAppId"] != float64(190000001) ||
			payload["AppSecretKey"] != captchaTestAppSecret || payload["Ticket"] != "ticket-1" ||
			payload["Randstr"] != "rand-1" || payload["UserIp"] != "203.0.113.7" {
			http.Error(writer, "unexpected request", http.StatusBadRequest)
			return
		}
		host := strings.TrimPrefix(strings.TrimPrefix(request.Host, "https://"), "http://")
		canonical := tc3CanonicalRequest(host, "DescribeCaptchaResult", body)
		wantAuthorization := "TC3-HMAC-SHA256 Credential=" + captchaTestSecretID + "/" + time.Unix(1760662800, 0).UTC().Format("2006-01-02") + "/captcha/tc3_request, " +
			"SignedHeaders=content-type;host;x-tc-action, Signature=" +
			tc3Signature([]byte(captchaTestSecretKey), 1760662800, "captcha", tc3StringToSign(1760662800, "captcha", canonical))
		if request.Header.Get("Authorization") != wantAuthorization {
			http.Error(writer, "bad signature", http.StatusUnauthorized)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"Response":{"CaptchaCode":` + jsonInt(code.Load()) + `,"CaptchaMsg":"OK","EvilLevel":0,"RequestId":"r-1"}}`))
	}))
	defer server.Close()
	verifier := newCaptchaTestVerifier(t, server, captchaTestRuntime("tencent", "190000001"), captchaTestSecrets())
	proof := `{"ticket":"ticket-1","randstr":"rand-1"}`
	if err := verifier.Verify(t.Context(), "tencent", proof, "203.0.113.7"); err != nil {
		t.Fatalf("valid ticket rejected: %v", err)
	}
	code.Store(9) // ticket reused
	if err := verifier.Verify(t.Context(), "tencent", proof, "203.0.113.7"); !errors.Is(err, ErrHumanInvalid) {
		t.Fatalf("reused ticket error = %v", err)
	}
}

func TestTencentCaptchaRejectsCloudAPIErrorEnvelope(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"Response":{"Error":{"Code":"AuthFailure.SignatureFailure","Message":"x"},"CaptchaCode":1,"RequestId":"r"}}`))
	}))
	defer server.Close()
	verifier := newCaptchaTestVerifier(t, server, captchaTestRuntime("tencent", "190000001"), captchaTestSecrets())
	if err := verifier.Verify(t.Context(), "tencent", `{"ticket":"t","randstr":"r"}`, "203.0.113.7"); !errors.Is(err, ErrHumanInvalid) {
		t.Fatalf("error envelope accepted: %v", err)
	}
}

func TestGeetestV4CaptchaSignsLotNumberWithCaptchaKey(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_ = request.ParseForm()
		mac := hmac.New(sha256.New, []byte(captchaTestAppSecret))
		_, _ = mac.Write([]byte("lot-1"))
		result := "fail"
		if request.URL.Path == "/validate" && request.URL.Query().Get("captcha_id") == "gt-captcha-id" &&
			request.PostForm.Get("sign_token") == hex.EncodeToString(mac.Sum(nil)) &&
			request.PostForm.Get("captcha_output") == "out-1" && request.PostForm.Get("pass_token") == "pass-1" &&
			request.PostForm.Get("gen_time") == "1760662800" {
			result = "success"
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"status":"success","result":"` + result + `","reason":""}`))
	}))
	defer server.Close()
	verifier := newCaptchaTestVerifier(t, server, captchaTestRuntime("geetest_v4", "gt-captcha-id"), captchaTestSecrets())
	proof := `{"lot_number":"lot-1","captcha_output":"out-1","pass_token":"pass-1","gen_time":"1760662800"}`
	if err := verifier.Verify(t.Context(), "geetest_v4", proof, "203.0.113.7"); err != nil {
		t.Fatalf("valid geetest proof rejected: %v", err)
	}
	tampered := `{"lot_number":"lot-2","captcha_output":"out-1","pass_token":"pass-1","gen_time":"1760662800"}`
	if err := verifier.Verify(t.Context(), "geetest_v4", tampered, "203.0.113.7"); !errors.Is(err, ErrHumanInvalid) {
		t.Fatalf("tampered geetest proof error = %v", err)
	}
}

func TestExternalCaptchaFailsClosedBeforeCallingTheProvider(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"Response":{"CaptchaCode":1,"RequestId":"r"}}`))
	}))
	defer server.Close()
	cases := map[string]struct {
		runtime systemusersettings.CaptchaRuntime
		secrets SecretResolver
		mode    string
		proof   string
	}{
		"provider differs from mode": {captchaTestRuntime("geetest_v4", "gt"), captchaTestSecrets(), "tencent", `{"ticket":"t","randstr":"r"}`},
		"secret not configured":      {captchaTestRuntime("tencent", "190000001"), StaticSecretResolver{}, "tencent", `{"ticket":"t","randstr":"r"}`},
		"non-numeric tencent app id": {captchaTestRuntime("tencent", "app-1"), captchaTestSecrets(), "tencent", `{"ticket":"t","randstr":"r"}`},
		"unknown proof field":        {captchaTestRuntime("tencent", "190000001"), captchaTestSecrets(), "tencent", `{"ticket":"t","randstr":"r","x":1}`},
		"turnstile token":            {captchaTestRuntime("tencent", "190000001"), captchaTestSecrets(), "tencent", "0.turnstile-token-value"},
	}
	for name, test := range cases {
		verifier := newCaptchaTestVerifier(t, server, test.runtime, test.secrets)
		err := verifier.Verify(t.Context(), test.mode, test.proof, "203.0.113.7")
		if !errors.Is(err, ErrHumanInvalid) {
			t.Fatalf("%s: error = %v", name, err)
		}
		for _, secret := range []string{captchaTestSecretID, captchaTestSecretKey, captchaTestAppSecret} {
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("%s: error leaked a secret: %v", name, err)
			}
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("provider called %d times for rejected inputs", calls.Load())
	}
}

func TestParseCaptchaSecretsJSON(t *testing.T) {
	t.Parallel()

	secrets, err := ParseCaptchaSecretsJSON(`{"vault://captcha/app-secret":"` + captchaTestAppSecret + `"}`)
	if err != nil {
		t.Fatal(err)
	}
	if value, ok := secrets.ResolveSecret("vault://captcha/app-secret"); !ok || value != captchaTestAppSecret {
		t.Fatalf("resolved = (%q,%t)", value, ok)
	}
	for _, raw := range []string{`[]`, `{"plain":"x"}`, `{"vault://a":""}`, `{"vault://a":"x","vault://a":"y"}`, `{"vault://a":"line\nbreak"}`} {
		if _, err := ParseCaptchaSecretsJSON(raw); err == nil {
			t.Fatalf("invalid secrets %s accepted", url.QueryEscape(raw))
		}
	}
}

func jsonInt(value int64) string {
	raw, _ := json.Marshal(value)
	return string(raw)
}
