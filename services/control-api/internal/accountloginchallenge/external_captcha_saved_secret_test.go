package accountloginchallenge

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/systemusersettings"
)

// secrets saved on the settings page reach the
// provider without any reference or ACCOUNT_LOGIN_CAPTCHA_SECRETS_JSON entry,
// and take precedence over a reference.
func TestTencentCaptchaUsesSecretsSavedOnThePage(t *testing.T) {
	t.Parallel()

	const savedID, savedKey, savedApp = "AKIDsavedonthepage0000001", "saved-secret-key-0123456789", "saved-app-secret-0123456789"
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		var payload map[string]any
		host := strings.TrimPrefix(strings.TrimPrefix(request.Host, "https://"), "http://")
		want := "TC3-HMAC-SHA256 Credential=" + savedID + "/" + time.Unix(1760662800, 0).UTC().Format("2006-01-02") + "/captcha/tc3_request, " +
			"SignedHeaders=content-type;host;x-tc-action, Signature=" +
			tc3Signature([]byte(savedKey), 1760662800, "captcha", tc3StringToSign(1760662800, "captcha", tc3CanonicalRequest(host, "DescribeCaptchaResult", body)))
		if json.Unmarshal(body, &payload) != nil || payload["AppSecretKey"] != savedApp || request.Header.Get("Authorization") != want {
			http.Error(writer, "unexpected request", http.StatusBadRequest)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"Response":{"CaptchaCode":1,"RequestId":"r-1"}}`))
	}))
	defer server.Close()
	proof := `{"ticket":"ticket-1","randstr":"rand-1"}`

	saved := systemusersettings.CaptchaRuntime{Provider: "tencent", AppID: "190000001",
		SecretID: savedID, SecretKey: savedKey, AppSecret: savedApp}
	if err := newCaptchaTestVerifier(t, server, saved, StaticSecretResolver{}).Verify(t.Context(), "tencent", proof, "203.0.113.7"); err != nil {
		t.Fatalf("saved secrets rejected: %v", err)
	}
	// the saved values win over references that resolve to other secrets
	both := captchaTestRuntime("tencent", "190000001")
	both.SecretID, both.SecretKey, both.AppSecret = savedID, savedKey, savedApp
	if err := newCaptchaTestVerifier(t, server, both, captchaTestSecrets()).Verify(t.Context(), "tencent", proof, "203.0.113.7"); err != nil {
		t.Fatalf("saved secrets next to references rejected: %v", err)
	}
	// nothing saved and no mapping: fail closed as before
	if err := newCaptchaTestVerifier(t, server, systemusersettings.CaptchaRuntime{Provider: "tencent", AppID: "190000001"},
		StaticSecretResolver{}).Verify(t.Context(), "tencent", proof, "203.0.113.7"); err == nil {
		t.Fatal("verification without any secret succeeded")
	}
}
