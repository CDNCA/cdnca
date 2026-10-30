package main

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/notificationruntime"
	"github.com/google/uuid"
)

// 阿里云官方签名示例（RPC 风格 v1，HMAC-SHA1，密钥 = AccessKeySecret + "&"）。
func TestAliyunSMSSignatureMatchesOfficialVector(t *testing.T) {
	params := url.Values{
		"AccessKeyId": {"testId"}, "Action": {"SendSms"}, "Format": {"XML"}, "OutId": {"123"},
		"PhoneNumbers": {"15300000001"}, "RegionId": {"cn-hangzhou"}, "SignName": {"阿里云短信测试专用"},
		"SignatureMethod": {"HMAC-SHA1"}, "SignatureNonce": {"45e25e9b-0a6f-4070-8c85-2956eda1b466"},
		"SignatureVersion": {"1.0"}, "TemplateCode": {"SMS_71390007"}, "TemplateParam": {`{"customer":"test"}`},
		"Timestamp": {"2017-07-12T02:42:19Z"}, "Version": {"2017-05-25"},
	}
	if got := aliyunSMSSignature(http.MethodGet, params, []byte("testSecret")); got != "zJDF+Lrzhj/ThnlvIToysFRq6t4=" {
		t.Fatalf("signature=%s", got)
	}
	if got := aliyunPercentEncode("a b*~+/"); got != "a%20b%2A~%2B%2F" {
		t.Fatalf("percent encode=%s", got)
	}
}

func TestAliyunSMSTransportSignsTemplateRequest(t *testing.T) {
	const secret = "aliyun-secret"
	var mu sync.Mutex
	var forms []url.Values
	code := "OK"
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if err := request.ParseForm(); err != nil || request.Method != http.MethodPost {
			t.Errorf("method=%s err=%v", request.Method, err)
		}
		form := request.PostForm
		signature := form.Get("Signature")
		form.Del("Signature")
		if expected := independentAliyunSignature(http.MethodPost, form, secret); signature != expected {
			t.Errorf("signature %s, independently computed %s", signature, expected)
		}
		mu.Lock()
		forms = append(forms, form)
		current := code
		mu.Unlock()
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]string{"Code": current, "Message": "m", "BizId": "biz-1", "RequestId": "r"})
	}))
	defer server.Close()
	transport, err := newNativeSMSTransport(nativeSMSTestConfig(t, server, notificationSMSProviderAliyun, "LTAI-test", secret))
	if err != nil {
		t.Fatal(err)
	}
	result, err := transport.Send(t.Context(), nativeSMSTestMessage("+8613900000000"))
	if err != nil || result.Disposition != notificationruntime.ProviderAccepted || result.ProviderDeliveryID != "biz-1" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	form := forms[0]
	if form.Get("Action") != "SendSms" || form.Get("Version") != "2017-05-25" || form.Get("AccessKeyId") != "LTAI-test" ||
		form.Get("SignName") != "CDNCA" || form.Get("TemplateCode") != "SMS_100" || form.Get("PhoneNumbers") != "8613900000000" ||
		form.Get("SignatureMethod") != "HMAC-SHA1" || form.Get("SignatureVersion") != "1.0" || form.Get("Format") != "JSON" ||
		form.Get("SignatureNonce") == "" || form.Get("Timestamp") == "" {
		t.Fatalf("form=%v", form)
	}
	var templateParam map[string]string
	if err := json.Unmarshal([]byte(form.Get("TemplateParam")), &templateParam); err != nil ||
		len(templateParam) != 2 || templateParam["name"] != "edge-1" || templateParam["time"] != "2026-10-17" {
		t.Fatalf("variable mapping=%v err=%v", templateParam, err)
	}
	for _, test := range []struct {
		code        string
		disposition notificationruntime.ProviderDisposition
	}{
		{"isv.BUSINESS_LIMIT_CONTROL", notificationruntime.ProviderRateLimited},
		{"Throttling.User", notificationruntime.ProviderRateLimited},
		{"isp.SYSTEM_ERROR", notificationruntime.ProviderTemporaryFailure},
		{"isv.MOBILE_NUMBER_ILLEGAL", notificationruntime.ProviderPermanentFailure},
	} {
		mu.Lock()
		code = test.code
		mu.Unlock()
		result, err := transport.Send(t.Context(), nativeSMSTestMessage("+8613900000000"))
		if err != nil || result.Disposition != test.disposition || strings.Contains(result.Code, ".") {
			t.Fatalf("code %s result=%+v err=%v", test.code, result, err)
		}
	}
}

func TestSubmailSMSTransportSignsXSend(t *testing.T) {
	const appKey = "submail-app-key"
	var mu sync.Mutex
	var forms []url.Values
	status := `{"status":"success","send_id":"send-9","fee":1}`
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if err := request.ParseMultipartForm(1 << 16); err != nil && err != http.ErrNotMultipart {
			t.Error(err)
		}
		if err := request.ParseForm(); err != nil || request.Method != http.MethodPost || request.URL.Path != "/sms/xsend" {
			t.Errorf("request %s %s err=%v", request.Method, request.URL.Path, err)
		}
		form := request.PostForm
		if expected := independentSubmailSignature(form, "app-1", appKey); form.Get("signature") != expected {
			t.Errorf("signature %s, independently computed %s", form.Get("signature"), expected)
		}
		mu.Lock()
		forms = append(forms, form)
		body := status
		mu.Unlock()
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(body))
	}))
	defer server.Close()
	transport, err := newNativeSMSTransport(nativeSMSTestConfig(t, server, notificationSMSProviderSubmail, "app-1", appKey))
	if err != nil {
		t.Fatal(err)
	}
	result, err := transport.Send(t.Context(), nativeSMSTestMessage("+8613900000000"))
	if err != nil || result.Disposition != notificationruntime.ProviderAccepted || result.ProviderDeliveryID != "send-9" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	form := forms[0]
	if form.Get("appid") != "app-1" || form.Get("project") != "SMS_100" || form.Get("to") != "13900000000" ||
		form.Get("sign_type") != "md5" || form.Get("sign_version") != "2" || form.Get("timestamp") == "" {
		t.Fatalf("form=%v", form)
	}
	var vars map[string]string
	if err := json.Unmarshal([]byte(form.Get("vars")), &vars); err != nil || vars["name"] != "edge-1" || vars["time"] != "2026-10-17" {
		t.Fatalf("vars=%v err=%v", vars, err)
	}
	if result, err := transport.Send(t.Context(), nativeSMSTestMessage("+12025550100")); err != nil ||
		result.Disposition != notificationruntime.ProviderPermanentFailure || result.Code != "sms_destination_unsupported" {
		t.Fatalf("international result=%+v err=%v", result, err)
	}
	mu.Lock()
	status = `{"status":"error","code":"103","msg":"bad"}`
	mu.Unlock()
	if result, err := transport.Send(t.Context(), nativeSMSTestMessage("+8613900000000")); err != nil ||
		result.Disposition != notificationruntime.ProviderPermanentFailure || result.Code != "sms_provider_rejected" {
		t.Fatalf("error result=%+v err=%v", result, err)
	}
}

func TestNativeSMSTransportRejectsUnmappedTemplateAndMissingVariable(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("provider must not be called")
	}))
	defer server.Close()
	transport, err := newNativeSMSTransport(nativeSMSTestConfig(t, server, notificationSMSProviderAliyun, "id", "secret"))
	if err != nil {
		t.Fatal(err)
	}
	unmapped := nativeSMSTestMessage("+8613900000000")
	unmapped.TemplateID = "other.template"
	missing := nativeSMSTestMessage("+8613900000000")
	delete(missing.Params, "occurred_at")
	for name, message := range map[string]notificationruntime.ProviderMessage{"unmapped": unmapped, "missing": missing} {
		result, err := transport.Send(t.Context(), message)
		if err != nil || result.Disposition != notificationruntime.ProviderPermanentFailure || result.Code != "sms_template_unmapped" {
			t.Fatalf("%s result=%+v err=%v", name, result, err)
		}
	}
	for _, invalid := range []nativeSMSConfig{
		{Provider: notificationSMSProviderAliyun, AccessKeyID: "id", SignName: "s"},
		{Provider: "tencent", AccessKeyID: "id", AccessKeySecret: []byte("x"), SignName: "s"},
		{Provider: notificationSMSProviderAliyun, AccessKeyID: "id", AccessKeySecret: []byte("x"), SignName: "s", Endpoint: "http://plain.example/"},
	} {
		if _, err := newNativeSMSTransport(invalid); err == nil {
			t.Fatalf("invalid config accepted: %+v", invalid)
		}
	}
}

func nativeSMSTestConfig(t *testing.T, server *httptest.Server, provider, accessKeyID, secret string) nativeSMSConfig {
	t.Helper()
	caFile := filepath.Join(t.TempDir(), "sms-native-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	endpoint := server.URL + "/"
	if provider == notificationSMSProviderSubmail {
		endpoint = server.URL + "/sms/xsend"
	}
	return nativeSMSConfig{
		Provider: provider, Endpoint: endpoint, CAFile: caFile, AccessKeyID: accessKeyID,
		AccessKeySecret: []byte(secret), SignName: "CDNCA",
		Templates: map[string]nativeSMSTemplate{"node.availability.offline.zh-cn": {
			Code: "SMS_100", Variables: map[string]string{"node_name": "name", "occurred_at": "time"},
		}},
	}
}

func nativeSMSTestMessage(contact string) notificationruntime.ProviderMessage {
	return notificationruntime.ProviderMessage{
		OutboxID: uuid.New(), Channel: notification.ChannelSMS, Contact: contact,
		Body: "节点 edge-1 已离线", IdempotencyKey: "notification-v1-native", AttemptNumber: 1,
		TemplateID: "node.availability.offline.zh-cn",
		Params:     map[string]string{"node_name": "edge-1", "occurred_at": "2026-10-17", "reason": "probe_unhealthy"},
	}
}

// 按官方文档独立实现一遍，用来校验被测代码的签名。
func independentAliyunSignature(method string, form url.Values, secret string) string {
	keys := make([]string, 0, len(form))
	for key := range form {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	encode := func(value string) string {
		return strings.NewReplacer("+", "%20", "*", "%2A", "%7E", "~").Replace(url.QueryEscape(value))
	}
	pairs := make([]string, 0, len(keys))
	for _, key := range keys {
		pairs = append(pairs, encode(key)+"="+encode(form.Get(key)))
	}
	stringToSign := method + "&" + encode("/") + "&" + encode(strings.Join(pairs, "&"))
	mac := hmac.New(sha1.New, []byte(secret+"&"))
	mac.Write([]byte(stringToSign))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func independentSubmailSignature(form url.Values, appID, appKey string) string {
	keys := []string{"appid", "project", "sign_type", "sign_version", "timestamp", "to"}
	pairs := make([]string, 0, len(keys))
	for _, key := range keys {
		pairs = append(pairs, key+"="+form.Get(key))
	}
	sum := md5.Sum([]byte(appID + appKey + strings.Join(pairs, "&") + appID + appKey))
	return hex.EncodeToString(sum[:])
}
