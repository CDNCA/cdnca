package mail_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/mail"
	"github.com/cdnca/cdnca/libs/mail/mailtest"
)

var message = mail.Message{To: "user@example.com", Subject: "验证码", Text: "code 123456", HTML: "<p>code <b>123456</b></p>",
	ReplyTo: "support@example.com", ID: "outbox-1"}

func smtpConfig(server *mailtest.Server, mode string) mail.SMTPConfig {
	return mail.SMTPConfig{Host: server.Host, Port: server.Port, TLS: mode, Username: "u", Password: "p",
		From: "noreply@example.com", FromName: "CDNCA", RootCAs: server.RootCAs}
}

func TestSMTPSendsOverImplicitTLSAndSTARTTLS(t *testing.T) {
	for _, mode := range []string{mail.TLSImplicit, mail.TLSStartTLS} {
		t.Run(mode, func(t *testing.T) {
			server := mailtest.Start(t, mailtest.Options{Implicit: mode == mail.TLSImplicit, Username: "u", Password: "p"})
			sender, err := mail.NewSMTP(smtpConfig(server, mode))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := sender.Send(t.Context(), message); err != nil {
				t.Fatal(err)
			}
			got := server.Messages()
			if len(got) != 1 || !got[0].TLS || got[0].From != "noreply@example.com" || got[0].To != "user@example.com" {
				t.Fatalf("messages %+v", got)
			}
			for _, want := range []string{"Reply-To: <support@example.com>", "multipart/alternative", "text/html", `From: "CDNCA" <noreply@example.com>`} {
				if !strings.Contains(got[0].Data, want) {
					t.Errorf("message lacks %q:\n%s", want, got[0].Data)
				}
			}
			if mode == mail.TLSStartTLS {
				commands := strings.Join(server.Commands(), "|")
				if strings.Index(commands, "STARTTLS") > strings.Index(commands, "AUTH") {
					t.Fatalf("AUTH before STARTTLS: %s", commands)
				}
			}
		})
	}
}

func TestSMTPRefusesServerWithoutSTARTTLS(t *testing.T) {
	server := mailtest.Start(t, mailtest.Options{NoSTARTTLS: true, Username: "u", Password: "p"})
	sender, _ := mail.NewSMTP(smtpConfig(server, mail.TLSStartTLS))
	_, err := sender.Send(t.Context(), message)
	if failure := mail.ErrorOf(err); failure == nil || failure.Code != mail.CodeTLSRequired || failure.Disposition != mail.Permanent {
		t.Fatalf("err %v", err)
	}
	for _, command := range server.Commands() {
		if strings.HasPrefix(command, "AUTH") || strings.HasPrefix(command, "MAIL") {
			t.Fatalf("sent %q without TLS", command)
		}
	}
}

func TestSMTPClassifiesReplies(t *testing.T) {
	cases := map[string]struct {
		options     mailtest.Options
		disposition mail.Disposition
		code        string
	}{
		"bad password": {mailtest.Options{Username: "u", Password: "other"}, mail.Permanent, mail.CodeCredentialRejected},
		"unknown user": {mailtest.Options{Username: "u", Password: "p", RejectRcpt: "550 no such user"}, mail.Permanent, mail.CodeRecipientRejected},
		"mailbox busy": {mailtest.Options{Username: "u", Password: "p", RejectRcpt: "450 try later"}, mail.Temporary, mail.CodeUnavailable},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			server := mailtest.Start(t, c.options)
			sender, _ := mail.NewSMTP(smtpConfig(server, mail.TLSStartTLS))
			_, err := sender.Send(t.Context(), message)
			if failure := mail.ErrorOf(err); failure == nil || failure.Code != c.code || failure.Disposition != c.disposition {
				t.Fatalf("err %v", err)
			}
		})
	}
}

func TestSMTPConfigRejectsPlaintextAndHalfCredentials(t *testing.T) {
	base := mail.SMTPConfig{Host: "smtp.example.com", Port: 587, TLS: mail.TLSStartTLS, From: "a@example.com"}
	for name, mutate := range map[string]func(*mail.SMTPConfig){
		"plaintext":   func(c *mail.SMTPConfig) { c.TLS = "none" },
		"no mode":     func(c *mail.SMTPConfig) { c.TLS = "" },
		"half creds":  func(c *mail.SMTPConfig) { c.Username = "u" },
		"bad from":    func(c *mail.SMTPConfig) { c.From = "Name <a@example.com>" },
		"bad host":    func(c *mail.SMTPConfig) { c.Host = "smtp.example.com:25" },
		"header name": func(c *mail.SMTPConfig) { c.FromName = "x\r\nBcc: y" },
	} {
		config := base
		mutate(&config)
		if mail.ValidSMTPConfig(config) {
			t.Errorf("%s accepted", name)
		}
	}
	if !mail.ValidSMTPConfig(base) {
		t.Fatal("base rejected")
	}
}

func fixedClock() time.Time { return time.Date(2026, 10, 22, 3, 4, 5, 0, time.UTC) }

func TestDirectMailSignsSingleSendMail(t *testing.T) {
	var form url.Values
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		form, _ = url.ParseQuery(string(body))
		_, _ = writer.Write([]byte(`{"EnvId":"600000","RequestId":"r1"}`))
	}))
	defer server.Close()
	sender, err := mail.NewService(mail.ServiceConfig{Provider: mail.ProviderAliyun, AccessKeyID: "LTAIexample",
		AccessKeySecret: "secret-value", From: "noreply@mail.example.com", FromName: "CDNCA", Endpoint: server.URL + "/",
		HTTPClient: server.Client(), Now: fixedClock, Nonce: func() string { return "nonce-1" }})
	if err != nil {
		t.Fatal(err)
	}
	result, err := sender.Send(t.Context(), message)
	if err != nil || result.MessageID != "600000" {
		t.Fatalf("result %+v err %v", result, err)
	}
	want := map[string]string{"Action": "SingleSendMail", "Version": "2015-11-23", "AccountName": "noreply@mail.example.com",
		"AddressType": "1", "ReplyToAddress": "false", "ToAddress": "user@example.com", "Subject": "验证码",
		"TextBody": "code 123456", "HtmlBody": "<p>code <b>123456</b></p>", "FromAlias": "CDNCA", "RegionId": "cn-hangzhou",
		"Timestamp": "2026-10-22T03:04:05Z", "SignatureNonce": "nonce-1", "SignatureMethod": "HMAC-SHA1"}
	for key, value := range want {
		if form.Get(key) != value {
			t.Errorf("%s = %q, want %q", key, form.Get(key), value)
		}
	}
	signature := form.Get("Signature")
	form.Del("Signature")
	if signature == "" || signature != mail.AliyunSignature(http.MethodPost, form, "secret-value") {
		t.Fatalf("signature %q", signature)
	}
}

// Known-answer: Alibaba Cloud's documented RPC signature example
// (DescribeRegions, secret "testsecret") yields this value.
func TestAliyunSignatureKnownAnswer(t *testing.T) {
	form := url.Values{"Format": {"XML"}, "AccessKeyId": {"testid"}, "Action": {"DescribeRegions"},
		"SignatureMethod": {"HMAC-SHA1"}, "SignatureNonce": {"3ee8c1b8-83d3-44af-a94f-4e0ad82fd6cf"},
		"SignatureVersion": {"1.0"}, "Version": {"2014-05-26"}, "Timestamp": {"2016-02-23T12:46:24Z"}}
	if got := mail.AliyunSignature(http.MethodGet, form, "testsecret"); got != "OLeaidS1JvxuMvnyHOwuJ+uX5qY=" {
		t.Fatalf("signature %q", got)
	}
}

func TestDirectMailMapsErrors(t *testing.T) {
	cases := map[string]struct {
		status      int
		body        string
		disposition mail.Disposition
		code        string
	}{
		"throttled":    {400, `{"Code":"Throttling.User"}`, mail.RateLimited, mail.CodeRateLimited},
		"bad key":      {404, `{"Code":"InvalidAccessKeyId.NotFound"}`, mail.Permanent, mail.CodeCredentialRejected},
		"signature":    {400, `{"Code":"SignatureDoesNotMatch"}`, mail.Permanent, mail.CodeCredentialRejected},
		"sender":       {400, `{"Code":"InvalidMailAddress.NotFound"}`, mail.Permanent, mail.CodeSenderRejected},
		"recipient":    {400, `{"Code":"InvalidToAddress"}`, mail.Permanent, mail.CodeRecipientRejected},
		"server error": {503, `{"Code":"ServiceUnavailable"}`, mail.Temporary, mail.CodeUnavailable},
		"html page":    {502, `<html>bad gateway</html>`, mail.Temporary, mail.CodeUnavailable},
		"garbled 200":  {200, `not json`, mail.Unknown, mail.CodeResponseUnknown},
		"no env id":    {200, `{"RequestId":"r"}`, mail.Unknown, mail.CodeResponseUnknown},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.WriteHeader(c.status)
				_, _ = writer.Write([]byte(c.body))
			}))
			defer server.Close()
			sender, _ := mail.NewService(mail.ServiceConfig{Provider: mail.ProviderAliyun, AccessKeyID: "id", AccessKeySecret: "s",
				From: "a@example.com", Endpoint: server.URL, HTTPClient: server.Client()})
			_, err := sender.Send(t.Context(), message)
			if failure := mail.ErrorOf(err); failure == nil || failure.Code != c.code || failure.Disposition != c.disposition {
				t.Fatalf("err %v", err)
			}
		})
	}
}

func TestSendGridSendsMailSend(t *testing.T) {
	var payload map[string]any
	var authorization string
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		authorization = request.Header.Get("Authorization")
		_ = json.NewDecoder(request.Body).Decode(&payload)
		writer.Header().Set("X-Message-Id", "sg-1")
		writer.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	sender, err := mail.NewService(mail.ServiceConfig{Provider: mail.ProviderSendGrid, AccessKeySecret: "SG.key",
		From: "noreply@example.com", FromName: "CDNCA", Endpoint: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	result, err := sender.Send(t.Context(), message)
	if err != nil || result.MessageID != "sg-1" || authorization != "Bearer SG.key" {
		t.Fatalf("result %+v err %v auth %q", result, err, authorization)
	}
	encoded, _ := json.Marshal(payload)
	for _, want := range []string{`"personalizations":[{"to":[{"email":"user@example.com"}]}]`,
		`"from":{"email":"noreply@example.com","name":"CDNCA"}`, `"reply_to":{"email":"support@example.com"}`,
		`"content":[{"type":"text/plain","value":"code 123456"},{"type":"text/html"`, `"subject":"验证码"`} {
		if !strings.Contains(string(encoded), want) {
			t.Errorf("payload lacks %s: %s", want, encoded)
		}
	}
}

func TestSendGridMapsErrors(t *testing.T) {
	cases := map[int]struct {
		disposition mail.Disposition
		code        string
	}{
		401: {mail.Permanent, mail.CodeCredentialRejected}, 403: {mail.Permanent, mail.CodeSenderRejected},
		400: {mail.Permanent, mail.CodeRejected}, 413: {mail.Permanent, mail.CodeInvalidMessage},
		429: {mail.RateLimited, mail.CodeRateLimited}, 500: {mail.Temporary, mail.CodeUnavailable},
	}
	for status, c := range cases {
		server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writer.WriteHeader(status)
			_, _ = writer.Write([]byte(`{"errors":[{"message":"x"}]}`))
		}))
		sender, _ := mail.NewService(mail.ServiceConfig{Provider: mail.ProviderSendGrid, AccessKeySecret: "SG.key",
			From: "a@example.com", Endpoint: server.URL, HTTPClient: server.Client()})
		_, err := sender.Send(t.Context(), message)
		server.Close()
		if failure := mail.ErrorOf(err); failure == nil || failure.Code != c.code || failure.Disposition != c.disposition {
			t.Errorf("%d: err %v", status, err)
		}
	}
}

func TestServiceRefusesRedirectAndUnreachable(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusAccepted)
	}))
	defer target.Close()
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	client := mail.NewHTTPClient(5 * time.Second)
	client.Transport = redirect.Client().Transport
	sender, _ := mail.NewService(mail.ServiceConfig{Provider: mail.ProviderSendGrid, AccessKeySecret: "SG.key",
		From: "a@example.com", Endpoint: redirect.URL, HTTPClient: client})
	if _, err := sender.Send(t.Context(), message); mail.ErrorOf(err) == nil {
		t.Fatal("redirect followed as success")
	}
	sender, _ = mail.NewService(mail.ServiceConfig{Provider: mail.ProviderSendGrid, AccessKeySecret: "SG.key",
		From: "a@example.com", Endpoint: "https://127.0.0.1:1/v3/mail/send", HTTPClient: client})
	if failure := mail.ErrorOf(func() error { _, err := sender.Send(t.Context(), message); return err }()); failure == nil ||
		failure.Disposition != mail.Temporary {
		t.Fatalf("unreachable %+v", failure)
	}
}

func TestServiceConfigValidation(t *testing.T) {
	valid := mail.ServiceConfig{Provider: mail.ProviderAliyun, AccessKeyID: "id", AccessKeySecret: "s", From: "a@example.com"}
	if !mail.ValidServiceConfig(valid) {
		t.Fatal("valid rejected")
	}
	for name, mutate := range map[string]func(*mail.ServiceConfig){
		"unknown provider":  func(c *mail.ServiceConfig) { c.Provider = "ses" },
		"unknown region":    func(c *mail.ServiceConfig) { c.Region = "mars-1" },
		"aliyun without id": func(c *mail.ServiceConfig) { c.AccessKeyID = "" },
		"sendgrid with id":  func(c *mail.ServiceConfig) { c.Provider = mail.ProviderSendGrid },
		"secret with space": func(c *mail.ServiceConfig) { c.AccessKeySecret = "a b" },
		"from display name": func(c *mail.ServiceConfig) { c.From = "A <a@example.com>" },
	} {
		config := valid
		mutate(&config)
		if mail.ValidServiceConfig(config) {
			t.Errorf("%s accepted", name)
		}
	}
	if got := mail.ModuleCode(mail.ProviderSendGrid); got != "module.mail.sendgrid" {
		t.Fatal(got)
	}
}
