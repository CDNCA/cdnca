package acmecacredentials

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// 假 ZeroSSL 服务器（不调生产）：表单 email、成功/失败/坏响应。
func TestZeroSSLEABFetcher(t *testing.T) {
	var gotEmail, gotType string
	reply := `{"success":true,"eab_kid":"kid-1","eab_hmac_key":"QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo"}`
	status := http.StatusOK
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s", r.Method)
		}
		_ = r.ParseForm()
		gotEmail, gotType = r.PostForm.Get("email"), r.Header.Get("Content-Type")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(reply))
	}))
	defer server.Close()
	fetcher := &ZeroSSLEABFetcher{Endpoint: server.URL, Client: server.Client()}
	kid, key, err := fetcher.Fetch(context.Background(), "ops@example.com")
	if err != nil || kid != "kid-1" || key == "" || gotEmail != "ops@example.com" || gotType != "application/x-www-form-urlencoded" {
		t.Fatalf("fetch = %q %q %v email=%q type=%q", kid, key, err, gotEmail, gotType)
	}
	for name, test := range map[string]struct {
		reply  string
		status int
	}{
		"refused":  {`{"success":false,"error":{"code":2,"type":"invalid_email"}}`, http.StatusOK},
		"no key":   {`{"success":true,"eab_kid":"kid-1"}`, http.StatusOK},
		"not json": {`<html>`, http.StatusOK},
		"http 500": {reply, http.StatusInternalServerError},
	} {
		reply, status = test.reply, test.status
		if _, _, err := fetcher.Fetch(context.Background(), "ops@example.com"); !errors.Is(err, ErrEABFetchFailed) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	for _, email := range []string{"", "no-at", "A <a@example.com>", " a@example.com", "a@example.com,b@example.com"} {
		if _, _, err := fetcher.Fetch(context.Background(), email); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("email %q: err = %v", email, err)
		}
	}
	if _, _, err := (&ZeroSSLEABFetcher{Endpoint: "http://example.com", Client: server.Client()}).Fetch(context.Background(), "a@example.com"); !errors.Is(err, ErrUnavailable) {
		t.Errorf("plain http endpoint: %v", err)
	}
}
