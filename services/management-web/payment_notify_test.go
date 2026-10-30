package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

type notifySeen struct {
	method, path, query, contentType, signature, serial, forwardedFor string
	contentLength                                                     int64
	body                                                              []byte
}

func paymentNotifyHandler(t *testing.T) (http.Handler, func() []notifySeen) {
	t.Helper()
	var mu sync.Mutex
	var seen []notifySeen
	upstreamServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		mu.Lock()
		seen = append(seen, notifySeen{method: request.Method, path: request.URL.Path, query: request.URL.RawQuery,
			contentType: request.Header.Get("Content-Type"), signature: request.Header.Get("Wechatpay-Signature"),
			serial: request.Header.Get("Wechatpay-Serial"), forwardedFor: request.Header.Get("X-Forwarded-For"),
			contentLength: request.ContentLength, body: body})
		mu.Unlock()
		response.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(response, "success")
	}))
	t.Cleanup(upstreamServer.Close)
	upstream, _ := url.Parse(upstreamServer.URL)
	handler, err := newHandler(testStaticRoot(t), upstream)
	if err != nil {
		t.Fatal(err)
	}
	return handler, func() []notifySeen {
		mu.Lock()
		defer mu.Unlock()
		return append([]notifySeen(nil), seen...)
	}
}

func TestPaymentNotifyIsForwardedByteForByte(t *testing.T) {
	handler, seen := paymentNotifyHandler(t)
	const channel = "/payments/v1/notify/0193a0c4-6a9e-7c1d-9e0b-3f2a1c4d5e6f"
	// Alipay posts a form whose signature covers the exact encoding; WeChat Pay v3 signs the raw JSON
	// with its headers. Neither may be re-encoded on the way.
	form := "gmt_create=2026-10-16+12%3A00%3A00&out_trade_no=700001&sign=abc%2B%2F%3D&trade_status=TRADE_SUCCESS"
	request := httptest.NewRequest(http.MethodPost, channel, strings.NewReader(form))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	request.Header.Set("Wechatpay-Signature", "c2lnbmF0dXJl")
	request.Header.Set("Wechatpay-Serial", "5157F09EFDC096DE15EBE81A47057A72")
	request.RemoteAddr = "203.0.113.9:4242"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() != "success" {
		t.Fatalf("notify status=%d body=%q", response.Code, response.Body.String())
	}
	// Epay/码支付 notify with GET and the signed fields in the query.
	getRequest := httptest.NewRequest(http.MethodGet, channel+"?pid=1001&trade_no=T1&money=1.00&sign=9f86d081&sign_type=MD5", nil)
	handler.ServeHTTP(httptest.NewRecorder(), getRequest)

	got := seen()
	if len(got) != 2 {
		t.Fatalf("upstream calls=%d", len(got))
	}
	post := got[0]
	if post.method != http.MethodPost || post.path != channel || !bytes.Equal(post.body, []byte(form)) ||
		post.contentLength != int64(len(form)) || post.contentType != "application/x-www-form-urlencoded; charset=utf-8" ||
		post.signature != "c2lnbmF0dXJl" || post.serial != "5157F09EFDC096DE15EBE81A47057A72" || !strings.HasPrefix(post.forwardedFor, "203.0.113.9") {
		t.Fatalf("forwarded POST=%+v body=%q", post, post.body)
	}
	if get := got[1]; get.method != http.MethodGet || get.query != "pid=1001&trade_no=T1&money=1.00&sign=9f86d081&sign_type=MD5" ||
		len(get.body) != 0 {
		t.Fatalf("forwarded GET=%+v", get)
	}
}

func TestPaymentNotifyRejectsOversizedBodiesAndOtherMethods(t *testing.T) {
	handler, seen := paymentNotifyHandler(t)
	const channel = "/payments/v1/notify/0193a0c4-6a9e-7c1d-9e0b-3f2a1c4d5e6f"
	limit := bytes.Repeat([]byte("a"), maxPaymentNotifyBytes)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, channel, bytes.NewReader(limit)))
	if response.Code != http.StatusOK {
		t.Fatalf("a body at the limit status=%d", response.Code)
	}
	declared := httptest.NewRequest(http.MethodPost, channel, bytes.NewReader(append(limit, 'a')))
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, declared)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized declared body status=%d", response.Code)
	}
	// Chunked (no Content-Length): measured while buffering.
	chunked := httptest.NewRequest(http.MethodPost, channel, io.MultiReader(bytes.NewReader(limit), strings.NewReader("a")))
	chunked.ContentLength = -1
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, chunked)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized chunked body status=%d", response.Code)
	}
	put := httptest.NewRequest(http.MethodPut, channel, strings.NewReader("x"))
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, put)
	if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != "GET, POST" {
		t.Fatalf("PUT status=%d allow=%q", response.Code, response.Header().Get("Allow"))
	}
	if got := seen(); len(got) != 1 || len(got[0].body) != maxPaymentNotifyBytes {
		t.Fatalf("only the body at the limit may reach the upstream, got %d calls", len(got))
	}
}
