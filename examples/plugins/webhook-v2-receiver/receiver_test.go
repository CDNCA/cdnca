package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	vectorTenant       = "018cc251-f400-7def-8000-000000000030"
	vectorSubscription = "018cc251-f400-7def-8000-000000000010"
	vectorEvent        = "018cc251-f400-7def-8000-000000000001"
	vectorDelivery     = "018cc251-f400-7def-8000-000000000002"
	vectorKeyID        = "018cc251-f400-7def-8000-000000000011"
	vectorPath         = "/cdnca/hooks"
	vectorBody         = `{"specversion":"1.0","id":"018cc251-f400-7def-8000-000000000001","source":"/control-plane/plugin-webhooks","type":"io.cdnca.webhook.v1.test","subject":"webhook_subscription/018cc251-f400-7def-8000-000000000010","time":"2024-01-01T00:00:00Z","datacontenttype":"application/json","dataschema":"https://schemas.cdnca.example/marketplace/v1/webhook-test-event.schema.json","tenant_id":"018cc251-f400-7def-8000-000000000030","request_id":"request-084","traceparent":"00-11111111111111111111111111111111-2222222222222222-01","sequence":1,"data":{"subscription_id":"018cc251-f400-7def-8000-000000000010","test":true}}`
)

var vectorKey = func() []byte {
	key, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	return key
}()

func TestReceiverUsesPublishedV2VectorAndDurableReplay(t *testing.T) {
	receiver, journal := vectorReceiver(t, vectorKey, vectorKeyID, time.Time{})
	request := signedRequest([]byte(vectorBody), vectorKey, vectorKeyID, vectorEvent, vectorDelivery, time.Unix(1704067200, 0))
	if request.Header.Get("X-CDNCA-Webhook-Content-Sha256") != "a151948885c16b99e9baf2836b61a9ad29ebf5bb3e993f2517cf8901120662a3" ||
		request.Header.Get("X-CDNCA-Webhook-Signature") != "v2=VgARCiCHvvwQHdzbKrvVyC5bP-6px3-tRz1z4rS2LQo" {
		t.Fatalf("published vector changed: digest=%s signature=%s", request.Header.Get("X-CDNCA-Webhook-Content-Sha256"), request.Header.Get("X-CDNCA-Webhook-Signature"))
	}
	assertCode(t, receiver, request, http.StatusAccepted, "accepted")
	assertCode(t, receiver, signedRequest([]byte(vectorBody), vectorKey, vectorKeyID, vectorEvent, vectorDelivery, time.Unix(1704067200, 0)), http.StatusOK, "replay_accepted")
	secondDelivery := "018cc251-f400-7def-8000-000000000003"
	assertCode(t, receiver, signedRequest([]byte(vectorBody), vectorKey, vectorKeyID, vectorEvent, secondDelivery, time.Unix(1704067200, 0)), http.StatusAccepted, "accepted")
	contents, err := os.ReadFile(journal.file.Name())
	if err != nil || bytes.Count(contents, []byte("\n")) != 2 {
		t.Fatalf("journal entries = %q err=%v", contents, err)
	}
}

func TestReceiverVerifiesBeforeJSONAndRejectsTamperOrWrongKey(t *testing.T) {
	receiver, _ := vectorReceiver(t, vectorKey, vectorKeyID, time.Time{})
	body := []byte(vectorBody)
	tampered := append([]byte(nil), body...)
	tampered[len(tampered)-2] = 'f'
	tamperedRequest := signedRequest(body, vectorKey, vectorKeyID, vectorEvent, vectorDelivery, time.Unix(1704067200, 0))
	tamperedRequest.Body = io.NopCloser(bytes.NewReader(tampered))
	assertCode(t, receiver, tamperedRequest, http.StatusUnauthorized, "webhook_authentication_failed")
	wrongKey := bytes.Repeat([]byte{0x42}, 32)
	assertCode(t, receiver, signedRequest(body, wrongKey, vectorKeyID, vectorEvent, vectorDelivery, time.Unix(1704067200, 0)), http.StatusUnauthorized, "webhook_authentication_failed")
	invalidJSON := bytes.Replace(body, []byte(`"test":true`), []byte(`"test":false`), 1)
	assertCode(t, receiver, signedRequest(invalidJSON, vectorKey, vectorKeyID, vectorEvent, "018cc251-f400-7def-8000-000000000004", time.Unix(1704067200, 0)), http.StatusBadRequest, "event_invalid")
}

func TestReceiverRejectsScopeAndTimestampOutsideInclusiveWindow(t *testing.T) {
	receiver, _ := vectorReceiver(t, vectorKey, vectorKeyID, time.Time{})
	wrongTenant := bytes.Replace([]byte(vectorBody), []byte(vectorTenant), []byte("018cc251-f400-7def-8000-000000000031"), 1)
	assertCode(t, receiver, signedRequest(wrongTenant, vectorKey, vectorKeyID, vectorEvent, vectorDelivery, time.Unix(1704067200, 0)), http.StatusForbidden, "event_scope_denied")
	now := time.Unix(1704067200, 0)
	assertCode(t, receiver, signedRequest([]byte(vectorBody), vectorKey, vectorKeyID, vectorEvent, "018cc251-f400-7def-8000-000000000005", now.Add(-maxTimestampSkew-time.Second)), http.StatusUnauthorized, "webhook_authentication_failed")
}

func TestReceiverDoesNotAcknowledgeBeforeJournalSync(t *testing.T) {
	receiver, journal := vectorReceiver(t, vectorKey, vectorKeyID, time.Time{})
	journal.sync = func(*os.File) error { return errors.New("injected fsync failure") }
	assertCode(t, receiver, signedRequest([]byte(vectorBody), vectorKey, vectorKeyID, vectorEvent, vectorDelivery, time.Unix(1704067200, 0)), http.StatusServiceUnavailable, "journal_unavailable")
	if journal.Ready() {
		t.Fatal("journal remained ready after rollback sync failure")
	}
}

func TestReceiverBindsHeaderIdentityAndAttemptToDelivery(t *testing.T) {
	receiver, _ := vectorReceiver(t, vectorKey, vectorKeyID, time.Time{})
	request := signedRequest([]byte(vectorBody), vectorKey, vectorKeyID, vectorEvent, vectorDelivery, time.Unix(1704067200, 0))
	request.Header.Set("X-CDNCA-Idempotency-Key", "plugin-webhook-v2-"+strings.Repeat("a", 64))
	assertCode(t, receiver, request, http.StatusBadRequest, "webhook_headers_invalid")
	request = signedRequest([]byte(vectorBody), vectorKey, vectorKeyID, vectorEvent, vectorDelivery, time.Unix(1704067200, 0))
	request.Header.Set("X-CDNCA-Webhook-Attempt", "0")
	assertCode(t, receiver, request, http.StatusBadRequest, "webhook_headers_invalid")
	request = signedRequest([]byte(vectorBody), vectorKey, vectorKeyID, vectorEvent, vectorDelivery, time.Unix(1704067200, 0))
	request.Header.Set("X-CDNCA-Webhook-Attempt", "01")
	assertCode(t, receiver, request, http.StatusBadRequest, "webhook_headers_invalid")
	request = signedRequest([]byte(vectorBody), vectorKey, vectorKeyID, vectorEvent, vectorDelivery, time.Unix(1704067200, 0))
	request.Header.Set("X-CDNCA-Webhook-Event-Id", "018cc251-f400-7def-8000-000000000004")
	assertCode(t, receiver, request, http.StatusUnauthorized, "webhook_authentication_failed")
	otherEventBody := bytes.Replace([]byte(vectorBody), []byte(vectorEvent), []byte("018cc251-f400-7def-8000-000000000007"), 1)
	assertCode(t, receiver, signedRequest(otherEventBody, vectorKey, vectorKeyID, vectorEvent, "018cc251-f400-7def-8000-000000000008", time.Unix(1704067200, 0)), http.StatusBadRequest, "event_invalid")
	if validUUID("00000000-0000-0000-0000-000000000000") {
		t.Fatal("zero UUID accepted")
	}
	zeroTrace := bytes.Replace([]byte(vectorBody), []byte("11111111111111111111111111111111"), []byte("00000000000000000000000000000000"), 1)
	assertCode(t, receiver, signedRequest(zeroTrace, vectorKey, vectorKeyID, vectorEvent, "018cc251-f400-7def-8000-000000000006", time.Unix(1704067200, 0)), http.StatusBadRequest, "event_invalid")
}

func vectorReceiver(t *testing.T, key []byte, keyID string, previousUntil time.Time) (*receiver, *journal) {
	t.Helper()
	journal, err := openJournal(t.TempDir() + "/events.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	now := time.Unix(1704067200, 0).UTC()
	receiver, err := newReceiver(secretVersion{ID: keyID, Secret: key}, secretVersion{}, vectorTenant, vectorSubscription, journal, func() time.Time { return now }, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(receiver.Close)
	return receiver, journal
}

func signedRequest(body, key []byte, keyID, eventID, deliveryID string, timestamp time.Time) *http.Request {
	digest := sha256.Sum256(body)
	digestText := hex.EncodeToString(digest[:])
	timestampText := strconv.FormatInt(timestamp.Unix(), 10)
	payload := strings.Join([]string{"cdnca.webhook.signature/v2", http.MethodPost, vectorPath, timestampText, eventID, deliveryID, keyID, digestText}, "\n")
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(payload))
	request := httptest.NewRequest(http.MethodPost, "http://example.invalid"+vectorPath, bytes.NewReader(body))
	request.Header.Set("Content-Type", contentType)
	request.Header.Set("X-CDNCA-Webhook-Event-Id", eventID)
	request.Header.Set("X-CDNCA-Webhook-Delivery-Id", deliveryID)
	request.Header.Set("X-CDNCA-Webhook-Timestamp", timestampText)
	request.Header.Set("X-CDNCA-Webhook-Content-Sha256", digestText)
	request.Header.Set("X-CDNCA-Webhook-Key-Id", keyID)
	request.Header.Set("X-CDNCA-Webhook-Signature-Version", "v2")
	request.Header.Set("X-CDNCA-Webhook-Signature", "v2="+base64.RawURLEncoding.EncodeToString(mac.Sum(nil)))
	deliveryDigest := sha256.Sum256([]byte(deliveryID))
	request.Header.Set("X-CDNCA-Idempotency-Key", "plugin-webhook-v2-"+hex.EncodeToString(deliveryDigest[:]))
	request.Header.Set("X-CDNCA-Webhook-Attempt", "1")
	return request
}

func serve(handler http.Handler, request *http.Request) *httptest.ResponseRecorder {
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func assertCode(t *testing.T, handler http.Handler, request *http.Request, status int, code string) {
	t.Helper()
	response := serve(handler, request)
	if response.Code != status || !strings.Contains(response.Body.String(), `"code":"`+code+`"`) {
		t.Fatalf("response = %d %s, want %d %s", response.Code, response.Body.String(), status, code)
	}
}

func testLogger() *log.Logger { return log.New(io.Discard, "", 0) }
