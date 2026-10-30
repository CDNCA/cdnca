package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testTenantID    = "019b143c-7e64-7cc6-b886-a1354a006283"
	testDeliveryID  = "019b143c-7e64-7cc6-b886-a1354a006299"
	testCurrentKey  = "current-webhook-secret-32-bytes!!"
	testPreviousKey = "previous-webhook-secret-32-bytes!"
)

var testNow = time.Date(2026, 7, 23, 8, 30, 0, 0, time.UTC)

func TestReceiverAuthenticationIdempotencyAndPermanentConflict(t *testing.T) {
	receiver, journal, logs := receiverFixture(t, [][]byte{[]byte(testCurrentKey)})
	body := eventBody(testEventID, testTenantID, allowedEventType, 17, `{"password":"do-not-log"}`)
	assertRequest(t, receiver, signedRequest(t, body, testCurrentKey, testNow), http.StatusAccepted, "accepted")
	assertRequest(t, receiver, signedRequest(t, body, testCurrentKey, testNow), http.StatusOK, "replay_accepted")
	changed := eventBody(testEventID, testTenantID, allowedEventType, 18, `{"password":"changed"}`)
	assertRequest(t, receiver, signedRequest(t, changed, testCurrentKey, testNow), http.StatusConflict, "event_digest_conflict")

	journalBytes, err := os.ReadFile(journal.file.Name())
	if err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{"journal": string(journalBytes), "logs": logs.String()} {
		if strings.Contains(content, "do-not-log") || strings.Contains(content, testCurrentKey) {
			t.Fatalf("%s leaked a sensitive value: %s", name, content)
		}
	}
}

func TestReceiverScopeOutOfOrderRotationAndRevocation(t *testing.T) {
	receiver, _, _ := receiverFixture(t, [][]byte{[]byte(testCurrentKey), []byte(testPreviousKey)})
	wrongTenant := eventBody("019b143c-7e64-7cc6-b886-a1354a006282", "019b143c-7e64-7cc6-b886-a1354a006284", allowedEventType, 1, `{}`)
	assertRequest(t, receiver, signedRequest(t, wrongTenant, testCurrentKey, testNow), http.StatusForbidden, "event_scope_denied")
	wrongType := eventBody("019b143c-7e64-7cc6-b886-a1354a006285", testTenantID, "io.cdnca.node.v1.status_changed", 1, `{}`)
	assertRequest(t, receiver, signedRequest(t, wrongType, testCurrentKey, testNow), http.StatusForbidden, "event_scope_denied")

	sequenceTwo := eventBody("019b143c-7e64-7cc6-b886-a1354a006286", testTenantID, allowedEventType, 2, `{}`)
	sequenceOne := eventBody("019b143c-7e64-7cc6-b886-a1354a006287", testTenantID, allowedEventType, 1, `{}`)
	assertRequest(t, receiver, signedRequest(t, sequenceTwo, testPreviousKey, testNow), http.StatusAccepted, "accepted")
	assertRequest(t, receiver, signedRequest(t, sequenceOne, testCurrentKey, testNow), http.StatusAccepted, "accepted")

	revoked, _, _ := receiverFixture(t, [][]byte{[]byte(testCurrentKey)})
	revokedBody := eventBody("019b143c-7e64-7cc6-b886-a1354a006288", testTenantID, allowedEventType, 3, `{}`)
	assertRequest(t, revoked, signedRequest(t, revokedBody, testPreviousKey, testNow), http.StatusUnauthorized, "webhook_authentication_failed")
	assertRequest(t, revoked, signedRequest(t, revokedBody, testCurrentKey, testNow), http.StatusAccepted, "accepted")
}

func TestReceiverStrictRequestValidation(t *testing.T) {
	receiver, _, _ := receiverFixture(t, [][]byte{[]byte(testCurrentKey)})
	body := eventBody(testEventID, testTenantID, allowedEventType, 1, `{}`)
	tests := []struct {
		name   string
		make   func() *http.Request
		status int
		code   string
	}{
		{name: "expired", make: func() *http.Request { return signedRequest(t, body, testCurrentKey, testNow.Add(-6*time.Minute)) }, status: 401, code: "webhook_timestamp_out_of_window"},
		{name: "future timestamp", make: func() *http.Request { return signedRequest(t, body, testCurrentKey, testNow.Add(6*time.Minute)) }, status: 401, code: "webhook_timestamp_out_of_window"},
		{name: "empty body", make: func() *http.Request { return signedRequest(t, nil, testCurrentKey, testNow) }, status: 400, code: "request_body_invalid"},
		{name: "tampered", make: func() *http.Request {
			request := signedRequest(t, body, testCurrentKey, testNow)
			request.Body = ioNopCloser(body[:len(body)-1])
			return request
		}, status: 401, code: "webhook_authentication_failed"},
		{name: "wrong content type", make: func() *http.Request {
			request := signedRequest(t, body, testCurrentKey, testNow)
			request.Header.Set("Content-Type", "application/json")
			return request
		}, status: 415, code: "content_type_invalid"},
		{name: "missing header", make: func() *http.Request {
			request := signedRequest(t, body, testCurrentKey, testNow)
			request.Header.Del("X-CDNCA-Webhook-Signature")
			return request
		}, status: 400, code: "webhook_headers_invalid"},
		{name: "duplicate header", make: func() *http.Request {
			request := signedRequest(t, body, testCurrentKey, testNow)
			request.Header.Add("X-CDNCA-Webhook-Signature", request.Header.Get("X-CDNCA-Webhook-Signature"))
			return request
		}, status: 400, code: "webhook_headers_invalid"},
		{name: "unknown event field", make: func() *http.Request {
			invalid := bytes.Replace(body, []byte(`"data":`), []byte(`"unknown":true,"data":`), 1)
			return signedRequest(t, invalid, testCurrentKey, testNow)
		}, status: 400, code: "event_invalid"},
		{name: "duplicate event field", make: func() *http.Request {
			invalid := bytes.Replace(body, []byte(`"sequence":1`), []byte(`"sequence":1,"sequence":2`), 1)
			return signedRequest(t, invalid, testCurrentKey, testNow)
		}, status: 400, code: "event_invalid"},
		{name: "invalid UTF-8", make: func() *http.Request {
			invalid := append([]byte(nil), body...)
			invalid[bytes.Index(invalid, []byte("request-example"))] = 0xff
			return signedRequest(t, invalid, testCurrentKey, testNow)
		}, status: 400, code: "event_invalid"},
		{name: "method", make: func() *http.Request {
			request := signedRequest(t, body, testCurrentKey, testNow)
			request.Method = http.MethodGet
			return request
		}, status: 405, code: "method_not_allowed"},
		{name: "too large", make: func() *http.Request {
			return signedRequest(t, bytes.Repeat([]byte("x"), maxBodyBytes+1), testCurrentKey, testNow)
		}, status: 413, code: "request_body_too_large"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertRequest(t, receiver, test.make(), test.status, test.code)
		})
	}
}

type failingRecorder struct{}

func (failingRecorder) Record(string, string, time.Time) (recordResult, error) {
	return recordAccepted, errors.New("storage unavailable")
}

func (failingRecorder) Ready() bool { return true }

func TestReceiverRetryableJournalFailureDoesNotAcknowledge(t *testing.T) {
	receiver, err := newReceiver([]byte(testCurrentKey), nil, time.Time{}, testTenantID, failingRecorder{}, func() time.Time { return testNow }, 5*time.Minute, log.New(&bytes.Buffer{}, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	body := eventBody(testEventID, testTenantID, allowedEventType, 1, `{}`)
	assertRequest(t, receiver, signedRequest(t, body, testCurrentKey, testNow), http.StatusServiceUnavailable, "journal_unavailable")
}

func TestReceiverReadinessTracksJournalPoison(t *testing.T) {
	journal, err := openJournal(filepath.Join(t.TempDir(), "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	receiver, err := newReceiver([]byte(testCurrentKey), nil, time.Time{}, testTenantID, journal, func() time.Time { return testNow }, 5*time.Minute, log.New(&bytes.Buffer{}, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(receiver.Close)
	response := httptest.NewRecorder()
	receiver.ServeHTTP(response, httptest.NewRequest(http.MethodGet, healthPath, nil))
	if response.Code != http.StatusOK {
		t.Fatalf("healthy status = %d", response.Code)
	}
	journal.writeFile = func(file *os.File, data []byte) (int, error) { return file.Write(data[:len(data)/2]) }
	journal.truncateFile = func(*os.File, int64) error { return errors.New("injected truncate failure") }
	body := eventBody("019b143c-7e64-7cc6-b886-a1354a006295", testTenantID, allowedEventType, 1, `{}`)
	assertRequest(t, receiver, signedRequest(t, body, testCurrentKey, testNow), http.StatusServiceUnavailable, "journal_unavailable")
	response = httptest.NewRecorder()
	receiver.ServeHTTP(response, httptest.NewRequest(http.MethodGet, healthPath, nil))
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), `"code":"journal_unavailable"`) {
		t.Fatalf("poisoned health = %d %s", response.Code, response.Body.String())
	}
}

func TestReceiverPreviousSecretExpiresAtBoundary(t *testing.T) {
	journal, err := openJournal(filepath.Join(t.TempDir(), "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	now := testNow
	validUntil := testNow.Add(time.Minute)
	receiver, err := newReceiver(
		[]byte(testCurrentKey), []byte(testPreviousKey), validUntil,
		testTenantID, journal, func() time.Time { return now }, 5*time.Minute, log.New(&bytes.Buffer{}, "", 0),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(receiver.Close)
	bodyBefore := eventBody("019b143c-7e64-7cc6-b886-a1354a006292", testTenantID, allowedEventType, 1, `{}`)
	assertRequest(t, receiver, signedRequest(t, bodyBefore, testPreviousKey, now), http.StatusAccepted, "accepted")

	now = validUntil
	bodyBoundary := eventBody("019b143c-7e64-7cc6-b886-a1354a006293", testTenantID, allowedEventType, 2, `{}`)
	assertRequest(t, receiver, signedRequest(t, bodyBoundary, testPreviousKey, now), http.StatusUnauthorized, "webhook_authentication_failed")
	receiver.secretMu.Lock()
	previousBytes := len(receiver.previousSecret)
	receiver.secretMu.Unlock()
	if previousBytes != 0 {
		t.Fatalf("previous secret retained %d bytes at expiry boundary", previousBytes)
	}
	assertRequest(t, receiver, signedRequest(t, bodyBoundary, testCurrentKey, now), http.StatusAccepted, "accepted")
}

func TestReceiverConcurrentDeliveryHasSingleAcceptedWinner(t *testing.T) {
	receiver, _, _ := receiverFixture(t, [][]byte{[]byte(testCurrentKey)})
	body := eventBody("019b143c-7e64-7cc6-b886-a1354a006294", testTenantID, allowedEventType, 1, `{}`)
	start := make(chan struct{})
	var wait sync.WaitGroup
	var accepted atomic.Int64
	var replayed atomic.Int64
	var unexpected atomic.Int64
	for range 32 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			response := httptest.NewRecorder()
			receiver.ServeHTTP(response, signedRequest(t, body, testCurrentKey, testNow))
			switch response.Code {
			case http.StatusAccepted:
				accepted.Add(1)
			case http.StatusOK:
				replayed.Add(1)
			default:
				unexpected.Add(1)
			}
		}()
	}
	close(start)
	wait.Wait()
	if accepted.Load() != 1 || replayed.Load() != 31 || unexpected.Load() != 0 {
		t.Fatalf("accepted=%d replayed=%d unexpected=%d", accepted.Load(), replayed.Load(), unexpected.Load())
	}
}

func receiverFixture(t *testing.T, secrets [][]byte) (*receiver, *journal, *bytes.Buffer) {
	t.Helper()
	journal, err := openJournal(filepath.Join(t.TempDir(), "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	logs := &bytes.Buffer{}
	var previous []byte
	var previousValidUntil time.Time
	if len(secrets) > 1 {
		previous = secrets[1]
		previousValidUntil = testNow.Add(time.Hour)
	}
	receiver, err := newReceiver(secrets[0], previous, previousValidUntil, testTenantID, journal, func() time.Time { return testNow }, 5*time.Minute, log.New(logs, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(receiver.Close)
	return receiver, journal, logs
}

func eventBody(id, tenantID, eventType string, sequence int, data string) []byte {
	return []byte(fmt.Sprintf(`{"specversion":"1.0","id":%q,"source":"/control-plane/sites","type":%q,"subject":"site/019b143c-7e64-7cc6-b886-a1354a006282","time":"2026-07-23T08:30:00Z","datacontenttype":"application/json","dataschema":"https://schemas.cdnca.example/events/site/v1/updated.schema.json","tenant_id":%q,"request_id":"request-example","traceparent":"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01","sequence":%d,"data":%s}`, id, eventType, tenantID, sequence, data))
}

func signedRequest(t *testing.T, body []byte, secret string, signedAt time.Time) *http.Request {
	t.Helper()
	digest := sha256.Sum256(body)
	digestText := hex.EncodeToString(digest[:])
	timestamp := fmt.Sprintf("%d", signedAt.Unix())
	payload := []byte("cdnca.webhook.signature/v1\n" + timestamp + "\n" + testDeliveryID + "\n" + digestText)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(payload)
	request := httptest.NewRequest(http.MethodPost, webhookPath, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/cloudevents+json")
	request.Header.Set("X-CDNCA-Webhook-Id", testDeliveryID)
	request.Header.Set("X-CDNCA-Webhook-Timestamp", timestamp)
	request.Header.Set("X-CDNCA-Webhook-Content-Sha256", digestText)
	request.Header.Set("X-CDNCA-Webhook-Signature", "v1="+base64.RawURLEncoding.EncodeToString(mac.Sum(nil)))
	request.Header.Set("X-CDNCA-Idempotency-Key", "plugin-webhook-v1-example")
	request.Header.Set("X-CDNCA-Webhook-Attempt", "1")
	return request
}

func assertRequest(t *testing.T, handler http.Handler, request *http.Request, status int, code string) {
	t.Helper()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != status || !strings.Contains(response.Body.String(), `"code":"`+code+`"`) {
		t.Fatalf("response = %d %s, want %d %s", response.Code, response.Body.String(), status, code)
	}
}

func ioNopCloser(body []byte) *nopCloser {
	return &nopCloser{Reader: bytes.NewReader(body)}
}

type nopCloser struct{ *bytes.Reader }

func (nopCloser) Close() error { return nil }
