package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	webhookPath       = "/webhooks/cdnca/v1"
	healthPath        = "/health/ready"
	allowedEventType  = "io.cdnca.site.v1.updated"
	maxBodyBytes      = 256 * 1024
	minimumSecretSize = 32
	maximumSecretSize = 4096
)

var (
	sourcePattern      = regexp.MustCompile(`^/control-plane/[a-z][a-z0-9_-]{0,63}$`)
	typePattern        = regexp.MustCompile(`^io\.cdnca\.[a-z][a-z0-9_]*\.v[1-9][0-9]*\.[a-z][a-z0-9_]*$`)
	subjectPattern     = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}/[A-Za-z0-9._:-]{1,160}$`)
	traceparentPattern = regexp.MustCompile(`^[0-9a-f]{2}-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$`)
)

type eventRecorder interface {
	Record(eventID, bodySHA256 string, receivedAt time.Time) (recordResult, error)
	Ready() bool
}

type receiver struct {
	secretMu           sync.Mutex
	currentSecret      []byte
	previousSecret     []byte
	previousValidUntil time.Time
	tenantID           string
	journal            eventRecorder
	now                func() time.Time
	maxSkew            time.Duration
	logger             *log.Logger
}

type domainEvent struct {
	SpecVersion     string          `json:"specversion"`
	ID              string          `json:"id"`
	Source          string          `json:"source"`
	Type            string          `json:"type"`
	Subject         string          `json:"subject"`
	Time            string          `json:"time"`
	DataContentType string          `json:"datacontenttype"`
	DataSchema      string          `json:"dataschema"`
	TenantID        string          `json:"tenant_id"`
	RequestID       *string         `json:"request_id,omitempty"`
	Traceparent     *string         `json:"traceparent,omitempty"`
	Sequence        int64           `json:"sequence"`
	Data            json.RawMessage `json:"data"`
}

func newReceiver(currentSecret, previousSecret []byte, previousValidUntil time.Time, tenantID string, recorder eventRecorder, now func() time.Time, maxSkew time.Duration, logger *log.Logger) (*receiver, error) {
	if !validUUID(tenantID) || recorder == nil || now == nil || maxSkew <= 0 || logger == nil ||
		len(currentSecret) < minimumSecretSize || len(currentSecret) > maximumSecretSize ||
		(len(previousSecret) == 0) != previousValidUntil.IsZero() ||
		(len(previousSecret) != 0 && (len(previousSecret) < minimumSecretSize || len(previousSecret) > maximumSecretSize)) {
		return nil, errors.New("invalid receiver configuration")
	}
	configuredAt := now().UTC()
	if configuredAt.IsZero() {
		return nil, errors.New("invalid receiver clock")
	}
	currentCopy := append([]byte(nil), currentSecret...)
	previousCopy := append([]byte(nil), previousSecret...)
	if len(previousCopy) != 0 && !configuredAt.Before(previousValidUntil) {
		clear(previousCopy)
		previousCopy = nil
		previousValidUntil = time.Time{}
	}
	return &receiver{
		currentSecret: currentCopy, previousSecret: previousCopy, previousValidUntil: previousValidUntil,
		tenantID: tenantID, journal: recorder, now: now, maxSkew: maxSkew, logger: logger,
	}, nil
}

func (receiver *receiver) Close() {
	receiver.secretMu.Lock()
	defer receiver.secretMu.Unlock()
	clear(receiver.currentSecret)
	clear(receiver.previousSecret)
	receiver.currentSecret = nil
	receiver.previousSecret = nil
	receiver.previousValidUntil = time.Time{}
}

func (receiver *receiver) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if request.URL.RawQuery != "" {
		writeResponse(response, http.StatusNotFound, "route_not_found")
		return
	}
	switch request.URL.Path {
	case healthPath:
		if request.Method != http.MethodGet {
			writeResponse(response, http.StatusMethodNotAllowed, "method_not_allowed")
			return
		}
		if !receiver.journal.Ready() {
			writeResponse(response, http.StatusServiceUnavailable, "journal_unavailable")
			return
		}
		writeResponse(response, http.StatusOK, "ready")
	case webhookPath:
		receiver.receive(response, request)
	default:
		writeResponse(response, http.StatusNotFound, "route_not_found")
	}
}

func (receiver *receiver) receive(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writeResponse(response, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	contentTypes := request.Header.Values("Content-Type")
	if len(contentTypes) != 1 || contentTypes[0] != "application/cloudevents+json" {
		writeResponse(response, http.StatusUnsupportedMediaType, "content_type_invalid")
		return
	}
	if request.Header.Get("Content-Encoding") != "" {
		writeResponse(response, http.StatusUnsupportedMediaType, "content_encoding_unsupported")
		return
	}
	headers, err := readSignatureHeaders(request.Header)
	if err != nil {
		writeResponse(response, http.StatusBadRequest, "webhook_headers_invalid")
		return
	}
	request.Body = http.MaxBytesReader(response, request.Body, maxBodyBytes)
	body, err := io.ReadAll(request.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeResponse(response, http.StatusRequestEntityTooLarge, "request_body_too_large")
			return
		}
		writeResponse(response, http.StatusBadRequest, "request_body_invalid")
		return
	}
	if len(body) == 0 {
		writeResponse(response, http.StatusBadRequest, "request_body_invalid")
		return
	}
	digest := sha256.Sum256(body)
	now := receiver.now().UTC()
	if !hmac.Equal([]byte(headers.bodySHA256), []byte(hex.EncodeToString(digest[:]))) || !receiver.verifySignature(headers, now) {
		writeResponse(response, http.StatusUnauthorized, "webhook_authentication_failed")
		return
	}
	signedAt := time.Unix(headers.timestamp, 0)
	if signedAt.Before(now.Add(-receiver.maxSkew)) || signedAt.After(now.Add(receiver.maxSkew)) {
		writeResponse(response, http.StatusUnauthorized, "webhook_timestamp_out_of_window")
		return
	}
	event, err := decodeEvent(body)
	if err != nil {
		writeResponse(response, http.StatusBadRequest, "event_invalid")
		return
	}
	if event.TenantID != receiver.tenantID || event.Type != allowedEventType {
		writeResponse(response, http.StatusForbidden, "event_scope_denied")
		return
	}
	result, err := receiver.journal.Record(event.ID, headers.bodySHA256, now)
	if err != nil {
		receiver.logger.Printf("webhook result code=journal_unavailable")
		writeResponse(response, http.StatusServiceUnavailable, "journal_unavailable")
		return
	}
	switch result {
	case recordAccepted:
		receiver.logger.Printf("webhook result code=accepted event_id=%s", event.ID)
		writeResponse(response, http.StatusAccepted, "accepted")
	case recordReplay:
		receiver.logger.Printf("webhook result code=replay_accepted event_id=%s", event.ID)
		writeResponse(response, http.StatusOK, "replay_accepted")
	default:
		receiver.logger.Printf("webhook result code=event_digest_conflict event_id=%s", event.ID)
		writeResponse(response, http.StatusConflict, "event_digest_conflict")
	}
}

type signatureHeaders struct {
	timestampText string
	timestamp     int64
	deliveryID    string
	bodySHA256    string
	signature     []byte
	idempotency   string
	attempt       uint64
}

func readSignatureHeaders(headers http.Header) (signatureHeaders, error) {
	get := func(name string) (string, bool) {
		values := headers.Values(name)
		returnValue := ""
		if len(values) == 1 {
			returnValue = values[0]
		}
		return returnValue, len(values) == 1 && returnValue != ""
	}
	timestampText, timestampOK := get("X-CDNCA-Webhook-Timestamp")
	deliveryID, deliveryOK := get("X-CDNCA-Webhook-Id")
	bodySHA256, digestOK := get("X-CDNCA-Webhook-Content-Sha256")
	signatureText, signatureOK := get("X-CDNCA-Webhook-Signature")
	idempotency, idempotencyOK := get("X-CDNCA-Idempotency-Key")
	attemptText, attemptOK := get("X-CDNCA-Webhook-Attempt")
	timestamp, timestampErr := strconv.ParseInt(timestampText, 10, 64)
	attempt, attemptErr := strconv.ParseUint(attemptText, 10, 32)
	signature, signatureErr := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(signatureText, "v1="))
	if !timestampOK || !deliveryOK || !digestOK || !signatureOK || !idempotencyOK || !attemptOK ||
		timestampErr != nil || timestamp <= 0 || strconv.FormatInt(timestamp, 10) != timestampText ||
		attemptErr != nil || attempt == 0 || strconv.FormatUint(attempt, 10) != attemptText ||
		!validUUID(deliveryID) || !validSHA256(bodySHA256) || !strings.HasPrefix(signatureText, "v1=") ||
		signatureErr != nil || len(signature) != sha256.Size || len(idempotency) > 128 || !visibleASCII(idempotency) {
		return signatureHeaders{}, errors.New("invalid webhook headers")
	}
	return signatureHeaders{
		timestampText: timestampText, timestamp: timestamp, deliveryID: deliveryID, bodySHA256: bodySHA256,
		signature: signature, idempotency: idempotency, attempt: attempt,
	}, nil
}

func (receiver *receiver) verifySignature(headers signatureHeaders, now time.Time) bool {
	receiver.secretMu.Lock()
	defer receiver.secretMu.Unlock()
	payload := []byte("cdnca.webhook.signature/v1\n" + headers.timestampText + "\n" + headers.deliveryID + "\n" + headers.bodySHA256)
	verify := func(secret []byte) bool {
		mac := hmac.New(sha256.New, secret)
		_, _ = mac.Write(payload)
		return hmac.Equal(headers.signature, mac.Sum(nil))
	}
	valid := verify(receiver.currentSecret)
	if len(receiver.previousSecret) != 0 {
		if now.Before(receiver.previousValidUntil) {
			valid = verify(receiver.previousSecret) || valid
		} else {
			clear(receiver.previousSecret)
			receiver.previousSecret = nil
			receiver.previousValidUntil = time.Time{}
		}
	}
	return valid
}

func decodeEvent(body []byte) (domainEvent, error) {
	if err := validateJSON(body); err != nil {
		return domainEvent{}, err
	}
	var event domainEvent
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&event); err != nil {
		return domainEvent{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return domainEvent{}, errors.New("trailing JSON value")
	}
	parsedSchema, schemaErr := url.Parse(event.DataSchema)
	_, timeErr := time.Parse(time.RFC3339Nano, event.Time)
	var data map[string]json.RawMessage
	dataErr := json.Unmarshal(event.Data, &data)
	if event.SpecVersion != "1.0" || !validUUID(event.ID) || !sourcePattern.MatchString(event.Source) || len(event.Source) > 128 ||
		!typePattern.MatchString(event.Type) || len(event.Type) > 160 || !subjectPattern.MatchString(event.Subject) || len(event.Subject) > 225 ||
		timeErr != nil || event.DataContentType != "application/json" || schemaErr != nil || !parsedSchema.IsAbs() || len(event.DataSchema) > 2048 ||
		!validUUID(event.TenantID) || (event.RequestID != nil && (len(*event.RequestID) == 0 || len(*event.RequestID) > 128)) ||
		(event.Traceparent != nil && !traceparentPattern.MatchString(*event.Traceparent)) || event.Sequence < 1 || dataErr != nil || data == nil {
		return domainEvent{}, errors.New("event does not match domain-event v1")
	}
	return event, nil
}

func validateJSON(body []byte) error {
	if !utf8.Valid(body) {
		return errors.New("JSON is not valid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return errors.New("event must be a JSON object")
	}
	if err := validateJSONObject(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON value")
	}
	return nil
}

func validateJSONObject(decoder *json.Decoder) error {
	seen := make(map[string]struct{})
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		key, ok := token.(string)
		if !ok {
			return errors.New("invalid JSON object key")
		}
		if _, duplicate := seen[key]; duplicate {
			return errors.New("duplicate JSON object key")
		}
		seen[key] = struct{}{}
		if err := validateJSONValue(decoder); err != nil {
			return err
		}
	}
	_, err := decoder.Token()
	return err
}

func validateJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		return validateJSONObject(decoder)
	case '[':
		for decoder.More() {
			if err := validateJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err := decoder.Token()
		return err
	default:
		return errors.New("invalid JSON delimiter")
	}
}

func validUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(strings.ReplaceAll(value, "-", ""))
	if err != nil || len(decoded) != 16 {
		return false
	}
	for _, part := range decoded {
		if part != 0 {
			return true
		}
	}
	return false
}

func validSHA256(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && value == strings.ToLower(value)
}

func visibleASCII(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range []byte(value) {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

func writeResponse(response http.ResponseWriter, status int, code string) {
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(status)
	_, _ = fmt.Fprintf(response, "{\"code\":%q}\n", code)
}
