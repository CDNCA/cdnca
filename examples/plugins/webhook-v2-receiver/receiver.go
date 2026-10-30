package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	webhookPath      = "/cdnca/hooks"
	healthPath       = "/health/ready"
	maxBodyBytes     = 320 * 1024
	maxSecretBytes   = 4096
	minSecretBytes   = 32
	maxTimestampSkew = 5 * time.Minute
	contentType      = "application/cloudevents+json"
	testEventType    = "io.cdnca.webhook.v1.test"
	testSchema       = "https://schemas.cdnca.example/marketplace/v1/webhook-test-event.schema.json"
	siteEventType    = "io.cdnca.site.v1.updated"
	domainSchema     = "https://schemas.cdnca.example/marketplace/v1/domain-event.schema.json"
)

// Site change values from domain-event.schema.json (definitions.site_updated).
var (
	siteChanges      = map[string]bool{"created": true, "updated": true, "enabled": true, "disabled": true, "deleted": true}
	siteChangeFields = map[string]bool{"domains": true, "origins": true, "ports": true, "https": true, "line_group": true, "status": true, "settings": true}
)

var (
	requestIDPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	traceparentPattern = regexp.MustCompile(`^00-[0-9a-f]{32}-[0-9a-f]{16}-(00|01)$`)
	hexDigestPattern   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	extensionPattern   = regexp.MustCompile(`^x_[a-z][a-z0-9_]{0,63}$`)
	idempotencyPattern = regexp.MustCompile(`^plugin-webhook-v2-[0-9a-f]{64}$`)
	eventTimePattern   = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z$`)
)

type secretVersion struct {
	ID       string
	Secret   []byte
	ValidTil time.Time
}

type cloudEvent struct {
	SpecVersion     string                     `json:"specversion"`
	ID              string                     `json:"id"`
	Source          string                     `json:"source"`
	Type            string                     `json:"type"`
	Subject         string                     `json:"subject"`
	Time            string                     `json:"time"`
	DataContentType string                     `json:"datacontenttype"`
	DataSchema      string                     `json:"dataschema"`
	TenantID        string                     `json:"tenant_id"`
	RequestID       string                     `json:"request_id"`
	Traceparent     string                     `json:"traceparent,omitempty"`
	Sequence        uint64                     `json:"sequence"`
	Data            map[string]json.RawMessage `json:"data"`

	site *siteChange
}

// siteChange is the business payload of one io.cdnca.site.v1.updated event.
type siteChange struct {
	SiteID          string   `json:"site_id"`
	Change          string   `json:"change"`
	ChangedFields   []string `json:"changed_fields"`
	SubjectSequence uint64   `json:"subject_sequence"`
}

type eventRecorder interface {
	// Record stores one delivery. site is the business change of a site event
	// (nil for a test event); it is recorded once per event ID.
	Record(deliveryID, eventID, bodySHA256 string, receivedAt time.Time, site *siteChange) (recordResult, error)
	Ready() bool
}

type recordResult uint8

const (
	recordAccepted recordResult = iota
	recordReplay
	recordConflict
	// recordEventDuplicate: a new delivery (explicit replay) of an event
	// already processed; the business change is not applied again.
	recordEventDuplicate
)

type receiver struct {
	mu             sync.RWMutex
	current        secretVersion
	previous       secretVersion
	tenantID       string
	subscriptionID string
	journal        eventRecorder
	now            func() time.Time
	logger         *log.Logger
}

func newReceiver(current, previous secretVersion, tenantID, subscriptionID string, journal eventRecorder, now func() time.Time, logger *log.Logger) (*receiver, error) {
	if !validUUID(current.ID) || len(current.Secret) < minSecretBytes || len(current.Secret) > maxSecretBytes ||
		!validUUID(tenantID) || !validUUID(subscriptionID) || journal == nil || now == nil || logger == nil {
		return nil, errors.New("invalid receiver configuration")
	}
	if (previous.ID == "") != (len(previous.Secret) == 0) || (previous.ID == "") != previous.ValidTil.IsZero() ||
		previous.ID != "" && (!validUUID(previous.ID) || len(previous.Secret) < minSecretBytes || len(previous.Secret) > maxSecretBytes) {
		return nil, errors.New("invalid previous secret configuration")
	}
	return &receiver{current: cloneSecret(current), previous: cloneSecret(previous), tenantID: tenantID, subscriptionID: subscriptionID, journal: journal, now: now, logger: logger}, nil
}

func (r *receiver) Close() {
	r.mu.Lock()
	clear(r.current.Secret)
	clear(r.previous.Secret)
	r.current.Secret = nil
	r.previous.Secret = nil
	r.mu.Unlock()
}

func (r *receiver) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodGet && request.URL.EscapedPath() == healthPath && request.URL.RawQuery == "" {
		if r.journal.Ready() {
			writeJSON(response, http.StatusOK, `{"code":"ready"}`)
		} else {
			writeJSON(response, http.StatusServiceUnavailable, `{"code":"journal_unavailable"}`)
		}
		return
	}
	if request.URL.EscapedPath() == webhookPath && request.URL.RawQuery == "" && request.Method != http.MethodPost {
		writeJSON(response, http.StatusMethodNotAllowed, `{"code":"method_not_allowed"}`)
		return
	}
	if request.Method != http.MethodPost || request.URL.EscapedPath() != webhookPath || request.URL.RawPath != "" || request.URL.RawQuery != "" {
		writeJSON(response, http.StatusNotFound, `{"code":"route_not_found"}`)
		return
	}
	if len(request.Header.Values("Content-Type")) != 1 || request.Header.Get("Content-Type") != contentType || len(request.Header.Values("Content-Encoding")) != 0 {
		writeJSON(response, http.StatusUnsupportedMediaType, `{"code":"content_type_invalid"}`)
		return
	}
	if !validRequestHeaders(request) {
		writeJSON(response, http.StatusBadRequest, `{"code":"webhook_headers_invalid"}`)
		return
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, maxBodyBytes+1))
	if err != nil {
		writeJSON(response, http.StatusBadRequest, `{"code":"request_body_invalid"}`)
		return
	}
	if len(body) == 0 {
		writeJSON(response, http.StatusBadRequest, `{"code":"request_body_invalid"}`)
		return
	}
	if len(body) > maxBodyBytes {
		writeJSON(response, http.StatusRequestEntityTooLarge, `{"code":"request_body_too_large"}`)
		return
	}
	digest := sha256.Sum256(body)
	digestText := hex.EncodeToString(digest[:])
	if !hmac.Equal([]byte(digestText), []byte(request.Header.Get("X-CDNCA-Webhook-Content-Sha256"))) {
		writeJSON(response, http.StatusUnauthorized, `{"code":"webhook_authentication_failed"}`)
		return
	}
	if !r.verifySignature(request, digestText) {
		writeJSON(response, http.StatusUnauthorized, `{"code":"webhook_authentication_failed"}`)
		return
	}
	event, err := decodeEvent(body)
	if err != nil {
		writeJSON(response, http.StatusBadRequest, `{"code":"event_invalid"}`)
		return
	}
	if event.ID != request.Header.Get("X-CDNCA-Webhook-Event-Id") {
		writeJSON(response, http.StatusBadRequest, `{"code":"event_invalid"}`)
		return
	}
	if event.TenantID != r.tenantID || event.Type == testEventType && event.Subject != "webhook_subscription/"+r.subscriptionID ||
		event.Data["subscription_id"] == nil || string(event.Data["subscription_id"]) != `"`+r.subscriptionID+`"` {
		writeJSON(response, http.StatusForbidden, `{"code":"event_scope_denied"}`)
		return
	}
	var site *siteChange
	if event.Type == siteEventType {
		site = event.site
	}
	deliveryID := request.Header.Get("X-CDNCA-Webhook-Delivery-Id")
	result, err := r.journal.Record(deliveryID, event.ID, digestText, r.now().UTC(), site)
	if err != nil {
		writeJSON(response, http.StatusServiceUnavailable, `{"code":"journal_unavailable"}`)
		return
	}
	switch result {
	case recordReplay:
		writeJSON(response, http.StatusOK, `{"code":"replay_accepted"}`)
	case recordEventDuplicate:
		writeJSON(response, http.StatusOK, `{"code":"event_already_processed"}`)
	case recordConflict:
		writeJSON(response, http.StatusConflict, `{"code":"delivery_digest_conflict"}`)
	default:
		writeJSON(response, http.StatusAccepted, `{"code":"accepted"}`)
	}
}

func (r *receiver) verifySignature(request *http.Request, digest string) bool {
	timestampText := request.Header.Get("X-CDNCA-Webhook-Timestamp")
	timestamp, err := strconv.ParseInt(timestampText, 10, 64)
	if err != nil || strconv.FormatInt(timestamp, 10) != timestampText {
		return false
	}
	when := time.Unix(timestamp, 0)
	now := r.now().UTC()
	if when.Before(now.Add(-maxTimestampSkew)) || when.After(now.Add(maxTimestampSkew)) {
		return false
	}
	eventID := request.Header.Get("X-CDNCA-Webhook-Event-Id")
	deliveryID := request.Header.Get("X-CDNCA-Webhook-Delivery-Id")
	keyID := request.Header.Get("X-CDNCA-Webhook-Key-Id")
	if !validUUID(eventID) || !validUUID(deliveryID) || !validUUID(keyID) ||
		request.Header.Get("X-CDNCA-Webhook-Signature-Version") != "v2" {
		return false
	}
	signatureText := request.Header.Get("X-CDNCA-Webhook-Signature")
	if !strings.HasPrefix(signatureText, "v2=") {
		return false
	}
	signature, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(signatureText, "v2="))
	if err != nil || len(signature) != sha256.Size {
		return false
	}
	secret, ok := r.secret(keyID, now)
	if !ok {
		return false
	}
	payload := strings.Join([]string{"cdnca.webhook.signature/v2", http.MethodPost, webhookPath, timestampText, eventID, deliveryID, keyID, digest}, "\n")
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(payload))
	valid := hmac.Equal(signature, mac.Sum(nil))
	clear(secret)
	return valid
}

func (r *receiver) secret(keyID string, now time.Time) ([]byte, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if keyID == r.current.ID {
		return append([]byte(nil), r.current.Secret...), true
	}
	if keyID == r.previous.ID {
		if !now.Before(r.previous.ValidTil) {
			clear(r.previous.Secret)
			r.previous = secretVersion{}
			return nil, false
		}
		return append([]byte(nil), r.previous.Secret...), true
	}
	return nil, false
}

func decodeEvent(body []byte) (cloudEvent, error) {
	var event cloudEvent
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&event); err != nil {
		return cloudEvent{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return cloudEvent{}, errors.New("trailing JSON")
	}
	canonical, err := json.Marshal(event)
	if err != nil || !bytes.Equal(canonical, body) {
		return cloudEvent{}, errors.New("non-canonical event")
	}
	if event.SpecVersion != "1.0" || !validUUIDv7(event.ID) || event.Source != "/control-plane/plugin-webhooks" ||
		!validUUID(event.TenantID) || event.DataContentType != "application/json" ||
		!requestIDPattern.MatchString(event.RequestID) || event.Sequence == 0 || !validEventTime(event.Time) ||
		(event.Traceparent != "" && !validTraceparent(event.Traceparent)) {
		return cloudEvent{}, errors.New("event fields invalid")
	}
	switch event.Type {
	case testEventType:
		if !validSubject(event.Subject) || event.DataSchema != testSchema || !validData(event.Data) {
			return cloudEvent{}, errors.New("test event fields invalid")
		}
	case siteEventType:
		site, ok := siteData(event.Data)
		if !ok || event.DataSchema != domainSchema || event.Subject != "site/"+site.SiteID {
			return cloudEvent{}, errors.New("site event fields invalid")
		}
		event.site = site
	default:
		// Only the events this example subscribes to; anything else is refused, not acknowledged.
		return cloudEvent{}, errors.New("unsupported event type")
	}
	return event, nil
}

// siteData strictly decodes the data of io.cdnca.site.v1.updated: exactly
// subscription_id, subject_sequence, site_id, change and changed_fields.
func siteData(data map[string]json.RawMessage) (*siteChange, bool) {
	if len(data) != 5 || data["subscription_id"] == nil {
		return nil, false
	}
	var subscriptionID string
	if json.Unmarshal(data["subscription_id"], &subscriptionID) != nil || !validUUID(subscriptionID) {
		return nil, false
	}
	var site siteChange
	if json.Unmarshal(data["site_id"], &site.SiteID) != nil || !validUUID(site.SiteID) ||
		json.Unmarshal(data["change"], &site.Change) != nil || !siteChanges[site.Change] ||
		json.Unmarshal(data["changed_fields"], &site.ChangedFields) != nil || site.ChangedFields == nil || len(site.ChangedFields) > 32 {
		return nil, false
	}
	seen := make(map[string]bool, len(site.ChangedFields))
	for _, field := range site.ChangedFields {
		if !siteChangeFields[field] || seen[field] {
			return nil, false
		}
		seen[field] = true
	}
	sequenceText := string(data["subject_sequence"])
	sequence, err := strconv.ParseUint(sequenceText, 10, 64)
	if err != nil || sequence == 0 || sequence > 999999999999999999 || strconv.FormatUint(sequence, 10) != sequenceText {
		return nil, false
	}
	site.SubjectSequence = sequence
	return &site, true
}

func validData(data map[string]json.RawMessage) bool {
	if len(data) < 2 || len(data) > 10 {
		return false
	}
	subscription, ok := data["subscription_id"]
	if !ok || string(subscription) == "" {
		return false
	}
	if _, ok := data["test"]; !ok || string(data["test"]) != "true" {
		return false
	}
	for key, value := range data {
		if len(value) == 0 || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return false
		}
		if key == "subscription_id" || key == "test" {
			continue
		}
		if !extensionPattern.MatchString(key) {
			return false
		}
	}
	var subscriptionID string
	return json.Unmarshal(subscription, &subscriptionID) == nil && validUUID(subscriptionID)
}

func validRequestHeaders(request *http.Request) bool {
	for _, name := range []string{
		"X-CDNCA-Webhook-Event-Id", "X-CDNCA-Webhook-Delivery-Id", "X-CDNCA-Webhook-Timestamp",
		"X-CDNCA-Webhook-Content-Sha256", "X-CDNCA-Webhook-Key-Id", "X-CDNCA-Webhook-Signature-Version",
		"X-CDNCA-Webhook-Signature", "X-CDNCA-Idempotency-Key", "X-CDNCA-Webhook-Attempt",
	} {
		if len(request.Header.Values(name)) != 1 || request.Header.Get(name) == "" {
			return false
		}
	}
	if !validUUID(request.Header.Get("X-CDNCA-Webhook-Event-Id")) ||
		!validUUID(request.Header.Get("X-CDNCA-Webhook-Delivery-Id")) ||
		!validUUID(request.Header.Get("X-CDNCA-Webhook-Key-Id")) ||
		!hexDigestPattern.MatchString(request.Header.Get("X-CDNCA-Webhook-Content-Sha256")) ||
		!idempotencyPattern.MatchString(request.Header.Get("X-CDNCA-Idempotency-Key")) ||
		request.Header.Get("X-CDNCA-Webhook-Signature-Version") != "v2" {
		return false
	}
	deliveryID := request.Header.Get("X-CDNCA-Webhook-Delivery-Id")
	deliveryDigest := sha256.Sum256([]byte(deliveryID))
	if request.Header.Get("X-CDNCA-Idempotency-Key") != "plugin-webhook-v2-"+hex.EncodeToString(deliveryDigest[:]) {
		return false
	}
	attemptText := request.Header.Get("X-CDNCA-Webhook-Attempt")
	attempt, err := strconv.ParseUint(attemptText, 10, 64)
	if err != nil || attempt == 0 || strconv.FormatUint(attempt, 10) != attemptText {
		return false
	}
	return true
}

func validEventTime(value string) bool {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	return err == nil && eventTimePattern.MatchString(value) && parsed.UTC().Format(time.RFC3339Nano) == value
}

func validSubject(value string) bool {
	return strings.HasPrefix(value, "webhook_subscription/") && validUUID(value[len("webhook_subscription/"):])
}

func validUUID(value string) bool {
	if len(value) != 36 || value == "00000000-0000-0000-0000-000000000000" || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' || value != strings.ToLower(value) {
		return false
	}
	for index, character := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			continue
		}
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

func validUUIDv7(value string) bool {
	return validUUID(value) && value[14] == '7' && strings.ContainsRune("89ab", rune(value[19]))
}

func validTraceparent(value string) bool {
	if !traceparentPattern.MatchString(value) {
		return false
	}
	parts := strings.Split(value, "-")
	return strings.Trim(parts[1], "0") != "" && strings.Trim(parts[2], "0") != ""
}

func cloneSecret(value secretVersion) secretVersion {
	value.Secret = append([]byte(nil), value.Secret...)
	return value
}

func writeJSON(response http.ResponseWriter, status int, body string) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_, _ = response.Write([]byte(body))
}

func decodeBase64Secret(value string) ([]byte, error) {
	if len(value) != 43 {
		return nil, errors.New("secret must be 43-character base64url")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != minSecretBytes || base64.RawURLEncoding.EncodeToString(decoded) != value {
		clear(decoded)
		return nil, errors.New("secret must be canonical base64url for 32 raw bytes")
	}
	return decoded, nil
}
