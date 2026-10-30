package analytics

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

const edgeCaptureObjectKeyLimitForTest = 128

func TestCapturedHeaderCardinalityMatchesEdgeLimit(t *testing.T) {
	t.Parallel()
	validators := []struct {
		name     string
		validate func(map[string]string) error
	}{
		{name: "access request", validate: func(headers map[string]string) error {
			event := cardinalityAccessEvent()
			event.RequestHeaders = headers
			return validateAccessEvent(event)
		}},
		{name: "access response", validate: func(headers map[string]string) error {
			event := cardinalityAccessEvent()
			event.ResponseHeaders = headers
			return validateAccessEvent(event)
		}},
		{name: "security request", validate: func(headers map[string]string) error {
			event := cardinalitySecurityEvent()
			event.RequestHeaders = headers
			return validateSecurityEvent(event)
		}},
		{name: "security response", validate: func(headers map[string]string) error {
			event := cardinalitySecurityEvent()
			event.ResponseHeaders = headers
			return validateSecurityEvent(event)
		}},
	}
	for _, validator := range validators {
		validator := validator
		t.Run(validator.name, func(t *testing.T) {
			t.Parallel()
			if err := validator.validate(cardinalityHeaders(edgeCaptureObjectKeyLimitForTest)); err != nil {
				t.Fatalf("128 captured headers rejected: %v", err)
			}
			if err := validator.validate(cardinalityHeaders(edgeCaptureObjectKeyLimitForTest + 1)); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("129 captured headers error = %v, want %v", err, ErrInvalidInput)
			}
		})
	}
}

func TestCapturedBodyAggregateNestedKeyCardinalityMatchesEdgeLimit(t *testing.T) {
	t.Parallel()
	validators := []struct {
		name     string
		validate func(map[string]any) error
	}{
		{name: "access request", validate: func(body map[string]any) error {
			event := cardinalityAccessEvent()
			event.RequestBody = body
			return validateAccessEvent(event)
		}},
		{name: "access response", validate: func(body map[string]any) error {
			event := cardinalityAccessEvent()
			event.ResponseBody = body
			return validateAccessEvent(event)
		}},
		{name: "security request", validate: func(body map[string]any) error {
			event := cardinalitySecurityEvent()
			event.RequestBody = body
			return validateSecurityEvent(event)
		}},
		{name: "security response", validate: func(body map[string]any) error {
			event := cardinalitySecurityEvent()
			event.ResponseBody = body
			return validateSecurityEvent(event)
		}},
	}
	for _, validator := range validators {
		validator := validator
		t.Run(validator.name, func(t *testing.T) {
			t.Parallel()
			if err := validator.validate(cardinalityNestedBody(edgeCaptureObjectKeyLimitForTest)); err != nil {
				t.Fatalf("128 aggregate captured body keys rejected: %v", err)
			}
			if err := validator.validate(cardinalityNestedBody(edgeCaptureObjectKeyLimitForTest + 1)); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("129 aggregate captured body keys error = %v, want %v", err, ErrInvalidInput)
			}
		})
	}
}

func cardinalityHeaders(count int) map[string]string {
	headers := make(map[string]string, count)
	for index := 0; index < count; index++ {
		headers[fmt.Sprintf("X-Capture-%03d", index)] = "value"
	}
	return headers
}

func cardinalityNestedBody(totalKeys int) map[string]any {
	leftKeys := (totalKeys - 2) / 2
	rightKeys := totalKeys - 2 - leftKeys
	return map[string]any{
		"left":  cardinalityNestedObject("left", leftKeys),
		"right": cardinalityNestedObject("right", rightKeys),
	}
}

func cardinalityNestedObject(prefix string, count int) map[string]any {
	object := make(map[string]any, count)
	for index := 0; index < count; index++ {
		object[fmt.Sprintf("%s_%03d", prefix, index)] = "value"
	}
	return object
}

func cardinalityAccessEvent() AccessEvent {
	return AccessEvent{
		MetricVersion: MetricVersion, EventID: "cardinality-access", OccurredAt: cardinalityEventTime(),
		TenantID: "10000000-0000-4000-8000-000000000001",
		SiteID:   "20000000-0000-4000-8000-000000000001",
		NodeID:   "30000000-0000-4000-8000-000000000001",
		Host:     "example.test", Path: "/asset", ClientIP: "192.0.2.1",
		Method: "GET", Protocol: "HTTP/2", CacheStatus: "HIT", StatusCode: 200,
	}
}

func cardinalitySecurityEvent() SecurityEvent {
	return SecurityEvent{
		MetricVersion: MetricVersion, EventID: "cardinality-security", OccurredAt: cardinalityEventTime(),
		TenantID: "10000000-0000-4000-8000-000000000001",
		SiteID:   "20000000-0000-4000-8000-000000000001",
		NodeID:   "30000000-0000-4000-8000-000000000001",
		Host:     "example.test", Path: "/blocked", ClientIP: "192.0.2.2",
		EventType: "waf", Action: "block", Severity: "high", StatusCode: 403,
	}
}

func cardinalityEventTime() time.Time {
	return time.Date(2026, time.August, 5, 0, 0, 0, 0, time.UTC)
}
