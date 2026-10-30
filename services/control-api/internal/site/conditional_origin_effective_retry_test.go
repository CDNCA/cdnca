package site

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/google/uuid"
)

func TestConditionalOriginResponseExposesFixedEffectiveRetry(t *testing.T) {
	state := withConditionalOriginEffectiveRetry(ConditionalOriginState{SiteID: uuid.New(), Version: 7})
	wantRetryOn := []string{
		"connect_error", "connect_timeout", "read_timeout", "http_502", "http_503", "http_504",
	}
	if !state.EffectiveRetry.BodylessOnly || !state.EffectiveRetry.ResponseNotStarted ||
		!reflect.DeepEqual(state.EffectiveRetry.RetryOn, wantRetryOn) {
		t.Fatalf("effective retry = %+v", state.EffectiveRetry)
	}

	encoded, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	var response map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &response); err != nil {
		t.Fatal(err)
	}
	if _, exists := response["effective_retry"]; !exists {
		t.Fatalf("response has no effective_retry: %s", encoded)
	}

	state.EffectiveRetry.RetryOn[0] = "mutated"
	second := withConditionalOriginEffectiveRetry(ConditionalOriginState{})
	if !reflect.DeepEqual(second.EffectiveRetry.RetryOn, wantRetryOn) {
		t.Fatalf("effective retry shares mutable state: %+v", second.EffectiveRetry)
	}
}

func TestConditionalOriginWriteDocumentRejectsEffectiveRetryOverride(t *testing.T) {
	document := validConditionalOriginDocument()
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(encoded, &body); err != nil {
		t.Fatal(err)
	}
	body["effective_retry"] = map[string]any{
		"bodyless_only": false, "response_not_started": false, "retry_on": []string{"http_500"},
	}
	encoded, err = json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}

	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var decoded ConditionalOriginDocument
	if err := decoder.Decode(&decoded); err == nil {
		t.Fatal("effective_retry override was accepted by the PUT document DTO")
	}
}
