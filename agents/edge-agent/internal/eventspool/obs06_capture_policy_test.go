package eventspool

import "testing"

func TestOBS06CapturePolicyFiltersBeforeSanitizing(t *testing.T) {
	policy := CapturePolicy{
		Enabled:           true,
		Methods:           []string{"POST"},
		URIPrefixes:       []string{"/api/private"},
		RequestHeaders:    []string{"Authorization", "X-API-Key", "X-Safe"},
		ResponseHeaders:   []string{"Set-Cookie"},
		RequestBodyFields: []string{"password", "profile"},
	}
	event := sourceAccess(tenantOne)
	event.Method = "POST"
	event.Path = "/api/private/orders?token=must-not-survive"
	event.RequestHeaders = map[string]string{"Authorization": "Bearer raw", "X-API-Key": "raw-key", "X-Safe": "ok"}
	event.ResponseHeaders = map[string]string{"Set-Cookie": "session=raw"}
	event.RequestBody = map[string]any{"password": "raw-password", "profile": map[string]any{"dns_key": "raw-dns", "name": "alice"}}
	captured, err := ParseSourceLine(sourceLine(t, event), policy)
	if err != nil {
		t.Fatal(err)
	}
	profile := captured.RequestBody["profile"].(map[string]any)
	if captured.RequestHeaders["Authorization"] != redactedValue || captured.RequestHeaders["X-Api-Key"] != redactedValue ||
		captured.ResponseHeaders["Set-Cookie"] != redactedValue || captured.RequestBody["password"] != redactedValue ||
		profile["dns_key"] != redactedValue || profile["name"] != "alice" {
		t.Fatalf("capture not structurally redacted: %+v", captured)
	}

	for _, change := range []func(*Envelope){
		func(value *Envelope) { value.Method = "GET" },
		func(value *Envelope) { value.Path = "/public" },
	} {
		candidate := event
		change(&candidate)
		filtered, err := ParseSourceLine(sourceLine(t, candidate), policy)
		if err != nil {
			t.Fatal(err)
		}
		if filtered.RequestHeaders != nil || filtered.ResponseHeaders != nil || filtered.RequestBody != nil || filtered.ResponseBody != nil {
			t.Fatalf("non-matching event retained capture: %+v", filtered)
		}
	}
}

func TestOBS06CapturePolicyDefaultsOffAndRejectsInvalidFilters(t *testing.T) {
	event := sourceAccess(tenantOne)
	event.RequestHeaders = map[string]string{"X-Safe": "must-not-survive"}
	parsed, err := ParseSourceLine(sourceLine(t, event), CapturePolicy{})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.RequestHeaders != nil {
		t.Fatalf("default capture=%+v", parsed.RequestHeaders)
	}

	for _, policy := range []CapturePolicy{
		{Enabled: true, Methods: []string{"get"}},
		{Enabled: true, Methods: []string{"TRACE"}},
		{Enabled: true, URIPrefixes: []string{"api"}},
		{Enabled: true, URIPrefixes: []string{"/api?key=raw"}},
	} {
		if _, err := ParseSourceLine(sourceLine(t, event), policy); err == nil {
			t.Errorf("invalid policy accepted: %+v", policy)
		}
	}
}
