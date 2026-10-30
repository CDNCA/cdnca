package eventspool

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestOBS12CapturePresenceSurvivesSanitizerAndPublication(t *testing.T) {
	event := sourceAccess(tenantOne)
	event.RequestHeaders = map[string]string{}
	event.ResponseHeaders = map[string]string{}
	event.RequestBody = map[string]any{}
	event.ResponseBody = map[string]any{}
	policy := CapturePolicy{
		Enabled:        true,
		RequestHeaders: []string{"X-Request"}, ResponseHeaders: []string{"X-Response"},
		RequestBodyFields: []string{"request"}, ResponseBodyFields: []string{"response"},
		MaxHeaderValueBytes: 64, MaxBodyBytes: 1024, MaxEventBytes: 8192,
	}
	captured, err := ParseSourceLine(sourceLine(t, event), policy)
	if err != nil {
		t.Fatal(err)
	}
	if captured.RequestHeaders == nil || captured.ResponseHeaders == nil || captured.RequestBody == nil || captured.ResponseBody == nil {
		t.Fatalf("enabled empty captures lost presence: %+v", captured)
	}
	disabled, err := ParseSourceLine(sourceLine(t, event), CapturePolicy{})
	if err != nil {
		t.Fatal(err)
	}
	if disabled.RequestHeaders != nil || disabled.ResponseHeaders != nil || disabled.RequestBody != nil || disabled.ResponseBody != nil {
		t.Fatalf("disabled captures must remain null: %+v", disabled)
	}

	assertPublicationCapturePresence(t, captured, `{}`)
	assertPublicationCapturePresence(t, disabled, `null`)
}

func TestOBS12SourceRejectsSelfReportedAuthorityAndInvalidOriginTiming(t *testing.T) {
	identity := TrustedIdentity{
		EnrollmentNodeID: nodeOne, TenantID: tenantOne, SiteID: siteOne, ConfigVersionID: "cfg-1",
	}
	forgedInstallation := sourceAccess(tenantOne)
	forgedInstallation.InstallationID = "55555555-5555-4555-8555-555555555555"
	if _, err := ParseSourceLineBound(sourceLine(t, forgedInstallation), CapturePolicy{}, identity); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("self-reported installation error = %v, want ErrInvalidEvent", err)
	}
	forgedTask := sourceAccess(tenantOne)
	forgedTask.TaskID = stringPointer("forged-task")
	if _, err := ParseSourceLineBound(sourceLine(t, forgedTask), CapturePolicy{}, identity); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("self-reported task error = %v, want ErrInvalidEvent", err)
	}
	// JA4 comes from the node's own TLS layer ($cdnca_ja4): a fingerprint is
	// kept, "" (no TLS fingerprint) becomes null, anything else is refused.
	for _, malformed := range []string{"forged-ja4", "t13d1516h2_8daaf6152771", "T13D1516H2_8DAAF6152771_E5627EFA2AB1"} {
		forged := sourceAccess(tenantOne)
		forged.JA4 = stringPointer(malformed)
		if _, err := ParseSourceLineBound(sourceLine(t, forged), CapturePolicy{}, identity); !errors.Is(err, ErrInvalidEvent) {
			t.Fatalf("malformed JA4 %q error = %v, want ErrInvalidEvent", malformed, err)
		}
	}
	fingerprinted := sourceAccess(tenantOne)
	fingerprinted.JA4 = stringPointer("t13d1516h2_8daaf6152771_e5627efa2ab1")
	if parsed, err := ParseSourceLineBound(sourceLine(t, fingerprinted), CapturePolicy{}, identity); err != nil ||
		parsed.JA4 == nil || *parsed.JA4 != "t13d1516h2_8daaf6152771_e5627efa2ab1" {
		t.Fatalf("JA4 source = %+v, %v; want the fingerprint kept", parsed.JA4, err)
	}
	unfingerprinted := sourceAccess(tenantOne)
	unfingerprinted.JA4 = stringPointer("")
	if parsed, err := ParseSourceLineBound(sourceLine(t, unfingerprinted), CapturePolicy{}, identity); err != nil || parsed.JA4 != nil {
		t.Fatalf("empty JA4 source = %+v, %v; want null", parsed.JA4, err)
	}

	valid := sourceAccess(tenantOne)
	valid.DurationUS = 999999
	valid.OriginConnectUS = uint64Pointer(1200)
	valid.OriginFirstByteUS = uint64Pointer(2400)
	valid.OriginTotalUS = uint64Pointer(3600)
	line := sourceLine(t, valid)
	parsed, err := ParseSourceLine(line, CapturePolicy{})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.DurationUS != valid.DurationUS || *parsed.OriginConnectUS != 1200 || *parsed.OriginFirstByteUS != 2400 || *parsed.OriginTotalUS != 3600 {
		t.Fatalf("origin timing changed or reused duration: %+v", parsed)
	}

	invalid := [][]byte{
		bytes.Replace(line, []byte(`"origin_connect_us":1200`), []byte(`"origin_connect_us":-1`), 1),
		bytes.Replace(line, []byte(`"origin_connect_us":1200`), []byte(`"origin_connect_us":"not-a-number"`), 1),
		bytes.Replace(line, []byte(`"origin_connect_us":1200`), []byte(`"origin_connect_us":"0.001, 0.002"`), 1),
		bytes.Replace(line, []byte(`"origin_connect_us":1200`), []byte(`"origin_connect_us":18446744073709551616`), 1),
		bytes.Replace(line, []byte(`"origin_connect_us":1200`), []byte(`"origin_connect_us":3000`), 1),
	}
	for index, candidate := range invalid {
		if _, err := ParseSourceLine(candidate, CapturePolicy{}); !errors.Is(err, ErrInvalidEvent) {
			t.Errorf("invalid timing case %d error = %v, want ErrInvalidEvent", index, err)
		}
	}
}

func TestOBS12SanitizerRedactsAndBoundsCapture(t *testing.T) {
	event := sourceAccess(tenantOne)
	event.RequestHeaders = map[string]string{"Authorization": "Bearer secret", "X-Allowed": "ok"}
	event.RequestBody = map[string]any{
		"profile": map[string]any{"password": "secret", "name": "alice"},
	}
	policy := CapturePolicy{
		Enabled: true, RequestHeaders: []string{"Authorization", "X-Allowed"}, RequestBodyFields: []string{"profile"},
		MaxHeaderValueBytes: 64, MaxBodyBytes: 4096, MaxEventBytes: 16384,
	}
	parsed, err := ParseSourceLine(sourceLine(t, event), policy)
	if err != nil {
		t.Fatal(err)
	}
	profile := parsed.RequestBody["profile"].(map[string]any)
	if parsed.RequestHeaders["Authorization"] != redactedValue || profile["password"] != redactedValue {
		t.Fatalf("sensitive capture was not redacted: %+v", parsed)
	}

	tooMany := sourceAccess(tenantOne)
	nested := make(map[string]any, 129)
	for index := 0; index < 129; index++ {
		nested[fmt.Sprintf("key-%03d", index)] = index
	}
	tooMany.RequestBody = map[string]any{"profile": nested}
	if _, err := ParseSourceLine(sourceLine(t, tooMany), policy); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("capture key limit error = %v", err)
	}

	tooDeep := sourceAccess(tenantOne)
	var value any = "leaf"
	for depth := 0; depth < 10; depth++ {
		value = map[string]any{"level": value}
	}
	tooDeep.RequestBody = map[string]any{"profile": value}
	if _, err := ParseSourceLine(sourceLine(t, tooDeep), policy); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("capture depth limit error = %v", err)
	}

	tooLarge := event
	tooLarge.RequestHeaders = map[string]string{"X-Allowed": strings.Repeat("x", 65)}
	if _, err := ParseSourceLine(sourceLine(t, tooLarge), policy); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("capture value limit error = %v", err)
	}

	duplicate := bytes.Replace(sourceLine(t, event), []byte(`"name":"alice"`), []byte(`"name":"alice","name":"forged"`), 1)
	if _, err := ParseSourceLine(duplicate, policy); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("duplicate nested JSON key error = %v", err)
	}

	policy.MaxEventBytes = 512
	if _, err := ParseSourceLine(sourceLine(t, event), policy); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("event byte limit error = %v", err)
	}
}

func assertPublicationCapturePresence(t *testing.T, event Envelope, want string) {
	t.Helper()
	event.EventID = "evt-presence"
	event.Sequence = 1
	publication, err := encodePublication([]Record{{
		Sequence: 1, EventID: event.EventID, TenantID: event.TenantID, NodeID: event.NodeID,
		Type: event.Type, OccurredAt: event.OccurredAt, envelope: event,
	}})
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Events []map[string]json.RawMessage `json:"events"`
	}
	if err := json.Unmarshal(publication.Payload, &envelope); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"request_headers", "response_headers", "request_body", "response_body"} {
		if got := string(envelope.Events[0][field]); got != want {
			t.Errorf("publication %s = %s, want %s; payload=%s", field, got, want, publication.Payload)
		}
	}
}

func stringPointer(value string) *string { return &value }
func uint64Pointer(value uint64) *uint64 { return &value }
