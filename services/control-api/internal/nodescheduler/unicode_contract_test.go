package nodescheduler

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestUnicodeCodePointLimitsMatchPublicContract(t *testing.T) {
	endpoint := testEndpoint("192.0.2.10", 443, 0, 1)
	endpoint.Region = strings.Repeat("区", 64)
	endpoint.Carrier = strings.Repeat("商", 64)
	request := PutGroupRequest{
		GroupID: uuid.New(), Name: strings.Repeat("线", 128), Endpoints: []Endpoint{endpoint},
		IdempotencyKey: "unicode-create", RequestID: "unicode-create",
	}
	if _, err := normalizePutRequest(request); err != nil {
		t.Fatalf("128/64 code-point labels rejected: %v", err)
	}

	request.Name = strings.Repeat("线", 129)
	if _, err := normalizePutRequest(request); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("129 code-point name error = %v", err)
	}
	request.Name = "线路"
	request.Endpoints[0].Region = strings.Repeat("区", 65)
	if _, err := normalizePutRequest(request); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("65 code-point region error = %v", err)
	}

	plan := Plan{Candidates: []Endpoint{{ID: uuid.New(), Weight: 1}}}
	if _, err := Decide(plan, DecisionRequest{
		Strategy: StrategyWeightedBaseline, StableKey: "  " + strings.Repeat("键", 1020) + "  ",
	}, nil, time.Unix(0, 0)); err != nil {
		t.Fatalf("1024 code-point stable key rejected: %v", err)
	}
	if _, err := Decide(plan, DecisionRequest{
		Strategy: StrategyWeightedBaseline, StableKey: strings.Repeat("键", 1024) + " ",
	}, nil, time.Unix(0, 0)); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("1025 code-point stable key error = %v", err)
	}
	if _, err := Decide(plan, DecisionRequest{
		Strategy: StrategyWeightedBaseline, StableKey: "   ",
	}, nil, time.Unix(0, 0)); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("blank stable key error = %v", err)
	}
}

func TestDecideCurrentRejectsInvalidStableKeyBeforeStorage(t *testing.T) {
	actor := Actor{UserID: uuid.New(), ScopeID: uuid.New()}
	for _, testCase := range []struct {
		name      string
		stableKey string
	}{
		{name: "blank", stableKey: "   "},
		{name: "Unicode White_Space U+0085", stableKey: "\u0085"},
		{name: "raw code-point overflow", stableKey: strings.Repeat("键", 1024) + " "},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			service := &Service{now: func() time.Time {
				t.Fatal("invalid stable key reached clock")
				return time.Time{}
			}}
			_, err := service.DecideCurrent(context.Background(), actor, uuid.New(), DecisionRequest{
				Strategy: StrategyWeightedBaseline, StableKey: testCase.stableKey, RequestID: "unicode-invalid",
			})
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("invalid stable key error = %v", err)
			}
		})
	}
}

func TestECMAScriptWhitespaceNormalizationContract(t *testing.T) {
	plan := Plan{Candidates: []Endpoint{{ID: uuid.New(), Weight: 1}}}
	if _, err := Decide(plan, DecisionRequest{
		Strategy: StrategyWeightedBaseline, StableKey: "\u0085",
	}, nil, time.Unix(0, 0)); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("Unicode White_Space U+0085 error = %v", err)
	}
	if _, err := Decide(plan, DecisionRequest{
		Strategy: StrategyWeightedBaseline, StableKey: "\ufeff",
	}, nil, time.Unix(0, 0)); err != nil {
		t.Fatalf("non-White_Space U+FEFF rejected: %v", err)
	}
	if _, ok := normalizeLabel("\u0085", 1, 128); ok {
		t.Fatal("control U+0085 label accepted")
	}
	if value, ok := normalizeLabel("\ufeff", 1, 128); !ok || value != "\ufeff" {
		t.Fatalf("U+FEFF label = %q, %t", value, ok)
	}
	if value, ok := normalizeStableKey("\u0085\u00a0 key\u3000"); !ok || value != "key" {
		t.Fatalf("mixed-boundary stable key = %q, %t", value, ok)
	}
	if value, ok := normalizeStableKey("\ufeffkey\ufeff"); !ok || value != "\ufeffkey\ufeff" {
		t.Fatalf("U+FEFF stable key = %q, %t", value, ok)
	}
	if _, ok := normalizeStableKey(strings.Repeat("键", 1024) + "\u0085"); ok {
		t.Fatal("trimmed stable key bypassed raw code-point maximum")
	}
	if value, ok := normalizeStableKey(strings.Repeat("键", 1023) + "\ufeff"); !ok || value != strings.Repeat("键", 1023)+"\ufeff" {
		t.Fatalf("U+FEFF at raw maximum = %q, %t", value, ok)
	}
	if _, ok := normalizeStableKey(strings.Repeat("键", 1024) + "\ufeff"); ok {
		t.Fatal("U+FEFF did not count toward raw code-point maximum")
	}
	if value, ok := normalizeLabel("\u00a0线路\u3000", 1, 128); !ok || value != "\u00a0线路\u3000" {
		t.Fatalf("mixed-boundary label = %q, %t", value, ok)
	}
	if _, ok := normalizeLabel(" "+strings.Repeat("线", 128), 1, 128); ok {
		t.Fatal("trimmed label bypassed raw code-point maximum")
	}
}

func TestNormalizePutRequestPreservesControlFreeLabelBytes(t *testing.T) {
	endpoint := testEndpoint("192.0.2.10", 443, 0, 1)
	endpoint.Region = "\u00a0华东\u3000"
	endpoint.Carrier = "\ufeff"
	request := PutGroupRequest{
		GroupID: uuid.New(), Name: "\u00a0线路组\u3000", Endpoints: []Endpoint{endpoint},
		IdempotencyKey: "unicode-preserve", RequestID: "unicode-preserve",
	}

	normalized, err := normalizePutRequest(request)
	if err != nil {
		t.Fatalf("normalizePutRequest() error = %v", err)
	}
	if normalized.name != request.Name || normalized.endpoints[0].Region != endpoint.Region ||
		normalized.endpoints[0].Carrier != endpoint.Carrier {
		t.Fatalf("labels mutated: name=%q region=%q carrier=%q", normalized.name,
			normalized.endpoints[0].Region, normalized.endpoints[0].Carrier)
	}

	request.Endpoints[0].Region = "\u0085"
	if _, err := normalizePutRequest(request); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("control U+0085 region error = %v", err)
	}
}

func TestOpenAPIUnicodeLabelAndStableKeyPatterns(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "api", "control-node-scheduling.openapi.yaml"))
	if err != nil {
		t.Fatalf("read NODE OpenAPI fragment: %v", err)
	}
	contract := string(contents)
	labelCases := []struct {
		schema   string
		property string
		accept   []string
		reject   []string
	}{
		{schema: "LineGroupWrite", property: "name", accept: []string{"线路", "\u00a0线路\u3000", "\ufeff"}, reject: []string{"", "   ", "\u0085", "线\x00路"}},
		{schema: "EndpointWrite", property: "region", accept: []string{"", "\u00a0华东\u3000", "\ufeff"}, reject: []string{"\u0085", "华\x00东"}},
		{schema: "EndpointWrite", property: "carrier", accept: []string{"", "carrier", "\ufeff"}, reject: []string{"\u0085", "carrier\x7f"}},
		{schema: "Selector", property: "region", accept: []string{"", "\ufeff"}, reject: []string{"\u0085", "x\x00"}},
		{schema: "Selector", property: "carrier", accept: []string{"", "\ufeff"}, reject: []string{"\u0085", "x\x7f"}},
		{schema: "DecisionRequest", property: "stable_key", accept: []string{"\ufeff", "key\x00"}, reject: []string{"", " ", "\u0085", "\u00a0\u3000"}},
	}
	for _, testCase := range labelCases {
		t.Run(testCase.schema+"/"+testCase.property, func(t *testing.T) {
			pattern := openAPIPropertyPattern(t, contract, testCase.schema, testCase.property)
			for _, value := range testCase.accept {
				if !pattern.MatchString(value) {
					t.Errorf("pattern %q rejected %q", pattern.String(), value)
				}
			}
			for _, value := range testCase.reject {
				if pattern.MatchString(value) {
					t.Errorf("pattern %q accepted %q", pattern.String(), value)
				}
			}
		})
	}
	if strings.Contains(contract, `\\S`) {
		t.Fatal("NODE OpenAPI uses ECMAScript \\S instead of the explicit Unicode White_Space set")
	}
}

func TestOpenAPIDecisionSnapshotContract(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "api", "control-node-scheduling.openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	contract := string(contents)
	for _, fragment := range []string{
		"required: [endpoint, requested_mode, effective_mode, reason, fallback, priority, candidates, standby, snapshot]",
		"snapshot: {$ref: '#/components/schemas/DecisionSnapshot'}",
		"tier_reason: {type: string, enum: [primary_priority_selected, backup_priority_selected, no_healthy_endpoint]}",
		"enum: [candidate, standby, disabled, selector_mismatch, less_specific, health_unknown, health_unhealthy, health_stale]",
		"health_row_revision: {type: integer, format: int64, minimum: 1}",
	} {
		if !strings.Contains(contract, fragment) {
			t.Fatalf("node scheduling OpenAPI missing %q", fragment)
		}
	}
}

func openAPIPropertyPattern(t *testing.T, contract, schema, property string) *regexp.Regexp {
	t.Helper()
	schemaStart := strings.Index(contract, "\n    "+schema+":\n")
	if schemaStart < 0 {
		t.Fatalf("OpenAPI schema %s not found", schema)
	}
	schemaContract := contract[schemaStart+1:]
	schemaLinePattern := regexp.MustCompile(`(?m)^    [A-Za-z][A-Za-z0-9]+:$`)
	if locations := schemaLinePattern.FindAllStringIndex(schemaContract, 2); len(locations) == 2 {
		schemaContract = schemaContract[:locations[1][0]]
	}
	propertyStart := strings.Index(schemaContract, "\n        "+property+": {")
	if propertyStart < 0 {
		t.Fatalf("OpenAPI property %s.%s not found", schema, property)
	}
	line := schemaContract[propertyStart+1:]
	if end := strings.IndexByte(line, '\n'); end >= 0 {
		line = line[:end]
	}
	const marker = "pattern: '"
	patternStart := strings.Index(line, marker)
	if patternStart < 0 {
		t.Fatalf("OpenAPI property %s.%s has no pattern: %s", schema, property, line)
	}
	encoded := line[patternStart+len(marker):]
	patternEnd := strings.IndexByte(encoded, '\'')
	if patternEnd < 0 {
		t.Fatalf("OpenAPI property %s.%s has malformed pattern: %s", schema, property, line)
	}
	decoded, err := strconv.Unquote(`"` + encoded[:patternEnd] + `"`)
	if err != nil {
		t.Fatalf("decode OpenAPI pattern for %s.%s: %v", schema, property, err)
	}
	pattern, err := regexp.Compile(decoded)
	if err != nil {
		t.Fatalf("compile OpenAPI pattern for %s.%s: %v", schema, property, err)
	}
	return pattern
}

func TestOpenAPIPlatformOwnScopeDeleteContract(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "api", "control-node-scheduling.openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	contract := string(contents)
	for _, fragment := range []string{
		"operationId: deleteNodeLineGroup",
		"summary: 软删除线路组并保留不可变修订历史",
		"平台会话未指定 target_scope_id 时删除本主控平台作用域线路组",
		"显式指定租户作用域时返回 403",
		"'204':",
		"ETag: {$ref: '#/components/headers/ETag'}",
		"Idempotency-Replayed: {$ref: '#/components/headers/IdempotencyReplayed'}",
		"A platform session without target_scope_id manages the platform scope; an explicit tenant target is read-only.",
		"an explicit tenant scope is allowed only on read or decision operations.",
	} {
		if !strings.Contains(contract, fragment) {
			t.Fatalf("node scheduling OpenAPI missing platform owner/delete contract %q", fragment)
		}
	}
}
