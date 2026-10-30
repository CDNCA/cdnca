package l4forward

import (
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

const guardRuleID = "66666666-6666-4666-8666-666666666661"

// 防护规则: guard_rules is checked as the edge does, kept in order, carried
// by the runtime intent; unset it leaves request digests and intents
// unchanged, while responses always carry the array.
func TestGuardRulesNormalizeAndReachTheRuntimeIntent(t *testing.T) {
	encoded, err := json.Marshal(Fields{Protocol: ProtocolTCP})
	if err != nil || strings.Contains(string(encoded), "guard_rules") {
		t.Fatalf("plain fields digest input changed: %s %v", encoded, err)
	}
	fields := validFields()
	fields.GuardRules = []GuardRule{
		{ID: guardRuleID, Action: edgeconfig.L4GuardActionBan, BanSeconds: 600, Threshold: 5, WindowSeconds: 60,
			ClientIP: &edgeconfig.L4GuardClientIP{CIDRs: []string{"198.51.100.0/24", "192.0.2.0/24"}}},
		{ID: "66666666-6666-4666-8666-666666666662", Action: edgeconfig.L4GuardActionDrop,
			FirstPacket: &edgeconfig.L4GuardFirstPacket{Match: edgeconfig.L4GuardMatchPrefixHex, Value: "16030100"}},
	}
	if err := normalizeFields(&fields); err != nil {
		t.Fatalf("guard rules rejected: %v", err)
	}
	if got := strings.Join(fields.GuardRules[0].ClientIP.CIDRs, ","); got != "192.0.2.0/24,198.51.100.0/24" || fields.GuardRules[1].ID == guardRuleID {
		t.Fatalf("rules not canonical or reordered: %+v", fields.GuardRules)
	}
	for name, invalid := range map[string]func(*Fields){
		"sni without passthrough": func(f *Fields) {
			f.GuardRules = []GuardRule{{ID: guardRuleID, Action: edgeconfig.L4GuardActionDrop, ServerNames: []string{"a.example.com"}}}
		},
		"no condition": func(f *Fields) { f.GuardRules = []GuardRule{{ID: guardRuleID, Action: edgeconfig.L4GuardActionDrop}} },
		"ban without threshold": func(f *Fields) {
			f.GuardRules = []GuardRule{{ID: guardRuleID, Action: edgeconfig.L4GuardActionBan, BanSeconds: 60,
				ClientIP: &edgeconfig.L4GuardClientIP{CIDRs: []string{"192.0.2.0/24"}}}}
		},
	} {
		fields := validFields()
		invalid(&fields)
		if err := normalizeFields(&fields); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("%s: %v", name, err)
		}
	}

	item := Forward{ID: uuid.New(), ScopeID: uuid.New(), Protocol: ProtocolTCP, ListenAddress: "*",
		ListenPort: 9000, UpstreamAddress: "192.0.2.10", UpstreamPort: 9000, MaxConnectionsPerClient: 100, Revision: 1,
		GuardRules: []GuardRule{}}
	plain, err := json.Marshal(runtimeSpec(item))
	if err != nil || strings.Contains(string(plain), "guard_rules") {
		t.Fatalf("plain stream intent changed: %s %v", plain, err)
	}
	item.GuardRules = fields.GuardRules
	intent, err := json.Marshal(runtimeSpec(item))
	if err != nil || !strings.Contains(string(intent), `"guard_rules":[{"id":"`+guardRuleID+`","action":"ban"`) {
		t.Fatalf("guarded stream intent: %s %v", intent, err)
	}
	var wire edgeconfig.L4StreamRuntimeV2
	if err := json.Unmarshal(intent, &wire); err != nil || len(wire.GuardRules) != 2 || wire.GuardRules[0].Threshold != 5 {
		t.Fatalf("intent does not decode into the edge contract: %+v %v", wire.GuardRules, err)
	}
	if encoded, err := json.Marshal(Forward{}); err != nil || !strings.Contains(string(encoded), `"guard_rules":[]`) {
		t.Fatalf("stream response must always carry guard_rules: %s %v", encoded, err)
	}
	if column := guardRulesColumn(nil); column != nil {
		t.Fatalf("no rules stored as %v, want NULL", column)
	}
}

// The OpenAPI rule schema names exactly the edge contract's fields.
func TestGuardRuleOpenAPIMatchesTheEdgeContract(t *testing.T) {
	raw, err := os.ReadFile("../../../../api/control-l4-forward.openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := yaml.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	schemas := l4OpenAPIMap(t, l4OpenAPIMap(t, document, "components"), "schemas")
	rule := l4OpenAPIMap(t, l4OpenAPIMap(t, schemas, "StreamGuardRule"), "properties")
	var want []string
	kind := reflect.TypeOf(GuardRule{})
	for index := 0; index < kind.NumField(); index++ {
		want = append(want, strings.Split(kind.Field(index).Tag.Get("json"), ",")[0])
	}
	sort.Strings(want)
	if got := l4OpenAPIKeys(rule); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("StreamGuardRule properties %v, edge contract %v", got, want)
	}
	attributes := l4OpenAPIMap(t, l4OpenAPIMap(t, schemas, "StreamAttributes"), "properties")
	runtime := l4OpenAPIMap(t, l4OpenAPIMap(t, schemas, "StreamRuntimeSpecV2"), "properties")
	if attributes["guard_rules"] == nil || runtime["guard_rules"] == nil {
		t.Fatal("guard_rules missing from the stream or its runtime spec")
	}
}
