package nodescheduler

import (
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestNormalizeL2ConfigWrite(t *testing.T) {
	request := L2ConfigWriteRequest{
		ExpectedRevision: 0,
		Name:             "  华东 L2  ",
		Region:           "  华东  ",
		Remark:           "  主配置  ",
		Mode:             L2ModeCache,
		LoadMethod:       L2LoadRoundRobin,
		IdempotencyKey:   "l2-config-create-1",
		RequestID:        "l2-config-request-1",
	}
	normalized, err := normalizeL2ConfigWrite(request)
	if err != nil {
		t.Fatal(err)
	}
	if normalized.Name != "华东 L2" || normalized.Region != "华东" || normalized.Remark != "主配置" {
		t.Fatalf("normalized config = %#v", normalized)
	}
	for _, region := range []string{"", "默认", "cn-east", strings.Repeat("区", 64)} {
		t.Run("region="+region, func(t *testing.T) {
			candidate := request
			candidate.Region = region
			got, err := normalizeL2ConfigWrite(candidate)
			if err != nil || got.Region != region {
				t.Fatalf("region = %q, err = %v, want %q", got.Region, err, region)
			}
		})
	}

	for name, mutate := range map[string]func(*L2ConfigWriteRequest){
		"missing name":         func(candidate *L2ConfigWriteRequest) { candidate.Name = " " },
		"blank region":         func(candidate *L2ConfigWriteRequest) { candidate.Region = " " },
		"unicode whitespace":   func(candidate *L2ConfigWriteRequest) { candidate.Region = "\u00a0\u3000" },
		"oversized region":     func(candidate *L2ConfigWriteRequest) { candidate.Region = strings.Repeat("区", 65) },
		"control in region":    func(candidate *L2ConfigWriteRequest) { candidate.Region = "华\n东" },
		"invalid UTF-8 region": func(candidate *L2ConfigWriteRequest) { candidate.Region = "\xff" },
		"invalid mode":         func(candidate *L2ConfigWriteRequest) { candidate.Mode = "proxy" },
		"invalid load method":  func(candidate *L2ConfigWriteRequest) { candidate.LoadMethod = "random" },
		"invalid revision":     func(candidate *L2ConfigWriteRequest) { candidate.ExpectedRevision = -1 },
		"invalid metadata":     func(candidate *L2ConfigWriteRequest) { candidate.IdempotencyKey = "contains space" },
		"control character":    func(candidate *L2ConfigWriteRequest) { candidate.Remark = "bad\nremark" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := request
			mutate(&candidate)
			if _, err := normalizeL2ConfigWrite(candidate); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("error = %v, want ErrInvalidInput", err)
			}
		})
	}
}

func TestNormalizeL2ConditionWrite(t *testing.T) {
	request := L2ConditionWriteRequest{
		Name: " 海外请求 ", Remark: " 节点选择 ",
		Rules:          []L2Rule{{Field: "node_country", Operator: "neq", Value: " CN "}},
		IdempotencyKey: "l2-condition-create-1", RequestID: "l2-condition-request-1",
	}
	normalized, err := normalizeL2ConditionWrite(request)
	if err != nil {
		t.Fatal(err)
	}
	if normalized.Name != "海外请求" || len(normalized.Rules) != 1 || normalized.Rules[0].Value != "CN" {
		t.Fatalf("normalized condition = %#v", normalized)
	}

	invalid := request
	invalid.Rules = []L2Rule{{Field: "cookie", Operator: "eq", Value: "x"}}
	if _, err := normalizeL2ConditionWrite(invalid); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("invalid field error = %v", err)
	}
	invalid = request
	invalid.Rules = []L2Rule{{Field: "host", Operator: "matches", Value: "x"}}
	if _, err := normalizeL2ConditionWrite(invalid); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("invalid operator error = %v", err)
	}
	invalid = request
	invalid.Rules = make([]L2Rule, 33)
	if _, err := normalizeL2ConditionWrite(invalid); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("rule limit error = %v", err)
	}
}

// L2-REGEX-01: a regex rule the node cannot compile is refused on save, and
// names the rule; non-regex operators keep any text.
func TestNormalizeL2ConditionWriteRejectsInvalidRegex(t *testing.T) {
	base := L2ConditionWriteRequest{
		Name: "正则", IdempotencyKey: "l2-condition-create-1", RequestID: "l2-condition-request-1",
	}
	for _, value := range []string{"[", "(abc", `abc\`, "a{2,1}", `(?<=a)b`, `(a)\1`} {
		for _, operator := range []string{"regex", "not_regex"} {
			request := base
			request.Rules = []L2Rule{{Field: "uri", Operator: "eq", Value: "/"}, {Field: "host", Operator: operator, Value: value}}
			_, err := normalizeL2ConditionWrite(request)
			var invalid *L2RuleRegexError
			if !errors.Is(err, ErrInvalidInput) || !errors.As(err, &invalid) || invalid.Index != 1 {
				t.Fatalf("%s %q error = %v, want rule 1 invalid regex", operator, value, err)
			}
		}
	}
	for _, rule := range []L2Rule{
		{Field: "host", Operator: "regex", Value: `^www\.example\.com$`},
		{Field: "uri", Operator: "not_regex", Value: `^/static/.*\.(js|css)$`},
		{Field: "host", Operator: "contains", Value: "["},
	} {
		request := base
		request.Rules = []L2Rule{rule}
		if _, err := normalizeL2ConditionWrite(request); err != nil {
			t.Fatalf("%#v error = %v", rule, err)
		}
	}
}

func TestNormalizeL2NodeWrites(t *testing.T) {
	configID, nodeID := uuid.New(), uuid.New()
	add := L2NodeAddRequest{
		ConfigID: configID, NodeIDs: []uuid.UUID{nodeID}, ExpectedRevision: 0,
		IdempotencyKey: "l2-node-add-1", RequestID: "l2-node-request-1",
	}
	if _, err := normalizeL2NodeAdd(add); err != nil {
		t.Fatal(err)
	}
	duplicate := add
	duplicate.NodeIDs = []uuid.UUID{nodeID, nodeID}
	if _, err := normalizeL2NodeAdd(duplicate); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("duplicate node error = %v", err)
	}

	update := L2NodeWriteRequest{
		MembershipID: uuid.New(), ExpectedRevision: 1, Enabled: true, Weight: 100, Sort: 0,
		IdempotencyKey: "l2-node-update-1", RequestID: "l2-node-update-request-1",
	}
	if _, err := normalizeL2NodeWrite(update); err != nil {
		t.Fatal(err)
	}
	update.Weight = 101
	if _, err := normalizeL2NodeWrite(update); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("weight error = %v", err)
	}
	update.Weight = 1
	update.Sort = -1
	if _, err := normalizeL2NodeWrite(update); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("sort error = %v", err)
	}
	update.Sort = 0
	update.RequestID = strings.Repeat("x", 129)
	if _, err := normalizeL2NodeWrite(update); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("request ID error = %v", err)
	}
}
