package ccreference

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestNormalizeFieldsTrimsAndDefaultsFilterParameters(t *testing.T) {
	matcher := MatcherFields{
		Name:        "  请求头匹配  ",
		Description: "  说明  ",
		Field:       " header ",
		Operator:    " equals ",
		Key:         " X-Trace ",
		Values:      []string{"  edge  "},
	}
	if err := normalizeFields(KindMatcher, &matcher, nil); err != nil {
		t.Fatalf("normalize matcher: %v", err)
	}
	if matcher.Name != "请求头匹配" || matcher.Description != "说明" || matcher.Field != "header" ||
		matcher.Operator != "equals" || matcher.Key != "X-Trace" {
		t.Fatalf("normalized matcher = %#v", matcher)
	}

	filter := FilterFields{Name: "  速率限制  ", Description: "  说明 ", Type: " req_rate "}
	if err := normalizeFields(KindFilter, nil, &filter); err != nil {
		t.Fatalf("normalize filter: %v", err)
	}
	if filter.Name != "速率限制" || filter.Description != "说明" || filter.Type != "req_rate" || string(filter.Parameters) != `{}` {
		t.Fatalf("normalized filter = %#v", filter)
	}
}

func TestNormalizeFieldsRejectsInvalidMatcherAndFilterInput(t *testing.T) {
	tests := []struct {
		name    string
		kind    Kind
		matcher MatcherFields
		filter  FilterFields
	}{
		{name: "empty matcher name", kind: KindMatcher, matcher: MatcherFields{Field: "path", Operator: "equals"}},
		{name: "empty matcher field", kind: KindMatcher, matcher: MatcherFields{Name: "name", Operator: "equals"}},
		{name: "too many matcher values", kind: KindMatcher, matcher: MatcherFields{Name: "name", Field: "path", Operator: "equals", Values: make([]string, 101)}},
		{name: "invalid filter type", kind: KindFilter, filter: FilterFields{Name: "filter", Type: "带空格"}},
		{name: "array filter parameters", kind: KindFilter, filter: FilterFields{Name: "filter", Type: "req_rate", Parameters: json.RawMessage(`[]`)}},
		{name: "malformed filter parameters", kind: KindFilter, filter: FilterFields{Name: "filter", Type: "req_rate", Parameters: json.RawMessage(`{`)}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := normalizeFields(test.kind, &test.matcher, &test.filter)
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("error = %v, want ErrInvalidInput", err)
			}
		})
	}
}

func TestServiceRejectsInvalidActorsAndRequestMetadataBeforeStore(t *testing.T) {
	service := &Service{}
	validActor := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant"}

	if _, err := service.List(t.Context(), validActor, KindMatcher, ListFilter{Page: 0, Limit: 10}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("invalid list pagination error = %v", err)
	}
	if _, err := service.List(t.Context(), validActor, KindMatcher, ListFilter{Page: 1, Limit: 10, Owner: "other"}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("tenant owner filter error = %v", err)
	}
	if _, err := service.Create(t.Context(), validActor, CreateRequest{Kind: KindMatcher, IdempotencyKey: "bad key", RequestID: "request-1"}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("invalid idempotency key error = %v", err)
	}
	if _, err := service.Create(t.Context(), validActor, CreateRequest{Kind: KindMatcher, IdempotencyKey: "create-1", RequestID: "request-1"}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("missing tenant target error = %v", err)
	}
	if _, err := service.Get(t.Context(), validActor, KindMatcher, uuid.Nil); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("nil reference ID error = %v", err)
	}
}
