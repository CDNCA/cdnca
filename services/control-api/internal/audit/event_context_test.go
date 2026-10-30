package audit

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestEnrichFillsUnifiedFields(t *testing.T) {
	user := uuid.New()
	ctx := WithSourceIP(context.Background(), netip.MustParseAddr("::ffff:203.0.113.7"))
	got, err := enrich(ctx, Event{
		ScopeID: uuid.New(), ActorUserID: &user, Action: "site.update", ResourceType: "site", ResourceID: "s1",
		RequestID: "r1", Result: "denied", Payload: map[string]any{"reason_code": "quota_exceeded", "count": 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Category != string(CategorySite) || got.ActorKind != ActorUser || got.SourceIP != "203.0.113.7" ||
		got.ReasonCode != "quota_exceeded" || string(got.Changes) != "[]" {
		t.Fatalf("enrich = category %q kind %q ip %q reason %q changes %s", got.Category, got.ActorKind,
			got.SourceIP, got.ReasonCode, got.Changes)
	}
}

func TestEnrichPrefersExplicitThenPayloadThenContextIP(t *testing.T) {
	ctx := WithSourceIP(context.Background(), netip.MustParseAddr("192.0.2.1"))
	cases := []struct {
		name  string
		input Event
		want  string
	}{
		{"explicit", Event{SourceIP: "198.51.100.1", Payload: map[string]any{"ip": "198.51.100.2"}}, "198.51.100.1"},
		{"payload ip", Event{Payload: map[string]any{"ip": "198.51.100.2"}}, "198.51.100.2"},
		{"payload source_ip with port", Event{Payload: map[string]any{"source_ip": "[2001:db8::1]:443"}}, "2001:db8::1"},
		{"context", Event{Payload: map[string]any{}}, "192.0.2.1"},
		{"invalid dropped", Event{SourceIP: "not-an-ip"}, ""},
	}
	for _, test := range cases {
		test.input.Action, test.input.Result = "auth.login", "success"
		got, err := enrich(ctx, test.input)
		if err != nil {
			t.Fatalf("%s: %v", test.name, err)
		}
		if got.SourceIP != test.want {
			t.Errorf("%s: source ip = %q, want %q", test.name, got.SourceIP, test.want)
		}
	}
}

func TestEnrichActorKind(t *testing.T) {
	user := uuid.New()
	plugin := WithActor(context.Background(), ContextActor{Kind: ActorPlugin, Ref: "plugin:waf-pack"})
	for name, test := range map[string]struct {
		ctx      context.Context
		input    Event
		kind     string
		ref      string
		wantFail bool
	}{
		"no actor is system":          {context.Background(), Event{}, ActorSystem, "", false},
		"user id is user":             {context.Background(), Event{ActorUserID: &user}, ActorUser, "", false},
		"context plugin":              {plugin, Event{}, ActorPlugin, "plugin:waf-pack", false},
		"user wins over context":      {plugin, Event{ActorUserID: &user}, ActorUser, "", false},
		"explicit node":               {context.Background(), Event{ActorKind: ActorNode, ActorRef: "node:n1"}, ActorNode, "node:n1", false},
		"user kind without user fail": {context.Background(), Event{ActorKind: ActorUser}, "", "", true},
		"unknown kind fails":          {context.Background(), Event{ActorKind: "robot"}, "", "", true},
	} {
		test.input.Action, test.input.Result = "node.update", "success"
		got, err := enrich(test.ctx, test.input)
		if test.wantFail {
			if err == nil {
				t.Errorf("%s: want error", name)
			}
			continue
		}
		if err != nil || got.ActorKind != test.kind || got.ActorRef != test.ref {
			t.Errorf("%s: kind %q ref %q err %v, want %q %q", name, got.ActorKind, got.ActorRef, err, test.kind, test.ref)
		}
	}
}

func TestEnrichChangesRedactSecretsAndLeavePayload(t *testing.T) {
	payload := map[string]any{
		"changes": []map[string]any{
			{"field": "cc_enabled", "before": false, "after": true},
			{"field": "origin_password", "before": "old-secret", "after": "new-secret"},
			{"field": "headers", "before": map[string]any{"x_api_key": "k1"}, "after": nil},
		},
		"site": "example.test",
	}
	got, err := enrich(context.Background(), Event{Action: "site.update", Result: "success", Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"old-secret", "new-secret", "k1"} {
		if strings.Contains(string(got.Changes), secret) || strings.Contains(string(got.Payload), secret) {
			t.Fatalf("secret %q leaked: changes=%s payload=%s", secret, got.Changes, got.Payload)
		}
	}
	var changes []Change
	if err := json.Unmarshal(got.Changes, &changes); err != nil || len(changes) != 3 {
		t.Fatalf("changes = %s (%v)", got.Changes, err)
	}
	if changes[0].Field != "cc_enabled" || changes[0].Before != false || changes[0].After != true {
		t.Fatalf("first change = %#v", changes[0])
	}
	if changes[1].Before != "[REDACTED]" || changes[1].After != "[REDACTED]" {
		t.Fatalf("secret change = %#v", changes[1])
	}
	if strings.Contains(string(got.Payload), "changes") {
		t.Fatalf("payload kept a raw changes copy: %s", got.Payload)
	}
	if _, ok := payload["changes"]; !ok {
		t.Fatal("enrich mutated the caller's payload")
	}
}

func TestChangesFromPayloadShapes(t *testing.T) {
	for name, value := range map[string]any{
		"map of before/after": map[string]any{"mode": map[string]any{"before": "a", "after": "b"}},
		"map of from/to":      map[string]any{"mode": map[string]any{"from": "a", "to": "b"}},
		"map of pairs":        map[string]any{"mode": []any{"a", "b"}},
		"list":                []any{map[string]any{"field": "mode", "before": "a", "after": "b"}},
		"typed":               []Change{{Field: "mode", Before: "a", After: "b"}},
	} {
		got := changesFromPayload(value)
		if len(got) != 1 || got[0].Field != "mode" || got[0].Before != "a" || got[0].After != "b" {
			t.Errorf("%s: %#v", name, got)
		}
	}
}

// payload "changes" is moved to the changes column, so no writer shape may
// lose its content there (unified-log alignment).
func TestChangesFromPayloadKeepsEveryWriterShape(t *testing.T) {
	type siteChanges struct {
		Added []string `json:"sites_added"`
	}
	for name, test := range map[string]struct {
		value any
		want  string
	}{
		"struct of lists": {siteChanges{Added: []string{"a", "b"}}, `[{"after":["a","b"],"before":null,"field":"sites_added"}]`},
		"typed list of two is a value": {map[string]any{"missing": []string{"m1", "m2"}},
			`[{"after":["m1","m2"],"before":null,"field":"missing"}]`},
		"typed before/after map": {map[string]any{"state": map[string]string{"before": "planned", "after": "cancelled"}},
			`[{"after":"cancelled","before":"planned","field":"state"}]`},
		"counters in field order": {map[string]any{"updated": 0, "added": 1},
			`[{"after":1,"before":null,"field":"added"},{"after":0,"before":null,"field":"updated"}]`},
		"pair with an extra key": {map[string]any{"source_url": map[string]any{"from": "a", "to": "b", "query_changed": true}},
			`[{"after":"b","before":"a","field":"source_url"},{"after":true,"before":null,"field":"source_url.query_changed"}]`},
		"list items without a field": {[]map[string]any{{"table": "t", "days": 2}},
			`[{"after":{"days":2,"table":"t"},"before":null,"field":"#1"}]`},
	} {
		got, err := encodeChanges(changesFromPayload(test.value))
		if err != nil || string(got) != test.want {
			t.Errorf("%s: %s (%v), want %s", name, got, err, test.want)
		}
	}
}

func TestNormalizeChangesIsStableAcrossJSONBRoundTrip(t *testing.T) {
	first, err := normalizeChanges([]byte(`[{"after":2,"field":"x","before":1}]`))
	if err != nil {
		t.Fatal(err)
	}
	second, err := normalizeChanges([]byte(`[ {"field": "x", "before": 1, "after": 2} ]`))
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatalf("%s != %s", first, second)
	}
	if _, err := normalizeChanges([]byte(`{"field":"x"}`)); err == nil {
		t.Fatal("object accepted as changes")
	}
}
