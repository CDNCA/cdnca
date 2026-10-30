package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

type sourceIPKey struct{}
type actorKey struct{}

// ContextActor is a non-user actor carried by the request context.
type ContextActor struct {
	Kind string // ActorSystem, ActorPlugin or ActorNode
	Ref  string // "plugin:<id>", "node:<id>", "job:<name>", ...
}

// WithSourceIP records the client address for every event appended under ctx.
func WithSourceIP(ctx context.Context, address netip.Addr) context.Context {
	if !address.IsValid() {
		return ctx
	}
	return context.WithValue(ctx, sourceIPKey{}, address.Unmap().String())
}

// SourceIPFrom returns the address recorded by WithSourceIP.
func SourceIPFrom(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	value, _ := ctx.Value(sourceIPKey{}).(string)
	return value
}

// maxUserAgentBytes bounds audit_events.user_agent (tp-b6b; the column CHECK
// allows 512 characters, bytes are the stricter bound).
const maxUserAgentBytes = 512

type userAgentKey struct{}

// WithUserAgent records the request's User-Agent for every event appended
// under ctx (set by the HTTP middleware next to WithSourceIP).
func WithUserAgent(ctx context.Context, userAgent string) context.Context {
	if cleaned := cleanUserAgent(userAgent); cleaned != "" {
		return context.WithValue(ctx, userAgentKey{}, cleaned)
	}
	return ctx
}

// UserAgentFrom returns the User-Agent recorded by WithUserAgent.
func UserAgentFrom(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	value, _ := ctx.Value(userAgentKey{}).(string)
	return value
}

// cleanUserAgent drops control characters and invalid UTF-8, trims, and cuts
// to maxUserAgentBytes on a rune boundary.
func cleanUserAgent(raw string) string {
	cleaned := strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, strings.ToValidUTF8(raw, "")))
	if len(cleaned) <= maxUserAgentBytes {
		return cleaned
	}
	cut := maxUserAgentBytes
	for cut > 0 && !utf8.RuneStart(cleaned[cut]) {
		cut--
	}
	return strings.TrimSpace(cleaned[:cut])
}

// WithActor marks events appended under ctx (without ActorUserID) as done by
// a system job, plugin or node.
func WithActor(ctx context.Context, actor ContextActor) context.Context {
	return context.WithValue(ctx, actorKey{}, actor)
}

func actorFrom(ctx context.Context) (ContextActor, bool) {
	if ctx == nil {
		return ContextActor{}, false
	}
	actor, ok := ctx.Value(actorKey{}).(ContextActor)
	return actor, ok
}

func validActorKind(kind string) bool {
	switch kind {
	case ActorUser, ActorSystem, ActorPlugin, ActorNode:
		return true
	}
	return false
}

// enrich fills the unified-log fields of input and returns the record to
// hash and insert (ID, position and previous hash are set by the caller).
func enrich(ctx context.Context, input Event) (record, error) {
	payload := input.Payload
	if _, hasChanges := payload["changes"]; hasChanges {
		// The changes column holds them (redacted); do not keep a raw copy.
		payload = make(map[string]any, len(input.Payload))
		for key, value := range input.Payload {
			if key != "changes" {
				payload[key] = value
			}
		}
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return record{}, fmt.Errorf("encode audit payload: %w", err)
	}
	payloadBytes, err = normalizePayload(payloadBytes)
	if err != nil {
		return record{}, fmt.Errorf("normalize audit payload: %w", err)
	}
	if string(payloadBytes) == "null" {
		payloadBytes = []byte("{}")
	}

	actorKind, actorRef := input.ActorKind, input.ActorRef
	if actorKind == "" {
		if contextActor, ok := actorFrom(ctx); ok && input.ActorUserID == nil {
			actorKind = contextActor.Kind
			if actorRef == "" {
				actorRef = contextActor.Ref
			}
		} else if input.ActorUserID != nil {
			actorKind = ActorUser
		} else {
			actorKind = ActorSystem
		}
	}
	if !validActorKind(actorKind) {
		return record{}, fmt.Errorf("audit actor kind %q is not user/system/plugin/node", actorKind)
	}
	if actorKind == ActorUser && input.ActorUserID == nil {
		return record{}, fmt.Errorf("audit actor kind user requires ActorUserID")
	}

	sourceIP := input.SourceIP
	if sourceIP == "" {
		sourceIP = payloadString(input.Payload, "ip")
	}
	if sourceIP == "" {
		sourceIP = payloadString(input.Payload, "source_ip")
	}
	if sourceIP == "" {
		sourceIP = SourceIPFrom(ctx)
	}
	sourceIP = normalizeIP(sourceIP)

	reasonCode := input.ReasonCode
	if reasonCode == "" {
		reasonCode = payloadString(input.Payload, "reason_code")
	}

	changes := input.Changes
	if len(changes) == 0 && input.Payload != nil {
		changes = changesFromPayload(input.Payload["changes"])
	}
	changesBytes, err := encodeChanges(changes)
	if err != nil {
		return record{}, err
	}

	occurredAt := input.OccurredAt
	if occurredAt.IsZero() {
		occurredAt = time.Now()
	}
	return record{
		ScopeID:      input.ScopeID,
		ActorUserID:  input.ActorUserID,
		Action:       input.Action,
		ResourceType: input.ResourceType,
		ResourceID:   input.ResourceID,
		RequestID:    input.RequestID,
		Result:       input.Result,
		Payload:      payloadBytes,
		OccurredAt:   occurredAt.UTC().Truncate(time.Microsecond),
		Category:     string(CategoryOf(input.Action)),
		ActorKind:    actorKind,
		ActorRef:     truncateString(actorRef, 200),
		SourceIP:     sourceIP,
		ReasonCode:   truncateString(reasonCode, 200),
		Changes:      changesBytes,
		UserAgent:    UserAgentFrom(ctx),
	}, nil
}

func payloadString(payload map[string]any, key string) string {
	if payload == nil {
		return ""
	}
	value, _ := payload[key].(string)
	return strings.TrimSpace(value)
}

// normalizeIP returns the canonical text of an IP (or "ip:port"), "" otherwise.
func normalizeIP(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if address, err := netip.ParseAddr(raw); err == nil {
		return address.Unmap().WithZone("").String()
	}
	if addrPort, err := netip.ParseAddrPort(raw); err == nil {
		return addrPort.Addr().Unmap().WithZone("").String()
	}
	return ""
}

// changesFromPayload accepts []Change, a list of {field,before,after}, or a
// {field: {before, after}} / {field: {from, to}} / {field: [before, after]}
// map. Other values are typed Go values (structs, map[string]string, ...)
// and are read through their JSON form. Nothing is dropped: payload
// "changes" is not kept in the payload, so a value that is not a before ->
// after pair is recorded as the field's after value (before empty), and a
// list item without a field is recorded under its position ("#1", ...).
func changesFromPayload(value any) []Change {
	if value == nil {
		return nil
	}
	if typed, ok := value.([]Change); ok {
		return typed
	}
	if typed, ok := value.(map[string]any); ok {
		return mapChanges(typed, true)
	}
	switch typed := jsonValue(value).(type) {
	case []any:
		out := make([]Change, 0, len(typed))
		for index, item := range typed {
			object, _ := item.(map[string]any)
			if change, ok := changeFromMap(object); ok {
				out = append(out, change)
				continue
			}
			out = append(out, Change{Field: fmt.Sprintf("#%d", index+1), After: item})
		}
		return out
	case map[string]any:
		return mapChanges(typed, false)
	case nil:
		return nil
	default:
		return []Change{{Field: "value", After: typed}}
	}
}

// mapChanges reads a {field: change} map in field order (map order is random;
// the hash input must not be). goPairs: the map is the writer's own
// map[string]any, where a []any of two is a [before, after] pair; a typed
// list ([]string of two sites, ...) or a list decoded from JSON is a value.
func mapChanges(fields map[string]any, goPairs bool) []Change {
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]Change, 0, len(fields))
	for _, name := range names {
		if pair, ok := fields[name].([]any); goPairs && ok && len(pair) == 2 {
			out = append(out, Change{Field: name, Before: jsonValue(pair[0]), After: jsonValue(pair[1])})
			continue
		}
		out = append(out, objectChanges(name, jsonValue(fields[name]))...)
	}
	return out
}

// jsonValue is value as encoding/json decodes it (structs and typed maps or
// slices become map[string]any / []any); an unencodable value is kept.
func jsonValue(value any) any {
	raw, err := json.Marshal(value)
	if err != nil {
		return value
	}
	var generic any
	if err := json.Unmarshal(raw, &generic); err != nil {
		return value
	}
	return generic
}

// objectChanges is the change of field: a {before, after} or {from, to}
// object is the pair (any other key of it is its own "<field>.<key>" change,
// e.g. source_url.query_changed); any other value is the after value.
func objectChanges(field string, value any) []Change {
	object, ok := value.(map[string]any)
	if !ok {
		return []Change{{Field: field, After: value}}
	}
	beforeKey, afterKey := "before", "after"
	_, hasBefore := object["before"]
	_, hasAfter := object["after"]
	if !hasBefore && !hasAfter {
		beforeKey, afterKey = "from", "to"
		_, hasBefore = object["from"]
		_, hasAfter = object["to"]
	}
	if !hasBefore && !hasAfter {
		return []Change{{Field: field, After: value}}
	}
	out := []Change{{Field: field, Before: object[beforeKey], After: object[afterKey]}}
	extra := make([]string, 0, len(object))
	for key := range object {
		if key != beforeKey && key != afterKey {
			extra = append(extra, key)
		}
	}
	sort.Strings(extra)
	for _, key := range extra {
		out = append(out, Change{Field: field + "." + key, After: object[key]})
	}
	return out
}

func changeFromMap(item map[string]any) (Change, bool) {
	field, _ := item["field"].(string)
	if strings.TrimSpace(field) == "" {
		return Change{}, false
	}
	return Change{Field: field, Before: item["before"], After: item["after"]}, true
}

// encodeChanges sorts nothing (order is meaningful to the reader) but redacts
// secret fields and nested secret keys.
func encodeChanges(changes []Change) ([]byte, error) {
	if len(changes) == 0 {
		return []byte("[]"), nil
	}
	items := make([]any, 0, len(changes))
	for _, change := range changes {
		field := strings.TrimSpace(change.Field)
		if field == "" {
			return nil, fmt.Errorf("audit change field is empty")
		}
		before, after := any(change.Before), any(change.After)
		if sensitivePayloadKey(field) {
			before, after = redactedOrNil(before), redactedOrNil(after)
		}
		items = append(items, map[string]any{"field": field, "before": before, "after": after})
	}
	raw, err := json.Marshal(items)
	if err != nil {
		return nil, fmt.Errorf("encode audit changes: %w", err)
	}
	return normalizeChanges(raw)
}

func redactedOrNil(value any) any {
	if value == nil {
		return nil
	}
	return "[REDACTED]"
}

// normalizeChanges decodes and re-encodes a JSON array so the hash is the same
// before and after a jsonb round trip; nested secret keys are redacted.
func normalizeChanges(raw []byte) ([]byte, error) {
	if len(strings.TrimSpace(string(raw))) == 0 {
		return []byte("[]"), nil
	}
	wrapped := append(append([]byte(`{"changes":`), raw...), '}')
	normalized, err := normalizePayload(wrapped)
	if err != nil {
		return nil, err
	}
	var holder struct {
		Changes json.RawMessage `json:"changes"`
	}
	if err := json.Unmarshal(normalized, &holder); err != nil {
		return nil, err
	}
	if len(holder.Changes) == 0 || string(holder.Changes) == "null" {
		return []byte("[]"), nil
	}
	if holder.Changes[0] != '[' {
		return nil, fmt.Errorf("audit changes must be a JSON array")
	}
	return holder.Changes, nil
}

func truncateString(value string, limit int) string {
	value = strings.TrimSpace(value)
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}
