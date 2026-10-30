package audit

// Plain-language rendering of audit events. The log center shows Summary and
// the structured parts as they are; the browser does not build sentences.

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

// RenderInput is one stored event plus the display names the reader resolved.
type RenderInput struct {
	ID           uuid.UUID
	ScopeID      uuid.UUID
	OccurredAt   time.Time
	Action       string
	Category     string
	ActorKind    string
	ActorUserID  *uuid.UUID
	ActorRef     string
	ActorName    string // username / display name; "" when unknown
	ActorIsAdmin bool   // the user acted as a platform administrator
	SourceIP     string
	ResourceType string
	ResourceID   string
	ResourceName string // site domain, node name, ...; "" when unknown
	// ResourceDeleted: a nameable object that no longer exists in the row's scope.
	ResourceDeleted bool
	// log-merge: what the admin log center shows per row (B6/B6b facts).
	TenantName string // the row scope's tenant display name; "" for the platform scope
	UserAgent  string
	GeoCode    string // ISO country code; "" when unknown
	GeoRegion  string
	GeoCity    string
	Result     string
	ReasonCode string
	RequestID  string
	Payload    map[string]any
	Changes    []Change
}

// RenderedChange is one before -> after line.
type RenderedChange struct {
	Field  string `json:"field"`
	Label  string `json:"label"`
	Before string `json:"before"`
	After  string `json:"after"`
}

// RenderedField is one payload value the catalog allows to show.
type RenderedField struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	Value string `json:"value"`
}

// Rendered is what the log center API returns for one event.
type Rendered struct {
	ID            string    `json:"id"`
	OccurredAt    time.Time `json:"occurred_at"`
	Time          string    `json:"time"`
	Category      string    `json:"category"`
	CategoryLabel string    `json:"category_label"`
	Action        string    `json:"action"`
	Catalogued    bool      `json:"catalogued"`
	Actor         string    `json:"actor"`
	ActorKind     string    `json:"actor_kind"`
	ActorUserID   string    `json:"actor_user_id,omitempty"`
	ActorRef      string    `json:"actor_ref,omitempty"`
	SourceIP      string    `json:"source_ip"`
	ScopeID       string    `json:"scope_id"`
	ResourceType  string    `json:"resource_type"`
	ResourceID    string    `json:"resource_id"`
	Resource      string    `json:"resource"`
	// log-merge: resource_deleted marks an object gone from its scope (B6b);
	// tenant_name / actor_username / user_agent / geo_* feed the admin columns.
	ResourceDeleted bool             `json:"resource_deleted,omitempty"`
	TenantName      string           `json:"tenant_name,omitempty"`
	ActorUsername   string           `json:"actor_username,omitempty"`
	UserAgent       string           `json:"user_agent,omitempty"`
	GeoCode         string           `json:"geo_code,omitempty"`
	GeoRegion       string           `json:"geo_region,omitempty"`
	GeoCity         string           `json:"geo_city,omitempty"`
	Result          string           `json:"result"`
	ResultLabel     string           `json:"result_label"`
	ReasonCode      string           `json:"reason_code,omitempty"`
	Reason          string           `json:"reason,omitempty"`
	RequestID       string           `json:"request_id"`
	Summary         string           `json:"summary"`
	Changes         []RenderedChange `json:"changes"`
	Fields          []RenderedField  `json:"fields"`
}

// Locale selects the template language.
type Locale string

const (
	LocaleZH Locale = "zh"
	LocaleEN Locale = "en"
)

// ParseLocale maps an Accept-Language style value to a Locale (default zh).
func ParseLocale(value string) Locale {
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(value)), "en") {
		return LocaleEN
	}
	return LocaleZH
}

// Render turns input into display text. location formats the time (nil = UTC).
func Render(input RenderInput, locale Locale, location *time.Location) Rendered {
	if location == nil {
		location = time.UTC
	}
	entry, catalogued := Lookup(input.Action)
	category := input.Category
	if category == "" {
		category = string(CategoryOf(input.Action))
	}
	out := Rendered{
		ID: input.ID.String(), OccurredAt: input.OccurredAt, Time: input.OccurredAt.In(location).Format("2006-01-02 15:04:05"),
		Category: category, CategoryLabel: categoryLabel(Category(category), locale), Action: input.Action,
		Catalogued: catalogued, ActorKind: input.ActorKind, ActorRef: input.ActorRef, SourceIP: input.SourceIP,
		ScopeID: input.ScopeID.String(), ResourceType: input.ResourceType, ResourceID: input.ResourceID,
		Result: input.Result, ResultLabel: resultLabel(input.Result, locale), ReasonCode: input.ReasonCode,
		Reason: reasonLabel(input.ReasonCode, locale), RequestID: input.RequestID,
		Changes: []RenderedChange{}, Fields: []RenderedField{},
	}
	if input.ActorUserID != nil {
		out.ActorUserID = input.ActorUserID.String()
	}
	out.Actor = actorLabel(input, locale)
	out.ActorUsername, out.TenantName, out.UserAgent = input.ActorName, input.TenantName, input.UserAgent
	out.GeoCode, out.GeoRegion, out.GeoCity = input.GeoCode, input.GeoRegion, input.GeoCity
	out.ResourceDeleted = input.ResourceDeleted
	out.Resource = input.ResourceName
	if out.Resource == "" {
		out.Resource = input.ResourceID
	}
	masked := map[string]bool{}
	for _, key := range entry.Masked {
		masked[key] = true
	}
	for _, change := range input.Changes {
		before, after := displayValue(change.Before, locale), displayValue(change.After, locale)
		if masked[change.Field] {
			before, after = maskValue(before), maskValue(after)
		}
		out.Changes = append(out.Changes, RenderedChange{Field: change.Field, Label: fieldLabel(change.Field, locale),
			Before: before, After: after})
	}
	shown := append(append([]string(nil), entry.Fields...), entry.Masked...)
	sort.Strings(shown)
	for index, key := range shown {
		if index > 0 && shown[index-1] == key {
			continue
		}
		value, ok := input.Payload[key]
		if !ok || value == nil {
			continue
		}
		text := displayValue(value, locale)
		if masked[key] {
			text = maskValue(text)
		}
		out.Fields = append(out.Fields, RenderedField{Key: key, Label: fieldLabel(key, locale), Value: text})
	}
	out.Summary = summary(input, entry, catalogued, out, locale)
	return out
}

func summary(input RenderInput, entry Entry, catalogued bool, out Rendered, locale Locale) string {
	values := map[string]string{
		"resource": out.Resource, "resource_type": input.ResourceType, "resource_id": input.ResourceID,
		"reason": out.Reason, "changes": changesPhrase(out.Changes, locale),
	}
	for _, field := range out.Fields {
		values[field.Key] = field.Value
	}
	var body string
	switch {
	case !catalogued && locale == LocaleEN:
		body = fmt.Sprintf("performed %s on %s %s", input.Action, input.ResourceType, out.Resource)
	case !catalogued:
		body = fmt.Sprintf("执行了操作 %s（对象：%s %s）", input.Action, input.ResourceType, out.Resource)
	case locale == LocaleEN:
		body = fill(entry.TemplateEN, values)
	default:
		body = fill(entry.TemplateZH, values)
	}
	var builder strings.Builder
	if locale == LocaleEN {
		builder.WriteString(out.Actor)
		if out.SourceIP != "" {
			builder.WriteString(" from " + out.SourceIP)
		}
		builder.WriteString(" at " + out.Time + " " + body)
		switch input.Result {
		case "denied":
			builder.WriteString(" — denied")
		case "failure":
			builder.WriteString(" — failed")
		}
		if input.Result != "success" && out.Reason != "" {
			builder.WriteString(" (" + out.Reason + ")")
		}
		return builder.String()
	}
	builder.WriteString(out.Actor + " 于 " + out.Time)
	if out.SourceIP != "" {
		builder.WriteString(" 从 " + out.SourceIP)
	}
	builder.WriteString(" " + body)
	switch input.Result {
	case "denied":
		builder.WriteString("，被拒绝")
	case "failure":
		builder.WriteString("，失败")
	}
	if input.Result != "success" && out.Reason != "" {
		builder.WriteString("（原因：" + out.Reason + "）")
	}
	return builder.String()
}

func fill(template string, values map[string]string) string {
	return placeholderPattern.ReplaceAllStringFunc(template, func(match string) string {
		value := values[match[1:len(match)-1]]
		return value
	})
}

func changesPhrase(changes []RenderedChange, locale Locale) string {
	if len(changes) == 0 {
		return ""
	}
	parts := make([]string, 0, len(changes))
	for _, change := range changes {
		if locale == LocaleEN {
			parts = append(parts, fmt.Sprintf("%s from \"%s\" to \"%s\"", change.Label, change.Before, change.After))
		} else {
			parts = append(parts, fmt.Sprintf("%s从「%s」改为「%s」", change.Label, change.Before, change.After))
		}
	}
	if locale == LocaleEN {
		return ": " + strings.Join(parts, "; ")
	}
	return "：" + strings.Join(parts, "；")
}

func actorLabel(input RenderInput, locale Locale) string {
	name := input.ActorName
	if name == "" && input.ActorUserID != nil {
		name = input.ActorUserID.String()
	}
	en := locale == LocaleEN
	label := ""
	switch input.ActorKind {
	case ActorUser:
		switch {
		case input.ActorIsAdmin && en:
			label = "Administrator " + name
		case input.ActorIsAdmin:
			label = "管理员 " + name
		case en:
			label = "User " + name
		default:
			label = "用户 " + name
		}
		if strings.HasPrefix(input.ActorRef, "api_key:") {
			if en {
				label += " (via API key)"
			} else {
				label += "（通过 API 密钥）"
			}
		}
	case ActorPlugin:
		if en {
			label = "Plugin " + strings.TrimPrefix(input.ActorRef, "plugin:")
		} else {
			label = "插件 " + strings.TrimPrefix(input.ActorRef, "plugin:")
		}
	case ActorNode:
		if en {
			label = "Node " + strings.TrimPrefix(input.ActorRef, "node:")
		} else {
			label = "节点 " + strings.TrimPrefix(input.ActorRef, "node:")
		}
	default:
		if en {
			label = "System"
		} else {
			label = "系统"
		}
	}
	return strings.TrimSpace(label)
}

func categoryLabel(category Category, locale Locale) string {
	for _, info := range categories {
		if info.Category == category {
			if locale == LocaleEN {
				return info.LabelEN
			}
			return info.LabelZH
		}
	}
	return string(category)
}

func resultLabel(result string, locale Locale) string {
	labels := map[string][2]string{"success": {"成功", "Succeeded"}, "denied": {"被拒绝", "Denied"}, "failure": {"失败", "Failed"}}
	if pair, ok := labels[result]; ok {
		if locale == LocaleEN {
			return pair[1]
		}
		return pair[0]
	}
	return result
}

// displayValue formats a JSON value for people: booleans read as 开启/关闭.
func displayValue(value any, locale Locale) string {
	en := locale == LocaleEN
	switch typed := value.(type) {
	case nil:
		if en {
			return "(none)"
		}
		return "空"
	case bool:
		switch {
		case typed && en:
			return "on"
		case typed:
			return "开启"
		case en:
			return "off"
		default:
			return "关闭"
		}
	case string:
		if typed == "" {
			if en {
				return "(empty)"
			}
			return "空"
		}
		return typed
	case json.Number:
		return typed.String()
	case float64, float32, int, int64, int32, uint, uint64, uint32:
		return fmt.Sprint(typed)
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprint(value)
	}
	return string(raw)
}

// maskValue keeps enough of an email / phone / identifier to recognise it.
func maskValue(value string) string {
	runes := []rune(value)
	if at := strings.IndexRune(value, '@'); at > 0 {
		local := []rune(value[:at])
		return string(local[:1]) + "***" + value[at:]
	}
	switch {
	case len(runes) <= 2:
		return "**"
	case len(runes) <= 6:
		return string(runes[:1]) + strings.Repeat("*", len(runes)-1)
	case len(runes) <= 11:
		return string(runes[:3]) + strings.Repeat("*", len(runes)-5) + string(runes[len(runes)-2:])
	default:
		return string(runes[:3]) + "****" + string(runes[len(runes)-4:])
	}
}
