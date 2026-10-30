// Package domaineventsource owns the durable source facts behind the public
// plugin domain events. A source fact is appended in the same transaction as
// the business write that caused it; fanout to webhook subscriptions is a
// separate concern (domaineventfanout + pluginwebhook).
//
// The field contracts below are the single Go definition of what each public
// event may carry. Migration 367 holds the same rows in
// domain_event_contract_fields_368; contract_test.go keeps both in step.
package domaineventsource

import (
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	DeploymentStatusChangedType  = "io.cdnca.deployment.v1.status_changed"
	SiteUpdatedType              = "io.cdnca.site.v1.updated"
	CertificateStatusChangedType = "io.cdnca.certificate.v1.status_changed"
	CertificateExpiryReachedType = "io.cdnca.certificate.v1.expiry_reached"
	NodeStatusChangedType        = "io.cdnca.node.v1.status_changed"
	UsageThresholdReachedType    = "io.cdnca.usage.v1.threshold_reached"
	SecurityIncidentDetectedType = "io.cdnca.security.v1.incident_detected"
)

// Field kinds understood by both the Go validator and migration 368.
const (
	KindUUID        = "uuid"
	KindString      = "string"
	KindInteger     = "integer"
	KindTimestamp   = "timestamp"
	KindStringArray = "string_array"
)

// Webhook delivery fields are added by fanout to every domain event body.
const (
	FieldSubscriptionID  = "subscription_id"
	FieldSubjectSequence = "subject_sequence"
)

// MaxDataFields bounds a delivered data object (contract fields + webhook fields).
const MaxDataFields = 16

var errNotNumber = errors.New("json value is not a number")

type Field struct {
	Name     string
	Kind     string
	Required bool
	// Allowed restricts string values (or every array item) when non-empty.
	Allowed []string
}

type Contract struct {
	Type               string
	SubjectKind        string
	RequiredPermission string
	// SiteBound events carry site_id, so a site-filtered subscription can match them.
	SiteBound bool
	Fields    []Field
}

var deploymentStates = []string{"queued", "delivered", "agent_queued", "started", "staged", "prechecked",
	"activated", "healthy", "failed", "reverting", "reverted", "rollback_failed"}

var siteChanges = []string{"created", "updated", "enabled", "disabled", "deleted"}

// SiteChangedFields is the closed vocabulary of site.updated changed_fields
// (migration 368 emit_site_updated_event_368 derives them from the sites row).
var SiteChangedFields = []string{"domains", "origins", "ports", "https", "line_group", "status", "settings"}

var certificateStates = []string{"pending", "validating", "issuing", "issued", "deploying", "active",
	"renewal_due", "failed", "revoked"}

var nodeStates = []string{"online", "offline", "pending", "active", "draining", "disabled", "retired"}

var usageMetrics = []string{"traffic_bytes", "bandwidth_bps", "connections", "sites", "expiration"}

// Migrations 368 produce these four events from their source tables in the
// business transaction (certificate_orders, node_presence/nodes,
// package_monitor_transition_facts/package_cycle_enforcement_transitions,
// cc_auto_switch_notification_windows).
var contracts = map[string]Contract{
	CertificateStatusChangedType: {
		Type: CertificateStatusChangedType, SubjectKind: "certificate_order", RequiredPermission: "events.certificate.read",
		Fields: []Field{
			{Name: "order_id", Kind: KindUUID, Required: true},
			{Name: "status", Kind: KindString, Required: true, Allowed: certificateStates},
			{Name: "previous_status", Kind: KindString, Allowed: certificateStates},
			{Name: "revision", Kind: KindInteger, Required: true},
			{Name: "renewal_of_order_id", Kind: KindUUID},
			{Name: "not_after", Kind: KindTimestamp},
		},
	},
	// Migration 370: written by the certificate expiry scanner (certificateexpiry).
	CertificateExpiryReachedType: {
		Type: CertificateExpiryReachedType, SubjectKind: "certificate_asset", RequiredPermission: "events.certificate.read",
		Fields: []Field{
			{Name: "asset_id", Kind: KindUUID, Required: true},
			{Name: "version_id", Kind: KindUUID, Required: true},
			{Name: "stage", Kind: KindString, Required: true,
				Allowed: []string{"expiring_30d", "expiring_7d", "expiring_1d", "expired"}},
			{Name: "not_after", Kind: KindTimestamp, Required: true},
			{Name: "source", Kind: KindString, Required: true, Allowed: []string{"uploaded", "acme"}},
			{Name: "renewal_order_id", Kind: KindUUID},
		},
	},
	NodeStatusChangedType: {
		Type: NodeStatusChangedType, SubjectKind: "node", RequiredPermission: "events.node.read",
		Fields: []Field{
			{Name: "node_id", Kind: KindUUID, Required: true},
			{Name: "kind", Kind: KindString, Required: true, Allowed: []string{"presence", "admin"}},
			{Name: "status", Kind: KindString, Required: true, Allowed: nodeStates},
			{Name: "previous_status", Kind: KindString, Allowed: nodeStates},
			{Name: "revision", Kind: KindInteger, Required: true},
		},
	},
	UsageThresholdReachedType: {
		Type: UsageThresholdReachedType, SubjectKind: "package_subscription", RequiredPermission: "events.usage.read",
		Fields: []Field{
			{Name: "package_subscription_id", Kind: KindUUID, Required: true},
			{Name: "source", Kind: KindString, Required: true, Allowed: []string{"monitor", "enforcement"}},
			{Name: "metric", Kind: KindString, Required: true, Allowed: usageMetrics},
			{Name: "phase", Kind: KindString, Required: true, Allowed: []string{"triggered", "recovered", "suspended", "resumed"}},
			{Name: "period_key", Kind: KindString, Required: true},
			{Name: "observed_value", Kind: KindInteger},
			{Name: "revision", Kind: KindInteger, Required: true},
		},
	},
	SecurityIncidentDetectedType: {
		Type: SecurityIncidentDetectedType, SubjectKind: "site", RequiredPermission: "events.security.read", SiteBound: true,
		Fields: []Field{
			{Name: "site_id", Kind: KindUUID, Required: true},
			{Name: "category", Kind: KindString, Required: true, Allowed: []string{"cc_auto_switch"}},
			{Name: "incident_sequence", Kind: KindInteger, Required: true},
			{Name: "node_id", Kind: KindUUID, Required: true},
			{Name: "started_at", Kind: KindTimestamp, Required: true},
		},
	},
	DeploymentStatusChangedType: {
		Type: DeploymentStatusChangedType, SubjectKind: "deployment", RequiredPermission: "events.deployment.read",
		Fields: []Field{
			{Name: "deployment_id", Kind: KindUUID, Required: true},
			{Name: "rollout_id", Kind: KindUUID, Required: true},
			{Name: "node_id", Kind: KindUUID, Required: true},
			{Name: "attempt", Kind: KindInteger, Required: true},
			{Name: "transition_sequence", Kind: KindInteger, Required: true},
			{Name: "state", Kind: KindString, Required: true, Allowed: deploymentStates},
		},
	},
	SiteUpdatedType: {
		Type: SiteUpdatedType, SubjectKind: "site", RequiredPermission: "events.site.read", SiteBound: true,
		Fields: []Field{
			{Name: "site_id", Kind: KindUUID, Required: true},
			{Name: "change", Kind: KindString, Required: true, Allowed: siteChanges},
			{Name: "changed_fields", Kind: KindStringArray, Required: true, Allowed: SiteChangedFields},
		},
	},
}

// Lookup returns the contract of a public (available) domain event.
func Lookup(eventType string) (Contract, bool) {
	contract, ok := contracts[eventType]
	return contract, ok
}

// Types lists the available domain event types in lexical order.
func Types() []string {
	result := make([]string, 0, len(contracts))
	for eventType := range contracts {
		result = append(result, eventType)
	}
	sort.Strings(result)
	return result
}

var (
	canonicalUUID   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	canonicalInt    = regexp.MustCompile(`^(0|[1-9][0-9]{0,17})$`)
	canonicalTime   = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?Z$`)
	arrayItemFormat = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
)

const (
	maxStringValue = 256
	maxArrayItems  = 32
)

// ValidPayload reports whether data holds exactly the declared fields of the
// contract (required ones present, every value of the declared kind).
func ValidPayload(contract Contract, data map[string]json.RawMessage) bool {
	declared := make(map[string]Field, len(contract.Fields))
	for _, field := range contract.Fields {
		declared[field.Name] = field
	}
	for name, raw := range data {
		field, ok := declared[name]
		if !ok || !validValue(field, raw) {
			return false
		}
	}
	for _, field := range contract.Fields {
		if _, ok := data[field.Name]; field.Required && !ok {
			return false
		}
	}
	return true
}

// ValidWebhookData checks a delivered event body: the contract fields plus the
// webhook fields fanout adds. subscriptionID is the canonical UUID text.
func ValidWebhookData(eventType, subscriptionID string, data map[string]json.RawMessage) bool {
	contract, ok := Lookup(eventType)
	if !ok || len(data) > MaxDataFields {
		return false
	}
	var subscription string
	var sequence json.Number
	if json.Unmarshal(data[FieldSubscriptionID], &subscription) != nil || subscription != subscriptionID ||
		unmarshalNumber(data[FieldSubjectSequence], &sequence) != nil || !canonicalInt.MatchString(sequence.String()) ||
		sequence.String() == "0" {
		return false
	}
	domain := make(map[string]json.RawMessage, len(data))
	for name, value := range data {
		switch name {
		case FieldSubscriptionID, FieldSubjectSequence:
		default:
			domain[name] = value
		}
	}
	return ValidPayload(contract, domain)
}

// ValidSubject reports whether subject names a resource of the contract's kind.
func ValidSubject(eventType, subject string) bool {
	contract, ok := Lookup(eventType)
	if !ok {
		return false
	}
	id, found := strings.CutPrefix(subject, contract.SubjectKind+"/")
	return found && canonicalUUID.MatchString(id)
}

func validValue(field Field, raw json.RawMessage) bool {
	switch field.Kind {
	case KindUUID:
		var value string
		return json.Unmarshal(raw, &value) == nil && canonicalUUID.MatchString(value)
	case KindString:
		var value string
		return json.Unmarshal(raw, &value) == nil && value != "" && len(value) <= maxStringValue &&
			strings.TrimSpace(value) == value && allowed(field, value)
	case KindInteger:
		var value json.Number
		return unmarshalNumber(raw, &value) == nil && canonicalInt.MatchString(value.String())
	case KindTimestamp:
		var value string
		if json.Unmarshal(raw, &value) != nil || !canonicalTime.MatchString(value) {
			return false
		}
		_, err := time.Parse(time.RFC3339Nano, value)
		return err == nil
	case KindStringArray:
		var values []string
		if json.Unmarshal(raw, &values) != nil || values == nil || len(values) > maxArrayItems {
			return false
		}
		seen := make(map[string]bool, len(values))
		for _, value := range values {
			if seen[value] || !arrayItemFormat.MatchString(value) || !allowed(field, value) {
				return false
			}
			seen[value] = true
		}
		return true
	}
	return false
}

func allowed(field Field, value string) bool {
	if len(field.Allowed) == 0 {
		return true
	}
	for _, candidate := range field.Allowed {
		if candidate == value {
			return true
		}
	}
	return false
}

func unmarshalNumber(raw json.RawMessage, target *json.Number) error {
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return err
	}
	number, ok := value.(json.Number)
	if !ok {
		return errNotNumber
	}
	*target = number
	return nil
}
