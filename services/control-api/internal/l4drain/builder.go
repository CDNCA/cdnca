package l4drain

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const SchemaVersionV1 = "cdnca.edge.drain/v1"

const maxPlanListeners = 2000

var (
	ErrInvalidInput   = errors.New("invalid L4 drain input")
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
)

type Listener struct {
	ID              string `json:"id"`
	Protocol        string `json:"protocol"`
	Address         string `json:"address"`
	Port            int    `json:"port"`
	UpstreamAddress string `json:"upstream_address"`
	UpstreamPort    int    `json:"upstream_port"`
}

type Version struct {
	VersionID string     `json:"version_id"`
	Listeners []Listener `json:"listeners"`
}

type HealthCheck struct {
	ListenerID         string `json:"listener_id"`
	Path               string `json:"path,omitempty"`
	ExpectedStatus     int    `json:"expected_status,omitempty"`
	Payload            string `json:"payload,omitempty"`
	ExpectedBodyPrefix string `json:"expected_body_prefix"`
}

type DrainPolicy struct {
	MaxDrainSeconds int    `json:"max_drain_seconds"`
	Force           string `json:"force"`
	ForceReason     string `json:"force_reason,omitempty"`
}

type Plan struct {
	SchemaVersion        string        `json:"schema_version"`
	PlanID               string        `json:"plan_id"`
	Revision             uint64        `json:"revision"`
	Old                  Version       `json:"old"`
	New                  Version       `json:"new"`
	HealthTimeoutSeconds int           `json:"health_timeout_seconds"`
	HealthChecks         []HealthCheck `json:"health_checks"`
	Drain                DrainPolicy   `json:"drain"`
}

type CommandInput struct {
	CommandID     string
	NodeID        string
	RequestID     string
	Traceparent   string
	CorrelationID string
	OccurredAt    time.Time
	Deadline      time.Time
	Plan          Plan
}

func BuildCommand(input CommandInput) (*agentv1.DrainCommand, error) {
	if !canonicalUUID(input.CommandID) || !canonicalUUID(input.NodeID) || !canonicalUUID(input.RequestID) ||
		input.OccurredAt.IsZero() || input.Deadline.IsZero() || !input.Deadline.After(input.OccurredAt) ||
		input.Deadline.After(input.OccurredAt.Add(25*time.Hour)) || !validMetadata(input.Traceparent) ||
		!validMetadata(input.CorrelationID) {
		return nil, ErrInvalidInput
	}
	plan, err := normalizePlan(input.Plan)
	if err != nil {
		return nil, err
	}
	canonical, err := json.Marshal(plan)
	if err != nil {
		return nil, ErrInvalidInput
	}
	digest := sha256.Sum256(canonical)
	taskID := input.CommandID
	return &agentv1.DrainCommand{
		Event: &commonv1.EventMetadata{EventId: uuid.NewSHA1(uuid.NameSpaceOID, []byte("l4-drain:"+input.CommandID)).String(),
			RequestId: input.RequestID, OccurredTime: timestamppb.New(input.OccurredAt.UTC()), Traceparent: input.Traceparent,
			CorrelationId: input.CorrelationID, TaskId: &taskID},
		Schema: agentv1.DrainSchema_DRAIN_SCHEMA_V1, CommandId: input.CommandID, NodeId: input.NodeID,
		PlanId: plan.PlanID, Revision: plan.Revision, CanonicalPlanJson: canonical, PlanSha256: digest[:],
		DeadlineTime: timestamppb.New(input.Deadline.UTC()),
	}, nil
}

func normalizePlan(plan Plan) (Plan, error) {
	if plan.SchemaVersion != SchemaVersionV1 || !validIdentifier(plan.PlanID) || plan.Revision == 0 ||
		plan.Old.VersionID == plan.New.VersionID || plan.HealthTimeoutSeconds < 1 || plan.HealthTimeoutSeconds > 300 ||
		plan.Drain.MaxDrainSeconds < 1 || plan.Drain.MaxDrainSeconds > 86400 {
		return Plan{}, ErrInvalidInput
	}
	oldVersion, err := normalizeVersion(plan.Old, false)
	if err != nil {
		return Plan{}, err
	}
	newVersion, err := normalizeVersion(plan.New, true)
	if err != nil {
		return Plan{}, err
	}
	checks, err := normalizeHealthChecks(plan.HealthChecks, newVersion.Listeners)
	if err != nil {
		return Plan{}, err
	}
	switch plan.Drain.Force {
	case "never":
		if plan.Drain.ForceReason != "" {
			return Plan{}, ErrInvalidInput
		}
	case "after-deadline":
		if !validReason(plan.Drain.ForceReason) {
			return Plan{}, ErrInvalidInput
		}
	default:
		return Plan{}, ErrInvalidInput
	}
	plan.Old = oldVersion
	plan.New = newVersion
	plan.HealthChecks = checks
	return plan, nil
}

func normalizeVersion(version Version, allowEmpty bool) (Version, error) {
	if !validIdentifier(version.VersionID) || len(version.Listeners) > maxPlanListeners || !allowEmpty && len(version.Listeners) == 0 {
		return Version{}, ErrInvalidInput
	}
	listeners := append([]Listener{}, version.Listeners...)
	ids := make(map[string]struct{}, len(listeners))
	for index := range listeners {
		listener := &listeners[index]
		if !validIdentifier(listener.ID) || listener.Protocol != "http" && listener.Protocol != "tcp" ||
			listener.Port < 1 || listener.Port > 65535 || listener.UpstreamPort < 1 || listener.UpstreamPort > 65535 {
			return Version{}, ErrInvalidInput
		}
		address, err := normalizeAddress(listener.Address, true)
		if err != nil {
			return Version{}, err
		}
		upstream, err := normalizeAddress(listener.UpstreamAddress, false)
		if err != nil {
			return Version{}, err
		}
		listener.Address, listener.UpstreamAddress = address, upstream
		if _, exists := ids[listener.ID]; exists {
			return Version{}, ErrInvalidInput
		}
		ids[listener.ID] = struct{}{}
		for previous := 0; previous < index; previous++ {
			if listenersOverlap(listeners[previous], *listener) {
				return Version{}, ErrInvalidInput
			}
		}
	}
	sort.Slice(listeners, func(i, j int) bool {
		left, right := listeners[i], listeners[j]
		if left.Protocol != right.Protocol {
			return left.Protocol < right.Protocol
		}
		if left.Address != right.Address {
			return left.Address < right.Address
		}
		if left.Port != right.Port {
			return left.Port < right.Port
		}
		if left.ID != right.ID {
			return left.ID < right.ID
		}
		if left.UpstreamAddress != right.UpstreamAddress {
			return left.UpstreamAddress < right.UpstreamAddress
		}
		return left.UpstreamPort < right.UpstreamPort
	})
	return Version{VersionID: version.VersionID, Listeners: listeners}, nil
}

func normalizeHealthChecks(checks []HealthCheck, listeners []Listener) ([]HealthCheck, error) {
	if len(listeners) == 0 {
		if len(checks) != 0 {
			return nil, ErrInvalidInput
		}
		return []HealthCheck{}, nil
	}
	if len(checks) == 0 || len(checks) != len(listeners) || len(checks) > maxPlanListeners {
		return nil, ErrInvalidInput
	}
	byID := make(map[string]Listener, len(listeners))
	for _, listener := range listeners {
		byID[listener.ID] = listener
	}
	result := append([]HealthCheck(nil), checks...)
	seen := make(map[string]struct{}, len(result))
	for _, check := range result {
		listener, exists := byID[check.ListenerID]
		if !exists {
			return nil, ErrInvalidInput
		}
		if _, duplicate := seen[check.ListenerID]; duplicate || !validProbe(check.ExpectedBodyPrefix, false) {
			return nil, ErrInvalidInput
		}
		seen[check.ListenerID] = struct{}{}
		if listener.Protocol == "http" {
			parsed, err := url.ParseRequestURI(check.Path)
			if err != nil || parsed.IsAbs() || !strings.HasPrefix(check.Path, "/") || check.ExpectedStatus < 100 ||
				check.ExpectedStatus > 599 || check.Payload != "" {
				return nil, ErrInvalidInput
			}
		} else if check.Path != "" || check.ExpectedStatus != 0 || !validProbe(check.Payload, true) {
			return nil, ErrInvalidInput
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ListenerID < result[j].ListenerID })
	return result, nil
}

func normalizeAddress(value string, listener bool) (string, error) {
	address, err := netip.ParseAddr(value)
	if err != nil || address.Zone() != "" || address.Is4In6() || address.IsMulticast() || !listener && address.IsUnspecified() {
		return "", ErrInvalidInput
	}
	return address.String(), nil
}

func listenersOverlap(left, right Listener) bool {
	if left.Port != right.Port {
		return false
	}
	leftAddress := netip.MustParseAddr(left.Address)
	rightAddress := netip.MustParseAddr(right.Address)
	return leftAddress.BitLen() == rightAddress.BitLen() &&
		(leftAddress == rightAddress || leftAddress.IsUnspecified() || rightAddress.IsUnspecified())
}

func canonicalUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

func validIdentifier(value string) bool {
	return value != "" && len(value) <= 64 && utf8.ValidString(value) && identifierPattern.MatchString(value)
}

func validMetadata(value string) bool {
	if len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func validReason(value string) bool {
	return value != "" && len(value) <= 256 && utf8.ValidString(value) && validMetadata(value)
}

func validProbe(value string, allowEmpty bool) bool {
	return (allowEmpty || value != "") && len(value) <= 1024 && utf8.ValidString(value) && !strings.ContainsAny(value, "\r\n\x00")
}
