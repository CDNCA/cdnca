package nodescheduler

import (
	"crypto/sha256"
	"encoding/json"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
	"github.com/google/uuid"
)

var writeMetadataPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
var resolvedValuePattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

const (
	defaultLineGroupSortOrder = 100
	defaultFailoverMode       = FailoverPrimaryOffline
)

type normalizedPut struct {
	groupID            uuid.UUID
	expectedRevision   int64
	name               string
	region             string
	resolvedValue      string
	ipv4ResolvedValue  string
	l2ConfigID         *uuid.UUID
	failoverMode       string
	note               string
	sortOrder          int
	policy             HealthPolicy
	endpoints          []Endpoint
	idempotencyKey     string
	requestID          string
	requestDigest      [32]byte
	v233RequestDigest  [32]byte
	v233ReplayEligible bool
	v226RequestDigest  [32]byte
	v226ReplayEligible bool
	configDigest       [32]byte
	purpose            string
}

type canonicalPolicy struct {
	ProbeIntervalMS    int64 `json:"probe_interval_ms"`
	ProbeTimeoutMS     int64 `json:"probe_timeout_ms"`
	FailureThreshold   int   `json:"failure_threshold"`
	RecoveryThreshold  int   `json:"recovery_threshold"`
	FailureDebounceMS  int64 `json:"failure_debounce_ms"`
	RecoveryDebounceMS int64 `json:"recovery_debounce_ms"`
}

type canonicalEndpoint struct {
	ID        string `json:"id"`
	NodeID    string `json:"node_id,omitempty"`
	Address   string `json:"address"`
	Port      int    `json:"port"`
	Region    string `json:"region"`
	Carrier   string `json:"carrier"`
	Priority  int    `json:"priority"`
	SortOrder int    `json:"sort_order"`
	Weight    int    `json:"weight"`
	Enabled   bool   `json:"enabled"`
}

type legacyCanonicalEndpoint struct {
	ID       string `json:"id"`
	NodeID   string `json:"node_id,omitempty"`
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Region   string `json:"region"`
	Carrier  string `json:"carrier"`
	Priority int    `json:"priority"`
	Weight   int    `json:"weight"`
	Enabled  bool   `json:"enabled"`
}

type canonicalConfiguration struct {
	Name              string              `json:"name"`
	Region            string              `json:"region"`
	ResolvedValue     string              `json:"resolved_value"`
	IPv4ResolvedValue string              `json:"ipv4_resolved_value"`
	L2ConfigID        string              `json:"l2_config_id"`
	FailoverMode      string              `json:"failover_mode"`
	Note              string              `json:"note"`
	SortOrder         int                 `json:"sort_order"`
	Policy            canonicalPolicy     `json:"health_policy"`
	Endpoints         []canonicalEndpoint `json:"endpoints"`
}

type v233CanonicalConfiguration struct {
	Name          string                    `json:"name"`
	Region        string                    `json:"region"`
	ResolvedValue string                    `json:"resolved_value"`
	Note          string                    `json:"note"`
	SortOrder     int                       `json:"sort_order"`
	Policy        canonicalPolicy           `json:"health_policy"`
	Endpoints     []legacyCanonicalEndpoint `json:"endpoints"`
}

type v226CanonicalConfiguration struct {
	Name      string                    `json:"name"`
	Policy    canonicalPolicy           `json:"health_policy"`
	Endpoints []legacyCanonicalEndpoint `json:"endpoints"`
}

func normalizePutRequest(request PutGroupRequest) (normalizedPut, error) {
	if request.ExpectedRevision < 0 ||
		!writeMetadataPattern.MatchString(request.IdempotencyKey) || !writeMetadataPattern.MatchString(request.RequestID) {
		return normalizedPut{}, ErrInvalidInput
	}
	if len(request.Endpoints) > maxEndpoints {
		return normalizedPut{}, invalidField("endpoints", fielderr.TooLong)
	}
	name, err := labelField("name", request.Name, 1, 128, false)
	if err != nil {
		return normalizedPut{}, err
	}
	purpose, ok := normalizePurpose(request.Purpose)
	if !ok {
		return normalizedPut{}, invalidField("purpose", fielderr.Invalid)
	}
	region, err := labelField("region", request.Region, 0, 64, true)
	if err != nil {
		return normalizedPut{}, err
	}
	note, err := labelField("note", request.Note, 0, 512, true)
	if err != nil {
		return normalizedPut{}, err
	}
	resolvedValue := strings.ToLower(strings.TrimSpace(request.ResolvedValue))
	if resolvedValue != "" && !resolvedValuePattern.MatchString(resolvedValue) {
		return normalizedPut{}, invalidField("resolved_value", fielderr.InvalidFormat)
	}
	ipv4ResolvedValue := strings.ToLower(strings.TrimSpace(request.IPv4ResolvedValue))
	if ipv4ResolvedValue != "" && !resolvedValuePattern.MatchString(ipv4ResolvedValue) {
		return normalizedPut{}, invalidField("ipv4_resolved_value", fielderr.InvalidFormat)
	}
	var l2ConfigID *uuid.UUID
	if request.L2ConfigID != nil {
		if *request.L2ConfigID == uuid.Nil {
			return normalizedPut{}, invalidField("l2_config_id", fielderr.Invalid)
		}
		value := *request.L2ConfigID
		l2ConfigID = &value
	}
	failoverMode := strings.TrimSpace(request.FailoverMode)
	if failoverMode == "" {
		failoverMode = defaultFailoverMode
	}
	// "interval" rotation has no defined semantics here and is
	// rejected rather than silently run as primary_offline.
	if failoverMode != FailoverPrimaryOffline && failoverMode != FailoverOnlineLessThanBackupCount {
		return normalizedPut{}, invalidField("failover_mode", fielderr.Invalid)
	}
	sortOrder := request.SortOrder
	if sortOrder == 0 {
		sortOrder = defaultLineGroupSortOrder
	}
	if sortOrder < 1 || int64(sortOrder) > int64(1<<31-1) {
		return normalizedPut{}, invalidField("sort_order", fielderr.OutOfRange)
	}
	policy, ok := normalizePolicy(request.Policy)
	if !ok {
		return normalizedPut{}, invalidField("health_policy", fielderr.Invalid)
	}
	endpoints := slices.Clone(request.Endpoints)
	seenIDs := make(map[uuid.UUID]struct{}, len(endpoints))
	seenAddresses := make(map[string]struct{}, len(endpoints))
	for index := range endpoints {
		item := &endpoints[index]
		at := func(field, reason string) error {
			return invalidField("endpoints["+strconv.Itoa(index)+"]."+field, reason)
		}
		for _, check := range []struct {
			bad   bool
			field string
		}{
			{item.Port < 1 || item.Port > 65535, "port"},
			{item.Priority < 0 || item.Priority > maxPriority, "priority"},
			{item.SortOrder < 0 || item.SortOrder > 999999, "sort_order"},
			{item.Weight < 1 || item.Weight > maxWeight, "weight"},
		} {
			if check.bad {
				return normalizedPut{}, at(check.field, fielderr.OutOfRange)
			}
		}
		if item.ID == uuid.Nil {
			return normalizedPut{}, at("id", fielderr.Required)
		}
		if item.SortOrder == 0 {
			item.SortOrder = 100
		}
		address, err := netip.ParseAddr(strings.TrimSpace(item.Address))
		if err != nil || address.Is4In6() || address.Zone() != "" {
			return normalizedPut{}, at("address", fielderr.InvalidFormat)
		}
		item.Address = address.String()
		var valid bool
		item.Region, valid = normalizeLabel(item.Region, 0, 64)
		if !valid {
			return normalizedPut{}, at("region", labelReason(item.Region, 64))
		}
		carrier := item.Carrier
		item.Carrier, valid = normalizeLabel(item.Carrier, 0, 64)
		if !valid {
			return normalizedPut{}, at("carrier", labelReason(carrier, 64))
		}
		item.Health = HealthState{}
		item.DisplayID = ""
		// 同一运营商线路下 IP+端口唯一；同一 IP 可分别挂到不同运营商线路（迁移 500）。
		addressKey := item.Carrier + "\x00" + netip.AddrPortFrom(address, uint16(item.Port)).String()
		if _, exists := seenIDs[item.ID]; exists {
			return normalizedPut{}, at("id", fielderr.Duplicate)
		}
		if _, exists := seenAddresses[addressKey]; exists {
			return normalizedPut{}, at("address", fielderr.Duplicate)
		}
		seenIDs[item.ID] = struct{}{}
		seenAddresses[addressKey] = struct{}{}
	}
	slices.SortFunc(endpoints, compareEndpoint)
	configuration := canonicalConfiguration{
		Name: name, Region: region, ResolvedValue: resolvedValue, IPv4ResolvedValue: ipv4ResolvedValue,
		L2ConfigID: uuidPointerString(l2ConfigID), FailoverMode: failoverMode, Note: note, SortOrder: sortOrder,
		Policy: canonicalizePolicy(policy), Endpoints: canonicalizeEndpoints(endpoints),
	}
	configDigest, err := digestConfiguration(configuration)
	if err != nil {
		return normalizedPut{}, err
	}
	requestBytes, err := json.Marshal(struct {
		GroupID          string                 `json:"group_id"`
		ExpectedRevision int64                  `json:"expected_revision"`
		Configuration    canonicalConfiguration `json:"configuration"`
	}{request.GroupID.String(), request.ExpectedRevision, configuration})
	if err != nil {
		return normalizedPut{}, err
	}
	v233RequestBytes, err := json.Marshal(struct {
		GroupID          string                     `json:"group_id"`
		ExpectedRevision int64                      `json:"expected_revision"`
		Configuration    v233CanonicalConfiguration `json:"configuration"`
	}{request.GroupID.String(), request.ExpectedRevision, v233CanonicalConfiguration{
		Name: name, Region: region, ResolvedValue: resolvedValue, Note: note, SortOrder: sortOrder,
		Policy: canonicalizePolicy(policy), Endpoints: canonicalizeLegacyEndpoints(endpoints),
	}})
	if err != nil {
		return normalizedPut{}, err
	}
	v226RequestBytes, err := json.Marshal(struct {
		GroupID          string                     `json:"group_id"`
		ExpectedRevision int64                      `json:"expected_revision"`
		Configuration    v226CanonicalConfiguration `json:"configuration"`
	}{request.GroupID.String(), request.ExpectedRevision, v226CanonicalConfiguration{
		Name: name, Policy: canonicalizePolicy(policy), Endpoints: canonicalizeLegacyEndpoints(endpoints),
	}})
	if err != nil {
		return normalizedPut{}, err
	}
	referenceFieldsLegacyEligible := strings.TrimSpace(request.IPv4ResolvedValue) == "" &&
		request.L2ConfigID == nil && (strings.TrimSpace(request.FailoverMode) == "" || failoverMode == defaultFailoverMode)
	return normalizedPut{
		groupID: request.GroupID, expectedRevision: request.ExpectedRevision, name: name,
		region: region, resolvedValue: resolvedValue, ipv4ResolvedValue: ipv4ResolvedValue,
		l2ConfigID: l2ConfigID, failoverMode: failoverMode, note: note, sortOrder: sortOrder,
		policy: policy, endpoints: endpoints, idempotencyKey: request.IdempotencyKey,
		requestID: request.RequestID, requestDigest: sha256.Sum256(requestBytes),
		v233RequestDigest: sha256.Sum256(v233RequestBytes), v233ReplayEligible: referenceFieldsLegacyEligible,
		v226RequestDigest: sha256.Sum256(v226RequestBytes),
		v226ReplayEligible: referenceFieldsLegacyEligible && len(endpoints) > 0 && region == "" && resolvedValue == "" &&
			note == "" && sortOrder == defaultLineGroupSortOrder,
		configDigest: configDigest,
		purpose:      purpose,
	}, nil
}

// normalizePurpose maps the empty purpose to general and rejects unknown ones.
func normalizePurpose(value string) (string, bool) {
	switch value {
	case "", PurposeGeneral:
		return PurposeGeneral, true
	case PurposeMarketSupply:
		return PurposeMarketSupply, true
	}
	return "", false
}

func applyGroupDefaults(input normalizedPut) (normalizedPut, error) {
	if input.groupID == uuid.Nil {
		return normalizedPut{}, ErrInvalidInput
	}
	if input.resolvedValue == "" {
		input.resolvedValue = defaultResolvedValue(input.groupID)
	}
	if input.ipv4ResolvedValue == "" {
		input.ipv4ResolvedValue = defaultIPv4ResolvedValue(input.groupID)
	}
	digest, err := digestConfiguration(canonicalConfiguration{
		Name: input.name, Region: input.region, ResolvedValue: input.resolvedValue,
		IPv4ResolvedValue: input.ipv4ResolvedValue, L2ConfigID: uuidPointerString(input.l2ConfigID),
		FailoverMode: input.failoverMode, Note: input.note, SortOrder: input.sortOrder,
		Policy: canonicalizePolicy(input.policy), Endpoints: canonicalizeEndpoints(input.endpoints),
	})
	if err != nil {
		return normalizedPut{}, err
	}
	input.configDigest = digest
	return input, nil
}

func defaultResolvedValue(groupID uuid.UUID) string {
	return "lg-" + strings.ReplaceAll(groupID.String(), "-", "")
}

func defaultIPv4ResolvedValue(groupID uuid.UUID) string {
	return "v4-" + strings.ReplaceAll(groupID.String(), "-", "")
}

func uuidPointerString(value *uuid.UUID) string {
	if value == nil {
		return ""
	}
	return value.String()
}

func digestConfiguration(configuration canonicalConfiguration) ([32]byte, error) {
	encoded, err := json.Marshal(configuration)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

func normalizePolicy(policy HealthPolicy) (HealthPolicy, bool) {
	defaults := DefaultHealthPolicy()
	if policy.ProbeInterval == 0 {
		policy.ProbeInterval = defaults.ProbeInterval
	}
	if policy.ProbeTimeout == 0 {
		policy.ProbeTimeout = defaults.ProbeTimeout
	}
	if policy.FailureThreshold == 0 {
		policy.FailureThreshold = defaults.FailureThreshold
	}
	if policy.RecoveryThreshold == 0 {
		policy.RecoveryThreshold = defaults.RecoveryThreshold
	}
	validDuration := func(value time.Duration) bool { return value%time.Millisecond == 0 }
	if policy.ProbeInterval < time.Second || policy.ProbeInterval > 5*time.Minute || !validDuration(policy.ProbeInterval) ||
		policy.ProbeTimeout < 100*time.Millisecond || policy.ProbeTimeout > time.Minute ||
		policy.ProbeTimeout > policy.ProbeInterval || !validDuration(policy.ProbeTimeout) ||
		policy.FailureThreshold < 1 || policy.FailureThreshold > 20 ||
		policy.RecoveryThreshold < 1 || policy.RecoveryThreshold > 20 ||
		policy.FailureDebounce < 0 || policy.FailureDebounce > time.Hour || !validDuration(policy.FailureDebounce) ||
		policy.RecoveryDebounce < 0 || policy.RecoveryDebounce > time.Hour || !validDuration(policy.RecoveryDebounce) {
		return HealthPolicy{}, false
	}
	return policy, true
}

func normalizeLabel(value string, minimum, maximum int) (string, bool) {
	if !utf8.ValidString(value) || strings.ContainsFunc(value, unicode.IsControl) {
		return "", false
	}
	length := utf8.RuneCountInString(value)
	trimmedLength := utf8.RuneCountInString(strings.TrimSpace(value))
	return value, trimmedLength >= minimum && length <= maximum
}

// invalidField is ErrInvalidInput naming the refused line group request field
// (fix-fielderr-be; endpoints[n] is the index in the request).
func invalidField(field, reason string) error { return fielderr.New(ErrInvalidInput, field, reason) }

// labelField is normalizeLabel (trim: of the trimmed value) with the refusal located.
func labelField(field, value string, minimum, maximum int, trim bool) (string, error) {
	if trim {
		value = strings.TrimSpace(value)
	}
	normalized, ok := normalizeLabel(value, minimum, maximum)
	if ok {
		return normalized, nil
	}
	if minimum > 0 && utf8.ValidString(value) && strings.TrimSpace(value) == "" {
		return "", invalidField(field, fielderr.Required)
	}
	return "", invalidField(field, labelReason(value, maximum))
}

func labelReason(value string, maximum int) string {
	if !utf8.ValidString(value) || strings.ContainsFunc(value, unicode.IsControl) {
		return fielderr.InvalidFormat
	}
	if utf8.RuneCountInString(value) > maximum {
		return fielderr.TooLong
	}
	return fielderr.Required
}

func canonicalizePolicy(policy HealthPolicy) canonicalPolicy {
	return canonicalPolicy{
		ProbeIntervalMS: policy.ProbeInterval.Milliseconds(), ProbeTimeoutMS: policy.ProbeTimeout.Milliseconds(),
		FailureThreshold: policy.FailureThreshold, RecoveryThreshold: policy.RecoveryThreshold,
		FailureDebounceMS: policy.FailureDebounce.Milliseconds(), RecoveryDebounceMS: policy.RecoveryDebounce.Milliseconds(),
	}
}

func canonicalizeEndpoints(endpoints []Endpoint) []canonicalEndpoint {
	result := make([]canonicalEndpoint, len(endpoints))
	for index, endpoint := range endpoints {
		result[index] = canonicalEndpoint{
			ID: endpoint.ID.String(), NodeID: uuidString(endpoint.NodeID), Address: endpoint.Address, Port: endpoint.Port,
			Region: endpoint.Region, Carrier: endpoint.Carrier, Priority: endpoint.Priority, SortOrder: endpoint.SortOrder,
			Weight: endpoint.Weight, Enabled: endpoint.Enabled,
		}
	}
	return result
}

func canonicalizeLegacyEndpoints(endpoints []Endpoint) []legacyCanonicalEndpoint {
	result := make([]legacyCanonicalEndpoint, len(endpoints))
	for index, endpoint := range endpoints {
		result[index] = legacyCanonicalEndpoint{
			ID: endpoint.ID.String(), NodeID: uuidString(endpoint.NodeID), Address: endpoint.Address, Port: endpoint.Port,
			Region: endpoint.Region, Carrier: endpoint.Carrier, Priority: endpoint.Priority,
			Weight: endpoint.Weight, Enabled: endpoint.Enabled,
		}
	}
	return result
}

func compareEndpoint(left, right Endpoint) int {
	if left.Priority != right.Priority {
		return left.Priority - right.Priority
	}
	if left.SortOrder != right.SortOrder {
		return left.SortOrder - right.SortOrder
	}
	leftAddress, _ := netip.ParseAddr(left.Address)
	rightAddress, _ := netip.ParseAddr(right.Address)
	if leftAddress.BitLen() != rightAddress.BitLen() {
		return leftAddress.BitLen() - rightAddress.BitLen()
	}
	if comparison := leftAddress.Compare(rightAddress); comparison != 0 {
		return comparison
	}
	if left.Port != right.Port {
		return left.Port - right.Port
	}
	return strings.Compare(left.ID.String(), right.ID.String())
}
