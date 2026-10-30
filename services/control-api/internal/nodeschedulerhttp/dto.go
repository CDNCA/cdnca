package nodeschedulerhttp

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/nodescheduler"
	"github.com/google/uuid"
)

type healthPolicyDTO struct {
	ProbeIntervalMS    int64 `json:"probe_interval_ms"`
	ProbeTimeoutMS     int64 `json:"probe_timeout_ms"`
	FailureThreshold   int   `json:"failure_threshold"`
	RecoveryThreshold  int   `json:"recovery_threshold"`
	FailureDebounceMS  int64 `json:"failure_debounce_ms"`
	RecoveryDebounceMS int64 `json:"recovery_debounce_ms"`
}

type healthStateDTO struct {
	Status               string     `json:"status"`
	ConsecutiveSuccesses int        `json:"consecutive_successes"`
	ConsecutiveFailures  int        `json:"consecutive_failures"`
	LastSequence         int64      `json:"last_sequence"`
	LastObservedAt       *time.Time `json:"last_observed_at"`
	LastChangedAt        time.Time  `json:"last_changed_at"`
	RowRevision          int64      `json:"row_revision"`
}

type endpointDTO struct {
	ID        uuid.UUID       `json:"id"`
	DisplayID string          `json:"display_id,omitempty"`
	NodeID    uuid.UUID       `json:"node_id"`
	Address   string          `json:"address"`
	Port      int             `json:"port"`
	Region    string          `json:"region"`
	Carrier   string          `json:"carrier"`
	Priority  int             `json:"priority"`
	SortOrder int             `json:"sort_order"`
	Weight    int             `json:"weight"`
	Enabled   bool            `json:"enabled"`
	Health    *healthStateDTO `json:"health,omitempty"`
	Published *bool           `json:"published,omitempty"`
}

type lineGroupStatisticsDTO struct {
	NodeCount    int64 `json:"node_count"`
	SiteCount    int64 `json:"site_count"`
	ForwardCount int64 `json:"forward_count"`
}

type lineGroupDTO struct {
	ID                  uuid.UUID               `json:"id"`
	DisplayID           string                  `json:"display_id"`
	TenantScopeID       uuid.UUID               `json:"tenant_scope_id"`
	Revision            int64                   `json:"revision"`
	Name                string                  `json:"name"`
	Region              string                  `json:"region"`
	ResolvedValue       string                  `json:"resolved_value"`
	IPv4ResolvedValue   string                  `json:"ipv4_resolved_value"`
	L2ConfigID          *uuid.UUID              `json:"l2_config_id"`
	FailoverMode        string                  `json:"failover_mode"`
	Note                string                  `json:"note"`
	SortOrder           int                     `json:"sort_order"`
	HealthPolicy        healthPolicyDTO         `json:"health_policy"`
	Endpoints           []endpointDTO           `json:"endpoints"`
	Statistics          *lineGroupStatisticsDTO `json:"statistics,omitempty"`
	ConfigurationDigest string                  `json:"configuration_digest"`
	CreatedByUserID     uuid.UUID               `json:"created_by_user_id"`
	CreatedAt           time.Time               `json:"created_at"`
	SealedAt            time.Time               `json:"sealed_at"`
	IsPlatformDefault   bool                    `json:"is_platform_default"`
	BackupStates        []backupStateDTO        `json:"backup_states,omitempty"`
}

type backupStateDTO struct {
	AddressFamily   int       `json:"address_family"`
	State           string    `json:"state"`
	BackupAddresses []string  `json:"backup_addresses"`
	ChangedAt       time.Time `json:"changed_at"`
}

type platformDefaultBody struct {
	IsPlatformDefault *bool `json:"is_platform_default"`
}

type lineGroupWriteBody struct {
	Name              string           `json:"name"`
	Region            string           `json:"region"`
	ResolvedValue     string           `json:"resolved_value"`
	IPv4ResolvedValue string           `json:"ipv4_resolved_value"`
	L2ConfigID        *uuid.UUID       `json:"l2_config_id"`
	FailoverMode      string           `json:"failover_mode"`
	Note              string           `json:"note"`
	SortOrder         int              `json:"sort_order"`
	HealthPolicy      *healthPolicyDTO `json:"health_policy"`
	Endpoints         []endpointDTO    `json:"endpoints"`
	// zeroSortOrder 记录请求里显式写了 sort_order:0（线路组或任一 IP）。契约最小为 1，
	// 省略字段才取默认 100；显式 0 由 handler 拒绝，不再静默改成 100（卡 52）。
	zeroSortOrder bool
}

func (body *lineGroupWriteBody) UnmarshalJSON(data []byte) error {
	type plain lineGroupWriteBody
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode((*plain)(body)); err != nil {
		return err
	}
	var probe struct {
		SortOrder *int `json:"sort_order"`
		Endpoints []struct {
			SortOrder *int `json:"sort_order"`
		} `json:"endpoints"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return err
	}
	body.zeroSortOrder = probe.SortOrder != nil && *probe.SortOrder == 0
	for _, endpoint := range probe.Endpoints {
		body.zeroSortOrder = body.zeroSortOrder || endpoint.SortOrder != nil && *endpoint.SortOrder == 0
	}
	return nil
}

func (body lineGroupWriteBody) request(groupID uuid.UUID, revision int64, idempotencyKey, requestID string) nodescheduler.PutGroupRequest {
	policy := healthPolicyDTO{}
	if body.HealthPolicy != nil {
		policy = *body.HealthPolicy
	}
	endpoints := make([]nodescheduler.Endpoint, len(body.Endpoints))
	for index, endpoint := range body.Endpoints {
		endpoints[index] = nodescheduler.Endpoint{
			ID: endpoint.ID, NodeID: endpoint.NodeID, Address: endpoint.Address, Port: endpoint.Port,
			Region: endpoint.Region, Carrier: endpoint.Carrier, Priority: endpoint.Priority,
			SortOrder: endpoint.SortOrder, Weight: endpoint.Weight, Enabled: endpoint.Enabled,
		}
	}
	return nodescheduler.PutGroupRequest{
		GroupID: groupID, ExpectedRevision: revision, Name: body.Name,
		Region: body.Region, ResolvedValue: body.ResolvedValue, IPv4ResolvedValue: body.IPv4ResolvedValue,
		L2ConfigID: body.L2ConfigID, FailoverMode: body.FailoverMode, Note: body.Note, SortOrder: body.SortOrder,
		Policy: nodescheduler.HealthPolicy{
			ProbeInterval:    time.Duration(policy.ProbeIntervalMS) * time.Millisecond,
			ProbeTimeout:     time.Duration(policy.ProbeTimeoutMS) * time.Millisecond,
			FailureThreshold: policy.FailureThreshold, RecoveryThreshold: policy.RecoveryThreshold,
			FailureDebounce:  time.Duration(policy.FailureDebounceMS) * time.Millisecond,
			RecoveryDebounce: time.Duration(policy.RecoveryDebounceMS) * time.Millisecond,
		},
		Endpoints: endpoints, IdempotencyKey: idempotencyKey, RequestID: requestID,
	}
}

func lineGroupView(group nodescheduler.LineGroupRevision) lineGroupDTO {
	endpoints := make([]endpointDTO, len(group.Endpoints))
	for index, endpoint := range group.Endpoints {
		health := healthStateDTO{
			Status: endpoint.Health.Status, ConsecutiveSuccesses: endpoint.Health.ConsecutiveSuccesses,
			ConsecutiveFailures: endpoint.Health.ConsecutiveFailures, LastSequence: endpoint.Health.LastSequence,
			LastObservedAt: endpoint.Health.LastObservedAt, LastChangedAt: endpoint.Health.LastChangedAt,
			RowRevision: endpoint.Health.RowRevision,
		}
		endpoints[index] = endpointDTO{
			ID: endpoint.ID, DisplayID: endpoint.DisplayID, NodeID: endpoint.NodeID, Address: endpoint.Address, Port: endpoint.Port,
			Region: endpoint.Region, Carrier: endpoint.Carrier, Priority: endpoint.Priority,
			SortOrder: endpoint.SortOrder, Weight: endpoint.Weight, Enabled: endpoint.Enabled, Health: &health,
			Published: endpoint.Published,
		}
	}
	return lineGroupDTO{
		ID: group.GroupID, DisplayID: group.DisplayID, TenantScopeID: group.TenantScopeID, Revision: group.Revision, Name: group.Name,
		Region: group.Region, ResolvedValue: group.ResolvedValue, IPv4ResolvedValue: group.IPv4ResolvedValue,
		L2ConfigID: group.L2ConfigID, FailoverMode: group.FailoverMode, Note: group.Note, SortOrder: group.SortOrder,
		HealthPolicy: healthPolicyDTO{
			ProbeIntervalMS: group.Policy.ProbeInterval.Milliseconds(), ProbeTimeoutMS: group.Policy.ProbeTimeout.Milliseconds(),
			FailureThreshold: group.Policy.FailureThreshold, RecoveryThreshold: group.Policy.RecoveryThreshold,
			FailureDebounceMS: group.Policy.FailureDebounce.Milliseconds(), RecoveryDebounceMS: group.Policy.RecoveryDebounce.Milliseconds(),
		},
		Endpoints: endpoints, ConfigurationDigest: hex.EncodeToString(group.ConfigurationDigest),
		CreatedByUserID: group.CreatedByUserID, CreatedAt: group.CreatedAt, SealedAt: group.SealedAt,
		IsPlatformDefault: group.IsPlatformDefault, BackupStates: backupStatesView(group.BackupStates),
	}
}

func backupStatesView(states []nodescheduler.LineBackupState) []backupStateDTO {
	if states == nil {
		return nil
	}
	views := make([]backupStateDTO, len(states))
	for index, state := range states {
		addresses := state.BackupAddresses
		if addresses == nil {
			addresses = []string{}
		}
		views[index] = backupStateDTO{AddressFamily: state.AddressFamily, State: state.State,
			BackupAddresses: addresses, ChangedAt: state.ChangedAt}
	}
	return views
}

func endpointView(endpoint nodescheduler.Endpoint) endpointDTO {
	group := nodescheduler.LineGroupRevision{Endpoints: []nodescheduler.Endpoint{endpoint}}
	return lineGroupView(group).Endpoints[0]
}
