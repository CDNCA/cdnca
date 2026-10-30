package nodescheduler

import (
	"crypto/sha256"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestNormalizePutRequestDefaultsDualStackAndRejectsInvalidInput(t *testing.T) {
	endpoint4 := testEndpoint("192.0.2.10", 443, 0, 1)
	endpoint6 := testEndpoint("2001:db8::10", 443, 1, 100)
	request := PutGroupRequest{
		GroupID: uuid.New(), Name: " 华东线路 ", Endpoints: []Endpoint{endpoint6, endpoint4},
		IdempotencyKey: "group-create", RequestID: "request-1",
	}
	normalized, err := normalizePutRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if normalized.name != " 华东线路 " || normalized.policy != DefaultHealthPolicy() {
		t.Fatalf("normalized request = %#v", normalized)
	}
	if normalized.endpoints[0].Address != endpoint4.Address || normalized.endpoints[1].Address != endpoint6.Address {
		t.Fatalf("endpoint order = %#v", normalized.endpoints)
	}

	tests := map[string]func(*PutGroupRequest){
		"control name":      func(value *PutGroupRequest) { value.Name = "bad\nname" },
		"control region":    func(value *PutGroupRequest) { value.Endpoints[0].Region = "cn\t-east" },
		"invalid address":   func(value *PutGroupRequest) { value.Endpoints[0].Address = "not-an-ip" },
		"mapped address":    func(value *PutGroupRequest) { value.Endpoints[0].Address = "::ffff:192.0.2.10" },
		"zero port":         func(value *PutGroupRequest) { value.Endpoints[0].Port = 0 },
		"priority overflow": func(value *PutGroupRequest) { value.Endpoints[0].Priority = maxPriority + 1 },
		"zero weight":       func(value *PutGroupRequest) { value.Endpoints[0].Weight = 0 },
		"weight overflow":   func(value *PutGroupRequest) { value.Endpoints[0].Weight = maxWeight + 1 },
		"duplicate id": func(value *PutGroupRequest) {
			value.Endpoints[1].ID = value.Endpoints[0].ID
		},
		"duplicate address port": func(value *PutGroupRequest) {
			value.Endpoints[1].Address = value.Endpoints[0].Address
			value.Endpoints[1].Port = value.Endpoints[0].Port
		},
		"duplicate address port same carrier": func(value *PutGroupRequest) {
			value.Endpoints[0].Carrier, value.Endpoints[1].Carrier = "电信", "电信"
			value.Endpoints[1].Address = value.Endpoints[0].Address
			value.Endpoints[1].Port = value.Endpoints[0].Port
		},
		"timeout after interval": func(value *PutGroupRequest) {
			value.Policy = HealthPolicy{ProbeInterval: time.Second, ProbeTimeout: 2 * time.Second}
		},
		"threshold overflow": func(value *PutGroupRequest) {
			value.Policy = HealthPolicy{FailureThreshold: 21}
		},
		"sub-ms debounce": func(value *PutGroupRequest) {
			value.Policy = HealthPolicy{FailureDebounce: time.Microsecond}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := request
			candidate.Endpoints = slices.Clone(request.Endpoints)
			mutate(&candidate)
			if _, err := normalizePutRequest(candidate); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("normalize error = %v", err)
			}
		})
	}
}

// NET-02：同一 IP+端口可分别挂到不同运营商线路（迁移 500 的去重键含 carrier）。
func TestNormalizePutRequestAllowsSameAddressOnDifferentCarriers(t *testing.T) {
	var endpoints []Endpoint
	for _, carrier := range []string{"", "电信", "联通", "移动"} {
		endpoint := testEndpoint("192.0.2.10", 443, 0, 100)
		endpoint.Carrier = carrier
		endpoints = append(endpoints, endpoint)
	}
	normalized, err := normalizePutRequest(PutGroupRequest{GroupID: uuid.New(), Name: "多线路", Endpoints: endpoints,
		IdempotencyKey: "multi-carrier", RequestID: "multi-carrier"})
	if err != nil {
		t.Fatal(err)
	}
	carriers := make([]string, 0, len(normalized.endpoints))
	for _, endpoint := range normalized.endpoints {
		carriers = append(carriers, endpoint.Carrier)
	}
	slices.Sort(carriers)
	if !slices.Equal(carriers, []string{"", "电信", "移动", "联通"}) {
		t.Fatalf("carriers = %v", carriers)
	}
}

func TestNormalizePutRequestLineGroupMetadataAndEmptyEndpoints(t *testing.T) {
	groupID := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	request := PutGroupRequest{
		Name: "空线路组", Region: " 华东 ", ResolvedValue: " Edge-01 ", Note: " 首次配置 ",
		IdempotencyKey: "empty-group-create", RequestID: "empty-group-request",
	}
	normalized, err := normalizePutRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if normalized.region != "华东" || normalized.resolvedValue != "edge-01" ||
		normalized.note != "首次配置" || normalized.sortOrder != 100 || len(normalized.endpoints) != 0 {
		t.Fatalf("normalized metadata = %#v", normalized)
	}

	request.Region, request.ResolvedValue, request.Note, request.SortOrder = "", "", "", 7
	normalized, err = normalizePutRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	originalRequestDigest, originalConfigDigest := normalized.requestDigest, normalized.configDigest
	normalized.groupID = groupID
	normalized, err = applyGroupDefaults(normalized)
	if err != nil {
		t.Fatal(err)
	}
	if normalized.resolvedValue != "lg-11111111111141118111111111111111" || normalized.sortOrder != 7 {
		t.Fatalf("defaulted metadata = %#v", normalized)
	}
	if normalized.requestDigest != originalRequestDigest {
		t.Fatal("generated resolved value changed the idempotency request digest")
	}
	if normalized.configDigest == originalConfigDigest {
		t.Fatal("generated resolved value did not change the persisted configuration digest")
	}

	invalid := map[string]func(*PutGroupRequest){
		"resolved dot":        func(value *PutGroupRequest) { value.ResolvedValue = "edge.example" },
		"resolved port":       func(value *PutGroupRequest) { value.ResolvedValue = "edge:443" },
		"resolved underscore": func(value *PutGroupRequest) { value.ResolvedValue = "edge_one" },
		"resolved too long":   func(value *PutGroupRequest) { value.ResolvedValue = strings.Repeat("a", 64) },
		"region control":      func(value *PutGroupRequest) { value.Region = "华\n东" },
		"region too long":     func(value *PutGroupRequest) { value.Region = strings.Repeat("区", 65) },
		"note control":        func(value *PutGroupRequest) { value.Note = "备注\t值" },
		"note too long":       func(value *PutGroupRequest) { value.Note = strings.Repeat("注", 513) },
		"negative sort":       func(value *PutGroupRequest) { value.SortOrder = -1 },
		"sort overflow":       func(value *PutGroupRequest) { value.SortOrder = 1 << 31 },
	}
	for name, mutate := range invalid {
		t.Run(name, func(t *testing.T) {
			candidate := request
			mutate(&candidate)
			if _, err := normalizePutRequest(candidate); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("normalize error = %v", err)
			}
		})
	}
}

func TestNormalizePutRequestKeepsExactV226ReplayDigestOnlyForLegacyCompatibleWrites(t *testing.T) {
	groupID := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	request := PutGroupRequest{
		GroupID: groupID, ExpectedRevision: 1, Name: "legacy-line",
		Endpoints: []Endpoint{{
			ID:      uuid.MustParse("22222222-2222-4222-8222-222222222222"),
			NodeID:  uuid.MustParse("33333333-3333-4333-8333-333333333333"),
			Address: "192.0.2.10", Port: 443, Weight: 1, Enabled: true,
		}},
		IdempotencyKey: "legacy-line-update", RequestID: "legacy-line-update-request",
	}
	normalized, err := normalizePutRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256([]byte(`{"group_id":"11111111-1111-4111-8111-111111111111","expected_revision":1,"configuration":{"name":"legacy-line","health_policy":{"probe_interval_ms":10000,"probe_timeout_ms":3000,"failure_threshold":3,"recovery_threshold":3,"failure_debounce_ms":0,"recovery_debounce_ms":0},"endpoints":[{"id":"22222222-2222-4222-8222-222222222222","node_id":"33333333-3333-4333-8333-333333333333","address":"192.0.2.10","port":443,"region":"","carrier":"","priority":0,"weight":1,"enabled":true}]}}`))
	if normalized.v226RequestDigest != want || !normalized.v226ReplayEligible {
		t.Fatalf("v226 digest=%x eligible=%v, want %x true",
			normalized.v226RequestDigest, normalized.v226ReplayEligible, want)
	}

	withMetadata := request
	withMetadata.Region = "华东"
	withMetadataNormalized, err := normalizePutRequest(withMetadata)
	if err != nil {
		t.Fatal(err)
	}
	if withMetadataNormalized.v226ReplayEligible {
		t.Fatal("metadata-bearing write was eligible for v226 replay")
	}

	empty := request
	empty.Endpoints = nil
	emptyNormalized, err := normalizePutRequest(empty)
	if err != nil {
		t.Fatal(err)
	}
	if emptyNormalized.v226ReplayEligible {
		t.Fatal("empty write was eligible for a v226 replay that could never have existed")
	}
}

func TestCanonicalNodeSetDigestIsOrderIndependentAndSetScoped(t *testing.T) {
	first, second := uuid.MustParse("00000000-0000-0000-0000-000000000001"), uuid.MustParse("00000000-0000-0000-0000-000000000002")
	if got, want := CanonicalNodeSetDigest([]uuid.UUID{second, first, first}), CanonicalNodeSetDigest([]uuid.UUID{first, second}); got != want {
		t.Fatalf("digest changed with order or duplicate: %x != %x", got, want)
	}
	if CanonicalNodeSetDigest([]uuid.UUID{first}) == CanonicalNodeSetDigest([]uuid.UUID{first, second}) {
		t.Fatal("different node sets share digest")
	}
}

func TestBuildPlanDualStackRegionalPrimaryBackupAndDeterminism(t *testing.T) {
	now := time.Date(2026, 7, 29, 4, 0, 0, 0, time.UTC)
	tenantID, groupID := uuid.New(), uuid.New()
	global := testEndpoint("192.0.2.1", 443, 0, 5)
	global.Health.Status = HealthHealthy
	regional4 := testEndpoint("192.0.2.2", 443, 10, 1)
	regional4.Region, regional4.Carrier, regional4.Health.Status = "cn-east", "telecom", HealthHealthy
	regional6 := testEndpoint("2001:db8::2", 443, 10, 3)
	regional6.Region, regional6.Carrier, regional6.Health.Status = "cn-east", "telecom", HealthHealthy
	backup := testEndpoint("192.0.2.3", 443, 20, 100)
	backup.Region, backup.Carrier, backup.Health.Status = "cn-east", "telecom", HealthHealthy
	disabled := testEndpoint("192.0.2.4", 443, 0, 100)
	disabled.Region, disabled.Carrier, disabled.Health.Status, disabled.Enabled = "cn-east", "telecom", HealthHealthy, false
	group := LineGroupRevision{
		TenantScopeID: tenantID, GroupID: groupID, Revision: 7,
		Policy:    DefaultHealthPolicy(),
		Endpoints: []Endpoint{backup, regional6, disabled, global, regional4},
	}
	for index := range group.Endpoints {
		group.Endpoints[index].Health.LastReceivedAt = &now
	}
	selector := Selector{Region: "cn-east", Carrier: "telecom"}
	plan, err := BuildPlan(group, selector, now)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Priority != 10 || len(plan.Candidates) != 2 || len(plan.Standby) != 1 {
		t.Fatalf("plan = %#v", plan)
	}
	if plan.Candidates[0].Address != regional4.Address || plan.Candidates[1].Address != regional6.Address ||
		plan.Standby[0].Address != backup.Address {
		t.Fatalf("plan order = candidates %#v standby %#v", plan.Candidates, plan.Standby)
	}

	reversed := group
	reversed.Endpoints = slices.Clone(group.Endpoints)
	slices.Reverse(reversed.Endpoints)
	repeated, err := BuildPlan(reversed, selector, now)
	if err != nil || repeated.Digest != plan.Digest {
		t.Fatalf("reordered plan digest = %x, %v; want %x", repeated.Digest, err, plan.Digest)
	}

	fallback, err := BuildPlan(group, Selector{Region: "cn-north", Carrier: "mobile"}, now)
	if err != nil || len(fallback.Candidates) != 1 || fallback.Candidates[0].ID != global.ID {
		t.Fatalf("global fallback = %#v, %v", fallback, err)
	}
	for index := range group.Endpoints {
		group.Endpoints[index].Health.Status = HealthUnhealthy
	}
	if _, err := BuildPlan(group, selector, now); !errors.Is(err, ErrNoHealthyEndpoint) {
		t.Fatalf("no-health error = %v", err)
	}
}

func TestBuildPlanEmptyLineGroupFailsClosed(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	plan, err := BuildPlan(LineGroupRevision{
		TenantScopeID: uuid.New(), GroupID: uuid.New(), Revision: 1,
		Policy: DefaultHealthPolicy(), ConfigurationDigest: make([]byte, 32),
	}, Selector{}, now)
	if !errors.Is(err, ErrNoHealthyEndpoint) || plan.TierReason != ReasonNoHealthyEndpoint ||
		len(plan.Candidates) != 0 || len(plan.Standby) != 0 || len(plan.Evaluations) != 0 ||
		plan.Digest == ([32]byte{}) {
		t.Fatalf("empty group plan = %#v, err = %v", plan, err)
	}
}

func TestBuildPlanPriorityFailoverAndFailClosedSnapshot(t *testing.T) {
	now := time.Date(2026, 8, 9, 9, 0, 0, 0, time.UTC)
	primary := testEndpoint("192.0.2.10", 443, 0, 100)
	primary.Health = HealthState{Status: HealthUnhealthy, RowRevision: 7, LastChangedAt: now.Add(-time.Minute)}
	backupA := testEndpoint("192.0.2.20", 443, 10, 1)
	backupB := testEndpoint("192.0.2.21", 443, 10, 3)
	standby := testEndpoint("192.0.2.30", 443, 20, 100)
	for _, endpoint := range []*Endpoint{&backupA, &backupB, &standby} {
		endpoint.Health = HealthState{Status: HealthHealthy, RowRevision: 9, LastReceivedAt: &now}
	}
	group := LineGroupRevision{
		TenantScopeID: uuid.New(), GroupID: uuid.New(), Revision: 8,
		Policy: DefaultHealthPolicy(), ConfigurationDigest: []byte("configuration-digest"),
		Endpoints: []Endpoint{standby, backupB, primary, backupA},
	}

	plan, err := BuildPlan(group, Selector{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Priority != 10 || plan.TierReason != ReasonBackupPrioritySelected ||
		len(plan.Candidates) != 2 || len(plan.Standby) != 1 {
		t.Fatalf("failover plan=%#v", plan)
	}
	if plan.Evaluations[0].Endpoint.ID != primary.ID ||
		plan.Evaluations[0].Disposition != EndpointDispositionUnhealthy {
		t.Fatalf("primary evaluation=%#v", plan.Evaluations)
	}
	counts := map[uuid.UUID]int{}
	for sample := uint64(0); sample < 400; sample++ {
		selected, selectErr := plan.ChooseWeighted(sample)
		if selectErr != nil {
			t.Fatal(selectErr)
		}
		counts[selected.ID]++
		if selected.Priority != 10 {
			t.Fatalf("weight escaped active priority: %#v", selected)
		}
	}
	if counts[backupA.ID] != 100 || counts[backupB.ID] != 300 || counts[standby.ID] != 0 {
		t.Fatalf("same-priority weighted counts=%v", counts)
	}

	changed := group
	changed.Endpoints = slices.Clone(group.Endpoints)
	changed.Endpoints[2].Health.RowRevision++
	changedPlan, err := BuildPlan(changed, Selector{}, now)
	if err != nil || changedPlan.Digest == plan.Digest {
		t.Fatalf("health snapshot digest did not change: %x %x err=%v", plan.Digest, changedPlan.Digest, err)
	}

	for index := range group.Endpoints {
		group.Endpoints[index].Health.Status = HealthUnhealthy
		group.Endpoints[index].Health.LastReceivedAt = nil
	}
	failed, err := BuildPlan(group, Selector{}, now)
	if !errors.Is(err, ErrNoHealthyEndpoint) || failed.TierReason != ReasonNoHealthyEndpoint ||
		len(failed.Evaluations) != len(group.Endpoints) || failed.Digest == ([32]byte{}) {
		t.Fatalf("fail-closed snapshot=%#v err=%v", failed, err)
	}
}

func TestPlanWeightedSelectionHasReproducibleDistribution(t *testing.T) {
	now := time.Date(2026, 7, 29, 4, 0, 0, 0, time.UTC)
	left := testEndpoint("192.0.2.10", 443, 0, 1)
	right := testEndpoint("2001:db8::10", 443, 0, 3)
	left.Health.Status, right.Health.Status = HealthHealthy, HealthHealthy
	left.Health.LastReceivedAt, right.Health.LastReceivedAt = &now, &now
	plan, err := BuildPlan(LineGroupRevision{
		TenantScopeID: uuid.New(), GroupID: uuid.New(), Revision: 1,
		Policy:    DefaultHealthPolicy(),
		Endpoints: []Endpoint{right, left},
	}, Selector{}, now)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[uuid.UUID]int{}
	for sample := uint64(0); sample < 4000; sample++ {
		selected, err := plan.ChooseWeighted(sample)
		if err != nil {
			t.Fatal(err)
		}
		counts[selected.ID]++
	}
	if counts[left.ID] != 1000 || counts[right.ID] != 3000 {
		t.Fatalf("weighted counts = %#v", counts)
	}
	first, _ := plan.ChooseKey("site-42.example")
	second, _ := plan.ChooseKey("site-42.example")
	if first.ID != second.ID {
		t.Fatalf("key selection changed: %s != %s", first.ID, second.ID)
	}
}

func TestBuildPlanRejectsExpiredHealthyProbe(t *testing.T) {
	now := time.Date(2026, 7, 29, 4, 0, 0, 0, time.UTC)
	lastReceived := now.Add(-34 * time.Second)
	endpoint := testEndpoint("192.0.2.81", 443, 0, 1)
	endpoint.Health = HealthState{Status: HealthHealthy, LastReceivedAt: &lastReceived}
	_, err := BuildPlan(LineGroupRevision{
		TenantScopeID: uuid.New(), GroupID: uuid.New(), Revision: 1,
		Policy: DefaultHealthPolicy(), Endpoints: []Endpoint{endpoint},
	}, Selector{}, now)
	if !errors.Is(err, ErrNoHealthyEndpoint) {
		t.Fatalf("expired healthy status error=%v, want %v", err, ErrNoHealthyEndpoint)
	}
}

func TestBuildPlanHealthyFreshnessDeadlineBoundaries(t *testing.T) {
	lastReceived := time.Date(2026, 7, 29, 4, 0, 0, 0, time.UTC)
	policy := HealthPolicy{
		ProbeInterval: 10 * time.Second, ProbeTimeout: 3 * time.Second,
		FailureThreshold: 3, RecoveryThreshold: 3, FailureDebounce: 2 * time.Second,
	}
	deadline := lastReceived.Add(35 * time.Second)
	tests := []struct {
		name     string
		now      time.Time
		received *time.Time
		eligible bool
	}{
		{name: "immediately before deadline", now: deadline.Add(-time.Nanosecond), received: &lastReceived, eligible: true},
		{name: "exact deadline", now: deadline, received: &lastReceived},
		{name: "after deadline", now: deadline.Add(time.Nanosecond), received: &lastReceived},
		{name: "missing receipt timestamp", now: lastReceived, received: nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			endpoint := testEndpoint("192.0.2.82", 443, 0, 1)
			endpoint.Health = HealthState{Status: HealthHealthy, LastReceivedAt: test.received}
			plan, err := BuildPlan(LineGroupRevision{
				TenantScopeID: uuid.New(), GroupID: uuid.New(), Revision: 1,
				Policy: policy, Endpoints: []Endpoint{endpoint},
			}, Selector{}, test.now)
			if test.eligible {
				if err != nil || len(plan.Candidates) != 1 || plan.Candidates[0].ID != endpoint.ID {
					t.Fatalf("eligible plan=%#v err=%v", plan, err)
				}
				return
			}
			if !errors.Is(err, ErrNoHealthyEndpoint) {
				t.Fatalf("ineligible error=%v, want %v", err, ErrNoHealthyEndpoint)
			}
		})
	}
}

func TestHealthStateSubsequentRecoveryHonorsThresholdAndDebounce(t *testing.T) {
	base := time.Date(2026, 7, 29, 5, 0, 0, 0, time.UTC)
	policy := HealthPolicy{
		ProbeInterval: 10 * time.Second, ProbeTimeout: 3 * time.Second,
		FailureThreshold: 2, RecoveryThreshold: 2,
		FailureDebounce: 15 * time.Second, RecoveryDebounce: 15 * time.Second,
	}
	state := HealthState{Status: HealthUnknown, LastChangedAt: base, RowRevision: 1}
	probe := func(sequence int64, offset time.Duration, healthy bool) bool {
		var transitioned bool
		state, transitioned = nextHealthState(state, policy, ProbeRequest{
			Sequence: sequence, ObservedAt: base.Add(offset), Healthy: healthy,
		}, base.Add(offset))
		return transitioned
	}
	if probe(1, 0, true) || probe(2, 10*time.Second, true) || !probe(3, 15*time.Second, true) || state.Status != HealthHealthy {
		t.Fatalf("initial recovery state=%#v", state)
	}
	if probe(4, 20*time.Second, false) || probe(5, 30*time.Second, false) || !probe(6, 35*time.Second, false) || state.Status != HealthUnhealthy {
		t.Fatalf("failure state=%#v", state)
	}
	if probe(7, 40*time.Second, true) || probe(8, 50*time.Second, true) || !probe(9, 55*time.Second, true) || state.Status != HealthHealthy {
		t.Fatalf("subsequent recovery state=%#v", state)
	}
}

func TestHealthStateThresholdsDebounceAndRecovery(t *testing.T) {
	base := time.Date(2026, 7, 22, 8, 0, 0, 0, time.UTC)
	policy := HealthPolicy{
		ProbeInterval: 10 * time.Second, ProbeTimeout: 3 * time.Second,
		FailureThreshold: 2, RecoveryThreshold: 2,
		FailureDebounce: 15 * time.Second, RecoveryDebounce: 15 * time.Second,
	}
	state := HealthState{Status: HealthUnknown, LastChangedAt: base, RowRevision: 1, CreatedAt: base, UpdatedAt: base}
	probe := func(sequence int64, offset time.Duration, healthy bool) bool {
		var transitioned bool
		state, transitioned = nextHealthState(state, policy, ProbeRequest{
			Sequence: sequence, ObservedAt: base.Add(offset), Healthy: healthy,
		}, base.Add(offset))
		return transitioned
	}
	if probe(1, 10*time.Second, true) || probe(2, 20*time.Second, true) || !probe(3, 30*time.Second, true) || state.Status != HealthHealthy {
		t.Fatalf("recovery state = %#v", state)
	}
	if probe(4, 40*time.Second, false) || probe(5, 50*time.Second, false) || !probe(6, 60*time.Second, false) || state.Status != HealthUnhealthy {
		t.Fatalf("failure state = %#v", state)
	}
	if defaults := DefaultHealthPolicy(); defaults.ProbeInterval != 10*time.Second ||
		defaults.FailureThreshold != 3 || defaults.RecoveryThreshold != 3 {
		t.Fatalf("default policy = %#v", defaults)
	}
}

func testEndpoint(address string, port, priority, weight int) Endpoint {
	return Endpoint{
		ID: uuid.New(), Address: address, Port: port, Priority: priority, Weight: weight, Enabled: true,
	}
}
