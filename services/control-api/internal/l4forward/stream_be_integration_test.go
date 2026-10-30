package l4forward

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func streamBeTemplate(subscription uuid.UUID) Fields {
	return Fields{PackageSubscriptionID: new(subscription), Remark: "batch", ListenAddress: "*",
		ConnectTimeoutMS: 1000, ResponseTimeoutMS: 30000, MaxConnectionsPerClient: 100, Enabled: true}
}

// 批量添加 (migration 490): without 忽略错误 one failed line writes nothing
// (422, per-line result); with it the failed line is skipped and the rest are
// committed; the idempotency key covers the batch (an exact replay returns
// the stored result, other input conflicts).
func TestStreamBatchCreateAtomicIgnoreErrorsAndReplay(t *testing.T) {
	fixture := newStreamAddonFixture(t)
	service, actor := NewService(NewStore(fixture.pool)), fixture.actor
	subscription := fixture.subscription(t, actor.UserID, -1)
	template := streamBeTemplate(subscription)
	count := func() int {
		var total int
		if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM l4_forwards WHERE deleted_at IS NULL`).Scan(&total); err != nil {
			t.Fatal(err)
		}
		return total
	}
	lines := []string{"24001 24002/udp|192.0.2.10|8080", "24003|not a host!|80", "24004|192.0.2.11|80"}

	atomic := uuid.NewString()
	result, err := service.BatchCreate(t.Context(), actor, BatchCreateRequest{Template: template, Lines: lines,
		IdempotencyKey: atomic, RequestID: atomic})
	if !errors.Is(err, ErrBatchFailed) || result.Committed || result.Created != 0 || count() != 0 ||
		result.Items[0].Status != BatchLineSkipped || result.Items[1].Status != BatchLineFailed ||
		result.Items[1].Error.Code != "validation_error" || result.Items[2].Status != BatchLineSkipped {
		t.Fatalf("atomic batch = %+v, %v (rows %d)", result, err, count())
	}

	key := uuid.NewString()
	request := BatchCreateRequest{Template: template, Lines: lines, IgnoreErrors: true, IdempotencyKey: key, RequestID: key}
	result, err = service.BatchCreate(t.Context(), actor, request)
	if err != nil || !result.Committed || result.Created != 2 || result.Failed != 1 || count() != 2 ||
		result.Items[0].Status != BatchLineCreated || result.Items[1].Status != BatchLineFailed || result.Items[2].Status != BatchLineCreated {
		t.Fatalf("ignore-errors batch = %+v, %v (rows %d)", result, err, count())
	}
	first := result.Items[0].Stream
	if first == nil || first.ListenPort != 24001 || len(first.AdditionalListeners) != 1 || first.AdditionalListeners[0].Protocol != ProtocolUDP ||
		first.UpstreamAddress != "192.0.2.10" || first.UpstreamPort != 8080 || first.Remark != "batch" || first.Name != "TCP 24001" {
		t.Fatalf("first line stream = %+v", first)
	}
	replay, err := service.BatchCreate(t.Context(), actor, request)
	if err != nil || !replay.Replayed || replay.Created != 2 || count() != 2 || replay.Items[0].Stream.ID != first.ID {
		t.Fatalf("replay = %+v, %v", replay, err)
	}
	other := request
	other.Lines = lines[:1]
	if _, err := service.BatchCreate(t.Context(), actor, other); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed batch under the same key = %v", err)
	}
	// A line conflicting with an existing stream's port fails on its own.
	conflict := uuid.NewString()
	result, err = service.BatchCreate(t.Context(), actor, BatchCreateRequest{Template: template, IgnoreErrors: true,
		Lines: []string{"24004|192.0.2.12|80", "24005|192.0.2.12|80"}, IdempotencyKey: conflict, RequestID: conflict})
	if err != nil || result.Items[0].Error == nil || result.Items[0].Error.Code != "stream_port_conflict" || result.Created != 1 {
		t.Fatalf("port conflict line = %+v, %v", result, err)
	}
}

// 源站列表 / ACL / IPv6 persist, read back and reach the intent; 设置状态
// applies per item with its own revision and takes a stream off the nodes;
// the list filters on admin_status and sync_state and returns the line.
func TestStreamOriginsACLStatusAndListFilters(t *testing.T) {
	fixture := newStreamAddonFixture(t)
	service, actor := NewService(NewStore(fixture.pool)), fixture.actor
	subscription := fixture.subscription(t, actor.UserID, -1)
	fields := streamBeTemplate(subscription)
	fields.Name, fields.Protocol, fields.ListenPort, fields.UpstreamPort, fields.BalanceWay = "pool", ProtocolTCP, 24100, 9000, BalanceWayIPHash
	fields.Origins = []Origin{{Address: "192.0.2.20", Weight: 3}, {Address: "192.0.2.21", Weight: 1, Down: true}}
	fields.ListenIPv6 = true
	fields.ACL = &ACL{DefaultAction: ACLActionDeny, Rules: []ACLRule{{CIDR: "198.51.100.0/24", Action: ACLActionAllow}}}
	key := uuid.NewString()
	created, err := service.Create(t.Context(), actor, CreateRequest{Fields: fields, IdempotencyKey: key, RequestID: key})
	if err != nil {
		t.Fatal(err)
	}
	spec := created.Forward.PublishIntent.RuntimeSpec
	if len(spec.Endpoint.Origins) != 2 || spec.Endpoint.Balance != "ip_hash" || !spec.ListenIPv6 || len(spec.GuardRules) != 2 ||
		spec.GuardRules[0].Action != "allow" || spec.GuardRules[1].Action != "drop" {
		t.Fatalf("intent = %s", mustJSON(t, spec))
	}
	got, err := service.Get(t.Context(), actor, created.Forward.ID)
	if err != nil || len(got.Origins) != 2 || got.Origins[0].Weight != 3 || !got.Origins[1].Down || !got.ListenIPv6 ||
		got.ACL.DefaultAction != ACLActionDeny || len(got.ACL.Rules) != 1 || got.AdminStatus != AdminStatusNormal {
		t.Fatalf("read back = %+v, %v", got, err)
	}
	encoded, _ := json.Marshal(got)
	var wire map[string]any
	_ = json.Unmarshal(encoded, &wire)
	if wire["sync_state"] != SyncStatePending || wire["line"] == nil {
		t.Fatalf("wire sync_state/line = %v %v", wire["sync_state"], wire["line"])
	}
	// A single-origin stream reads its one origin as a list.
	plain := streamBeTemplate(subscription)
	plain.Name, plain.Protocol, plain.ListenPort, plain.UpstreamAddress, plain.UpstreamPort = "plain", ProtocolTCP, 24101, "192.0.2.30", 80
	key = uuid.NewString()
	single, err := service.Create(t.Context(), actor, CreateRequest{Fields: plain, IdempotencyKey: key, RequestID: key})
	if err != nil || len(single.Forward.Origins) != 1 || single.Forward.Origins[0] != (Origin{Address: "192.0.2.30", Weight: 1}) {
		t.Fatalf("single origin = %+v, %v", single.Forward.Origins, err)
	}

	platform := Actor{UserID: fixture.admin.UserID, ScopeID: fixture.admin.ScopeID, ScopeKind: "platform"}
	key = uuid.NewString()
	batch, err := service.BatchAction(t.Context(), platform, BatchActionRequest{Action: BatchActionSetStatus, AdminStatus: AdminStatusLocked,
		Items: []BatchActionItem{{ID: created.Forward.ID, ExpectedRevision: created.Forward.Revision},
			{ID: single.Forward.ID, ExpectedRevision: single.Forward.Revision + 5}, {ID: uuid.New(), ExpectedRevision: 1}},
		IdempotencyKey: key, RequestID: key})
	if err != nil || batch.Items[0].Status != BatchItemUpdated || batch.Items[0].Stream.AdminStatus != AdminStatusLocked ||
		batch.Items[0].Stream.PublishIntent.DesiredState != "disabled" ||
		batch.Items[1].Error == nil || batch.Items[1].Error.Code != "version_conflict" ||
		batch.Items[2].Error == nil || batch.Items[2].Error.Code != "stream_not_found" {
		t.Fatalf("batch action = %s, %v", mustJSON(t, batch), err)
	}
	if _, err := service.BatchAction(t.Context(), actor, BatchActionRequest{Action: BatchActionSetStatus, AdminStatus: AdminStatusLocked,
		Items: []BatchActionItem{{ID: single.Forward.ID, ExpectedRevision: 1}}, IdempotencyKey: key, RequestID: key}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("tenant batch action = %v", err)
	}

	list := func(filter ListFilter) []uuid.UUID {
		filter.Page, filter.Limit = 1, 100
		result, err := service.List(t.Context(), actor, filter)
		if err != nil {
			t.Fatal(err)
		}
		ids := make([]uuid.UUID, len(result.Items))
		for index, item := range result.Items {
			ids[index] = item.ID
		}
		return ids
	}
	// L4-FILTER-01: 源站地址 matches the primary, the second (down) origin of
	// the pool, once per forward; a single-origin forward still matches.
	for upstream, want := range map[string][]uuid.UUID{
		"192.0.2.20": {created.Forward.ID}, "192.0.2.21": {created.Forward.ID}, "192.0.2.30": {single.Forward.ID},
		"192.0.2.99": {},
	} {
		if ids := list(ListFilter{Upstream: upstream}); len(ids) != len(want) || len(want) == 1 && ids[0] != want[0] {
			t.Fatalf("upstream=%s -> %v, want %v", upstream, ids, want)
		}
	}
	if ids := list(ListFilter{AdminStatus: AdminStatusLocked}); len(ids) != 1 || ids[0] != created.Forward.ID {
		t.Fatalf("admin_status=locked -> %v", ids)
	}
	if ids := list(ListFilter{SyncState: SyncStatePending}); len(ids) != 2 {
		t.Fatalf("sync_state=pending -> %v", ids)
	}
	if ids := list(ListFilter{SyncState: SyncStateDone}); len(ids) != 0 {
		t.Fatalf("sync_state=done -> %v", ids)
	}
	group := uuid.New()
	if _, err := service.List(t.Context(), actor, ListFilter{Page: 1, Limit: 10, NodeGroupID: &group}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("tenant node_group filter = %v", err)
	}
	result, err := service.List(t.Context(), platform, ListFilter{Page: 1, Limit: 10, NodeGroupID: &group})
	if err != nil || len(result.Items) != 0 {
		t.Fatalf("platform node_group filter = %+v, %v", result, err)
	}
}
