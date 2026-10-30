package l4forward

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/cnameallocation"
	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsreconcile"
	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/google/uuid"
)

type streamCNAMEKeyring struct{}

func (streamCNAMEKeyring) Active(context.Context) (cnameallocation.Key, error) {
	return cnameallocation.Key{ID: "stream-cname-key", Secret: []byte("0123456789abcdef0123456789abcdef")}, nil
}
func (keyring streamCNAMEKeyring) Lookup(ctx context.Context, _ string) (cnameallocation.Key, error) {
	return keyring.Active(ctx)
}

// streamCNAMEReconcile stands in for the DNS provider (no real provider in
// this test): Apply records the write, Get reports it read back
// (ready_to_commit), Commit settles it committed; failNext fails the next
// write's check instead.
type streamCNAMEReconcile struct {
	mu       sync.Mutex
	applied  []dnsreconcile.ApplyRequest
	commits  []dnsreconcile.CommitRequest
	tasks    map[uuid.UUID]dnsreconcile.Task
	failNext bool
}

func (fake *streamCNAMEReconcile) Apply(_ context.Context, request dnsreconcile.ApplyRequest) (dnsreconcile.Task, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	task := dnsreconcile.Task{ID: uuid.New(), TenantID: request.TenantID, SiteID: request.SiteID, Revision: 1}
	task.Result.Status = dnscheck.TaskReadyToCommit
	if fake.failNext {
		task.Result.Status, fake.failNext = dnscheck.TaskFailed, false
	}
	fake.applied = append(fake.applied, request)
	fake.tasks[task.ID] = task
	return task, nil
}
func (fake *streamCNAMEReconcile) Get(_ context.Context, _ uuid.UUID, id uuid.UUID) (dnsreconcile.Task, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	return fake.tasks[id], nil
}
func (fake *streamCNAMEReconcile) Commit(_ context.Context, request dnsreconcile.CommitRequest) (dnsreconcile.Task, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	task := fake.tasks[request.TaskID]
	task.Result.Status, task.Revision = dnscheck.TaskCommitted, task.Revision+1
	fake.tasks[task.ID] = task
	fake.commits = append(fake.commits, request)
	return task, nil
}

// streamCNAMECleaner records the retired owners the worker deletes.
type streamCNAMECleaner struct {
	owners []cnameallocation.RetiredOwner
}

func (cleaner *streamCNAMECleaner) CleanRetiredOwner(_ context.Context, owner cnameallocation.RetiredOwner) (int, int, error) {
	cleaner.owners = append(cleaner.owners, owner)
	return len(owner.A) + len(owner.AAAA), 0, nil
}

// 四层转发自有 CNAME (migration 505): 修改CNAME域名 gives the stream its own
// hostname, written to DNS (read back, committed) on the stream's line;
// changing the stream's line retargets it, regenerate retries a failure,
// clearing the override and deleting the stream retire the hostname, and
// concurrent intents for one stream allocate once.
func TestStreamOwnCNAMEAllocateRetargetRetire(t *testing.T) {
	fixture := newStreamAddonFixture(t)
	pool, ctx := fixture.pool, t.Context()
	service, actor := NewService(NewStore(pool)), fixture.actor
	platform := Actor{UserID: fixture.admin.UserID, ScopeID: fixture.admin.ScopeID, ScopeKind: "platform"}
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, query, args...); err != nil {
			t.Fatalf("%.80s: %v", query, err)
		}
	}
	packageGroup, _ := streamBe2LineGroup(t, pool, platform.ScopeID, platform.UserID, "192.0.2.61")
	streamGroup, _ := streamBe2LineGroup(t, pool, platform.ScopeID, platform.UserID, "192.0.2.62")
	exec(`INSERT INTO platform_system_other_settings(platform_scope_id,revision,settings,updated_at)
		VALUES($1,1,'{"dns_config":{"zones":[{"name":"edge.example"},{"name":"stream.example"}]}}',now())`, platform.ScopeID)
	exec(`INSERT INTO role_permissions(role_id,permission_name) SELECT role_id,'platform.admin' FROM role_assignments
		WHERE scope_id=$1 AND user_id=$2`, platform.ScopeID, platform.UserID)
	// The tenant's DNS provider with the default zone and the stream zone.
	providerID := uuid.New()
	exec(`INSERT INTO dns_providers(id,scope_id,name,provider_type,credential_key_id,credential_ciphertext,created_by_user_id,updated_by_user_id)
		VALUES($1,$2,'stream-cname','cloudflare','fixture-key',$3,$4,$4)`, providerID, actor.ScopeID, make([]byte, 32), actor.UserID)
	for _, zone := range []struct {
		name     string
		fallback bool
	}{{"edge.example", true}, {"stream.example", false}} {
		exec(`INSERT INTO dns_zones(id,scope_id,provider_id,name,is_default,created_by_user_id,updated_by_user_id)
			VALUES($1,$2,$3,$4,$5,$6,$6)`, uuid.New(), actor.ScopeID, providerID, zone.name, zone.fallback, actor.UserID)
	}
	subscription := fixture.subscriptionOnLine(t, actor.UserID, -1, packageGroup)
	// No website (migration 506): the tenant's only site is deleted, and the
	// stream's CNAME is still allocated, written and retired, anchored at the
	// stream (migration 507).
	exec(`UPDATE sites SET deleted_at=now() WHERE id=$1`, fixture.siteID)
	var tenantID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT tenant_id FROM access_scopes WHERE id=$1`, actor.ScopeID).Scan(&tenantID); err != nil {
		t.Fatal(err)
	}

	clock := time.Now().UTC().Truncate(time.Second)
	now := func() time.Time { return clock }
	jobs, err := jobstate.NewStore(pool, now)
	if err != nil {
		t.Fatal(err)
	}
	cname, err := cnameallocation.NewStore(pool, streamCNAMEKeyring{}, now)
	if err != nil {
		t.Fatal(err)
	}
	reconcile := &streamCNAMEReconcile{tasks: map[uuid.UUID]dnsreconcile.Task{}}
	cleaner := &streamCNAMECleaner{}
	worker, err := cnameallocation.NewWorker(cnameallocation.WorkerConfig{WorkerID: "stream-cname", LeaseDuration: time.Minute, Now: now},
		cnameallocation.WorkerDependencies{Tenants: cname, Intents: cname, StreamIntents: cname, Claims: jobs, Targets: cname,
			Reconcile: reconcile, Retargets: cname, Retirements: cname, RetiredOwners: cleaner})
	if err != nil {
		t.Fatal(err)
	}
	// drain runs the worker until no CNAME job is claimable, advancing the
	// clock past each yield (2 s polls).
	drain := func() {
		t.Helper()
		for round := 0; round < 20; round++ {
			didWork, err := worker.RunOnce(ctx, tenantID)
			if err != nil && !errors.Is(err, cnameallocation.ErrConflict) {
				t.Fatalf("worker round %d: %v", round, err)
			}
			if !didWork {
				clock = clock.Add(3 * time.Second)
				didWork, err = worker.RunOnce(ctx, tenantID)
				if err != nil && !errors.Is(err, cnameallocation.ErrConflict) {
					t.Fatalf("worker round %d after yield: %v", round, err)
				}
				if !didWork {
					return
				}
			}
		}
		t.Fatal("CNAME jobs did not settle")
	}
	create := func(port uint16) Forward {
		t.Helper()
		fields := streamBeTemplate(subscription)
		fields.Name, fields.Protocol, fields.ListenPort, fields.UpstreamAddress, fields.UpstreamPort =
			fmt.Sprintf("cname-%d", port), ProtocolTCP, port, "192.0.2.90", 80
		key := uuid.NewString()
		created, err := service.Create(ctx, actor, CreateRequest{Fields: fields, IdempotencyKey: key, RequestID: key})
		if err != nil {
			t.Fatal(err)
		}
		return created.Forward
	}
	get := func(id uuid.UUID) Forward {
		t.Helper()
		item, err := service.Get(ctx, platform, id)
		if err != nil {
			t.Fatal(err)
		}
		return item
	}
	batch := func(request BatchActionRequest, items ...Forward) BatchActionResult {
		t.Helper()
		key := uuid.NewString()
		request.IdempotencyKey, request.RequestID = key, key
		for _, item := range items {
			request.Items = append(request.Items, BatchActionItem{ID: item.ID, ExpectedRevision: get(item.ID).Revision})
		}
		result, err := service.BatchAction(ctx, platform, request)
		if err != nil {
			t.Fatalf("%s batch: %v", request.Action, err)
		}
		return result
	}
	value := func(pointer *string) string {
		if pointer == nil {
			return ""
		}
		return *pointer
	}
	own := func(stream Forward) cnameallocation.Allocation {
		t.Helper()
		allocation, err := cname.GetStream(ctx, actor.ScopeID, stream.ID)
		if err != nil {
			t.Fatalf("stream allocation: %v", err)
		}
		return allocation
	}
	frozenA := func(allocation cnameallocation.Allocation) []string {
		t.Helper()
		var addresses []string
		if err := pool.QueryRow(ctx, `SELECT target_a FROM cname_allocation_targets WHERE job_id=$1 AND stream_id IS NOT NULL`,
			allocation.JobID).Scan(&addresses); err != nil {
			t.Fatal(err)
		}
		return addresses
	}

	first, second := create(24301), create(24302)
	if item := get(first.ID); value(item.CNAMEState) != "" && item.CNAME != nil {
		t.Fatalf("no override yet: %+v", item)
	}

	// 1. 修改CNAME域名 → pending, then the worker allocates, writes, reads back
	// (ready_to_commit) and commits: done with the stream's own hostname.
	domain := "stream.example"
	result := batch(BatchActionRequest{Action: BatchActionCNAMEDomain, CNAMEDomain: &domain}, first)
	if result.Items[0].Status != BatchItemUpdated {
		t.Fatalf("cname_domain batch = %s", mustJSON(t, result))
	}
	if item := get(first.ID); value(item.CNAMEState) != "pending" || item.CNAME != nil || value(item.CNAMEDomain) != domain {
		t.Fatalf("queued stream CNAME = state %q cname %v domain %q", value(item.CNAMEState), item.CNAME, value(item.CNAMEDomain))
	}
	drain()
	allocated := own(first)
	item := get(first.ID)
	if allocated.State != cnameallocation.StateDone || value(item.CNAMEState) != "done" || value(item.CNAME) != allocated.Hostname ||
		!slices.Contains([]string{allocated.Hostname}, value(item.CNAME)) || len(allocated.Hostname) <= len(domain) ||
		allocated.Hostname[len(allocated.Hostname)-len(domain)-1:] != "."+domain || allocated.SiteID != uuid.Nil {
		t.Fatalf("allocated stream CNAME = %+v, list %q/%q", allocated, value(item.CNAME), value(item.CNAMEState))
	}
	if siteCNAME := get(second.ID).CNAME; siteCNAME != nil && *siteCNAME == allocated.Hostname {
		t.Fatal("a stream without override must not show another stream's hostname")
	}
	// The DNS task's anchor is the stream (dnsreconcile SiteID = anchor ID).
	if len(reconcile.applied) != 1 || reconcile.applied[0].SiteID != first.ID || len(reconcile.commits) != 1 ||
		strings.TrimSuffix(reconcile.applied[0].Check.Name, ".") != allocated.Hostname {
		t.Fatalf("DNS writes = %+v commits = %d", reconcile.applied, len(reconcile.commits))
	}
	// The stream's line is the package's (no stream line override yet).
	if addresses := frozenA(allocated); !slices.Equal(addresses, []string{"192.0.2.61"}) {
		t.Fatalf("frozen target = %v, want the package's line group", addresses)
	}
	var factSites int
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM cname_allocation_targets WHERE allocation_id=$1 AND site_id IS NOT NULL)+
		(SELECT count(*) FROM cname_allocation_requests WHERE allocation_id=$1 AND site_id IS NOT NULL)`, allocated.ID).Scan(&factSites); err != nil ||
		factSites != 0 {
		t.Fatalf("stream CNAME facts anchored at a site: %d %v", factSites, err)
	}
	var requestStream *uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT stream_id FROM cname_allocation_requests WHERE allocation_id=$1 AND operation='settle'`,
		allocated.ID).Scan(&requestStream); err != nil || requestStream == nil || *requestStream != first.ID {
		t.Fatalf("settle request stream = %v %v", requestStream, err)
	}

	// 2. 修改线路分组 to the stream's own group: the retarget planner follows
	// 转发 > 套餐 and republishes the hostname on the stream's group.
	if planned, err := cname.PlanRetargets(ctx); err != nil || planned != 0 {
		t.Fatalf("retargets before line change = %d %v", planned, err)
	}
	batch(BatchActionRequest{Action: BatchActionLineGroup, NodeGroupID: &streamGroup}, first)
	if planned, err := cname.PlanRetargets(ctx); err != nil || planned != 1 {
		t.Fatalf("retargets after line change = %d %v", planned, err)
	}
	open, err := cname.OpenRetargets(ctx)
	if err != nil || len(open) != 1 || open[0].OwnerName != allocated.Hostname || !slices.Equal(open[0].Values.A, []string{"192.0.2.62"}) ||
		open[0].NodeGroupID != streamGroup || open[0].SiteID != first.ID {
		t.Fatalf("stream retarget = %+v %v", open, err)
	}
	if err := cname.AttachRetarget(ctx, open[0], dnsreconcile.Task{ID: uuid.New(), Revision: 1}); err != nil {
		t.Fatal(err)
	}
	if err := cname.SettleRetarget(ctx, open[0], "committed", ""); err != nil {
		t.Fatal(err)
	}
	if planned, err := cname.PlanRetargets(ctx); err != nil || planned != 0 {
		t.Fatalf("retargets after commit = %d %v", planned, err)
	}

	// 3. 修改CNAME生成模式: a new generation, a new hostname on the stream's
	// own group; the old one is retired after the rotation grace.
	mode := "package"
	batch(BatchActionRequest{Action: BatchActionCNAMEMode, CNAMEMode: &mode}, first)
	drain()
	rotated := own(first)
	if rotated.ID != allocated.ID || rotated.Hostname == allocated.Hostname || rotated.State != cnameallocation.StateDone ||
		rotated.Mode != cnameallocation.ModePackage || !slices.Equal(frozenA(rotated), []string{"192.0.2.62"}) {
		t.Fatalf("rotated stream CNAME = %+v (was %s)", rotated, allocated.Hostname)
	}
	var rotatedReason string
	var eligible time.Time
	if err := pool.QueryRow(ctx, `SELECT reason,eligible_at FROM cname_record_retirements WHERE allocation_id=$1 AND owner_name=$2`,
		allocated.ID, allocated.Hostname).Scan(&rotatedReason, &eligible); err != nil || rotatedReason != cnameallocation.RetireGenerationRotated ||
		!eligible.After(clock.Add(23*time.Hour)) {
		t.Fatalf("rotated owner retirement = %s %v %v", rotatedReason, eligible, err)
	}

	// 4. A failed write is shown failed with its code; 重新生成 retries it.
	other := "edge.example"
	reconcile.failNext = true
	batch(BatchActionRequest{Action: BatchActionCNAMEDomain, CNAMEDomain: &other}, first)
	drain()
	if item := get(first.ID); value(item.CNAMEState) != "failed" || value(item.CNAMEFailureCode) == "" {
		t.Fatalf("failed stream CNAME = %q code %q", value(item.CNAMEState), value(item.CNAMEFailureCode))
	}
	if retry := batch(BatchActionRequest{Action: BatchActionCNAMERegenerate}, second); retry.Items[0].Error == nil ||
		retry.Items[0].Error.Code != "stream_cname_not_overridden" {
		t.Fatalf("regenerate without override = %s", mustJSON(t, retry))
	}
	if retry := batch(BatchActionRequest{Action: BatchActionCNAMERegenerate}, first); retry.Items[0].Status != BatchItemUpdated {
		t.Fatalf("regenerate = %s", mustJSON(t, retry))
	}
	drain()
	retried := own(first)
	if item := get(first.ID); retried.State != cnameallocation.StateDone || value(item.CNAMEState) != "done" ||
		value(item.CNAME) != retried.Hostname || retried.Domain != other {
		t.Fatalf("retried stream CNAME = %+v list %q", retried, value(item.CNAMEState))
	}
	if retry := batch(BatchActionRequest{Action: BatchActionCNAMERegenerate}, first); retry.Items[0].Error == nil ||
		retry.Items[0].Error.Code != "stream_cname_not_failed" {
		t.Fatalf("regenerate of a done CNAME = %s", mustJSON(t, retry))
	}

	// 5. Concurrent intents for one stream (two batches, then workers racing):
	// one allocation, one new generation; the superseded intent is not applied.
	batch(BatchActionRequest{Action: BatchActionCNAMEDomain, CNAMEDomain: &domain}, first)
	batch(BatchActionRequest{Action: BatchActionCNAMEDomain, CNAMEDomain: &domain}, first)
	generation := func() int64 {
		var value int64
		if err := pool.QueryRow(ctx, `SELECT generation FROM cname_allocations WHERE stream_owner_id=$1`, first.ID).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	before := generation()
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, _ = worker.RunOnce(ctx, tenantID)
		}()
	}
	wait.Wait()
	drain()
	var allocations int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM cname_allocations WHERE stream_owner_id=$1`, first.ID).Scan(&allocations); err != nil ||
		allocations != 1 || generation() != before+1 || own(first).State != cnameallocation.StateDone {
		t.Fatalf("concurrent intents: allocations=%d generation %d→%d state %s %v", allocations, before, generation(), own(first).State, err)
	}

	// 6. Tenant isolation: the tenant reads its stream's hostname but cannot
	// change the CNAME; another tenant's view of the stream is not found.
	if _, err := service.BatchAction(ctx, actor, BatchActionRequest{Action: BatchActionCNAMERegenerate, IdempotencyKey: "tenant-cname",
		RequestID: "tenant-cname", Items: []BatchActionItem{{ID: first.ID, ExpectedRevision: get(first.ID).Revision}}}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("tenant CNAME batch = %v", err)
	}
	if mine, err := service.Get(ctx, actor, first.ID); err != nil || value(mine.CNAME) != own(first).Hostname {
		t.Fatalf("tenant read of own CNAME = %v %v", mine.CNAME, err)
	}
	stranger := Actor{UserID: fixture.member(t), ScopeID: actor.ScopeID, ScopeKind: "tenant"}
	if _, err := service.Get(ctx, stranger, first.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("other user's read = %v", err)
	}
	if _, err := cname.GetStream(ctx, uuid.New(), first.ID); !errors.Is(err, cnameallocation.ErrNotFound) {
		t.Fatalf("stream allocation from another scope = %v", err)
	}

	// 7. Clearing both overrides retires the hostname at once (stream_released),
	// the worker deletes its records; the list falls back to the package.
	current := own(first)
	empty := ""
	batch(BatchActionRequest{Action: BatchActionCNAMEDomain, CNAMEDomain: &empty}, first)
	batch(BatchActionRequest{Action: BatchActionCNAMEMode, CNAMEMode: &empty}, first)
	if item := get(first.ID); item.CNAME != nil && *item.CNAME == current.Hostname {
		t.Fatalf("cleared override still lists %s", current.Hostname)
	}
	if err := worker.RunRetirements(ctx); err != nil {
		t.Fatal(err)
	}
	released := map[string]bool{}
	for _, owner := range cleaner.owners {
		released[owner.Owner] = owner.Reason == cnameallocation.RetireStreamReleased
	}
	if !released[current.Hostname] {
		t.Fatalf("released owners = %+v, want %s", cleaner.owners, current.Hostname)
	}

	// 8. Deleting a stream with its own CNAME retires it (stream_deleted).
	batch(BatchActionRequest{Action: BatchActionCNAMEDomain, CNAMEDomain: &domain}, second)
	drain()
	secondHost := own(second).Hostname
	key := uuid.NewString()
	if _, err := service.Delete(ctx, actor, DeleteRequest{ID: second.ID, ExpectedRevision: get(second.ID).Revision,
		IdempotencyKey: key, RequestID: key}); err != nil {
		t.Fatal(err)
	}
	if err := worker.RunRetirements(ctx); err != nil {
		t.Fatal(err)
	}
	var reason string
	var state string
	if err := pool.QueryRow(ctx, `SELECT reason,state FROM cname_record_retirements WHERE owner_name=$1`, secondHost).Scan(&reason, &state); err != nil ||
		reason != cnameallocation.RetireStreamDeleted || state != "cleaned" {
		t.Fatalf("deleted stream retirement = %s/%s %v", reason, state, err)
	}
}
