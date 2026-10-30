package errorpagecontrol

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/jackc/pgx/v5"
)

func TestErrorPageSlotsPostgreSQL(t *testing.T) {
	fixture := openErrorPageDatabase(t)
	identities := seedErrorPageIdentities(t, fixture.pool)
	store := newMemoryContentStore()
	service, err := NewServiceWithDependencies(
		fixture.pool,
		store,
		&testScanner{name: "slot-scanner"},
		staticLimits{quota: AssetQuota{MaxAssetBytes: MaxEdgeResourceBytes, MaxAssets: 100, MaxTotalBytes: 8 << 20}},
		audit.New(fixture.pool),
		time.Now,
		testTxAuthorizer{},
	)
	if err != nil {
		t.Fatal(err)
	}

	page, err := service.ListSlots(t.Context(), identities.platform)
	if err != nil || len(page.Items) != len(ErrorPageSlotKeys) {
		t.Fatalf("initial slots=%#v err=%v", page, err)
	}
	for index, key := range ErrorPageSlotKeys {
		if page.Items[index].Key != key || page.Items[index].Revision != 0 || page.Items[index].AssetID != nil {
			t.Fatalf("slot[%d]=%#v want key=%s unbound", index, page.Items[index], key)
		}
	}

	body := []byte(`<!doctype html><html><body><h1>访问受限</h1></body></html>`)
	asset := readyAsset(t, service, identities.platform, identities.platformScope,
		"slot-blacklist", body, "text/html")
	bindRequest := BindSlotRequest{
		Key: SlotBlacklist, AssetID: asset.ID, ExpectedRevision: 0,
		WriteMetadata: writeMetadata("slot-bind"),
	}
	bound, err := service.BindSlot(t.Context(), identities.platform, bindRequest)
	if err != nil || bound.Replayed || bound.Value.Revision != 1 || bound.Value.AssetID == nil ||
		*bound.Value.AssetID != asset.ID || bound.Value.MIMEType != "text/html" || bound.Value.SHA256 != asset.SHA256 {
		t.Fatalf("bound=%#v err=%v", bound, err)
	}

	document, err := service.GetSlot(t.Context(), identities.platform, SlotBlacklist)
	if err != nil || document.Content != string(body) || document.Binding.Revision != 1 || document.Source != "override" ||
		// blacklist 是节点自出页槽位（c8b389a91 slotOwnPages）：未绑定时节点用内置回答（delivery=fallback），
		// 绑定会到达节点，因此追加发布修订（Publication 非空）
		document.Delivery != SlotDeliveryFallback || bound.Value.Publication == nil {
		t.Fatalf("document=%#v err=%v", document, err)
	}
	replay, err := service.BindSlot(t.Context(), identities.platform, bindRequest)
	if err != nil || !replay.Replayed || replay.Value.Revision != 1 {
		t.Fatalf("bind replay=%#v err=%v", replay, err)
	}

	stale := bindRequest
	stale.WriteMetadata = writeMetadata("slot-bind-stale")
	if _, err := service.BindSlot(t.Context(), identities.platform, stale); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale bind error=%v", err)
	}
	if _, err := service.DeleteAsset(t.Context(), identities.platform, DeleteAssetRequest{
		AssetID: asset.ID, ExpectedRevision: asset.Revision,
		WriteMetadata: writeMetadata("slot-bound-delete"),
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("bound asset delete error=%v, want conflict", err)
	}

	if _, err := service.ListSlots(t.Context(), identities.tenantOwner); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("tenant list error=%v", err)
	}
	if _, err := service.GetSlot(t.Context(), identities.tenantOwner, SlotBlacklist); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("tenant get error=%v", err)
	}
	if _, err := service.BindSlot(t.Context(), identities.tenantOwner, bindRequest); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("tenant bind error=%v", err)
	}

	var auditPayload string
	if err := fixture.pool.QueryRow(t.Context(), `SELECT payload::text FROM audit_events
		WHERE scope_id=$1 AND action='error_page.slot.bind' ORDER BY stream_position DESC LIMIT 1`,
		identities.platformScope).Scan(&auditPayload); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(auditPayload, `"slot_key": "blacklist"`) || strings.Contains(auditPayload, "访问受限") ||
		strings.Contains(auditPayload, "<!doctype") {
		t.Fatalf("unexpected slot audit payload=%s", auditPayload)
	}

	unbound, err := service.UnbindSlot(t.Context(), identities.platform, UnbindSlotRequest{
		Key: SlotBlacklist, ExpectedRevision: 1, WriteMetadata: writeMetadata("slot-unbind"),
	})
	if err != nil || unbound.Value.Revision != 2 || unbound.Value.AssetID != nil {
		t.Fatalf("unbound=%#v err=%v", unbound, err)
	}
	document, err = service.GetSlot(t.Context(), identities.platform, SlotBlacklist)
	// An unbound slot shows the built-in page in effect.
	if err != nil || document.Source != "builtin" || !strings.Contains(document.Content, "黑名单") ||
		document.Binding.Revision != 2 || document.Binding.AssetID != nil {
		t.Fatalf("unbound document=%#v err=%v", document, err)
	}
}

type countingSlotRepublisher struct{ calls int }

func (republisher *countingSlotRepublisher) QueueSlotRepublicationTx(context.Context, pgx.Tx) (int, error) {
	republisher.calls++
	return 0, nil
}

// 待出包前全量跑: binding a slot a node page reads
// appends a publication revision pinning it and queues the republication;
// unbinding pins none again.
func TestErrorPageSlotBindPublishesPostgreSQL(t *testing.T) {
	fixture := openErrorPageDatabase(t)
	identities := seedErrorPageIdentities(t, fixture.pool)
	republisher := &countingSlotRepublisher{}
	service, err := NewServiceWithDependencies(fixture.pool, newMemoryContentStore(), &testScanner{name: "slot-scanner"},
		staticLimits{quota: AssetQuota{MaxAssetBytes: MaxEdgeResourceBytes, MaxAssets: 100, MaxTotalBytes: 8 << 20}},
		audit.New(fixture.pool), time.Now, testTxAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.WithSlotRepublisher(republisher); err != nil {
		t.Fatal(err)
	}
	builtin, err := service.GetSlot(t.Context(), identities.platform, SlotHTTP502)
	if err != nil || builtin.Source != "builtin" || !strings.Contains(builtin.Content, "502") || builtin.Delivery == "" {
		t.Fatalf("builtin=%#v err=%v", builtin, err)
	}
	body := []byte(`<!doctype html><html><head><title>502</title></head><body><h1>源站维护中</h1></body></html>`)
	asset := readyAsset(t, service, identities.platform, identities.platformScope, "slot-502", body, "text/html")
	bound, err := service.BindSlot(t.Context(), identities.platform, BindSlotRequest{
		Key: SlotHTTP502, AssetID: asset.ID, WriteMetadata: writeMetadata("slot-502-bind"),
	})
	if err != nil || bound.Value.Publication == nil || bound.Value.Publication.Revision < 1 || republisher.calls != 1 {
		t.Fatalf("bound=%#v calls=%d err=%v", bound, republisher.calls, err)
	}
	snapshot, err := service.PublicationSnapshot(t.Context(), identities.platform)
	if err != nil || len(snapshot.Policy.Slots) != 1 || snapshot.Policy.Slots[0].Key != SlotHTTP502 ||
		snapshot.Policy.Slots[0].Category != CategoryEdgeConnect || snapshot.Policy.Slots[0].Status != 502 ||
		snapshot.Policy.Slots[0].Resource.SHA256 != asset.SHA256 {
		t.Fatalf("snapshot=%#v err=%v", snapshot.Policy, err)
	}
	if _, err := service.UnbindSlot(t.Context(), identities.platform, UnbindSlotRequest{
		Key: SlotHTTP502, ExpectedRevision: 1, WriteMetadata: writeMetadata("slot-502-unbind"),
	}); err != nil || republisher.calls != 2 {
		t.Fatalf("unbind calls=%d err=%v", republisher.calls, err)
	}
	if snapshot, err = service.PublicationSnapshot(t.Context(), identities.platform); err != nil || len(snapshot.Policy.Slots) != 0 {
		t.Fatalf("snapshot after unbind=%#v err=%v", snapshot.Policy, err)
	}
}

func TestErrorPageSlotConcurrentInitialBindReturnsRevisionConflict(t *testing.T) {
	fixture := openErrorPageDatabase(t)
	identities := seedErrorPageIdentities(t, fixture.pool)
	store := newMemoryContentStore()
	baseService, err := NewServiceWithDependencies(
		fixture.pool,
		store,
		&testScanner{name: "slot-race-scanner"},
		staticLimits{quota: AssetQuota{MaxAssetBytes: MaxEdgeResourceBytes, MaxAssets: 100, MaxTotalBytes: 8 << 20}},
		audit.New(fixture.pool),
		time.Now,
		testTxAuthorizer{},
	)
	if err != nil {
		t.Fatal(err)
	}
	asset := readyAsset(t, baseService, identities.platform, identities.platformScope,
		"slot-race-asset", []byte(`<!doctype html><title>race</title>`), "text/html")

	if _, err := fixture.pool.Exec(t.Context(), `CREATE FUNCTION delay_error_page_slot_insert_test()
		RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			PERFORM pg_sleep(0.25);
			RETURN NEW;
		END;
		$$;
		CREATE TRIGGER a_delay_error_page_slot_insert_test
		BEFORE INSERT ON error_page_slots
		FOR EACH ROW EXECUTE FUNCTION delay_error_page_slot_insert_test()`); err != nil {
		t.Fatal(err)
	}

	authorized := make(chan struct{}, 2)
	release := make(chan struct{})
	racingAuthorizer := testTxAuthorizer{hooks: &testAuthorizationHooks{
		authorized: authorized,
		release:    release,
	}}
	raceService, err := NewServiceWithDependencies(
		fixture.pool,
		store,
		&testScanner{name: "slot-race-scanner"},
		staticLimits{quota: AssetQuota{MaxAssetBytes: MaxEdgeResourceBytes, MaxAssets: 100, MaxTotalBytes: 8 << 20}},
		audit.New(fixture.pool),
		time.Now,
		racingAuthorizer,
	)
	if err != nil {
		t.Fatal(err)
	}

	results := make(chan error, 2)
	var started sync.WaitGroup
	started.Add(2)
	for contender := 0; contender < 2; contender++ {
		contender := contender
		go func() {
			started.Done()
			_, err := raceService.BindSlot(t.Context(), identities.platform, BindSlotRequest{
				Key: SlotHTTP403, AssetID: asset.ID, ExpectedRevision: 0,
				WriteMetadata: writeMetadata("slot-initial-race-" + string(rune('a'+contender))),
			})
			results <- err
		}()
	}
	started.Wait()
	<-authorized
	<-authorized
	close(release)

	successes, conflicts := 0, 0
	for range 2 {
		err := <-results
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrRevisionConflict):
			conflicts++
		default:
			t.Fatalf("unexpected initial slot race error=%v state=%s", err, sqlState(err))
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("successes=%d revision_conflicts=%d", successes, conflicts)
	}
}

func TestErrorPageSlotMigration218RoundTrip(t *testing.T) {
	fixture := openErrorPageDatabaseThrough(t, 217)
	if err := execMigration(t.Context(), fixture.pool, "218_error_page_slots.up.sql"); err != nil {
		t.Fatal(err)
	}
	assertSlotTables(t, fixture, true)
	if err := execMigration(t.Context(), fixture.pool, "218_error_page_slots.down.sql"); err != nil {
		t.Fatal(err)
	}
	assertSlotTables(t, fixture, false)
	if err := execMigration(t.Context(), fixture.pool, "218_error_page_slots.up.sql"); err != nil {
		t.Fatal(err)
	}
	assertSlotTables(t, fixture, true)
}

func assertSlotTables(t *testing.T, fixture integrationFixture, expected bool) {
	t.Helper()
	for _, table := range []string{"error_page_slots", "error_page_slot_revisions"} {
		var exists bool
		if err := fixture.pool.QueryRow(t.Context(), `SELECT to_regclass($1) IS NOT NULL`, table).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if exists != expected {
			t.Fatalf("table %s exists=%t, want %t", table, exists, expected)
		}
	}
}
