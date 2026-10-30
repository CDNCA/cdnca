package installationban

import (
	"context"
	"errors"
	"testing"
	"time"

	contract "github.com/cdnca/cdnca/libs/entitlement/installationban"
	"github.com/cdnca/cdnca/services/control-api/internal/installationlock"
)

var testNow = time.Unix(1_900_000_000, 0).UTC()

func banned(revision uint64, until *int64) *contract.BanNotice {
	return &contract.BanNotice{BanID: "0190a000-0000-7000-8000-000000000003", Revision: revision,
		State: contract.StateBanned, ReasonCode: "abuse", ReasonText: "滥用", StartsAt: testNow.Unix(), Until: until}
}

func TestEvaluate(t *testing.T) {
	past, future := testNow.Add(-time.Minute).Unix(), testNow.Add(time.Hour).Unix()
	for name, test := range map[string]struct {
		state  State
		locked bool
		reason string
	}{
		"no lease, no notice":         {State{}, false, ""},
		"valid lease":                 {State{LeasePresent: true, LeaseStatus: "valid", LeaseGrace: testNow.Add(time.Hour)}, false, ""},
		"permanent ban":               {State{NoticeBody: banned(3, nil)}, true, installationlock.ReasonBanned},
		"ban until future":            {State{NoticeBody: banned(3, &future)}, true, installationlock.ReasonBanned},
		"ban until past, valid lease": {State{NoticeBody: banned(3, &past), LeasePresent: true, LeaseStatus: "valid"}, false, ""},
		"lifted":                      {State{NoticeBody: &contract.BanNotice{Revision: 4, State: contract.StateLifted}}, false, ""},
		"later ticket supersedes ban": {State{NoticeBody: banned(3, nil), TicketBody: &contract.ServiceTicket{Revision: 4}}, false, ""},
		"older ticket keeps ban":      {State{NoticeBody: banned(3, nil), TicketBody: &contract.ServiceTicket{Revision: 2}}, true, installationlock.ReasonBanned},
		"lease revoked":               {State{LeasePresent: true, LeaseStatus: "revoked"}, true, installationlock.ReasonLeaseRevoked},
		"lease expired":               {State{LeasePresent: true, LeaseStatus: "expired"}, true, installationlock.ReasonLeaseExpired},
		"lease past grace":            {State{LeasePresent: true, LeaseStatus: "grace", LeaseGrace: testNow}, true, installationlock.ReasonLeaseExpired},
		"lease in grace":              {State{LeasePresent: true, LeaseStatus: "grace", LeaseGrace: testNow.Add(time.Second)}, false, ""},
		"lease invalid only":          {State{LeasePresent: true, LeaseStatus: "invalid"}, false, ""},
	} {
		t.Run(name, func(t *testing.T) {
			lock := Evaluate(test.state, testNow)
			if lock.Locked != test.locked || lock.Reason != test.reason {
				t.Fatalf("lock = %+v, want locked=%v reason=%q", lock, test.locked, test.reason)
			}
		})
	}
	lock := Evaluate(State{NoticeBody: banned(3, &future)}, testNow)
	if lock.Until == nil || !lock.Until.Equal(time.Unix(future, 0)) || lock.ReasonText != "滥用" || lock.BanID == "" {
		t.Fatalf("ban lock fields = %+v", lock)
	}
}

type fakeFetcher struct {
	documents Documents
	err       error
}

func (fetcher *fakeFetcher) Fetch(context.Context, time.Time) (Documents, error) {
	return fetcher.documents, fetcher.err
}

type fakeStore struct {
	state    State
	accepted int
}

func (store *fakeStore) Accept(context.Context, Documents, time.Time) (State, error) {
	store.accepted++
	return store.state, nil
}
func (store *fakeStore) Current(context.Context, time.Time) (State, error) { return store.state, nil }

func TestRuntimeLocksUnlocksAndRenewsAfterLift(t *testing.T) {
	t.Cleanup(func() { installationlock.Set(installationlock.Lock{}) })
	store := &fakeStore{state: State{NoticeBody: banned(3, nil), LeasePresent: true, LeaseStatus: "revoked"}}
	changed, renewed := 0, 0
	runtime := &Runtime{Fetcher: &fakeFetcher{}, Store: store, Now: func() time.Time { return testNow },
		Changed: func() { changed++ },
		RenewLease: func(context.Context) error {
			renewed++
			store.state.LeaseStatus = "valid"
			return nil
		}}
	if err := runtime.SyncOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if lock := installationlock.Current(); !lock.Locked || lock.Reason != installationlock.ReasonBanned || renewed != 0 {
		t.Fatalf("banned: lock %+v renewed %d", lock, renewed)
	}
	if !installationlock.Skip("test-loop") {
		t.Fatal("a locked installation must skip background rounds")
	}
	// lifted: the old lease serial stays revoked; the runtime renews it once
	store.state.NoticeBody = &contract.BanNotice{Revision: 4, State: contract.StateLifted}
	if err := runtime.SyncOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if lock := installationlock.Current(); lock.Locked || renewed != 1 || changed != 2 {
		t.Fatalf("lifted: lock %+v renewed %d changed %d", lock, renewed, changed)
	}
	if installationlock.Skip("test-loop") {
		t.Fatal("an unlocked installation must run background rounds")
	}
}

// ui-leftover3 #3：lease_expired 锁定时「重新检查」只拉 ban 状态、不续租，授权端恢复后
// 点了也解不了锁；检查时须续租一次，续上即解锁。
func TestRuntimeRenewsExpiredLeaseOnCheck(t *testing.T) {
	t.Cleanup(func() { installationlock.Set(installationlock.Lock{}) })
	store := &fakeStore{state: State{LeasePresent: true, LeaseStatus: "expired"}}
	renewed := 0
	runtime := &Runtime{Fetcher: &fakeFetcher{}, Store: store, Now: func() time.Time { return testNow },
		RenewLease: func(context.Context) error {
			renewed++
			store.state.LeaseStatus = "valid"
			return nil
		}}
	if err := runtime.SyncOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if lock := installationlock.Current(); lock.Locked || renewed != 1 {
		t.Fatalf("expired lease: lock %+v renewed %d, want one renewal that unlocks", lock, renewed)
	}
}

func TestRuntimeKeepsStoredStateWhenRemoteFails(t *testing.T) {
	t.Cleanup(func() { installationlock.Set(installationlock.Lock{}) })
	store := &fakeStore{state: State{NoticeBody: banned(3, nil)}}
	runtime := &Runtime{Fetcher: &fakeFetcher{err: &HTTPError{StatusCode: 503}}, Store: store,
		Now: func() time.Time { return testNow }}
	err := runtime.SyncOnce(t.Context())
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) || !IsRemoteError(err) || store.accepted != 0 {
		t.Fatalf("err = %v accepted %d", err, store.accepted)
	}
	if !installationlock.Locked() {
		t.Fatal("a remote failure must keep the stored ban in force")
	}
}

// fix-ipswitch：授权端回 master_ip_rebound 时首页显示"授权已换绑到其他服务器"，
// 租约还在有效期内也显示（不锁定、不停流量）；网络故障保留上次结论，成功拉取后清除。
func TestRuntimeReportsMasterIPRebound(t *testing.T) {
	t.Cleanup(func() { installationlock.Set(installationlock.Lock{}) })
	store := &fakeStore{state: State{LeasePresent: true, LeaseStatus: "valid", LeaseGrace: testNow.Add(time.Hour)}}
	fetcher := &fakeFetcher{err: &HTTPError{StatusCode: 403, Code: CodeMasterIPRebound}}
	runtime := &Runtime{Fetcher: fetcher, Store: store, Now: func() time.Time { return testNow }}
	_ = runtime.SyncOnce(t.Context())
	if lock := installationlock.Current(); lock.Locked || !lock.Rebound {
		t.Fatalf("rebound: lock %+v, want rebound without lock", lock)
	}
	fetcher.err = &HTTPError{StatusCode: 503}
	_ = runtime.SyncOnce(t.Context())
	if !installationlock.Current().Rebound {
		t.Fatal("an outage must keep the last rebound answer")
	}
	fetcher.err = nil
	if err := runtime.SyncOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if installationlock.Current().Rebound {
		t.Fatal("a successful fetch clears rebound")
	}
}
