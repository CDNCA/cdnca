package installationban

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"testing"
	"time"

	contract "github.com/cdnca/cdnca/libs/entitlement/installationban"
)

const (
	testInstallation = "0190a000-0000-7000-8000-000000000001"
	testCustomer     = "0190a000-0000-7000-8000-000000000002"
	testBan          = "0190a000-0000-7000-8000-000000000003"
	testLicense      = "0190a000-0000-7000-8000-000000000004"
)

type signer struct{ private ed25519.PrivateKey }

func (signer) KeyID() string { return "license-ban" }
func (s signer) Sign(_ context.Context, payload []byte) ([]byte, error) {
	return ed25519.Sign(s.private, payload), nil
}

func newSigner(label string) signer {
	seed := sha256.Sum256([]byte(label))
	return signer{private: ed25519.NewKeyFromSeed(seed[:])}
}

type fakeServing struct {
	stopped    bool
	stops      int
	resumes    int
	retryAfter time.Time
}

func (serving *fakeServing) Stop(_ context.Context, retryAfter time.Time) error {
	serving.stopped, serving.retryAfter = true, retryAfter
	serving.stops++
	return nil
}
func (serving *fakeServing) Resume(context.Context) error {
	serving.stopped = false
	serving.resumes++
	return nil
}

type fixture struct {
	t       *testing.T
	trusted signer
	now     time.Time
	serving *fakeServing
	dir     string
}

func (f *fixture) runtime() *Runtime {
	runtime, err := New(Config{Dir: f.dir, InstallationID: testInstallation, Serving: f.serving,
		Now: func() time.Time { return f.now },
		Keys: func() map[string]ed25519.PublicKey {
			return map[string]ed25519.PublicKey{f.trusted.KeyID(): f.trusted.private.Public().(ed25519.PublicKey)}
		}})
	if err != nil {
		f.t.Fatal(err)
	}
	if err := runtime.Restore(f.t.Context()); err != nil {
		f.t.Fatal(err)
	}
	return runtime
}

func (f *fixture) notice(by signer, revision uint64, state string, until *int64) []byte {
	encoded, err := contract.SignNotice(f.t.Context(), contract.BanNotice{Schema: contract.NoticeSchema,
		InstallationID: testInstallation, CustomerID: testCustomer, BanID: testBan, Revision: revision, State: state,
		ReasonCode: "abuse", ReasonText: "滥用", StartsAt: f.now.Unix(), Until: until, IssuedAt: f.now.Unix()}, by)
	if err != nil {
		f.t.Fatal(err)
	}
	return encoded
}

func (f *fixture) ticket(revision uint64, validity time.Duration) []byte {
	encoded, err := contract.SignTicket(f.t.Context(), contract.ServiceTicket{Schema: contract.TicketSchema,
		InstallationID: testInstallation, CustomerID: testCustomer, LicenseID: testLicense, Revision: revision,
		IssuedAt: f.now.Unix(), NotAfter: f.now.Add(validity).Unix()}, f.trusted)
	if err != nil {
		f.t.Fatal(err)
	}
	return encoded
}

func newFixture(t *testing.T) *fixture {
	return &fixture{t: t, trusted: newSigner("license"), now: time.Unix(1_900_000_000, 0).UTC(),
		serving: &fakeServing{}, dir: t.TempDir()}
}

func TestBanStopsLiftResumesAndRestartKeepsState(t *testing.T) {
	f := newFixture(t)
	runtime := f.runtime()
	if result := runtime.Apply(t.Context(), nil, f.ticket(1, contract.DefaultNodeOfflineTolerance)); !result.Applied ||
		result.Status != contract.StatusServing || f.serving.stopped {
		t.Fatalf("ticket: %+v", result)
	}
	until := f.now.Add(48 * time.Hour).Unix()
	result := runtime.Apply(t.Context(), f.notice(f.trusted, 2, contract.StateBanned, &until), nil)
	if !result.Applied || result.Status != contract.StatusBanned || !f.serving.stopped ||
		f.serving.retryAfter.Unix() != until {
		t.Fatalf("ban: %+v serving %+v", result, f.serving)
	}
	if RetryAfterHeader(f.serving.retryAfter) != time.Unix(until, 0).UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT") {
		t.Fatal("Retry-After must be the ban's until as an HTTP date")
	}
	// forged lift, old ticket, other installation: refused, still stopped
	if result := runtime.Apply(t.Context(), f.notice(newSigner("forged"), 3, contract.StateLifted, nil), nil); result.Applied ||
		result.Reason != ReasonUntrusted || result.Status != contract.StatusBanned {
		t.Fatalf("forged: %+v", result)
	}
	if result := runtime.Apply(t.Context(), nil, f.ticket(1, contract.DefaultNodeOfflineTolerance)); !result.Applied ||
		result.Status != contract.StatusBanned {
		t.Fatalf("same old ticket redelivered: %+v", result)
	}
	if result := runtime.Apply(t.Context(), f.notice(f.trusted, 1, contract.StateLifted, nil), nil); result.Reason != ReasonStale {
		t.Fatalf("stale lift: %+v", result)
	}
	// restart: a new process stops again (the serving side forgot it)
	f.serving = &fakeServing{}
	restarted := f.runtime()
	if restarted.Status() != contract.StatusBanned || !f.serving.stopped || f.serving.retryAfter.Unix() != until {
		t.Fatalf("restart: %s serving %+v", restarted.Status(), f.serving)
	}
	// lifted (higher revision) and a later ticket: resumed
	if result := restarted.Apply(t.Context(), f.notice(f.trusted, 3, contract.StateLifted, nil),
		f.ticket(4, contract.DefaultNodeOfflineTolerance)); !result.Applied || result.Status != contract.StatusServing ||
		f.serving.stopped || f.serving.resumes != 1 {
		t.Fatalf("lift: %+v serving %+v", result, f.serving)
	}
}

// 票据过期只冻结（不停流量），回拨时钟也不能把冻结变回正常。
func TestTicketExpiryFreezesKeepsServingAndClockRollbackDoesNotExtend(t *testing.T) {
	f := newFixture(t)
	runtime := f.runtime()
	runtime.Apply(t.Context(), nil, f.ticket(1, contract.DefaultNodeOfflineTolerance))
	stops := f.serving.stops // the fresh node stopped once before its first ticket
	f.now = f.now.Add(contract.DefaultNodeOfflineTolerance - time.Minute)
	if status, _ := runtime.Tick(t.Context()); status != contract.StatusServing || f.serving.stopped || runtime.Frozen() {
		t.Fatalf("before expiry: %s", status)
	}
	f.now = f.now.Add(2 * time.Minute)
	if status, _ := runtime.Tick(t.Context()); status != contract.StatusTicketExpired || f.serving.stopped ||
		f.serving.stops != stops || !runtime.Frozen() {
		t.Fatalf("after expiry the node keeps serving, frozen: %s %+v", status, f.serving)
	}
	// setting the clock back a day does not unfreeze
	f.now = f.now.Add(-24 * time.Hour)
	if status, _ := runtime.Tick(t.Context()); status != contract.StatusTicketExpired || f.serving.stopped || !runtime.Frozen() {
		t.Fatalf("clock rollback: %s", status)
	}
	// a restart while frozen keeps serving
	f.serving = &fakeServing{}
	restarted := f.runtime()
	if restarted.Status() != contract.StatusTicketExpired || f.serving.stopped || !restarted.Frozen() {
		t.Fatalf("restart while frozen: %s %+v", restarted.Status(), f.serving)
	}
	// a fresh ticket unfreezes
	f.now = f.now.Add(25 * time.Hour)
	if result := restarted.Apply(t.Context(), nil, f.ticket(2, contract.DefaultNodeOfflineTolerance)); result.Status != contract.StatusServing ||
		f.serving.stopped || restarted.Frozen() {
		t.Fatalf("renewed: %+v", result)
	}
}

// 节点从“票过期停服”的旧状态文件升级上来时恢复服务（Stopped 不再残留）。
func TestFrozenAfterStoppedStateResumes(t *testing.T) {
	f := newFixture(t)
	runtime := f.runtime()
	runtime.Apply(t.Context(), nil, f.ticket(1, time.Hour))
	f.now = f.now.Add(2 * time.Hour)
	resumes := f.serving.resumes
	runtime.state.Stopped = true // what an older agent persisted for an expired ticket
	if status, err := runtime.Tick(t.Context()); err != nil || status != contract.StatusTicketExpired ||
		f.serving.resumes != resumes+1 || runtime.state.Stopped {
		t.Fatalf("expired ticket must not keep the node stopped: %s %v %+v", status, err, f.serving)
	}
}

// PF09：首张凭据到达之前节点不对外开放，不再有安装后 24 小时的宽限。
func TestNoTicketStaysClosedUntilTheFirstTicket(t *testing.T) {
	f := newFixture(t)
	runtime := f.runtime()
	if status := runtime.Status(); status != contract.StatusNoTicket || !f.serving.stopped || f.serving.stops != 1 {
		t.Fatalf("fresh node must not serve before its first ticket: %s %+v", status, f.serving)
	}
	if held := runtime.Ticket(); held != nil {
		t.Fatalf("fresh node holds no ticket: %+v", held)
	}
	// a restart before the first ticket stays closed
	f.serving = &fakeServing{}
	restarted := f.runtime()
	if restarted.Status() != contract.StatusNoTicket || !f.serving.stopped {
		t.Fatalf("restart before the first ticket: %s %+v", restarted.Status(), f.serving)
	}
	result := restarted.Apply(t.Context(), nil, f.ticket(1, contract.DefaultNodeOfflineTolerance))
	if !result.Applied || result.Status != contract.StatusServing || f.serving.stopped || f.serving.resumes != 1 {
		t.Fatalf("first ticket opens the node: %+v %+v", result, f.serving)
	}
	if held := restarted.Ticket(); held == nil || held.IssuedAt != f.now.Unix() ||
		held.NotAfter != f.now.Add(contract.DefaultNodeOfflineTolerance).Unix() {
		t.Fatalf("held ticket: %+v", held)
	}
}

// 商业到期/暂停/吊销（无安全封禁）时授权端不再续签；最后一张票
// 到期后节点继续服务已有配置、进入冻结；恢复后的新票（更高 revision）解除冻结。
func TestCommercialExpiryFinalTicketKeepsServingFrozen(t *testing.T) {
	f := newFixture(t)
	runtime := f.runtime()
	runtime.Apply(t.Context(), nil, f.ticket(1, contract.DefaultNodeOfflineTolerance))
	for day := 1; day <= 8; day++ {
		f.now = f.now.Add(24 * time.Hour)
		if result := runtime.Apply(t.Context(), nil, f.ticket(uint64(1+day), contract.DefaultNodeOfflineTolerance)); !result.Applied ||
			result.Status != contract.StatusServing || f.serving.stopped {
			t.Fatalf("daily renewal day %d: %+v", day, result)
		}
	}
	// commercial expiry: the control plane only redelivers the last ticket
	last := f.ticket(20, contract.DefaultNodeOfflineTolerance)
	runtime.Apply(t.Context(), nil, last)
	stops := f.serving.stops
	f.now = f.now.Add(contract.DefaultNodeOfflineTolerance + time.Minute)
	result := runtime.Apply(t.Context(), nil, last)
	if result.Status != contract.StatusTicketExpired || result.Reason != ReasonExpired || f.serving.stopped ||
		f.serving.stops != stops || !runtime.Frozen() {
		t.Fatalf("final ticket expired: the node keeps serving, frozen: %+v %+v", result, f.serving)
	}
	f.now = f.now.Add(3 * 24 * time.Hour)
	if result := runtime.Apply(t.Context(), nil, f.ticket(21, contract.DefaultNodeOfflineTolerance)); !result.Applied ||
		result.Status != contract.StatusServing || f.serving.stopped || runtime.Frozen() {
		t.Fatalf("renewed after resume: %+v", result)
	}
}

// 主控失联（授权端正常）时节点收不到新票：在票据窗口内照常服务，
// 窗口过后继续服务并冻结。
func TestControlPlaneLostNoNewTicketKeepsServingFrozen(t *testing.T) {
	f := newFixture(t)
	runtime := f.runtime()
	runtime.Apply(t.Context(), nil, f.ticket(1, contract.DefaultNodeOfflineTolerance))
	for _, after := range []time.Duration{24 * time.Hour, 29 * 24 * time.Hour} {
		f.now = time.Unix(1_900_000_000, 0).UTC().Add(after)
		if status, _ := runtime.Tick(t.Context()); status != contract.StatusServing || f.serving.stopped || runtime.Frozen() {
			t.Fatalf("control plane lost %s: %s", after, status)
		}
	}
	f.now = time.Unix(1_900_000_000, 0).UTC().Add(31 * 24 * time.Hour)
	if status, _ := runtime.Tick(t.Context()); status != contract.StatusTicketExpired || f.serving.stopped || !runtime.Frozen() {
		t.Fatalf("control plane lost past the ticket: %s %+v", status, f.serving)
	}
}

// 伪造或别的安装的 BanNotice 不停流量；冻结中收到合法 BanNotice 才停，合法解除恢复。
func TestForgedNoticeDoesNotStopValidBanStopsLiftResumes(t *testing.T) {
	f := newFixture(t)
	runtime := f.runtime()
	runtime.Apply(t.Context(), nil, f.ticket(1, time.Hour))
	f.now = f.now.Add(2 * time.Hour) // frozen
	if result := runtime.Apply(t.Context(), f.notice(newSigner("forged"), 2, contract.StateBanned, nil), nil); result.Applied ||
		result.Reason != ReasonUntrusted || f.serving.stopped {
		t.Fatalf("forged ban: %+v %+v", result, f.serving)
	}
	until := f.now.Add(-time.Minute).Unix() // already over
	past := f.now.Add(-2 * time.Hour)
	saved := f.now
	f.now = past
	ended := f.notice(f.trusted, 2, contract.StateBanned, &until)
	f.now = saved
	if result := runtime.Apply(t.Context(), ended, nil); !result.Applied || f.serving.stopped {
		t.Fatalf("a ban whose until has passed must not stop: %+v %+v", result, f.serving)
	}
	resumes := f.serving.resumes
	if result := runtime.Apply(t.Context(), f.notice(f.trusted, 3, contract.StateBanned, nil), nil); !result.Applied ||
		result.Status != contract.StatusBanned || !f.serving.stopped {
		t.Fatalf("valid ban: %+v %+v", result, f.serving)
	}
	if result := runtime.Apply(t.Context(), f.notice(f.trusted, 4, contract.StateLifted, nil),
		f.ticket(5, contract.DefaultNodeOfflineTolerance)); !result.Applied || result.Status != contract.StatusServing ||
		f.serving.stopped || f.serving.resumes != resumes+1 {
		t.Fatalf("lift: %+v %+v", result, f.serving)
	}
}
