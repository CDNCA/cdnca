package entitlementsync

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/google/uuid"
)

type usageReportContract struct {
	Version        string       `json:"version"`
	Seed           string       `json:"seed"`
	InstallationID string       `json:"installation_id"`
	LeaseSerial    uint64       `json:"lease_serial"`
	ObservedAt     int64        `json:"observed_at"`
	Values         []UsageValue `json:"values"`
	RequestID      string       `json:"request_id"`
	Path           string       `json:"path"`
	Body           string       `json:"body"`
}

func loadUsageReportContract(t *testing.T) usageReportContract {
	t.Helper()
	_, filename, _, _ := runtime.Caller(0)
	encoded, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "../../../../tests/contracts/entitlement-usage-report-v2.json"))
	if err != nil {
		t.Fatal(err)
	}
	var contract usageReportContract
	if err := json.Unmarshal(encoded, &contract); err != nil || contract.Version != "cdnca-entitlement-usage-report-contract/v2" {
		t.Fatalf("contract=%+v err=%v", contract, err)
	}
	return contract
}

func contractKey(t *testing.T, contract usageReportContract) ed25519.PrivateKey {
	seed, err := base64.RawURLEncoding.DecodeString(contract.Seed)
	if err != nil {
		t.Fatal(err)
	}
	return ed25519.NewKeyFromSeed(seed)
}

// 主控签出的 v2 上报与授权端契约夹具逐字节一致（授权端用同一夹具验签入库）。
func TestUsageReportMatchesTheLicenseServiceContract(t *testing.T) {
	contract := loadUsageReportContract(t)
	report, err := prepareUsageReport(uuid.MustParse(contract.InstallationID), contract.LeaseSerial,
		time.Unix(contract.ObservedAt, 0), 0, contract.Values, contractKey(t, contract))
	if err != nil {
		t.Fatal(err)
	}
	if report.requestID != contract.RequestID || report.path != contract.Path || string(report.body) != contract.Body ||
		report.sequence != uint64(contract.ObservedAt) {
		t.Fatalf("report=%s %s %s", report.requestID, report.path, report.body)
	}
}

func usageValues(used int64) []UsageValue {
	values := make([]UsageValue, len(UsageReportCodes))
	for index, code := range UsageReportCodes {
		values[index] = UsageValue{Code: code, Used: used}
	}
	return values
}

func TestPrepareUsageReportRules(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(nil)
	id := uuid.New()
	at := time.Unix(1_900_000_000, 0)
	// 序号 = 观测秒；同秒或时钟回拨仍严格递增。
	if report, err := prepareUsageReport(id, 7, at, 0, usageValues(1), key); err != nil || report.sequence != 1_900_000_000 {
		t.Fatalf("sequence=%d err=%v", report.sequence, err)
	}
	if report, _ := prepareUsageReport(id, 7, at, 1_900_000_000, usageValues(1), key); report.sequence != 1_900_000_001 {
		t.Fatalf("same second sequence=%d", report.sequence)
	}
	if report, _ := prepareUsageReport(id, 7, at.Add(-time.Hour), 1_900_000_005, usageValues(1), key); report.sequence != 1_900_000_006 {
		t.Fatalf("clock step back sequence=%d", report.sequence)
	}
	bad := map[string][]UsageValue{
		"12 codes":  usageValues(1)[:12],
		"negative":  usageValues(-1),
		"over max":  usageValues(entitlement.MaxQuotaLimit + 1),
		"unordered": append([]UsageValue{usageValues(1)[1], usageValues(1)[0]}, usageValues(1)[2:]...),
	}
	for name, values := range bad {
		if _, err := prepareUsageReport(id, 7, at, 0, values, key); !errors.Is(err, ErrInvalidConfiguration) {
			t.Errorf("%s err=%v", name, err)
		}
	}
	if _, err := prepareUsageReport(id, 0, at, 0, usageValues(1), key); !errors.Is(err, ErrInvalidConfiguration) {
		t.Errorf("zero lease serial err=%v", err)
	}
}

type fakeLeaseStore struct {
	mu     sync.Mutex
	serial uint64
	err    error
}

func (store *fakeLeaseStore) Current(context.Context) (entitlement.SignedLease, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.err != nil {
		return entitlement.SignedLease{}, store.err
	}
	return entitlement.SignedLease{Lease: entitlement.Lease{Serial: store.serial}}, nil
}

func (*fakeLeaseStore) Install(context.Context, entitlementguard.InstallBundle, time.Time) (entitlementguard.Snapshot, error) {
	return entitlementguard.Snapshot{}, errors.New("unused")
}

type usageServer struct {
	mu       sync.Mutex
	statuses []int
	codes    []string // error code per non-201 status, in order
	bodies   []map[string]any
	keys     []string
}

func (server *usageServer) RoundTrip(request *http.Request) (*http.Response, error) {
	server.mu.Lock()
	defer server.mu.Unlock()
	body, _ := io.ReadAll(request.Body)
	var decoded map[string]any
	_ = json.Unmarshal(body, &decoded)
	server.bodies = append(server.bodies, decoded)
	server.keys = append(server.keys, request.Header.Get("Idempotency-Key"))
	status := http.StatusCreated
	if len(server.statuses) > 0 {
		status, server.statuses = server.statuses[0], server.statuses[1:]
	}
	response := `{"code":"temporarily_unavailable"}`
	if status != http.StatusCreated && len(server.codes) > 0 {
		response, server.codes = `{"code":"`+server.codes[0]+`"}`, server.codes[1:]
	}
	if status == http.StatusCreated {
		response = `{"schema":"` + UsageReportSchema + `","sequence":` + strconv.FormatFloat(decoded["sequence"].(float64), 'f', 0, 64) + `}`
	}
	return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(response))}, nil
}

func newTestUsageReporter(t *testing.T, server *usageServer, store *fakeLeaseStore, now *time.Time,
	collect UsageCollector, waits *[]time.Duration,
) *UsageReporter {
	t.Helper()
	client, err := NewClient("https://license.example.test", &http.Client{Transport: server})
	if err != nil {
		t.Fatal(err)
	}
	_, key, _ := ed25519.GenerateKey(nil)
	reporter, err := NewUsageReporter(UsageReporterConfig{
		Client: client, Store: store, State: &memoryUsageState{}, InstallationID: uuid.New(), PrivateKey: key, Collect: collect,
		Now: func() time.Time { return *now },
		Wait: func(ctx context.Context, delay time.Duration) error {
			*waits = append(*waits, delay)
			*now = now.Add(delay)
			return ctx.Err()
		},
		BackoffMin: time.Second, BackoffMax: 8 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return reporter
}

// 5xx/429 按退避重试同一份签名报文（同 Idempotency-Key），成功后记录上次成功时间。
func TestUsageReporterRetriesWithBackoffAndRecordsSuccess(t *testing.T) {
	now := time.Unix(1_900_000_000, 0).UTC()
	server := &usageServer{statuses: []int{503, 503, 429, 201}}
	var waits []time.Duration
	collect := func(context.Context) (time.Time, []UsageValue, error) { return now, usageValues(3), nil }
	reporter := newTestUsageReporter(t, server, &fakeLeaseStore{serial: 9}, &now, collect, &waits)
	if err := reporter.ReportOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(server.keys) != 4 || server.keys[0] != server.keys[3] {
		t.Fatalf("keys=%v", server.keys)
	}
	if want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second}; len(waits) != 3 || waits[0] != want[0] ||
		waits[1] != want[1] || waits[2] != want[2] {
		t.Fatalf("waits=%v", waits)
	}
	if reporter.LastSuccess() != now || server.bodies[3]["lease_serial"].(float64) != 9 ||
		len(server.bodies[3]["values"].([]any)) != 13 || server.bodies[3]["schema"] != UsageReportSchema {
		t.Fatalf("success=%v body=%v", reporter.LastSuccess(), server.bodies[3])
	}
}

// 4xx（如 usage_lease_unknown）不重试；采集失败不发送、不伪造 0。
func TestUsageReporterDoesNotRetryDefinitiveFailuresOrSendPartialCounts(t *testing.T) {
	now := time.Unix(1_900_000_000, 0).UTC()
	server := &usageServer{statuses: []int{409}}
	var waits []time.Duration
	collect := func(context.Context) (time.Time, []UsageValue, error) { return now, usageValues(3), nil }
	reporter := newTestUsageReporter(t, server, &fakeLeaseStore{serial: 9}, &now, collect, &waits)
	var httpError *HTTPError
	if err := reporter.ReportOnce(context.Background()); !errors.As(err, &httpError) || httpError.StatusCode != 409 ||
		len(server.keys) != 1 || len(waits) != 0 || !reporter.LastSuccess().IsZero() {
		t.Fatalf("err=%v calls=%d waits=%v", err, len(server.keys), waits)
	}
	failing := newTestUsageReporter(t, server, &fakeLeaseStore{serial: 9}, &now,
		func(context.Context) (time.Time, []UsageValue, error) {
			return time.Time{}, nil, errors.New("clickhouse down")
		}, &waits)
	if err := failing.ReportOnce(context.Background()); err == nil || len(server.keys) != 1 {
		t.Fatalf("err=%v calls=%d", err, len(server.keys))
	}
}

// 启动即报；之后租约序号变化（续租）在下一次轮询就报，否则满 1 小时再报。
func TestUsageReporterRunReportsOnRenewalOrHourly(t *testing.T) {
	now := time.Unix(1_900_000_000, 0).UTC()
	server := &usageServer{}
	store := &fakeLeaseStore{serial: 1}
	var waits []time.Duration
	collect := func(context.Context) (time.Time, []UsageValue, error) { return now, usageValues(1), nil }
	reporter := newTestUsageReporter(t, server, store, &now, collect, &waits)
	ctx, cancel := context.WithCancel(context.Background())
	polls := 0
	reporter.config.Wait = func(ctx context.Context, delay time.Duration) error {
		polls++
		now = now.Add(delay)
		switch polls {
		case 5: // 续租：第 5 分钟换了租约
			store.mu.Lock()
			store.serial = 2
			store.mu.Unlock()
		case 70:
			cancel()
		}
		return ctx.Err()
	}
	if err := reporter.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	// 0 分钟启动、5 分钟续租、65 分钟满一小时。
	if len(server.bodies) != 3 || server.bodies[1]["lease_serial"].(float64) != 2 {
		t.Fatalf("reports=%d bodies=%v", len(server.bodies), server.bodies)
	}
	sequences := []float64{server.bodies[0]["sequence"].(float64), server.bodies[1]["sequence"].(float64), server.bodies[2]["sequence"].(float64)}
	if sequences[0] != 1_900_000_000 || sequences[1] != 1_900_000_300 || sequences[2] != 1_900_003_900 {
		t.Fatalf("sequences=%v", sequences)
	}
}

func TestUsageReporterRejectsMismatchedAcceptance(t *testing.T) {
	report := usageReport{requestID: "r", path: "/p", body: []byte(`{}`), sequence: 5}
	client, _ := NewClient("https://license.example.test", &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 201, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader([]byte(`{"schema":"` + UsageReportSchema + `","sequence":4}`)))}, nil
	})})
	if err := client.sendUsageReport(context.Background(), report); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("err=%v", err)
	}
}
