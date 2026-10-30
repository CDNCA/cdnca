package entitlementsync

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/google/uuid"
)

// The license service's v2 usage report (license-service
// internal/licensing/usage_quota_observation_v2.go): every round carries all
// thirteen quota codes in strict lexical order, signed by the installation
// key over the current lease serial. It has no "not counted" value, so a
// round whose counts cannot all be read is not sent (fix-usagereport).
const (
	UsageReportSchema            = "cdnca.entitlement.usage-report/v2"
	usageReportProofDomain       = "cdnca-entitlement-usage-report-proof/v2"
	defaultUsageReportInterval   = time.Hour
	defaultUsageLeasePollPeriod  = time.Minute
	defaultUsageReportBackoffMin = 5 * time.Second
)

// UsageReportCodes is the v2 code list in the order the license service
// requires.
var UsageReportCodes = [...]string{
	entitlement.QuotaDomainsCount,
	entitlement.QuotaErrorPageAssetBytes,
	entitlement.QuotaErrorPageAssetsCount,
	entitlement.QuotaErrorPagePublicationBytes,
	entitlement.QuotaErrorPagePublicationSites,
	entitlement.QuotaErrorPageRulesPerScope,
	entitlement.QuotaErrorPageTotalBytes,
	entitlement.QuotaExtensionsWebhooksCount,
	entitlement.QuotaMonthlyTrafficBytes,
	entitlement.QuotaNodesCount,
	entitlement.QuotaPackagesCount,
	entitlement.QuotaReleaseChannelsCount,
	entitlement.QuotaSitesCount,
}

type UsageValue struct {
	Code string `json:"code"`
	Used int64  `json:"used"`
}

// UsageCollector reads every quota count at one observation time.
type UsageCollector func(context.Context) (time.Time, []UsageValue, error)

type usageReport struct {
	requestID   string
	path        string
	body        []byte
	sequence    uint64
	leaseSerial uint64
}

func usageReportPath(installationID uuid.UUID) string {
	return "/control/v2/installations/" + url.PathEscape(installationID.String()) + "/usage-reports"
}

// prepareUsageReport signs a v2 report. The sequence is the observation's
// Unix second, or previous+1 when that is not larger: previous is the last
// sequence ever allocated for the installation (UsageReportState, migration
// 554), so restarts and clock steps never reuse or lower it (L08).
func prepareUsageReport(installationID uuid.UUID, leaseSerial uint64, observedAt time.Time, previous uint64,
	values []UsageValue, privateKey ed25519.PrivateKey,
) (usageReport, error) {
	observed := observedAt.UTC().Unix()
	if installationID == uuid.Nil || leaseSerial == 0 || observed <= 0 || len(privateKey) != ed25519.PrivateKeySize ||
		!validUsageValues(values) {
		return usageReport{}, ErrInvalidConfiguration
	}
	sequence := uint64(observed)
	if sequence <= previous {
		sequence = previous + 1
	}
	requestID := fmt.Sprintf("control-usage-%s-%d", installationID, sequence)
	fields := []string{usageReportProofDomain, requestID, installationID.String(), UsageReportSchema,
		strconv.FormatUint(sequence, 10), strconv.FormatUint(leaseSerial, 10), strconv.FormatInt(observed, 10)}
	for _, value := range values {
		fields = append(fields, value.Code, strconv.FormatInt(value.Used, 10))
	}
	proof := ed25519.Sign(privateKey, digestFields(fields...))
	body, err := json.Marshal(struct {
		Schema      string       `json:"schema"`
		Sequence    uint64       `json:"sequence"`
		LeaseSerial uint64       `json:"lease_serial"`
		ObservedAt  int64        `json:"observed_at"`
		Values      []UsageValue `json:"values"`
		Proof       string       `json:"proof"`
	}{UsageReportSchema, sequence, leaseSerial, observed, values, base64.RawURLEncoding.EncodeToString(proof)})
	if err != nil {
		return usageReport{}, fmt.Errorf("encode usage report: %w", err)
	}
	return usageReport{requestID: requestID, sequence: sequence, leaseSerial: leaseSerial, body: body,
		path: usageReportPath(installationID)}, nil
}

func validUsageValues(values []UsageValue) bool {
	if len(values) != len(UsageReportCodes) {
		return false
	}
	for index, code := range UsageReportCodes {
		if values[index].Code != code || values[index].Used < 0 || values[index].Used > entitlement.MaxQuotaLimit {
			return false
		}
	}
	return true
}

func (client *Client) sendUsageReport(ctx context.Context, report usageReport) error {
	if client == nil || client.baseURL == nil || client.http == nil || report.requestID == "" || len(report.body) == 0 {
		return ErrInvalidConfiguration
	}
	target := *client.baseURL
	target.Path += report.path
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(report.body))
	if err != nil {
		return fmt.Errorf("create usage report request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Idempotency-Key", report.requestID)
	request.Header.Set("X-Request-ID", report.requestID)
	response, err := client.http.Do(request)
	if err != nil {
		return fmt.Errorf("send usage report: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		return decodeHTTPError(response)
	}
	var accepted struct {
		Schema   string `json:"schema"`
		Sequence uint64 `json:"sequence"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, maxResponseBytes)).Decode(&accepted); err != nil ||
		accepted.Schema != UsageReportSchema || accepted.Sequence != report.sequence {
		return ErrInvalidResponse
	}
	return nil
}

type UsageReporterConfig struct {
	Client         *Client
	Store          LocalStore
	State          UsageReportState
	InstallationID uuid.UUID
	PrivateKey     ed25519.PrivateKey
	Collect        UsageCollector
	Now            func() time.Time
	Wait           func(context.Context, time.Duration) error
	Logger         *slog.Logger
	// Interval is the longest gap between reports (default 1h); a newly
	// installed lease (renewal) is reported at the next LeasePoll (1m).
	Interval   time.Duration
	LeasePoll  time.Duration
	BackoffMin time.Duration
	BackoffMax time.Duration
}

type UsageReporter struct {
	config UsageReporterConfig

	mu          sync.Mutex
	lastSerial  uint64
	lastSuccess time.Time
}

// Answers after which the pending report can never be accepted: drop it so
// the next round is built (the license service still fences the sequence).
var terminalUsageCodes = map[string]bool{
	"usage_lease_unknown": true, "usage_sequence_replay": true, "usage_sequence_conflict": true, "idempotency_conflict": true,
}

func NewUsageReporter(config UsageReporterConfig) (*UsageReporter, error) {
	if config.Client == nil || config.Store == nil || config.State == nil || config.InstallationID == uuid.Nil ||
		len(config.PrivateKey) != ed25519.PrivateKeySize || config.Collect == nil {
		return nil, ErrInvalidConfiguration
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Wait == nil {
		config.Wait = waitContext
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	if config.Interval == 0 {
		config.Interval = defaultUsageReportInterval
	}
	if config.LeasePoll == 0 {
		config.LeasePoll = defaultUsageLeasePollPeriod
	}
	if config.BackoffMin == 0 {
		config.BackoffMin = defaultUsageReportBackoffMin
	}
	if config.BackoffMax == 0 {
		config.BackoffMax = defaultBackoffMax
	}
	if config.Interval <= 0 || config.LeasePoll <= 0 || config.BackoffMin <= 0 || config.BackoffMax < config.BackoffMin {
		return nil, ErrInvalidConfiguration
	}
	config.PrivateKey = append(ed25519.PrivateKey(nil), config.PrivateKey...)
	return &UsageReporter{config: config}, nil
}

// LastSuccess is when the license service last accepted a report (zero
// before the first).
func (reporter *UsageReporter) LastSuccess() time.Time {
	reporter.mu.Lock()
	defer reporter.mu.Unlock()
	return reporter.lastSuccess
}

// Run reports at start, then whenever the local lease serial changes or the
// interval has passed since the last attempt, whichever comes first. Failures
// are logged and never stop the server.
func (reporter *UsageReporter) Run(ctx context.Context) error {
	var lastAttempt time.Time
	for {
		serial, err := reporter.currentSerial(ctx)
		switch {
		case err != nil:
			if !errors.Is(err, ErrNoLocalLease) {
				reporter.config.Logger.Warn("entitlement usage report deferred: local lease unreadable", "error", err)
			}
		case lastAttempt.IsZero() || serial != reporter.serial() ||
			!reporter.config.Now().Before(lastAttempt.Add(reporter.config.Interval)):
			lastAttempt = reporter.config.Now()
			roundCtx, cancel := context.WithTimeout(ctx, reporter.config.Interval)
			if err := reporter.ReportOnce(roundCtx); err != nil && ctx.Err() == nil {
				reporter.config.Logger.Error("entitlement usage report failed", "error", err,
					"last_success", reporter.LastSuccess())
			}
			cancel()
		}
		if err := reporter.config.Wait(ctx, reporter.config.LeasePoll); err != nil {
			return err
		}
	}
}

func (reporter *UsageReporter) serial() uint64 {
	reporter.mu.Lock()
	defer reporter.mu.Unlock()
	return reporter.lastSerial
}

func (reporter *UsageReporter) currentSerial(ctx context.Context) (uint64, error) {
	current, err := reporter.config.Store.Current(ctx)
	if err != nil {
		return 0, err
	}
	if current.Lease.Serial == 0 {
		return 0, ErrNoLocalLease
	}
	return current.Lease.Serial, nil
}

// ReportOnce sends the unconfirmed report left by an earlier round or
// process, byte for byte; with none, it collects all thirteen counts and
// stores a new signed report as pending before sending it. Retryable failures
// are retried with back-off until ctx ends; the report stays pending until the
// license service accepts it or refuses it for good (terminalUsageCodes).
func (reporter *UsageReporter) ReportOnce(ctx context.Context) error {
	serial, err := reporter.currentSerial(ctx)
	if err != nil {
		return err
	}
	// Recorded before collecting: a failed round waits for the next interval
	// or lease, not the next poll.
	reporter.mu.Lock()
	reporter.lastSerial = serial
	reporter.mu.Unlock()
	id := reporter.config.InstallationID
	pending, found, err := reporter.config.State.Pending(ctx, id)
	if err != nil {
		return err
	}
	if found {
		err := reporter.deliver(ctx, pending)
		// A report of a replaced lease the license service no longer knows was
		// dropped: report the current lease in this same round.
		if !isTerminalUsage(err) || pending.leaseSerial == serial {
			return err
		}
		reporter.config.Logger.Warn("entitlement usage report of an old lease dropped", "sequence", pending.sequence,
			"lease_serial", pending.leaseSerial, "error", err)
	}
	observedAt, values, err := reporter.config.Collect(ctx)
	if err != nil {
		return fmt.Errorf("collect entitlement usage: %w", err)
	}
	report, err := reporter.config.State.Reserve(ctx, id, func(previous uint64) (usageReport, error) {
		return prepareUsageReport(id, serial, observedAt, previous, values, reporter.config.PrivateKey)
	}, reporter.config.Now())
	if err != nil {
		return err
	}
	return reporter.deliver(ctx, report)
}

func isTerminalUsage(err error) bool {
	var httpError *HTTPError
	return errors.As(err, &httpError) && terminalUsageCodes[httpError.Code]
}

// deliver sends one stored report until it is accepted or refused.
func (reporter *UsageReporter) deliver(ctx context.Context, report usageReport) error {
	id := reporter.config.InstallationID
	delay := reporter.config.BackoffMin
	for {
		err := reporter.config.Client.sendUsageReport(ctx, report)
		if err == nil {
			if err := reporter.config.State.Settle(ctx, id, report); err != nil {
				// Accepted but not recorded: the next round resends the same bytes and the license service answers it again.
				return err
			}
			reporter.mu.Lock()
			reporter.lastSuccess = reporter.config.Now().UTC()
			reporter.mu.Unlock()
			reporter.config.Logger.Info("entitlement usage reported", "sequence", report.sequence, "lease_serial", report.leaseSerial)
			return nil
		}
		if isTerminalUsage(err) {
			if settleErr := reporter.config.State.Settle(ctx, id, report); settleErr != nil {
				return errors.Join(err, settleErr)
			}
			return err
		}
		retryAfter, canRetry := retryable(err)
		if !canRetry || errors.Is(err, ErrInvalidResponse) {
			return err
		}
		wait := max(delay, retryAfter)
		wait = min(wait, reporter.config.BackoffMax)
		reporter.config.Logger.Warn("entitlement usage report deferred", "error", err, "retry_in", wait)
		if err := reporter.config.Wait(ctx, wait); err != nil {
			return errors.Join(fmt.Errorf("usage report sequence %d not accepted", report.sequence), err)
		}
		delay = min(delay*2, reporter.config.BackoffMax)
	}
}
