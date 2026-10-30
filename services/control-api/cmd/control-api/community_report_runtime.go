package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// cdncaCE community installation report: the community edition needs no
// activation, but tells the official service it runs: once right after the
// first start, then every 7 days (user decision 10-29). The time of the last
// accepted report is kept in COMMUNITY_REPORT_STATE_FILE so a restart does
// not report again early. The
// report carries only installation facts (ID, version, node and site
// counts); the official service takes the public IP from the connection and
// rate-limits one report per installation per hour. It grants nothing and
// nothing depends on its answer.
const (
	communityReportURLEnv      = "COMMUNITY_REPORT_URL"
	communityReportDefaultURL  = "https://auth.cdnca.com/public/v1/community/installations/report"
	communityReportInterval    = 7 * 24 * time.Hour
	communityReportFirstDelay  = 2 * time.Minute
	communityReportRetryDelay  = 6 * time.Hour
	communityReportStateEnv    = "COMMUNITY_REPORT_STATE_FILE"
	communityReportStateFile   = "/etc/cdnca-control/community/last-report"
	communityReportTimeout     = 15 * time.Second
	communityReportMaxRespBody = 4 << 10
)

// communityReport is the official report body (license service
// /public/v1/community/installations/report, unknown fields refused, 2 KiB).
// public_ip is advisory there (the connection source counts) and left out.
type communityReport struct {
	InstallationID string `json:"installation_id"`
	Version        string `json:"version"`
	NodeCount      int64  `json:"node_count"`
	SiteCount      int64  `json:"site_count"`
	Edition        string `json:"edition"`
}

type communityReporter struct {
	pool    *pgxpool.Pool
	url     string
	version string
	client  *http.Client
	state   string
	now     func() time.Time
}

// newCommunityReporter returns nil when COMMUNITY_REPORT_URL is "off" (an
// operator may opt out) or the pool is missing. An empty value uses the
// official endpoint; any other value must be an https URL.
func newCommunityReporter(pool *pgxpool.Pool, version string) (*communityReporter, error) {
	target, set := os.LookupEnv(communityReportURLEnv)
	if target == "off" || !configuredRuntimePool(pool) {
		return nil, nil
	}
	if !set || target == "" {
		target = communityReportDefaultURL
	}
	parsed, err := url.Parse(target)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return nil, fmt.Errorf("%s must be an https URL or off", communityReportURLEnv)
	}
	return &communityReporter{pool: pool, url: target, version: version,
		client: &http.Client{Timeout: communityReportTimeout}, state: communityReportStatePath(), now: time.Now}, nil
}

func communityReportStatePath() string {
	if path := strings.TrimSpace(os.Getenv(communityReportStateEnv)); path != "" {
		return path
	}
	return communityReportStateFile
}

// nextDelay: the first start reports soon; afterwards the next report is
// due 7 days after the last accepted one (an unreadable state reports soon).
func (reporter *communityReporter) nextDelay() time.Duration {
	encoded, err := os.ReadFile(reporter.state)
	if err != nil {
		return communityReportFirstDelay
	}
	last, err := time.Parse(time.RFC3339, strings.TrimSpace(string(encoded)))
	if err != nil {
		return communityReportFirstDelay
	}
	due := last.Add(communityReportInterval).Sub(reporter.now())
	return max(due, communityReportFirstDelay)
}

func (reporter *communityReporter) recordReported() {
	if err := os.MkdirAll(filepath.Dir(reporter.state), 0o700); err != nil {
		slog.Warn("community report state not saved", "error", err)
		return
	}
	stamp := []byte(reporter.now().UTC().Format(time.RFC3339) + "\n")
	if err := os.WriteFile(reporter.state, stamp, 0o600); err != nil {
		slog.Warn("community report state not saved", "error", err)
	}
}

// Run reports once after the first start, then every 7 days; a failed
// report is retried after 6 hours. It never stops the control plane.
func (reporter *communityReporter) Run(ctx context.Context) error {
	delay := reporter.nextDelay()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(delay):
		}
		if err := reporter.reportOnce(ctx); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			slog.Warn("community installation report failed", "error", err)
			delay = communityReportRetryDelay
			continue
		}
		reporter.recordReported()
		delay = communityReportInterval
	}
}

func (reporter *communityReporter) reportOnce(ctx context.Context) error {
	report := communityReport{Edition: "community", Version: reporter.version}
	if err := reporter.pool.QueryRow(ctx, `SELECT installation_id FROM control_installation_entitlement WHERE singleton`).
		Scan(&report.InstallationID); err != nil {
		return fmt.Errorf("read installation: %w", err)
	}
	if err := reporter.pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM nodes WHERE admin_state <> 'retired'),
		(SELECT count(*) FROM sites WHERE deleted_at IS NULL)`).Scan(&report.NodeCount, &report.SiteCount); err != nil {
		return fmt.Errorf("read scale: %w", err)
	}
	body, err := json.Marshal(report)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, reporter.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := reporter.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, communityReportMaxRespBody))
	if response.StatusCode/100 != 2 {
		return fmt.Errorf("official service answered %d", response.StatusCode)
	}
	return nil
}
