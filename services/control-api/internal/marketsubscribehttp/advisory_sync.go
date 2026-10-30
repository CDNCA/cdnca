package marketsubscribehttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// License-service plugin runtime exchange (license 069, M2): the controller
// calls the installation mTLS listener with its installation certificate on
// the activation path, selecting the operation by "schema".
const (
	advisorySyncSchema = "cdnca.plugin-security-advisory-sync/v1"
	advisoryAckSchema  = "cdnca.plugin-security-advisory-ack/v1"
	activationPath     = "/installation/v1/plugin-installation-activation-facts:resolve"
	advisoryBodyLimit  = 1 << 20
)

// ErrAdvisoryUnsupported: the license service predates advisory delivery.
var ErrAdvisoryUnsupported = errors.New("license service does not deliver plugin advisories")

// LicenseAdvisoryClient talks to the license service on behalf of this
// installation. HTTP must present the installation client certificate
// (the plugin installation runtime's mTLS client).
type LicenseAdvisoryClient struct {
	endpoint       string
	http           *http.Client
	installationID uuid.UUID
}

func NewLicenseAdvisoryClient(baseURL string, client *http.Client, installationID uuid.UUID) (*LicenseAdvisoryClient, error) {
	if !strings.HasPrefix(baseURL, "https://") || client == nil || installationID == uuid.Nil {
		return nil, ErrStoreInvalid
	}
	return &LicenseAdvisoryClient{endpoint: strings.TrimSuffix(baseURL, "/") + activationPath, http: client,
		installationID: installationID}, nil
}

type deliveredAdvisory struct {
	AdvisoryID       uuid.UUID `json:"advisory_id"`
	PluginID         string    `json:"plugin_id"`
	AffectedVersions string    `json:"affected_versions"`
	FixedVersion     string    `json:"fixed_version"`
	Severity         string    `json:"severity"`
	Action           string    `json:"action"`
	TitleZhCN        string    `json:"title_zh_cn"`
	BodyZhCN         string    `json:"body_zh_cn"`
	PublishedAt      time.Time `json:"published_at"`
}

// Delivered returns the published advisories for this installation, one per
// advisory (the license service lists one row per affected authorization).
func (c *LicenseAdvisoryClient) Delivered(ctx context.Context) ([]Advisory, error) {
	var out struct {
		Schema         string              `json:"schema"`
		InstallationID uuid.UUID           `json:"installation_id"`
		Advisories     []deliveredAdvisory `json:"advisories"`
	}
	if err := c.post(ctx, map[string]any{"schema": advisorySyncSchema, "installation_id": c.installationID}, &out); err != nil {
		return nil, err
	}
	if out.Schema != advisorySyncSchema || out.InstallationID != c.installationID || out.Advisories == nil {
		return nil, fmt.Errorf("license advisory sync: unexpected response")
	}
	seen := map[uuid.UUID]bool{}
	items := make([]Advisory, 0, len(out.Advisories))
	for _, d := range out.Advisories {
		if d.AdvisoryID == uuid.Nil || seen[d.AdvisoryID] {
			continue
		}
		seen[d.AdvisoryID] = true
		items = append(items, Advisory{ID: d.AdvisoryID, PluginID: d.PluginID, AffectedVersions: d.AffectedVersions,
			FixedVersion: d.FixedVersion, Severity: d.Severity, Action: d.Action, Title: d.TitleZhCN, Body: d.BodyZhCN,
			PublishedAt: d.PublishedAt.UTC()})
	}
	return items, nil
}

// Acknowledge records the installation's acknowledgement upstream (idempotent there).
func (c *LicenseAdvisoryClient) Acknowledge(ctx context.Context, advisory uuid.UUID) error {
	var out struct {
		AdvisoryID uuid.UUID `json:"advisory_id"`
	}
	if err := c.post(ctx, map[string]any{"schema": advisoryAckSchema, "installation_id": c.installationID,
		"advisory_id": advisory}, &out); err != nil {
		return err
	}
	if out.AdvisoryID != advisory {
		return fmt.Errorf("license advisory ack: unexpected response")
	}
	return nil
}

func (c *LicenseAdvisoryClient) post(ctx context.Context, body, into any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("X-Request-ID", uuid.NewString())
	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("license advisory exchange: %w", err)
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(response.Body, advisoryBodyLimit+1))
	if err != nil || len(payload) > advisoryBodyLimit {
		return fmt.Errorf("license advisory exchange: response too large")
	}
	if response.StatusCode == http.StatusBadRequest {
		// An older license service refuses the unknown schema as invalid_request.
		return ErrAdvisoryUnsupported
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("license advisory exchange: status %d", response.StatusCode)
	}
	if err := json.Unmarshal(payload, into); err != nil {
		return fmt.Errorf("license advisory exchange: %w", err)
	}
	return nil
}

// AdvisoryUpstream is LicenseAdvisoryClient's contract, for tests.
type AdvisoryUpstream interface {
	Delivered(ctx context.Context) ([]Advisory, error)
	Acknowledge(ctx context.Context, advisory uuid.UUID) error
}

// AdvisoryStorage is the PostgresStore side of the sync.
type AdvisoryStorage interface {
	ReplaceDelivered(ctx context.Context, delivered []Advisory) error
	UnreportedPlatformAcks(ctx context.Context) ([]uuid.UUID, error)
	MarkReported(ctx context.Context, advisory uuid.UUID) error
}

// AdvisorySync pulls delivered advisories and pushes platform
// acknowledgements. Run loops; Report pushes acknowledgements now.
type AdvisorySync struct {
	upstream AdvisoryUpstream
	store    AdvisoryStorage
	interval time.Duration
	log      *slog.Logger
	mu       sync.Mutex
}

func NewAdvisorySync(upstream AdvisoryUpstream, store AdvisoryStorage, interval time.Duration, log *slog.Logger) *AdvisorySync {
	if interval <= 0 {
		interval = 10 * time.Minute
	}
	if log == nil {
		log = slog.Default()
	}
	return &AdvisorySync{upstream: upstream, store: store, interval: interval, log: log}
}

// Once pulls the delivered set and then reports pending acknowledgements.
func (s *AdvisorySync) Once(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delivered, err := s.upstream.Delivered(ctx)
	if err != nil {
		return err
	}
	if err := s.store.ReplaceDelivered(ctx, delivered); err != nil {
		return err
	}
	return s.report(ctx)
}

func (s *AdvisorySync) Report(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.report(ctx)
}

func (s *AdvisorySync) report(ctx context.Context) error {
	pending, err := s.store.UnreportedPlatformAcks(ctx)
	if err != nil {
		return err
	}
	for _, advisory := range pending {
		if err := s.upstream.Acknowledge(ctx, advisory); err != nil {
			return err
		}
		if err := s.store.MarkReported(ctx, advisory); err != nil {
			return err
		}
	}
	return nil
}

// Run syncs at start and then every interval until ctx ends. An older license
// service is logged once per run and retried at the next interval.
func (s *AdvisorySync) Run(ctx context.Context) error {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		if err := s.Once(ctx); err != nil && ctx.Err() == nil {
			s.log.Warn("plugin advisory sync failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}
