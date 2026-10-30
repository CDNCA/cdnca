package edgesignertrustsync

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement/edgesignertrust"
)

// DefaultDocumentPath is the license service publication endpoint: operators
// upload the offline-signed document in the operator console (versioned and
// audited there) and every control plane pulls the latest revision here.
const DefaultDocumentPath = "/public/v1/edge-signer-trust"

type FetcherConfig struct {
	URL       string
	TLSConfig *tls.Config
	Interval  time.Duration
	Timeout   time.Duration
	Store     DocumentStore
	Logger    *slog.Logger
	// OnAccepted runs after a new revision is stored (the distributor wakes up).
	OnAccepted func()
	// DownloadsDir, when set, is this control plane's edge-agent download
	// directory: artifacts.json and signer-trust.json follow the latest
	// accepted document (PublishDownloads), at start and after each accept.
	DownloadsDir string
}

// DocumentStore is what the fetcher needs of Store.
type DocumentStore interface {
	Accept(ctx context.Context, encoded []byte, source string) (Accepted, error)
	RecordEvent(ctx context.Context, event, reason string, revision uint64, digest []byte) error
	Latest(ctx context.Context) (Accepted, bool, error)
}

// Fetcher downloads the published document. The document carries its own
// offline-root signature, so the download needs no authentication. Outages
// and rejections keep the LKG: a revocation, once accepted, is never lost by
// a failed fetch.
type Fetcher struct {
	config   FetcherConfig
	client   *http.Client
	last     string
	rejected [32]byte // digest of the last rejected download: not re-audited every poll
}

func NewFetcher(config FetcherConfig) (*Fetcher, error) {
	parsed, err := url.Parse(config.URL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" ||
		parsed.Fragment != "" || config.Store == nil || config.Interval < time.Minute || config.Timeout <= 0 ||
		config.Timeout > time.Minute {
		return nil, errors.New("edge signer trust fetcher configuration is invalid")
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if config.TLSConfig != nil {
		tlsConfig = config.TLSConfig.Clone()
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: tlsConfig, ForceAttemptHTTP2: true,
		TLSHandshakeTimeout: config.Timeout, ResponseHeaderTimeout: config.Timeout, MaxIdleConns: 1}
	client := &http.Client{Transport: transport, Timeout: config.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &Fetcher{config: config, client: client}, nil
}

func (fetcher *Fetcher) Run(ctx context.Context) error {
	if latest, found, err := fetcher.config.Store.Latest(ctx); err != nil {
		fetcher.config.Logger.Warn("edge signer trust LKG unavailable", "error", err)
	} else if found {
		fetcher.publish(latest)
	}
	ticker := time.NewTicker(fetcher.config.Interval)
	defer ticker.Stop()
	for {
		fetcher.FetchOnce(ctx)
		select {
		case <-ctx.Done():
			fetcher.client.CloseIdleConnections()
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// FetchOnce runs one fetch and returns the outcome reason.
func (fetcher *Fetcher) FetchOnce(ctx context.Context) string {
	encoded, reason := fetcher.download(ctx)
	if reason == "" && sha256.Sum256(encoded) == fetcher.rejected {
		return fetcher.last
	}
	if reason == "" {
		accepted, err := fetcher.config.Store.Accept(ctx, encoded, SourceFetch)
		var rejected *RejectedError
		switch {
		case errors.As(err, &rejected):
			reason = rejected.Reason
			fetcher.rejected = sha256.Sum256(encoded)
		case err != nil:
			fetcher.config.Logger.Warn("edge signer trust document could not be stored", "error", err)
			return "storage_failure"
		case accepted.Replayed:
			reason = ReasonReplayed
		default:
			reason = ReasonAccepted
			fetcher.config.Logger.Info("edge signer trust document accepted", "revision", accepted.Revision)
			fetcher.publish(accepted)
			if fetcher.config.OnAccepted != nil {
				fetcher.config.OnAccepted()
			}
		}
	} else if reason != fetcher.last {
		if err := fetcher.config.Store.RecordEvent(ctx, "unavailable", reason, 0, nil); err != nil {
			fetcher.config.Logger.Warn("edge signer trust outage could not be recorded", "error", err)
		}
	}
	if reason != fetcher.last && reason != ReasonReplayed && reason != ReasonAccepted {
		level := slog.LevelWarn
		if reason == ReasonNotPublished {
			level = slog.LevelInfo
		}
		fetcher.config.Logger.Log(ctx, level, "edge signer trust document not applied; last accepted revision kept",
			"reason", reason, "event", "edge_signer_trust.retained")
	}
	fetcher.last = reason
	return reason
}

func (fetcher *Fetcher) publish(accepted Accepted) {
	if fetcher.config.DownloadsDir == "" {
		return
	}
	conflicts, err := edgesignertrust.PublishDownloads(fetcher.config.DownloadsDir, accepted.Document)
	if err != nil {
		fetcher.config.Logger.Error("edge download trust not refreshed; new nodes may still trust a revoked key",
			"revision", accepted.Revision, "error", err, "event", "edge_signer_trust.downloads_failed")
		return
	}
	if len(conflicts) > 0 {
		fetcher.config.Logger.Warn("edge signer trust keys conflict with artifacts.json entries; existing kept",
			"key_ids", conflicts)
	}
}

func (fetcher *Fetcher) download(ctx context.Context) ([]byte, string) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, fetcher.config.URL, nil)
	if err != nil {
		return nil, ReasonNetwork
	}
	request.Header.Set("Accept", "application/json")
	response, err := fetcher.client.Do(request)
	if err != nil {
		return nil, ReasonNetwork
	}
	defer response.Body.Close()
	switch {
	case response.StatusCode == http.StatusNotFound:
		return nil, ReasonNotPublished
	case response.StatusCode != http.StatusOK:
		return nil, ReasonServer
	}
	encoded, err := io.ReadAll(io.LimitReader(response.Body, edgesignertrust.MaxDocumentBytes+4097))
	if err != nil {
		return nil, ReasonNetwork
	}
	if len(encoded) > edgesignertrust.MaxDocumentBytes+4096 {
		return nil, ReasonInvalid
	}
	return encoded, ""
}

// DocumentURL joins the licensing origin and DefaultDocumentPath.
func DocumentURL(origin string) (string, error) {
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || (parsed.Path != "" && parsed.Path != "/") {
		return "", fmt.Errorf("licensing origin %q is not an https origin", origin)
	}
	return "https://" + parsed.Host + DefaultDocumentPath, nil
}
