package nativebackup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/controlupgrade"
)

// fix-btenv5: a migrated control plane is restored while the control-plane
// domain still resolves to the old host, so the node install trust it
// publishes then names the old addresses. control-api checks the published
// document at start and every NodeInstallTrustCheckInterval against the
// current resolution of the domain and control.env's download port and root
// CA, and republishes it (PublishNodeInstallTrust, the same implementation as
// the installer and verify-migration) when they differ: after the DNS switch
// the copied node install command follows within one interval.
const (
	NodeInstallTrustCheckInterval = 10 * time.Minute
	// NodeInstallTrustAlertAfter consecutive failed checks (30 minutes) raise
	// one notification per failure streak.
	NodeInstallTrustAlertAfter = 3
)

// NodeInstallTrustOutcome is the result of one check.
type NodeInstallTrustOutcome string

const (
	// NodeInstallTrustSkipped: no node upgrade runtime (control.env has no
	// CONTROL_UPGRADE_ARTIFACT_BASE_URL), nothing is published.
	NodeInstallTrustSkipped     NodeInstallTrustOutcome = "skipped"
	NodeInstallTrustInSync      NodeInstallTrustOutcome = "in_sync"
	NodeInstallTrustRepublished NodeInstallTrustOutcome = "republished"
	// NodeInstallTrustFailed: resolution or publication failed; the published
	// files are left as they were.
	NodeInstallTrustFailed NodeInstallTrustOutcome = "failed"
)

// NodeInstallTrustCheck is one check: the download endpoint of control.env
// and, when republished, the new document.
type NodeInstallTrustCheck struct {
	Outcome NodeInstallTrustOutcome
	Host    string
	Port    int
	Trust   NodeInstallTrust
	Err     error
}

// NodeInstallTrustChange is a republication: the download policy the old
// document named (nil when there was none) and the new one.
type NodeInstallTrustChange struct {
	Before         *entitlement.UpgradeDownloadPolicy
	After          entitlement.UpgradeDownloadPolicy
	PreviousSHA256 string
	SHA256         string
}

// NodeInstallTrustAlert is a failure streak that reached
// NodeInstallTrustAlertAfter checks; Since (the first failure) identifies it.
type NodeInstallTrustAlert struct {
	Since    time.Time
	At       time.Time
	Failures int
	Host     string
	Port     int
	Reason   string
}

// NodeInstallTrustWatcher runs the check. Zero values use the host: real
// resolver, wall clock, time.After and PublishNodeInstallTrust.
type NodeInstallTrustWatcher struct {
	Layout  Layout
	Lookup  func(context.Context, string) ([]string, error)
	Publish func(context.Context, Layout, func(context.Context, string) ([]string, error)) (NodeInstallTrust, error)
	Now     func() time.Time
	After   func(time.Duration) <-chan time.Time
	Logger  *slog.Logger
	// OnPublished records a republication (audit); OnAlert queues the failure
	// notification and an error retries it on the next failed check.
	OnPublished func(context.Context, NodeInstallTrustChange)
	OnAlert     func(context.Context, NodeInstallTrustAlert) error

	failures     int
	failingSince time.Time
	alerted      bool
}

var pinnedDigest = regexp.MustCompile(`(?m)^(?:upgrade_trust_sha256=|window\.__CDNCA_NODE_UPGRADE_TRUST_SHA256__ = ")([0-9a-f]{64})"?;?$`)

// Run checks at once and then every NodeInstallTrustCheckInterval until ctx ends.
func (watcher *NodeInstallTrustWatcher) Run(ctx context.Context) {
	after := watcher.After
	if after == nil {
		after = time.After
	}
	for {
		watcher.tick(ctx)
		select {
		case <-ctx.Done():
			return
		case <-after(NodeInstallTrustCheckInterval):
		}
	}
}

// tick is Check with logging and failure streak alerting.
func (watcher *NodeInstallTrustWatcher) tick(ctx context.Context) NodeInstallTrustCheck {
	check := watcher.Check(ctx)
	logger := watcher.Logger
	if logger == nil {
		logger = slog.Default()
	}
	switch check.Outcome {
	case NodeInstallTrustFailed:
		now := watcher.now()
		if watcher.failures == 0 {
			watcher.failingSince = now
		}
		watcher.failures++
		logger.Warn("node install trust check failed; the published document is unchanged", "host", check.Host, "port", check.Port,
			"consecutive_failures", watcher.failures, "error", check.Err)
		if watcher.failures >= NodeInstallTrustAlertAfter && !watcher.alerted && watcher.OnAlert != nil {
			err := watcher.OnAlert(ctx, NodeInstallTrustAlert{Since: watcher.failingSince, At: now, Failures: watcher.failures,
				Host: check.Host, Port: check.Port, Reason: check.Err.Error()})
			if err != nil {
				logger.Error("cannot queue the node install trust failure notification", "error", err)
			}
			watcher.alerted = err == nil
		}
		return check
	case NodeInstallTrustRepublished:
		logger.Info("republished the node install trust", "sha256", check.Trust.SHA256, "host", check.Trust.Download.Host,
			"port", check.Trust.Download.Port, "addresses", check.Trust.Download.Addresses)
	}
	watcher.failures, watcher.alerted = 0, false
	return check
}

// Check compares the published document with control.env and the current
// resolution and republishes it when they differ. A failure writes nothing.
func (watcher *NodeInstallTrustWatcher) Check(ctx context.Context) NodeInstallTrustCheck {
	environment, err := ReadEnvironmentFile(watcher.Layout.Path(ConfigDirectory + "/control.env"))
	if errors.Is(err, os.ErrNotExist) {
		return NodeInstallTrustCheck{Outcome: NodeInstallTrustSkipped}
	}
	if err != nil {
		return NodeInstallTrustCheck{Outcome: NodeInstallTrustFailed, Err: err}
	}
	baseURL := environment["CONTROL_UPGRADE_ARTIFACT_BASE_URL"]
	if baseURL == "" {
		return NodeInstallTrustCheck{Outcome: NodeInstallTrustSkipped}
	}
	check := NodeInstallTrustCheck{Outcome: NodeInstallTrustFailed}
	if parsed, err := url.Parse(baseURL); err == nil {
		check.Host, check.Port = parsed.Hostname(), 443
		if parsed.Port() != "" {
			check.Port, _ = strconv.Atoi(parsed.Port())
		}
	}
	source := controlupgrade.DownloadPolicySource{LookupHost: watcher.Lookup}
	if root := environment["CONTROL_UPGRADE_DOWNLOAD_ROOT_CA_FILE"]; root != "" {
		source.RootCAFile = watcher.Layout.Path(root)
	}
	want, err := source.Resolve(ctx, baseURL)
	if err != nil {
		check.Err = err
		return check
	}
	before, previousSHA, consistent := watcher.published(*want)
	if consistent {
		check.Outcome = NodeInstallTrustInSync
		return check
	}
	publish := watcher.Publish
	if publish == nil {
		publish = PublishNodeInstallTrust
	}
	trust, err := publish(ctx, watcher.Layout, watcher.Lookup)
	if err != nil {
		check.Err = err
		return check
	}
	check.Outcome, check.Trust = NodeInstallTrustRepublished, trust
	if watcher.OnPublished != nil {
		watcher.OnPublished(ctx, NodeInstallTrustChange{Before: before, After: trust.Download, PreviousSHA256: previousSHA, SHA256: trust.SHA256})
	}
	return check
}

// published reads the current document: its download policy, digest, and
// whether it names want and every existing digest pin names it.
func (watcher *NodeInstallTrustWatcher) published(want entitlement.UpgradeDownloadPolicy) (*entitlement.UpgradeDownloadPolicy, string, bool) {
	encoded, err := os.ReadFile(watcher.Layout.Path(NodeInstallTrustFile))
	if err != nil {
		return nil, "", false
	}
	sum := sha256.Sum256(encoded)
	digest := hex.EncodeToString(sum[:])
	var document struct {
		Download *entitlement.UpgradeDownloadPolicy `json:"download"`
	}
	if json.NewDecoder(bytes.NewReader(encoded)).Decode(&document) != nil || document.Download == nil {
		return nil, digest, false
	}
	current := document.Download
	if current.Host != want.Host || current.Port != want.Port || current.RootCA != want.RootCA ||
		!slices.Equal(current.Addresses, want.Addresses) {
		return current, digest, false
	}
	for _, path := range []string{NodeInstallDefaultsFile, WebRuntimeConfigFile} {
		content, err := os.ReadFile(watcher.Layout.Path(path))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		matches := pinnedDigest.FindAllSubmatch(content, -1)
		if err != nil || len(matches) != 1 || string(matches[0][1]) != digest {
			return current, digest, false
		}
	}
	return current, digest, true
}

func (watcher *NodeInstallTrustWatcher) now() time.Time {
	if watcher.Now != nil {
		return watcher.Now()
	}
	return time.Now()
}
