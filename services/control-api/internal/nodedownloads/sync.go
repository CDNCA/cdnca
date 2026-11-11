// Package nodedownloads keeps the console's /downloads/edge-agent/latest node
// package current: install-control.sh writes it once at
// install time and a management upgrade never refreshed it (a console kept the
// package of its install day, so 重装此节点 installed an agent without later fixes). The
// syncer fetches the latest package from the release server, verifies it with
// install-node.sh --verify-native-package against this console's
// edge-agent/artifacts.json (the same check install-control.sh runs), accepts
// only the running control version and only then replaces the served copy.
// A failed fetch or verification keeps the served package and is reported in
// Status (maintenance upgrade status) and the log.
package nodedownloads

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	ArchiveName   = "cdnca-edge-agent.tar.gz"
	ChecksumsName = "SHA256SUMS"
	// MaxArchive is install-node.sh verify_native_package's MAX_ARCHIVE.
	MaxArchive   = 512 << 20
	maxChecksums = 4096
)

// State values of Status.State.
const (
	StatePending  = "pending"
	StateCurrent  = "current"
	StateWaiting  = "waiting_for_control_upgrade"
	StateFailed   = "failed"
	StateDisabled = "disabled"
)

// Facts is the verified release identity install-node.sh prints.
type Facts struct {
	Version string `json:"version"`
	Source  struct {
		Commit string `json:"commit"`
	} `json:"source"`
}

// Config wires a Syncer. Verify defaults to install-node.sh; tests replace it.
type Config struct {
	// Source is the release server origin (commercial: LICENSE_SERVICE_URL,
	// community: the --release-server base); packages are read from
	// <Source>/downloads/edge-agent/latest/.
	Source string
	// DownloadDir is the served /downloads directory (DATA_DIR/downloads).
	DownloadDir string
	// Installers are tried in order for --verify-native-package (the active
	// release's served copy first, then the install-time copy).
	Installers     []string
	ControlVersion string
	Interval       time.Duration
	Client         *http.Client
	Verify         func(ctx context.Context, archive, trust, stage string) (Facts, error)
	Logger         *slog.Logger
	Now            func() time.Time
}

// Status is what the maintenance upgrade page shows.
type Status struct {
	State         string     `json:"state"`
	Reason        string     `json:"reason,omitempty"`
	ServedSHA256  string     `json:"served_sha256,omitempty"`
	SourceSHA256  string     `json:"source_sha256,omitempty"`
	SourceVersion string     `json:"source_version,omitempty"`
	CheckedAt     *time.Time `json:"checked_at,omitempty"`
	UpdatedAt     *time.Time `json:"updated_at,omitempty"`
}

// Syncer runs the periodic check (runtimeWorker).
type Syncer struct {
	config Config
	latest string
	mu     sync.Mutex
	status Status
	// refused: a verified digest of another version (do not download it again).
	refused map[string]Facts
}

var sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// SourceURL validates an https origin (a path prefix is kept: the community
// release server is https://www.cdnca.com/downloads/ce).
func SourceURL(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("node downloads source %q is not an https URL", raw)
	}
	return parsed.String(), nil
}

func New(config Config) (*Syncer, error) {
	source, err := SourceURL(config.Source)
	if err != nil {
		return nil, err
	}
	config.Source = source
	if !filepath.IsAbs(config.DownloadDir) || filepath.Clean(config.DownloadDir) != config.DownloadDir || config.ControlVersion == "" ||
		config.Interval <= 0 {
		return nil, errors.New("node downloads syncer needs an absolute download directory, the control version and an interval")
	}
	if config.Client == nil {
		config.Client = &http.Client{Timeout: 15 * time.Minute}
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Verify == nil {
		installers := config.Installers
		config.Verify = func(ctx context.Context, archive, trust, stage string) (Facts, error) {
			return verifyWithInstaller(ctx, installers, archive, trust, stage)
		}
	}
	return &Syncer{config: config, latest: filepath.Join(config.DownloadDir, "edge-agent", "latest"),
		status: Status{State: StatePending}, refused: map[string]Facts{}}, nil
}

// DisabledStatus is reported when the syncer is switched off.
func DisabledStatus(reason string) Status { return Status{State: StateDisabled, Reason: reason} }

func (s *Syncer) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status
}

func (s *Syncer) Run(ctx context.Context) error {
	ticker := time.NewTicker(s.config.Interval)
	defer ticker.Stop()
	for {
		s.SyncOnce(ctx)
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// SyncOnce runs one check and records its Status.
func (s *Syncer) SyncOnce(ctx context.Context) Status {
	now := s.config.Now().UTC()
	s.mu.Lock()
	status := Status{CheckedAt: &now, UpdatedAt: s.status.UpdatedAt}
	s.mu.Unlock()
	status.ServedSHA256, _ = readDigest(filepath.Join(s.latest, ChecksumsName))
	var err error
	status.State, status.Reason, err = s.sync(ctx, &status)
	switch status.State {
	case StateFailed:
		// The served package is untouched; the next interval retries.
		s.config.Logger.Warn("node downloads not updated; the console keeps serving its current node package",
			"reason", status.Reason, "error", err, "source", s.config.Source)
	case StateWaiting:
		s.config.Logger.Info("node downloads wait for a management upgrade: the release server's latest node package is another version",
			"source_version", status.SourceVersion, "control_version", s.config.ControlVersion)
	}
	s.mu.Lock()
	s.status = status
	s.mu.Unlock()
	return status
}

func (s *Syncer) sync(ctx context.Context, status *Status) (string, string, error) {
	base := s.config.Source + "/downloads/edge-agent/latest/"
	var sums strings.Builder
	if err := s.fetch(ctx, base+ChecksumsName, maxChecksums, &sums); err != nil {
		return StateFailed, "source_unreachable", err
	}
	digest, err := archiveDigest(sums.String())
	if err != nil {
		return StateFailed, "source_checksum_invalid", err
	}
	status.SourceSHA256 = digest
	if info, err := os.Lstat(filepath.Join(s.latest, ArchiveName)); err == nil && info.Mode().IsRegular() && digest == status.ServedSHA256 {
		return StateCurrent, "", nil
	}
	s.mu.Lock()
	refused, known := s.refused[digest]
	s.mu.Unlock()
	if known {
		status.SourceVersion = refused.Version
		return StateWaiting, "source_version_differs", nil
	}
	stage, err := os.MkdirTemp(filepath.Dir(s.config.DownloadDir), ".node-downloads-stage-")
	if err != nil {
		return StateFailed, "write_failed", err
	}
	defer os.RemoveAll(stage)
	archive := filepath.Join(stage, ArchiveName)
	if err := s.download(ctx, base+ArchiveName, archive, digest); err != nil {
		return StateFailed, "download_failed", err
	}
	facts, err := s.config.Verify(ctx, archive, filepath.Join(s.config.DownloadDir, "edge-agent", "artifacts.json"),
		filepath.Join(stage, "verify"))
	if err != nil {
		return StateFailed, "signature_invalid", err
	}
	status.SourceVersion = facts.Version
	if facts.Version != s.config.ControlVersion {
		// install-control.sh pairs node and management packages of one version;
		// a newer release waits until this console is upgraded to it.
		s.mu.Lock()
		s.refused[digest] = facts
		s.mu.Unlock()
		return StateWaiting, "source_version_differs", nil
	}
	if err := s.replace(stage, archive, digest); err != nil {
		return StateFailed, "write_failed", err
	}
	now := s.config.Now().UTC()
	status.ServedSHA256, status.UpdatedAt = digest, &now
	s.config.Logger.Info("node downloads updated to the release server's verified node package",
		"version", facts.Version, "source_commit", facts.Source.Commit, "sha256", digest)
	return StateCurrent, "", nil
}

// replace renames the archive first, then SHA256SUMS: an installer that read
// the old SHA256SUMS in between refuses the new archive and is run again.
func (s *Syncer) replace(stage, archive, digest string) error {
	if err := os.MkdirAll(s.latest, 0o755); err != nil {
		return err
	}
	sums := filepath.Join(stage, ChecksumsName)
	if err := os.WriteFile(sums, []byte(digest+"  "+ArchiveName+"\n"), 0o644); err != nil {
		return err
	}
	for _, name := range []string{archive, sums} {
		if err := os.Chmod(name, 0o644); err != nil {
			return err
		}
	}
	if err := os.Rename(archive, filepath.Join(s.latest, ArchiveName)); err != nil {
		return err
	}
	if err := os.Rename(sums, filepath.Join(s.latest, ChecksumsName)); err != nil {
		return err
	}
	if directory, err := os.Open(s.latest); err == nil {
		_ = directory.Sync()
		_ = directory.Close()
	}
	return nil
}

func (s *Syncer) download(ctx context.Context, address, path, digest string) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	hash := sha256.New()
	err = s.fetch(ctx, address, MaxArchive, io.MultiWriter(file, hash))
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err == nil && hex.EncodeToString(hash.Sum(nil)) != digest {
		err = errors.New("archive does not match the release server SHA256SUMS")
	}
	return err
}

func (s *Syncer) fetch(ctx context.Context, address string, limit int64, out io.Writer) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return err
	}
	response, err := s.config.Client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: HTTP %d", address, response.StatusCode)
	}
	written, err := io.Copy(out, io.LimitReader(response.Body, limit+1))
	if err == nil && written > limit {
		err = fmt.Errorf("GET %s: larger than %d bytes", address, limit)
	}
	return err
}

// archiveDigest reads the archive line of a SHA256SUMS file.
func archiveDigest(sums string) (string, error) {
	scanner := bufio.NewScanner(strings.NewReader(sums))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 2 && strings.TrimPrefix(strings.TrimPrefix(fields[1], "*"), "./") == ArchiveName &&
			sha256Pattern.MatchString(fields[0]) {
			return fields[0], nil
		}
	}
	return "", errors.New("SHA256SUMS has no " + ArchiveName + " line")
}

func readDigest(path string) (string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return archiveDigest(string(content))
}

// verifyWithInstaller runs install-node.sh --verify-native-package (signature,
// inventory, platform and safe extraction; the pinned Ed25519 tool) and reads
// the release facts it prints.
func verifyWithInstaller(ctx context.Context, installers []string, archive, trust, stage string) (Facts, error) {
	installer := ""
	for _, candidate := range installers {
		if info, err := os.Lstat(candidate); err == nil && info.Mode().IsRegular() {
			installer = candidate
			break
		}
	}
	if installer == "" {
		return Facts{}, errors.New("no install-node.sh to verify the node package with")
	}
	var stdout, stderr strings.Builder
	command := exec.CommandContext(ctx, "bash", installer, "--verify-native-package", archive, trust, stage)
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		return Facts{}, fmt.Errorf("%s --verify-native-package: %w: %s", installer, err, strings.TrimSpace(lastLine(stderr.String())))
	}
	var facts Facts
	if err := json.Unmarshal([]byte(lastLine(stdout.String())), &facts); err != nil || facts.Version == "" {
		return Facts{}, errors.New("install-node.sh --verify-native-package printed no release facts")
	}
	return facts, nil
}

func lastLine(text string) string {
	lines := strings.Split(strings.TrimSpace(text), "\n")
	return lines[len(lines)-1]
}
