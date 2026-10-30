//go:build !windows

package controlplaneupgrade

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
)

type SystemdConfig struct {
	ReleaseRoot     string
	CurrentLink     string
	UnitName        string
	DrainURL        string
	ResumeURL       string
	HealthURL       string
	InternalToken   string
	InstallationID  string
	CurrentVersion  string
	ProtocolVersion int
	HTTPClient      *http.Client
	PollInterval    time.Duration
	StepTimeout     time.Duration
	HealthTimeout   time.Duration
}

type commandRunner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}

type execCommands struct{}

func (execCommands) Run(ctx context.Context, name string, arguments ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, arguments...).CombinedOutput()
}

type SystemdExecutor struct {
	config   SystemdConfig
	client   *http.Client
	control  *internalControlClient
	commands commandRunner
}

func NewSystemdExecutor(config SystemdConfig) (*SystemdExecutor, error) {
	return newSystemdExecutor(config, execCommands{})
}

func newSystemdExecutor(config SystemdConfig, commands commandRunner) (*SystemdExecutor, error) {
	if !filepath.IsAbs(config.ReleaseRoot) || !filepath.IsAbs(config.CurrentLink) ||
		filepath.Dir(config.CurrentLink) != filepath.Clean(config.ReleaseRoot) || !validMeta(config.UnitName, 128) ||
		config.CurrentVersion == "" || config.ProtocolVersion < 1 || commands == nil ||
		!validSystemdURL(config.DrainURL, config.HTTPClient != nil) ||
		!validSystemdURL(config.ResumeURL, config.HTTPClient != nil) ||
		!validSystemdURL(config.HealthURL, config.HTTPClient != nil) {
		return nil, ErrInvalidConfig
	}
	if parsedInstallationID, err := uuid.Parse(config.InstallationID); err != nil ||
		parsedInstallationID == uuid.Nil || parsedInstallationID.String() != config.InstallationID {
		return nil, ErrInvalidConfig
	}
	paths := []string{config.ReleaseRoot, filepath.Join(config.ReleaseRoot, "releases")}
	for index, path := range paths {
		info, err := os.Lstat(path)
		if index == 1 && os.IsNotExist(err) {
			if err := os.Mkdir(path, 0o700); err != nil {
				return nil, err
			}
			info, err = os.Lstat(path)
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, ErrInvalidConfig
		}
		if info.Mode().Perm() != 0o700 && os.Chmod(path, 0o700) != nil {
			return nil, ErrInvalidConfig
		}
	}
	client := config.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	if config.PollInterval <= 0 {
		config.PollInterval = time.Second
	}
	if config.HealthTimeout <= 0 {
		config.HealthTimeout = 10 * time.Minute
	}
	if config.StepTimeout <= 0 {
		config.StepTimeout = 3 * time.Minute
	}
	if config.StepTimeout < 10*time.Second || config.StepTimeout > 30*time.Minute {
		return nil, ErrInvalidConfig
	}
	control, err := newInternalControlClient(client, config.InternalToken, config.DrainURL, config.ResumeURL,
		config.HealthURL, config.PollInterval, config.HealthTimeout)
	if err != nil {
		return nil, err
	}
	return &SystemdExecutor{config: config, client: client, control: control, commands: commands}, nil
}

func (executor *SystemdExecutor) Target() Target { return TargetSystemd }

func (executor *SystemdExecutor) Facts(context.Context) (Facts, error) {
	release, err := executor.currentRelease()
	if err != nil {
		return Facts{}, err
	}
	digest := filepath.Base(release)
	physicalDigest, _, err := digestRegularFile(filepath.Join(release, "control-api"), 1<<30)
	if err != nil || physicalDigest != digest {
		return Facts{}, ErrTargetMismatch
	}
	version := executor.config.CurrentVersion
	encoded, err := os.ReadFile(filepath.Join(release, "release.json"))
	if err == nil {
		var metadata struct {
			Version string `json:"version"`
			Digest  string `json:"sha256"`
		}
		if json.Unmarshal(encoded, &metadata) != nil || metadata.Digest != digest || metadata.Version == "" {
			return Facts{}, ErrTargetMismatch
		}
		version = metadata.Version
	}
	if !digestPattern.MatchString(digest) || version == "" {
		return Facts{}, ErrTargetMismatch
	}
	return Facts{InstallationID: executor.config.InstallationID, CurrentVersion: version,
		CurrentDigest: digest, ProtocolVersion: executor.config.ProtocolVersion}, nil
}

func (executor *SystemdExecutor) Expand(ctx context.Context, plan Plan) error {
	binary, err := executor.ensureArtifact(ctx, plan.Target)
	if err != nil {
		return err
	}
	_, err = executor.migrate(ctx, binary, "expand")
	return err
}

func (executor *SystemdExecutor) Preflight(ctx context.Context, plan Plan) error {
	binary, err := executor.verifyArtifact(plan.Target)
	if err != nil {
		return err
	}
	output, err := executor.runCommand(ctx, binary, "--version")
	if err != nil || strings.TrimSpace(string(output)) != plan.Target.Version {
		return ErrTargetMismatch
	}
	return nil
}

func (executor *SystemdExecutor) Drain(ctx context.Context, plan Plan) error {
	return executor.control.drain(ctx, plan)
}

func (executor *SystemdExecutor) Resume(ctx context.Context, plan Plan) error {
	return executor.control.resume(ctx, plan)
}

func (executor *SystemdExecutor) Activate(ctx context.Context, plan Plan) error {
	if _, err := executor.ensureArtifact(ctx, plan.Target); err != nil {
		return err
	}
	return executor.switchRelease(ctx, plan.Target)
}

func (executor *SystemdExecutor) Rollback(ctx context.Context, plan Plan) error {
	if _, err := executor.verifyArtifact(plan.Rollback); err != nil {
		return err
	}
	return executor.switchRelease(ctx, plan.Rollback)
}

func (executor *SystemdExecutor) Health(ctx context.Context, plan Plan, artifact Artifact) error {
	ctx, cancel := context.WithTimeout(ctx, executor.config.HealthTimeout)
	defer cancel()
	ticker := time.NewTicker(executor.config.PollInterval)
	defer ticker.Stop()
	for {
		release, linkErr := executor.currentRelease()
		binary, artifactErr := executor.verifyArtifact(artifact)
		var output []byte
		versionErr := artifactErr
		if artifactErr == nil {
			output, versionErr = executor.runCommand(ctx, binary, "--version")
		}
		if linkErr == nil && artifactErr == nil && filepath.Base(release) == artifact.Digest && versionErr == nil &&
			strings.TrimSpace(string(output)) == artifact.Version {
			return executor.control.health(ctx, plan, artifact)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (executor *SystemdExecutor) Contract(ctx context.Context, plan Plan) error {
	binary, err := executor.verifyArtifact(plan.Target)
	if err != nil {
		return err
	}
	_, err = executor.migrate(ctx, binary, "contract")
	return err
}

func (executor *SystemdExecutor) migrate(ctx context.Context, binary, phase string) ([]byte, error) {
	if phase != "expand" && phase != "contract" {
		return nil, ErrInvalidPlan
	}
	return executor.runCommand(ctx, "/usr/bin/env", "CDNCA_MIGRATION_PHASE="+phase, binary, "migrate", "up")
}

func (executor *SystemdExecutor) runCommand(ctx context.Context, name string, arguments ...string) ([]byte, error) {
	stepContext, cancel := context.WithTimeout(ctx, executor.config.StepTimeout)
	defer cancel()
	output, err := executor.commands.Run(stepContext, name, arguments...)
	if stepContext.Err() != nil {
		return output, stepContext.Err()
	}
	return output, err
}

func (executor *SystemdExecutor) ensureArtifact(ctx context.Context, artifact Artifact) (string, error) {
	binary := executor.binary(artifact)
	if _, err := os.Lstat(binary); err == nil {
		return executor.verifyArtifact(artifact)
	} else if !os.IsNotExist(err) {
		return "", ErrPlanConflict
	}
	parsed, err := url.Parse(artifact.URL)
	if err != nil || (parsed.Scheme != "https" && !(parsed.Scheme == "http" && executor.config.HTTPClient != nil)) {
		return "", ErrInvalidPlan
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, artifact.URL, nil)
	if err != nil {
		return "", err
	}
	response, err := executor.client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", fmt.Errorf("artifact download status %d", response.StatusCode)
	}
	encoded, err := io.ReadAll(io.LimitReader(response.Body, artifact.Size+1))
	if err != nil || int64(len(encoded)) != artifact.Size {
		return "", ErrInvalidPlan
	}
	digest := sha256.Sum256(encoded)
	if fmt.Sprintf("%x", digest) != artifact.Digest {
		return "", ErrInvalidPlan
	}
	release := filepath.Dir(binary)
	if err := os.Mkdir(release, 0o700); err != nil && !os.IsExist(err) {
		return "", err
	}
	releaseInfo, err := os.Lstat(release)
	if err != nil || !releaseInfo.IsDir() || releaseInfo.Mode()&os.ModeSymlink != 0 ||
		releaseInfo.Mode().Perm()&0o077 != 0 {
		return "", ErrPlanConflict
	}
	temporary, err := os.CreateTemp(release, ".control-api-*.tmp")
	if err != nil {
		return "", err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if temporary.Chmod(0o500) != nil {
		_ = temporary.Close()
		return "", ErrInvalidPlan
	}
	if _, err := temporary.Write(encoded); err != nil || temporary.Sync() != nil || temporary.Close() != nil {
		_ = temporary.Close()
		return "", ErrInvalidPlan
	}
	if err := os.Rename(temporaryPath, binary); err != nil {
		return "", err
	}
	metadata, _ := json.Marshal(struct {
		Version string `json:"version"`
		Digest  string `json:"sha256"`
	}{artifact.Version, artifact.Digest})
	if err := writeAtomicFile(release, "release.json", metadata, 0o600); err != nil {
		return "", err
	}
	return binary, syncDirectory(release)
}

func (executor *SystemdExecutor) switchRelease(ctx context.Context, artifact Artifact) error {
	binary, err := executor.verifyArtifact(artifact)
	if err != nil {
		return err
	}
	release := filepath.Dir(binary)
	current, err := executor.currentRelease()
	if err == nil && current == release {
		return nil
	}
	temporary := executor.config.CurrentLink + ".new"
	_ = os.Remove(temporary)
	if err := os.Symlink(release, temporary); err != nil {
		return err
	}
	if err := os.Rename(temporary, executor.config.CurrentLink); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	if err := syncDirectory(executor.config.ReleaseRoot); err != nil {
		return err
	}
	_, err = executor.runCommand(ctx, "systemctl", "restart", executor.config.UnitName)
	return err
}

func (executor *SystemdExecutor) binary(artifact Artifact) string {
	return filepath.Join(executor.config.ReleaseRoot, "releases", artifact.Digest, "control-api")
}

func (executor *SystemdExecutor) currentRelease() (string, error) {
	target, err := os.Readlink(executor.config.CurrentLink)
	if err != nil || !filepath.IsAbs(target) || target != filepath.Clean(target) ||
		filepath.Dir(target) != filepath.Join(executor.config.ReleaseRoot, "releases") {
		return "", ErrTargetMismatch
	}
	info, err := os.Lstat(target)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", ErrTargetMismatch
	}
	return target, nil
}

func (executor *SystemdExecutor) verifyArtifact(artifact Artifact) (string, error) {
	if artifact.Size <= 0 || artifact.Size > 1<<30 || !digestPattern.MatchString(artifact.Digest) {
		return "", ErrInvalidPlan
	}
	binary := executor.binary(artifact)
	releaseInfo, err := os.Lstat(filepath.Dir(binary))
	if err != nil || !releaseInfo.IsDir() || releaseInfo.Mode()&os.ModeSymlink != 0 ||
		releaseInfo.Mode().Perm()&0o077 != 0 {
		return "", ErrPlanConflict
	}
	digest, size, err := digestRegularFile(binary, artifact.Size)
	if err != nil || digest != artifact.Digest || size != artifact.Size {
		return "", ErrPlanConflict
	}
	return binary, nil
}

func digestRegularFile(path string, maximum int64) (string, int64, error) {
	info, err := os.Lstat(path)
	stat, ok := infoSysStat(info)
	if err != nil || info == nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 ||
		!ok || stat.Nlink != 1 || info.Size() <= 0 || info.Size() > maximum {
		return "", 0, ErrPlanConflict
	}
	file, err := os.Open(path)
	if err != nil {
		return "", 0, ErrPlanConflict
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	openedStat, openedOK := infoSysStat(openedInfo)
	if err != nil || !openedOK || openedStat.Dev != stat.Dev || openedStat.Ino != stat.Ino {
		return "", 0, ErrPlanConflict
	}
	hasher := sha256.New()
	size, err := io.Copy(hasher, io.LimitReader(file, maximum+1))
	if err != nil || size != info.Size() {
		return "", 0, ErrPlanConflict
	}
	return fmt.Sprintf("%x", hasher.Sum(nil)), size, nil
}

func validSystemdURL(value string, allowHTTP bool) bool {
	if validHTTPURL(value, allowHTTP) {
		return true
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "http" {
		return false
	}
	host := parsed.Hostname()
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func writeAtomicFile(root, name string, content []byte, mode os.FileMode) error {
	temporary, err := os.CreateTemp(root, "."+name+"-*.tmp")
	if err != nil {
		return err
	}
	path := temporary.Name()
	defer os.Remove(path)
	if err := temporary.Chmod(mode); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(content); err != nil || temporary.Sync() != nil || temporary.Close() != nil {
		_ = temporary.Close()
		return ErrInvalidPlan
	}
	if err := os.Rename(path, filepath.Join(root, name)); err != nil {
		return err
	}
	return syncDirectory(root)
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
