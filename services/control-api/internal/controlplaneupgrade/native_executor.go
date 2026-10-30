//go:build !windows

package controlplaneupgrade

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/mod/semver"
)

type nativeExecutor struct {
	config   NativeStandaloneConfig
	owner    uint32
	commands commandRunner
	inspect  nativeProcessInspector
	now      func() time.Time
	client   *http.Client
	// webClient checks WebIndexURL; it is client unless WebCAFile is set.
	webClient *http.Client
	platform  NativePlatform
	syncDir   func(string) error
	// runnerUnit is the runner's own systemd unit, for its journal tail; empty
	// falls back to the runner PID.
	runnerUnit string
	// Database migration boundary; tests replace these.
	database   nativeDatabase
	controlDSN func(context.Context) (string, error)
	freeSpace  func(string) (int64, error)
	backupDir  string
}

func (*nativeExecutor) Target() Target { return TargetNativeStandalone }

func (executor *nativeExecutor) Facts(context.Context) (Facts, error) {
	artifact, manifest, err := executor.current()
	if err != nil {
		return Facts{}, err
	}
	return Facts{InstallationID: executor.config.InstallationID, CurrentVersion: manifest.Version,
		CurrentDigest: artifact.Digest, ProtocolVersion: executor.config.ProtocolVersion}, nil
}

func (executor *nativeExecutor) Expand(ctx context.Context, plan Plan) error {
	currentArtifact, current, err := executor.current()
	if err != nil || currentArtifact.Digest != plan.Rollback.Digest || current.Version != plan.CurrentVersion {
		return ErrTargetMismatch
	}
	if err := executor.verifyServices(ctx, current); err != nil {
		logRun(ctx, RunLogEntry{Level: "error", Event: "services_check_failed", Version: current.Version})
		return err
	}
	logRun(ctx, RunLogEntry{Level: "info", Event: "services_verified", Version: current.Version})
	candidate, err := executor.ensureArchive(ctx, plan.Target)
	if err != nil {
		return err
	}
	if err := nativeCandidateLineage(current, candidate); err != nil {
		logRun(ctx, RunLogEntry{Level: "error", Event: "lineage_rejected", Reason: nativeLineageReason(current, candidate), Version: candidate.Version})
		return err
	}
	if err := executor.verifySource(ctx, current, candidate); err != nil {
		logRun(ctx, RunLogEntry{Level: "error", Event: "source_rejected", Version: candidate.Version})
		return err
	}
	logRun(ctx, RunLogEntry{Level: "info", Event: "lineage_verified", Version: candidate.Version})
	// Only an append-only migration set passes lineage; it is applied after
	// Drain from a database backup (see native_migration_exec.go).
	if err := executor.stage(plan, current, candidate); err != nil {
		logRun(ctx, RunLogEntry{Level: "error", Event: "stage_failed", Version: candidate.Version})
		return err
	}
	logRun(ctx, RunLogEntry{Level: "info", Event: "release_staged", Version: candidate.Version, Count: len(candidate.Files)})
	return nil
}

func (executor *nativeExecutor) Preflight(ctx context.Context, plan Plan) error {
	current, err := executor.verifyArtifact(plan.Rollback)
	if err != nil {
		return err
	}
	candidate, err := executor.verifyArtifact(plan.Target)
	if err != nil {
		return ErrTargetMismatch
	}
	if err := nativeCandidateLineage(current, candidate); err != nil {
		return err
	}
	if err := executor.verifySource(ctx, current, candidate); err != nil {
		return err
	}
	if err := executor.verifyServices(ctx, current); err != nil {
		return err
	}
	output, err := executor.command(ctx, filepath.Join(executor.release(plan.Target), "bin/control-api"), "--version")
	if err != nil || strings.TrimSpace(string(output)) != plan.Target.Version {
		logRun(ctx, RunLogEntry{Level: "error", Event: "candidate_version_mismatch", Version: plan.Target.Version})
		return ErrTargetMismatch
	}
	logRun(ctx, RunLogEntry{Level: "info", Event: "candidate_version_checked", Version: plan.Target.Version})
	if err := executor.databasePreflight(ctx, plan, current, candidate); err != nil {
		return err
	}
	// Read-only: a ledger the candidate can never apply over is found before Drain.
	return executor.clickhouseMigrate(ctx, plan, candidate, true)
}

func (executor *nativeExecutor) Drain(ctx context.Context, plan Plan) error {
	ctx, cancel := context.WithTimeout(ctx, executor.config.StepTimeout)
	defer cancel()
	lock, err := openNativeLock(executor.config.MaintenanceFile+".lock", executor.owner, false)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := nativeWaitLock(ctx, lock); err != nil {
		return err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	state, err := readNativeMaintenance(executor.config.MaintenanceFile, executor.config.InstallationID, executor.owner)
	if err != nil || (state.Phase == "draining" && state.PlanID != plan.ID) {
		return ErrPlanConflict
	}
	if err := writeNativeMaintenance(executor.config.MaintenanceFile, executor.config.InstallationID, "draining", plan.ID, executor.now()); err != nil {
		return err
	}
	logRun(ctx, RunLogEntry{Level: "info", Event: "maintenance_draining"})
	return nil
}

func (executor *nativeExecutor) Activate(ctx context.Context, plan Plan) error {
	state, err := readNativeMaintenance(executor.config.MaintenanceFile, executor.config.InstallationID, executor.owner)
	if err != nil || state.Phase != "draining" || state.PlanID != plan.ID {
		return ErrPlanConflict
	}
	candidate, err := executor.verifyArtifact(plan.Target)
	if err != nil {
		return err
	}
	if _, err := executor.verifyArtifact(plan.Rollback); err != nil {
		return err
	}
	current, _, err := executor.current()
	if err != nil || (current.Digest != plan.Rollback.Digest && current.Digest != plan.Target.Digest) {
		return ErrTargetMismatch
	}
	// Additive and ledgered: applied before the candidate's control-api starts,
	// and a no-op when an interrupted activation is resumed.
	if err := executor.clickhouseMigrate(ctx, plan, candidate, false); err != nil {
		return err
	}
	if err := executor.link("previous", executor.release(plan.Rollback)); err != nil {
		return err
	}
	if err := executor.link("current", executor.release(plan.Target)); err != nil {
		return err
	}
	logRun(ctx, RunLogEntry{Level: "info", Event: "release_switched", Version: plan.Target.Version})
	return executor.restart(ctx)
}

func (executor *nativeExecutor) Rollback(ctx context.Context, plan Plan) error {
	// The request/runner stop signal must not cancel recovery halfway through.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), executor.config.StepTimeout)
	defer cancel()
	if _, err := executor.verifyArtifact(plan.Rollback); err != nil {
		return err
	}
	if err := executor.link("current", executor.release(plan.Rollback)); err != nil {
		return err
	}
	logRun(ctx, RunLogEntry{Level: "warning", Event: "release_switched", Version: plan.Rollback.Version})
	return executor.restart(ctx)
}

func (executor *nativeExecutor) Health(ctx context.Context, plan Plan, artifact Artifact) error {
	if artifact.Digest == plan.Rollback.Digest {
		ctx = context.WithoutCancel(ctx)
	}
	ctx, cancel := context.WithTimeout(ctx, executor.config.HealthTimeout)
	defer cancel()
	ticker := time.NewTicker(executor.config.PollInterval)
	defer ticker.Stop()
	started, checks := executor.now(), 0
	var last *RunLogEntry
	logRun(ctx, RunLogEntry{Level: "info", Event: "health_check_started", Version: artifact.Version,
		DurationMS: executor.config.HealthTimeout.Milliseconds()})
	for {
		checks++
		// Reason names the failing check; for HTTP checks Host and HTTPStatus
		// say which endpoint answered what (0: no response).
		waiting := RunLogEntry{Level: "warning", Event: "health_check_waiting", Version: artifact.Version}
		current, manifest, err := executor.current()
		switch {
		case err != nil || current.Digest != artifact.Digest || current.Version != artifact.Version:
			waiting.Reason = "release_mismatch"
		case executor.verifyServices(ctx, manifest) != nil:
			waiting.Reason = "services_not_running"
		default:
			if err := executor.checkHTTP(ctx, manifest); err != nil {
				waiting.Reason = "http_not_ready"
				var failure *nativeHTTPCheckError
				if errors.As(err, &failure) {
					waiting.Reason, waiting.Host, waiting.HTTPStatus = failure.Reason, failure.Host, failure.HTTPStatus
				}
			}
		}
		if waiting.Reason != "" && ctx.Err() != nil && last != nil {
			// The deadline cut this check short (systemctl/HTTP were cancelled);
			// report the last real observation, not the cancellation.
			waiting = *last
		}
		elapsed := executor.now().Sub(started).Milliseconds()
		if waiting.Reason == "" {
			logRun(ctx, RunLogEntry{Level: "info", Event: "health_check_passed", Version: artifact.Version, DurationMS: elapsed, Count: checks})
			return nil
		}
		// Log only changes, so a two-minute wait stays a few readable lines.
		if last == nil || waiting.Reason != last.Reason || waiting.Host != last.Host || waiting.HTTPStatus != last.HTTPStatus {
			waiting.DurationMS = elapsed
			logRun(ctx, waiting)
			last = &waiting
		}
		select {
		case <-ctx.Done():
			logRun(ctx, RunLogEntry{Level: "error", Event: "health_check_timeout", Reason: waiting.Reason, Host: waiting.Host,
				HTTPStatus: waiting.HTTPStatus, Version: artifact.Version,
				DurationMS: executor.now().Sub(started).Milliseconds(), Count: checks})
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (executor *nativeExecutor) Contract(ctx context.Context, plan Plan) error {
	// Native migrations are append-only expand steps; nothing is contracted.
	_, err := executor.verifyArtifact(plan.Target)
	return err
}

func (executor *nativeExecutor) Resume(ctx context.Context, plan Plan) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), executor.config.StepTimeout)
	defer cancel()
	state, err := readNativeMaintenance(executor.config.MaintenanceFile, executor.config.InstallationID, executor.owner)
	if err != nil || state.PlanID != plan.ID || (state.Phase != "draining" && state.Phase != "active") {
		return ErrPlanConflict
	}
	artifact, manifest, err := executor.current()
	if err != nil || (artifact.Digest != plan.Target.Digest && artifact.Digest != plan.Rollback.Digest) {
		return ErrTargetMismatch
	}
	if executor.verifyServices(ctx, manifest) != nil || executor.checkHTTP(ctx, manifest) != nil {
		return ErrTargetMismatch
	}
	if err := writeNativeMaintenance(executor.config.MaintenanceFile, executor.config.InstallationID, "active", plan.ID, executor.now()); err != nil {
		return err
	}
	logRun(ctx, RunLogEntry{Level: "info", Event: "maintenance_active", Version: manifest.Version})
	return nil
}

// nativeCandidateLineage rejects a signed candidate that can never be applied
// over the current release; the failure is terminal for the plan.
func nativeCandidateLineage(current, candidate NativeManifest) error {
	if nativeLineageReason(current, candidate) != "" {
		return fmt.Errorf("%w: %w", ErrCandidateRejected, ErrTargetMismatch)
	}
	return nil
}

// nativeLineageReason names the first lineage rule a candidate breaks, or "".
func nativeLineageReason(current, candidate NativeManifest) string {
	_, appendOnly := nativeAppendedMigrations(current, candidate)
	_, clickhouseAppendOnly := nativeAppendedClickHouseMigrations(current, candidate)
	switch {
	case current.Schema == NativeManifestSignedSchema && candidate.Schema != NativeManifestSignedSchema:
		return "unsigned_candidate"
	case semver.Compare("v"+candidate.Version, "v"+current.Version) <= 0:
		return "version_not_newer"
	case current.Source.Commit == candidate.Source.Commit:
		return "same_source_commit"
	case candidate.Source.PreviousCommit != current.Source.Commit:
		return "previous_commit_mismatch"
	case !appendOnly:
		return "migrations_not_append_only"
	case !clickhouseAppendOnly:
		return "clickhouse_migrations_not_append_only"
	case !nativeCompatibleFiles(current, candidate):
		return "incompatible_files"
	}
	return ""
}

func (executor *nativeExecutor) verifySource(ctx context.Context, current, candidate NativeManifest) error {
	if err := nativeCandidateLineage(current, candidate); err != nil {
		return err
	}
	for _, manifest := range []NativeManifest{current, candidate} {
		if manifest.Schema == NativeManifestSchema {
			if err := executor.verifySourceTree(ctx, manifest.Source); err != nil {
				return err
			}
		}
	}
	// v2 archives already verified the publisher's persistent source/inventory
	// attestation. The publisher proves Git ancestry without distributing it.
	if candidate.Schema == NativeManifestSignedSchema {
		return nil
	}
	_, err := executor.command(ctx, "git", "--no-replace-objects", "--git-dir="+executor.config.SourceGitDirectory,
		"merge-base", "--is-ancestor", current.Source.Commit, candidate.Source.Commit)
	if err != nil {
		return ErrTargetMismatch
	}
	return nil
}

func (executor *nativeExecutor) verifySourceTree(ctx context.Context, source NativeSource) error {
	if executor.config.SourceGitDirectory == "" {
		return ErrTargetMismatch
	}
	output, err := executor.command(ctx, "git", "--no-replace-objects", "--git-dir="+executor.config.SourceGitDirectory,
		"rev-parse", "--verify", source.Commit+"^{tree}")
	if err != nil || strings.TrimSpace(string(output)) != source.Tree {
		return ErrTargetMismatch
	}
	return nil
}

func (executor *nativeExecutor) command(ctx context.Context, name string, arguments ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, executor.config.StepTimeout)
	defer cancel()
	return executor.commands.Run(ctx, name, arguments...)
}

var nativeExecStartPath = regexp.MustCompile(`(?:^|[ {;])path=([^ ;}]+)(?:[ ;}]|$)`)

func (executor *nativeExecutor) verifyServices(ctx context.Context, manifest NativeManifest) error {
	for _, service := range []struct{ unit, binary string }{
		{executor.config.ControlUnit, "bin/control-api"}, {executor.config.GatewayUnit, "bin/agent-gateway"},
	} {
		output, err := executor.command(ctx, "systemctl", "show", "--no-pager", "--property=ExecStart,MainPID,ActiveState,SubState", service.unit)
		if err != nil {
			return ErrTargetMismatch
		}
		properties := make(map[string]string)
		for _, line := range strings.Split(string(output), "\n") {
			key, value, found := strings.Cut(line, "=")
			if found {
				if _, duplicate := properties[key]; duplicate {
					return ErrTargetMismatch
				}
				properties[key] = value
			}
		}
		paths := nativeExecStartPath.FindAllStringSubmatch(properties["ExecStart"], -1)
		pid, pidErr := strconv.Atoi(properties["MainPID"])
		if len(paths) != 1 || paths[0][1] != filepath.Join(executor.config.ReleaseRoot, "current", service.binary) ||
			properties["ActiveState"] != "active" || properties["SubState"] != "running" || pidErr != nil || pid < 1 {
			return ErrTargetMismatch
		}
		process, err := executor.inspect(pid)
		if err != nil || process.digest != nativeFile(manifest, service.binary).SHA256 {
			return ErrTargetMismatch
		}
	}
	return nil
}

// nativeHTTPCheckError names the health check that failed so the run log shows
// which endpoint kept the release from becoming healthy. HTTPStatus is 0 when
// no response arrived.
type nativeHTTPCheckError struct {
	Reason     string
	Host       string
	HTTPStatus int
	err        error
}

func (failure *nativeHTTPCheckError) Error() string {
	return fmt.Sprintf("%s (host %s, HTTP %d): %v", failure.Reason, failure.Host, failure.HTTPStatus, failure.err)
}

func (failure *nativeHTTPCheckError) Unwrap() error { return failure.err }

func (executor *nativeExecutor) checkHTTP(ctx context.Context, manifest NativeManifest) error {
	ctx, cancel := context.WithTimeout(ctx, executor.config.StepTimeout)
	defer cancel()
	for _, check := range []struct{ address, reason string }{
		{executor.config.ControlHealthURL, "control_api_not_ready"},
		{executor.config.GatewayHealthURL, "agent_gateway_not_ready"},
		{executor.config.WebIndexURL, "console_index_not_ready"},
	} {
		address := check.address
		failed := func(reason string, status int, err error) error {
			host := ""
			if parsed, parseErr := url.Parse(address); parseErr == nil {
				host = parsed.Host
			}
			return &nativeHTTPCheckError{Reason: reason, Host: host, HTTPStatus: status, err: err}
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
		if err != nil {
			return err
		}
		request.Header.Set("Cache-Control", "no-cache")
		client := executor.client
		if address == executor.config.WebIndexURL && executor.webClient != nil {
			client = executor.webClient
		}
		response, err := client.Do(request)
		if err != nil {
			return failed(check.reason, 0, err)
		}
		if address == executor.config.WebIndexURL {
			expected := nativeFile(manifest, "static/web/index.html")
			status := response.StatusCode
			digest, err := nativeResponseDigest(response, expected.Bytes)
			if status != http.StatusOK || err != nil {
				return failed(check.reason, status, ErrTargetMismatch)
			}
			if digest != expected.SHA256 {
				return failed("console_index_mismatch", status, ErrTargetMismatch)
			}
		} else {
			encoded, readErr := io.ReadAll(io.LimitReader(response.Body, 4097))
			_ = response.Body.Close()
			var ready struct {
				Status string `json:"status"`
			}
			if response.StatusCode != http.StatusOK || readErr != nil || len(encoded) > 4096 ||
				strings.Split(response.Header.Get("Content-Type"), ";")[0] != "application/json" ||
				decodeNativeJSON(encoded, &ready) != nil || ready.Status != "ready" {
				return failed(check.reason, response.StatusCode, ErrTargetMismatch)
			}
		}
	}
	return nil
}

func (executor *nativeExecutor) link(name, destination string) error {
	file, err := os.CreateTemp(executor.config.ReleaseRoot, "."+name+"-*.link")
	if err != nil {
		return err
	}
	temporary := file.Name()
	_ = file.Close()
	defer os.Remove(temporary)
	if err := os.Remove(temporary); err != nil {
		return err
	}
	if err := os.Symlink(destination, temporary); err != nil {
		return err
	}
	if err := os.Rename(temporary, filepath.Join(executor.config.ReleaseRoot, name)); err != nil {
		return err
	}
	return syncDirectory(executor.config.ReleaseRoot)
}

func (executor *nativeExecutor) restart(ctx context.Context) error {
	started := executor.now()
	_, err := executor.command(ctx, "systemctl", "restart", executor.config.ControlUnit, executor.config.GatewayUnit)
	elapsed := executor.now().Sub(started).Milliseconds()
	if err != nil {
		logRun(ctx, RunLogEntry{Level: "error", Event: "services_restart_failed", Unit: executor.config.ControlUnit, DurationMS: elapsed})
		return fmt.Errorf("native management service restart failed: %w", err)
	}
	logRun(ctx, RunLogEntry{Level: "info", Event: "services_restarted", Unit: executor.config.ControlUnit, DurationMS: elapsed})
	return nil
}

const nativeJournalTimeout = 10 * time.Second

// collectProgramLogs attaches the latest journal tail of the control API, the
// gateway and the runner itself. Each read is short, bounded and redacted;
// a missing journal is recorded as unavailable, never as an upgrade failure.
func (executor *nativeExecutor) collectProgramLogs(ctx context.Context, trigger string) {
	writer := runLogFrom(ctx)
	if writer == nil {
		return
	}
	since := writer.startedAt()
	if since <= 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), nativeJournalTimeout)
	defer cancel()
	runner := executor.runnerUnit
	sources := []struct{ label, selector string }{
		{executor.config.ControlUnit, "--unit=" + executor.config.ControlUnit},
		{executor.config.GatewayUnit, "--unit=" + executor.config.GatewayUnit},
		{"control-upgrade-runner", "_PID=" + strconv.Itoa(os.Getpid())},
	}
	if runner != "" {
		sources[2] = struct{ label, selector string }{runner, "--unit=" + runner}
	}
	for _, source := range sources {
		output, err := executor.commands.Run(ctx, "journalctl", "--no-pager", "--quiet", "--no-hostname", "--output=short-iso",
			"--since=@"+strconv.FormatInt(since, 10), "--lines="+strconv.Itoa(maxRunLogProgramLines), source.selector)
		program := RunLogProgram{Unit: source.label, Trigger: trigger}
		if err != nil {
			program.Unavailable = true
		} else if text := strings.TrimRight(string(output), "\n"); text != "" {
			program.Lines = strings.Split(text, "\n")
		}
		writer.setProgram(program)
	}
}

// nativeRunnerUnit reads the runner's own systemd unit from its cgroup.
func nativeRunnerUnit() string {
	encoded, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(encoded), "\n") {
		if path, found := strings.CutPrefix(line, "0::"); found {
			unit := filepath.Base(path)
			if nativeUnitName.MatchString(unit) {
				return unit
			}
		}
	}
	return ""
}
