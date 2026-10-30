package nativebackup

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Settings are written by control-api (root) and read by the backup agent.
// The file is root-only; target secrets never leave it through the API.
type Settings struct {
	Schedule   Schedule `json:"schedule"`
	KeepLocal  int      `json:"keep_local"`
	KeepRemote int      `json:"keep_remote"`
	Targets    []Target `json:"targets"`
}

// Schedule runs a backup at Hour:Minute host local time on Weekdays
// (0=Sunday). Disabled by default: every backup briefly stops the console.
type Schedule struct {
	Enabled  bool  `json:"enabled"`
	Weekdays []int `json:"weekdays"`
	Hour     int   `json:"hour"`
	Minute   int   `json:"minute"`
}

func DefaultSettings() Settings {
	return Settings{Schedule: Schedule{Weekdays: []int{0, 1, 2, 3, 4, 5, 6}, Hour: 4}, KeepLocal: 7, KeepRemote: 14}
}

func (settings Settings) Validate() error {
	if settings.KeepLocal < 1 || settings.KeepLocal > 100 || settings.KeepRemote < 1 || settings.KeepRemote > 1000 ||
		settings.Schedule.Hour < 0 || settings.Schedule.Hour > 23 || settings.Schedule.Minute < 0 || settings.Schedule.Minute > 59 ||
		len(settings.Targets) > 8 {
		return errors.New("invalid backup settings")
	}
	seenDay := map[int]bool{}
	for _, day := range settings.Schedule.Weekdays {
		if day < 0 || day > 6 || seenDay[day] {
			return errors.New("invalid schedule weekday")
		}
		seenDay[day] = true
	}
	if settings.Schedule.Enabled && len(settings.Schedule.Weekdays) == 0 {
		return errors.New("an enabled schedule needs at least one weekday")
	}
	seen := map[string]bool{}
	for _, target := range settings.Targets {
		if err := target.Validate(); err != nil {
			return fmt.Errorf("target %s: %w", target.Name, err)
		}
		if seen[target.Name] {
			return errors.New("duplicate target name")
		}
		seen[target.Name] = true
	}
	return nil
}

func LoadSettings(layout Layout) (Settings, error) {
	encoded, err := readPrivateFile(layout.Path(SettingsFile), 1<<20)
	if errors.Is(err, os.ErrNotExist) {
		return DefaultSettings(), nil
	}
	if err != nil {
		return Settings{}, err
	}
	var settings Settings
	if err := json.Unmarshal(encoded, &settings); err != nil {
		return Settings{}, errors.New("backup settings are unreadable")
	}
	return settings, settings.Validate()
}

func SaveSettings(layout Layout, settings Settings) error {
	if err := settings.Validate(); err != nil {
		return err
	}
	path := layout.Path(SettingsFile)
	if err := ensurePrivateDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, append(encoded, '\n'), 0o600)
}

// ---- requests and runs ----

type RequestKind string

const (
	RequestBackup  RequestKind = "backup"
	RequestDelete  RequestKind = "delete"
	RequestMigrate RequestKind = "migrate"
	// RequestRollback ends the migration hold on this host: the writers are
	// re-enabled and started again (fix-migrollback).
	RequestRollback RequestKind = "rollback"
)

// MigrationTarget is the new host of a console-driven migration. The
// credential is removed from disk as soon as the agent has read it.
type MigrationTarget struct {
	Host          string `json:"host"`
	Port          int    `json:"port"`
	User          string `json:"user"`
	HostKeySHA256 string `json:"host_key_sha256"`
	Password      string `json:"password,omitempty"`
	PrivateKey    string `json:"private_key,omitempty"`
	// Env is the target environment (fix-btenv): auto (default, detect the
	// BaoTa panel), bt (coexist with BaoTa) or plain (dedicated host).
	Env string `json:"env,omitempty"`
}

func (target MigrationTarget) Validate() error {
	if !hostPattern.MatchString(target.Host) || target.Port < 1 || target.Port > 65535 || !usernamePattern.MatchString(target.User) ||
		!hostKeyPattern.MatchString(target.HostKeySHA256) || (target.Password == "") == (target.PrivateKey == "") {
		return errors.New("migration target needs host, port, user, pinned host key and exactly one of password or private key")
	}
	switch target.Env {
	case "", "auto", "bt", "plain":
	default:
		return errors.New("migration target environment must be auto, bt or plain")
	}
	return nil
}

type Request struct {
	ID          string           `json:"id"`
	Kind        RequestKind      `json:"kind"`
	RequestedAt time.Time        `json:"requested_at"`
	RequestedBy string           `json:"requested_by"`
	BackupID    string           `json:"backup_id,omitempty"`
	Migration   *MigrationTarget `json:"migration,omitempty"`
}

type RunState string

const (
	RunQueued    RunState = "queued"
	RunRunning   RunState = "running"
	RunSucceeded RunState = "succeeded"
	RunFailed    RunState = "failed"
	// RunStopped is a migration ended by a stop request (Error is
	// migration_stopped or migration_aborted).
	RunStopped RunState = "stopped"
)

// Migration phases, logged as "phase: <name>" and kept in Run.Phase.
const (
	PhaseConnect       = "connect"
	PhasePrepareTarget = "prepare_target"
	PhaseBackup        = "backup"
	PhaseTransfer      = "transfer"
	PhaseRestore       = "restore"
	PhaseVerify        = "verify"
	PhaseDone          = "done"
)

// PhaseReachedTarget reports whether the target may already hold restored
// data (restore started or later).
func PhaseReachedTarget(phase string) bool {
	return phase == PhaseRestore || phase == PhaseVerify || phase == PhaseDone
}

// Run is the console-visible record of one agent job. It never carries a
// secret: messages pass through Redact.
type Run struct {
	ID          string      `json:"id"`
	Kind        RequestKind `json:"kind"`
	Reason      string      `json:"reason"`
	State       RunState    `json:"state"`
	RequestedAt time.Time   `json:"requested_at"`
	RequestedBy string      `json:"requested_by,omitempty"`
	StartedAt   *time.Time  `json:"started_at,omitempty"`
	EndedAt     *time.Time  `json:"ended_at,omitempty"`
	BackupID    string      `json:"backup_id,omitempty"`
	Target      string      `json:"target,omitempty"`
	// TargetEnv is the detected environment of a migration target (bt or
	// plain); on bt the console tells the operator to configure the BaoTa
	// reverse proxy on the new host (fix-btenv2).
	TargetEnv string            `json:"target_env,omitempty"`
	Phase     string            `json:"phase,omitempty"`
	Error     string            `json:"error,omitempty"`
	Uploads   map[string]string `json:"uploads,omitempty"`
	Log       []string          `json:"log"`
}

var runIDPattern = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}$`)

func newRunID(now time.Time) string {
	suffix := make([]byte, 6)
	_, _ = rand.Read(suffix)
	return now.UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(suffix)
}

func runsDirectory(layout Layout) string { return layout.Path(AgentRoot + "/runs") }
func stopPath(layout Layout, id string) string {
	return filepath.Join(runsDirectory(layout), id+".stop")
}
func requestsDirectory(layout Layout) string { return layout.Path(AgentRoot + "/requests") }

// SubmitRequest queues a job for the agent and records it as queued. Only one
// backup or migration may be queued or running at a time.
func SubmitRequest(layout Layout, request Request, now time.Time) (Run, error) {
	switch request.Kind {
	case RequestBackup:
	case RequestDelete:
		if !backupIDPattern.MatchString(request.BackupID) {
			return Run{}, errors.New("invalid backup id")
		}
	case RequestMigrate:
		if request.Migration == nil || request.Migration.Validate() != nil {
			return Run{}, errors.New("invalid migration target")
		}
	case RequestRollback:
	default:
		return Run{}, errors.New("invalid request kind")
	}
	for _, directory := range []string{runsDirectory(layout), requestsDirectory(layout)} {
		if err := ensurePrivateDirectory(directory); err != nil {
			return Run{}, err
		}
	}
	runs, err := ListRuns(layout, 50)
	if err != nil {
		return Run{}, err
	}
	for _, existing := range runs {
		if (existing.State == RunQueued || existing.State == RunRunning) && existing.Kind != RequestDelete && request.Kind != RequestDelete {
			return Run{}, ErrBusy
		}
	}
	request.ID, request.RequestedAt = newRunID(now), now.UTC()
	run := Run{ID: request.ID, Kind: request.Kind, Reason: "manual", State: RunQueued, RequestedAt: request.RequestedAt,
		RequestedBy: request.RequestedBy, BackupID: request.BackupID, Log: []string{}}
	switch request.Kind {
	case RequestMigrate:
		run.Reason, run.Target = "migration", request.Migration.Host
	case RequestRollback:
		run.Reason = "rollback"
	}
	if err := writeRun(layout, run); err != nil {
		return Run{}, err
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		return Run{}, err
	}
	if err := writeExclusive(filepath.Join(requestsDirectory(layout), request.ID+".json"), encoded); err != nil {
		return Run{}, err
	}
	return run, nil
}

func writeRun(layout Layout, run Run) error {
	encoded, err := json.MarshalIndent(run, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(runsDirectory(layout), run.ID+".json"), append(encoded, '\n'), 0o600)
}

func ReadRun(layout Layout, id string) (Run, error) {
	if !runIDPattern.MatchString(id) {
		return Run{}, os.ErrNotExist
	}
	encoded, err := readPrivateFile(filepath.Join(runsDirectory(layout), id+".json"), 4<<20)
	if err != nil {
		return Run{}, err
	}
	var run Run
	if err := json.Unmarshal(encoded, &run); err != nil {
		return Run{}, err
	}
	return run, nil
}

// ListRuns returns the newest runs first.
func ListRuns(layout Layout, limit int) ([]Run, error) {
	entries, err := os.ReadDir(runsDirectory(layout))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, entry := range entries {
		if id, found := strings.CutSuffix(entry.Name(), ".json"); found && runIDPattern.MatchString(id) {
			ids = append(ids, id)
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(ids)))
	var runs []Run
	for _, id := range ids {
		if len(runs) >= limit {
			break
		}
		if run, err := ReadRun(layout, id); err == nil {
			runs = append(runs, run)
		}
	}
	return runs, nil
}

// ---- agent ----

// Migrator pushes this host to a new one (implemented in migrate.go).
type Migrator interface {
	Migrate(ctx context.Context, target MigrationTarget, log func(string)) (MigrationResult, error)
}

type Agent struct {
	Layout   Layout
	Backuper Backuper
	Migrator Migrator
	Now      func() time.Time
	// StopPoll is how often a running migration checks for a stop request
	// (default 2 s).
	StopPoll time.Duration
	// Storage opens a remote target; tests substitute local fakes.
	Storage func(Target) (Storage, error)
}

type runLogger struct {
	mu     sync.Mutex
	layout Layout
	run    *Run
	now    func() time.Time
}

func (logger *runLogger) line(message string) {
	logger.mu.Lock()
	defer logger.mu.Unlock()
	message = Redact(message)
	if phase, ok := strings.CutPrefix(message, "phase: "); ok {
		logger.run.Phase = phase
	}
	if len(logger.run.Log) >= 500 {
		logger.run.Log = append(logger.run.Log[:1], logger.run.Log[len(logger.run.Log)-498:]...)
	}
	now := time.Now
	if logger.now != nil {
		now = logger.now
	}
	logger.run.Log = append(logger.run.Log, now().UTC().Format(time.RFC3339)+" "+message)
	_ = writeRun(logger.layout, *logger.run)
}

func (agent Agent) lock() (func(), error) {
	if err := ensurePrivateDirectory(agent.Layout.Path(AgentRoot)); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(agent.Layout.Path(AgentRoot+"/agent.lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, ErrBusy
	}
	return func() { _ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN); _ = file.Close() }, nil
}

// Tick runs queued requests, then a due scheduled backup, then retention.
// It is started by cdnca-control-backup.service (path + timer units).
func (agent Agent) Tick(ctx context.Context) error {
	unlock, err := agent.lock()
	if errors.Is(err, ErrBusy) {
		return nil
	}
	if err != nil {
		return err
	}
	defer unlock()
	for _, directory := range []string{runsDirectory(agent.Layout), requestsDirectory(agent.Layout)} {
		if err := ensurePrivateDirectory(directory); err != nil {
			return err
		}
	}
	settings, err := LoadSettings(agent.Layout)
	if err != nil {
		return err
	}
	agent.recoverInterrupted()
	entries, _ := os.ReadDir(requestsDirectory(agent.Layout))
	var names []string
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".json") {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	var joined error
	for _, name := range names {
		joined = errors.Join(joined, agent.handleRequest(ctx, settings, filepath.Join(requestsDirectory(agent.Layout), name)))
	}
	// A migrated-away host is held: scheduled backups would only copy a
	// stale database.
	held := false
	if current, err := (Freezer{Layout: agent.Layout}).Current(); err == nil && current != nil && current.Mode == FreezeHold {
		held = true
	}
	if slot, due := agent.dueSlot(settings); due && !held {
		run := Run{ID: newRunID(agent.Now()), Kind: RequestBackup, Reason: "scheduled", State: RunQueued, RequestedAt: agent.Now().UTC(), Log: []string{}}
		// Mark first: a failing scheduled backup is reported once, not retried
		// every tick.
		joined = errors.Join(joined, agent.markSlot(slot), writeRun(agent.Layout, run))
		joined = errors.Join(joined, agent.runBackup(ctx, settings, &run, "scheduled"))
	}
	return errors.Join(joined, agent.retention(ctx, settings))
}

// recoverInterrupted marks runs left "running" by a crashed agent as failed.
func (agent Agent) recoverInterrupted() {
	runs, _ := ListRuns(agent.Layout, 20)
	for _, run := range runs {
		if run.State == RunRunning {
			run.State, run.Error = RunFailed, "agent_interrupted"
			now := agent.Now().UTC()
			run.EndedAt = &now
			_ = writeRun(agent.Layout, run)
		}
	}
}

func (agent Agent) handleRequest(ctx context.Context, settings Settings, path string) error {
	encoded, err := readPrivateFile(path, 1<<20)
	_ = os.Remove(path) // A request is consumed exactly once, secrets included.
	if err != nil {
		return err
	}
	var request Request
	if err := json.Unmarshal(encoded, &request); err != nil || !runIDPattern.MatchString(request.ID) {
		return errors.New("invalid backup request")
	}
	clear(encoded)
	run, err := ReadRun(agent.Layout, request.ID)
	if err != nil {
		run = Run{ID: request.ID, Kind: request.Kind, RequestedAt: request.RequestedAt, Log: []string{}}
	}
	switch request.Kind {
	case RequestBackup:
		return agent.runBackup(ctx, settings, &run, "manual")
	case RequestDelete:
		return agent.finish(&run, agent.deleteBundle(ctx, settings, request.BackupID))
	case RequestMigrate:
		if agent.Migrator == nil || request.Migration == nil {
			return agent.finish(&run, errors.New("migration is not available"))
		}
		agent.start(&run)
		logger := &runLogger{layout: agent.Layout, run: &run, now: agent.Now}
		result, err := agent.migrate(ctx, run.ID, *request.Migration, logger.line)
		run.BackupID, run.TargetEnv = result.BackupID, result.TargetEnv
		return agent.finishMigration(&run, err)
	case RequestRollback:
		agent.start(&run)
		logger := &runLogger{layout: agent.Layout, run: &run, now: agent.Now}
		logger.line("rollback: re-enabling and starting control-api, agent-gateway and the upgrade runner")
		err := agent.Backuper.Freezer.Unfreeze(ctx)
		if err == nil {
			logger.line("rollback: this control plane serves again; point the control and Gateway DNS back here if they were changed")
		}
		return agent.finish(&run, err)
	}
	return agent.finish(&run, errors.New("invalid request kind"))
}

// migrate runs the migration and cancels it when RequestStop marks the run.
func (agent Agent) migrate(ctx context.Context, runID string, target MigrationTarget, log func(string)) (MigrationResult, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer os.Remove(stopPath(agent.Layout, runID))
	poll := agent.StopPoll
	if poll <= 0 {
		poll = 2 * time.Second
	}
	done, exited := make(chan struct{}), make(chan struct{})
	// The poller has exited before the caller finalizes the run record.
	defer func() { close(done); <-exited }()
	go func() {
		defer close(exited)
		ticker := time.NewTicker(poll)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				if fileExists(stopPath(agent.Layout, runID)) {
					log("stop: requested from the console")
					cancel()
					return
				}
			}
		}
	}()
	return agent.Migrator.Migrate(ctx, target, log)
}

func (agent Agent) finishMigration(run *Run, err error) error {
	code := ""
	switch {
	case errors.Is(err, ErrMigrationStopped):
		code = "migration_stopped"
	case errors.Is(err, ErrMigrationAborted):
		code = "migration_aborted"
	default:
		return agent.finish(run, err)
	}
	logger := &runLogger{layout: agent.Layout, run: run, now: agent.Now}
	logger.line("stopped: " + err.Error())
	now := agent.Now().UTC()
	run.EndedAt, run.State, run.Error = &now, RunStopped, code
	return writeRun(agent.Layout, *run)
}

// RequestStop asks the agent to stop a running migration at its next safe
// point. Only a running migration can be stopped.
func RequestStop(layout Layout, runID string) error {
	run, err := ReadRun(layout, runID)
	if err != nil {
		return err
	}
	if run.Kind != RequestMigrate || run.State != RunRunning {
		return ErrNotStoppable
	}
	if err := writeFileAtomic(stopPath(layout, runID), []byte("stop\n"), 0o600); err != nil {
		return err
	}
	return nil
}

func (agent Agent) start(run *Run) {
	now := agent.Now().UTC()
	run.State, run.StartedAt = RunRunning, &now
	_ = writeRun(agent.Layout, *run)
}

func (agent Agent) finish(run *Run, err error) error {
	now := agent.Now().UTC()
	run.EndedAt, run.State = &now, RunSucceeded
	if err != nil {
		run.State, run.Error = RunFailed, Redact(err.Error())
	}
	return errors.Join(err, writeRun(agent.Layout, *run))
}

func (agent Agent) runBackup(ctx context.Context, settings Settings, run *Run, reason string) error {
	agent.start(run)
	run.Reason = reason
	logger := &runLogger{layout: agent.Layout, run: run}
	backuper := agent.Backuper
	backuper.Progress = logger.line
	result, err := backuper.Run(ctx, BackupRequest{Reason: reason, OutputDirectory: agent.Layout.Path(BackupRoot)})
	if err != nil {
		return agent.finish(run, err)
	}
	run.BackupID = result.BackupID
	bundle, err := OpenBundle(result.Directory, backuper.Keys.Fingerprint())
	if err != nil {
		return agent.finish(run, err)
	}
	run.Uploads = map[string]string{}
	var uploadErr error
	for _, target := range settings.Targets {
		if !target.Enabled {
			continue
		}
		logger.line("upload: " + target.Name)
		if err := agent.upload(ctx, target, bundle); err != nil {
			run.Uploads[target.Name] = "failed: " + Redact(err.Error())
			uploadErr = errors.Join(uploadErr, fmt.Errorf("upload %s: %w", target.Name, err))
			continue
		}
		run.Uploads[target.Name] = "ok"
	}
	return agent.finish(run, uploadErr)
}

func (agent Agent) open(target Target) (Storage, error) {
	if agent.Storage != nil {
		return agent.Storage(target)
	}
	return OpenStorage(target)
}

func (agent Agent) upload(ctx context.Context, target Target, bundle Bundle) error {
	storage, err := agent.open(target)
	if err != nil {
		return err
	}
	defer storage.Close()
	return Upload(ctx, storage, bundle)
}

func (agent Agent) deleteBundle(ctx context.Context, settings Settings, backupID string) error {
	directory := filepath.Join(agent.Layout.Path(BackupRoot), backupID)
	signed, err := ReadSignedManifest(directory)
	if err != nil {
		return err
	}
	manifest, err := ReadUnverifiedManifest(signed)
	if err != nil {
		return err
	}
	if err := os.RemoveAll(directory); err != nil {
		return err
	}
	var joined error
	files := []string{manifestFile}
	for _, component := range manifest.Components {
		files = append(files, component.File)
	}
	for _, target := range settings.Targets {
		if !target.Enabled {
			continue
		}
		storage, err := agent.open(target)
		if err == nil {
			err = storage.DeleteBackup(ctx, backupID, files)
			_ = storage.Close()
		}
		joined = errors.Join(joined, err)
	}
	return joined
}

// retention keeps the newest KeepLocal local bundles and KeepRemote remote
// ones. The newest local bundle is never removed.
func (agent Agent) retention(ctx context.Context, settings Settings) error {
	var joined error
	local, err := ListBundles(agent.Layout.Path(BackupRoot), "")
	if err != nil {
		return err
	}
	for index, summary := range local {
		if index >= settings.KeepLocal && index > 0 {
			joined = errors.Join(joined, os.RemoveAll(filepath.Join(agent.Layout.Path(BackupRoot), summary.BackupID)))
		}
	}
	for _, target := range settings.Targets {
		if !target.Enabled {
			continue
		}
		storage, err := agent.open(target)
		if err != nil {
			joined = errors.Join(joined, err)
			continue
		}
		ids, err := storage.List(ctx)
		if err == nil && len(ids) > settings.KeepRemote {
			sort.Strings(ids)
			for _, id := range ids[:len(ids)-settings.KeepRemote] {
				files := []string{manifestFile}
				for _, name := range ComponentOrder {
					files = append(files, string(name)+".tar.age")
				}
				err = errors.Join(err, storage.DeleteBackup(ctx, id, files))
			}
		}
		joined = errors.Join(joined, err, storage.Close())
	}
	return joined
}

type scheduleState struct {
	LastSlot time.Time `json:"last_slot"`
}

func (agent Agent) schedulePath() string { return agent.Layout.Path(AgentRoot + "/schedule.json") }

// dueSlot returns the most recent scheduled time not yet run. A slot older
// than six hours (host was down) is skipped rather than run late.
func (agent Agent) dueSlot(settings Settings) (time.Time, bool) {
	if !settings.Schedule.Enabled {
		return time.Time{}, false
	}
	now := agent.Now()
	var state scheduleState
	if encoded, err := readPrivateFile(agent.schedulePath(), 4096); err == nil {
		_ = json.Unmarshal(encoded, &state)
	}
	for days := 0; days < 8; days++ {
		day := now.AddDate(0, 0, -days)
		slot := time.Date(day.Year(), day.Month(), day.Day(), settings.Schedule.Hour, settings.Schedule.Minute, 0, 0, now.Location())
		if slot.After(now) || !containsInt(settings.Schedule.Weekdays, int(slot.Weekday())) {
			continue
		}
		if !slot.After(state.LastSlot) || now.Sub(slot) > 6*time.Hour {
			return time.Time{}, false
		}
		return slot, true
	}
	return time.Time{}, false
}

// NextSlot is the next scheduled backup time after now (host local time), or
// false when the schedule is off. A failed backup is not retried: the next
// attempt is this slot or a manual backup.
func NextSlot(settings Settings, now time.Time) (time.Time, bool) {
	if !settings.Schedule.Enabled {
		return time.Time{}, false
	}
	for days := 0; days < 8; days++ {
		day := now.AddDate(0, 0, days)
		slot := time.Date(day.Year(), day.Month(), day.Day(), settings.Schedule.Hour, settings.Schedule.Minute, 0, 0, now.Location())
		if slot.After(now) && containsInt(settings.Schedule.Weekdays, int(slot.Weekday())) {
			return slot, true
		}
	}
	return time.Time{}, false
}

func (agent Agent) markSlot(slot time.Time) error {
	encoded, _ := json.Marshal(scheduleState{LastSlot: slot})
	return writeFileAtomic(agent.schedulePath(), encoded, 0o600)
}

func containsInt(values []int, value int) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
