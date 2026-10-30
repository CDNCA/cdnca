package nativebackup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"filippo.io/age"
)

// ServiceUnits are started after a restore, in this order. Units that the
// bundle did not contain are skipped.
var ServiceUnits = []string{
	// The Gateway access firewall loads before the listeners it guards.
	"cdnca-gateway-access.service",
	"cdnca-gateway-access.path",
	"cdnca-objectstore.service",
	"cdnca-control-nats.service",
	"cdnca-control-api.service",
	"cdnca-agent-gateway.service",
	"cdnca-control-web.service",
	"cdnca-native-control-upgrade-runner.service",
	"cdnca-control-backup.path",
	"cdnca-control-backup.timer",
}

// systemAccounts are created on the target when the bundle needs them and the
// dependency installer does not provide them.
var systemAccounts = map[string]string{"cdnca-objectstore": ObjectStoreData}

type RestoreRequest struct {
	Bundle   Bundle
	Identity age.Identity
	// Compensate removes a previous partial restore of the same bundle.
	Compensate bool
}

type RestoreResult struct {
	BackupID  string    `json:"backup_id"`
	Version   string    `json:"version"`
	StartedAt time.Time `json:"started_at"`
	EndedAt   time.Time `json:"ended_at"`
	Started   []string  `json:"started_units"`
}

const restoreIntentSchema = "cdnca.control-native-restore.intent/v1"

type restoreIntent struct {
	Schema    string    `json:"schema"`
	BackupID  string    `json:"backup_id"`
	Applied   []string  `json:"applied"`
	StartedAt time.Time `json:"started_at"`
	Completed bool      `json:"completed"`
}

var ErrRestoreUncertain = errors.New("a previous restore of this bundle did not finish; rerun with --compensate to remove it first")

type Restorer struct {
	Host       *Host
	Components []Component
	Now        func() time.Time
	Progress   func(string)
}

func (restorer Restorer) progress(format string, values ...any) {
	if restorer.Progress != nil {
		restorer.Progress(fmt.Sprintf(format, values...))
	}
}

func (restorer Restorer) intentPath() string {
	return filepath.Join(restorer.Host.Layout.Path(AgentRoot+"/restore"), "intent.json")
}

func (restorer Restorer) readIntent() (*restoreIntent, error) {
	encoded, err := readPrivateFile(restorer.intentPath(), 64<<10)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var intent restoreIntent
	if err := json.Unmarshal(encoded, &intent); err != nil || intent.Schema != restoreIntentSchema {
		return nil, errors.New("restore intent is invalid")
	}
	return &intent, nil
}

func (restorer Restorer) writeIntent(intent restoreIntent) error {
	if err := ensurePrivateDirectory(filepath.Dir(restorer.intentPath())); err != nil {
		return err
	}
	encoded, _ := json.MarshalIndent(intent, "", "  ")
	return writeFileAtomic(restorer.intentPath(), append(encoded, '\n'), 0o600)
}

// Run restores every component onto an empty target and starts the services.
// Any failure before the services start compensates the applied components in
// reverse order, leaving the target as empty as it was.
func (restorer Restorer) Run(ctx context.Context, request RestoreRequest) (RestoreResult, error) {
	manifest := request.Bundle.Manifest
	if len(restorer.Components) != len(ComponentOrder) {
		return RestoreResult{}, errors.New("restore component set is incomplete")
	}
	unlock, err := LockRelease(restorer.Host.Layout)
	if err != nil {
		return RestoreResult{}, err
	}
	defer unlock()
	intent, err := restorer.readIntent()
	if err != nil {
		return RestoreResult{}, err
	}
	if intent != nil && !intent.Completed {
		if !request.Compensate || intent.BackupID != manifest.BackupID {
			return RestoreResult{}, ErrRestoreUncertain
		}
		restorer.progress("compensate: removing the unfinished restore of %s", intent.BackupID)
		if err := restorer.compensate(ctx, manifest, intent.Applied); err != nil {
			return RestoreResult{}, err
		}
		if err := os.Remove(restorer.intentPath()); err != nil {
			return RestoreResult{}, err
		}
	} else if intent != nil {
		return RestoreResult{}, fmt.Errorf("restore_already_completed:%s", intent.BackupID)
	}
	restorer.progress("verify: decrypting every component of %s", manifest.BackupID)
	if err := request.Bundle.VerifyAll(request.Identity); err != nil {
		return RestoreResult{}, err
	}
	for index, component := range restorer.Components {
		if component.Name() != ComponentOrder[index] {
			return RestoreResult{}, errors.New("restore component order is invalid")
		}
		record, _ := manifest.Component(component.Name())
		if err := component.Preflight(ctx, restorer.Host, record, manifest); err != nil {
			return RestoreResult{}, fmt.Errorf("preflight %s: %w", component.Name(), err)
		}
	}
	if err := restorer.preflightGatewayAccess(manifest); err != nil {
		return RestoreResult{}, err
	}
	trust, err := restorer.trustRebuild(manifest)
	if err != nil {
		return RestoreResult{}, err
	}
	if err := restorer.ensureAccounts(ctx, manifest); err != nil {
		return RestoreResult{}, err
	}
	started := restorer.Now().UTC()
	state := restoreIntent{Schema: restoreIntentSchema, BackupID: manifest.BackupID, StartedAt: started}
	if err := restorer.writeIntent(state); err != nil {
		return RestoreResult{}, err
	}
	scratch, err := os.MkdirTemp(filepath.Dir(restorer.intentPath()), ".scratch-")
	if err != nil {
		return RestoreResult{}, err
	}
	defer os.RemoveAll(scratch)
	restorer.Host.Scratch = scratch
	fail := func(cause error) (RestoreResult, error) {
		restorer.progress("restore failed; compensating applied components")
		if compensateErr := restorer.compensate(context.WithoutCancel(ctx), manifest, state.Applied); compensateErr != nil {
			return RestoreResult{}, errors.Join(cause, fmt.Errorf("compensation failed, the intent is kept: %w", compensateErr))
		}
		_ = os.Remove(restorer.intentPath())
		return RestoreResult{}, cause
	}
	for _, component := range restorer.Components {
		record, _ := manifest.Component(component.Name())
		// Record before mutating so a crash leaves a compensatable intent.
		state.Applied = append(state.Applied, string(component.Name()))
		if err := restorer.writeIntent(state); err != nil {
			return fail(err)
		}
		restorer.progress("restore: %s", component.Name())
		stream, err := request.Bundle.Open(component.Name(), request.Identity)
		if err != nil {
			return fail(err)
		}
		restoreErr := component.Restore(ctx, restorer.Host, record, stream)
		closeErr := stream.Close()
		if restoreErr != nil || closeErr != nil {
			return fail(fmt.Errorf("restore %s: %w", component.Name(), errors.Join(restoreErr, closeErr)))
		}
	}
	// The restored configuration names the source host's dependency ports; a
	// migration between a plain and a BaoTa host moves them (fix-btenv).
	if err := RetargetPorts(ctx, restorer.Host.Layout, restorer.progress); err != nil {
		return fail(err)
	}
	if _, err := run(ctx, restorer.Host.Exec, trust); err != nil {
		return fail(err)
	}
	if err := restorer.Host.Systemd.DaemonReload(ctx); err != nil {
		return fail(err)
	}
	// The upgrade runner's /run state (status directory and release lock) is
	// created by its boot-only tmpfiles rule; create it now instead of waiting
	// for a reboot.
	if tmpfiles := "/etc/tmpfiles.d/cdnca-native-control-upgrade-runner.conf"; fileExists(restorer.Host.Layout.Path(tmpfiles)) {
		if _, err := run(ctx, restorer.Host.Exec, Command{Path: "/usr/bin/systemd-tmpfiles", Args: []string{"--create", "--boot", tmpfiles}}); err != nil {
			return fail(err)
		}
	}
	// The source was frozen with the writers disabled (hold). Their unit files
	// came across with that state; enable every restored unit explicitly.
	var units []string
	for _, unit := range ServiceUnits {
		if _, err := os.Lstat(restorer.Host.Layout.Path("/etc/systemd/system/" + unit)); err == nil {
			units = append(units, unit)
		}
	}
	state.Completed = true
	if err := restorer.writeIntent(state); err != nil {
		return fail(err)
	}
	var startErr error
	if err := restorer.enableRedisGatewayAccess(ctx); err != nil {
		startErr = errors.Join(startErr, fmt.Errorf("redis gateway access: %w", err))
	}
	for _, unit := range units {
		restorer.progress("start: %s", unit)
		if err := restorer.Host.Systemd.Enable(ctx, unit); err != nil {
			startErr = errors.Join(startErr, fmt.Errorf("enable %s: %w", unit, err))
			continue
		}
		if err := restorer.Host.Systemd.Start(ctx, unit); err != nil {
			startErr = errors.Join(startErr, fmt.Errorf("start %s: %w", unit, err))
		}
	}
	// Data is in place even if a service does not start; never compensate
	// here, the operator inspects the journal and retries the unit.
	return RestoreResult{BackupID: manifest.BackupID, Version: manifest.Control.Version, StartedAt: started,
		EndedAt: restorer.Now().UTC(), Started: units}, startErr
}

// gatewayAccessFirewallUnit is archived only on hosts with standalone Gateway
// access; its nftables allow-list must load before those listeners open.
const gatewayAccessFirewallUnit = "/etc/systemd/system/cdnca-gateway-access.service"

// preflightGatewayAccess refuses, before any mutation, a target that cannot
// load the Gateway access firewall: the dependency installer does not install
// nftables, and without it the restored listeners would accept every source.
func (restorer Restorer) preflightGatewayAccess(manifest Manifest) error {
	record, _ := manifest.Component(ComponentRuntime)
	if !slices.Contains(presentPaths(record.Detail), gatewayAccessFirewallUnit) {
		return nil
	}
	for _, nft := range []string{"/usr/sbin/nft", "/sbin/nft"} {
		if fileExists(restorer.Host.Layout.Path(nft)) {
			return nil
		}
	}
	return errors.New("restore_target_missing_nftables: the bundle has standalone Gateway access; install nftables on the target first")
}

// trustRebuild picks, before any mutation, the command that rebuilds the
// target's CA store: the one of the OS family whose anchor the backup
// carries (the target's when the backup has none). A backup of one family
// is refused on the other: anchors, clamd sockets and the PostgreSQL layout
// all differ, and the restored configuration would point at missing paths.
func (restorer Restorer) trustRebuild(manifest Manifest) (Command, error) {
	record, _ := manifest.Component(ComponentConfig)
	archived := presentPaths(record.Detail)
	var target, source string
	var rebuild Command
	for _, family := range trustFamilies {
		if fileExists(restorer.Host.Layout.Path(family.Rebuild.Path)) && target == "" {
			target, rebuild = family.Family, family.Rebuild
		}
		if slices.Contains(archived, family.Anchor) {
			source = family.Family
		}
	}
	if target == "" {
		return Command{}, errors.New("restore_target_missing_ca_tools: neither update-ca-certificates nor update-ca-trust is installed")
	}
	if source != "" && source != target {
		return Command{}, fmt.Errorf("restore_target_os_family_mismatch: the backup is from a %s host, the target is %s; restore onto the same OS family", source, target)
	}
	return rebuild, nil
}

// enableRedisGatewayAccess re-attaches a restored standalone Gateway access
// include to the target's Redis configuration and restarts Redis, so the
// control plane (whose gateway-access.env carries the Redis password) starts
// against the same Redis as on the source without enable-gateway-access.
// Hosts without Gateway access restored nothing here and are left untouched.
func (restorer Restorer) enableRedisGatewayAccess(ctx context.Context) error {
	changed := false
	for _, pair := range redisGatewayIncludes {
		include := pair.Directory + "/redis-gateway.conf"
		if !fileExists(restorer.Host.Layout.Path(include)) {
			continue
		}
		config := restorer.Host.Layout.Path(pair.Config)
		current, err := os.ReadFile(config)
		if err != nil {
			return fmt.Errorf("%s is missing on the target: %w", pair.Config, err)
		}
		line := "include " + include
		if slices.Contains(strings.Split(string(current), "\n"), line) {
			continue
		}
		file, err := os.OpenFile(config, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			return err
		}
		_, writeErr := file.WriteString("\n" + line + "\n")
		if err := errors.Join(writeErr, file.Sync(), file.Close()); err != nil {
			return err
		}
		restorer.progress("redis: %s includes %s", pair.Config, include)
		changed = true
	}
	if !changed {
		return nil
	}
	for _, unit := range RedisUnits {
		state, err := restorer.Host.Systemd.State(ctx, unit)
		if err != nil || !state.Loaded {
			continue
		}
		if err := restorer.Host.Systemd.Stop(ctx, unit); err != nil {
			return err
		}
		return restorer.Host.Systemd.Start(ctx, unit)
	}
	return errors.New("no Redis service unit is loaded on the target")
}

func (restorer Restorer) compensate(ctx context.Context, manifest Manifest, applied []string) error {
	var joined error
	for index := len(applied) - 1; index >= 0; index-- {
		for _, component := range restorer.Components {
			if string(component.Name()) != applied[index] {
				continue
			}
			record, _ := manifest.Component(component.Name())
			if err := component.Compensate(ctx, restorer.Host, record); err != nil {
				joined = errors.Join(joined, fmt.Errorf("compensate %s: %w", component.Name(), err))
			}
		}
	}
	return joined
}

func (restorer Restorer) ensureAccounts(ctx context.Context, manifest Manifest) error {
	record, _ := manifest.Component(ComponentObjectStore)
	if len(presentPaths(record.Detail)) == 0 {
		return nil
	}
	for account, home := range systemAccounts {
		if _, _, err := restorer.Host.Owners.Lookup(account, account, -1, -1); err == nil {
			continue
		}
		if _, err := run(ctx, restorer.Host.Exec, Command{Path: "/usr/sbin/useradd", Args: []string{"--system", "--user-group",
			"--no-create-home", "--home-dir", home, "--shell", "/usr/sbin/nologin", account}}); err != nil {
			return fmt.Errorf("create account %s: %w", account, err)
		}
	}
	return nil
}

// CleanTarget removes a restore of this bundle from a migration target that
// is no longer wanted (migration stopped mid-restore, or rolled back): the
// restored services are stopped and disabled, then every applied component is
// compensated in reverse order and the intent removed, so the host is empty
// again. Without an intent there is nothing of this bundle to remove.
func (restorer Restorer) CleanTarget(ctx context.Context, bundle Bundle) error {
	manifest := bundle.Manifest
	unlock, err := LockRelease(restorer.Host.Layout)
	if err != nil {
		return err
	}
	defer unlock()
	intent, err := restorer.readIntent()
	if err != nil {
		return err
	}
	if intent == nil {
		return errors.New("no restore of this bundle is recorded on this host")
	}
	if intent.BackupID != manifest.BackupID {
		return fmt.Errorf("this host holds a restore of %s, not %s", intent.BackupID, manifest.BackupID)
	}
	var joined error
	for index := len(ServiceUnits) - 1; index >= 0; index-- {
		unit := ServiceUnits[index]
		state, err := restorer.Host.Systemd.State(ctx, unit)
		if err != nil || !state.Loaded {
			continue
		}
		restorer.progress("stop: %s", unit)
		if err := restorer.Host.Systemd.Stop(ctx, unit); err != nil {
			joined = errors.Join(joined, fmt.Errorf("stop %s: %w", unit, err))
		}
		if state.Enabled {
			if err := restorer.Host.Systemd.Disable(ctx, unit); err != nil {
				joined = errors.Join(joined, fmt.Errorf("disable %s: %w", unit, err))
			}
		}
	}
	if joined != nil {
		return joined
	}
	applied := intent.Applied
	if intent.Completed {
		applied = nil
		for _, name := range ComponentOrder {
			applied = append(applied, string(name))
		}
	}
	restorer.progress("clean: removing the restore of %s", manifest.BackupID)
	if err := restorer.compensate(ctx, manifest, applied); err != nil {
		return fmt.Errorf("clean failed, the intent is kept: %w", err)
	}
	if err := os.Remove(restorer.intentPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return restorer.Host.Systemd.DaemonReload(ctx)
}
