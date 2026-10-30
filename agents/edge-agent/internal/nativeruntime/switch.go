package nativeruntime

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const StatusSchema = "cdnca.edge.native-runtime-status/v1"

// Outcome states.
const (
	StateSwitched  = "switched"   // the package's runtime is now active
	StateUnchanged = "unchanged"  // the active runtime already is the package's
	StateFailed    = "failed"     // the previous runtime stays active
	StateNoPackage = "no_package" // native node, but this Agent release carries no runtime
)

// Error codes (upgrade status error_code; ^[A-Z][A-Z0-9_]*$).
const (
	CodeSignature    = "RUNTIME_SIGNATURE_INVALID"
	CodeMismatch     = "RUNTIME_AGENT_MISMATCH"
	CodeInstall      = "RUNTIME_INSTALL_FAILED"
	CodePrecheck     = "RUNTIME_PRECHECK_FAILED"
	CodeSwitch       = "RUNTIME_SWITCH_FAILED"
	CodeReload       = "RUNTIME_RELOAD_FAILED"
	CodeNotPackaged  = "RUNTIME_NOT_PACKAGED"
	CodeStatusAbsent = "RUNTIME_STATUS_UNAVAILABLE"
)

// Status is the outcome of the last Apply, read by the upgrade health probe.
type Status struct {
	Schema           string    `json:"schema"`
	State            string    `json:"state"`
	AgentVersion     string    `json:"agent_version"`
	AgentSHA256      string    `json:"agent_sha256,omitempty"`
	Version          string    `json:"version,omitempty"`
	OpenRestyVersion string    `json:"openresty_version,omitempty"`
	Release          string    `json:"release,omitempty"`
	PreviousRelease  string    `json:"previous_release,omitempty"`
	ErrorCode        string    `json:"error_code,omitempty"`
	Error            string    `json:"error,omitempty"`
	At               time.Time `json:"at"`
	// RolledBack is the failed switch of another Agent release this Agent
	// replaced (the updater rolled the Agent back after it): kept with an
	// unchanged runtime so the node keeps reporting the rollback.
	RolledBack *Rollback `json:"rolled_back,omitempty"`
}

// Rollback is a failed switch: the release it targeted and its error code.
type Rollback struct {
	AgentVersion string `json:"agent_version"`
	Release      string `json:"release,omitempty"`
	ErrorCode    string `json:"error_code,omitempty"`
}

// Config is one native node's layout.
type Config struct {
	Root         string // /opt/cdnca-node
	PackagePath  string // <agent release>/native.tar.gz
	AgentPath    string // the running Agent executable
	AgentVersion string
	ConfigPath   string // config.json
	StatusPath   string
	Keys         map[string]ed25519.PublicKey
	Clock        func() time.Time
	Timeout      time.Duration
}

// Master is a running OpenResty master the switch hot upgrades (the HTTP
// dynamic routing master, the L4 master).
type Master interface {
	// UpgradeBinary replaces the running master by one of the binary the
	// OpenResty path resolves to now (nginx binary upgrade); the old master
	// is then ended (QUIT, TERM after 10 seconds, KILL 5 seconds later), its
	// connections are cut. A failure leaves the old master serving. No
	// running master: nothing to do.
	UpgradeBinary(ctx context.Context) error
}

// Prechecker runs `openresty -t` of the live configuration through the
// current link (new binary, libraries and Lua); nothing running changes.
type Prechecker func(ctx context.Context) error

// codedError carries an upgrade status error code.
type codedError struct {
	code string
	err  error
}

func (e *codedError) Error() string      { return e.code + ": " + e.err.Error() }
func (e *codedError) Unwrap() error      { return e.err }
func (e *codedError) HealthCode() string { return e.code }

func coded(code string, err error) error { return &codedError{code: code, err: err} }

// Code is the error code of err ("" when it has none).
func Code(err error) string {
	var value *codedError
	if errors.As(err, &value) {
		return value.code
	}
	return ""
}

// Pending is a switched runtime whose running HTTP master still runs the
// previous binary: Commit hot upgrades it (or puts everything back).
type Pending struct {
	config         Config
	status         Status
	target         string
	previousTarget string
	previousConfig []byte
	switched       bool
}

// Prepare brings the files to the runtime of the running Agent: it verifies
// the source (the release's package, else the installed release that
// carries this Agent), installs it as releases/<sha>, switches the current
// link, prechecks the live configuration with it and rewrites config.json.
// On failure the previous link and config.json are back and the failed
// status is written. The caller reloads config.json after a switch.
func Prepare(ctx context.Context, config Config, precheck Prechecker) (*Pending, error) {
	if config.Clock == nil {
		config.Clock = time.Now
	}
	if config.Timeout <= 0 {
		config.Timeout = 2 * time.Minute
	}
	pending := &Pending{config: config, status: Status{Schema: StatusSchema, AgentVersion: config.AgentVersion}}
	ctx, cancel := context.WithTimeout(ctx, config.Timeout)
	defer cancel()
	if err := pending.prepare(ctx, precheck); err != nil {
		return nil, pending.finish(err)
	}
	if !pending.switched {
		return pending, pending.finish(nil)
	}
	return pending, nil
}

// Switched reports whether Prepare switched the runtime (config.json changed).
func (p *Pending) Switched() bool { return p != nil && p.switched }

// Status is the outcome so far.
func (p *Pending) Status() Status { return p.status }

// Commit hot upgrades the running masters in order (nil entries: none
// runs). A failure puts the previous runtime back and moves the masters
// already upgraded back to its binary; the status says which.
func (p *Pending) Commit(ctx context.Context, masters ...Master) error {
	if p == nil || !p.switched {
		return nil
	}
	p.switched = false
	ctx, cancel := context.WithTimeout(ctx, p.config.Timeout)
	defer cancel()
	for index, master := range masters {
		if master == nil {
			continue
		}
		if err := master.UpgradeBinary(ctx); err != nil {
			// This master kept serving on the previous binary and Lua.
			err = p.restore(err)
			for _, upgraded := range masters[:index] {
				if upgraded != nil {
					err = errors.Join(err, upgraded.UpgradeBinary(ctx))
				}
			}
			return p.finish(coded(CodeReload, err))
		}
	}
	p.status.State = StateSwitched
	prune(p.config.Root, p.target, p.previousTarget)
	return p.finish(nil)
}

// Abort puts the previous runtime back (the caller could not continue after
// Prepare, e.g. the rewritten config.json was rejected).
func (p *Pending) Abort(cause error) error {
	if p == nil || !p.switched {
		return cause
	}
	p.switched = false
	return p.finish(coded(CodeSwitch, p.restore(cause)))
}

func (p *Pending) restore(cause error) error {
	return errors.Join(cause, switchLink(p.config.Root, p.previousTarget), writeConfig(p.config.ConfigPath, p.previousConfig))
}

func (p *Pending) finish(err error) error {
	p.status.At = p.config.Clock().UTC()
	if err != nil {
		p.status.State, p.status.ErrorCode, p.status.Error = StateFailed, Code(err), truncate(err.Error())
	}
	if writeErr := writeStatus(p.config.StatusPath, p.status); writeErr != nil && err == nil {
		err = coded(CodeSwitch, writeErr)
	}
	return err
}

func (p *Pending) prepare(ctx context.Context, precheck Prechecker) error {
	config := p.config
	previousTarget, err := os.Readlink(filepath.Join(config.Root, "current"))
	if err != nil || !validReleaseTarget(previousTarget) {
		return coded(CodeSwitch, fmt.Errorf("active runtime link: %v", err))
	}
	p.previousTarget = previousTarget
	p.status.PreviousRelease = strings.TrimPrefix(previousTarget, "releases/")
	agentDigest, err := fileSHA256(config.AgentPath)
	if err != nil {
		return coded(CodeMismatch, err)
	}
	p.status.AgentSHA256 = agentDigest
	// A restart of the same Agent on the runtime it switched to last time:
	// nothing to verify again.
	last, readErr := ReadStatus(config.StatusPath)
	if readErr == nil && last.AgentSHA256 == agentDigest &&
		last.AgentVersion == config.AgentVersion && (last.State == StateSwitched || last.State == StateUnchanged) &&
		"releases/"+last.Release == previousTarget {
		p.status = last
		p.status.State, p.status.PreviousRelease = StateUnchanged, ""
		return nil
	}
	// The Agent before this one failed its switch (this is the Agent the
	// updater rolled back to): an unchanged outcome keeps reporting it.
	var rolledBack *Rollback
	if readErr == nil && last.State == StateFailed && last.AgentSHA256 != agentDigest {
		rolledBack = &Rollback{AgentVersion: last.AgentVersion, Release: last.Release, ErrorCode: last.ErrorCode}
	}
	source, err := p.source(agentDigest)
	if err != nil {
		return err
	}
	p.status.Version, p.status.OpenRestyVersion, p.status.Release = source.Manifest.Version, source.Manifest.Runtime.OpenRestyVersion, source.ManifestSHA256

	previousRelease := filepath.Join(config.Root, previousTarget)
	if active, manifest, readErr := installedRuntimeSHA256(previousRelease); readErr == nil && active == source.RuntimeSHA256() &&
		manifest.Runtime.OpenRestyVersion == source.Manifest.Runtime.OpenRestyVersion {
		// Same OpenResty, libraries and Lua: only the Agent changed.
		p.status.State, p.status.Release, p.status.PreviousRelease = StateUnchanged, strings.TrimPrefix(previousTarget, "releases/"), ""
		p.status.RolledBack = rolledBack
		return nil
	}

	p.target = "releases/" + source.ManifestSHA256
	release := filepath.Join(config.Root, p.target)
	if source.path != "" {
		if err := install(source, release); err != nil {
			return coded(CodeInstall, err)
		}
	}
	if p.previousConfig, err = os.ReadFile(config.ConfigPath); err != nil {
		return coded(CodeSwitch, err)
	}
	// Switch first, then precheck through the link, so it checks the new Lua
	// with the new binary. `openresty -t` alone never runs init_by_lua; the
	// precheck (PrecheckOpenResty) adds an init-only load that does.
	// The running masters keep their mapped binary and loaded modules.
	if err := switchLink(config.Root, p.target); err != nil {
		return coded(CodeSwitch, err)
	}
	if precheck != nil {
		if err := precheck(ctx); err != nil {
			return coded(CodePrecheck, p.restore(err))
		}
	}
	updated, err := rewriteConfig(p.previousConfig, source, release)
	if err == nil {
		err = writeConfig(config.ConfigPath, updated)
	}
	if err != nil {
		return coded(CodeSwitch, p.restore(err))
	}
	p.switched = true
	return nil
}

// source is the runtime this Agent runs with: the signed package of its
// release (native.tar.gz), else the installed release whose signed
// inventory carries this very Agent (the first installation's version has no
// package beside the Agent; a rollback to it finds it here).
func (p *Pending) source(agentDigest string) (Package, error) {
	config := p.config
	if _, err := os.Stat(config.PackagePath); err == nil {
		pkg, err := Verify(config.PackagePath, config.Keys)
		if err != nil {
			return Package{}, coded(CodeSignature, err)
		}
		if pkg.Manifest.Version != config.AgentVersion || pkg.SignedSHA256(AgentPath) != agentDigest {
			return Package{}, coded(CodeMismatch, fmt.Errorf("package %s does not carry this Agent (%s)", pkg.Manifest.Version, config.AgentVersion))
		}
		return pkg, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return Package{}, coded(CodeSignature, err)
	}
	entries, _ := os.ReadDir(filepath.Join(config.Root, "releases"))
	for _, entry := range entries {
		if !entry.IsDir() || !digestPattern.MatchString(entry.Name()) {
			continue
		}
		pkg, err := VerifyInstalledRelease(filepath.Join(config.Root, "releases", entry.Name()), config.Keys)
		if err != nil || pkg.ManifestSHA256 != entry.Name() || pkg.Manifest.Version != config.AgentVersion ||
			pkg.SignedSHA256(AgentPath) != agentDigest {
			continue
		}
		return pkg, nil
	}
	p.status.State = StateNoPackage
	return Package{}, coded(CodeNotPackaged, errors.New("no signed native runtime carries this Agent"))
}

func validReleaseTarget(target string) bool {
	name := strings.TrimPrefix(target, "releases/")
	return name != target && digestPattern.MatchString(name)
}

func install(pkg Package, release string) error {
	if info, err := os.Lstat(release); err == nil {
		// A release kept from before (the previous runtime of a rollback).
		if !info.IsDir() {
			return fmt.Errorf("%s is not a directory", release)
		}
		return verifyInstalled(release, pkg.Manifest)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	staging := filepath.Join(filepath.Dir(release), fmt.Sprintf(".staging-%s-%d", filepath.Base(release), os.Getpid()))
	_ = os.RemoveAll(staging)
	if err := pkg.Extract(staging); err != nil {
		return err
	}
	if err := os.Rename(staging, release); err != nil {
		_ = os.RemoveAll(staging)
		return err
	}
	return syncDirectory(filepath.Dir(release))
}

// switchLink points root/current at target atomically (symlink + rename).
func switchLink(root, target string) error {
	temporary := filepath.Join(root, ".current-switch")
	_ = os.Remove(temporary)
	if err := os.Symlink(target, temporary); err != nil {
		return err
	}
	if err := os.Rename(temporary, filepath.Join(root, "current")); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return syncDirectory(root)
}

// rewriteConfig sets openresty.version and the security_runtime asset paths
// and digests to the release's (signed digests; the Agent re-hashes them).
func rewriteConfig(raw []byte, pkg Package, release string) ([]byte, error) {
	var document map[string]json.RawMessage
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, fmt.Errorf("config.json: %w", err)
	}
	var openResty map[string]any
	if err := json.Unmarshal(document["openresty"], &openResty); err != nil {
		return nil, fmt.Errorf("config.json openresty: %w", err)
	}
	openResty["version"] = pkg.Manifest.Runtime.OpenRestyVersion
	encoded, err := json.Marshal(openResty)
	if err != nil {
		return nil, err
	}
	document["openresty"] = encoded
	if security, ok := document["security_runtime"]; ok {
		var value map[string]any
		if err := json.Unmarshal(security, &value); err != nil {
			return nil, fmt.Errorf("config.json security_runtime: %w", err)
		}
		if value["mode"] == "native" {
			for name, file := range map[string]string{"waf": "cdnca_waf.lua", "cc": "cc.lua", "adaptive": "cc_adaptive.lua"} {
				member := SecurityRoot + "/" + file
				digest := pkg.SignedSHA256(member)
				if digest == "" {
					return nil, fmt.Errorf("package does not sign %s", member)
				}
				value[name] = map[string]any{"path": filepath.Join(release, filepath.FromSlash(member)), "sha256": digest}
			}
			if document["security_runtime"], err = json.Marshal(value); err != nil {
				return nil, err
			}
		}
	}
	output, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(output, '\n'), nil
}

func writeConfig(path string, content []byte) error {
	temporary := path + ".runtime-switch"
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(content)
	syncErr := file.Sync()
	closeErr := file.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

// prune keeps the active and the previous release (the rollback target).
func prune(root, active, previous string) {
	entries, err := os.ReadDir(filepath.Join(root, "releases"))
	if err != nil {
		return
	}
	for _, entry := range entries {
		name := "releases/" + entry.Name()
		if name == active || name == previous || !digestPattern.MatchString(entry.Name()) {
			continue
		}
		_ = os.RemoveAll(filepath.Join(root, name))
	}
}

func writeStatus(path string, status Status) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	raw, err := json.Marshal(status)
	if err != nil {
		return err
	}
	return writeConfig(path, append(raw, '\n'))
}

// ReadStatus reads the status the last Apply wrote.
func ReadStatus(path string) (Status, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Status{}, err
	}
	var status Status
	if err := json.Unmarshal(raw, &status); err != nil || status.Schema != StatusSchema {
		return Status{}, errors.New("native runtime status is invalid")
	}
	return status, nil
}

// HealthError is nil when status shows the runtime at this Agent's version,
// otherwise an error carrying the status's code.
func HealthError(status Status, agentVersion string) error {
	switch {
	case status.AgentVersion != agentVersion:
		return coded(CodeStatusAbsent, errors.New("native runtime status is from another Agent"))
	case status.State == StateSwitched || status.State == StateUnchanged:
		return nil
	case status.ErrorCode != "":
		return coded(status.ErrorCode, errors.New(status.Error))
	default:
		return coded(CodeSwitch, errors.New("native runtime was not switched"))
	}
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func truncate(value string) string {
	if len(value) > 512 {
		return value[:512]
	}
	return value
}
