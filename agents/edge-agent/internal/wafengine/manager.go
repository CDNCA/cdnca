package wafengine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/entitlement/enginemodule"
)

// Config locates the extension and its trust.
//   - Root: protected directory owned by the agent (versions/, installed.json;
//     gates are not here: they live in edgeconfig.WAFEngineGateRoot(StateRoot)).
//   - StateRoot: the deployment root nginx.conf's gate includes point into.
//   - OpenRestyVersion / Architecture: this node; a build for another
//     platform is refused. Empty OpenRestyVersion: the engine is unavailable
//     (every module is refused and CRS sites run self-developed detection only).
//   - Trust: platform release keys (signatures.json); see Trust.
type Config struct {
	Root             string
	StateRoot        string
	OpenRestyVersion string
	Architecture     string
	Trust            Trust
	Now              func() time.Time
}

// Status is the last gate decision, reported with deployment status.
type Status struct {
	State           string `json:"state"` // not_required | active | degraded
	Reason          string `json:"reason,omitempty"`
	Version         string `json:"version,omitempty"`
	ConfigVersionID string `json:"config_version_id,omitempty"`
	UpdatedAt       int64  `json:"updated_at"`
}

const (
	StateNotRequired = "not_required"
	StateActive      = "active"
	StateDegraded    = "degraded"

	// ReasonUnavailable: no engine module is installed (the node artifact set
	// holds none for this node, or this node cannot run one).
	ReasonUnavailable    = "engine_unavailable"
	ReasonSignature      = "signature_invalid"
	ReasonManifest       = "manifest_mismatch"
	ReasonPayload        = "payload_mismatch"
	ReasonInstall        = "install_failed"
	ReasonGatePath       = "gate_path_mismatch"
	ReasonModuleLoad     = "module_load_failed"
	ReasonRestart        = "restart_failed"
	ReasonInvalidRelease = "invalid_engine_manifest"
)

var ErrInvalidConfig = errors.New("invalid waf engine configuration")

// installed is installed.json: the active build. The signed manifest bytes
// and signatures.json are kept so every Prepare re-verifies the build
// against the node's trust as it is then (a revoked signer stops loading).
type installed struct {
	ArtifactID    string `json:"artifact_id"`
	Revision      uint64 `json:"revision"`
	BundleSHA256  string `json:"bundle_sha256"`
	ManifestBytes []byte `json:"manifest"`
	Signatures    []byte `json:"signatures"`
	Path          string `json:"path"`
	Signer        Signer `json:"signer"`
	InstalledAt   int64  `json:"installed_at"`
}

// Manager owns Root, the gate directories and the engine status.
type Manager struct {
	mu     sync.Mutex
	config Config
	status Status
}

func NewManager(config Config) (*Manager, error) {
	if !filepath.IsAbs(config.Root) || filepath.Clean(config.Root) != config.Root ||
		!filepath.IsAbs(config.StateRoot) || filepath.Clean(config.StateRoot) != config.StateRoot ||
		config.OpenRestyVersion != "" && (!enginemodule.ValidOpenRestyVersion(config.OpenRestyVersion) ||
			!enginemodule.ValidArchitecture(config.Architecture) || config.Trust.empty()) {
		return nil, ErrInvalidConfig
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if err := os.MkdirAll(filepath.Join(config.Root, "versions"), 0o755); err != nil {
		return nil, err
	}
	manager := &Manager{config: config, status: Status{State: StateNotRequired}}
	if content, err := os.ReadFile(filepath.Join(config.Root, "status.json")); err == nil {
		_ = json.Unmarshal(content, &manager.status)
	}
	return manager, nil
}

// Status returns the last gate decision.
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.status
}

func (m *Manager) setStatus(status Status) {
	status.UpdatedAt = m.config.Now().UTC().Unix()
	m.status = status
	if encoded, err := json.Marshal(status); err == nil {
		_ = writeAtomic(filepath.Join(m.config.Root, "status.json"), encoded, 0o644)
	}
}

func (m *Manager) statePath() string { return filepath.Join(m.config.Root, "installed.json") }

func (m *Manager) readInstalled() (*installed, error) {
	content, err := os.ReadFile(m.statePath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var current installed
	if err := json.Unmarshal(content, &current); err != nil {
		return nil, ErrManifest
	}
	return &current, nil
}

// Installed returns the active build's artifact ID and version ("" if none).
func (m *Manager) Installed() (artifactID, version string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	current, err := m.readInstalled()
	if err != nil || current == nil {
		return "", ""
	}
	manifest, err := enginemodule.DecodeManifest(current.ManifestBytes)
	if err != nil {
		return current.ArtifactID, ""
	}
	return current.ArtifactID, manifest.Version
}

// VerifiedPaths re-verifies the active build for this node (platform,
// trusted signature, every file) and returns its module and unicode mapping
// paths; the dynamic routing skeleton loads the engine from them
// (dynwaf.Engine). An error means no usable engine is installed.
func (m *Manager) VerifiedPaths() (modulePath, unicodeMapPath string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	current, _, _, err := m.verifyInstalled()
	if err != nil {
		return "", "", err
	}
	return filepath.Join(current.Path, ModulePath), filepath.Join(current.Path, UnicodeMapPath), nil
}

// verifyInstalled re-checks the active build for this node now: platform,
// a platform release signature trusted now, every installed file. The
// reason classifies a failure for the status report.
func (m *Manager) verifyInstalled() (installed, Manifest, string, error) {
	current, err := m.readInstalled()
	if err != nil {
		return installed{}, Manifest{}, ReasonManifest, err
	}
	if current == nil || m.config.OpenRestyVersion == "" {
		return installed{}, Manifest{}, ReasonUnavailable, errors.New("no waf engine module is installed")
	}
	manifest, err := enginemodule.DecodeManifest(current.ManifestBytes)
	if err != nil {
		return installed{}, Manifest{}, ReasonManifest, err
	}
	if err := m.matchPlatform(manifest); err != nil {
		return installed{}, Manifest{}, ReasonManifest, err
	}
	signatures, err := enginemodule.ParseSignatures(current.Signatures)
	if err != nil {
		return installed{}, Manifest{}, ReasonSignature, err
	}
	if _, err := VerifySignature(current.ManifestBytes, signatures, m.config.Trust); err != nil {
		return installed{}, Manifest{}, ReasonSignature, err
	}
	if filepath.Dir(current.Path) != filepath.Join(m.config.Root, "versions") {
		return installed{}, Manifest{}, ReasonPayload, ErrPayload
	}
	if err := VerifyInstalled(current.Path, manifest); err != nil {
		return installed{}, Manifest{}, ReasonPayload, err
	}
	return *current, manifest, "", nil
}

func (m *Manager) matchPlatform(manifest Manifest) error {
	if manifest.OpenRestyVersion != m.config.OpenRestyVersion || manifest.Architecture != m.config.Architecture ||
		manifest.Platform != "linux" {
		return ErrManifest
	}
	return nil
}

// Gate is the decision for one release.
type Gate struct {
	ConfigVersionID string
	Required        bool
	ModulePath      string // "" = the module is not loaded for this release
}

func (m *Manager) gateDir(versionID string) string {
	return filepath.FromSlash(edgeconfig.WAFEngineGateDir(filepath.ToSlash(m.config.StateRoot), versionID))
}

// Prepare writes (or removes) the gate of the release at releasePath. It
// never fails the deployment for engine reasons: the gate is simply absent
// and the status says why. An error means the gate directory itself could
// not be written or removed.
func (m *Manager) Prepare(_ context.Context, versionID, releasePath string) (Gate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	gate := Gate{ConfigVersionID: versionID}
	resolved, err := filepath.EvalSymlinks(releasePath)
	if err != nil {
		return gate, err
	}
	content, err := os.ReadFile(filepath.Join(resolved, filepath.FromSlash(edgeconfig.WAFEngineManifestPath)))
	if errors.Is(err, os.ErrNotExist) {
		m.setStatus(Status{State: StateNotRequired, ConfigVersionID: versionID})
		return gate, m.removeGate(versionID)
	}
	gate.Required = true
	degrade := func(reason, version string) (Gate, error) {
		m.setStatus(Status{State: StateDegraded, Reason: reason, Version: version, ConfigVersionID: versionID})
		return gate, m.removeGate(versionID)
	}
	if err != nil {
		return degrade(ReasonInvalidRelease, "")
	}
	manifest, err := edgeconfig.ParseWAFEngineManifest(content)
	if err != nil {
		return degrade(ReasonInvalidRelease, "")
	}
	nginx, err := os.ReadFile(filepath.Join(resolved, "nginx.conf"))
	if err != nil || !bytes.Contains(nginx, []byte("include "+filepath.ToSlash(m.gateDir(versionID))+"/load[.]conf;")) {
		return degrade(ReasonGatePath, "")
	}
	if m.disabled(versionID) {
		return degrade(ReasonModuleLoad, "")
	}
	current, module, reason, err := m.verifyInstalled()
	if err != nil {
		return degrade(reason, module.Version)
	}
	files, err := edgeconfig.RenderWAFEngineGate(manifest, edgeconfig.WAFEngineGate{
		ReleasePath: filepath.ToSlash(resolved), ModulePath: filepath.ToSlash(filepath.Join(current.Path, ModulePath)),
		UnicodeMapPath: filepath.ToSlash(filepath.Join(current.Path, UnicodeMapPath))})
	if err != nil {
		return degrade(ReasonGatePath, module.Version)
	}
	if err := m.writeGate(versionID, files); err != nil {
		return gate, err
	}
	gate.ModulePath = filepath.Join(current.Path, ModulePath)
	m.setStatus(Status{State: StateActive, Version: module.Version, ConfigVersionID: versionID})
	return gate, nil
}

// Disable records that the module could not be loaded for a release (nginx
// -t or a restart failed with the gate) and removes the gate.
func (m *Manager) Disable(versionID, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := writeAtomic(filepath.Join(m.config.Root, "disabled", versionID), []byte(reason+"\n"), 0o644); err != nil {
		return err
	}
	m.setStatus(Status{State: StateDegraded, Reason: reason, Version: m.status.Version, ConfigVersionID: versionID})
	return m.removeGate(versionID)
}

func (m *Manager) disabled(versionID string) bool {
	_, err := os.Stat(filepath.Join(m.config.Root, "disabled", versionID))
	return err == nil
}

// LoadedModule is the module path the running master loaded ("" = none).
func (m *Manager) LoadedModule() string {
	content, err := os.ReadFile(filepath.Join(m.config.Root, "loaded"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(content))
}

func (m *Manager) SetLoadedModule(module string) error {
	return writeAtomic(filepath.Join(m.config.Root, "loaded"), []byte(module+"\n"), 0o644)
}

func (m *Manager) writeGate(versionID string, files map[string][]byte) error {
	root := filepath.Dir(m.gateDir(versionID))
	if err := os.MkdirAll(root, 0o755); err != nil {
		return err
	}
	staging, err := os.MkdirTemp(root, ".gate-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(staging)
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(staging, name), content, 0o644); err != nil {
			return err
		}
	}
	if err := os.Chmod(staging, 0o755); err != nil {
		return err
	}
	target := m.gateDir(versionID)
	if err := os.RemoveAll(target); err != nil {
		return err
	}
	if err := os.Rename(staging, target); err != nil {
		return err
	}
	return m.pruneGates(versionID)
}

func (m *Manager) removeGate(versionID string) error {
	if err := os.RemoveAll(m.gateDir(versionID)); err != nil {
		return err
	}
	return m.pruneGates(versionID)
}

// pruneGates keeps the gates of the newest releases (rollback targets and a
// master restarted out of band keep their module) and removes older ones.
func (m *Manager) pruneGates(keep string) error {
	root := filepath.Dir(m.gateDir(keep))
	entries, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	type gate struct {
		name string
		time time.Time
	}
	gates := []gate{}
	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") || entry.Name() == keep {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		gates = append(gates, gate{entry.Name(), info.ModTime()})
	}
	sort.Slice(gates, func(i, j int) bool { return gates[i].time.After(gates[j].time) })
	for index, item := range gates {
		if index >= 4 {
			if err := os.RemoveAll(filepath.Join(root, item.name)); err != nil {
				return err
			}
		}
	}
	return nil
}

func writeAtomic(path string, content []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".tmp-")
	if err != nil {
		return err
	}
	name := temp.Name()
	defer os.Remove(name)
	if _, err := io.Copy(temp, bytes.NewReader(content)); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(name, mode); err != nil {
		return err
	}
	return os.Rename(name, path)
}
