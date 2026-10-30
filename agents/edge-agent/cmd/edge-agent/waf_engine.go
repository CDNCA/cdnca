package main

import (
	"errors"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/gatewayclient"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/nodeartifacts"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/wafengine"
	"github.com/cdnca/cdnca/libs/edgeconfig/artifactset"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/protobuf/types/known/durationpb"
)

// wafEngineSettings: the extension arrives as an item of the node artifact
// set (license catalog -> control plane -> node, ADR 0007 B3). It is signed
// by the platform release keys that verified this node's package
// (artifact_trust_file), checked again on the node (wafengine.Trust).
// Disabled, or without an OpenResty version, every module item is refused
// (platform_mismatch), CRS sites run self-developed detection only and the
// status says engine_unavailable. Timeout is accepted for configurations
// written by earlier installers and has no effect.
type wafEngineSettings struct {
	Disabled bool   `json:"disabled,omitempty"`
	Root     string `json:"root,omitempty"`
	Timeout  string `json:"timeout,omitempty"`
}

// validate: root must be an absolute clean directory inside deployment_root
// (the native OpenResty unit only reads below /var/lib/cdnca-edge).
func (settings wafEngineSettings) validate(config fileConfig) error {
	if settings.Root != "" && (!absoluteCleanPath(settings.Root) || settings.Root == config.DeploymentRoot ||
		!strings.HasPrefix(settings.Root, config.DeploymentRoot+string(filepath.Separator))) {
		return errors.New("waf_engine.root must be an absolute clean path inside deployment_root")
	}
	if settings.Timeout != "" {
		parsed, err := time.ParseDuration(settings.Timeout)
		if err != nil || parsed <= 0 || parsed > time.Hour {
			return errors.New("waf_engine.timeout is invalid")
		}
	}
	return nil
}

func assembleWAFEngine(config fileConfig, releaseTrust *gatewayclient.TrustStore) (*wafengine.Manager, error) {
	root := config.WAFEngine.Root
	if root == "" {
		root = filepath.Join(config.DeploymentRoot, "extensions", "waf-crs")
	}
	settings := wafengine.Config{Root: root, StateRoot: config.DeploymentRoot}
	if config.WAFEngine.Disabled || config.OpenResty.Version == "" {
		return wafengine.NewManager(settings)
	}
	settings.OpenRestyVersion, settings.Architecture = config.OpenResty.Version, runtime.GOARCH
	// Live lookups: a node signer trust revocation applies to the next
	// install and the next Prepare, including a build installed before it
	// (wafengine signer_revocation_test.go).
	settings.Trust = wafengine.Trust{ReleaseKey: releaseTrust.Ed25519Key, Revoked: releaseTrust.RevokedEd25519}
	return wafengine.NewManager(settings)
}

// engineModuleInstaller is the node artifact set installer of
// MediaTypeEngineModule.
type engineModuleInstaller struct{ engine *wafengine.Manager }

func (installer engineModuleInstaller) Prepare(item artifactset.Item, content []byte, now time.Time) (nodeartifacts.Staged, error) {
	staged, err := installer.engine.PrepareModule(content, wafengine.Expected{ArtifactID: item.ArtifactID,
		Version: item.Version, Revision: item.Revision}, now)
	if err != nil {
		return nil, err
	}
	return staged, nil
}

func (installer engineModuleInstaller) Remove() error { return installer.engine.RemoveModule() }

// wafEngineChecks reports the engine gate with every terminal deployment.
func wafEngineChecks(engine *wafengine.Manager) func() []*agentv1.CheckResult {
	return func() []*agentv1.CheckResult {
		summary, ok := engine.Status().CheckSummary()
		return []*agentv1.CheckResult{{Name: "edge_waf_crs_engine", Succeeded: ok, Summary: summary,
			LatencyDuration: durationpb.New(0)}}
	}
}
