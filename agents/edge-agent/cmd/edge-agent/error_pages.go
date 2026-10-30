package main

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/errorpage"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/gatewayclient"
)

// errorPageStateRoot holds the published error page policies (agent-owned).
func errorPageStateRoot(deploymentRoot string) string {
	return filepath.Join(deploymentRoot, "errorpage")
}

// errorPageNodeRuntime installs a new error page policy on a dynamic routing
// node: the pages reach the workers inside the site objects and node pages
// (control renders them from the same policy), so the snapshot is checked
// and recorded, and nothing reloads.
type errorPageNodeRuntime struct {
	precheck *errorpage.OpenRestyRuntime
}

func (runtime errorPageNodeRuntime) Precheck(ctx context.Context, release string) error {
	return runtime.precheck.Precheck(ctx, release)
}

func (errorPageNodeRuntime) Activate(context.Context, string) error { return nil }

func (errorPageNodeRuntime) Health(context.Context, string, errorpage.Artifact) error { return nil }

func (errorPageNodeRuntime) Stop(context.Context) error { return nil }

// assembleErrorPages is the gateway consumer for signed error page snapshots
// (FX43: production never wired it, so every publication was refused).
func assembleErrorPages(openRestyBinary, deploymentRoot string, trust *gatewayclient.TrustStore) (gatewayclient.ErrorPageArtifactConsumer, error) {
	precheck, err := errorpage.NewOpenRestyRuntime(errorpage.OpenRestyRuntimeConfig{
		Binary: openRestyBinary, RuntimePrefix: deploymentRoot, ConfigFile: "nginx.conf",
		Probe: func(context.Context, errorpage.Artifact) error { return nil },
	})
	if err != nil {
		return nil, fmt.Errorf("configure error page precheck: %w", err)
	}
	publisher, err := errorpage.NewPublisher(errorPageStateRoot(deploymentRoot), "", errorPageNodeRuntime{precheck: precheck})
	if err != nil {
		return nil, fmt.Errorf("configure error page publisher: %w", err)
	}
	return gatewayclient.NewErrorPageArtifactConsumer(publisher, trust)
}
