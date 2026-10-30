package main

import (
	"fmt"
	"path/filepath"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/dynroute"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/originauth"
)

// originAuthPolicyRoot holds the installed origin auth policy; credentials
// live beside it in keys/ (both agent-private).
func originAuthPolicyRoot(deploymentRoot string) string {
	return filepath.Join(deploymentRoot, "originauth", "policy")
}

// assembleOriginAuth is the gateway consumer for sealed origin auth snapshots
// (NF03: the daemon never installed them, so rules were never applied). The
// dynamic routing workers sign from the secret objects at request time;
// installing a snapshot writes them, nothing reloads.
func assembleOriginAuth(deploymentRoot string, dynamic *dynroute.Runtime) (*originauth.ProductionSnapshotInstaller, error) {
	installer, err := originauth.NewProductionSnapshotInstaller(originAuthPolicyRoot(deploymentRoot),
		filepath.Join(deploymentRoot, "originauth", "keys"), dynroute.OriginAuthRuntime{})
	if err == nil {
		err = installer.WithSecretObjects(dynamic.OriginAuthSecrets())
	}
	if err != nil {
		return nil, fmt.Errorf("configure origin auth installer: %w", err)
	}
	return installer, nil
}
