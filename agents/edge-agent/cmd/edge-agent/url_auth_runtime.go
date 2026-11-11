package main

import (
	"context"
	"log/slog"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/urlauth"
)

// urlAuthReapplyingRuntime installs a URL auth artifact and applies dynamic
// routing again: the skeleton preloads only installed policy
// versions, so a version that arrives after the site object that references
// it is loaded by this reapply (the site answered 503 until then).
type urlAuthReapplyingRuntime struct {
	runtime *urlauth.ArtifactRuntime
	reapply func(context.Context) error
}

func (r urlAuthReapplyingRuntime) InstallJSON(raw []byte, binding urlauth.ArtifactBinding) (urlauth.Publication, error) {
	publication, err := r.runtime.InstallJSON(raw, binding)
	if err != nil {
		return publication, err
	}
	// Not under the deployment command: the reapply takes the dynamic
	// routing lock, which a running activation may hold.
	go func() {
		if err := r.reapply(context.Background()); err != nil {
			slog.Warn("URL auth: dynamic routing reapply failed", "policy_id", binding.PolicyID,
				"policy_version", binding.PolicyVersion, "error", err)
		}
	}()
	return publication, nil
}
