package dynroute

import (
	"context"
	"path/filepath"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/originauth"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgeskeleton"
)

// OriginAuthSecrets is the worker readable secret object directory the
// skeleton's cdnca_originauth signs from (D5b): the origin auth installer
// writes it with WithSecretObjects.
func (runtime *Runtime) OriginAuthSecrets() originauth.SecretObjectDir {
	return originauth.SecretObjectDir{Root: filepath.Join(runtime.config.StateRoot, edgeskeleton.OriginAuthDirectory), GID: runtime.config.WorkerGID}
}

// OriginAuthRuntime is the origin auth installer's runtime on a dynamic
// routing node: the workers read a new secret object at request time (the
// site object names its revision), so nothing is checked or reloaded.
type OriginAuthRuntime struct{}

func (OriginAuthRuntime) Precheck(context.Context, originauth.ProductionCandidate) error { return nil }
func (OriginAuthRuntime) Activate(context.Context, originauth.ProductionCandidate) error { return nil }
