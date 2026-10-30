package edgeconfig

import "path/filepath"

const (
	ACMEHTTP01RouteMarker         = "# cdnca-acme-http01-overlay-v1"
	ACMEHTTP01ChallengePathPrefix = "/.well-known/acme-challenge/"
)

func ACMEHTTP01OverlayRoot(stateRoot string) string {
	return filepath.ToSlash(filepath.Join(stateRoot, "acme-http01", "current"))
}
