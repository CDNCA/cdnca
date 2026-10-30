package nodeidentity

import (
	"github.com/google/uuid"
)

type PublishedTelemetryListener struct {
	SiteID     string
	Domain     string
	ListenPort uint16
}

// PublishedTelemetryListeners reuses the same canonical snapshot validation as
// Gateway authorization; realtime settlement cannot invent a separate roster.
// It reads either schema the control plane publishes.
func PublishedTelemetryListeners(raw, digest []byte, scopeID, tenantID, configID uuid.UUID) ([]PublishedTelemetryListener, error) {
	_, listeners, _, err := parseTelemetrySnapshot(raw, digest, scopeID, tenantID, configID, telemetrySiteSubscriptions{})
	if err != nil {
		return nil, err
	}
	return listeners, nil
}
