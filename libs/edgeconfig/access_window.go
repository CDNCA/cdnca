package edgeconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"
)

const AccessWindowType = "access_window.v1"

type AccessWindowEvent struct {
	MetricVersion         uint16    `json:"metric_version"`
	EventID               string    `json:"event_id"`
	WindowStart           time.Time `json:"window_start"`
	WindowEnd             time.Time `json:"window_end"`
	TenantID              string    `json:"tenant_id"`
	PackageSubscriptionID string    `json:"package_subscription_id"`
	SiteID                string    `json:"site_id"`
	NodeID                string    `json:"node_id"`
	InstallationID        string    `json:"installation_id"`
	ConfigVersionID       string    `json:"config_version_id"`
	Host                  string    `json:"host"`
	ListenPort            uint16    `json:"listen_port"`
	SourceWatermark       uint64    `json:"source_watermark"`
	FinalizedThrough      time.Time `json:"finalized_through"`
	DependencyState       string    `json:"dependency_state"`
	EvidenceSHA256        string    `json:"evidence_sha256"`
}

type AccessWindowEnvelope struct {
	SchemaVersion         uint16              `json:"schema_version"`
	Type                  string              `json:"type"`
	MessageID             string              `json:"message_id"`
	ProducedAt            time.Time           `json:"produced_at"`
	TenantID              string              `json:"tenant_id"`
	InstallationID        string              `json:"installation_id"`
	NodeID                string              `json:"node_id"`
	PackageSubscriptionID string              `json:"package_subscription_id"`
	Events                []AccessWindowEvent `json:"events"`
}

func AccessWindowEventID(event AccessWindowEvent) string {
	event.EventID, event.InstallationID, event.PackageSubscriptionID = "", "", ""
	encoded, _ := json.Marshal(event)
	digest := sha256.Sum256(append([]byte("cdnca.access-window.event/v1\x00"), encoded...))
	return "access_window_" + hex.EncodeToString(digest[:])
}

func AccessWindowMessageID(envelope AccessWindowEnvelope) string {
	envelope.MessageID, envelope.InstallationID, envelope.PackageSubscriptionID = "", "", ""
	envelope.Events = append([]AccessWindowEvent(nil), envelope.Events...)
	for i := range envelope.Events {
		envelope.Events[i].InstallationID, envelope.Events[i].PackageSubscriptionID = "", ""
	}
	encoded, _ := json.Marshal(envelope)
	digest := sha256.Sum256(append([]byte("cdnca.access-window.message/v1\x00"), encoded...))
	return "window_" + hex.EncodeToString(digest[:])
}

func ValidAccessWindowEvent(event AccessWindowEvent) bool {
	if event.MetricVersion != 1 || event.EventID != AccessWindowEventID(event) ||
		event.WindowStart.IsZero() || !event.WindowStart.Equal(event.WindowStart.UTC().Truncate(time.Hour)) ||
		!event.WindowEnd.Equal(event.WindowStart.Add(time.Hour)) || !event.FinalizedThrough.Equal(event.WindowEnd) ||
		event.DependencyState != "ready" || event.SourceWatermark == 0 || event.ListenPort == 0 ||
		event.Host == "" || event.Host != strings.ToLower(event.Host) || strings.ContainsAny(event.Host, " /:@\r\n\t") || len(event.Host) > 253 {
		return false
	}
	for _, value := range []string{event.TenantID, event.SiteID, event.NodeID, event.ConfigVersionID} {
		if !uuidPattern.MatchString(value) || value == "00000000-0000-0000-0000-000000000000" || value != strings.ToLower(value) {
			return false
		}
	}
	digest, err := hex.DecodeString(event.EvidenceSHA256)
	return err == nil && len(digest) == 32 && event.EvidenceSHA256 == strings.ToLower(event.EvidenceSHA256) && event.EvidenceSHA256 != strings.Repeat("0", 64)
}
