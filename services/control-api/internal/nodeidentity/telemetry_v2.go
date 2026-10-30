package nodeidentity

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/google/uuid"
)

const (
	telemetrySnapshotSchemaPrefix = "cdnca.edge.site-runtime/"
	telemetrySnapshotSchemaV2     = telemetrySnapshotSchemaPrefix + "v2"
)

// TelemetrySnapshotError says why a config version's canonical snapshot gives
// no telemetry bindings; it unwraps to ErrPersistence.
type TelemetrySnapshotError struct {
	ConfigVersionID uuid.UUID
	Reason          string
}

func (e *TelemetrySnapshotError) Error() string {
	return fmt.Sprintf("%v: config version %s: %s", ErrPersistence, e.ConfigVersionID, e.Reason)
}

func (e *TelemetrySnapshotError) Unwrap() error { return ErrPersistence }

func telemetrySnapshotError(configVersionID uuid.UUID, reason string) error {
	return &TelemetrySnapshotError{ConfigVersionID: configVersionID, Reason: reason}
}

// telemetrySiteRuntimeV2 is the part of a site runtime v2 canonical document
// (edgepublish.siteRuntimeV2Document) telemetry needs. The digest already
// binds the bytes to what the control plane published; this checks identity
// and the listener roster.
type telemetrySiteRuntimeV2 struct {
	Schema               string                       `json:"schema"`
	ConfigurationScopeID string                       `json:"configuration_scope_id"`
	SourceRevision       int64                        `json:"source_revision"`
	ConfigVersionID      string                       `json:"config_version_id"`
	Sites                []telemetrySiteRuntimeV2Site `json:"sites"`
	Streams              *edgeconfig.StreamRuntime    `json:"streams,omitempty"`
}

type telemetrySiteRuntimeV2Site struct {
	ID            string                             `json:"id"`
	Revision      int64                              `json:"revision"`
	Domains       []string                           `json:"domains"`
	Listeners     []telemetrySiteRuntimeV2Listener   `json:"listeners"`
	PackageLimits *edgeconfig.PackageConnectionLimit `json:"package_limits,omitempty"`
}

type telemetrySiteRuntimeV2Listener struct {
	Port      int64           `json:"port"`
	Protocols []string        `json:"protocols"`
	TLS       json.RawMessage `json:"tls,omitempty"`
}

// telemetrySiteSubscriptions are the package subscriptions recorded for the
// sites of one config version. recorded is set when the publication wrote
// every site's subscription (migration 295); otherwise sites come from the
// package monitor bindings (114) and may be missing.
type telemetrySiteSubscriptions struct {
	sites    map[uuid.UUID]uuid.UUID
	recorded bool
}

// telemetrySnapshotSchema reads the schema of a canonical snapshot.
func telemetrySnapshotSchema(raw []byte) (string, error) {
	var head struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(raw, &head); err != nil {
		return "", err
	}
	return head.Schema, nil
}

// telemetrySiteRuntimeCandidate reports whether a deployed config version
// may carry sites: any site runtime schema, or a snapshot that does not
// decode (it still fails closed in parseTelemetrySnapshot). JSON documents of
// another schema (node artifact set and segments, certificate and challenge
// publications) carry no site.
func telemetrySiteRuntimeCandidate(raw []byte) bool {
	schema, err := telemetrySnapshotSchema(raw)
	return err != nil || strings.HasPrefix(schema, telemetrySnapshotSchemaPrefix)
}

// parseTelemetrySiteRuntimeV2 binds the sites of a site runtime v2 snapshot:
// one binding per site, with the site's package subscription. The v2 document carries the
// subscription only with a connection limit; subscriptions (what the
// publication recorded for this version) supplies it otherwise. For a
// version published before migration 295 the record may be incomplete: the
// document's limit wins and sites stay unattributed rather than failing the
// node; those sites are returned as unverified. It returns the bindings, the
// site listeners and the unverified sites.
func parseTelemetrySiteRuntimeV2(
	raw []byte,
	configurationScopeID, tenantID, configVersionID uuid.UUID,
	subscriptions telemetrySiteSubscriptions,
) ([]TelemetrySiteScope, []PublishedTelemetryListener, []uuid.UUID, error) {
	var document telemetrySiteRuntimeV2
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, nil, nil, telemetrySnapshotError(configVersionID, "site runtime v2 document does not decode")
	}
	if document.Schema != telemetrySnapshotSchemaV2 || document.ConfigurationScopeID != configurationScopeID.String() ||
		document.ConfigVersionID != configVersionID.String() || document.SourceRevision < 1 || document.Sites == nil {
		return nil, nil, nil, telemetrySnapshotError(configVersionID, "site runtime v2 identity does not match the config version")
	}
	var unverified []uuid.UUID
	bindings := make([]TelemetrySiteScope, 0, len(document.Sites))
	listeners := make([]PublishedTelemetryListener, 0, len(document.Sites))
	seen := make(map[uuid.UUID]struct{}, len(document.Sites))
	var claims []edgeconfig.PortClaim
	for _, site := range document.Sites {
		siteID, err := uuid.Parse(site.ID)
		if err != nil || siteID == uuid.Nil || siteID.String() != site.ID || site.Revision < 1 ||
			len(site.Domains) == 0 || site.Domains[0] == "" || len(site.Listeners) == 0 {
			return nil, nil, nil, telemetrySnapshotError(configVersionID, "site runtime v2 site is invalid")
		}
		if _, duplicate := seen[siteID]; duplicate {
			return nil, nil, nil, telemetrySnapshotError(configVersionID, "site runtime v2 site is duplicated")
		}
		seen[siteID] = struct{}{}
		subscriptionID, known := subscriptions.sites[siteID]
		if site.PackageLimits != nil {
			limit, err := uuid.Parse(site.PackageLimits.SubscriptionID)
			if site.PackageLimits.Validate() != nil || err != nil {
				return nil, nil, nil, telemetrySnapshotError(configVersionID, "site runtime v2 package limit is invalid")
			}
			if subscriptions.recorded && subscriptionID != limit {
				return nil, nil, nil, telemetrySnapshotError(configVersionID, "site runtime v2 package subscription is inconsistent")
			}
			subscriptionID, known = limit, true
		}
		switch {
		case subscriptions.recorded && !known:
			return nil, nil, nil, telemetrySnapshotError(configVersionID, "site runtime v2 site has no recorded telemetry binding")
		case !subscriptions.recorded && !known:
			unverified = append(unverified, siteID)
		}
		for _, listener := range site.Listeners {
			if listener.Port < 1 || listener.Port > 65535 {
				return nil, nil, nil, telemetrySnapshotError(configVersionID, "site runtime v2 listener port is invalid")
			}
			// The control plane lists a site's primary domain first
			// (edgepublish siteRuntimeV2Domains), the telemetry domain.
			listeners = append(listeners, PublishedTelemetryListener{SiteID: site.ID, Domain: site.Domains[0], ListenPort: uint16(listener.Port)})
			tls := len(listener.TLS) != 0 && string(listener.TLS) != "null"
			http3 := false
			for _, protocol := range listener.Protocols {
				http3 = http3 || protocol == "http3"
			}
			claims = append(claims, edgeconfig.SiteListenerPortClaims("", site.ID, uint16(listener.Port), tls, http3, site.Domains)...)
		}
		bindings = append(bindings, TelemetrySiteScope{
			SiteID: siteID, TenantID: tenantID, ConfigurationScopeID: configurationScopeID,
			ConfigVersionID: configVersionID, PackageSubscriptionID: subscriptionID,
		})
	}
	if document.Streams != nil {
		// The same structural check the control plane applies before it
		// publishes the L4 sidecar.
		runtime := *document.Streams
		if runtime.TenantID != tenantID.String() {
			return nil, nil, nil, telemetrySnapshotError(configVersionID, "site runtime v2 streams name another tenant")
		}
		if _, _, err := edgeconfig.RenderSharedStreamFragment(document.ConfigVersionID, uint64(document.SourceRevision),
			runtime, telemetryV2HealthPort(claims, runtime), claims); err != nil {
			return nil, nil, nil, telemetrySnapshotError(configVersionID, "site runtime v2 streams are invalid")
		}
		// Since tcp/udp v12 a forward is its own telemetry partition: the
		// node puts the stream ID where a site ID goes. Its binding carries
		// the package the release named (L4_PACKAGE_ATTRIBUTION), which the
		// Gateway checks on every L4 session fact.
		for _, stream := range runtime.StreamsV2 {
			streamID, err := uuid.Parse(stream.StreamID)
			if err != nil || streamID.String() != stream.StreamID {
				return nil, nil, nil, telemetrySnapshotError(configVersionID, "site runtime v2 stream is invalid")
			}
			if _, duplicate := seen[streamID]; duplicate {
				return nil, nil, nil, telemetrySnapshotError(configVersionID, "site runtime v2 stream is duplicated")
			}
			seen[streamID] = struct{}{}
			var subscriptionID uuid.UUID
			if stream.PackageSubscriptionID != "" {
				if subscriptionID, err = uuid.Parse(stream.PackageSubscriptionID); err != nil || subscriptionID == uuid.Nil {
					return nil, nil, nil, telemetrySnapshotError(configVersionID, "site runtime v2 stream package is invalid")
				}
			}
			bindings = append(bindings, TelemetrySiteScope{
				SiteID: streamID, TenantID: tenantID, ConfigurationScopeID: configurationScopeID,
				ConfigVersionID: configVersionID, PackageSubscriptionID: subscriptionID,
			})
		}
	}
	return bindings, listeners, unverified, nil
}

// telemetryV2HealthPort picks a port no listener uses, as the v1 path does.
func telemetryV2HealthPort(claims []edgeconfig.PortClaim, runtime edgeconfig.StreamRuntime) uint16 {
	used := make(map[uint16]struct{})
	for _, claim := range claims {
		used[claim.Port] = struct{}{}
	}
	for _, stream := range runtime.StreamsV2 {
		for _, claim := range edgeconfig.L4StreamPortClaims("", stream) {
			used[claim.Port] = struct{}{}
		}
	}
	for candidate := uint16(65535); candidate > 0; candidate-- {
		if _, exists := used[candidate]; !exists {
			return candidate
		}
	}
	return 0
}

// telemetrySnapshotReason is the reason recorded for a snapshot that gives no
// bindings.
func telemetrySnapshotReason(err error) string {
	var snapshotErr *TelemetrySnapshotError
	if errors.As(err, &snapshotErr) {
		return snapshotErr.Reason
	}
	return "canonical snapshot is invalid"
}
