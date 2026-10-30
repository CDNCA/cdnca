package edgeconfig

// StreamRuntime is a scope's L4 forwards (v2 streams; 1.0.35 has no v1).
type StreamRuntime struct {
	TenantID  string              `json:"tenant_id"`
	StreamsV2 []L4StreamRuntimeV2 `json:"streams_v2,omitempty"`
}

// RenderStreamFragment validates runtime's streams with every socket
// exclusive and occupiedPorts reserved, and returns the L4 runtime artifact
// (L4RuntimeV2ArtifactPath; none without streams). The nginx part is
// always empty: v2 streams run in the L4 runtime.
func RenderStreamFragment(versionID string, revision uint64, runtime StreamRuntime, occupiedPorts []uint16) (string, map[string][]byte, error) {
	for _, stream := range runtime.StreamsV2 {
		for _, claim := range L4StreamPortClaims("", stream) {
			for _, port := range occupiedPorts {
				if port >= claim.Port && port <= claim.LastPort() {
					return "", nil, ErrInvalidConfig
				}
			}
		}
	}
	return renderStreamFragment(versionID, revision, runtime, false)
}

// RenderSharedStreamFragment is RenderStreamFragment for agents with tcp/udp
// API v4: v2 streams may share ports with the given website claims (see
// SiteListenerPortClaims) and with each other under FindPortConflicts. The
// health port stays exclusive.
func RenderSharedStreamFragment(versionID string, revision uint64, runtime StreamRuntime, healthPort uint16,
	siteClaims []PortClaim) (string, map[string][]byte, error) {
	claims := append([]PortClaim{{Kind: PortClaimReserved, Protocol: StreamProtocolTCP, Port: healthPort}}, siteClaims...)
	for _, stream := range runtime.StreamsV2 {
		claims = append(claims, L4StreamPortClaims("", stream)...)
	}
	if len(FindPortConflicts(claims)) != 0 {
		return "", nil, ErrInvalidConfig
	}
	return renderStreamFragment(versionID, revision, runtime, true)
}

func renderStreamFragment(versionID string, revision uint64, runtime StreamRuntime, shared bool) (string, map[string][]byte, error) {
	value, err := normalize(Spec{ConfigVersionID: versionID, ConfigRevision: revision, TenantID: runtime.TenantID,
		HealthPort: 1, StateRoot: "/var/lib/cdnca-stream-validation", L4StreamsV2: runtime.StreamsV2,
		AllowEmpty: true, SharedL4Ports: shared})
	if err != nil {
		return "", nil, err
	}
	files := make(map[string][]byte)
	if len(value.L4StreamsV2) > 0 {
		content, err := canonicalL4StreamSetV2(versionID, revision, value.L4StreamsV2)
		if err != nil {
			return "", nil, err
		}
		files[L4RuntimeV2ArtifactPath] = content
	}
	return "", files, nil
}
