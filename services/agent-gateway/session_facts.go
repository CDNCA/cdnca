package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"sort"
	"strings"
	"unicode/utf8"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// Only Connect, after mTLS authorization and fenced lease acquisition, supplies
// these inputs. Incomplete legacy hellos remain usable but cannot prove upgrades.
func newGatewaySessionFacts(identity nodeIdentity, epoch uint64, selected *commonv1.ProtocolVersion, hello *agentv1.AgentHello) *controlv1.GatewaySessionFactsV1 {
	if hello == nil || hello.Capabilities == nil || epoch == 0 || selected == nil || selected.Major == 0 {
		return nil
	}
	capabilities := proto.Clone(hello.Capabilities).(*agentv1.AgentCapabilities)
	for _, field := range []struct {
		value    string
		limit    int
		optional bool
	}{
		{capabilities.AgentVersion, 128, false}, {capabilities.BuildId, 128, false},
		{capabilities.OperatingSystem, 64, false}, {capabilities.Architecture, 64, false},
		{capabilities.OpenrestyVersion, 128, true},
	} {
		if (!field.optional && field.value == "") || len(field.value) > field.limit ||
			strings.TrimSpace(field.value) != field.value || !utf8.ValidString(field.value) {
			return nil
		}
	}
	if len(capabilities.ProtoReflect().GetUnknown()) != 0 || len(capabilities.Features) == 0 || len(capabilities.Features) > 64 {
		return nil
	}
	// A capability this Gateway build does not know (a newer Agent) is left
	// out of the facts instead of discarding them: the session keeps its
	// upgrade proof and control-api still sees every capability it knows.
	known := capabilities.Features[:0]
	for _, feature := range capabilities.Features {
		if feature == nil || feature.Name <= 0 || feature.ApiVersion == 0 || len(feature.ProtoReflect().GetUnknown()) != 0 {
			return nil
		}
		if _, ok := agentv1.CapabilityName_name[int32(feature.Name)]; !ok {
			continue
		}
		known = append(known, feature)
	}
	capabilities.Features = known
	if len(capabilities.Features) == 0 {
		return nil
	}
	sort.Slice(capabilities.Features, func(i, j int) bool { return capabilities.Features[i].Name < capabilities.Features[j].Name })
	for index := 1; index < len(capabilities.Features); index++ {
		if capabilities.Features[index-1].Name == capabilities.Features[index].Name {
			return nil
		}
	}
	return &controlv1.GatewaySessionFactsV1{
		SchemaVersion: 1, NodeId: identity.NodeID, SessionEpoch: epoch,
		CertificateSha256:       bytes.Clone(identity.CertificateSHA256[:]),
		SelectedProtocolVersion: proto.Clone(selected).(*commonv1.ProtocolVersion),
		ArtifactEncryptionKeyId: hello.ArtifactEncryptionKeyId, Capabilities: capabilities,
	}
}

// knownCapabilityFeatures keeps the capabilities this release's proto names.
func knownCapabilityFeatures(features []*agentv1.Capability) []*agentv1.Capability {
	known := make([]*agentv1.Capability, 0, len(features))
	for _, feature := range features {
		if _, ok := agentv1.CapabilityName_name[int32(feature.GetName())]; feature != nil && ok {
			known = append(known, feature)
		}
	}
	return known
}

func (g *Gateway) confirmSessionFacts(ctx context.Context, identity nodeIdentity, lease SessionLease, facts *controlv1.GatewaySessionFactsV1, previous *controlv1.GetNodeAuthorizationResponse) (*controlv1.GetNodeAuthorizationResponse, bool, error) {
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(facts)
	if err != nil {
		return nil, false, status.Error(codes.InvalidArgument, "invalid session facts")
	}
	digest := sha256.Sum256(encoded)
	var authorization *controlv1.GetNodeAuthorizationResponse
	confirmed := false
	err = lease.FencedSend(func() error {
		var requestErr error
		authorization, requestErr = g.authorizeConnection(ctx, identity, facts)
		if requestErr != nil {
			return requestErr
		}
		selected := facts.SelectedProtocolVersion
		accepted := authorization.AcceptedProtocolVersions
		if authorization.ArtifactEncryptionKeyId != facts.ArtifactEncryptionKeyId || authorization.InstallationId != previous.InstallationId ||
			compareVersions(selected, accepted.Minimum) < 0 || compareVersions(selected, accepted.Maximum) > 0 {
			return status.Error(codes.FailedPrecondition, "session authorization changed during handshake")
		}
		// An implementation that accepts but does not receipt the new field may
		// serve existing traffic. It cannot enable upgrade commands. RPC errors,
		// including an old Control rejecting unknown fields, never downgrade.
		if len(authorization.SessionFactsSha256) == 0 {
			return nil
		}
		if subtle.ConstantTimeCompare(authorization.SessionFactsSha256, digest[:]) != 1 {
			return status.Error(codes.FailedPrecondition, "session evidence receipt does not match")
		}
		confirmed = true
		return nil
	})
	return authorization, confirmed, err
}

// enrollmentCapabilities forwards only capability names this release knows:
// the control-api of the same release refuses any other one, so a newer Agent
// could not enroll through this Gateway. The Agent re-offers the rest on
// Connect.
func enrollmentCapabilities(capabilities *agentv1.AgentCapabilities) *agentv1.AgentCapabilities {
	if capabilities == nil {
		return nil
	}
	filtered := proto.Clone(capabilities).(*agentv1.AgentCapabilities)
	filtered.Features = knownCapabilityFeatures(filtered.Features)
	return filtered
}
