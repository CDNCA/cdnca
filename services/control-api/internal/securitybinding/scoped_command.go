package securitybinding

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/netip"
	"slices"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/securitybundle"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	maxScopedBundleSize = 1 << 20
	maxScopedTargets    = 10_000
	maxScopedUnixTime   = int64(253402300799)
)

type ScopedCommandConsumer interface {
	ConsumeScopedCommand(context.Context, *agentv1.FirewallCommand) error
}

// ProjectScopedCommand derives a node command from a structurally valid signed
// publication. Signature authenticity remains the edge trust boundary.
func ProjectScopedCommand(publication Publication, nodeID uuid.UUID) (*agentv1.FirewallCommand, error) {
	bundle, canonicalPayloadDigest, runtimeDigest, err := parseScopedBundle(publication.BundleJSON)
	if err != nil {
		return nil, ErrInvalidInput
	}
	payload := bundle.Payload
	issuedAt := time.Unix(payload.IssuedAt, 0).UTC()
	expiresAt := time.Unix(payload.ExpiresAt, 0).UTC()
	bundleDigest := sha256.Sum256(publication.BundleJSON)
	if nodeID == uuid.Nil || bundleDigest != publication.BundleSHA256 ||
		canonicalPayloadDigest != publication.CanonicalPayloadSHA256 ||
		runtimeDigest != publication.RuntimeSnapshotSHA256 ||
		payload.PolicyVersion != payload.ExpectedActiveVersion+1 ||
		payload.BundleID != publication.BundleID ||
		payload.TenantScopeID != publication.TenantScopeID ||
		payload.SiteID != publication.SiteID ||
		payload.PolicyID != publication.PolicyID ||
		payload.RuntimeSnapshot.Kind != publication.PolicyKind ||
		payload.PolicyVersion != publication.PolicyVersion ||
		!slices.Equal(payload.TargetNodeIDs, publication.TargetNodeIDs) ||
		!slices.Contains(payload.TargetNodeIDs, nodeID) ||
		payload.ExpectedActiveVersion != publication.ExpectedActiveVersion ||
		payload.RolloutID != publication.RolloutID ||
		bundle.KeyID != publication.SigningKeyID ||
		!issuedAt.Equal(publication.IssuedAt) || !expiresAt.Equal(publication.ExpiresAt) {
		return nil, ErrInvalidInput
	}
	targets, err := projectScopedTargets(payload.RuntimeSnapshot)
	if err != nil {
		return nil, ErrInvalidInput
	}

	taskID := payload.RolloutID.String()
	command := &agentv1.FirewallCommand{
		Event: &commonv1.EventMetadata{
			EventId:   scopedCommandIdentity(payload.BundleID, "firewall-event", nodeID).String(),
			RequestId: payload.RolloutID.String(), OccurredTime: timestamppb.New(issuedAt),
			CorrelationId: payload.BundleID.String(), TaskId: &taskID,
		},
		Schema: agentv1.FirewallSchema_FIREWALL_SCHEMA_V1,
		TaskId: taskID, TaskRevision: uint64(payload.PolicyVersion),
		IdempotencyKey: scopedCommandIdentity(payload.BundleID, "firewall-idempotency", nodeID).String(),
		TenantId:       payload.TenantScopeID.String(), SiteId: payload.SiteID.String(), NodeId: nodeID.String(),
		PolicyVersion: uint64(payload.PolicyVersion), ExpectedActivePolicyVersion: uint64(payload.ExpectedActiveVersion),
		Operation:      agentv1.FirewallOperation_FIREWALL_OPERATION_APPLY,
		RecoveryReason: agentv1.FirewallRecoveryReason_FIREWALL_RECOVERY_REASON_NOT_APPLICABLE,
		Targets:        targets, DeadlineTime: timestamppb.New(expiresAt),
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(command)
	if err != nil {
		return nil, ErrInvalidInput
	}
	digest := sha256.Sum256(encoded)
	command.CommandSha256 = digest[:]
	return command, nil
}

func projectScopedTargets(snapshot securitypolicy.RuntimeSnapshot) ([]*agentv1.FirewallCIDRTarget, error) {
	if snapshot.Kind != securitypolicy.KindACL || snapshot.DefaultAction != securitypolicy.ActionAllow {
		return nil, ErrInvalidInput
	}
	targets := make([]*agentv1.FirewallCIDRTarget, 0, len(snapshot.Rules))
	seen := make(map[string]struct{}, len(snapshot.Rules))
	for _, rule := range snapshot.Rules {
		if !rule.Enabled {
			continue
		}
		if rule.Flow != securitypolicy.FlowStop || len(rule.Conditions) != 1 {
			return nil, ErrInvalidInput
		}
		condition := rule.Conditions[0]
		if condition.Field != "client_ip" || condition.Operator != "ip_in_cidr" ||
			condition.Key != "" || len(condition.Values) != 1 {
			return nil, ErrInvalidInput
		}
		cidr := condition.Values[0]
		prefix, err := netip.ParsePrefix(cidr)
		address := prefix.Addr()
		if err != nil || prefix != prefix.Masked() || prefix.String() != cidr || address.Is4In6() ||
			address.IsUnspecified() || address.IsMulticast() || address.IsLinkLocalUnicast() ||
			address.IsLinkLocalMulticast() || prefix.Bits() == 0 {
			return nil, ErrInvalidInput
		}
		if _, duplicate := seen[cidr]; duplicate {
			return nil, ErrInvalidInput
		}
		seen[cidr] = struct{}{}
		action := agentv1.FirewallCIDRAction_FIREWALL_CIDR_ACTION_UNSPECIFIED
		switch rule.Action {
		case securitypolicy.ActionAllow:
			action = agentv1.FirewallCIDRAction_FIREWALL_CIDR_ACTION_ALLOW
		case securitypolicy.ActionBlock:
			action = agentv1.FirewallCIDRAction_FIREWALL_CIDR_ACTION_DENY
		default:
			return nil, ErrInvalidInput
		}
		targets = append(targets, &agentv1.FirewallCIDRTarget{
			Ordinal: uint32(len(targets) + 1), TenantId: snapshot.TenantScopeID.String(),
			SiteId: snapshot.SiteID.String(), Action: action, Cidr: cidr,
			Source: "policy:" + snapshot.PolicyID.String(), ReasonCode: "rule:" + rule.ID.String(),
		})
	}
	return targets, nil
}

func scopedCommandIdentity(bundleID uuid.UUID, kind string, nodeID uuid.UUID) uuid.UUID {
	return uuid.NewSHA1(bundleID, []byte(kind+"\x00"+nodeID.String()))
}

func parseScopedBundle(encoded []byte) (securitybundle.SignedBundle, [32]byte, [32]byte, error) {
	if len(encoded) == 0 || len(encoded) > maxScopedBundleSize {
		return securitybundle.SignedBundle{}, [32]byte{}, [32]byte{}, ErrInvalidInput
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var bundle securitybundle.SignedBundle
	if err := decoder.Decode(&bundle); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return securitybundle.SignedBundle{}, [32]byte{}, [32]byte{}, ErrInvalidInput
	}
	canonicalBundle, err := json.Marshal(bundle)
	if err != nil || !bytes.Equal(canonicalBundle, encoded) ||
		bundle.Algorithm != entitlement.Algorithm || entitlement.ValidateKeyID(bundle.KeyID) != nil {
		return securitybundle.SignedBundle{}, [32]byte{}, [32]byte{}, ErrInvalidInput
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(bundle.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize ||
		base64.RawURLEncoding.EncodeToString(signature) != bundle.Signature {
		return securitybundle.SignedBundle{}, [32]byte{}, [32]byte{}, ErrInvalidInput
	}

	payload := bundle.Payload
	if payload.SchemaVersion != securitybundle.SchemaVersion || payload.BundleID == uuid.Nil ||
		payload.TenantScopeID == uuid.Nil || payload.SiteID == uuid.Nil || payload.PolicyID == uuid.Nil ||
		payload.PolicyVersion < 1 || payload.ExpectedActiveVersion < 0 || payload.RolloutID == uuid.Nil ||
		!validScopedIdempotencyKey(payload.IdempotencyKey) || payload.IssuedAt <= 0 ||
		payload.ExpiresAt > maxScopedUnixTime || payload.ExpiresAt <= payload.IssuedAt ||
		payload.ExpiresAt-payload.IssuedAt > int64((24*time.Hour)/time.Second) ||
		payload.BundleID != uuid.NewSHA1(payload.TenantScopeID, []byte(payload.SiteID.String()+"\x00"+payload.IdempotencyKey)) ||
		!validScopedTargets(payload.TargetNodeIDs) {
		return securitybundle.SignedBundle{}, [32]byte{}, [32]byte{}, ErrInvalidInput
	}
	if err := securitypolicy.ValidateRuntimeSnapshot(payload.RuntimeSnapshot); err != nil ||
		payload.RuntimeSnapshot.TenantScopeID != payload.TenantScopeID ||
		payload.RuntimeSnapshot.SiteID != payload.SiteID || payload.RuntimeSnapshot.PolicyID != payload.PolicyID ||
		payload.RuntimeSnapshot.PolicyVersion != payload.PolicyVersion {
		return securitybundle.SignedBundle{}, [32]byte{}, [32]byte{}, ErrInvalidInput
	}

	canonicalPayload, err := json.Marshal(payload)
	if err != nil {
		return securitybundle.SignedBundle{}, [32]byte{}, [32]byte{}, ErrInvalidInput
	}
	canonicalPayloadDigest := sha256.Sum256(canonicalPayload)
	if bundle.PayloadSHA256 != hex.EncodeToString(canonicalPayloadDigest[:]) {
		return securitybundle.SignedBundle{}, [32]byte{}, [32]byte{}, ErrInvalidInput
	}
	runtimeSnapshot, err := json.Marshal(payload.RuntimeSnapshot)
	if err != nil {
		return securitybundle.SignedBundle{}, [32]byte{}, [32]byte{}, ErrInvalidInput
	}
	runtimeDigest := sha256.Sum256(runtimeSnapshot)
	if payload.RuntimeSnapshotSHA256 != hex.EncodeToString(runtimeDigest[:]) {
		return securitybundle.SignedBundle{}, [32]byte{}, [32]byte{}, ErrInvalidInput
	}
	return bundle, canonicalPayloadDigest, runtimeDigest, nil
}

func validScopedTargets(targets []uuid.UUID) bool {
	if len(targets) == 0 || len(targets) > maxScopedTargets {
		return false
	}
	for index, target := range targets {
		if target == uuid.Nil || index > 0 && bytes.Compare(targets[index-1][:], target[:]) >= 0 {
			return false
		}
	}
	return true
}

func validScopedIdempotencyKey(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character < 'A' || character > 'Z') && (character < 'a' || character > 'z') &&
			(character < '0' || character > '9') && character != '.' && character != '_' && character != '-' {
			return false
		}
	}
	return true
}
