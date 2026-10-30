package nodeidentity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/netip"
	"regexp"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type NetworkInventoryRequest struct {
	GetAuthorizationRequest
	Inventory *agentv1.ReportNodeNetworkInventoryV1Request
	PeerIP    string
	// PeerIPSource is "tcp" or "trusted_proxy" (ADR 0013 §4.4); audit only,
	// the candidate == peer rule is unchanged.
	PeerIPSource string
}

func (s *Service) ReportNetworkInventory(ctx context.Context, request NetworkInventoryRequest) (*agentv1.ReportNodeNetworkInventoryV1Response, error) {
	now := s.config.Clock().UTC().Truncate(time.Microsecond)
	id, digest, err := normalizeNetworkInventory(request, now)
	if err != nil {
		return nil, err
	}
	result := &agentv1.ReportNodeNetworkInventoryV1Response{SchemaVersion: 1, NodeId: request.NodeID.String(), ReceivedTime: timestamppb.New(now)}
	err = pgx.BeginFunc(ctx, s.store.pool, func(tx pgx.Tx) error {
		var scopeID uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT scope_id FROM nodes WHERE id=$1`, request.NodeID).Scan(&scopeID); errors.Is(err, pgx.ErrNoRows) {
			return ErrCertificateNotFound
		} else if err != nil {
			return err
		}
		// Share the exact lock domain with node.Update/BatchAdminState before
		// checking address uniqueness. Certificate locking also serializes revoke.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, scopeID.String()); err != nil {
			return err
		}
		var certID uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT id FROM node_certificates WHERE node_id=$1 AND serial_number=$2 AND leaf_der_sha256=$3 FOR UPDATE`, request.NodeID, request.CertificateSerialNumber, request.CertificateSHA256[:]).Scan(&certID); errors.Is(err, pgx.ErrNoRows) {
			return ErrCertificateNotFound
		} else if err != nil {
			return err
		}
		var ipv4, ipv6 *string
		var allowed bool
		err := tx.QueryRow(ctx, `SELECT host(n.ipv4),host(n.ipv6),
		 n.admin_state='active' AND sc.kind='platform' AND c.status='active' AND c.rotation_status='current'
		 AND e.status<>'revoked'
		 AND EXISTS(SELECT 1 FROM node_identity_authorizations a WHERE a.node_id=n.id AND a.status='issued' AND a.gateway_workload_identity=$4)
		 FROM nodes n JOIN access_scopes sc ON sc.id=n.scope_id
		 JOIN node_certificates c ON c.id=$3 AND c.node_id=n.id AND c.owner_scope_id=n.scope_id
		 JOIN control_installation_entitlement i ON i.singleton AND i.installation_id=c.installation_id
		 JOIN node_ca_key_epochs e ON e.id=c.ca_epoch_id AND e.installation_id=i.installation_id
		 WHERE n.id=$1 AND n.scope_id=$2 FOR UPDATE OF n FOR SHARE OF c,sc,i,e`, request.NodeID, scopeID, certID, request.GatewayWorkloadIdentity).Scan(&ipv4, &ipv6, &allowed)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrCertificateNotFound
		}
		if err != nil {
			return err
		}
		if !allowed {
			return ErrNodeStateDenied
		}
		// Refresh the clock after all authority locks: a queued request must not
		// use the certificate validity or scheduled-revocation time from arrival.
		now = s.config.Clock().UTC().Truncate(time.Microsecond)
		err = tx.QueryRow(ctx, `SELECT c.not_before<=$2 AND c.not_after>$2 AND e.not_before<=$2 AND e.not_after>$2
		 AND NOT EXISTS(SELECT 1 FROM node_certificate_revocations r WHERE r.certificate_id=c.id AND r.node_id=c.node_id AND r.binding_status='bound' AND r.effective_at<=$2)
		 FROM node_certificates c JOIN node_ca_key_epochs e ON e.id=c.ca_epoch_id WHERE c.id=$1`, certID, now).Scan(&allowed)
		if err != nil {
			return err
		}
		if !allowed {
			return ErrNodeStateDenied
		}
		result.ReceivedTime = timestamppb.New(now)
		// Recheck current authority before returning even a previously committed receipt.
		var storedDigest []byte
		var storedNode uuid.UUID
		var received time.Time
		err = tx.QueryRow(ctx, `SELECT request_digest,node_id,ipv4_state,ipv6_state,received_at FROM node_network_inventory_reports WHERE request_id=$1`, id).Scan(&storedDigest, &storedNode, &result.Ipv4State, &result.Ipv6State, &received)
		if err == nil {
			if storedNode != request.NodeID || !bytes.Equal(storedDigest, digest[:]) {
				return ErrIdempotencyConflict
			}
			result.Replayed = true
			result.ReceivedTime = timestamppb.New(received)
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if request.Inventory.Request.SentTime.AsTime().Before(now.Add(-5 * time.Minute)) {
			return ErrInvalidInput
		}
		var changed bool
		for _, family := range []struct {
			candidate *agentv1.NodeNetworkCandidateV1
			reason    string
			current   **string
			state     *string
			column    string
		}{
			{request.Inventory.Ipv4, request.Inventory.Ipv4Reason, &ipv4, &result.Ipv4State, "ipv4"},
			{request.Inventory.Ipv6, request.Inventory.Ipv6Reason, &ipv6, &result.Ipv6State, "ipv6"},
		} {
			if family.candidate == nil {
				*family.state = family.reason
				continue
			}
			if family.candidate.Address != request.PeerIP {
				*family.state = "peer_mismatch"
				continue
			}
			if *family.current != nil && **family.current != family.candidate.Address {
				*family.state = "address_conflict"
				continue
			}
			var conflict bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM nodes WHERE scope_id=$1 AND id<>$2 AND admin_state IN ('active','draining') AND `+family.column+`=$3::inet)`, scopeID, request.NodeID, family.candidate.Address).Scan(&conflict); err != nil {
				return err
			}
			if conflict {
				*family.state = "address_conflict"
				continue
			}
			*family.state = "verified"
			if *family.current == nil {
				value := family.candidate.Address
				*family.current = &value
				changed = true
			}
		}
		if changed {
			if _, err := tx.Exec(ctx, `UPDATE nodes SET ipv4=$2::inet,ipv6=$3::inet,revision=revision+1,updated_at=$4 WHERE id=$1`, request.NodeID, ipv4, ipv6, now); err != nil {
				return err
			}
		}
		payload, err := json.Marshal(request.Inventory)
		if err != nil {
			return err
		}
		var peer any
		if request.PeerIP != "" {
			peer = request.PeerIP
		}
		if _, err := tx.Exec(ctx, `INSERT INTO node_network_inventory_reports(request_id,node_id,scope_id,certificate_id,request_digest,peer_ip,inventory_json,ipv4_state,ipv6_state,received_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, id, request.NodeID, scopeID, certID, digest[:], peer, payload, result.Ipv4State, result.Ipv6State, now); err != nil {
			return err
		}
		return s.store.auditor.Append(ctx, tx, audit.Event{ScopeID: scopeID, Action: "node.network_inventory.report", ResourceType: "node", ResourceID: request.NodeID.String(), RequestID: id.String(), Result: "success", Payload: map[string]any{"ipv4_state": result.Ipv4State, "ipv6_state": result.Ipv6State, "inventory_changed": changed, "peer_ip_source": peerIPSource(request.PeerIPSource)}})
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

var inventoryInterfaceName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$`)

func normalizeNetworkInventory(request NetworkInventoryRequest, now time.Time) (uuid.UUID, [32]byte, error) {
	bad := func() (uuid.UUID, [32]byte, error) { return uuid.Nil, [32]byte{}, ErrInvalidInput }
	inventory := request.Inventory
	if request.NodeID == uuid.Nil || !validSerial(request.CertificateSerialNumber) || request.CertificateSHA256 == [32]byte{} || !validIdentity(request.GatewayWorkloadIdentity, 256) || !validIdentity(request.GatewayInstanceID, 128) || inventory == nil || inventoryHasUnknown(inventory.ProtoReflect()) || inventory.SchemaVersion != 1 || inventory.Request == nil || inventory.Request.SentTime == nil || inventory.Request.SentTime.CheckValid() != nil {
		return bad()
	}
	id, err := canonicalRequestID(inventory.Request.RequestId)
	if err != nil {
		return bad()
	}
	if inventory.Request.SentTime.AsTime().After(now.Add(time.Minute)) {
		return bad()
	}
	for _, family := range []struct {
		candidate *agentv1.NodeNetworkCandidateV1
		reason    string
		ipv4      bool
	}{{inventory.Ipv4, inventory.Ipv4Reason, true}, {inventory.Ipv6, inventory.Ipv6Reason, false}} {
		if family.candidate == nil {
			if family.reason != "no_default_route" && family.reason != "no_global_address" && family.reason != "ambiguous_route" && family.reason != "unavailable" {
				return bad()
			}
			continue
		}
		a, err := netip.ParseAddr(family.candidate.Address)
		if err != nil || a.String() != family.candidate.Address || !inventoryPublicAddress(a) || a.Is4() != family.ipv4 || family.reason != "" || !inventoryInterfaceName.MatchString(family.candidate.InterfaceName) || family.candidate.InterfaceName == "lo" {
			return bad()
		}
	}
	if request.PeerIP != "" {
		a, err := netip.ParseAddr(request.PeerIP)
		if err != nil || a.Zone() != "" || a.Is4In6() || a.String() != request.PeerIP {
			return bad()
		}
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(inventory)
	if err != nil || len(encoded) > 4096 {
		return bad()
	}
	digestPayload, err := json.Marshal(struct {
		Body                    []byte
		Node                    uuid.UUID
		Serial                  string
		Certificate             [32]byte
		Workload, Gateway, Peer string
	}{encoded, request.NodeID, request.CertificateSerialNumber, request.CertificateSHA256, request.GatewayWorkloadIdentity, request.GatewayInstanceID, request.PeerIP})
	if err != nil {
		return bad()
	}
	return id, sha256.Sum256(digestPayload), nil
}

// V1 contains singular nested messages only; unknown fields at every level are
// rejected instead of being ignored by this writer.
func inventoryHasUnknown(message protoreflect.Message) bool {
	if !message.IsValid() || len(message.GetUnknown()) != 0 {
		return true
	}
	unknown := false
	message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		unknown = field.Message() != nil && inventoryHasUnknown(value.Message())
		return !unknown
	})
	return unknown
}

func inventoryPublicAddress(address netip.Addr) bool {
	if !address.IsGlobalUnicast() || address.IsPrivate() || address.Is4In6() || address.Zone() != "" {
		return false
	}
	for _, blocked := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001::/23", "2001:db8::/32", "2002::/16", "3ffe::/16", "3fff::/20"} {
		if netip.MustParsePrefix(blocked).Contains(address) {
			return false
		}
	}
	return address.Is4() || netip.MustParsePrefix("2000::/3").Contains(address)
}

func peerIPSource(value string) string {
	if value == "" {
		return "tcp"
	}
	return value
}
