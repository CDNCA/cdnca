package nodesshinstall

import (
	"context"
	"errors"
	"net/netip"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// "Only the controller may SSH" (node management SSH tab): when on, the
// node's sshd port only accepts the controller's egress addresses and the
// operator's allowlist; everything else is dropped by the node's own nft
// table (inet cdnca_ssh_access, next to cdnca_firewall and fail2ban). The
// node applies it with a 5 minute rollback timer and keeps it only once the
// controller confirmed it can still reach sshd (otherwise it reverts by
// itself, so a wrong egress address cannot lock the operator out).

// AccessRollbackWindow is how long the node waits for the confirmation.
const AccessRollbackWindow = 5 * time.Minute

const (
	AccessPending   = "pending"
	AccessApplied   = "applied"
	AccessConfirmed = "confirmed"
	AccessReverted  = "reverted"
	AccessFailed    = "failed"

	maxControllerCIDRs = 16
	maxAllowCIDRs      = 64
)

var (
	// ErrControllerEgressUnknown: no controller egress address is configured,
	// turning the restriction on would lock the controller out.
	ErrControllerEgressUnknown = errors.New("the controller egress address is not configured")
)

// AccessConfig is the controller's SSH egress (CDNCA_NODE_SSH_CONTROLLER_CIDRS).
type AccessConfig struct {
	ControllerCIDRs []string
}

// NewAccessConfig validates the controller egress list; empty means unknown.
func NewAccessConfig(cidrs []string) (*AccessConfig, error) {
	if len(cidrs) == 0 {
		return nil, nil
	}
	normalized, err := normalizeCIDRs(cidrs, maxControllerCIDRs)
	if err != nil {
		return nil, err
	}
	return &AccessConfig{ControllerCIDRs: normalized}, nil
}

// normalizeCIDRs canonicalizes addresses and prefixes (a bare address is a
// host prefix), sorted and deduplicated. Networks wider than /16 (IPv4) or
// /32 (IPv6) are refused: an allowlist of the whole internet is no
// restriction at all.
func normalizeCIDRs(values []string, limit int) ([]string, error) {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			address, addrErr := netip.ParseAddr(value)
			if addrErr != nil || address.Zone() != "" {
				return nil, ErrInvalidInput
			}
			prefix = netip.PrefixFrom(address, address.BitLen())
		}
		prefix = prefix.Masked()
		address := prefix.Addr()
		if address.Is4In6() || address.IsUnspecified() || address.IsMulticast() ||
			address.Is4() && prefix.Bits() < 16 || address.Is6() && prefix.Bits() < 32 {
			return nil, ErrInvalidInput
		}
		if text := prefix.String(); !seen[text] {
			seen[text] = true
			out = append(out, text)
		}
	}
	if len(out) > limit {
		return nil, ErrInvalidInput
	}
	sort.Strings(out)
	return out, nil
}

// Access is a node's restriction state.
type Access struct {
	NodeID          uuid.UUID  `json:"node_id"`
	Enabled         bool       `json:"enabled"`
	SSHPort         int        `json:"ssh_port"`
	ControllerCIDRs []string   `json:"controller_cidrs"`
	AllowCIDRs      []string   `json:"allow_cidrs"`
	Revision        int64      `json:"revision"`
	State           string     `json:"state"`
	FailureCode     string     `json:"failure_code"`
	AppliedAt       *time.Time `json:"applied_at"`
	ConfirmedAt     *time.Time `json:"confirmed_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
	// Supported: the node's newest session declared SSH_ACCESS v1 (false: the
	// node version cannot apply it; the console says so).
	Supported bool `json:"supported"`
}

// AccessChange turns the restriction on or off.
type AccessChange struct {
	Enabled    bool
	SSHPort    int
	AllowCIDRs []string
}

// Where ControllerEgress came from.
const (
	EgressConfigured = "configured" // CDNCA_NODE_SSH_CONTROLLER_CIDRS
	EgressDetected   = "detected"   // the controller's own public address (DetectEgress)
)

// UseEgressDetector sets how the controller's egress is found when
// CDNCA_NODE_SSH_CONTROLLER_CIDRS is not set (nil: never).
func (service *Service) UseEgressDetector(detect func(context.Context) []string) {
	service.detectEgress = detect
}

// ControllerEgress is the controller's SSH egress: the configured list, else
// the detected public addresses; empty (source "") when neither is known.
func (service *Service) ControllerEgress(ctx context.Context) ([]string, string) {
	if service.access != nil && len(service.access.ControllerCIDRs) > 0 {
		return append([]string(nil), service.access.ControllerCIDRs...), EgressConfigured
	}
	if service.detectEgress != nil {
		if detected, err := normalizeCIDRs(service.detectEgress(ctx), maxControllerCIDRs); err == nil && len(detected) > 0 {
			return detected, EgressDetected
		}
	}
	return []string{}, ""
}

// GetAccess returns the node's state (not configured: disabled, port 22).
func (service *Service) GetAccess(ctx context.Context, actor Actor, nodeID uuid.UUID) (Access, error) {
	if _, err := service.Endpoint(ctx, actor, nodeID); err != nil && !errors.Is(err, ErrNoAddress) {
		return Access{}, err
	}
	supported, err := service.accessSupported(ctx, nodeID)
	if err != nil {
		return Access{}, err
	}
	access, err := scanAccess(service.pool.QueryRow(ctx, selectAccess+` WHERE scope_id=$1 AND node_id=$2`, actor.ScopeID, nodeID))
	if errors.Is(err, pgx.ErrNoRows) {
		return Access{NodeID: nodeID, SSHPort: 22, ControllerCIDRs: []string{}, AllowCIDRs: []string{}, Supported: supported}, nil
	}
	access.Supported = supported
	return access, err
}

// accessSupported reads whether the node's newest session declared SSH_ACCESS v1.
func (service *Service) accessSupported(ctx context.Context, nodeID uuid.UUID) (bool, error) {
	var snapshot []byte
	err := service.pool.QueryRow(ctx, `SELECT capabilities_snapshot FROM node_session_capabilities WHERE node_id=$1
		ORDER BY session_epoch DESC LIMIT 1`, nodeID).Scan(&snapshot)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return AccessCapable(snapshot), err
}

// OnAccessChange registers the delivery worker's wake-up (a new revision).
func (service *Service) OnAccessChange(wake func()) { service.accessChanged = wake }

const selectAccess = `SELECT node_id,enabled,ssh_port,controller_cidrs,allow_cidrs,revision,state,failure_code,
	applied_at,confirmed_at,updated_at FROM node_ssh_access`

func scanAccess(row pgx.Row) (Access, error) {
	var access Access
	err := row.Scan(&access.NodeID, &access.Enabled, &access.SSHPort, &access.ControllerCIDRs, &access.AllowCIDRs,
		&access.Revision, &access.State, &access.FailureCode, &access.AppliedAt, &access.ConfirmedAt, &access.UpdatedAt)
	return access, err
}

// SetAccess records the wanted state as a new revision for the node agent.
// Turning it on needs a controller egress: configured, detected, or else the
// operator's allowlist taken as the controller's addresses.
// Either way the node keeps it only after the controller confirmed it can
// still reach sshd, otherwise it reverts by itself (AccessRollbackWindow).
func (service *Service) SetAccess(ctx context.Context, actor Actor, nodeID uuid.UUID, change AccessChange) (Access, error) {
	if change.SSHPort == 0 {
		change.SSHPort = 22
	}
	if change.SSHPort < 1 || change.SSHPort > 65535 {
		return Access{}, ErrInvalidInput
	}
	allow, err := normalizeCIDRs(change.AllowCIDRs, maxAllowCIDRs)
	if err != nil {
		return Access{}, err
	}
	controller, _ := service.ControllerEgress(ctx)
	if change.Enabled && len(controller) == 0 {
		if len(allow) == 0 {
			return Access{}, ErrControllerEgressUnknown
		}
		if len(allow) > maxControllerCIDRs {
			return Access{}, ErrInvalidInput
		}
		controller = allow
	}
	var result Access
	err = pgx.BeginFunc(ctx, service.pool, func(tx pgx.Tx) error {
		if err := service.requirePlatform(ctx, tx, actor); err != nil {
			return err
		}
		return service.setAccessTx(ctx, tx, actor, nodeID, change, allow, controller, &result)
	})
	if err != nil {
		return Access{}, err
	}
	if service.accessChanged != nil {
		service.accessChanged()
	}
	if result.Supported, err = service.accessSupported(ctx, nodeID); err != nil {
		return Access{}, err
	}
	return result, nil
}

// setAccessTx writes the new revision; actor.UserID is uuid.Nil for the
// install worker (restrict_ssh of a finished job).
func (service *Service) setAccessTx(ctx context.Context, tx pgx.Tx, actor Actor, nodeID uuid.UUID,
	change AccessChange, allow, controller []string, result *Access) error {
	scopeID := actor.ScopeID
	var userID *uuid.UUID
	if actor.UserID != uuid.Nil {
		userID = &actor.UserID
	}
	var before *Access
	if previous, err := scanAccess(tx.QueryRow(ctx, selectAccess+` WHERE scope_id=$1 AND node_id=$2 FOR UPDATE`, scopeID, nodeID)); err == nil {
		before = &previous
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	now := service.now().UTC()
	access, err := scanAccess(tx.QueryRow(ctx, `INSERT INTO node_ssh_access(node_id,scope_id,enabled,ssh_port,controller_cidrs,
			allow_cidrs,revision,state,failure_code,updated_by_user_id,updated_at)
		SELECT id,scope_id,$3,$4,$5,$6,1,'pending','',$7,$8 FROM nodes WHERE scope_id=$1 AND id=$2 AND admin_state <> 'retired'
		ON CONFLICT (node_id) DO UPDATE SET enabled=EXCLUDED.enabled,ssh_port=EXCLUDED.ssh_port,
			controller_cidrs=EXCLUDED.controller_cidrs,allow_cidrs=EXCLUDED.allow_cidrs,revision=node_ssh_access.revision+1,
			state='pending',failure_code='',updated_by_user_id=EXCLUDED.updated_by_user_id,applied_at=NULL,confirmed_at=NULL,
			published_operation='',published_at=NULL,updated_at=EXCLUDED.updated_at
		RETURNING node_id,enabled,ssh_port,controller_cidrs,allow_cidrs,revision,state,failure_code,applied_at,confirmed_at,updated_at`,
		scopeID, nodeID, change.Enabled, change.SSHPort, controller, allow, userID, now))
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	payload := map[string]any{"enabled": access.Enabled, "ssh_port": access.SSHPort, "controller_cidrs": access.ControllerCIDRs,
		"allow_cidrs": access.AllowCIDRs, "revision": access.Revision}
	if before != nil {
		payload["changes"] = []map[string]any{{"field": "enabled", "before": before.Enabled, "after": access.Enabled}}
	}
	if err := service.auditTx(ctx, tx, actor, "node.ssh_access.update", "node", nodeID.String(), "success", "", payload); err != nil {
		return err
	}
	*result = access
	return nil
}
