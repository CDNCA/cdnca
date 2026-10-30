package gatewayregistry

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var hostLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// Config wires the registry. Endpoints may be zero (standalone access not
// opened yet): the page still works, binding answers ErrRemoteAccessDisabled.
type Config struct {
	Pool           *pgxpool.Pool
	Signer         Signer
	RootCAPEM      string
	NodeCAPEM      string
	InstallationID string
	Endpoints      RemoteEndpoints
	// LocalGateway is the co-located Gateway (all/control installation,
	// spiffe://cdn-platform/gateway/control) as nodes reach it; published
	// after the online standalone Gateways (zero value: not published).
	LocalGateway Entrypoint
	Now          func() time.Time
}

type Service struct {
	config  Config
	auditor *audit.Log
	// rootFingerprint is the token fingerprint of this installation's root CA.
	rootFingerprint string
}

func New(config Config) (*Service, error) {
	if config.Pool == nil || config.Signer.Client.Certificate == nil || config.Signer.Server.Certificate == nil ||
		config.RootCAPEM == "" || config.NodeCAPEM == "" {
		return nil, ErrInvalidInput
	}
	if id, err := uuid.Parse(config.InstallationID); err != nil || id.String() != config.InstallationID {
		return nil, ErrInvalidInput
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &Service{config: config, auditor: audit.NewWithClock(config.Pool, config.Now),
		rootFingerprint: RootFingerprint(config.Signer.Server.Certificate.Raw)}, nil
}

// InstallationID is the tunnel token audience every Gateway signs against.
func (s *Service) InstallationID() string { return s.config.InstallationID }

func validHost(host string) bool {
	if host == "" || len(host) > 253 || host != strings.ToLower(strings.TrimSpace(host)) {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String() == host
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if !hostLabel.MatchString(label) {
			return false
		}
	}
	return true
}

func validName(name string) bool {
	return name != "" && len([]rune(name)) <= 64 && name == strings.TrimSpace(name) && !strings.ContainsAny(name, "\x00\r\n\t")
}

func (s *Service) List(ctx context.Context) ([]Gateway, error) {
	rows, err := s.config.Pool.Query(ctx, `SELECT g.id,g.name,g.host,g.enrollment_port,g.agent_port,g.status,g.version,g.created_at,g.bound_at,g.ready_at,
  (SELECT max(not_after) FROM agent_gateway_certificates c WHERE c.gateway_id=g.id AND c.kind='client' AND c.revoked_at IS NULL),
  (SELECT max(not_after) FROM agent_gateway_certificates c WHERE c.gateway_id=g.id AND c.kind='server' AND c.revoked_at IS NULL),
  host(g.source_ip),
  (SELECT COALESCE(array_agg(host(a.ip) ORDER BY a.ip),'{}') FROM agent_gateway_allowed_ips a WHERE a.gateway_id=g.id)
  FROM agent_gateways g WHERE g.status<>'deleted' ORDER BY g.created_at, g.id`)
	if err != nil {
		return nil, fmt.Errorf("list gateways: %w", err)
	}
	defer rows.Close()
	result := []Gateway{}
	for rows.Next() {
		var g Gateway
		if err := rows.Scan(&g.ID, &g.Name, &g.Host, &g.EnrollmentPort, &g.AgentPort, &g.Status, &g.Version, &g.CreatedAt,
			&g.BoundAt, &g.ReadyAt, &g.ClientCertificateExpiresAt, &g.ServerCertificateExpiresAt, &g.SourceIP, &g.AllowedIPs); err != nil {
			return nil, fmt.Errorf("scan gateway: %w", err)
		}
		if g.AllowedIPs == nil {
			g.AllowedIPs = []string{}
		}
		result = append(result, g)
	}
	return result, rows.Err()
}

// Create adds a pending Gateway and returns its binding token (shown once).
func (s *Service) Create(ctx context.Context, actor Actor, input CreateInput) (Created, error) {
	input.Host = strings.ToLower(strings.TrimSpace(input.Host))
	if !validName(input.Name) || !validHost(input.Host) {
		return Created{}, ErrInvalidInput
	}
	now := s.config.Now().UTC()
	id := uuid.New()
	var created Created
	err := pgx.BeginFunc(ctx, s.config.Pool, func(tx pgx.Tx) error {
		var taken bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM agent_gateways WHERE lower(name)=lower($1) AND status<>'deleted')`, input.Name).Scan(&taken); err != nil {
			return err
		}
		if taken {
			return ErrNameTaken
		}
		if _, err := tx.Exec(ctx, `INSERT INTO agent_gateways(id,name,host,status,created_by_user_id,created_at,updated_at)
  VALUES($1,$2,$3,'pending',$4,$5,$5)`, id, input.Name, input.Host, actor.UserID, now); err != nil {
			return err
		}
		token, expires, err := s.replaceToken(ctx, tx, id, now)
		if err != nil {
			return err
		}
		created = Created{Gateway: Gateway{ID: id, Name: input.Name, Host: input.Host, Status: StatusPending, CreatedAt: now},
			BindingToken: token, TokenExpiresAt: expires}
		return s.appendAudit(ctx, tx, actor, actionCreate, id, map[string]any{"name": input.Name, "host": input.Host})
	})
	return created, err
}

func (s *Service) replaceToken(ctx context.Context, tx pgx.Tx, id uuid.UUID, now time.Time) (string, time.Time, error) {
	token, digest, err := newBindingToken(id, s.rootFingerprint)
	if err != nil {
		return "", time.Time{}, err
	}
	expires := now.Add(TokenTTL)
	_, err = tx.Exec(ctx, `INSERT INTO agent_gateway_binding_tokens(gateway_id,secret_sha256,expires_at,created_at) VALUES($1,$2,$3,$4)
  ON CONFLICT (gateway_id) DO UPDATE SET secret_sha256=EXCLUDED.secret_sha256,expires_at=EXCLUDED.expires_at,used_at=NULL,created_at=EXCLUDED.created_at`,
		id, digest[:], expires, now)
	return token, expires, err
}

// IssueToken gives a still pending Gateway a new token (the old one stops
// working): the page's "regenerate install command".
func (s *Service) IssueToken(ctx context.Context, actor Actor, id uuid.UUID) (Created, error) {
	now := s.config.Now().UTC()
	var created Created
	err := pgx.BeginFunc(ctx, s.config.Pool, func(tx pgx.Tx) error {
		var g Gateway
		err := tx.QueryRow(ctx, `SELECT id,name,host,status,created_at FROM agent_gateways WHERE id=$1 FOR UPDATE`, id).
			Scan(&g.ID, &g.Name, &g.Host, &g.Status, &g.CreatedAt)
		if errors.Is(err, pgx.ErrNoRows) || g.Status == StatusDeleted {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if g.Status != StatusPending {
			return ErrConflict
		}
		token, expires, err := s.replaceToken(ctx, tx, id, now)
		if err != nil {
			return err
		}
		created = Created{Gateway: g, BindingToken: token, TokenExpiresAt: expires}
		return s.appendAudit(ctx, tx, actor, actionToken, id, map[string]any{})
	})
	return created, err
}

// SetDisabled disables or re-enables a bound Gateway. A disabled Gateway
// keeps serving its connected nodes for DisabledGrace (it learns it was
// disabled from GetGatewaySettings and moves them away, ADR 0013 §5.2), then
// ControlInternal refuses it.
func (s *Service) SetDisabled(ctx context.Context, actor Actor, id uuid.UUID, disabled bool) error {
	now := s.config.Now().UTC()
	return pgx.BeginFunc(ctx, s.config.Pool, func(tx pgx.Tx) error {
		var status string
		var readyAt *time.Time
		err := tx.QueryRow(ctx, `SELECT status,ready_at FROM agent_gateways WHERE id=$1 FOR UPDATE`, id).Scan(&status, &readyAt)
		if errors.Is(err, pgx.ErrNoRows) || status == StatusDeleted {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		next, action := StatusDisabled, actionDisable
		switch {
		case disabled && (status == StatusBound || status == StatusActive):
		case !disabled && status == StatusDisabled:
			next, action = StatusBound, actionEnable
			if readyAt != nil {
				next = StatusActive
			}
		default:
			return ErrConflict
		}
		if _, err := tx.Exec(ctx, `UPDATE agent_gateways SET status=$2,updated_at=$3,
  disabled_at=CASE WHEN $2='disabled' THEN $3::timestamptz END WHERE id=$1`, id, next, now); err != nil {
			return err
		}
		return s.appendAudit(ctx, tx, actor, action, id, map[string]any{"status": next})
	})
}

// Delete revokes every certificate of the Gateway and drops its token; the
// row stays (status deleted) so the revocation stays decidable.
func (s *Service) Delete(ctx context.Context, actor Actor, id uuid.UUID) error {
	now := s.config.Now().UTC()
	return pgx.BeginFunc(ctx, s.config.Pool, func(tx pgx.Tx) error {
		var status string
		err := tx.QueryRow(ctx, `SELECT status FROM agent_gateways WHERE id=$1 FOR UPDATE`, id).Scan(&status)
		if errors.Is(err, pgx.ErrNoRows) || status == StatusDeleted {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE agent_gateway_certificates SET revoked_at=$2 WHERE gateway_id=$1 AND revoked_at IS NULL`, id, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM agent_gateway_binding_tokens WHERE gateway_id=$1`, id); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE agent_gateways SET status='deleted',updated_at=$2 WHERE id=$1`, id, now); err != nil {
			return err
		}
		return s.appendAudit(ctx, tx, actor, actionDelete, id, map[string]any{"previous_status": status})
	})
}

func validPort(port int) bool { return port == 443 || (port >= 1024 && port <= 65535) }

// Bind completes a binding (POST /v1/gateway-bindings/complete): consumes the
// token, signs both certificates and returns what the installer writes.
func (s *Service) Bind(ctx context.Context, request BindRequest, sourceIP string) (BindResult, error) {
	token, ok := parseBindingToken(request.Token)
	if !ok {
		return BindResult{}, ErrInvalidToken
	}
	if token.Fingerprint != s.rootFingerprint {
		// The installer checked the fingerprint against the root CA it
		// downloaded; a mismatch here means the token is for another control plane.
		return BindResult{}, ErrInvalidToken
	}
	if !validPort(request.EnrollmentPort) || !validPort(request.AgentPort) || request.EnrollmentPort == request.AgentPort ||
		len(request.Version) > 64 {
		return BindResult{}, ErrInvalidInput
	}
	if s.config.Endpoints.ControlInternalAddress == "" {
		return BindResult{}, ErrRemoteAccessDisabled
	}
	clientCSR, _, err := parseCSR(request.ClientCSR, KindClient)
	if err != nil {
		return BindResult{}, err
	}
	serverCSR, _, err := parseCSR(request.ServerCSR, KindServer)
	if err != nil {
		return BindResult{}, err
	}
	now := s.config.Now().UTC()
	var result BindResult
	err = pgx.BeginFunc(ctx, s.config.Pool, func(tx pgx.Tx) error {
		var digest []byte
		var expires time.Time
		var used *time.Time
		var status, host string
		err := tx.QueryRow(ctx, `SELECT t.secret_sha256,t.expires_at,t.used_at,g.status,g.host FROM agent_gateway_binding_tokens t
  JOIN agent_gateways g ON g.id=t.gateway_id WHERE t.gateway_id=$1 FOR UPDATE OF t,g`, token.GatewayID).Scan(&digest, &expires, &used, &status, &host)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrInvalidToken
		}
		if err != nil {
			return err
		}
		if !secretMatches(token.Secret, digest) || used != nil || !now.Before(expires) || status != StatusPending {
			return ErrInvalidToken
		}
		client, err := s.config.Signer.issue(token.GatewayID, KindClient, host, clientCSR, now)
		if err != nil {
			return err
		}
		server, err := s.config.Signer.issue(token.GatewayID, KindServer, host, serverCSR, now)
		if err != nil {
			return err
		}
		for kind, certificate := range map[string]issued{KindClient: client, KindServer: server} {
			if err := insertCertificate(ctx, tx, token.GatewayID, kind, certificate, now); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE agent_gateway_binding_tokens SET used_at=$2 WHERE gateway_id=$1`, token.GatewayID, now); err != nil {
			return err
		}
		var source any
		if ip := net.ParseIP(sourceIP); ip != nil {
			source = ip.String()
		}
		if _, err := tx.Exec(ctx, `UPDATE agent_gateways SET status='bound',enrollment_port=$2,agent_port=$3,version=$4,bound_at=$5,updated_at=$5,source_ip=$6 WHERE id=$1`,
			token.GatewayID, request.EnrollmentPort, request.AgentPort, request.Version, now, source); err != nil {
			return err
		}
		// The binding address is the default allowed IP (page-editable).
		if source != nil {
			if _, err := tx.Exec(ctx, `INSERT INTO agent_gateway_allowed_ips(gateway_id,ip,created_at) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`,
				token.GatewayID, source, now); err != nil {
				return err
			}
		}
		result = BindResult{GatewayID: token.GatewayID, InstallationID: s.config.InstallationID,
			WorkloadURISAN: WorkloadURIPrefix + token.GatewayID.String(), ClientCertificatePEM: client.pem,
			ServerCertificatePEM: server.pem, RootCAPEM: s.config.RootCAPEM, NodeCAPEM: s.config.NodeCAPEM,
			Endpoints: s.config.Endpoints}
		return s.appendSystemAudit(ctx, tx, actionBind, token.GatewayID, map[string]any{"ip": sourceIP,
			"enrollment_port": request.EnrollmentPort, "agent_port": request.AgentPort, "version": request.Version})
	})
	return result, err
}

func insertCertificate(ctx context.Context, tx pgx.Tx, id uuid.UUID, kind string, c issued, now time.Time) error {
	_, err := tx.Exec(ctx, `INSERT INTO agent_gateway_certificates(serial_number,gateway_id,kind,certificate_sha256,public_key_sha256,
  certificate_pem,not_before,not_after,issued_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		c.serial, id, kind, c.certificateHash[:], c.publicKeyHash[:], c.pem, c.notBefore, c.notAfter, now)
	return err
}

// AuthorizeGateway is the ControlInternal check of a bound Gateway's client
// certificate (serial hex, lower case, no leading zeros as x509 parses it).
// disabled: the Gateway was disabled less than DisabledGrace ago; it may
// still serve its connected nodes but not enroll new ones.
func (s *Service) AuthorizeGateway(ctx context.Context, id uuid.UUID, serial string, certificateSHA256 [32]byte) (bool, error) {
	var status string
	var stored []byte
	var revoked, disabledAt *time.Time
	err := s.config.Pool.QueryRow(ctx, `SELECT g.status,g.disabled_at,c.certificate_sha256,c.revoked_at FROM agent_gateway_certificates c
  JOIN agent_gateways g ON g.id=c.gateway_id WHERE c.serial_number=$1 AND c.gateway_id=$2 AND c.kind='client'`, serial, id).
		Scan(&status, &disabledAt, &stored, &revoked)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrGatewayUnauthorized
	}
	if err != nil {
		return false, ErrUnavailable
	}
	if revoked != nil || string(stored) != string(certificateSHA256[:]) {
		return false, ErrGatewayUnauthorized
	}
	switch {
	case status == StatusBound || status == StatusActive:
		return false, nil
	case status == StatusDisabled && disabledAt != nil && s.config.Now().Before(disabledAt.Add(DisabledGrace)):
		return true, nil
	}
	return false, ErrGatewayUnauthorized
}

// AllowedSourceIPs are the allowed IPs of bound/active Gateways and of ones
// disabled less than DisabledGrace ago (default the binding address,
// editable on the page): the ControlInternal remote listener accepts only
// these (and loopback); the nftables set mirrors them.
func (s *Service) AllowedSourceIPs(ctx context.Context) ([]net.IP, error) {
	rows, err := s.config.Pool.Query(ctx, `SELECT host(a.ip) FROM agent_gateway_allowed_ips a JOIN agent_gateways g ON g.id=a.gateway_id
  WHERE g.status IN ('bound','active') OR (g.status='disabled' AND g.disabled_at > $1) ORDER BY a.ip`, s.config.Now().Add(-DisabledGrace))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []net.IP
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return nil, err
		}
		if ip := net.ParseIP(value); ip != nil {
			result = append(result, ip)
		}
	}
	return result, rows.Err()
}

// MarkReady records ReportGatewayReady (status bound/active → active).
func (s *Service) MarkReady(ctx context.Context, id uuid.UUID, version string) error {
	if len(version) > 64 {
		return ErrInvalidInput
	}
	now := s.config.Now().UTC()
	tag, err := s.config.Pool.Exec(ctx, `UPDATE agent_gateways SET status='active',version=$2,ready_at=$3,updated_at=$3
  WHERE id=$1 AND status IN ('bound','active')`, id, version, now)
	if err != nil {
		return ErrUnavailable
	}
	if tag.RowsAffected() != 1 {
		return ErrGatewayUnauthorized
	}
	return nil
}

// Renew signs a new certificate of the kind for the same public key as the
// Gateway's newest unrevoked certificate of that kind.
func (s *Service) Renew(ctx context.Context, id uuid.UUID, kind string, csrDER []byte) (RenewResult, error) {
	if kind != KindClient && kind != KindServer {
		return RenewResult{}, ErrInvalidInput
	}
	csr, keyHash, err := parseCSR(csrDER, kind)
	if err != nil {
		return RenewResult{}, err
	}
	now := s.config.Now().UTC()
	var result RenewResult
	err = pgx.BeginFunc(ctx, s.config.Pool, func(tx pgx.Tx) error {
		var status, host string
		if err := tx.QueryRow(ctx, `SELECT status,host FROM agent_gateways WHERE id=$1 FOR UPDATE`, id).Scan(&status, &host); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrGatewayUnauthorized
			}
			return err
		}
		if status != StatusBound && status != StatusActive {
			return ErrGatewayUnauthorized
		}
		var current []byte
		err := tx.QueryRow(ctx, `SELECT public_key_sha256 FROM agent_gateway_certificates WHERE gateway_id=$1 AND kind=$2 AND revoked_at IS NULL
  ORDER BY not_after DESC LIMIT 1`, id, kind).Scan(&current)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrGatewayUnauthorized
		}
		if err != nil {
			return err
		}
		if string(current) != string(keyHash[:]) {
			return ErrInvalidInput
		}
		certificate, err := s.config.Signer.issue(id, kind, host, csr, now)
		if err != nil {
			return err
		}
		if err := insertCertificate(ctx, tx, id, kind, certificate, now); err != nil {
			return err
		}
		result = RenewResult{CertificatePEM: []byte(certificate.pem), NotAfter: certificate.notAfter,
			RenewAt: renewAt(certificate.notBefore, certificate.notAfter)}
		return s.appendSystemAudit(ctx, tx, actionRenew, id, map[string]any{"kind": kind, "serial": certificate.serial})
	})
	return result, err
}

func (s *Service) appendAudit(ctx context.Context, tx pgx.Tx, actor Actor, action string, id uuid.UUID, payload map[string]any) error {
	return s.appendAuditResource(ctx, tx, actor, action, id.String(), payload)
}

func (s *Service) appendAuditResource(ctx context.Context, tx pgx.Tx, actor Actor, action, resource string, payload map[string]any) error {
	payload["ip"] = actor.IP
	user := actor.UserID
	return s.auditor.Append(ctx, tx, audit.Event{ScopeID: actor.ScopeID, ActorUserID: &user, Action: action,
		ResourceType: "agent_gateway", ResourceID: resource, RequestID: action + "." + uuid.NewString(),
		Result: "success", Payload: payload})
}

func (s *Service) appendSystemAudit(ctx context.Context, tx pgx.Tx, action string, id uuid.UUID, payload map[string]any) error {
	var scope uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform' AND tenant_id IS NULL`).Scan(&scope); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	}
	payload["actor"] = "gateway:" + id.String()
	return s.auditor.Append(ctx, tx, audit.Event{ScopeID: scope, Action: action, ActorKind: "system", ActorRef: "gateway:" + id.String(),
		ResourceType: "agent_gateway", ResourceID: id.String(), RequestID: action + "." + uuid.NewString(),
		Result: "success", Payload: payload})
}
