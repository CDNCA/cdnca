package gatewayregistry

// Gateway settings published by the management page (ADR 0013 §3.4/§4.4/§4.5,
// GW-06/GW-07): trusted CDN back-to-origin ranges, per-Gateway allowed IPs
// (the ControlInternal remote listener and nftables set read the same rows)
// and the extra node entry points. Gateways poll them over ControlInternal
// GetGatewaySettings.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	MaxTrustedProxies = 512
	MaxEntrypoints    = 16
	MaxAllowedIPs     = 16

	TransportGRPC = "grpc"
	TransportWS   = "ws"

	actionSettings   = "system.gateway.settings"
	actionAllowedIPs = "system.gateway.allowed_ips"
)

var headerName = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)

type TrustedProxy struct {
	CIDR   string `json:"cidr"`
	Header string `json:"header"`
}

// Entrypoint is one node entry point (ADR 0013 §4.5); TunnelHost is the outer
// SNI/Host of a ws entry when it differs from ServerName.
type Entrypoint struct {
	Address    string `json:"address"`
	ServerName string `json:"server_name"`
	Transport  string `json:"transport"`
	TunnelHost string `json:"tunnel_host"`
	// EnrollmentAddress is published for online Gateways only (host:
	// enrollment_port); page-edited entry points never carry one.
	EnrollmentAddress string `json:"-"`
}

// Settings is GET/PUT /v1/admin/gateway-settings.
type Settings struct {
	TrustedProxies []TrustedProxy `json:"trusted_proxies"`
	Entrypoints    []Entrypoint   `json:"entrypoints"`
}

// Published is what ControlInternal hands every Gateway.
type Published struct {
	TrustedProxies   []TrustedProxy
	Endpoints        []Entrypoint
	EndpointsVersion string
}

// normalizeTrustedProxies canonicalizes and validates the ranges (the same
// rules as the Gateway's ParseTrustedProxyRanges; duplicates refused).
func normalizeTrustedProxies(items []TrustedProxy) ([]TrustedProxy, error) {
	if len(items) > MaxTrustedProxies {
		return nil, ErrInvalidInput
	}
	out := make([]TrustedProxy, 0, len(items))
	seen := map[netip.Prefix]bool{}
	for _, item := range items {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(item.CIDR))
		header := strings.TrimSpace(item.Header)
		if header == "" {
			header = "X-Forwarded-For"
		}
		if err != nil || prefix.Addr().Zone() != "" || !headerName.MatchString(header) {
			return nil, ErrInvalidInput
		}
		prefix = prefix.Masked()
		if seen[prefix] {
			return nil, ErrInvalidInput
		}
		seen[prefix] = true
		out = append(out, TrustedProxy{CIDR: prefix.String(), Header: canonicalHeader(header)})
	}
	return out, nil
}

func canonicalHeader(value string) string {
	parts := strings.Split(strings.ToLower(value), "-")
	for i, part := range parts {
		if part != "" {
			parts[i] = strings.ToUpper(part[:1]) + part[1:]
		}
	}
	return strings.Join(parts, "-")
}

func normalizeEntrypoints(items []Entrypoint) ([]Entrypoint, error) {
	if len(items) > MaxEntrypoints {
		return nil, ErrInvalidInput
	}
	out := make([]Entrypoint, 0, len(items))
	seen := map[string]bool{}
	for _, item := range items {
		e := Entrypoint{Address: strings.ToLower(strings.TrimSpace(item.Address)), ServerName: strings.ToLower(strings.TrimSpace(item.ServerName)),
			Transport: strings.TrimSpace(item.Transport), TunnelHost: strings.ToLower(strings.TrimSpace(item.TunnelHost))}
		host, port, err := net.SplitHostPort(e.Address)
		number, portErr := strconv.Atoi(port)
		if err != nil || portErr != nil || number < 1 || number > 65535 || !validHost(host) || len(e.Address) > 260 ||
			!validHost(e.ServerName) || (e.Transport != TransportGRPC && e.Transport != TransportWS) ||
			(e.TunnelHost != "" && (e.Transport != TransportWS || !validHost(e.TunnelHost))) || seen[e.Address] {
			return nil, ErrInvalidInput
		}
		seen[e.Address] = true
		out = append(out, e)
	}
	return out, nil
}

// normalizeAllowedIPs accepts single IPv4/IPv6 addresses (no ranges).
func normalizeAllowedIPs(items []string) ([]string, error) {
	if len(items) == 0 || len(items) > MaxAllowedIPs {
		return nil, ErrInvalidInput
	}
	out := make([]string, 0, len(items))
	seen := map[string]bool{}
	for _, item := range items {
		addr, err := netip.ParseAddr(strings.TrimSpace(item))
		if err != nil || addr.Zone() != "" || addr.IsUnspecified() {
			return nil, ErrInvalidInput
		}
		value := addr.Unmap().String()
		if seen[value] {
			return nil, ErrInvalidInput
		}
		seen[value] = true
		out = append(out, value)
	}
	return out, nil
}

// SettingsETag is the quoted content digest of the settings (G1): GET returns
// it and PUT must send it back in If-Match, so an outdated form cannot
// overwrite a newer save. The tables carry no revision; the digest needs none.
func SettingsETag(settings Settings) string {
	raw, _ := json.Marshal(settings)
	sum := sha256.Sum256(raw)
	return `"sha256-` + hex.EncodeToString(sum[:]) + `"`
}

type settingsQuerier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

func (s *Service) Settings(ctx context.Context) (Settings, error) {
	return readSettings(ctx, s.config.Pool)
}

func readSettings(ctx context.Context, db settingsQuerier) (Settings, error) {
	result := Settings{TrustedProxies: []TrustedProxy{}, Entrypoints: []Entrypoint{}}
	rows, err := db.Query(ctx, `SELECT cidr::text,header FROM agent_gateway_trusted_ranges ORDER BY position`)
	if err != nil {
		return result, fmt.Errorf("list trusted ranges: %w", err)
	}
	for rows.Next() {
		var item TrustedProxy
		if err := rows.Scan(&item.CIDR, &item.Header); err != nil {
			rows.Close()
			return result, err
		}
		result.TrustedProxies = append(result.TrustedProxies, item)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return result, err
	}
	rows, err = db.Query(ctx, `SELECT address,server_name,transport,tunnel_host FROM agent_gateway_entrypoints ORDER BY position`)
	if err != nil {
		return result, fmt.Errorf("list entry points: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var item Entrypoint
		if err := rows.Scan(&item.Address, &item.ServerName, &item.Transport, &item.TunnelHost); err != nil {
			return result, err
		}
		result.Entrypoints = append(result.Entrypoints, item)
	}
	return result, rows.Err()
}

// UpdateSettings replaces both lists (the page always sends the whole form).
// ifMatch must be the SettingsETag of the current rows, compared under the
// table lock; otherwise ErrSettingsChanged and nothing is written.
func (s *Service) UpdateSettings(ctx context.Context, actor Actor, ifMatch string, input Settings) (Settings, error) {
	proxies, err := normalizeTrustedProxies(input.TrustedProxies)
	if err != nil {
		return Settings{}, err
	}
	entrypoints, err := normalizeEntrypoints(input.Entrypoints)
	if err != nil {
		return Settings{}, err
	}
	var saved Settings
	err = pgx.BeginFunc(ctx, s.config.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `LOCK TABLE agent_gateway_trusted_ranges, agent_gateway_entrypoints IN EXCLUSIVE MODE`); err != nil {
			return err
		}
		current, err := readSettings(ctx, tx)
		if err != nil {
			return err
		}
		if SettingsETag(current) != ifMatch {
			return ErrSettingsChanged
		}
		if _, err := tx.Exec(ctx, `DELETE FROM agent_gateway_trusted_ranges`); err != nil {
			return err
		}
		for i, item := range proxies {
			if _, err := tx.Exec(ctx, `INSERT INTO agent_gateway_trusted_ranges(position,cidr,header) VALUES($1,$2,$3)`, i+1, item.CIDR, item.Header); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `DELETE FROM agent_gateway_entrypoints`); err != nil {
			return err
		}
		for i, item := range entrypoints {
			if _, err := tx.Exec(ctx, `INSERT INTO agent_gateway_entrypoints(position,address,server_name,transport,tunnel_host) VALUES($1,$2,$3,$4,$5)`,
				i+1, item.Address, item.ServerName, item.Transport, item.TunnelHost); err != nil {
				return err
			}
		}
		// Read back what a later GET returns, so the new ETag matches it.
		if saved, err = readSettings(ctx, tx); err != nil {
			return err
		}
		return s.appendAuditResource(ctx, tx, actor, actionSettings, "settings", map[string]any{"trusted_proxies": len(proxies), "entrypoints": entrypoints})
	})
	if err != nil {
		return Settings{}, err
	}
	return saved, nil
}

// SetAllowedIPs replaces the addresses a standalone Gateway may connect from
// (default: its binding source address).
func (s *Service) SetAllowedIPs(ctx context.Context, actor Actor, id uuid.UUID, ips []string) ([]string, error) {
	normalized, err := normalizeAllowedIPs(ips)
	if err != nil {
		return nil, err
	}
	now := s.config.Now().UTC()
	err = pgx.BeginFunc(ctx, s.config.Pool, func(tx pgx.Tx) error {
		var status string
		err := tx.QueryRow(ctx, `SELECT status FROM agent_gateways WHERE id=$1 FOR UPDATE`, id).Scan(&status)
		if errors.Is(err, pgx.ErrNoRows) || status == StatusDeleted {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if status == StatusPending {
			// No binding yet: the first address comes from the binding itself.
			return ErrConflict
		}
		var previous []string
		if err := tx.QueryRow(ctx, `SELECT COALESCE(array_agg(host(ip) ORDER BY ip),'{}') FROM agent_gateway_allowed_ips WHERE gateway_id=$1`, id).Scan(&previous); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM agent_gateway_allowed_ips WHERE gateway_id=$1`, id); err != nil {
			return err
		}
		for _, ip := range normalized {
			if _, err := tx.Exec(ctx, `INSERT INTO agent_gateway_allowed_ips(gateway_id,ip,created_at) VALUES($1,$2,$3)`, id, ip, now); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE agent_gateways SET updated_at=$2 WHERE id=$1`, id, now); err != nil {
			return err
		}
		return s.appendAudit(ctx, tx, actor, actionAllowedIPs, id, map[string]any{"previous": previous, "allowed_ips": normalized})
	})
	return normalized, err
}

// Publish is ControlInternal GetGatewaySettings: online (active) Gateways
// first, each as host:agent_port grpc, then the co-located Gateway of an
// all/control installation (Config.LocalGateway), then the extra entry points.
func (s *Service) Publish(ctx context.Context) (Published, error) {
	settings, err := s.Settings(ctx)
	if err != nil {
		return Published{}, ErrUnavailable
	}
	rows, err := s.config.Pool.Query(ctx, `SELECT host,agent_port,enrollment_port FROM agent_gateways WHERE status='active' AND agent_port IS NOT NULL ORDER BY bound_at,id`)
	if err != nil {
		return Published{}, ErrUnavailable
	}
	defer rows.Close()
	endpoints := []Entrypoint{}
	for rows.Next() {
		var host string
		var port, enrollmentPort int
		if err := rows.Scan(&host, &port, &enrollmentPort); err != nil {
			return Published{}, ErrUnavailable
		}
		endpoints = append(endpoints, Entrypoint{Address: net.JoinHostPort(host, strconv.Itoa(port)), ServerName: host, Transport: TransportGRPC,
			EnrollmentAddress: net.JoinHostPort(host, strconv.Itoa(enrollmentPort))})
	}
	if rows.Err() != nil {
		return Published{}, ErrUnavailable
	}
	endpoints = publishedEndpoints(endpoints, s.config.LocalGateway, settings.Entrypoints)
	return Published{TrustedProxies: settings.TrustedProxies, Endpoints: endpoints, EndpointsVersion: EndpointsVersion(endpoints)}, nil
}

// publishedEndpoints orders the node endpoint list (K1): standalone, local
// (zero value: none), extra; a later entry repeating an address is dropped.
func publishedEndpoints(standalone []Entrypoint, local Entrypoint, extra []Entrypoint) []Entrypoint {
	out := make([]Entrypoint, 0, len(standalone)+1+len(extra))
	seen := map[string]bool{}
	add := func(e Entrypoint) {
		if !seen[e.Address] {
			seen[e.Address] = true
			out = append(out, e)
		}
	}
	for _, e := range standalone {
		add(e)
	}
	if local.Address != "" {
		add(local)
	}
	for _, e := range extra {
		add(e)
	}
	return out
}

// LocalGatewayEndpoint validates the co-located Gateway's public node channel
// (host:agent_port), its server name and enrollment address (host:port). All
// empty: no local Gateway is published.
func LocalGatewayEndpoint(address, serverName, enrollmentAddress string) (Entrypoint, error) {
	if address == "" && serverName == "" && enrollmentAddress == "" {
		return Entrypoint{}, nil
	}
	items, err := normalizeEntrypoints([]Entrypoint{{Address: address, ServerName: serverName, Transport: TransportGRPC}})
	if err != nil {
		return Entrypoint{}, err
	}
	enrollment := strings.ToLower(strings.TrimSpace(enrollmentAddress))
	host, port, err := net.SplitHostPort(enrollment)
	number, portErr := strconv.Atoi(port)
	if err != nil || portErr != nil || number < 1 || number > 65535 || !validHost(host) {
		return Entrypoint{}, ErrInvalidInput
	}
	items[0].EnrollmentAddress = enrollment
	return items[0], nil
}

// EndpointsVersion is a digest of the ordered list (empty list: "").
func EndpointsVersion(endpoints []Entrypoint) string {
	if len(endpoints) == 0 {
		return ""
	}
	digest := sha256.New()
	for _, e := range endpoints {
		fmt.Fprintf(digest, "%s\x00%s\x00%s\x00%s\x00%s\n", e.Address, e.ServerName, e.Transport, e.TunnelHost, e.EnrollmentAddress)
	}
	return hex.EncodeToString(digest.Sum(nil))[:32]
}
