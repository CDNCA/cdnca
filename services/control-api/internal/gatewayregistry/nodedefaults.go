package gatewayregistry

// node-install-defaults 的网关段（Q20，ih-control）：节点复制命令
// 从这里读首选入口、传输与备用入口。写这一段的唯一函数是 NodeGatewayDefaultsFor + WriteNodeGatewayDefaults：
// install-control.sh 全新安装写出同样内容，control-api 启动、网关管理保存入口、独立网关上下线、
// control-host bind 改地址后都调它重写，页面复制的命令始终与节点实际可达的入口一致。
//
// 选首选入口的规则：发布列表（Publish 的顺序）里第一个 ws 入口（套 CDN：节点经 CDN 443 走 WebSocket 隧道），
// 没有 ws 就取第一个入口；其余按顺序进 gateway_endpoints。注册地址：入口自带的
// （在线独立网关、本机网关）> ws 入口本身（隧道两个端口都提供 /agent/v1/enroll）> 本机网关的注册地址。

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/cdnca/cdnca/services/control-api/internal/cdnranges"
)

const maxNodeEndpoints = 8

// NodeGatewayDefaults is the gateway part of node-install-defaults.
type NodeGatewayDefaults struct {
	EnrollmentAddress string
	Address           string
	ServerName        string
	Transport         string
	TunnelHost        string
	Endpoints         []Entrypoint
}

var (
	nodeDefaultsGatewayLine = regexp.MustCompile(`^gateway_(enrollment_address|address|server_name|transport|tunnel_host|endpoints)=`)
	nodeDefaultsAddress     = regexp.MustCompile(`^([A-Za-z0-9.-]+|\[[0-9A-Fa-f:.]+\]):[0-9]{1,5}$`)
	nodeDefaultsServer      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.:-]{0,252}$`)
	nodeDefaultsTunnel      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$`)
)

// NodeGatewayDefaultsFor picks the node defaults from the published endpoint
// list; local is the co-located Gateway (its EnrollmentAddress is the last
// enrollment fallback). An empty list yields ok=false (nothing to publish).
func NodeGatewayDefaultsFor(published []Entrypoint, local Entrypoint) (NodeGatewayDefaults, bool) {
	if len(published) == 0 {
		return NodeGatewayDefaults{}, false
	}
	primary := 0
	for index, endpoint := range published {
		if endpoint.Transport == TransportWS {
			primary = index
			break
		}
	}
	p := published[primary]
	defaults := NodeGatewayDefaults{Address: p.Address, ServerName: p.ServerName, Transport: p.Transport, TunnelHost: p.TunnelHost}
	if defaults.Transport == "" {
		defaults.Transport = TransportGRPC
	}
	switch {
	case p.EnrollmentAddress != "":
		defaults.EnrollmentAddress = p.EnrollmentAddress
	case defaults.Transport == TransportWS:
		defaults.EnrollmentAddress = p.Address
	default:
		defaults.EnrollmentAddress = local.EnrollmentAddress
	}
	if defaults.EnrollmentAddress == "" {
		defaults.EnrollmentAddress = p.Address
	}
	for index, endpoint := range published {
		if index != primary && len(defaults.Endpoints) < maxNodeEndpoints {
			defaults.Endpoints = append(defaults.Endpoints, endpoint)
		}
	}
	return defaults, true
}

// Lines renders the gateway lines in install-control.sh write_node_install_defaults order.
func (d NodeGatewayDefaults) Lines() ([]string, error) {
	if !nodeDefaultsAddress.MatchString(d.EnrollmentAddress) || !nodeDefaultsAddress.MatchString(d.Address) ||
		!nodeDefaultsServer.MatchString(d.ServerName) || (d.Transport != TransportGRPC && d.Transport != TransportWS) ||
		(d.TunnelHost != "" && (d.Transport != TransportWS || !nodeDefaultsTunnel.MatchString(d.TunnelHost))) {
		return nil, errors.New("node gateway defaults are invalid")
	}
	lines := []string{"gateway_enrollment_address=" + d.EnrollmentAddress, "gateway_address=" + d.Address,
		"gateway_server_name=" + d.ServerName}
	if d.Transport == TransportWS {
		lines = append(lines, "gateway_transport="+TransportWS)
		if d.TunnelHost != "" {
			lines = append(lines, "gateway_tunnel_host="+d.TunnelHost)
		}
	}
	var entries []string
	for _, e := range d.Endpoints {
		transport := e.Transport
		if transport == "" {
			transport = TransportGRPC
		}
		if !nodeDefaultsAddress.MatchString(e.Address) || !nodeDefaultsServer.MatchString(e.ServerName) ||
			(e.TunnelHost != "" && !nodeDefaultsTunnel.MatchString(e.TunnelHost)) {
			return nil, errors.New("node gateway endpoint is invalid")
		}
		entry := e.Address + "|" + e.ServerName + "|" + transport
		if e.TunnelHost != "" {
			entry += "|" + e.TunnelHost
		}
		entries = append(entries, entry)
	}
	if len(entries) > 0 {
		lines = append(lines, "gateway_endpoints="+strings.Join(entries, " "))
	}
	return lines, nil
}

// RenderNodeGatewayDefaults replaces every gateway_* line of content with
// d's, placed after upgrade_trust_sha256 (other lines keep their order).
func RenderNodeGatewayDefaults(content []byte, d NodeGatewayDefaults) ([]byte, error) {
	lines, err := d.Lines()
	if err != nil {
		return nil, err
	}
	var out []string
	inserted := false
	for _, line := range strings.Split(strings.TrimRight(string(content), "\n"), "\n") {
		if nodeDefaultsGatewayLine.MatchString(line) || line == "" {
			continue
		}
		out = append(out, line)
		if strings.HasPrefix(line, "upgrade_trust_sha256=") && !inserted {
			out, inserted = append(out, lines...), true
		}
	}
	if !inserted {
		out = append(lines, out...)
	}
	return []byte(strings.Join(out, "\n") + "\n"), nil
}

// WriteNodeGatewayDefaults rewrites path in place (mode and owner kept);
// a missing file is left alone (the installer creates it). Reports a change.
func WriteNodeGatewayDefaults(path string, d NodeGatewayDefaults) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() {
		return false, errors.New(path + " is not a regular file")
	}
	current, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	updated, err := RenderNodeGatewayDefaults(current, d)
	if err != nil || bytes.Equal(current, updated) {
		return false, err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return false, err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if _, err = temporary.Write(updated); err == nil {
		err = temporary.Chmod(info.Mode().Perm())
	}
	if closeErr := temporary.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		chownLike(name, info)
		err = os.Rename(name, path)
	}
	return err == nil, err
}

// ParseNodeGatewayDefaults reads the gateway part back (control-host bind keeps
// the entries it does not move).
func ParseNodeGatewayDefaults(content []byte) NodeGatewayDefaults {
	var d NodeGatewayDefaults
	for _, line := range strings.Split(string(content), "\n") {
		key, value, _ := strings.Cut(line, "=")
		switch key {
		case "gateway_enrollment_address":
			d.EnrollmentAddress = value
		case "gateway_address":
			d.Address = value
		case "gateway_server_name":
			d.ServerName = value
		case "gateway_transport":
			d.Transport = value
		case "gateway_tunnel_host":
			d.TunnelHost = value
		case "gateway_endpoints":
			for _, entry := range strings.Fields(value) {
				parts := strings.Split(entry, "|")
				for len(parts) < 4 {
					parts = append(parts, "")
				}
				d.Endpoints = append(d.Endpoints, Entrypoint{Address: parts[0], ServerName: parts[1], Transport: parts[2], TunnelHost: parts[3]})
			}
		}
	}
	if d.Transport == "" {
		d.Transport = TransportGRPC
	}
	return d
}

// CDNTunnelPort is the console HTTPS port a CDN forwards (Cloudflare proxies
// 443; it does not forward the Gateway ports 29402/20407).
const CDNTunnelPort = "443"

// WithCDNTunnel puts the 443 WebSocket tunnel first when the co-located
// Gateway host is behind a CDN (behindCDN) and no ws entry is published
// (11-02, 73: gateway.cdnca.com is a Cloudflare name, enrollment on 29402
// timed out). The tunnel is <gateway host>:443 through the management nginx
// location ^~ /agent/v1/, inner TLS still the Gateway server name; the
// direct entries stay as fallbacks. A published ws entry (Gateway page,
// install-control.sh --gateway-transport ws) is left as it is.
func WithCDNTunnel(published []Entrypoint, local Entrypoint, behindCDN bool) []Entrypoint {
	if !behindCDN || len(published) == 0 {
		return published
	}
	for _, endpoint := range published {
		if endpoint.Transport == TransportWS {
			return published
		}
	}
	host, _, err := net.SplitHostPort(local.Address)
	if err != nil || !nodeDefaultsTunnel.MatchString(host) || local.ServerName == "" {
		return published
	}
	tunnel := Entrypoint{Address: net.JoinHostPort(host, CDNTunnelPort), ServerName: local.ServerName,
		Transport: TransportWS, TunnelHost: host}
	return append([]Entrypoint{tunnel}, published...)
}

// nodeEndpoints is the published list as nodes are told to use it
// (node-install-defaults and the copied / SSH install command alike).
func (s *Service) nodeEndpoints(ctx context.Context) ([]Entrypoint, error) {
	published, err := s.Publish(ctx)
	if err != nil {
		return nil, err
	}
	host, _, _ := net.SplitHostPort(s.config.LocalGateway.Address)
	behind := host != "" && cdnranges.HostBehindCDN(ctx, s.config.LookupHost, host)
	return WithCDNTunnel(published.Endpoints, s.config.LocalGateway, behind), nil
}

// SyncNodeDefaults rewrites the gateway lines of Config.NodeDefaultsFile from
// the current published endpoint list (control-api start and every change).
func (s *Service) SyncNodeDefaults(ctx context.Context) (bool, error) {
	if s.config.NodeDefaultsFile == "" {
		return false, nil
	}
	endpoints, err := s.nodeEndpoints(ctx)
	if err != nil {
		return false, err
	}
	defaults, ok := NodeGatewayDefaultsFor(endpoints, s.config.LocalGateway)
	if !ok {
		return false, nil
	}
	return WriteNodeGatewayDefaults(s.config.NodeDefaultsFile, defaults)
}

// DirectNodeInstallGateway is the Gateway entry the console writes into the
// copied / SSH node install command (--gateway-enrollment-address,
// --gateway-address, --gateway-server-name; the node connects to
// the Gateway IP directly). Same choice as node-install-defaults
// (NodeGatewayDefaultsFor); ok=false when nothing is published, the
// preferred entry is ws (CDN tunnel: the command stays as it is) or the
// values would not pass Lines.
func DirectNodeInstallGateway(published []Entrypoint, local Entrypoint) (NodeGatewayDefaults, bool) {
	d, ok := NodeGatewayDefaultsFor(published, local)
	if !ok || d.Transport != TransportGRPC {
		return NodeGatewayDefaults{}, false
	}
	if _, err := d.Lines(); err != nil {
		return NodeGatewayDefaults{}, false
	}
	return NodeGatewayDefaults{EnrollmentAddress: d.EnrollmentAddress, Address: d.Address, ServerName: d.ServerName, Transport: TransportGRPC}, true
}

// ReinstallNodeInstallGateway is the Gateway entry of the 重装此节点 command
//: DirectNodeInstallGateway, and on a ws console the
// first published grpc entry (same enrollment-address rule as
// NodeGatewayDefaultsFor). A reinstalled node usually ran on grpc before;
// when that port is closed (CDN) the installer's 443 WebSocket fallback
// (install-node.sh gateway_fallback_defaults) still enrolls it.
func ReinstallNodeInstallGateway(published []Entrypoint, local Entrypoint) (NodeGatewayDefaults, bool) {
	if d, ok := DirectNodeInstallGateway(published, local); ok {
		return d, true
	}
	var direct []Entrypoint
	for _, endpoint := range published {
		if endpoint.Transport == TransportGRPC || endpoint.Transport == "" {
			direct = append(direct, endpoint)
		}
	}
	return DirectNodeInstallGateway(direct, local)
}

// NodeReinstallGateway reads the published list and applies ReinstallNodeInstallGateway.
func (s *Service) NodeReinstallGateway(ctx context.Context) (NodeGatewayDefaults, bool, error) {
	if s == nil {
		return NodeGatewayDefaults{}, false, nil
	}
	endpoints, err := s.nodeEndpoints(ctx)
	if err != nil {
		return NodeGatewayDefaults{}, false, err
	}
	d, ok := ReinstallNodeInstallGateway(endpoints, s.config.LocalGateway)
	return d, ok, nil
}

// NodeInstallGateway reads the published list and applies DirectNodeInstallGateway.
// A nil service (no Gateway registry on this console) yields ok=false.
func (s *Service) NodeInstallGateway(ctx context.Context) (NodeGatewayDefaults, bool, error) {
	if s == nil {
		return NodeGatewayDefaults{}, false, nil
	}
	endpoints, err := s.nodeEndpoints(ctx)
	if err != nil {
		return NodeGatewayDefaults{}, false, err
	}
	d, ok := DirectNodeInstallGateway(endpoints, s.config.LocalGateway)
	return d, ok, nil
}

// syncNodeDefaultsAfterChange: the change itself is committed; a failed
// rewrite is logged (control-api retries at the next start or change).
func (s *Service) syncNodeDefaultsAfterChange(ctx context.Context) {
	if changed, err := s.SyncNodeDefaults(context.WithoutCancel(ctx)); err != nil {
		slog.Warn("node install defaults not updated after a Gateway change", "error", err)
	} else if changed {
		slog.Info("node install defaults follow the published Gateway entry points", "file", s.config.NodeDefaultsFile)
	}
}

// MoveLocalGateway replaces the co-located Gateway's old entry (address,
// enrollment address, server name) with the new one wherever it appears in
// d (primary or fallback); CDN/page entries stay. control-host bind uses it
// before control-api restarts and SyncNodeDefaults recomputes the same lines.
func (d NodeGatewayDefaults) MoveLocalGateway(old, updated Entrypoint) NodeGatewayDefaults {
	swap := func(value string) string {
		switch value {
		case old.Address:
			return updated.Address
		case old.EnrollmentAddress:
			return updated.EnrollmentAddress
		}
		return value
	}
	moved := d
	if d.Address == old.Address || d.EnrollmentAddress == old.EnrollmentAddress {
		moved.Address, moved.EnrollmentAddress = swap(d.Address), swap(d.EnrollmentAddress)
		if d.ServerName == old.ServerName {
			moved.ServerName = updated.ServerName
		}
	}
	moved.Endpoints = nil
	for _, e := range d.Endpoints {
		if e.Address == old.Address {
			e.Address, e.ServerName = updated.Address, updated.ServerName
		}
		moved.Endpoints = append(moved.Endpoints, e)
	}
	return moved
}

// EnsureInstallEntrypoint is install-control.sh's seed for a ws install (Q20):
// the node entry on the console HTTPS port (nginx proxies /agent/v1/* to the
// local Gateway) is appended to the page-edited entry points unless its
// address is already there, and the loopback proxy is trusted for header
// (the node's real IP; nginx sets it). Idempotent; no audit row (system seed
// before the first administrator signs in).
func EnsureInstallEntrypoint(ctx context.Context, db *pgxpool.Pool, entry Entrypoint, loopbackHeader string) error {
	items, err := normalizeEntrypoints([]Entrypoint{entry})
	if err != nil {
		return err
	}
	if loopbackHeader != "" && !headerName.MatchString(loopbackHeader) {
		return ErrInvalidInput
	}
	e := items[0]
	return pgx.BeginFunc(ctx, db, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `LOCK TABLE agent_gateway_trusted_ranges, agent_gateway_entrypoints IN EXCLUSIVE MODE`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO agent_gateway_entrypoints(position,address,server_name,transport,tunnel_host)
  SELECT COALESCE(max(position),0)+1,$1,$2,$3,$4 FROM agent_gateway_entrypoints
  HAVING NOT EXISTS (SELECT 1 FROM agent_gateway_entrypoints WHERE address=$1)`, e.Address, e.ServerName, e.Transport, e.TunnelHost); err != nil {
			return err
		}
		if loopbackHeader == "" {
			return nil
		}
		_, err := tx.Exec(ctx, `INSERT INTO agent_gateway_trusted_ranges(position,cidr,header)
  SELECT COALESCE(max(position),0)+1,'127.0.0.1/32',$1 FROM agent_gateway_trusted_ranges
  HAVING NOT EXISTS (SELECT 1 FROM agent_gateway_trusted_ranges WHERE cidr='127.0.0.1/32')`, canonicalHeader(loopbackHeader))
		return err
	})
}
