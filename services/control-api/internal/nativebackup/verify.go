package nativebackup

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// VerifyReport is printed after a restore or migration. Version, schema and
// health are hard requirements; node reconnection and DNS depend on the
// operator switching DNS, so they are reported, not failed.
type VerifyReport struct {
	Version         string `json:"version"`
	SchemaVersion   uint64 `json:"schema_version"`
	ControlReady    bool   `json:"control_ready"`
	GatewayReady    bool   `json:"gateway_ready"`
	ActiveNodes     int    `json:"active_nodes"`
	OnlineNodes     int    `json:"online_nodes"`
	ControlDomain   string `json:"control_domain"`
	GatewayEndpoint string `json:"gateway_endpoint"`
	DNSPointsHere   bool   `json:"dns_points_here"`
	// NodeInstallTrust is the node install trust republished for this host
	// once control-api and the Gateway are healthy (fix-btenv4).
	NodeInstallTrust *NodeInstallTrustReport `json:"node_install_trust,omitempty"`
	Warnings         []string                `json:"warnings"`
}

// NodeInstallTrustReport names the republished document and the download
// endpoint it gives newly installed nodes.
type NodeInstallTrustReport struct {
	SHA256    string   `json:"sha256"`
	Host      string   `json:"download_host"`
	Port      uint16   `json:"download_port"`
	Addresses []string `json:"download_addresses"`
}

// Message is the migration log line.
func (trust NodeInstallTrustReport) Message() string {
	return fmt.Sprintf("已重新发布节点安装信任文档（sha256 %s，节点升级下载 %s → %s），控制台节点安装命令随之更新",
		trust.SHA256, net.JoinHostPort(trust.Host, strconv.Itoa(int(trust.Port))), strings.Join(trust.Addresses, ","))
}

type Verifier struct {
	Host   *Host
	HTTP   *http.Client
	Lookup func(context.Context, string) ([]string, error)
	Local  func() ([]string, error)
	// PublishTrust republishes the node install trust (PublishNodeInstallTrust);
	// nil skips it.
	PublishTrust func(context.Context) (NodeInstallTrust, error)
}

func (verifier Verifier) ready(ctx context.Context, url string) bool {
	for attempt := 0; attempt < 60; attempt++ {
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if response, err := verifier.HTTP.Do(request); err == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return true
			}
		}
		if !sleepContext(ctx, 2*time.Second) {
			return false
		}
	}
	return false
}

func (verifier Verifier) Verify(ctx context.Context, manifest Manifest, since time.Time) (VerifyReport, error) {
	facts, err := NativeFacts(ctx, verifier.Host)
	if err != nil {
		return VerifyReport{}, err
	}
	report := VerifyReport{Version: facts.Version, ControlDomain: facts.ControlDomain, GatewayEndpoint: facts.GatewayEndpoint, Warnings: []string{}}
	var failures []string
	if facts.Version != manifest.Control.Version {
		failures = append(failures, fmt.Sprintf("version %s != backup %s", facts.Version, manifest.Control.Version))
	}
	report.ControlReady = verifier.ready(ctx, "http://127.0.0.1:8080/health/ready")
	report.GatewayReady = verifier.ready(ctx, "http://127.0.0.1:8082/health/ready")
	if !report.ControlReady {
		failures = append(failures, "control-api /health/ready did not answer 200")
	}
	if !report.GatewayReady {
		failures = append(failures, "agent-gateway /health/ready did not answer 200")
	}
	component := postgresComponent{}
	if value, err := component.psql(ctx, verifier.Host, verifier.Host.Database.Name, "SELECT max(version) FROM schema_migrations"); err == nil {
		report.SchemaVersion, _ = strconv.ParseUint(value, 10, 64)
	}
	if report.SchemaVersion != manifest.Control.SchemaVersion {
		failures = append(failures, fmt.Sprintf("schema %d != backup %d", report.SchemaVersion, manifest.Control.SchemaVersion))
	}
	counts, err := component.psql(ctx, verifier.Host, verifier.Host.Database.Name,
		"SELECT (SELECT count(*) FROM nodes WHERE admin_state IN ('active','draining'))||','||"+
			"(SELECT count(*) FROM node_presence WHERE status='online' AND last_seen_at > '"+since.UTC().Format(time.RFC3339)+"')")
	if active, online, found := strings.Cut(counts, ","); err == nil && found {
		report.ActiveNodes, _ = strconv.Atoi(active)
		report.OnlineNodes, _ = strconv.Atoi(online)
	}
	host := facts.GatewayEndpoint
	if split, _, err := net.SplitHostPort(host); err == nil {
		host = split
	}
	if net.ParseIP(strings.Trim(host, "[]")) != nil {
		report.Warnings = append(report.Warnings, "Gateway 地址是 IP（"+host+"）：节点不会随 DNS 切换，需在每个节点改主控地址或让新主控沿用旧 IP")
	} else if host != "" && verifier.Lookup != nil && verifier.Local != nil {
		resolved, _ := verifier.Lookup(ctx, host)
		local, _ := verifier.Local()
		report.DNSPointsHere = intersects(resolved, local)
		if !report.DNSPointsHere {
			report.Warnings = append(report.Warnings, fmt.Sprintf("%s 仍解析到 %s，请把控制台与 Gateway 域名的 DNS 改到本机，节点会自动重连", host, strings.Join(resolved, ",")))
		}
	}
	if report.ControlReady && report.GatewayReady {
		verifier.republishNodeInstallTrust(ctx, &report)
	}
	if report.OnlineNodes < report.ActiveNodes {
		report.Warnings = append(report.Warnings, fmt.Sprintf("已重连节点 %d/%d", report.OnlineNodes, report.ActiveNodes))
	}
	report.Warnings = append(report.Warnings, "授权门户“我的授权”里把主控 IP 改为本机出口 IP（授权续期不受影响，但升级包下载按主控 IP 校验）")
	if len(failures) > 0 {
		return report, errors.New(strings.Join(failures, "; "))
	}
	return report, nil
}

// republishNodeInstallTrust points the node install command at this host:
// the restored document still names the source host's addresses, port and
// root. A failure is a warning, not a failed verification: running nodes
// follow the download policy signed into each upgrade (fix-btenv3) and
// control-api retries every 10 minutes (NodeInstallTrustWatcher, fix-btenv5).
func (verifier Verifier) republishNodeInstallTrust(ctx context.Context, report *VerifyReport) {
	if verifier.PublishTrust == nil {
		return
	}
	trust, err := verifier.PublishTrust(ctx)
	if err != nil {
		report.Warnings = append(report.Warnings, "节点安装信任文档重新发布失败（"+err.Error()+"）：新装节点仍会连旧主控的升级下载地址；修复后 control-api 最长 10 分钟自动重新发布，也可立即运行 verify-migration")
		return
	}
	report.NodeInstallTrust = &NodeInstallTrustReport{SHA256: trust.SHA256, Host: trust.Download.Host, Port: trust.Download.Port,
		Addresses: trust.Download.Addresses}
	if verifier.Local != nil {
		if local, err := verifier.Local(); err == nil && !intersects(trust.Download.Addresses, local) {
			report.Warnings = append(report.Warnings, fmt.Sprintf("节点安装信任文档里 %s 解析到 %s（不是本机）；切换管理端域名 DNS 后 control-api 最长 10 分钟自动按新地址重新发布，也可立即在本机运行 verify-migration",
				trust.Download.Host, strings.Join(trust.Download.Addresses, ",")))
		}
	}
}

func intersects(left, right []string) bool {
	set := map[string]bool{}
	for _, value := range right {
		set[value] = true
	}
	for _, value := range left {
		if set[value] {
			return true
		}
	}
	return false
}

func LocalAddresses() ([]string, error) {
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	var values []string
	for _, address := range addresses {
		if network, ok := address.(*net.IPNet); ok && !network.IP.IsLoopback() {
			values = append(values, network.IP.String())
		}
	}
	return values, nil
}

// ---- systemd units for the backup agent ----

const (
	agentServiceUnit = "cdnca-control-backup.service"
	agentPathUnit    = "cdnca-control-backup.path"
	agentTimerUnit   = "cdnca-control-backup.timer"
)

// AgentUnits returns the unit files. The agent is a separate root oneshot:
// it stops control-api while backing up, so it cannot live inside it.
func AgentUnits() map[string]string {
	return map[string]string{
		agentServiceUnit: `[Unit]
Description=CDNCA control backup, restore and migration agent
After=network-online.target postgresql.service clickhouse-server.service

[Service]
Type=oneshot
User=root
UMask=0077
ExecStart=` + NativeRoot + `/current/bin/control-api native-backup agent
TimeoutStartSec=6h
Nice=10
IOSchedulingClass=idle
StandardOutput=journal
StandardError=journal
`,
		agentPathUnit: `[Unit]
Description=Run the CDNCA control backup agent when the console queues a job

[Path]
DirectoryNotEmpty=` + AgentRoot + `/requests
Unit=` + agentServiceUnit + `

[Install]
WantedBy=multi-user.target
`,
		FrozenConsoleUnit: `[Unit]
Description=CDNCA frozen console (migration hold: status, logs and rollback only)
After=network-online.target postgresql.service redis-server.service
Conflicts=cdnca-control-api.service

[Service]
Type=simple
User=root
UMask=0077
EnvironmentFile=` + ConfigDirectory + `/control.env
EnvironmentFile=-` + ConfigDirectory + `/runtime-extra.env
ExecStart=` + NativeRoot + `/current/bin/control-api native-backup frozen-console
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
ProtectHome=read-only
ProtectSystem=full
ReadWritePaths=` + AgentRoot + `
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
`,
		agentTimerUnit: `[Unit]
Description=Check the CDNCA control backup schedule

[Timer]
OnBootSec=5min
OnUnitInactiveSec=5min
Unit=` + agentServiceUnit + `

[Install]
WantedBy=timers.target
`,
	}
}

// InstallUnits writes the agent units if missing or different and enables
// the path and timer. Idempotent; used by the installer and on upgrade.
func InstallUnits(ctx context.Context, host *Host) error {
	for _, directory := range []string{AgentRoot, AgentRoot + "/requests", AgentRoot + "/runs", BackupRoot} {
		if err := ensurePrivateDirectory(host.Layout.Path(directory)); err != nil {
			return err
		}
	}
	changed := false
	for name, content := range AgentUnits() {
		path := host.Layout.Path("/etc/systemd/system/" + name)
		if current, err := os.ReadFile(path); err == nil && string(current) == content {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if err := writeFileAtomic(path, []byte(content), 0o644); err != nil {
			return err
		}
		changed = true
	}
	if changed {
		if err := host.Systemd.DaemonReload(ctx); err != nil {
			return err
		}
	}
	for _, unit := range []string{agentPathUnit, agentTimerUnit} {
		if err := host.Systemd.Enable(ctx, unit); err != nil {
			return err
		}
		if err := host.Systemd.Start(ctx, unit); err != nil {
			return err
		}
	}
	return nil
}
