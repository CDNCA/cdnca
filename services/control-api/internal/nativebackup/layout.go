// Package nativebackup backs up, restores and migrates a native (systemd)
// control plane installed by scripts/install-control.sh. It is separate from
// the Kubernetes recovery driver (cmd/control-recovery-driver), whose signed
// manifest covers exactly PostgreSQL, ClickHouse and three JetStream streams.
// A native host also carries its configuration, keys, release tree and
// object store, and every JetStream stream, so the native bundle has its own
// schema (cdnca.control-native-backup/v1).
package nativebackup

import (
	"errors"
	"path/filepath"
	"strings"
)

// Fixed native paths, mirroring scripts/install-control.sh and the
// scripts/native-runtime helpers.
const (
	ConfigDirectory   = "/etc/cdnca-control"
	DataDirectory     = "/var/lib/cdnca-control"
	NativeRoot        = "/data/cdnca-native-root/cdnca"
	UpgradeConfig     = "/etc/cdnca-upgrade"
	UpgradeState      = "/var/lib/cdnca-upgrade"
	AnalyticsConfig   = "/etc/cdnca-analytics"
	ObjectStoreConfig = "/etc/cdnca-objectstore"
	ObjectStoreData   = "/var/lib/cdnca-objectstore"
	NATSStore         = DataDirectory + "/nats"
	// AgentRoot holds bundles, run records, requests and the freeze record. It
	// is outside every archived tree so an in-place restore cannot remove it.
	AgentRoot          = "/var/lib/cdnca-control-backup"
	BackupRoot         = AgentRoot + "/bundles"
	SettingsFile       = ConfigDirectory + "/backup/settings.json"
	SupportDirectory   = "/usr/local/cdnca-control/support"
	BackupKeyDirectory = ConfigDirectory + "/keys/backup"
	ReleaseLock        = "/run/lock/cdnca-management-release.lock"
	ClickHouseData     = "/var/lib/clickhouse"
)

// Layout resolves the fixed absolute paths below Root. Production uses
// Root "/"; tests use a temporary directory so no host path is touched.
type Layout struct {
	Root string
}

func (layout Layout) Path(absolute string) string {
	if layout.Root == "" || layout.Root == "/" {
		return absolute
	}
	return filepath.Join(layout.Root, absolute)
}

func (layout Layout) validate() error {
	if layout.Root != "" && (!filepath.IsAbs(layout.Root) || filepath.Clean(layout.Root) != layout.Root) {
		return errors.New("layout root must be a clean absolute path")
	}
	return nil
}

// configPaths are the secret-bearing paths restored before any service starts.
// Every entry is optional except the control configuration directory; absent
// optional paths are recorded as absent and are not created on restore.
var configPaths = []treePath{
	{Path: ConfigDirectory, Required: true},
	{Path: UpgradeConfig},
	{Path: AnalyticsConfig},
	{Path: ObjectStoreConfig},
	{Path: "/etc/letsencrypt"},
	// cdnca-loopback.xml belongs to install-ubuntu-dependencies.sh on the target.
	{Path: "/etc/clickhouse-server/users.d/cdnca-private-default.xml"},
	// Object storage CA trust anchor: Debian/Ubuntu or RHEL family layout
	// (install-rustfs.py trust_layout); a host has exactly one of them.
	{Path: debianTrustAnchor},
	{Path: rhelTrustAnchor},
	// Standalone Gateway access (--mode control or enable-gateway-access):
	// the Redis TLS listener, password and Gateway ACL include, next to the
	// distribution's Redis configuration (see redisGatewayIncludes).
	{Path: "/etc/redis/cdnca-gateway"},
	{Path: "/etc/cdnca-gateway"},
	{Path: "/etc/valkey/cdnca-gateway"},
}

const (
	debianTrustAnchor = "/usr/local/share/ca-certificates/cdnca-objectstore.crt"
	rhelTrustAnchor   = "/etc/pki/ca-trust/source/anchors/cdnca-objectstore.crt"
)

// trustFamilies are the system CA stores the native installer supports: the
// archived anchor names the source's OS family, and the tool that rebuilds
// the store must exist on the target.
var trustFamilies = []struct {
	Family, Anchor string
	Rebuild        Command
}{
	{"debian", debianTrustAnchor, Command{Path: "/usr/sbin/update-ca-certificates"}},
	{"rhel", rhelTrustAnchor, Command{Path: "/usr/bin/update-ca-trust", Args: []string{"extract"}}},
}

// redisGatewayIncludes pairs each Redis configuration file the dependency
// installer can produce with the include directory install-control.sh puts
// beside it. The target's configuration is not archived (the dependency
// installer owns it), so a restore appends the same include line to it.
var redisGatewayIncludes = []struct{ Config, Directory string }{
	{Config: "/etc/redis/redis.conf", Directory: "/etc/redis/cdnca-gateway"},
	{Config: "/etc/redis.conf", Directory: "/etc/cdnca-gateway"},
	{Config: "/etc/valkey/valkey.conf", Directory: "/etc/valkey/cdnca-gateway"},
}

// RedisUnits are the Redis service names of the supported distributions.
var RedisUnits = []string{"redis-server.service", "redis.service", "valkey.service"}

// runtimePaths are the exact release tree, pinned runtime binaries and
// systemd units, so a new host runs the same signed version without
// downloading it again (the authorization service only serves "latest").
var runtimePaths = []treePath{
	{Path: NativeRoot, Required: true},
	{Path: UpgradeState},
	{Path: "/var/lib/cdnca-native-upgrade-maintenance"},
	{Path: DataDirectory, Required: true, Exclude: []string{"nats"}},
	{Path: "/usr/local/cdnca-control"},
	{Path: "/usr/local/libexec/cdnca"},
	{Path: "/usr/local/lib/cdnca-runtime"},
	{Path: "/usr/local/bin/nats-server"},
	{Path: "/usr/local/bin/nats"},
	{Path: "/etc/systemd/system/cdnca-control-api.service"},
	{Path: "/etc/systemd/system/cdnca-agent-gateway.service"},
	{Path: "/etc/systemd/system/cdnca-control-nats.service"},
	{Path: "/etc/systemd/system/cdnca-control-web.service"},
	{Path: "/etc/systemd/system/cdnca-objectstore.service"},
	{Path: "/etc/systemd/system/cdnca-native-control-upgrade-runner.service"},
	{Path: "/etc/tmpfiles.d/cdnca-native-control-upgrade-runner.conf"},
	{Path: "/etc/systemd/system/cdnca-control-backup.service"},
	{Path: "/etc/systemd/system/cdnca-control-backup.timer"},
	{Path: "/etc/systemd/system/cdnca-control-backup.path"},
	// Standalone Gateway access: env drop-ins loaded after control.env and the
	// nftables allow-list units (install-control.sh setup_gateway_access_firewall).
	{Path: "/etc/systemd/system/cdnca-control-api.service.d/60-gateway-access.conf"},
	{Path: "/etc/systemd/system/cdnca-agent-gateway.service.d/60-gateway-access.conf"},
	{Path: "/etc/systemd/system/cdnca-gateway-access.service"},
	{Path: "/etc/systemd/system/cdnca-gateway-access.path"},
	{Path: "/etc/systemd/system/cdnca-gateway-access-reload.service"},
}

type treePath struct {
	Path     string
	Required bool
	// Exclude lists direct children (relative names) that are not archived.
	Exclude []string
}

func (path treePath) excluded(relative string) bool {
	for _, name := range path.Exclude {
		if relative == name || strings.HasPrefix(relative, name+"/") {
			return true
		}
	}
	return false
}
