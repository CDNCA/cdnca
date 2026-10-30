package nativebackup

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

// HostPortsFile is the host port profile install-control.sh writes on a
// BaoTa host (fix-btenv) before the dependency installer runs. It is a
// property of the host, never archived: a restore keeps the target's own.
const HostPortsFile = "/etc/cdnca-native-dependencies/runtime.env"

// HostPorts are the loopback ports of the local dependencies.
type HostPorts struct {
	Env            string // bt or plain
	Web            int    // BaoTa: loopback port of the management web (0 = not recorded)
	NodeDownload   int    // BaoTa: direct node upgrade download port (0 = not recorded)
	PostgreSQL     int
	Redis          int
	ClickHouseHTTP int
	ClickHouseTCP  int
}

func DefaultHostPorts() HostPorts {
	return HostPorts{Env: "plain", PostgreSQL: 5432, Redis: 6379, ClickHouseHTTP: 8123, ClickHouseTCP: 9000}
}

var (
	hostPortsLine = regexp.MustCompile(`^([A-Z_]+)=([a-z0-9]+)$`)
	hostPortValue = regexp.MustCompile(`^[1-9][0-9]{3,4}$`)
	hostPortKeys  = map[string]bool{"ENV": true, "WEB_PORT": true, "NODE_DOWNLOAD_PORT": true, "PG_PORT": true, "REDIS_PORT": true, "CH_HTTP_PORT": true, "CH_TCP_PORT": true,
		"CH_MYSQL_PORT": true, "CH_POSTGRESQL_PORT": true, "CH_INTERSERVER_PORT": true}
)

// ReadHostPorts parses the profile with the same strict rules as the
// dependency installer; an absent profile means the default ports.
func ReadHostPorts(layout Layout) (HostPorts, error) {
	ports := DefaultHostPorts()
	content, err := os.ReadFile(layout.Path(HostPortsFile))
	if errors.Is(err, os.ErrNotExist) {
		return ports, nil
	}
	if err != nil {
		return HostPorts{}, err
	}
	seen := map[string]bool{}
	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		match := hostPortsLine.FindStringSubmatch(scanner.Text())
		if match == nil || !hostPortKeys[match[1]] || seen[match[1]] {
			return HostPorts{}, errors.New("invalid host port profile")
		}
		seen[match[1]] = true
		if match[1] == "ENV" {
			if match[2] != "bt" && match[2] != "plain" {
				return HostPorts{}, errors.New("invalid host port profile")
			}
			ports.Env = match[2]
			continue
		}
		value, err := strconv.Atoi(match[2])
		if !hostPortValue.MatchString(match[2]) || err != nil || value > 65535 {
			return HostPorts{}, errors.New("invalid host port profile")
		}
		switch match[1] {
		case "WEB_PORT":
			ports.Web = value
		case "NODE_DOWNLOAD_PORT":
			ports.NodeDownload = value
		case "PG_PORT":
			ports.PostgreSQL = value
		case "REDIS_PORT":
			ports.Redis = value
		case "CH_HTTP_PORT":
			ports.ClickHouseHTTP = value
		case "CH_TCP_PORT":
			ports.ClickHouseTCP = value
		}
	}
	return ports, scanner.Err()
}

// WithHostPorts points the PostgreSQL client programs at the profile port
// (peer authentication over the socket .s.PGSQL.<port>).
func (target DatabaseTarget) WithHostPorts(layout Layout) DatabaseTarget {
	ports, err := ReadHostPorts(layout)
	if err == nil && ports.PostgreSQL != DefaultHostPorts().PostgreSQL {
		target.Env = append(append([]string(nil), target.Env...), "PGPORT="+strconv.Itoa(ports.PostgreSQL))
	}
	return target
}

// retargetFiles are the restored environment files that name a local
// dependency by loopback URL.
var retargetFiles = []string{
	ConfigDirectory + "/control.env",
	ConfigDirectory + "/gateway.env",
	ConfigDirectory + "/gateway-access.env",
	ConfigDirectory + "/gateway-access-local.env",
	AnalyticsConfig + "/runtime.env",
}

var (
	retargetPostgreSQL = regexp.MustCompile(`^((?:[A-Z_]*DATABASE_URL)=postgres(?:ql)?://[^@\s]+@127\.0\.0\.1:)[0-9]+(/)`)
	retargetRedis      = regexp.MustCompile(`^((?:[A-Z_]*REDIS_URL)=redis://(?:[^@\s]*@)?127\.0\.0\.1:)[0-9]+(/)`)
	retargetClickHouse = regexp.MustCompile(`^((?:[A-Z_]*CLICKHOUSE_URL)=http://127\.0\.0\.1:)[0-9]+($)`)
)

// RetargetPorts rewrites, in the restored configuration, the loopback ports
// of PostgreSQL, Redis and ClickHouse to this host's profile, so a control
// plane moved between a plain and a BaoTa host reaches its own dependencies.
// External services and every other value are left byte-for-byte unchanged.
func RetargetPorts(_ context.Context, layout Layout, progress func(string, ...any)) error {
	ports, err := ReadHostPorts(layout)
	if err != nil {
		return err
	}
	replacements := []struct {
		pattern *regexp.Regexp
		port    int
	}{{retargetPostgreSQL, ports.PostgreSQL}, {retargetRedis, ports.Redis}, {retargetClickHouse, ports.ClickHouseHTTP}}
	if err := retargetWebListener(layout, ports, progress); err != nil {
		return err
	}
	if err := writeBaoTaProxyConfig(layout, ports, progress); err != nil {
		return err
	}
	if err := retargetNodeDownload(layout, ports, progress); err != nil {
		return err
	}
	for _, name := range retargetFiles {
		path := layout.Path(name)
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%s is not a regular file", name)
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		lines := strings.Split(string(content), "\n")
		changed := false
		for index, line := range lines {
			for _, replacement := range replacements {
				updated := replacement.pattern.ReplaceAllString(line, "${1}"+strconv.Itoa(replacement.port)+"${2}")
				if updated != line {
					lines[index], line, changed = updated, updated, true
				}
			}
		}
		if !changed {
			continue
		}
		if err := writeFileAtomic(path, []byte(strings.Join(lines, "\n")), info.Mode().Perm()); err != nil {
			return err
		}
		// Keep the restored owner (control.env is root:cdnca-control-api, etc.).
		if stat, ok := info.Sys().(*syscall.Stat_t); ok {
			if err := os.Lchown(path, int(stat.Uid), int(stat.Gid)); err != nil {
				return err
			}
		}
		progress("ports: %s follows this host's dependency ports", name)
	}
	return nil
}

var (
	webListen     = regexp.MustCompile(`(?m)^(        listen )(?:127\.0\.0\.1:)?[0-9]+( ssl http2;)\n(        server_name _;\n)(?:        set_real_ip_from 127\.0\.0\.1;\n        real_ip_header X-Real-IP;\n)?`)
	controlOrigin = regexp.MustCompile(`^https://(?:\[[^\]]+\]|[^:/]+)(?::([0-9]+))?/?$`)
)

// retargetWebListener moves the management web between a public listener
// (plain host: the control origin's port) and the BaoTa loopback listener
// behind the BaoTa site, so a migrated web never binds BaoTa's own 443.
func retargetWebListener(layout Layout, ports HostPorts, progress func(string, ...any)) error {
	path := layout.Path(ConfigDirectory + "/nginx.conf")
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("nginx.conf is not a regular file")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var listen, realIP string
	if ports.Env == "bt" && ports.Web != 0 {
		listen = "127.0.0.1:" + strconv.Itoa(ports.Web)
		realIP = "        set_real_ip_from 127.0.0.1;\n        real_ip_header X-Real-IP;\n"
	} else {
		environment, err := ReadEnvironmentFile(layout.Path(ConfigDirectory + "/control.env"))
		if err != nil {
			return err
		}
		match := controlOrigin.FindStringSubmatch(environment["PAYMENT_CHANNELS_NOTIFY_BASE"])
		if match == nil {
			return errors.New("cannot read the control origin from control.env")
		}
		listen = "443"
		if match[1] != "" {
			listen = match[1]
		}
	}
	if len(webListen.FindAllIndex(content, -1)) != 1 {
		return errors.New("nginx.conf has no single management web listener")
	}
	updated := webListen.ReplaceAll(content, []byte("${1}"+listen+"${2}\n${3}"+realIP))
	if bytes.Equal(updated, content) {
		return nil
	}
	if err := writeFileAtomic(path, updated, info.Mode().Perm()); err != nil {
		return err
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		if err := os.Lchown(path, int(stat.Uid), int(stat.Gid)); err != nil {
			return err
		}
	}
	progress("ports: the management web listens on %s on this host", listen)
	return nil
}
