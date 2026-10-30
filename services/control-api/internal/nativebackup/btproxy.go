package nativebackup

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"strings"
)

// BaoTaProxyFile is the BaoTa site reverse proxy that install-control.sh
// bt_report saves on a BaoTa host; a migration onto a BaoTa host writes the
// same file (fix-btenv2) so the operator copies it into the BaoTa site.
const BaoTaProxyFile = ConfigDirectory + "/bt-proxy.conf"

// BaoTaProxyConfig renders install-control.sh bt_proxy_config byte for byte
// (testdata/bt-proxy.conf pins both) for the control origin's domain.
func BaoTaProxyConfig(controlOrigin string, webPort int) (string, error) {
	parsed, err := url.Parse(controlOrigin)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || webPort < 1 || webPort > 65535 {
		return "", errors.New("cannot read the control origin for the BaoTa proxy")
	}
	domain := strings.ToLower(parsed.Hostname())
	if _, err := netip.ParseAddr(domain); err == nil {
		return "", errors.New("a BaoTa site needs a domain, the control origin is an IP address")
	}
	return fmt.Sprintf(`  # CDNCA 管理端（install-control.sh 生成）：宝塔站点 %[1]s 反向代理到本机管理端网页
  location ^~ / {
    proxy_pass https://127.0.0.1:%[2]d;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $http_connection;
    proxy_ssl_server_name on;
    proxy_ssl_name %[1]s;
    proxy_read_timeout 300s;
    client_max_body_size 0;
  }
`, domain, webPort), nil
}

// writeBaoTaProxyConfig writes bt-proxy.conf on a BaoTa host and removes a
// copy restored from a BaoTa source onto a plain host.
func writeBaoTaProxyConfig(layout Layout, ports HostPorts, progress func(string, ...any)) error {
	path := layout.Path(BaoTaProxyFile)
	if ports.Env != "bt" || ports.Web == 0 {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	environment, err := ReadEnvironmentFile(layout.Path(ConfigDirectory + "/control.env"))
	if err != nil {
		return err
	}
	config, err := BaoTaProxyConfig(environment["PAYMENT_CHANNELS_NOTIFY_BASE"], ports.Web)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(path, []byte(config), 0o644); err != nil {
		return err
	}
	progress("ports: BaoTa reverse proxy saved to %s (copy it into the BaoTa site)", BaoTaProxyFile)
	return nil
}
