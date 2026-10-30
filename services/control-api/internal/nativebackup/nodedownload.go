package nativebackup

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

// PKIDirectory and DownloadDirectory mirror install-control.sh PKI_DIR and DOWNLOAD_DIR.
const (
	PKIDirectory      = ConfigDirectory + "/keys/pki"
	DownloadDirectory = DataDirectory + "/downloads"
)

// NodeDownloadServer renders install-control.sh node_download_server byte for
// byte (testdata/node-download-server.conf pins both): on a BaoTa host the
// nodes download upgrade artifacts from this direct listener.
func NodeDownloadServer(port int) string {
	return fmt.Sprintf(`
    # 宝塔环境节点升级下载直连端口（fix-btenv2）：证书由本机私有根 CA 签发，节点已信任。
    server {
        listen %d ssl;
        server_name _;
        ssl_certificate %[2]s/public-server.pem;
        ssl_certificate_key %[2]s/public-server-key.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        add_header X-Content-Type-Options "nosniff" always;
        location ^~ /downloads/edge-agent/upgrades/sha256/ {
            alias %[3]s/edge-agent/upgrades/sha256/;
            limit_except GET { deny all; }
            default_type application/octet-stream;
        }
        location / { return 404; }
    }
`, port, PKIDirectory, DownloadDirectory)
}

var (
	nodeDownloadBlock = regexp.MustCompile(`\n    # 宝塔环境节点升级下载直连端口[^\n]*\n    server \{\n        listen [0-9]+ ssl;\n(?:        [^\n]*\n|            [^\n]*\n)*?    \}\n`)
	artifactBaseURL   = regexp.MustCompile(`^(CONTROL_UPGRADE_ARTIFACT_BASE_URL=https://(?:\[[^\]]+\]|[^:/\s]+))(?::[0-9]+)?(/downloads/edge-agent/upgrades/sha256)$`)
	downloadRootLine  = regexp.MustCompile(`^CONTROL_UPGRADE_DOWNLOAD_ROOT_CA_FILE=`)
)

// retargetNodeDownload moves the node upgrade download endpoint with the
// layout (fix-btenv3): a BaoTa host serves it on the profile's direct port
// with the private root, a plain host on the management HTTPS port. The
// artifact base URL and root in control.env feed the download policy signed
// into each upgrade execution, so nodes follow without being reinstalled.
func retargetNodeDownload(layout Layout, ports HostPorts, progress func(string, ...any)) error {
	bt := ports.Env == "bt" && ports.NodeDownload != 0
	controlPath := layout.Path(ConfigDirectory + "/control.env")
	environment, err := ReadEnvironmentFile(controlPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	// Without an upgrade runtime (no artifact base URL) only nginx.conf moves.
	port := ""
	if bt {
		port = ":" + strconv.Itoa(ports.NodeDownload)
	} else if environment["CONTROL_UPGRADE_ARTIFACT_BASE_URL"] != "" {
		match := controlOrigin.FindStringSubmatch(environment["PAYMENT_CHANNELS_NOTIFY_BASE"])
		if match == nil {
			return errors.New("cannot read the control origin from control.env")
		}
		if match[1] != "" && match[1] != "443" {
			port = ":" + match[1]
		}
	}
	err = rewriteRegularFile(controlPath, func(content []byte) []byte {
		lines := strings.Split(string(content), "\n")
		kept := lines[:0]
		for _, line := range lines {
			if bt && downloadRootLine.MatchString(line) {
				continue
			}
			if match := artifactBaseURL.FindStringSubmatch(line); match != nil {
				line = match[1] + port + match[2]
				if bt {
					kept = append(kept, line, "CONTROL_UPGRADE_DOWNLOAD_ROOT_CA_FILE="+PKIDirectory+"/root-ca-cert.pem")
					continue
				}
			}
			kept = append(kept, line)
		}
		return []byte(strings.Join(kept, "\n"))
	})
	if err != nil {
		return err
	}
	nginxPath := layout.Path(ConfigDirectory + "/nginx.conf")
	if _, err := os.Lstat(nginxPath); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	err = rewriteRegularFile(nginxPath, func(content []byte) []byte {
		// Plain layout: install-control.sh writes an empty line in its place.
		content = nodeDownloadBlock.ReplaceAll(content, []byte("\n"))
		if !bt {
			return content
		}
		// The block sits last inside http { ... } (write_nginx_config).
		end := bytes.LastIndex(content, []byte("\n}\n"))
		if end < 0 {
			return content
		}
		return append(append(append([]byte(nil), content[:end]...), []byte(NodeDownloadServer(ports.NodeDownload))...),
			content[end+1:]...)
	})
	if err != nil {
		return err
	}
	if bt {
		progress("ports: node upgrade downloads use the direct port %d on this host", ports.NodeDownload)
	} else {
		progress("ports: node upgrade downloads use the management HTTPS port on this host")
	}
	return nil
}

// rewriteRegularFile applies change and writes the file back atomically
// with its mode and owner when the content changed.
func rewriteRegularFile(path string, change func([]byte) []byte) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	updated := change(append([]byte(nil), content...))
	if bytes.Equal(updated, content) {
		return nil
	}
	if err := writeFileAtomic(path, updated, info.Mode().Perm()); err != nil {
		return err
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return os.Lchown(path, int(stat.Uid), int(stat.Gid))
	}
	return nil
}
