package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/nativebackup"
)

const controlHostUsage = `usage: control-api control-host <command>
  bind --domain DOMAIN [--cert-file FILE --key-file FILE] [--gateway-host-too=true|false] [--email EMAIL] [--skip-dns-check]
        bind a domain to this control plane (root; idempotent; rolls back on failure)
        绑定域名到本主控（需 root；可重复执行；任一步失败自动回滚）
  status
        current console address, certificates (expiry, SAN) and Gateway endpoint
        显示当前管理端地址、证书到期与 SAN、网关地址`

// runControlHost: `control-api control-host bind|status`.
func runControlHost(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New(controlHostUsage)
	}
	layout := nativebackup.Layout{Root: "/"}
	switch args[0] {
	case "status":
		if len(args) != 1 {
			return errors.New(controlHostUsage)
		}
		status, err := nativebackup.ReadHostStatus(layout)
		if err != nil {
			return err
		}
		printHostStatus(stdout, status)
		return nil
	case "bind":
		flags := flag.NewFlagSet("control-host bind", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		domain := flags.String("domain", "", "")
		certFile := flags.String("cert-file", "", "")
		keyFile := flags.String("key-file", "", "")
		gatewayHost := flags.Bool("gateway-host-too", true, "")
		email := flags.String("email", "", "")
		skipDNS := flags.Bool("skip-dns-check", false, "")
		if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 || *domain == "" {
			return errors.New(controlHostUsage)
		}
		if os.Geteuid() != 0 {
			return errors.New("run as root / 需要 root 运行")
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		result, err := nativebackup.Bind(ctx, hostBindEnvironment(layout, stderr), nativebackup.HostBindRequest{
			Domain: *domain, CertFile: *certFile, KeyFile: *keyFile, GatewayHost: *gatewayHost, Email: *email, SkipDNSCheck: *skipDNS})
		if err != nil {
			return err
		}
		printBindResult(stdout, result, *gatewayHost)
		return nil
	default:
		return errors.New(controlHostUsage)
	}
}

func hostBindEnvironment(layout nativebackup.Layout, stderr io.Writer) nativebackup.HostBindEnvironment {
	nginx := "/usr/sbin/nginx"
	if path, err := exec.LookPath("nginx"); err == nil {
		nginx = path
	}
	runtimeDir := nativebackup.DataDirectory + "/nginx-runtime"
	command := func(ctx context.Context, name string, arguments ...string) error {
		var output bytes.Buffer
		process := exec.CommandContext(ctx, name, arguments...)
		process.Stdout, process.Stderr = &output, &output
		if err := process.Run(); err != nil {
			detail := strings.TrimSpace(output.String())
			if len(detail) > 2000 {
				detail = detail[len(detail)-2000:]
			}
			return fmt.Errorf("%s: %w: %s", name, err, nativebackup.Redact(detail))
		}
		return nil
	}
	return nativebackup.HostBindEnvironment{
		Layout:         layout,
		LocalAddresses: nativebackup.LocalInterfaceAddresses,
		PortFree:       nativebackup.TCPPortFree,
		IssueCertificate: func(ctx context.Context, domain, email string) (string, error) {
			if _, err := exec.LookPath("certbot"); err != nil {
				return "", errors.New("certbot is not installed (apt-get install -y certbot / dnf -y install certbot), or pass --cert-file/--key-file")
			}
			arguments := []string{"certonly", "--standalone", "--non-interactive", "--agree-tos", "--cert-name", domain, "-d", domain}
			if email != "" {
				arguments = append(arguments, "--email", email)
			} else {
				arguments = append(arguments, "--register-unsafely-without-email")
			}
			if os.Getenv("CDNCA_HOST_BIND_ACME_STAGING") == "1" {
				arguments = append(arguments, "--test-cert")
			}
			if err := command(ctx, "certbot", arguments...); err != nil {
				return "", fmt.Errorf("Let's Encrypt request failed; check that %s resolves here and TCP 80 is reachable from the Internet: %w", domain, err)
			}
			return "/etc/letsencrypt/live/" + domain, nil
		},
		NginxTest: func(ctx context.Context, file string) error {
			return command(ctx, nginx, "-t", "-q", "-c", file, "-p", runtimeDir)
		},
		Service: func(ctx context.Context, verb, unit string) error {
			return command(ctx, "systemctl", verb, "--", unit)
		},
		Ready: hostBindReady,
		PublishTrust: func(ctx context.Context, layout nativebackup.Layout) (nativebackup.NodeInstallTrust, error) {
			return nativebackup.PublishNodeInstallTrust(ctx, layout, nil)
		},
		Progress: func(zh, en string) { fmt.Fprintf(stderr, "[control-host] %s / %s\n", zh, en) },
	}
}

// hostBindReady waits for control-api and the Gateway.
func hostBindReady(ctx context.Context) error {
	client := &http.Client{Timeout: 5 * time.Second}
	deadline := time.Now().Add(90 * time.Second)
	for _, url := range []string{"http://127.0.0.1:8080/health/ready", "http://127.0.0.1:8082/health/ready"} {
		for {
			request, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			response, err := client.Do(request)
			if err == nil {
				_ = response.Body.Close()
				if response.StatusCode == http.StatusOK {
					break
				}
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("%s did not answer 200", url)
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(2 * time.Second):
			}
		}
	}
	return nil
}

func printBindResult(stdout io.Writer, result nativebackup.HostBindResult, gatewayHost bool) {
	if !result.Changed {
		fmt.Fprintf(stdout, "已绑定 %s，无需改动 / %s is already bound; nothing changed\n", result.Domain, result.Domain)
	} else {
		fmt.Fprintf(stdout, "已绑定域名 %s / bound %s\n", result.Domain, result.Domain)
		fmt.Fprintf(stdout, "  备份 / backup: %s\n", result.BackupDir)
	}
	fmt.Fprintf(stdout, "  管理端地址 / console: %s/dashboard/\n", result.Origin)
	trusted := "否（浏览器会提示不安全）/ no (browsers will warn)"
	if result.PublicTrusted {
		trusted = "是 / yes"
	}
	fmt.Fprintf(stdout, "  证书受信 / publicly trusted: %s，到期 / expires %s\n", trusted, result.CertificateNA.UTC().Format("2006-01-02"))
	fmt.Fprintf(stdout, "  网关证书 SAN / Gateway SAN: %s\n", strings.Join(result.GatewaySAN, ","))
	if gatewayHost {
		fmt.Fprintln(stdout, "  新复制的节点命令使用域名连网关；已装节点继续按原 IP 连接 / new node installs dial the domain; installed nodes keep their address")
	}
	fmt.Fprintln(stdout, "  原 IP 访问与节点升级下载保持不变 / access by IP and node upgrade downloads are unchanged")
	if result.TrustSHA256 != "" {
		fmt.Fprintf(stdout, "  节点安装信任 / node install trust: %s\n", result.TrustSHA256)
	}
	fmt.Fprintln(stdout, "  请用域名重新打开管理端，再复制节点安装命令 / reopen the console at the domain before copying node install commands")
}

func printHostStatus(stdout io.Writer, status nativebackup.HostStatus) {
	fmt.Fprintf(stdout, "管理端地址 / console origin: %s\n", status.Origin)
	if status.BoundDomain != "" {
		fmt.Fprintf(stdout, "已绑定域名 / bound domain: %s\n", status.BoundDomain)
	} else {
		fmt.Fprintln(stdout, "已绑定域名 / bound domain: （无 / none）")
	}
	fmt.Fprintf(stdout, "网关地址（新节点）/ Gateway (new nodes): %s\n", status.GatewayLocal)
	fmt.Fprintf(stdout, "节点升级下载 / node upgrade downloads: %s\n", status.DownloadBase)
	show := func(label string, certificate *nativebackup.HostCertificate) {
		if certificate == nil {
			fmt.Fprintf(stdout, "%s: （无法读取 / unreadable）\n", label)
			return
		}
		trusted := "私有/自签 private"
		if certificate.Trusted {
			trusted = "公网受信 public"
		}
		fmt.Fprintf(stdout, "%s: %s，签发者 issuer %s，%s，到期 expires %s，SAN %s\n", label, certificate.File, certificate.Issuer, trusted,
			certificate.NotAfter.UTC().Format("2006-01-02"), strings.Join(certificate.SAN, ","))
	}
	if status.BoundDomain != "" {
		show("域名证书 / domain certificate", status.Public)
	}
	show("默认证书（IP 访问）/ default certificate", status.Default)
	show("网关证书 / Gateway certificate", status.Gateway)
	pin := status.ControlCAPin
	if pin == "" {
		pin = "（空：复制命令走系统信任 / empty: system trust）"
	}
	fmt.Fprintf(stdout, "复制命令根证书指纹 / copied command CA pin: %s\n", pin)
}
