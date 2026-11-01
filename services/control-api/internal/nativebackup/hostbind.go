package nativebackup

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/gatewayregistry"
)

// Bind a domain to an installed control plane (ctl-bind-domain): a console
// installed by IP starts answering https://<domain> with a public certificate
// without reinstalling, and copied node install commands use the domain.
//
// What deliberately stays on the old address, because installed nodes pin it:
//   - CONTROL_UPGRADE_ARTIFACT_BASE_URL and the upgrade trust download policy:
//     edge-agent PolicyDownloader.Adopt only accepts the host it was installed
//     with, so a domain there would stop every IP-installed node upgrading.
//   - the default nginx server (server_name _, private certificate): nodes
//     download upgrades by IP without SNI and verify the private root.
//     The domain gets its own server block (same locations, public
//     certificate), selected by SNI.
//   - the Gateway keeps its IP SAN (re-signed with the domain added, same key)
//     and nodes keep dialing the address they were installed with.
//
// What moves to the domain: PAYMENT_CHANNELS_NOTIFY_BASE (the control origin
// install-control.sh reads back), optionally CDNCA_GATEWAY_LOCAL_* (the
// GatewayHello endpoint list nodes learn as a fallback) with
// node-install-defaults and runtime-config.js (new installs dial the
// domain), and __CDNCA_CONTROL_CA_SHA256__ (empty for a public certificate:
// the copied command then needs no private CA pin).

const (
	HostBindBlockBegin   = "    # cdnca-host-bind begin (control-api control-host bind)"
	HostBindBlockEnd     = "    # cdnca-host-bind end"
	HostBindCertFile     = PKIDirectory + "/bind-public-cert.pem"
	HostBindKeyFile      = PKIDirectory + "/bind-public-key.pem"
	HostBindRenewalHook  = "/etc/letsencrypt/renewal-hooks/deploy/cdnca-control-web-bind.sh"
	hostBindNginxFile    = ConfigDirectory + "/nginx.conf"
	hostBindControlEnv   = ConfigDirectory + "/control.env"
	hostBindGatewayCert  = PKIDirectory + "/gateway-server.pem"
	hostBindGatewayKey   = PKIDirectory + "/gateway-server-key.pem"
	hostBindRootCert     = PKIDirectory + "/root-ca-cert.pem"
	hostBindRootKey      = PKIDirectory + "/root-ca-key.pem"
	hostBindGatewayCA    = DownloadDirectory + "/gateway-ca.pem"
	hostBindBackupPrefix = DataDirectory + "/host-bind-backup-"
	hostBindWebUnit      = "cdnca-control-web.service"
	hostBindGatewayUnit  = "cdnca-agent-gateway.service"
	hostBindControlUnit  = "cdnca-control-api.service"
)

var (
	hostBindDomain    = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	hostBindServer    = regexp.MustCompile(`(?s)\n    server \{\n        listen [^\n]* ssl(?: http2)?;\n        server_name _;\n.*?\n    \}\n`)
	hostBindBlock     = regexp.MustCompile(`(?s)\n` + regexp.QuoteMeta(HostBindBlockBegin) + `\n.*?` + regexp.QuoteMeta(HostBindBlockEnd) + `\n`)
	hostBindCertLines = regexp.MustCompile(`(?m)^        ssl_certificate(?:_key)? [^\n]*;\n`)
	runtimeCALine     = regexp.MustCompile(`(?m)^window\.__CDNCA_CONTROL_CA_SHA256__ = "(?:[0-9a-f]{64})?";$`)
	runtimeGateway    = regexp.MustCompile(`(?m)^window\.__CDNCA_GATEWAY_(ADDRESS|ENROLLMENT_ADDRESS|SERVER_NAME)__ = "[^"\n]*";$`)
)

// HostBindRequest is one `control-api control-host bind` run.
type HostBindRequest struct {
	Domain string
	// CertFile/KeyFile: an operator certificate (chain + key). Empty: the
	// certificate is requested with certbot (HTTP-01, standalone).
	CertFile, KeyFile string
	// GatewayHost also points new node installs and the published Gateway
	// endpoint list at the domain (default on).
	GatewayHost bool
	// Email for the Let's Encrypt account (certbot --email; empty: none).
	Email string
	// SkipDNSCheck accepts a domain that does not (yet) resolve to this
	// host; only allowed together with a certificate file.
	SkipDNSCheck bool
}

// HostBindEnvironment is the host the bind runs on; tests replace every hook.
type HostBindEnvironment struct {
	Layout Layout
	// Lookup resolves the domain (net.DefaultResolver when nil).
	Lookup func(context.Context, string) ([]string, error)
	// LocalAddresses are this host's interface addresses (net.InterfaceAddrs when nil).
	LocalAddresses func() ([]netip.Addr, error)
	// PortFree reports whether a TCP port is free on all addresses.
	PortFree func(int) bool
	// IssueCertificate runs certbot for domain and returns the lineage directory.
	IssueCertificate func(ctx context.Context, domain, email string) (string, error)
	// NginxTest checks a staged configuration (nginx -t -c file).
	NginxTest func(ctx context.Context, file string) error
	// Service runs `systemctl <verb> <unit>` (reload, restart, is-active).
	Service func(ctx context.Context, verb, unit string) error
	// Ready waits until the web, Gateway and API answer again.
	Ready func(ctx context.Context) error
	// PublishTrust republishes the node install trust (PublishNodeInstallTrust).
	PublishTrust func(ctx context.Context, layout Layout) (NodeInstallTrust, error)
	Now          func() time.Time
	Progress     func(zh, en string)
}

// HostBindResult reports what the bind changed.
type HostBindResult struct {
	Domain        string
	Origin        string
	Changed       bool
	BackupDir     string
	CertificateNA time.Time
	PublicTrusted bool
	GatewaySAN    []string
	TrustSHA256   string
}

func (environment HostBindEnvironment) progress(zh, en string) {
	if environment.Progress != nil {
		environment.Progress(zh, en)
	}
}

func (environment HostBindEnvironment) now() time.Time {
	if environment.Now != nil {
		return environment.Now()
	}
	return time.Now()
}

// NormalizeBindDomain lowercases and checks a DNS name (no IP literal, no wildcard).
func NormalizeBindDomain(value string) (string, error) {
	domain := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	if len(domain) > 253 || !hostBindDomain.MatchString(domain) {
		return "", errors.New("--domain must be a DNS name (not an IP address or wildcard)")
	}
	return domain, nil
}

// bindState is what the bind reads from the installation before changing it.
type bindState struct {
	environment map[string]string
	origin      string // https://host[:port]
	host        string // current control host (IP or name)
	port        string // "" for 443
	nginx       []byte
}

func readBindState(layout Layout) (bindState, error) {
	environment, err := ReadEnvironmentFile(layout.Path(hostBindControlEnv))
	if err != nil {
		return bindState{}, fmt.Errorf("read control.env: %w", err)
	}
	origin := environment["PAYMENT_CHANNELS_NOTIFY_BASE"]
	match := controlOrigin.FindStringSubmatch(origin)
	if match == nil {
		return bindState{}, errors.New("cannot read the control origin (PAYMENT_CHANNELS_NOTIFY_BASE) from control.env")
	}
	host := strings.TrimPrefix(strings.TrimSuffix(origin, "/"), "https://")
	if match[1] != "" {
		host = strings.TrimSuffix(host, ":"+match[1])
	}
	host = strings.Trim(host, "[]")
	port := match[1]
	if port == "443" {
		port = ""
	}
	nginx, err := os.ReadFile(layout.Path(hostBindNginxFile))
	if err != nil {
		return bindState{}, fmt.Errorf("read nginx.conf: %w", err)
	}
	return bindState{environment: environment, origin: strings.TrimSuffix(origin, "/"), host: host, port: port, nginx: nginx}, nil
}

// bindOrigin is https://domain[:port] for the management web port.
func bindOrigin(domain, port string) string {
	if port == "" {
		return "https://" + domain
	}
	return "https://" + domain + ":" + port
}

// checkResolution requires every public address of domain to belong to this
// host and at least one to be present (A/AAAA preflight).
func checkResolution(ctx context.Context, environment HostBindEnvironment, domain string, current ...string) ([]string, error) {
	lookup := environment.Lookup
	if lookup == nil {
		lookup = net.DefaultResolver.LookupHost
	}
	lookupContext, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	resolved, err := lookup(lookupContext, domain)
	if err != nil || len(resolved) == 0 {
		return nil, fmt.Errorf("%s does not resolve (A/AAAA); add a DNS record pointing at this host first", domain)
	}
	local := map[netip.Addr]bool{}
	for _, value := range current {
		if address, err := netip.ParseAddr(value); err == nil {
			local[address.Unmap()] = true
		}
	}
	if environment.LocalAddresses != nil {
		addresses, err := environment.LocalAddresses()
		if err != nil {
			return nil, err
		}
		for _, address := range addresses {
			local[address.Unmap()] = true
		}
	}
	var addresses []string
	for _, raw := range resolved {
		address, err := netip.ParseAddr(raw)
		if err != nil {
			continue
		}
		address = address.Unmap()
		if !local[address] {
			return nil, fmt.Errorf("%s resolves to %s, which is not this host (known addresses %s); fix the DNS record (CDN proxying must be off while binding)", domain, address, strings.Join(current, ","))
		}
		addresses = append(addresses, address.String())
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("%s does not resolve to an IP address", domain)
	}
	slices.Sort(addresses)
	return slices.Compact(addresses), nil
}

// LocalInterfaceAddresses lists this host's interface addresses.
func LocalInterfaceAddresses() ([]netip.Addr, error) {
	raw, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	var addresses []netip.Addr
	for _, item := range raw {
		if prefix, err := netip.ParsePrefix(item.String()); err == nil {
			addresses = append(addresses, prefix.Addr())
		}
	}
	return addresses, nil
}

// TCPPortFree reports whether nothing listens on port (any address).
func TCPPortFree(port int) bool {
	listener, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		return false
	}
	_ = listener.Close()
	return true
}

// VerifyServingCertificate checks an operator chain and key: the key matches
// the leaf, the leaf names domain, it is valid now and (when it chains to the
// system roots) reports whether browsers trust it.
func VerifyServingCertificate(chainPEM, keyPEM []byte, domain string, now time.Time) (*x509.Certificate, bool, error) {
	pair, err := tls.X509KeyPair(chainPEM, keyPEM)
	if err != nil {
		return nil, false, errors.New("certificate and private key do not form a pair (or are not PEM)")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, false, errors.New("cannot parse the certificate")
	}
	if err := leaf.VerifyHostname(domain); err != nil {
		return nil, false, fmt.Errorf("the certificate does not name %s (SAN %s)", domain, strings.Join(leaf.DNSNames, ","))
	}
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return nil, false, fmt.Errorf("the certificate is not valid now (%s - %s)", leaf.NotBefore.UTC().Format(time.RFC3339), leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	intermediates := x509.NewCertPool()
	for _, der := range pair.Certificate[1:] {
		if certificate, err := x509.ParseCertificate(der); err == nil {
			intermediates.AddCert(certificate)
		}
	}
	_, verifyErr := leaf.Verify(x509.VerifyOptions{DNSName: domain, Intermediates: intermediates, CurrentTime: now})
	return leaf, verifyErr == nil, nil
}

// MergeGatewaySAN re-signs the Gateway server certificate with the same key
// and root CA, keeping every existing SAN and adding domain. It returns the
// new PEM (nil when domain is already covered) and the resulting SAN list.
func MergeGatewaySAN(certPEM, keyPEM, caCertPEM, caKeyPEM []byte, domain string, now time.Time) ([]byte, []string, error) {
	current, err := parseCertificatePEM(certPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("gateway certificate: %w", err)
	}
	names := sanList(current)
	if slices.Contains(current.DNSNames, domain) {
		return nil, names, nil
	}
	key, err := parsePrivateKeyPEM(keyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("gateway key: %w", err)
	}
	ca, err := parseCertificatePEM(caCertPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("root CA: %w", err)
	}
	caKey, err := parsePrivateKeyPEM(caKeyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("root CA key: %w", err)
	}
	if err := current.CheckSignatureFrom(ca); err != nil {
		return nil, nil, errors.New("the gateway certificate is not issued by the installation root CA")
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: current.Subject.CommonName},
		NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(825 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, DNSNames: append(append([]string(nil), current.DNSNames...), domain),
		IPAddresses: current.IPAddresses, URIs: current.URIs,
	}
	if ca.NotAfter.Before(template.NotAfter) {
		template.NotAfter = ca.NotAfter
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, key.Public(), caKey)
	if err != nil {
		return nil, nil, err
	}
	issued, _ := x509.ParseCertificate(der)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), sanList(issued), nil
}

func sanList(certificate *x509.Certificate) []string {
	var names []string
	for _, name := range certificate.DNSNames {
		names = append(names, "DNS:"+name)
	}
	for _, address := range certificate.IPAddresses {
		names = append(names, "IP:"+address.String())
	}
	return names
}

func parseCertificatePEM(encoded []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(encoded)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("not a PEM certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

func parsePrivateKeyPEM(encoded []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(encoded)
	if block == nil {
		return nil, errors.New("not a PEM private key")
	}
	var parsed any
	var err error
	switch block.Type {
	case "RSA PRIVATE KEY":
		parsed, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		parsed, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	}
	if err != nil {
		return nil, err
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, errors.New("unsupported private key")
	}
	return signer, nil
}

// StripHostBindBlock removes the domain server block (converge and status
// operate on the installer's single server).
func StripHostBindBlock(content []byte) []byte {
	return hostBindBlock.ReplaceAll(content, []byte("\n"))
}

// RenderHostBindNginx returns nginx.conf with a domain server block: a copy of
// the installer's default server with server_name <domain> and the bind
// certificate, placed right after it. The default server is not changed.
func RenderHostBindNginx(content []byte, domain, certFile, keyFile string) ([]byte, error) {
	content = StripHostBindBlock(content)
	matches := hostBindServer.FindAllIndex(content, -1)
	if len(matches) != 1 {
		return nil, errors.New("nginx.conf does not have exactly one installer management server (server_name _); bind refused")
	}
	start, end := matches[0][0], matches[0][1]
	server := string(content[start+1 : end])
	if len(hostBindCertLines.FindAllStringIndex(server, -1)) != 2 {
		return nil, errors.New("the management server does not have exactly one ssl_certificate pair; bind refused")
	}
	server = strings.Replace(server, "        server_name _;\n", "        server_name "+domain+";\n", 1)
	replaced := 0
	server = hostBindCertLines.ReplaceAllStringFunc(server, func(line string) string {
		replaced++
		if strings.HasPrefix(line, "        ssl_certificate_key ") {
			return "        ssl_certificate_key " + keyFile + ";\n"
		}
		return "        ssl_certificate " + certFile + ";\n"
	})
	block := HostBindBlockBegin + "\n" + server + HostBindBlockEnd + "\n"
	var output bytes.Buffer
	output.Write(content[:end])
	output.WriteString(block)
	output.Write(content[end:])
	return output.Bytes(), nil
}

// HostBindDomainFromNginx returns the bound domain recorded in nginx.conf ("" when none).
func HostBindDomainFromNginx(content []byte) string {
	block := hostBindBlock.Find(content)
	if block == nil {
		return ""
	}
	match := regexp.MustCompile(`(?m)^        server_name ([^ ;]+);$`).FindSubmatch(block)
	if match == nil {
		return ""
	}
	return string(match[1])
}

// renewalHook copies a renewed lineage to the bind certificate paths and reloads the web.
func renewalHook(live string) string {
	return "#!/bin/sh\nset -eu\n" +
		"[ \"${RENEWED_LINEAGE:-}\" = \"" + live + "\" ] || exit 0\n" +
		"install -m 0444 \"" + live + "/fullchain.pem\" \"" + HostBindCertFile + "\"\n" +
		"install -m 0600 \"" + live + "/privkey.pem\" \"" + HostBindKeyFile + "\"\n" +
		"systemctl reload " + hostBindWebUnit + "\n"
}

// hostBindFiles are the files a bind may change; all are backed up first and
// restored (or removed when they did not exist) on any failure.
func hostBindFiles() []string {
	return []string{hostBindControlEnv, hostBindNginxFile, HostBindCertFile, HostBindKeyFile,
		hostBindGatewayCert, NodeInstallTrustFile, NodeInstallDefaultsFile, WebRuntimeConfigFile, HostBindRenewalHook}
}

type hostBindBackup struct {
	layout    Layout
	directory string
	existed   map[string]os.FileInfo
}

func newHostBindBackup(layout Layout, now time.Time) (*hostBindBackup, error) {
	base := layout.Path(hostBindBackupPrefix + now.UTC().Format("20060102T150405Z"))
	if err := os.MkdirAll(filepath.Dir(base), 0o755); err != nil {
		return nil, err
	}
	directory := base
	for attempt := 2; ; attempt++ {
		err := os.Mkdir(directory, 0o700)
		if err == nil {
			break
		}
		if !errors.Is(err, os.ErrExist) || attempt > 100 {
			return nil, fmt.Errorf("create backup directory: %w", err)
		}
		directory = base + "-" + strconv.Itoa(attempt)
	}
	backup := &hostBindBackup{layout: layout, directory: directory, existed: map[string]os.FileInfo{}}
	for _, path := range hostBindFiles() {
		info, err := os.Lstat(layout.Path(path))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("%s is not a regular file", path)
		}
		content, err := os.ReadFile(layout.Path(path))
		if err != nil {
			return nil, err
		}
		target := filepath.Join(directory, strings.TrimPrefix(path, "/"))
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(target, content, 0o600); err != nil {
			return nil, err
		}
		backup.existed[path] = info
	}
	return backup, nil
}

// restore puts every backed-up file back (mode and owner kept) and removes
// files the bind created.
func (backup *hostBindBackup) restore() error {
	var failures []string
	for _, path := range hostBindFiles() {
		target := backup.layout.Path(path)
		info, existed := backup.existed[path]
		if !existed {
			if err := os.Remove(target); err != nil && !errors.Is(err, os.ErrNotExist) {
				failures = append(failures, path)
			}
			continue
		}
		content, err := os.ReadFile(filepath.Join(backup.directory, strings.TrimPrefix(path, "/")))
		if err == nil {
			err = writeFileAtomic(target, content, info.Mode().Perm())
		}
		if err == nil {
			if stat, ok := statOwner(info); ok {
				err = os.Lchown(target, stat[0], stat[1])
			}
		}
		if err != nil {
			failures = append(failures, path)
		}
	}
	if len(failures) != 0 {
		return fmt.Errorf("cannot restore %s from %s", strings.Join(failures, ", "), backup.directory)
	}
	return nil
}

// writeKeepingOwner writes a file atomically, keeping an existing file's mode
// and owner (new files get mode).
func writeKeepingOwner(path string, content []byte, mode os.FileMode) error {
	info, err := os.Lstat(path)
	if err == nil {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%s is not a regular file", path)
		}
		mode = info.Mode().Perm()
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := writeFileAtomic(path, content, mode); err != nil {
		return err
	}
	if info != nil {
		if owner, ok := statOwner(info); ok {
			return os.Lchown(path, owner[0], owner[1])
		}
	}
	return nil
}

// setEnvironmentLines replaces KEY=... lines in control.env (appending keys
// that are missing).
func setEnvironmentLines(content []byte, values map[string]string, order []string) []byte {
	lines := strings.Split(strings.TrimRight(string(content), "\n"), "\n")
	seen := map[string]bool{}
	for index, line := range lines {
		name, _, found := strings.Cut(line, "=")
		if value, ok := values[name]; found && ok {
			lines[index] = name + "=" + value
			seen[name] = true
		}
	}
	for _, name := range order {
		if !seen[name] {
			lines = append(lines, name+"="+values[name])
		}
	}
	return []byte(strings.Join(lines, "\n") + "\n")
}

func bracketHost(host string) string {
	if strings.Contains(host, ":") {
		return "[" + host + "]"
	}
	return host
}

func portOf(address string) string {
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return ""
	}
	return port
}

// Bind binds request.Domain to the installation. Every changed file is backed
// up under /var/lib/cdnca-control/host-bind-backup-<UTC time>/ first; any
// failure restores them and reloads/restarts the services it touched.
// Running it again with the same domain changes nothing.
func Bind(ctx context.Context, environment HostBindEnvironment, request HostBindRequest) (result HostBindResult, err error) {
	layout := environment.Layout
	domain, err := NormalizeBindDomain(request.Domain)
	if err != nil {
		return result, err
	}
	if (request.CertFile == "") != (request.KeyFile == "") {
		return result, errors.New("--cert-file and --key-file must be given together")
	}
	if request.SkipDNSCheck && request.CertFile == "" {
		return result, errors.New("--skip-dns-check needs --cert-file/--key-file (Let's Encrypt validates the domain over HTTP)")
	}
	result.Domain = domain
	unlock, err := LockRelease(layout)
	if err != nil {
		return result, err
	}
	defer unlock()
	ports, err := ReadHostPorts(layout)
	if err != nil {
		return result, err
	}
	if ports.Env == "bt" {
		return result, errors.New("BaoTa installation: bind the domain in the BaoTa site (SSL tab) instead; the console listens on loopback behind it")
	}
	state, err := readBindState(layout)
	if err != nil {
		return result, err
	}
	result.Origin = bindOrigin(domain, state.port)

	// ---- preflight (nothing is written before it passes)
	environment.progress("预检：域名解析、证书来源", "preflight: DNS and certificate source")
	if !request.SkipDNSCheck {
		// This host's public addresses: the control origin before any bind and
		// the node download host, which a bind never moves (NAT hosts do not
		// carry their public IP on an interface).
		known := []string{state.host}
		if match := regexp.MustCompile(`^https://\[?([^\]/]+?)\]?(?::[0-9]+)?/`).FindStringSubmatch(state.environment["CONTROL_UPGRADE_ARTIFACT_BASE_URL"]); match != nil {
			known = append(known, match[1])
		}
		if _, err := checkResolution(ctx, environment, domain, known...); err != nil {
			return result, err
		}
	}
	var chainPEM, keyPEM []byte
	live := ""
	if request.CertFile != "" {
		if chainPEM, err = os.ReadFile(request.CertFile); err == nil {
			keyPEM, err = os.ReadFile(request.KeyFile)
		}
		if err != nil {
			return result, fmt.Errorf("read the certificate files: %w", err)
		}
		if dir := filepath.Dir(request.CertFile); strings.HasPrefix(dir, "/etc/letsencrypt/live/") && dir == filepath.Dir(request.KeyFile) {
			live = dir
		}
	} else {
		bound := HostBindDomainFromNginx(state.nginx) == domain
		if existing, err := os.ReadFile(layout.Path(HostBindCertFile)); bound && err == nil {
			// Re-run with the domain already bound: keep the installed certificate.
			if key, keyErr := os.ReadFile(layout.Path(HostBindKeyFile)); keyErr == nil {
				if _, _, verifyErr := VerifyServingCertificate(existing, key, domain, environment.now()); verifyErr == nil {
					chainPEM, keyPEM = existing, key
				}
			}
		}
		if chainPEM == nil && (environment.PortFree == nil || !environment.PortFree(80)) {
			return result, errors.New("TCP port 80 is in use; Let's Encrypt HTTP-01 needs it free (or pass --cert-file/--key-file)")
		}
	}
	if chainPEM != nil {
		leaf, trusted, err := VerifyServingCertificate(chainPEM, keyPEM, domain, environment.now())
		if err != nil {
			return result, err
		}
		result.CertificateNA, result.PublicTrusted = leaf.NotAfter, trusted
	}

	backup, err := newHostBindBackup(layout, environment.now())
	if err != nil {
		return result, err
	}
	result.BackupDir = backup.directory
	touched := map[string]bool{}
	defer func() {
		if err == nil {
			return
		}
		environment.progress("失败，正在回滚", "failed, rolling back")
		restoreErr := backup.restore()
		for _, unit := range []string{hostBindWebUnit, hostBindGatewayUnit, hostBindControlUnit} {
			if !touched[unit] || environment.Service == nil {
				continue
			}
			verb := "restart"
			if unit == hostBindWebUnit {
				verb = "reload"
			}
			if serviceErr := environment.Service(context.WithoutCancel(ctx), verb, unit); serviceErr != nil && restoreErr == nil {
				restoreErr = fmt.Errorf("%s %s after restore: %w", verb, unit, serviceErr)
			}
		}
		if restoreErr != nil {
			err = fmt.Errorf("%w; ROLLBACK INCOMPLETE: %v (backup %s)", err, restoreErr, backup.directory)
		} else {
			err = fmt.Errorf("%w; all changes were rolled back (backup %s)", err, backup.directory)
		}
	}()
	changed := func(path string, content []byte, mode os.FileMode) (bool, error) {
		current, readErr := os.ReadFile(layout.Path(path))
		if readErr == nil && bytes.Equal(current, content) {
			return false, nil
		}
		return true, writeKeepingOwner(layout.Path(path), content, mode)
	}

	// ---- public certificate
	if chainPEM == nil {
		environment.progress("向 Let's Encrypt 申请证书（HTTP-01，占用 80 端口）", "requesting a Let's Encrypt certificate (HTTP-01 on port 80)")
		if environment.IssueCertificate == nil {
			return result, errors.New("certificate issuance is not available")
		}
		if live, err = environment.IssueCertificate(ctx, domain, request.Email); err != nil {
			return result, err
		}
		if chainPEM, err = os.ReadFile(layout.Path(live + "/fullchain.pem")); err == nil {
			keyPEM, err = os.ReadFile(layout.Path(live + "/privkey.pem"))
		}
		if err != nil {
			return result, fmt.Errorf("read the issued certificate: %w", err)
		}
		leaf, trusted, verifyErr := VerifyServingCertificate(chainPEM, keyPEM, domain, environment.now())
		if verifyErr != nil {
			return result, verifyErr
		}
		result.CertificateNA, result.PublicTrusted = leaf.NotAfter, trusted
	}
	webChanged := false
	for _, file := range []struct {
		path    string
		content []byte
		mode    os.FileMode
	}{{HostBindCertFile, chainPEM, 0o444}, {HostBindKeyFile, keyPEM, 0o600}} {
		did, writeErr := changed(file.path, file.content, file.mode)
		if writeErr != nil {
			return result, writeErr
		}
		webChanged = webChanged || did
	}
	if live != "" {
		if _, err = changed(HostBindRenewalHook, []byte(renewalHook(live)), 0o755); err != nil {
			return result, err
		}
	}

	// ---- nginx: add the domain server block
	rendered, err := RenderHostBindNginx(state.nginx, domain, HostBindCertFile, HostBindKeyFile)
	if err != nil {
		return result, err
	}
	if !bytes.Equal(rendered, state.nginx) {
		staged := layout.Path(hostBindNginxFile) + ".host-bind"
		if err = os.WriteFile(staged, rendered, 0o600); err != nil {
			return result, err
		}
		testErr := error(nil)
		if environment.NginxTest != nil {
			testErr = environment.NginxTest(ctx, staged)
		}
		_ = os.Remove(staged)
		if testErr != nil {
			return result, fmt.Errorf("nginx -t rejected the configuration: %w", testErr)
		}
		if _, err = changed(hostBindNginxFile, rendered, 0o644); err != nil {
			return result, err
		}
		webChanged = true
	}
	if webChanged {
		environment.progress("重载管理端网页（不断连）", "reloading the management web (no downtime)")
		touched[hostBindWebUnit] = true
		if err = environment.Service(ctx, "reload", hostBindWebUnit); err != nil {
			return result, fmt.Errorf("reload %s: %w", hostBindWebUnit, err)
		}
	}

	// ---- Gateway certificate: keep the IP SAN, add the domain
	gatewayChanged := false
	read := func(path string) []byte {
		if err != nil {
			return nil
		}
		var content []byte
		content, err = os.ReadFile(layout.Path(path))
		return content
	}
	gatewayCert, gatewayKey, rootCert, rootKey := read(hostBindGatewayCert), read(hostBindGatewayKey), read(hostBindRootCert), read(hostBindRootKey)
	if err != nil {
		return result, fmt.Errorf("read the Gateway PKI: %w", err)
	}
	reissued, san, err := MergeGatewaySAN(gatewayCert, gatewayKey, rootCert, rootKey, domain, environment.now())
	if err != nil {
		return result, err
	}
	result.GatewaySAN = san
	if reissued != nil {
		if _, err = changed(hostBindGatewayCert, reissued, 0o444); err != nil {
			return result, err
		}
		gatewayChanged = true
	}

	// ---- control.env
	values := map[string]string{"PAYMENT_CHANNELS_NOTIFY_BASE": result.Origin}
	order := []string{"PAYMENT_CHANNELS_NOTIFY_BASE"}
	if request.GatewayHost {
		agent, enrollment := portOf(state.environment["CDNCA_GATEWAY_LOCAL_ADDRESS"]), portOf(state.environment["CDNCA_GATEWAY_LOCAL_ENROLLMENT_ADDRESS"])
		if agent == "" || enrollment == "" {
			return result, errors.New("control.env has no CDNCA_GATEWAY_LOCAL_ADDRESS/_ENROLLMENT_ADDRESS (no co-located Gateway); rerun with --gateway-host-too=false")
		}
		values["CDNCA_GATEWAY_LOCAL_ADDRESS"] = domain + ":" + agent
		values["CDNCA_GATEWAY_LOCAL_SERVER_NAME"] = domain
		values["CDNCA_GATEWAY_LOCAL_ENROLLMENT_ADDRESS"] = domain + ":" + enrollment
		order = append(order, "CDNCA_GATEWAY_LOCAL_ADDRESS", "CDNCA_GATEWAY_LOCAL_SERVER_NAME", "CDNCA_GATEWAY_LOCAL_ENROLLMENT_ADDRESS")
	}
	controlEnv, err := os.ReadFile(layout.Path(hostBindControlEnv))
	if err != nil {
		return result, err
	}
	controlChanged, err := changed(hostBindControlEnv, setEnvironmentLines(controlEnv, values, order), 0o600)
	if err != nil {
		return result, err
	}

	// ---- node-install-defaults and runtime-config.js
	pagesChanged := false
	if request.GatewayHost {
		agent, enrollment := portOf(values["CDNCA_GATEWAY_LOCAL_ADDRESS"]), portOf(values["CDNCA_GATEWAY_LOCAL_ENROLLMENT_ADDRESS"])
		defaults := map[string]string{"gateway_address": domain + ":" + agent, "gateway_enrollment_address": domain + ":" + enrollment, "gateway_server_name": domain}
		runtime := map[string]string{"ADDRESS": defaults["gateway_address"], "ENROLLMENT_ADDRESS": defaults["gateway_enrollment_address"], "SERVER_NAME": domain}
		// the one gateway writer (gatewayregistry, Q20) moves
		// the co-located Gateway and keeps CDN/page entries; control-api recomputes
		// the same lines from the published list after the restart below.
		oldLocal := gatewayregistry.Entrypoint{Address: state.environment["CDNCA_GATEWAY_LOCAL_ADDRESS"],
			ServerName: state.environment["CDNCA_GATEWAY_LOCAL_SERVER_NAME"], EnrollmentAddress: state.environment["CDNCA_GATEWAY_LOCAL_ENROLLMENT_ADDRESS"]}
		newLocal := gatewayregistry.Entrypoint{Address: defaults["gateway_address"], ServerName: domain, EnrollmentAddress: defaults["gateway_enrollment_address"]}
		if current, readErr := os.ReadFile(layout.Path(NodeInstallDefaultsFile)); readErr == nil {
			moved := gatewayregistry.ParseNodeGatewayDefaults(current).MoveLocalGateway(oldLocal, newLocal)
			did, writeErr := gatewayregistry.WriteNodeGatewayDefaults(layout.Path(NodeInstallDefaultsFile), moved)
			if writeErr != nil {
				return result, writeErr
			}
			pagesChanged = pagesChanged || did
		} else if !errors.Is(readErr, os.ErrNotExist) {
			return result, readErr
		}
		if did, rewriteErr := rewriteIfPresent(layout.Path(WebRuntimeConfigFile), func(content []byte) []byte {
			return runtimeGateway.ReplaceAllFunc(content, func(line []byte) []byte {
				name := runtimeGateway.FindSubmatch(line)[1]
				return []byte(`window.__CDNCA_GATEWAY_` + string(name) + `__ = "` + runtime[string(name)] + `";`)
			})
		}); rewriteErr != nil {
			return result, rewriteErr
		} else {
			pagesChanged = pagesChanged || did
		}
	}
	// The copied command pins the private root only while the console serves it.
	caDigest := ""
	if !result.PublicTrusted {
		if root, readErr := os.ReadFile(layout.Path(hostBindGatewayCA)); readErr == nil {
			caDigest = sha256Hex(root)
		}
	}
	if did, rewriteErr := rewriteIfPresent(layout.Path(WebRuntimeConfigFile), func(content []byte) []byte {
		return runtimeCALine.ReplaceAllLiteral(content, []byte(`window.__CDNCA_CONTROL_CA_SHA256__ = "`+caDigest+`";`))
	}); rewriteErr != nil {
		return result, rewriteErr
	} else {
		pagesChanged = pagesChanged || did
	}

	// ---- republish the node install trust (same document: the download policy keeps the old host)
	if state.environment["CONTROL_UPGRADE_ARTIFACT_BASE_URL"] != "" && environment.PublishTrust != nil {
		environment.progress("重发节点安装信任（upgrade-trust/node-install-defaults/runtime-config）", "republishing the node install trust")
		trust, publishErr := environment.PublishTrust(ctx, layout)
		if publishErr != nil {
			err = fmt.Errorf("republish the node install trust: %w", publishErr)
			return result, err
		}
		result.TrustSHA256 = trust.SHA256
		pagesChanged = pagesChanged || trust.Changed
	}

	// ---- services
	if gatewayChanged {
		environment.progress("重启节点网关（节点自动重连）", "restarting the Agent Gateway (nodes reconnect)")
		touched[hostBindGatewayUnit] = true
		if err = environment.Service(ctx, "restart", hostBindGatewayUnit); err != nil {
			return result, fmt.Errorf("restart %s: %w", hostBindGatewayUnit, err)
		}
	}
	if controlChanged {
		environment.progress("重启 control-api 以读取新地址", "restarting control-api for the new address")
		touched[hostBindControlUnit] = true
		if err = environment.Service(ctx, "restart", hostBindControlUnit); err != nil {
			return result, fmt.Errorf("restart %s: %w", hostBindControlUnit, err)
		}
	}
	if len(touched) != 0 && environment.Ready != nil {
		if err = environment.Ready(ctx); err != nil {
			return result, fmt.Errorf("services did not become ready: %w", err)
		}
	}
	result.Changed = webChanged || gatewayChanged || controlChanged || pagesChanged
	if !result.Changed {
		_ = os.RemoveAll(backup.directory)
		result.BackupDir = ""
	}
	return result, nil
}

func rewriteIfPresent(path string, change func([]byte) []byte) (bool, error) {
	before, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := rewriteRegularFile(path, change); err != nil {
		return false, err
	}
	after, err := os.ReadFile(path)
	return err == nil && !bytes.Equal(before, after), err
}

func statOwner(info os.FileInfo) ([2]int, bool) {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return [2]int{int(stat.Uid), int(stat.Gid)}, true
	}
	return [2]int{}, false
}

// HostCertificate describes one served certificate.
type HostCertificate struct {
	File     string
	Subject  string
	Issuer   string
	SAN      []string
	NotAfter time.Time
	Trusted  bool
}

// HostStatus is `control-host status`.
type HostStatus struct {
	Origin       string
	BoundDomain  string
	GatewayLocal string
	DownloadBase string
	Public       *HostCertificate // the domain server certificate (bound) or the default one
	Default      *HostCertificate
	Gateway      *HostCertificate
	ControlCAPin string
}

func describeCertificate(path string) *HostCertificate {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	leaf, err := parseCertificatePEM(content)
	if err != nil {
		return nil
	}
	rest := content
	intermediates := x509.NewCertPool()
	for first := true; ; first = false {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if !first {
			if certificate, err := x509.ParseCertificate(block.Bytes); err == nil {
				intermediates.AddCert(certificate)
			}
		}
	}
	_, verifyErr := leaf.Verify(x509.VerifyOptions{Intermediates: intermediates})
	return &HostCertificate{File: path, Subject: leaf.Subject.CommonName, Issuer: leaf.Issuer.CommonName,
		SAN: sanList(leaf), NotAfter: leaf.NotAfter, Trusted: verifyErr == nil}
}

var nginxDefaultCert = regexp.MustCompile(`(?m)^        ssl_certificate ([^ ;\n]+);$`)

// ReadHostStatus reports the current addresses and certificates.
func ReadHostStatus(layout Layout) (HostStatus, error) {
	state, err := readBindState(layout)
	if err != nil {
		return HostStatus{}, err
	}
	status := HostStatus{Origin: state.origin, BoundDomain: HostBindDomainFromNginx(state.nginx),
		GatewayLocal: state.environment["CDNCA_GATEWAY_LOCAL_ADDRESS"], DownloadBase: state.environment["CONTROL_UPGRADE_ARTIFACT_BASE_URL"]}
	if match := nginxDefaultCert.FindSubmatch(StripHostBindBlock(state.nginx)); match != nil {
		status.Default = describeCertificate(layout.Path(string(match[1])))
	}
	status.Public = status.Default
	if status.BoundDomain != "" {
		status.Public = describeCertificate(layout.Path(HostBindCertFile))
	}
	status.Gateway = describeCertificate(layout.Path(hostBindGatewayCert))
	if content, err := os.ReadFile(layout.Path(WebRuntimeConfigFile)); err == nil {
		if match := regexp.MustCompile(`(?m)^window\.__CDNCA_CONTROL_CA_SHA256__ = "([0-9a-f]{64})?";$`).FindSubmatch(content); match != nil {
			status.ControlCAPin = string(match[1])
		}
	}
	return status, nil
}
