package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/http3runtime"
)

type protocolProbe struct {
	clientBinary string
	port         int
}

type smokeEvidence struct {
	Mode                     string `json:"mode"`
	AppliedVersion           string `json:"applied_version"`
	ActiveVersion            string `json:"active_version"`
	ErrorCode                string `json:"error_code,omitempty"`
	RunningVersionUnchanged  bool   `json:"running_version_unchanged"`
	MasterPID                int    `json:"master_pid"`
	MasterPIDStable          bool   `json:"master_pid_stable,omitempty"`
	DualProtocolHealth       bool   `json:"dual_protocol_health"`
	HTTP3Enabled             bool   `json:"http3_enabled"`
	IdentityRecordOwned      bool   `json:"identity_record_owned,omitempty"`
	PIDFDNoLeak              bool   `json:"pidfd_no_leak,omitempty"`
	SubstituteSignalRejected bool   `json:"substitute_signal_rejected,omitempty"`
}

func main() {
	mode := flag.String("mode", "", "init, reload, disable, enable, fence, or bad")
	stateRoot := flag.String("state-root", "/var/lib/cdnca-edge-http3", "HTTP/3 state root")
	binary := flag.String("openresty-binary", "/usr/local/openresty/bin/openresty", "OpenResty binary")
	clientBinary := flag.String("h3-client", "/usr/local/bin/h3probe", "HTTP/3 probe binary")
	port := flag.Int("port", 18443, "TCP and UDP listener port")
	flag.Parse()
	if *mode != "init" && *mode != "reload" && *mode != "disable" && *mode != "enable" && *mode != "fence" && *mode != "bad" {
		fatal(errors.New("mode must be init, reload, disable, enable, fence, or bad"))
	}
	if *port < 1_024 || *port > 65_535 {
		fatal(errors.New("port must be between 1024 and 65535"))
	}
	if err := os.MkdirAll(*stateRoot, 0o700); err != nil {
		fatal(err)
	}
	if err := os.Chmod(*stateRoot, 0o700); err != nil {
		fatal(err)
	}
	certificateFile, certificateDigest, keyFile, keyDigest, err := ensureCertificate(*stateRoot)
	if err != nil {
		fatal(err)
	}
	probe := protocolProbe{clientBinary: *clientBinary, port: *port}
	runtime, err := http3runtime.NewOpenResty(*binary, filepath.Join(*stateRoot, "run", "nginx.pid"), 15*time.Second, probe)
	if err != nil {
		fatal(err)
	}
	manager, err := http3runtime.NewManager(*stateRoot, runtime)
	if err != nil {
		fatal(err)
	}
	base := policy("http3-v1", *port, certificateFile, certificateDigest, keyFile, keyDigest)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	var evidence smokeEvidence
	switch *mode {
	case "init":
		result, applyErr := manager.Apply(ctx, base)
		if applyErr != nil {
			fatal(applyErr)
		}
		pid, err := masterPID(*stateRoot)
		if err != nil {
			fatal(err)
		}
		evidence = smokeEvidence{
			Mode: *mode, AppliedVersion: result.VersionID, ActiveVersion: result.ActiveVersionID,
			MasterPID: pid, DualProtocolHealth: true, HTTP3Enabled: true,
		}
	case "reload":
		before, err := masterPID(*stateRoot)
		if err != nil {
			fatal(err)
		}
		next := base
		next.VersionID = "http3-v2"
		next.Limits.ConcurrentStreams = 4
		next.Limits.ConnectionsPerClient = 2
		result, applyErr := manager.Apply(ctx, next)
		if applyErr != nil {
			fatal(applyErr)
		}
		after, err := masterPID(*stateRoot)
		if err != nil {
			fatal(err)
		}
		if before != after {
			fatal(fmt.Errorf("reload replaced master PID: before=%d after=%d", before, after))
		}
		evidence = smokeEvidence{
			Mode: *mode, AppliedVersion: result.VersionID, ActiveVersion: result.ActiveVersionID,
			MasterPID: after, MasterPIDStable: true, DualProtocolHealth: true, HTTP3Enabled: true,
		}
	case "disable", "enable":
		before, err := masterPID(*stateRoot)
		if err != nil {
			fatal(err)
		}
		next := base
		next.VersionID = "http3-v3-off"
		next.Protocols = []string{"http1", "http2"}
		if *mode == "enable" {
			next.VersionID = "http3-v4-on"
			next.Protocols = []string{"http1", "http2", "http3"}
		}
		result, applyErr := manager.Apply(ctx, next)
		if applyErr != nil {
			fatal(applyErr)
		}
		after, err := masterPID(*stateRoot)
		if err != nil || before != after {
			fatal(fmt.Errorf("protocol toggle replaced master PID: before=%d after=%d error=%v", before, after, err))
		}
		evidence = smokeEvidence{
			Mode: *mode, AppliedVersion: result.VersionID, ActiveVersion: result.ActiveVersionID,
			MasterPID: after, MasterPIDStable: true, DualProtocolHealth: true, HTTP3Enabled: *mode == "enable",
		}
	case "fence":
		evidence, err = runFencingSmoke(ctx, runtime, manager, *stateRoot)
		if err != nil {
			fatal(err)
		}
	case "bad":
		before, err := masterPID(*stateRoot)
		if err != nil {
			fatal(err)
		}
		bad := base
		bad.VersionID = "http3-bad"
		bad.TLS.CertificateSHA256 = strings.Repeat("0", 64)
		result, applyErr := manager.Apply(ctx, bad)
		if !errors.Is(applyErr, http3runtime.ErrPrecheck) || result.ErrorCode != "PRECHECK_FAILED" ||
			!result.RunningVersionUnchanged || result.ActiveVersionID != "http3-v2" {
			fatal(fmt.Errorf("bad policy was not rejected with LKG intact: result=%+v error=%v", result, applyErr))
		}
		status, err := manager.Status()
		if err != nil || !status.Active || status.VersionID != "http3-v2" {
			fatal(fmt.Errorf("unexpected LKG status: %+v error=%v", status, err))
		}
		after, err := masterPID(*stateRoot)
		if err != nil {
			fatal(err)
		}
		if before != after {
			fatal(fmt.Errorf("bad policy changed master PID: before=%d after=%d", before, after))
		}
		evidence = smokeEvidence{
			Mode: *mode, AppliedVersion: result.VersionID, ActiveVersion: result.ActiveVersionID,
			ErrorCode: result.ErrorCode, RunningVersionUnchanged: true, MasterPID: after,
			MasterPIDStable: true, DualProtocolHealth: true, HTTP3Enabled: true,
		}
	}
	if err := runtime.Close(); err != nil {
		fatal(err)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(evidence); err != nil {
		fatal(err)
	}
}

func runFencingSmoke(
	ctx context.Context,
	runtime *http3runtime.OpenResty,
	manager *http3runtime.Manager,
	stateRoot string,
) (evidence smokeEvidence, result error) {
	pidFile := filepath.Join(stateRoot, "run", "nginx.pid")
	identityPath := pidFile + ".identity"
	identity, err := os.ReadFile(identityPath)
	if err != nil {
		return smokeEvidence{}, err
	}
	info, err := os.Lstat(identityPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return smokeEvidence{}, errors.New("OpenResty identity record is unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		return smokeEvidence{}, errors.New("OpenResty identity record is not owned")
	}
	fields := strings.Fields(string(identity))
	master, err := masterPID(stateRoot)
	if err != nil || len(fields) != 6 || fields[0] != strconv.Itoa(master) || string(identity) != strings.Join(fields, " ")+"\n" {
		return smokeEvidence{}, errors.New("OpenResty identity record is invalid")
	}
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return smokeEvidence{}, err
	}
	for attempt := 0; attempt < 32; attempt++ {
		if err := runtime.Activate(ctx, filepath.Join(stateRoot, "current")); err != nil {
			return smokeEvidence{}, fmt.Errorf("pidfd reload %d: %w", attempt, err)
		}
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil || len(after) != len(before) {
		return smokeEvidence{}, fmt.Errorf("pidfd descriptor leak: before=%d after=%d: %w", len(before), len(after), err)
	}
	startTicks, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil || startTicks == ^uint64(0) {
		return smokeEvidence{}, errors.New("OpenResty start ticks are invalid")
	}
	tamperedFields := append([]string(nil), fields...)
	tamperedFields[1] = strconv.FormatUint(startTicks+1, 10)
	if err := os.WriteFile(identityPath, []byte(strings.Join(tamperedFields, " ")+"\n"), 0o600); err != nil {
		return smokeEvidence{}, err
	}
	restored := false
	defer func() {
		if !restored {
			result = errors.Join(result, os.WriteFile(identityPath, identity, 0o600))
		}
	}()
	if err := runtime.Activate(ctx, filepath.Join(stateRoot, "current")); err == nil {
		return smokeEvidence{}, errors.New("tampered process identity reached reload signal")
	}
	afterRejected, err := masterPID(stateRoot)
	if err != nil || afterRejected != master {
		return smokeEvidence{}, errors.New("identity rejection changed the OpenResty master PID")
	}
	if err := os.WriteFile(identityPath, identity, 0o600); err != nil {
		return smokeEvidence{}, err
	}
	restored = true
	if err := runtime.Healthy(ctx, filepath.Join(stateRoot, "current")); err != nil {
		return smokeEvidence{}, err
	}
	status, err := manager.Status()
	if err != nil || !status.Active {
		return smokeEvidence{}, errors.New("HTTP/3 manager lost active state during fencing smoke")
	}
	return smokeEvidence{
		Mode: "fence", ActiveVersion: status.VersionID, MasterPID: master, MasterPIDStable: true,
		DualProtocolHealth: true, IdentityRecordOwned: true, PIDFDNoLeak: true, SubstituteSignalRejected: true,
		HTTP3Enabled: true,
	}, nil
}

func policy(versionID string, port int, certificateFile, certificateDigest, keyFile, keyDigest string) http3runtime.Policy {
	return http3runtime.Policy{
		SchemaVersion: http3runtime.SchemaVersionV1,
		VersionID:     versionID,
		Protocols:     []string{"http1", "http2", "http3"},
		Runtime: http3runtime.RuntimeRef{
			Family: http3runtime.RuntimeFamilyOpenResty, Version: http3runtime.RuntimeVersionOpenResty,
		},
		Listener: http3runtime.Listener{
			Address: "0.0.0.0", Port: port, ServerName: "h3.test", AltSvcMaxAgeSeconds: 300,
		},
		TLS: http3runtime.TLSConfig{
			MinimumVersion: "TLSv1.3", CertificateFile: certificateFile, CertificateSHA256: certificateDigest,
			PrivateKeyFile: keyFile, PrivateKeySHA256: keyDigest,
		},
		Limits: http3runtime.Limits{
			IdleTimeoutMS: 10_000, WorkerConnections: 128, ConnectionsPerClient: 8,
			ConcurrentStreams: 2, RequestHeaderBytes: 4_096, ActiveConnectionIDs: 4,
		},
	}
}

func (p protocolProbe) TCP(ctx context.Context, policy http3runtime.Policy) error {
	return retry(ctx, 5*time.Second, func() error {
		dialer := &net.Dialer{Timeout: time.Second}
		connection, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(p.port)), &tls.Config{
			InsecureSkipVerify: true, // The smoke certificate is generated inside the isolated container.
			ServerName:         policy.Listener.ServerName,
			MinVersion:         tls.VersionTLS13,
			NextProtos:         []string{"h2", "http/1.1"},
		})
		if err != nil {
			return err
		}
		defer connection.Close()
		state := connection.ConnectionState()
		if state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != "h2" {
			return fmt.Errorf("unexpected TCP TLS state: version=%x ALPN=%q", state.Version, state.NegotiatedProtocol)
		}
		return nil
	})
}

func (p protocolProbe) HTTP3(ctx context.Context, policy http3runtime.Policy) error {
	return retry(ctx, 8*time.Second, func() error {
		probeCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
		defer cancel()
		command := exec.CommandContext(probeCtx, p.clientBinary,
			"request", "--url", fmt.Sprintf("https://127.0.0.1:%d/healthz", p.port),
			"--server-name", policy.Listener.ServerName, "--timeout", "3s")
		output, err := command.CombinedOutput()
		if err != nil {
			return fmt.Errorf("h3probe: %s: %w", strings.TrimSpace(string(output)), err)
		}
		if !strings.Contains(string(output), `"protocol": "HTTP/3.0"`) ||
			!strings.Contains(string(output), `"version_header": "`+policy.VersionID+`"`) {
			return fmt.Errorf("unexpected h3probe output: %s", output)
		}
		return nil
	})
}

func retry(ctx context.Context, timeout time.Duration, operation func() error) error {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	var last error
	for {
		if err := operation(); err == nil {
			return nil
		} else {
			last = err
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%v: %w", last, ctx.Err())
		case <-deadline.C:
			return last
		case <-ticker.C:
		}
	}
}

func ensureCertificate(stateRoot string) (string, string, string, string, error) {
	directory := filepath.Join(stateRoot, "certs")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", "", "", "", err
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return "", "", "", "", err
	}
	certificateFile := filepath.Join(directory, "server.crt")
	keyFile := filepath.Join(directory, "server.key")
	certificate, certificateErr := os.ReadFile(certificateFile)
	key, keyErr := os.ReadFile(keyFile)
	if certificateErr == nil && keyErr == nil {
		return certificateFile, digest(certificate), keyFile, digest(key), nil
	}
	if !errors.Is(certificateErr, os.ErrNotExist) || !errors.Is(keyErr, os.ErrNotExist) {
		return "", "", "", "", errors.New("partial or unreadable smoke certificate state")
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", "", "", err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return "", "", "", "", err
	}
	now := time.Now().UTC()
	template := x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "h3.test"}, DNSNames: []string{"h3.test"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return "", "", "", "", err
	}
	certificate = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", "", "", "", err
	}
	key = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := writeExclusive(certificateFile, certificate); err != nil {
		return "", "", "", "", err
	}
	if err := writeExclusive(keyFile, key); err != nil {
		return "", "", "", "", err
	}
	return certificateFile, digest(certificate), keyFile, digest(key), nil
}

func writeExclusive(path string, content []byte) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.Write(content); err != nil {
		return err
	}
	return file.Sync()
}

func digest(content []byte) string {
	value := sha256.Sum256(content)
	return hex.EncodeToString(value[:])
}

func masterPID(stateRoot string) (int, error) {
	content, err := os.ReadFile(filepath.Join(stateRoot, "run", "nginx.pid"))
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(content)))
	if err != nil || pid <= 1 {
		return 0, errors.New("invalid OpenResty master PID")
	}
	return pid, nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
