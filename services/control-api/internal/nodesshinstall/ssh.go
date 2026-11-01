package nodesshinstall

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
)

var (
	errHostKeyMismatch = errors.New("SSH host key does not match the confirmed fingerprint")
	errBlockedAddress  = errors.New("SSH destination address is not allowed")
)

// HostKeySHA256 renders a key the way OpenSSH prints it.
func HostKeySHA256(key ssh.PublicKey) string {
	sum := sha256.Sum256(key.Marshal())
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// Dialer opens SSH connections. blocked refuses loopback, link-local (cloud
// metadata), multicast and unspecified addresses after DNS resolution;
// private ranges stay allowed (nodes often sit in a private network next
// to the controller).
type Dialer struct {
	blocked func(netip.Addr) bool
	timeout time.Duration
}

func NewDialer(blocked func(netip.Addr) bool) *Dialer {
	if blocked == nil {
		blocked = defaultBlocked
	}
	return &Dialer{blocked: blocked, timeout: 15 * time.Second}
}

func defaultBlocked(address netip.Addr) bool {
	address = address.Unmap()
	return !address.IsValid() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() ||
		address.IsUnspecified() || address.IsMulticast() || address.IsInterfaceLocalMulticast()
}

func (dialer *Dialer) connect(ctx context.Context, host string, port int) (net.Conn, string, error) {
	netDialer := &net.Dialer{Timeout: dialer.timeout, KeepAlive: 30 * time.Second, Control: func(_, address string, _ syscall.RawConn) error {
		hostPart, _, err := net.SplitHostPort(address)
		if err != nil {
			return errBlockedAddress
		}
		parsed, err := netip.ParseAddr(hostPart)
		if err != nil || dialer.blocked(parsed) {
			return errBlockedAddress
		}
		return nil
	}}
	address := net.JoinHostPort(strings.Trim(host, "[]"), strconv.Itoa(port))
	connection, err := netDialer.DialContext(ctx, "tcp", address)
	return connection, address, err
}

// FetchHostKey reads the server's host key without authenticating.
func (dialer *Dialer) FetchHostKey(ctx context.Context, host string, port int) (string, error) {
	connection, address, err := dialer.connect(ctx, host, port)
	if err != nil {
		return "", err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(dialer.timeout))
	var fingerprint string
	captured := errors.New("host key captured")
	config := &ssh.ClientConfig{User: "cdnca-host-key-probe", Timeout: dialer.timeout,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			fingerprint = HostKeySHA256(key)
			return captured
		}}
	_, _, _, err = ssh.NewClientConn(connection, address, config)
	if fingerprint != "" {
		return fingerprint, nil
	}
	return "", err
}

// login opens an authenticated SSH client whose host key must equal pinned.
// With deadline the TCP connection carries it (installs); without, the
// connection has no deadline (interactive terminals manage their own).
func (dialer *Dialer) login(ctx context.Context, host string, port int, credential Credential, pinned string,
	deadline bool) (*ssh.Client, error) {
	auth, err := authMethods(credential)
	if err != nil {
		return nil, err
	}
	connection, address, err := dialer.connect(ctx, host, port)
	if err != nil {
		return nil, err
	}
	if until, ok := ctx.Deadline(); ok && deadline {
		_ = connection.SetDeadline(until)
	} else {
		// The handshake still has to finish in time.
		_ = connection.SetDeadline(time.Now().Add(dialer.timeout))
	}
	config := &ssh.ClientConfig{User: credential.Username, Auth: auth, Timeout: dialer.timeout,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			if HostKeySHA256(key) != pinned {
				return errHostKeyMismatch
			}
			return nil
		}}
	conn, channels, requests, err := ssh.NewClientConn(connection, address, config)
	if err != nil {
		_ = connection.Close()
		return nil, err
	}
	if !deadline {
		_ = connection.SetDeadline(time.Time{})
	}
	return ssh.NewClient(conn, channels, requests), nil
}

// Shell is an interactive login shell on a pty (the console SSH terminal).
type Shell struct {
	client  *ssh.Client
	session *ssh.Session
	Stdin   io.WriteCloser
}

// OpenShell logs in with the pinned host key and starts a login shell on an
// xterm pty of cols x rows. The shell's stdout and stderr are both copied to
// output (from two goroutines: output must be safe for concurrent writes).
func (dialer *Dialer) OpenShell(ctx context.Context, host string, port int, credential Credential, pinned string,
	cols, rows int, output io.Writer) (*Shell, error) {
	client, err := dialer.login(ctx, host, port, credential, pinned, false)
	if err != nil {
		return nil, err
	}
	shell, err := startShell(client, cols, rows, output)
	if err != nil {
		_ = client.Close()
		return nil, err
	}
	return shell, nil
}

func startShell(client *ssh.Client, cols, rows int, output io.Writer) (*Shell, error) {
	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		return nil, err
	}
	session.Stdout, session.Stderr = output, output
	modes := ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 14400, ssh.TTY_OP_OSPEED: 14400}
	if err := session.RequestPty("xterm-256color", rows, cols, modes); err != nil {
		return nil, err
	}
	if err := session.Shell(); err != nil {
		return nil, err
	}
	return &Shell{client: client, session: session, Stdin: stdin}, nil
}

// Resize changes the pty size.
func (shell *Shell) Resize(cols, rows int) error { return shell.session.WindowChange(rows, cols) }

// Wait returns when the remote shell exits.
func (shell *Shell) Wait() error { return shell.session.Wait() }

// Close ends the session and the connection.
func (shell *Shell) Close() error {
	_ = shell.session.Close()
	return shell.client.Close()
}

// Run logs in with the pinned host key and runs command, writing stdin (may
// be empty) to it. Every output line is passed to line (stdout and stderr).
// It returns the exit error, if any.
func (dialer *Dialer) Run(ctx context.Context, host string, port int, credential Credential, pinned, command string,
	stdin []byte, line func(string)) error {
	client, err := dialer.login(ctx, host, port, credential, pinned, true)
	if err != nil {
		return err
	}
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	stdout, err := session.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		return err
	}
	input, err := session.StdinPipe()
	if err != nil {
		return err
	}
	if err := session.Start(command); err != nil {
		return err
	}
	if len(stdin) > 0 {
		_, _ = input.Write(stdin)
	}
	_ = input.Close()
	done := make(chan struct{}, 2)
	for _, stream := range []io.Reader{stdout, stderr} {
		go func(stream io.Reader) {
			defer func() { done <- struct{}{} }()
			scanner := bufio.NewScanner(stream)
			scanner.Buffer(make([]byte, 64<<10), 64<<10)
			for scanner.Scan() {
				line(scanner.Text())
			}
		}(stream)
	}
	waited := make(chan error, 1)
	go func() {
		<-done
		<-done
		waited <- session.Wait()
	}()
	select {
	case err := <-waited:
		return err
	case <-ctx.Done():
		_ = session.Signal(ssh.SIGTERM)
		_ = client.Close()
		return ctx.Err()
	}
}

func authMethods(credential Credential) ([]ssh.AuthMethod, error) {
	if credential.PrivateKey != "" {
		signer, err := ssh.ParsePrivateKey([]byte(credential.PrivateKey))
		if err != nil {
			return nil, ErrInvalidInput
		}
		return []ssh.AuthMethod{ssh.PublicKeys(signer)}, nil
	}
	if credential.Password == "" {
		return nil, ErrInvalidInput
	}
	password := credential.Password
	return []ssh.AuthMethod{ssh.Password(password), ssh.KeyboardInteractive(
		func(_, _ string, questions []string, _ []bool) ([]string, error) {
			answers := make([]string, len(questions))
			for index := range answers {
				answers[index] = password
			}
			return answers, nil
		})}, nil
}

var (
	registrationKeyPattern = regexp.MustCompile(`^nrk1\.[0-9a-f]{32}\.[A-Za-z0-9_-]{43}$`)
	controlCADigestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// InstallCommand is the console's install plus the node identity the
// controller already knows. No secret is on the command line (remote ps):
// the session's stdin carries line 1 = registration key and, for a non-root
// password login, line 2 = sudo password (see InstallInput). The shell reads
// the key with the read builtin, downloads install-node.sh to a 0700 temp
// dir (stdin stays free), lets "sudo -S -v" read the password line, then
// pipes the key with the printf builtin into the installer's
// --registration-key-stdin; "sudo -n" reuses the cached sudo ticket. Every
// argument is single-quoted.
//
// controlCASHA256 is
// the console's published digest of /downloads/gateway-ca.pem (the
// installer-generated self-signed root): that root is fetched once without
// verification, used only when its SHA-256 matches, then pins the script
// download (system trust as fallback) and is handed to the installer, the
// same rule as the copied console command (packages/cdnca-ui installerCommand).
//
// language (migration 610) is the operator's UI language when the job was
// created: "zh" / "en" append --lang zh / --lang en (a stock Ubuntu has
// LANG=C.UTF-8 and no terminal, so the installer would otherwise pick
// English); "" (older jobs) appends nothing.
func InstallCommand(controlPlane, registrationKey, host, name string, root bool, sudoPassword bool,
	controlCASHA256, language string) (string, error) {
	parsed, err := url.Parse(controlPlane)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Path != "" || parsed.RawQuery != "" ||
		parsed.User != nil || parsed.Fragment != "" || !registrationKeyPattern.MatchString(registrationKey) ||
		(controlCASHA256 != "" && !controlCADigestPattern.MatchString(controlCASHA256)) || !ValidLanguage(language) {
		return "", ErrInvalidInput
	}
	quote := func(value string) string { return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'" }
	arguments := []string{"--control-plane", quote(controlPlane), "--registration-key-stdin", "-y"}
	if address, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil && address.Is4() {
		arguments = append(arguments, "--public-ip", quote(address.String()))
	}
	if name != "" {
		arguments = append(arguments, "--node-name", quote(name))
	}
	prefix, runner := "", "bash"
	if !root {
		runner = "sudo -n bash"
		if sudoPassword {
			prefix = "sudo -S -p '' -v && "
		}
	}
	script := quote(controlPlane + "/downloads/install-node.sh")
	download := `curl --proto '=https' -fsSL -o "$d/install-node.sh" ` + script
	trust := ""
	if controlCASHA256 != "" {
		trust = `a="$d/control-plane-ca.pem"; curl --proto '=https' --proto-redir '=https' -k -fsSL --max-filesize 65536 -o "$a" ` +
			quote(controlPlane+"/downloads/gateway-ca.pem") + ` && [ "$(sha256sum "$a" | cut -d ' ' -f 1)" = ` + quote(controlCASHA256) +
			` ] || { echo '[cdnca-edge] error: cannot download the management root CA or its fingerprint does not match' >&2; exit 1; }; `
		download = `{ curl --proto '=https' --proto-redir '=https' --cacert "$a" -fsSL -o "$d/install-node.sh" ` + script + ` || ` + download + `; }`
		arguments = append(arguments, "--control-plane-ca-file", `"$a"`, "--control-plane-ca-sha256", quote(controlCASHA256))
	}
	if language != "" {
		arguments = append(arguments, "--lang", language)
	}
	return fmt.Sprintf(`set -o pipefail; umask 077; d=$(mktemp -d) || exit 1; trap 'rm -rf -- "$d"' EXIT; `+
		`IFS= read -r k || exit 1; %s%s && %s`+
		`printf '%%s\n' "$k" | %s "$d/install-node.sh" %s`,
		trust, download, prefix, runner, strings.Join(arguments, " ")), nil
}

// ValidLanguage is a job language: "" (none), "zh" or "en".
func ValidLanguage(language string) bool {
	return language == "" || language == "zh" || language == "en"
}

// InstallInput is the session stdin for InstallCommand: the registration
// key line, then the sudo password line when sudoPassword is not empty
// (normalizeCreate refuses passwords containing a line break).
func InstallInput(registrationKey, sudoPassword string) []byte {
	input := registrationKey + "\n"
	if sudoPassword != "" {
		input += sudoPassword + "\n"
	}
	return []byte(input)
}
