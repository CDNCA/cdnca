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

// Run logs in with the pinned host key and runs command, writing stdin (may
// be empty) to it. Every output line is passed to line (stdout and stderr).
// It returns the exit error, if any.
func (dialer *Dialer) Run(ctx context.Context, host string, port int, credential Credential, pinned, command string,
	stdin []byte, line func(string)) error {
	auth, err := authMethods(credential)
	if err != nil {
		return err
	}
	connection, address, err := dialer.connect(ctx, host, port)
	if err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
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
		return err
	}
	client := ssh.NewClient(conn, channels, requests)
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

var registrationKeyPattern = regexp.MustCompile(`^nrk1\.[0-9a-f]{32}\.[A-Za-z0-9_-]{43}$`)

// InstallCommand is the console's install plus the node identity the
// controller already knows. No secret is on the command line (remote ps):
// the session's stdin carries line 1 = registration key and, for a non-root
// password login, line 2 = sudo password (see InstallInput). The shell reads
// the key with the read builtin, downloads install-node.sh to a 0700 temp
// dir (stdin stays free), lets "sudo -S -v" read the password line, then
// pipes the key with the printf builtin into the installer's
// --registration-key-stdin; "sudo -n" reuses the cached sudo ticket. Every
// argument is single-quoted.
func InstallCommand(controlPlane, registrationKey, host, name string, root bool, sudoPassword bool) (string, error) {
	parsed, err := url.Parse(controlPlane)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Path != "" || parsed.RawQuery != "" ||
		parsed.User != nil || parsed.Fragment != "" || !registrationKeyPattern.MatchString(registrationKey) {
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
	return fmt.Sprintf(`set -o pipefail; umask 077; d=$(mktemp -d) || exit 1; trap 'rm -rf -- "$d"' EXIT; `+
		`IFS= read -r k || exit 1; curl --proto '=https' -fsSL -o "$d/install-node.sh" %s && %s`+
		`printf '%%s\n' "$k" | %s "$d/install-node.sh" %s`,
		quote(controlPlane+"/downloads/install-node.sh"), prefix, runner, strings.Join(arguments, " ")), nil
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
