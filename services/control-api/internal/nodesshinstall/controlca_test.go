package nodesshinstall

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testRegistrationKey = "nrk1.0123456789abcdef0123456789abcdef.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func TestInstallCommandPinsSelfSignedControlCA(t *testing.T) {
	digest := strings.Repeat("ef", 32)
	command, err := InstallCommand("https://198.51.100.126", testRegistrationKey, "203.0.113.7", "", true, false, digest, "", Gateway{})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`-k -fsSL --max-filesize 65536 -o "$a" 'https://198.51.100.126/downloads/gateway-ca.pem' && [ "$(sha256sum "$a" | cut -d ' ' -f 1)" = '` + digest + `' ] || {`,
		`--cacert "$a" -fsSL -o "$d/install-node.sh" 'https://198.51.100.126/downloads/install-node.sh' || curl --proto '=https' -fsSL`,
		`--control-plane-ca-file "$a" --control-plane-ca-sha256 '` + digest + `'`,
	} {
		if !strings.Contains(command, want) {
			t.Errorf("command missing %q:\n%s", want, command)
		}
	}
	// The script is only ever fetched with verification: -k applies to the CA alone.
	if strings.Count(command, " -k ") != 1 {
		t.Fatalf("unverified fetch beyond the pinned CA: %s", command)
	}
	plain, _ := InstallCommand("https://198.51.100.126", testRegistrationKey, "203.0.113.7", "", true, false, "", "", Gateway{})
	if strings.Contains(plain, "gateway-ca.pem") || strings.Contains(plain, "--control-plane-ca") {
		t.Fatalf("publicly trusted console got a pin: %s", plain)
	}
	for _, bad := range []string{"AB" + strings.Repeat("ab", 31), strings.Repeat("ab", 31), strings.Repeat("ab", 32) + "'; id"} {
		if _, err := InstallCommand("https://198.51.100.126", testRegistrationKey, "203.0.113.7", "", true, false, bad, "", Gateway{}); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("digest %q accepted", bad)
		}
	}
}

func TestRuntimeControlCA(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "runtime-config.js")
	digest := strings.Repeat("0a", 32)
	for content, want := range map[string]string{
		"window.__CDNCA_NODE_UPGRADE_TRUST_SHA256__ = \"" + strings.Repeat("cd", 32) + "\";\nwindow.__CDNCA_CONTROL_CA_SHA256__ = \"" + digest + "\";\n": digest,
		"window.__CDNCA_CONTROL_CA_SHA256__ = \"\";\n":    "",
		"window.__CDNCA_CONTROL_CA_SHA256__ = \"x'y\";\n": "",
		"// no pin\n": "",
		strings.Repeat("window.__CDNCA_CONTROL_CA_SHA256__ = \""+digest+"\";\n", 2): "",
	} {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		if got := RuntimeControlCA(path)(); got != want {
			t.Errorf("%q: got %q, want %q", content, got, want)
		}
	}
	if got := RuntimeControlCA(filepath.Join(directory, "missing.js"))(); got != "" {
		t.Fatalf("missing file: %q", got)
	}
	if (&Service{}).controlCASHA256() != "" {
		t.Fatal("unset pin source must mean no pin")
	}
}

// The real command against a real self-signed HTTPS console (openssl
// s_server) with the real curl: without the pin it fails like 126 did
// (curl 60), with it the installer runs and receives the root.
func TestInstallCommandRunsAgainstSelfSignedConsole(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not available")
	}
	for _, tool := range []string{"curl", "bash", "sha256sum"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available", tool)
		}
	}
	directory := t.TempDir()
	sh := func(script string) {
		t.Helper()
		command := exec.Command("bash", "-c", script)
		command.Dir = directory
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("%v: %s", err, output)
		}
	}
	sh(`set -e; mkdir -p downloads
o=` + openssl + `
"$o" req -x509 -newkey rsa:2048 -nodes -days 2 -subj '/CN=CDNCA local control root' -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign -keyout ca-key.pem -out downloads/gateway-ca.pem 2>/dev/null
"$o" req -newkey rsa:2048 -nodes -subj '/CN=127.0.0.1' -keyout key.pem -out server.csr 2>/dev/null
printf 'subjectAltName=IP:127.0.0.1\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n' > ext.cnf
"$o" x509 -req -in server.csr -CA downloads/gateway-ca.pem -CAkey ca-key.pem -CAcreateserial -days 2 -extfile ext.cnf -out server.pem 2>/dev/null
printf '#!/usr/bin/env bash\nmain() { printf "%%s\\n" "$@" > "$T/args"; for a in "$@"; do case "$a" in /*) cat "$a" > "$T/ca";; esac; done; IFS= read -r line; printf "%%s" "$line" > "$T/stdin"; }\nmain "$@"\n' > downloads/install-node.sh`)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	server := exec.Command(openssl, "s_server", "-WWW", "-quiet", "-accept", fmt.Sprint(port), "-cert", "server.pem", "-key", "key.pem")
	server.Dir = directory
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Process.Kill(); _ = server.Wait() })
	origin := fmt.Sprintf("https://127.0.0.1:%d", port)
	for attempt := 0; attempt < 100; attempt++ {
		if exec.Command("curl", "-k", "-fsS", "-o", "/dev/null", origin+"/downloads/gateway-ca.pem").Run() == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	root, err := os.ReadFile(filepath.Join(directory, "downloads/gateway-ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(root)
	run := func(digest string) (string, error, string) {
		out := t.TempDir()
		command, err := InstallCommand(origin, testRegistrationKey, "203.0.113.7", "", true, false, digest, "", Gateway{})
		if err != nil {
			t.Fatal(err)
		}
		shell := exec.Command("bash", "-c", command)
		shell.Env = append(os.Environ(), "T="+out)
		shell.Stdin = strings.NewReader(string(InstallInput(testRegistrationKey, "")))
		output, err := shell.CombinedOutput()
		return out, err, string(output)
	}
	if out, err, _ := run(""); err == nil {
		t.Fatal("an unpinned self-signed console must not be trusted")
	} else if _, statErr := os.Stat(filepath.Join(out, "args")); statErr == nil {
		t.Fatal("installer ran without verification")
	}
	if out, err, output := run(strings.Repeat("ab", 32)); err == nil || !strings.Contains(output, "fingerprint does not match") {
		t.Fatalf("a wrong pin must stop: %v %s", err, output)
	} else if _, statErr := os.Stat(filepath.Join(out, "args")); statErr == nil {
		t.Fatal("installer ran with a wrong pin")
	}
	out, err, output := run(hex.EncodeToString(sum[:]))
	if err != nil {
		t.Fatalf("pinned install: %v %s", err, output)
	}
	args, _ := os.ReadFile(filepath.Join(out, "args"))
	ca, _ := os.ReadFile(filepath.Join(out, "ca"))
	stdin, _ := os.ReadFile(filepath.Join(out, "stdin"))
	if !strings.Contains(string(args), "--control-plane-ca-sha256\n"+hex.EncodeToString(sum[:])+"\n") ||
		string(ca) != string(root) || string(stdin) != testRegistrationKey {
		t.Fatalf("installer got args=%q ca-match=%v stdin=%q", args, string(ca) == string(root), stdin)
	}
}
