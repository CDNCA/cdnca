package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func call(t *testing.T, args ...string) (int, []byte) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	if code != 0 && strings.Contains(stderr.String(), "PRIVATE") {
		t.Fatalf("stderr must not echo key material: %q", stderr.String())
	}
	return code, stdout.Bytes()
}

func write(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRoundTripAndFormats(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "key.pem")
	if code, _ := call(t, "genkey", key); code != 0 {
		t.Fatalf("genkey failed: %d", code)
	}
	info, err := os.Stat(key)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("private key must be 0600: %v %v", info.Mode(), err)
	}
	// Never overwrite an existing key.
	if code, _ := call(t, "genkey", key); code != 1 {
		t.Fatalf("genkey replaced an existing file")
	}
	block, _ := pem.Decode(mustRead(t, key))
	if block.Type != "PRIVATE KEY" || len(block.Bytes) != 48 || !bytes.Equal(block.Bytes[:16], pkcs8Prefix) {
		t.Fatalf("unexpected PKCS#8 encoding")
	}
	code, publicPEM := call(t, "pubkey", key)
	if code != 0 || !bytes.HasPrefix(publicPEM, []byte("-----BEGIN PUBLIC KEY-----\n")) {
		t.Fatalf("pubkey failed")
	}
	code, publicDER := call(t, "pubkey", key, "--der")
	if code != 0 || len(publicDER) != 44 || !bytes.Equal(publicDER[:12], spkiPrefix) {
		t.Fatalf("DER public key must be 44-byte SPKI")
	}
	public := write(t, dir, "public.pem", publicPEM)
	message := write(t, dir, "message", []byte("cdnca.native-management.install/v2\n{}"))
	code, signature := call(t, "sign", key, message)
	if code != 0 || len(signature) != 64 {
		t.Fatalf("sign must print a 64-byte signature")
	}
	sigfile := write(t, dir, "signature", signature)
	if code, _ := call(t, "verify", public, message, sigfile); code != 0 {
		t.Fatalf("valid signature rejected")
	}
	if code, _ := call(t, "check-public", public); code != 0 {
		t.Fatalf("check-public rejected a valid key")
	}
	for index := range signature {
		tampered := append([]byte{}, signature...)
		tampered[index] ^= 0x01
		if code, _ := call(t, "verify", public, message, write(t, dir, "tampered", tampered)); code != 1 {
			t.Fatalf("tampered signature byte %d accepted", index)
		}
	}
	if code, _ := call(t, "verify", public, write(t, dir, "other", []byte("other message")), sigfile); code != 1 {
		t.Fatalf("signature accepted for a different message")
	}
}

func TestRejectsMalformedInputs(t *testing.T) {
	dir := t.TempDir()
	_, private, _ := ed25519.GenerateKey(nil)
	der := append(append([]byte{}, spkiPrefix...), private.Public().(ed25519.PublicKey)...)
	good := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	cases := map[string][]byte{
		"trailing block":  append(append([]byte{}, good...), good...),
		"trailing text":   append(append([]byte{}, good...), []byte("garbage\n")...),
		"leading text":    append([]byte("garbage\n"), good...),
		"wrong type":      pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}),
		"headers":         pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: der}),
		"short key":       pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der[:43]}),
		"wrong algorithm": pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: append([]byte{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x71, 0x03, 0x21, 0x00}, der[12:]...)}),
		"empty":           {},
		"oversized":       bytes.Repeat([]byte("A"), maxPEMBytes+1),
	}
	for name, data := range cases {
		if code, _ := call(t, "check-public", write(t, dir, "key", data)); code != 1 {
			t.Fatalf("%s accepted", name)
		}
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(write(t, dir, "real", good), link); err != nil {
		t.Fatal(err)
	}
	if code, _ := call(t, "check-public", link); code != 1 {
		t.Fatalf("symlinked key accepted")
	}
	if code, _ := call(t, "check-public", dir); code != 1 {
		t.Fatalf("directory accepted")
	}
	message := write(t, dir, "message", []byte("m"))
	public := write(t, dir, "public", good)
	for _, size := range []int{0, 63, 65} {
		if code, _ := call(t, "verify", public, message, write(t, dir, "sig", make([]byte, size))); code != 1 {
			t.Fatalf("signature of %d bytes accepted", size)
		}
	}
	for _, args := range [][]string{{}, {"verify"}, {"genkey"}, {"pubkey", "a", "--pem"}, {"unknown"}} {
		if code, _ := call(t, args...); code != 2 {
			t.Fatalf("usage error expected for %v", args)
		}
	}
}

// Byte compatibility with OpenSSL 3 when it is available (CI and dev hosts).
func TestOpenSSLInteroperability(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not installed")
	}
	if out, err := exec.Command(openssl, "version").Output(); err != nil || !bytes.HasPrefix(out, []byte("OpenSSL 3.")) {
		t.Skip("OpenSSL 3 is required for pkeyutl -rawin")
	}
	dir := t.TempDir()
	message := write(t, dir, "message", []byte("interop message\n"))
	// OpenSSL key and signature, verified by the tool.
	opensslKey := filepath.Join(dir, "openssl.key")
	opensslPub := filepath.Join(dir, "openssl.pub")
	opensslSig := filepath.Join(dir, "openssl.sig")
	for _, args := range [][]string{
		{"genpkey", "-algorithm", "ED25519", "-out", opensslKey},
		{"pkey", "-in", opensslKey, "-pubout", "-out", opensslPub},
		{"pkeyutl", "-sign", "-rawin", "-inkey", opensslKey, "-in", message, "-out", opensslSig},
	} {
		if out, err := exec.Command(openssl, args...).CombinedOutput(); err != nil {
			t.Fatalf("openssl %v: %v %s", args[0], err, out)
		}
	}
	if code, _ := call(t, "verify", opensslPub, message, opensslSig); code != 0 {
		t.Fatalf("tool rejected an OpenSSL signature")
	}
	code, derivedPEM := call(t, "pubkey", opensslKey)
	if code != 0 || !bytes.Equal(derivedPEM, mustRead(t, opensslPub)) {
		t.Fatalf("tool and OpenSSL derive different public keys")
	}
	code, toolSig := call(t, "sign", opensslKey, message)
	if code != 0 || !bytes.Equal(toolSig, mustRead(t, opensslSig)) {
		t.Fatalf("Ed25519 is deterministic; signatures must be identical")
	}
	// Tool key and signature, verified by OpenSSL.
	toolKey := filepath.Join(dir, "tool.key")
	if code, _ := call(t, "genkey", toolKey); code != 0 {
		t.Fatal("genkey failed")
	}
	_, toolPub := call(t, "pubkey", toolKey)
	_, signature := call(t, "sign", toolKey, message)
	toolPubPath := write(t, dir, "tool.pub", toolPub)
	toolSigPath := write(t, dir, "tool.sig", signature)
	if out, err := exec.Command(openssl, "pkeyutl", "-verify", "-pubin", "-inkey", toolPubPath, "-rawin",
		"-in", message, "-sigfile", toolSigPath).CombinedOutput(); err != nil {
		t.Fatalf("OpenSSL rejected the tool signature: %s", out)
	}
	if out, err := exec.Command(openssl, "pkey", "-in", toolKey, "-noout").CombinedOutput(); err != nil {
		t.Fatalf("OpenSSL cannot read the tool private key: %s", out)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
