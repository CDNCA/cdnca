package nativebackup

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func TestAllowedAddressRefusesMetadataAndLoopback(t *testing.T) {
	for _, value := range []string{"169.254.169.254", "127.0.0.1", "::1", "0.0.0.0", "fe80::1", "224.0.0.1"} {
		if allowedAddress(netip.MustParseAddr(value), dialOptions{}) {
			t.Fatalf("%s must be refused", value)
		}
	}
	for _, value := range []string{"10.0.0.5", "192.168.1.10", "203.0.113.7"} {
		if !allowedAddress(netip.MustParseAddr(value), dialOptions{}) {
			t.Fatalf("%s must be allowed", value)
		}
	}
}

func TestTargetValidationAndRedaction(t *testing.T) {
	s3 := Target{Name: "offsite", Kind: "s3", Endpoint: "https://s3.example.com", Region: "us-east-1", Bucket: "cdnca-backups",
		Prefix: "control/", AccessKey: "AKIAEXAMPLE", SecretKey: "secret-value-123"}
	if err := s3.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Target){
		func(target *Target) { target.Endpoint = "http://s3.example.com" },
		func(target *Target) { target.Prefix = "../" },
		func(target *Target) { target.SecretKey = "" },
		func(target *Target) { target.Name = "Bad Name" },
	} {
		bad := s3
		mutate(&bad)
		if bad.Validate() == nil {
			t.Fatalf("invalid target accepted: %+v", bad)
		}
	}
	view := s3.Redacted()
	for _, value := range view {
		if text, ok := value.(string); ok && (strings.Contains(text, "secret-value") || text == "AKIAEXAMPLE") {
			t.Fatalf("redacted view leaks a secret: %v", view)
		}
	}
	sftpTarget := Target{Name: "nas", Kind: "sftp", Host: "10.0.0.9", Port: 22, Username: "backup", RemoteDir: "/backups",
		HostKeySHA256: "SHA256:" + strings.Repeat("A", 43), Password: "pw", PrivateKey: "key"}
	if sftpTarget.Validate() == nil {
		t.Fatal("password and private key together must be refused")
	}
}

func sftpServer(t *testing.T, password string) (string, int, string) {
	t.Helper()
	_, hostPrivate, _ := ed25519.GenerateKey(rand.Reader)
	signer, err := ssh.NewSignerFromKey(hostPrivate)
	if err != nil {
		t.Fatal(err)
	}
	config := &ssh.ServerConfig{PasswordCallback: func(meta ssh.ConnMetadata, given []byte) (*ssh.Permissions, error) {
		if meta.User() == "backup" && string(given) == password {
			return nil, nil
		}
		return nil, errors.New("denied")
	}}
	config.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				_, channels, requests, err := ssh.NewServerConn(connection, config)
				if err != nil {
					_ = connection.Close()
					return
				}
				go ssh.DiscardRequests(requests)
				for channel := range channels {
					if channel.ChannelType() != "session" {
						_ = channel.Reject(ssh.UnknownChannelType, "")
						continue
					}
					accepted, requests, _ := channel.Accept()
					go func() {
						for request := range requests {
							ok := request.Type == "subsystem" && len(request.Payload) > 4 && string(request.Payload[4:]) == "sftp"
							_ = request.Reply(ok, nil)
							if ok {
								if server, err := sftp.NewServer(accepted); err == nil {
									_ = server.Serve()
								}
								_ = accepted.Close()
							}
						}
					}()
				}
			}()
		}
	}()
	return "127.0.0.1", listener.Addr().(*net.TCPAddr).Port, HostKeySHA256(signer.PublicKey())
}

func TestSFTPUploadDownloadRoundTripWithPinnedHostKey(t *testing.T) {
	rig := newRig(t)
	result, err := rig.backuper(nil).Run(context.Background(), BackupRequest{Reason: "manual", OutputDirectory: filepath.Join(rig.root, "out")})
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := OpenBundle(result.Directory, rig.keys.Fingerprint())
	if err != nil {
		t.Fatal(err)
	}
	host, port, fingerprint := sftpServer(t, "sftp-password-2026")
	ctx := context.Background()
	options := dialOptions{allowLoopback: true}
	if got, err := fetchHostKey(ctx, host, port, options); err != nil || got != fingerprint {
		t.Fatalf("host key %q %v", got, err)
	}
	remoteDir := filepath.Join(t.TempDir(), "remote")
	target := Target{Name: "nas", Kind: "sftp", Host: host, Port: port, Username: "backup", RemoteDir: remoteDir,
		HostKeySHA256: "SHA256:" + strings.Repeat("B", 43), Password: "sftp-password-2026"}
	wrong, err := openStorage(target, options)
	if err != nil {
		t.Fatal(err)
	}
	if err := wrong.Probe(ctx); !errors.Is(err, ErrHostKeyMismatch) {
		t.Fatalf("a different host key must be refused: %v", err)
	}
	target.HostKeySHA256 = fingerprint
	storage, err := openStorage(target, options)
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	if err := storage.Probe(ctx); err != nil {
		t.Fatal(err)
	}
	if err := Upload(ctx, storage, bundle); err != nil {
		t.Fatal(err)
	}
	ids, err := storage.List(ctx)
	if err != nil || len(ids) != 1 || ids[0] != result.BackupID {
		t.Fatalf("list = %v %v", ids, err)
	}
	downloaded, err := Download(ctx, storage, result.BackupID, filepath.Join(t.TempDir(), "in"), rig.keys.Fingerprint())
	if err != nil {
		t.Fatal(err)
	}
	if err := downloaded.VerifyAll(rig.keys.Identity); err != nil {
		t.Fatal(err)
	}
	if _, err := Download(ctx, storage, result.BackupID, filepath.Join(t.TempDir(), "in2"), "SHA256:"+strings.Repeat("C", 43)); !errors.Is(err, ErrSignatureMismatch) {
		t.Fatalf("download must refuse an unpinned signer: %v", err)
	}
	var files []string
	for _, component := range bundle.Manifest.Components {
		files = append(files, component.File)
	}
	if err := storage.DeleteBackup(ctx, result.BackupID, append(files, manifestFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(remoteDir, result.BackupID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("remote backup must be gone: %v", err)
	}
}
