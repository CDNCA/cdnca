package updater

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
)

// fix-btenv3: a node follows its control plane's download endpoint (moved
// host, plain <-> BaoTa port and root) through the control-signed policy of
// the next upgrade execution, without being reinstalled.

// tlsArtifactServer serves body on 127.0.0.1 with a certificate for "cdnca.com".
func tlsArtifactServer(t *testing.T, body []byte) (*httptest.Server, uint16, []byte) {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write(body)
	}))
	server.EnableHTTP2 = false
	server.StartTLS()
	t.Cleanup(server.Close)
	root := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	_, portText, _ := net.SplitHostPort(server.Listener.Addr().String())
	port, _ := strconv.ParseUint(portText, 10, 16)
	return server, uint16(port), root
}

func TestPolicyDownloaderAdoptsNewerSameHostPolicyAndPersistsIt(t *testing.T) {
	// httptest certificates name example.com; the download host must match it.
	_, oldPort, oldRoot := tlsArtifactServer(t, []byte("old"))
	_, newPort, newRoot := tlsArtifactServer(t, []byte("new"))
	dir := filepath.Join(t.TempDir(), "download-policy")
	installed := InstalledDownloadPolicy{Host: "example.com", Port: oldPort, Addresses: []string{"127.0.0.1"}, RootPEM: oldRoot, Timeout: 5 * time.Second}
	downloader, err := NewPolicyDownloader(dir, installed)
	if err != nil {
		t.Fatal(err)
	}
	fetch := func(d *PolicyDownloader, port uint16) (string, error) {
		var out bytes.Buffer
		err := d.Download(context.Background(), DownloadRequest{URL: "https://example.com:" + strconv.Itoa(int(port)) + "/a", MaxBytes: 16}, &out)
		return out.String(), err
	}
	if got, err := fetch(downloader, oldPort); err != nil || got != "old" {
		t.Fatalf("installed endpoint = %q, %v", got, err)
	}
	newURL := "https://example.com:" + strconv.Itoa(int(newPort)) + "/a"
	policy := &entitlement.UpgradeDownloadPolicy{Host: "example.com", Port: newPort, Addresses: []string{"127.0.0.1"}, RootCA: string(newRoot)}
	for name, candidate := range map[string]*entitlement.UpgradeDownloadPolicy{
		"other host":             {Host: "www.example.com", Port: newPort, Addresses: []string{"127.0.0.1"}, RootCA: string(newRoot)},
		"port mismatch with URL": {Host: "example.com", Port: newPort + 1, Addresses: []string{"127.0.0.1"}, RootCA: string(newRoot)},
	} {
		if changed, err := downloader.Adopt(candidate, newURL, 100); changed || err != nil {
			t.Fatalf("%s: adopted (%v, %v)", name, changed, err)
		}
	}
	if changed, err := downloader.Adopt(policy, newURL, 100); !changed || err != nil {
		t.Fatalf("adopt = (%v, %v)", changed, err)
	}
	if _, err := fetch(downloader, oldPort); !errors.Is(err, ErrDownloadPolicy) {
		t.Fatalf("old port must be outside the adopted policy, got %v", err)
	}
	if got, err := fetch(downloader, newPort); err != nil || got != "new" {
		t.Fatalf("adopted endpoint = %q, %v", got, err)
	}
	// An older execution (issued before) cannot roll the endpoint back.
	back := &entitlement.UpgradeDownloadPolicy{Host: "example.com", Port: oldPort, Addresses: []string{"127.0.0.1"}, RootCA: string(oldRoot)}
	if changed, _ := downloader.Adopt(back, "https://example.com:"+strconv.Itoa(int(oldPort))+"/a", 99); changed {
		t.Fatal("an older policy must not replace a newer one")
	}
	info, err := os.Stat(filepath.Join(dir, downloadPolicyStateFile))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("persisted policy = %v, %v", info, err)
	}
	restarted, err := NewPolicyDownloader(dir, installed)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := fetch(restarted, newPort); err != nil || got != "new" || restarted.Current().Port != newPort {
		t.Fatalf("after restart = %q, %v (%+v)", got, err, restarted.Current())
	}
	// "system" keeps the root pinned at install time.
	systemPolicy := &entitlement.UpgradeDownloadPolicy{Host: "example.com", Port: oldPort, Addresses: []string{"127.0.0.1"}, RootCA: entitlement.UpgradeDownloadSystemRoot}
	if changed, err := restarted.Adopt(systemPolicy, "https://example.com:"+strconv.Itoa(int(oldPort))+"/a", 200); !changed || err != nil {
		t.Fatalf("system root adopt = (%v, %v)", changed, err)
	}
	if got, err := fetch(restarted, oldPort); err != nil || got != "old" {
		t.Fatalf("system root endpoint = %q, %v", got, err)
	}
	// A corrupt state file falls back to the installed endpoint.
	if err := os.WriteFile(filepath.Join(dir, downloadPolicyStateFile), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	fallback, err := NewPolicyDownloader(dir, installed)
	if err != nil || fallback.Current().Port != oldPort || fallback.Current().RootCA != entitlement.UpgradeDownloadSystemRoot {
		t.Fatalf("corrupt state = %+v, %v", fallback.Current(), err)
	}
}

// The runtime adopts the policy only from an execution whose control
// signature verifies; a forged policy changes nothing and is not accepted.
func TestUpgradeRuntimeAdoptsControlSignedDownloadPolicyBeforeAccept(t *testing.T) {
	fixture := newExecutionV2Fixture(t)
	fixture.execution.DownloadURL = "https://cdnca.com:19445/downloads/edge-agent/upgrades/sha256/ab"
	policy := &entitlement.UpgradeDownloadPolicy{Host: "cdnca.com", Port: 19445, Addresses: []string{"203.0.113.9"}, RootCA: entitlement.UpgradeDownloadSystemRoot}
	fixture.execution.DownloadPolicy = policy
	resignExecutionFixture(t, &fixture)
	newRuntime := func(t *testing.T) (*UpgradeRuntime, *PolicyDownloader, *DurableUpgradeStore) {
		store, err := NewDurableUpgradeStore(filepath.Join(t.TempDir(), "updater"))
		if err != nil {
			t.Fatal(err)
		}
		_, _, root := tlsArtifactServer(t, nil)
		downloader, err := NewPolicyDownloader(filepath.Join(t.TempDir(), "download-policy"), InstalledDownloadPolicy{
			Host: "cdnca.com", Port: 443, Addresses: []string{"198.51.100.1"}, RootPEM: root, Timeout: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		runtime, err := NewUpgradeRuntime(UpgradeRuntimeConfig{Store: store, Manager: &recordingUpgradeManager{},
			Options: fixture.options(), Now: func() time.Time { return fixture.now.Add(2 * time.Minute) }, DownloadPolicy: downloader})
		if err != nil {
			t.Fatal(err)
		}
		return runtime, downloader, store
	}

	runtime, downloader, _ := newRuntime(t)
	if err := runtime.AcceptCommand(context.Background(), encodeUpgradeCommand(t, fixture, fixture.encoded)); err != nil {
		t.Fatal(err)
	}
	if current := downloader.Current(); current.Port != 19445 || current.Addresses[0] != "203.0.113.9" {
		t.Fatalf("adopted policy = %+v", current)
	}

	forged := fixture.envelope
	forgedPolicy := *policy
	forgedPolicy.Addresses = []string{"192.0.2.66"}
	forged.Execution.DownloadPolicy = &forgedPolicy
	encoded, err := json.Marshal(forged)
	if err != nil {
		t.Fatal(err)
	}
	runtime, downloader, store := newRuntime(t)
	if err := runtime.AcceptCommand(context.Background(), encodeUpgradeCommand(t, fixture, encoded)); !errors.Is(err, ErrInvalidUpgradeExecutionControlSignature) {
		t.Fatalf("forged policy error = %v", err)
	}
	if current := downloader.Current(); current.Port != 443 || current.Addresses[0] != "198.51.100.1" {
		t.Fatalf("forged policy must not be adopted: %+v", current)
	}
	if commands, _ := store.PendingCommands(context.Background()); len(commands) != 0 {
		t.Fatal("forged command must not be accepted")
	}
}
