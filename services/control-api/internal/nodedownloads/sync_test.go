package nodedownloads

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

type release struct {
	archive    []byte
	status     int
	archiveGET atomic.Int32
}

func (r *release) server(t *testing.T) *httptest.Server {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if r.status != 0 {
			w.WriteHeader(r.status)
			return
		}
		switch req.URL.Path {
		case "/ce/downloads/edge-agent/latest/SHA256SUMS":
			sum := sha256.Sum256(r.archive)
			_, _ = io.WriteString(w, hex.EncodeToString(sum[:])+"  cdnca-edge-agent.tar.gz\n")
		case "/ce/downloads/edge-agent/latest/cdnca-edge-agent.tar.gz":
			r.archiveGET.Add(1)
			_, _ = w.Write(r.archive)
		default:
			http.NotFound(w, req)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

// served writes the console's current node package (what install-control.sh left).
func served(t *testing.T, archive string) string {
	data := filepath.Join(t.TempDir(), "cdnca-control")
	latest := filepath.Join(data, "downloads", "edge-agent", "latest")
	if err := os.MkdirAll(latest, 0o755); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(archive))
	writeFile(t, filepath.Join(latest, ArchiveName), archive)
	writeFile(t, filepath.Join(latest, ChecksumsName), hex.EncodeToString(sum[:])+"  "+ArchiveName+"\n")
	writeFile(t, filepath.Join(data, "downloads", "edge-agent", "artifacts.json"), `{"version":1,"keys":[]}`)
	return filepath.Join(data, "downloads")
}

func writeFile(t *testing.T, path, content string) {
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func newSyncer(t *testing.T, server *httptest.Server, downloads string, verify func(context.Context, string, string, string) (Facts, error)) *Syncer {
	s, err := New(Config{Source: server.URL + "/ce", DownloadDir: downloads, ControlVersion: "1.0.35", Interval: 1,
		Client: server.Client(), Verify: verify, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func facts(version string) Facts {
	var f Facts
	f.Version = version
	f.Source.Commit = "c0ffee"
	return f
}

func servedArchive(t *testing.T, downloads string) string {
	content, err := os.ReadFile(filepath.Join(downloads, "edge-agent", "latest", ArchiveName))
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}

func TestSyncReplacesTheServedPackageWithTheVerifiedRelease(t *testing.T) {
	r := &release{archive: []byte("new package")}
	server := r.server(t)
	downloads := served(t, "old package")
	var trust string
	s := newSyncer(t, server, downloads, func(_ context.Context, archive, trustFile, _ string) (Facts, error) {
		content, _ := os.ReadFile(archive)
		if string(content) != "new package" {
			return Facts{}, errors.New("verified another file")
		}
		trust = trustFile
		return facts("1.0.35"), nil
	})
	status := s.SyncOnce(t.Context())
	sum := sha256.Sum256(r.archive)
	if status.State != StateCurrent || status.ServedSHA256 != hex.EncodeToString(sum[:]) || status.UpdatedAt == nil ||
		status.SourceVersion != "1.0.35" {
		t.Fatalf("status = %+v", status)
	}
	if got := servedArchive(t, downloads); got != "new package" {
		t.Fatalf("served = %q", got)
	}
	if trust != filepath.Join(downloads, "edge-agent", "artifacts.json") {
		t.Fatalf("verified against %q, want the console's own artifact trust", trust)
	}
	sums, _ := os.ReadFile(filepath.Join(downloads, "edge-agent", "latest", ChecksumsName))
	if string(sums) != hex.EncodeToString(sum[:])+"  "+ArchiveName+"\n" {
		t.Fatalf("SHA256SUMS = %q", sums)
	}
	for _, name := range []string{ArchiveName, ChecksumsName} {
		if info, _ := os.Stat(filepath.Join(downloads, "edge-agent", "latest", name)); info.Mode().Perm() != 0o644 {
			t.Fatalf("%s mode = %v", name, info.Mode())
		}
	}
	// Up to date: SHA256SUMS only, no second archive download.
	if status := s.SyncOnce(t.Context()); status.State != StateCurrent || r.archiveGET.Load() != 1 {
		t.Fatalf("second sync = %+v archive GETs %d", status, r.archiveGET.Load())
	}
	if entries, _ := filepath.Glob(filepath.Join(filepath.Dir(downloads), ".node-downloads-stage-*")); len(entries) != 0 {
		t.Fatalf("stage left behind: %v", entries)
	}
}

func TestSyncKeepsTheServedPackageWhenFetchOrVerificationFails(t *testing.T) {
	for name, tc := range map[string]struct {
		status int
		verify error
		reason string
	}{
		"release server down": {status: http.StatusBadGateway, reason: "source_unreachable"},
		"signature refused":   {verify: errors.New("native package rejected"), reason: "signature_invalid"},
	} {
		t.Run(name, func(t *testing.T) {
			r := &release{archive: []byte("tampered package"), status: tc.status}
			downloads := served(t, "old package")
			s := newSyncer(t, r.server(t), downloads, func(context.Context, string, string, string) (Facts, error) {
				return facts("1.0.35"), tc.verify
			})
			status := s.SyncOnce(t.Context())
			if status.State != StateFailed || status.Reason != tc.reason || status.UpdatedAt != nil {
				t.Fatalf("status = %+v", status)
			}
			if got := servedArchive(t, downloads); got != "old package" {
				t.Fatalf("served = %q, the old package must stay", got)
			}
			if got := s.Status(); got.State != StateFailed {
				t.Fatalf("Status() = %+v", got)
			}
		})
	}
}

func TestSyncWaitsForAManagementUpgradeOnAnotherVersion(t *testing.T) {
	r := &release{archive: []byte("1.0.36 package")}
	downloads := served(t, "old package")
	verified := 0
	s := newSyncer(t, r.server(t), downloads, func(context.Context, string, string, string) (Facts, error) {
		verified++
		return facts("1.0.36"), nil
	})
	for range 2 {
		if status := s.SyncOnce(t.Context()); status.State != StateWaiting || status.SourceVersion != "1.0.36" {
			t.Fatalf("status = %+v", status)
		}
	}
	if verified != 1 || r.archiveGET.Load() != 1 {
		t.Fatalf("the refused release was downloaded %d / verified %d times", r.archiveGET.Load(), verified)
	}
	if got := servedArchive(t, downloads); got != "old package" {
		t.Fatalf("served = %q", got)
	}
}

func TestSourceURLAndConfig(t *testing.T) {
	for _, bad := range []string{"http://auth.example", "https://", "https://u@auth.example", "https://auth.example/?x=1"} {
		if _, err := SourceURL(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if got, err := SourceURL("https://www.cdnca.com/downloads/ce/"); err != nil || got != "https://www.cdnca.com/downloads/ce" {
		t.Fatalf("community source = %q, %v", got, err)
	}
	if _, err := New(Config{Source: "https://auth.example", DownloadDir: "relative", ControlVersion: "1.0.35", Interval: 1}); err == nil {
		t.Fatal("relative download directory accepted")
	}
}

func TestVerifyWithInstallerReadsTheReleaseFacts(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.sh")
	writeFile(t, good, "echo noise; echo '{\"version\":\"1.0.35\",\"source\":{\"commit\":\"abc\"}}'\n")
	bad := filepath.Join(dir, "bad.sh")
	writeFile(t, bad, "echo 'native package rejected: signature' >&2; exit 1\n")
	if f, err := verifyWithInstaller(t.Context(), []string{filepath.Join(dir, "missing"), good}, "a", "t", "s"); err != nil ||
		f.Version != "1.0.35" || f.Source.Commit != "abc" {
		t.Fatalf("facts = %+v, %v", f, err)
	}
	if _, err := verifyWithInstaller(t.Context(), []string{bad}, "a", "t", "s"); err == nil {
		t.Fatal("a refused package verified")
	}
	if _, err := verifyWithInstaller(t.Context(), nil, "a", "t", "s"); err == nil {
		t.Fatal("no installer")
	}
}

// The real installer refuses an unsigned archive.
func TestVerifyWithTheRealInstallerRefusesAnUnsignedArchive(t *testing.T) {
	installer, _ := filepath.Abs("../../../../scripts/install-node.sh")
	dir := t.TempDir()
	archive := filepath.Join(dir, "a.tar.gz")
	writeFile(t, archive, "not a signed package")
	trust := filepath.Join(dir, "artifacts.json")
	writeFile(t, trust, `{"version":1,"keys":[]}`)
	if _, err := verifyWithInstaller(t.Context(), []string{installer}, archive, trust, filepath.Join(dir, "stage")); err == nil {
		t.Fatal("unsigned archive verified")
	}
	if _, err := os.Stat(filepath.Join(dir, "stage")); !os.IsNotExist(err) {
		t.Fatalf("stage created for a refused archive: %v", err)
	}
}
