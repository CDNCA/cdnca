package http3runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

type noOpProbe struct{}

func (noOpProbe) TCP(context.Context, Policy) error   { return nil }
func (noOpProbe) HTTP3(context.Context, Policy) error { return nil }

type recordingProbe struct {
	tcpCalls   int
	http3Calls int
}

func (probe *recordingProbe) TCP(context.Context, Policy) error {
	probe.tcpCalls++
	return nil
}

func (probe *recordingProbe) HTTP3(context.Context, Policy) error {
	probe.http3Calls++
	return nil
}

func TestSupportsRuntimeRequiresExactVersionAndQUICFeatures(t *testing.T) {
	valid := "nginx version: openresty/" + RuntimeVersionOpenResty + " --with-http_ssl_module --with-http_v2_module --with-http_v3_module"
	ref := RuntimeRef{Family: RuntimeFamilyOpenResty, Version: RuntimeVersionOpenResty}
	if !supportsRuntime(valid, ref) {
		t.Fatal("supported runtime was rejected")
	}
	for name, output := range map[string]string{
		"wrong version": strings.Replace(valid, RuntimeVersionOpenResty, "1.27.1.2", 1),
		"no QUIC":       strings.Replace(valid, "--with-http_v3_module", "", 1),
		"no HTTP2":      strings.Replace(valid, "--with-http_v2_module", "", 1),
		"no TLS":        strings.Replace(valid, "--with-http_ssl_module", "", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if supportsRuntime(output, ref) {
				t.Fatal("unsupported runtime was accepted")
			}
		})
	}
}

func TestCheckBindingsRejectsTCPAndUDPPortConflicts(t *testing.T) {
	t.Run("TCP", func(t *testing.T) {
		occupied, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer occupied.Close()
		port := occupied.Addr().(*net.TCPAddr).Port
		if err := checkBindings(context.Background(), Listener{Address: "127.0.0.1", Port: port}, true); !errors.Is(err, ErrPortConflict) {
			t.Fatalf("checkBindings()=%v", err)
		}
	})
	t.Run("UDP", func(t *testing.T) {
		occupied, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer occupied.Close()
		port := occupied.LocalAddr().(*net.UDPAddr).Port
		if err := checkBindings(context.Background(), Listener{Address: "127.0.0.1", Port: port}, true); !errors.Is(err, ErrPortConflict) {
			t.Fatalf("checkBindings()=%v", err)
		}
	})
	t.Run("HTTP3 disabled ignores UDP", func(t *testing.T) {
		occupied, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer occupied.Close()
		port := occupied.LocalAddr().(*net.UDPAddr).Port
		if err := checkBindings(context.Background(), Listener{Address: "127.0.0.1", Port: port}, false); err != nil {
			t.Fatalf("HTTP/3-disabled binding consulted UDP: %v", err)
		}
	})
}

func TestHealthySkipsHTTP3ProbeWhenDisabled(t *testing.T) {
	fixture := newManagerTLSFixture(t, "http3-off")
	fixture.policy.Protocols = []string{"http1", "http2"}
	candidate := writeSealedPrecheckCandidate(t, fixture)
	probe := &recordingProbe{}
	runtime := newPrecheckRuntime(t)
	runtime.probe = probe
	master := testProcessIdentity(42, 100)
	worker := testWorkerIdentity(master, 43, 101)
	runtime.inspect = func(int) (processIdentity, error) { return master, nil }
	runtime.workers = func(processIdentity) ([]processIdentity, error) { return []processIdentity{worker}, nil }
	runtime.generation = workerGeneration{Master: master, Workers: []processIdentity{worker}}
	if err := runtime.Healthy(context.Background(), candidate); err != nil {
		t.Fatal(err)
	}
	if probe.tcpCalls != 1 || probe.http3Calls != 0 {
		t.Fatalf("unexpected health probes: tcp=%d http3=%d", probe.tcpCalls, probe.http3Calls)
	}
}

func TestVerifyAssetChecksDigestAndRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "cert.pem")
	content := []byte("certificate fixture")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	if err := verifyAsset(path, hex.EncodeToString(digest[:])); err != nil {
		t.Fatal(err)
	}
	if err := verifyAsset(path, strings.Repeat("0", 64)); err == nil {
		t.Fatal("digest mismatch was accepted")
	}
	link := filepath.Join(root, "link.pem")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := verifyAsset(link, hex.EncodeToString(digest[:])); err == nil {
		t.Fatal("symlink asset was accepted")
	}
}

func newPrecheckRuntime(t *testing.T) *OpenResty {
	t.Helper()
	root := t.TempDir()
	binary := filepath.Join(root, "openresty-fixture")
	script := "#!/bin/sh\n" +
		"if [ \"${1:-}\" = \"-V\" ]; then\n" +
		"  echo 'nginx version: openresty/" + RuntimeVersionOpenResty + " --with-http_ssl_module --with-http_v2_module --with-http_v3_module' >&2\n" +
		"fi\n" +
		"exit 0\n"
	if err := os.WriteFile(binary, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	runDir := filepath.Join(root, "state", "run")
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		t.Fatal(err)
	}
	openresty, err := NewOpenResty(binary, filepath.Join(runDir, "nginx.pid"), time.Second, noOpProbe{})
	if err != nil {
		t.Fatal(err)
	}
	return openresty
}

func writeSealedPrecheckCandidate(t *testing.T, fixture managerTLSFixture) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fixture.policy.Listener.Address = "127.0.0.1"
	fixture.policy.Listener.Port = listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	compiled, err := Compile(fixture.policy)
	if err != nil {
		t.Fatal(err)
	}
	candidate := t.TempDir()
	for name, content := range map[string][]byte{
		"policy.json": compiled.CanonicalJSON,
		"nginx.conf":  compiled.NginxConfig,
	} {
		if err := os.WriteFile(filepath.Join(candidate, name), content, 0o400); err != nil {
			t.Fatal(err)
		}
	}
	tlsPath := filepath.Join(candidate, "tls")
	if err := os.Mkdir(tlsPath, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string][]byte{"server.crt": fixture.certificate, "server.key": fixture.privateKey} {
		if err := os.WriteFile(filepath.Join(tlsPath, name), content, 0o400); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(tlsPath, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(tlsPath, 0o700) })
	return candidate
}

func TestOpenRestyPrecheckUsesOnlySealedTLSAssets(t *testing.T) {
	t.Run("deleted sources", func(t *testing.T) {
		fixture := newManagerTLSFixture(t, "http3-v1")
		candidate := writeSealedPrecheckCandidate(t, fixture)
		if err := os.Remove(fixture.certificatePath); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(fixture.privateKeyPath); err != nil {
			t.Fatal(err)
		}
		if err := newPrecheckRuntime(t).Precheck(context.Background(), candidate); err != nil {
			t.Fatalf("Precheck() consulted deleted TLS sources: %v", err)
		}
	})

	t.Run("tampered sealed certificate", func(t *testing.T) {
		fixture := newManagerTLSFixture(t, "http3-v1")
		candidate := writeSealedPrecheckCandidate(t, fixture)
		certificatePath := filepath.Join(candidate, "tls", "server.crt")
		if err := os.Chmod(certificatePath, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(certificatePath, []byte("tampered sealed certificate\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(certificatePath, 0o400); err != nil {
			t.Fatal(err)
		}
		if err := newPrecheckRuntime(t).Precheck(context.Background(), candidate); err == nil {
			t.Fatal("Precheck() accepted a tampered sealed certificate")
		}
	})
}

func TestNewOpenRestyRejectsUnsafePaths(t *testing.T) {
	for _, pidFile := range []string{"relative.pid", "/tmp/http3 pid", "/tmp/http3;pid", "/tmp/http3\npid", "/tmp/not-run/nginx.pid"} {
		if _, err := NewOpenResty("/bin/true", pidFile, time.Second, noOpProbe{}); !errors.Is(err, ErrInvalidPath) {
			t.Errorf("NewOpenResty(pid=%q)=%v", pidFile, err)
		}
	}
	pidFile := filepath.Join(t.TempDir(), "run", "nginx.pid")
	if _, err := NewOpenResty("/bin/true", pidFile, time.Second, noOpProbe{}); err != nil {
		t.Fatalf("valid constructor=%v", err)
	}
}

type fakeHTTP3ProcessHandle struct {
	mu         sync.Mutex
	signals    []syscall.Signal
	alive      []bool
	aliveErr   error
	closeErr   error
	closeCalls int
	onSignal   func(syscall.Signal) error
	onClose    func()
}

func (handle *fakeHTTP3ProcessHandle) Signal(signal syscall.Signal) error {
	handle.mu.Lock()
	handle.signals = append(handle.signals, signal)
	handle.mu.Unlock()
	if handle.onSignal != nil {
		return handle.onSignal(signal)
	}
	return nil
}

func (handle *fakeHTTP3ProcessHandle) Alive() (bool, error) {
	handle.mu.Lock()
	defer handle.mu.Unlock()
	if handle.aliveErr != nil {
		return false, handle.aliveErr
	}
	if len(handle.alive) == 0 {
		return false, nil
	}
	alive := handle.alive[0]
	handle.alive = handle.alive[1:]
	return alive, nil
}

func (handle *fakeHTTP3ProcessHandle) Close() error {
	handle.mu.Lock()
	handle.closeCalls++
	handle.mu.Unlock()
	if handle.onClose != nil {
		handle.onClose()
	}
	return handle.closeErr
}

func (handle *fakeHTTP3ProcessHandle) snapshot() ([]syscall.Signal, int) {
	handle.mu.Lock()
	defer handle.mu.Unlock()
	return append([]syscall.Signal(nil), handle.signals...), handle.closeCalls
}

func newProcessRuntimeFixture(t *testing.T) (*OpenResty, string, string, processIdentity) {
	t.Helper()
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "run"), 0o700); err != nil {
		t.Fatal(err)
	}
	current := filepath.Join(root, "current")
	if err := os.Mkdir(current, 0o700); err != nil {
		t.Fatal(err)
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binaryInfo, err := os.Stat(binary)
	if err != nil {
		t.Fatal(err)
	}
	binaryStat := binaryInfo.Sys().(*syscall.Stat_t)
	pidFile := filepath.Join(root, "run", "nginx.pid")
	openresty, err := NewOpenResty(binary, pidFile, 250*time.Millisecond, noOpProbe{})
	if err != nil {
		t.Fatal(err)
	}
	openresty.identityOK = true
	identity := processIdentity{
		PID: 42, StartTicks: 12345, ExecutableDevice: uint64(binaryStat.Dev), ExecutableInode: uint64(binaryStat.Ino),
		OwnerUID: uint32(os.Geteuid()), BootID: "test-boot-id",
	}
	workerObservations := 0
	openresty.workers = func(master processIdentity) ([]processIdentity, error) {
		workerObservations++
		pid := 43
		if workerObservations > 1 {
			pid = 44
		}
		return []processIdentity{testWorkerIdentity(master, pid, uint64(12_000+pid))}, nil
	}
	return openresty, pidFile, current, identity
}

func testProcessIdentity(pid int, start uint64) processIdentity {
	return processIdentity{
		PID: pid, StartTicks: start, ExecutableDevice: 10, ExecutableInode: 20,
		OwnerUID: 1000, BootID: "test-boot-id",
	}
}

func testWorkerIdentity(master processIdentity, pid int, start uint64) processIdentity {
	worker := master
	worker.PID = pid
	worker.StartTicks = start
	return worker
}

func writeRuntimePolicy(t *testing.T, directory, versionID string) CompiledPolicy {
	t.Helper()
	compiled, err := Compile(validPolicy(versionID))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "policy.json"), compiled.CanonicalJSON, 0o400); err != nil {
		t.Fatal(err)
	}
	return compiled
}

func TestOpenRestyReloadFencesNewWorkerAndOldDrainBeforeHealth(t *testing.T) {
	openresty, pidFile, current, master := newProcessRuntimeFixture(t)
	writeProcessFixture(t, pidFile, master)
	writeRuntimePolicy(t, current, "http3-v2")
	probe := &recordingProbe{}
	openresty.probe = probe
	openresty.inspect = func(int) (processIdentity, error) { return master, nil }
	openresty.openProcess = func(int) (processHandle, error) { return &fakeHTTP3ProcessHandle{}, nil }
	oldWorker := testWorkerIdentity(master, 43, 200)
	newWorker := testWorkerIdentity(master, 44, 300)
	observations := 0
	openresty.workers = func(processIdentity) ([]processIdentity, error) {
		observations++
		switch observations {
		case 1:
			return []processIdentity{oldWorker}, nil
		case 2:
			return nil, nil
		case 3, 4:
			return []processIdentity{oldWorker, newWorker}, nil
		default:
			return []processIdentity{newWorker}, nil
		}
	}

	if err := openresty.Activate(context.Background(), current); err != nil {
		t.Fatalf("Activate()=%v", err)
	}
	if observations < 6 {
		t.Fatalf("Activate() returned before the new generation stabilized and the old worker drained: observations=%d", observations)
	}
	if probe.tcpCalls+probe.http3Calls != 0 {
		t.Fatalf("Activate() ran health probes: tcp=%d http3=%d", probe.tcpCalls, probe.http3Calls)
	}
	if err := openresty.Healthy(context.Background(), current); err != nil {
		t.Fatalf("Healthy()=%v", err)
	}
	if probe.tcpCalls != 1 || probe.http3Calls != 1 {
		t.Fatalf("health probes tcp=%d http3=%d", probe.tcpCalls, probe.http3Calls)
	}
}

func TestOpenRestyReloadRejectsMissingNewWorkerAndDrainTimeout(t *testing.T) {
	for _, test := range []struct {
		name    string
		workers func(processIdentity, processIdentity) func(processIdentity) ([]processIdentity, error)
		want    string
	}{
		{
			name: "new worker never appears",
			workers: func(oldWorker, _ processIdentity) func(processIdentity) ([]processIdentity, error) {
				return func(processIdentity) ([]processIdentity, error) { return []processIdentity{oldWorker}, nil }
			},
			want: "new worker",
		},
		{
			name: "old worker never drains",
			workers: func(oldWorker, newWorker processIdentity) func(processIdentity) ([]processIdentity, error) {
				calls := 0
				return func(processIdentity) ([]processIdentity, error) {
					calls++
					if calls == 1 {
						return []processIdentity{oldWorker}, nil
					}
					return []processIdentity{oldWorker, newWorker}, nil
				}
			},
			want: "drain",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			openresty, pidFile, current, master := newProcessRuntimeFixture(t)
			writeProcessFixture(t, pidFile, master)
			openresty.timeout = 45 * time.Millisecond
			openresty.inspect = func(int) (processIdentity, error) { return master, nil }
			openresty.openProcess = func(int) (processHandle, error) { return &fakeHTTP3ProcessHandle{}, nil }
			oldWorker := testWorkerIdentity(master, 43, 200)
			newWorker := testWorkerIdentity(master, 44, 300)
			openresty.workers = test.workers(oldWorker, newWorker)
			if err := openresty.Activate(context.Background(), current); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Activate()=%v, want %q failure", err, test.want)
			}
		})
	}
}

func TestOpenRestyHealthRejectsMixedOrMissingCandidateGenerationBeforeProbe(t *testing.T) {
	for _, workers := range [][]processIdentity{
		nil,
		{testWorkerIdentity(testProcessIdentity(42, 100), 43, 101), testWorkerIdentity(testProcessIdentity(42, 100), 44, 102)},
	} {
		t.Run(fmt.Sprintf("workers-%d", len(workers)), func(t *testing.T) {
			fixture := newManagerTLSFixture(t, "http3-v2")
			candidate := writeSealedPrecheckCandidate(t, fixture)
			probe := &recordingProbe{}
			openresty := newPrecheckRuntime(t)
			openresty.probe = probe
			master := testProcessIdentity(42, 100)
			candidateWorker := testWorkerIdentity(master, 44, 102)
			openresty.inspect = func(int) (processIdentity, error) { return master, nil }
			openresty.workers = func(processIdentity) ([]processIdentity, error) { return workers, nil }
			openresty.generation = workerGeneration{Master: master, Workers: []processIdentity{candidateWorker}}
			if err := openresty.Healthy(context.Background(), candidate); err == nil {
				t.Fatal("Healthy() accepted a missing or mixed candidate generation")
			}
			if probe.tcpCalls+probe.http3Calls != 0 {
				t.Fatalf("stale generation reached probes: tcp=%d http3=%d", probe.tcpCalls, probe.http3Calls)
			}
		})
	}
}

func TestOpenRestyActiveEvidenceRejectsVanishedCandidateWorker(t *testing.T) {
	openresty, pidFile, current, master := newProcessRuntimeFixture(t)
	if err := os.Remove(current); err != nil {
		t.Fatal(err)
	}
	compiled, err := Compile(validPolicy("http3-v2"))
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(filepath.Dir(current), "versions", compiled.Policy.VersionID+"-"+compiled.Digest)
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "policy.json"), compiled.CanonicalJSON, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("versions", filepath.Base(target)), current); err != nil {
		t.Fatal(err)
	}
	writeProcessFixture(t, pidFile, master)
	openresty.inspect = func(int) (processIdentity, error) { return master, nil }
	openresty.openProcess = func(int) (processHandle, error) {
		return &fakeHTTP3ProcessHandle{alive: []bool{true}}, nil
	}
	openresty.generation = workerGeneration{
		Master:  master,
		Workers: []processIdentity{testWorkerIdentity(master, 44, 300)},
	}
	openresty.workers = func(processIdentity) ([]processIdentity, error) { return nil, nil }
	if _, err := openresty.ActiveEvidence(context.Background(), current, compiled.Policy.VersionID, compiled.Digest); err == nil {
		t.Fatal("ActiveEvidence() accepted a vanished candidate worker")
	}
}

func writeProcessFixture(t *testing.T, pidFile string, identity processIdentity) {
	t.Helper()
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(identity.PID)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pidFile+".identity", []byte(formatProcessRecord(identity)), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestOpenRestyRejectsUnsafeSymlinkAndForeignProcessFiles(t *testing.T) {
	t.Run("unsafe PID mode", func(t *testing.T) {
		_, pidFile, _, identity := newProcessRuntimeFixture(t)
		if err := os.WriteFile(pidFile, []byte(strconv.Itoa(identity.PID)+"\n"), 0o666); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(pidFile, 0o666); err != nil {
			t.Fatal(err)
		}
		if _, _, err := readProcessPID(pidFile); err == nil {
			t.Fatal("world-writable PID file was accepted")
		}
	})

	t.Run("PID symlink", func(t *testing.T) {
		_, pidFile, _, identity := newProcessRuntimeFixture(t)
		realPID := pidFile + ".real"
		if err := os.WriteFile(realPID, []byte(strconv.Itoa(identity.PID)+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(realPID, pidFile); err != nil {
			t.Fatal(err)
		}
		if _, _, err := readProcessPID(pidFile); err == nil {
			t.Fatal("PID symlink was accepted")
		}
	})

	t.Run("identity symlink", func(t *testing.T) {
		openresty, pidFile, current, identity := newProcessRuntimeFixture(t)
		if err := os.WriteFile(pidFile, []byte(strconv.Itoa(identity.PID)+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		realIdentity := pidFile + ".identity.real"
		if err := os.WriteFile(realIdentity, []byte(formatProcessRecord(identity)), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(realIdentity, pidFile+".identity"); err != nil {
			t.Fatal(err)
		}
		starts := 0
		openresty.start = func(context.Context, []string, ...string) error { starts++; return nil }
		if err := openresty.Activate(context.Background(), current); err == nil {
			t.Fatal("identity symlink was accepted")
		}
		if starts != 0 {
			t.Fatalf("unsafe identity started OpenResty %d time(s)", starts)
		}
	})

	t.Run("pending symlink", func(t *testing.T) {
		openresty, pidFile, current, _ := newProcessRuntimeFixture(t)
		realPending := pidFile + ".identity.pending.real"
		if err := os.WriteFile(realPending, []byte("pending 1 2 3 "+strings.Repeat("0", 64)+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(realPending, pidFile+".identity.pending"); err != nil {
			t.Fatal(err)
		}
		starts := 0
		openresty.start = func(context.Context, []string, ...string) error { starts++; return nil }
		if err := openresty.Activate(context.Background(), current); err == nil {
			t.Fatal("pending identity symlink was accepted")
		}
		if starts != 0 {
			t.Fatalf("unsafe pending identity started OpenResty %d time(s)", starts)
		}
	})

	t.Run("foreign numeric PID", func(t *testing.T) {
		openresty, pidFile, current, _ := newProcessRuntimeFixture(t)
		if err := os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		starts := 0
		openresty.start = func(context.Context, []string, ...string) error { starts++; return nil }
		if err := openresty.Activate(context.Background(), current); err == nil {
			t.Fatal("foreign PID without an owned identity was accepted")
		}
		if starts != 0 {
			t.Fatalf("foreign PID started OpenResty %d time(s)", starts)
		}
	})
}

func TestProcessRunningRejectsReusedPIDIdentity(t *testing.T) {
	_, pidFile, _, record := newProcessRuntimeFixture(t)
	writeProcessFixture(t, pidFile, record)
	current := record
	inspect := func(int) (processIdentity, error) { return current, nil }
	if running, err := processRunning(pidFile, inspect); err != nil || !running {
		t.Fatalf("exact process identity running=%v error=%v", running, err)
	}
	changes := []struct {
		name   string
		change func(*processIdentity)
	}{
		{name: "start ticks", change: func(value *processIdentity) { value.StartTicks++ }},
		{name: "executable device", change: func(value *processIdentity) { value.ExecutableDevice++ }},
		{name: "executable inode", change: func(value *processIdentity) { value.ExecutableInode++ }},
		{name: "owner UID", change: func(value *processIdentity) { value.OwnerUID++ }},
		{name: "boot ID", change: func(value *processIdentity) { value.BootID += "-other" }},
	}
	for _, test := range changes {
		t.Run(test.name, func(t *testing.T) {
			current = record
			test.change(&current)
			if running, err := processRunning(pidFile, inspect); err == nil || running {
				t.Fatalf("reused process identity running=%v error=%v", running, err)
			}
		})
	}
	inspect = func(int) (processIdentity, error) { return processIdentity{}, errProcessNotRunning }
	if running, err := processRunning(pidFile, inspect); err != nil || running {
		t.Fatalf("exited process running=%v error=%v", running, err)
	}
}

func TestOpenRestyRechecksIdentityAfterPIDFDCapture(t *testing.T) {
	openresty, pidFile, current, record := newProcessRuntimeFixture(t)
	writeProcessFixture(t, pidFile, record)
	inspections := 0
	openresty.inspect = func(int) (processIdentity, error) {
		inspections++
		if inspections == 1 {
			return record, nil
		}
		changed := record
		changed.StartTicks++
		return changed, nil
	}
	handle := &fakeHTTP3ProcessHandle{}
	openresty.openProcess = func(int) (processHandle, error) { return handle, nil }
	if err := openresty.Activate(context.Background(), current); err == nil {
		t.Fatal("identity change after pidfd capture was accepted")
	}
	signals, closes := handle.snapshot()
	if len(signals) != 0 || closes != 1 {
		t.Fatalf("changed process signals=%v closes=%d", signals, closes)
	}
}

func TestOpenRestyPersistsAndRecoversPendingStart(t *testing.T) {
	t.Run("persist before start", func(t *testing.T) {
		openresty, pidFile, current, record := newProcessRuntimeFixture(t)
		openresty.inspect = func(int) (processIdentity, error) { return record, nil }
		handle := &fakeHTTP3ProcessHandle{}
		openresty.openProcess = func(int) (processHandle, error) { return handle, nil }
		var pending processStartIdentity
		openresty.start = func(_ context.Context, environment []string, arguments ...string) error {
			var exists bool
			var err error
			pending, exists, err = readOptionalProcessStartIdentity(pidFile + ".identity.pending")
			if err != nil || !exists {
				t.Fatalf("pending identity was not durable before start: exists=%v error=%v", exists, err)
			}
			if len(environment) != 1 || environment[0] != processStartEnvironment+"="+pending.Token {
				t.Fatalf("start environment=%v", environment)
			}
			global := "env " + processStartEnvironment + "=" + pending.Token + "; pid " + pidFile + ";"
			if !containsArgumentPair(arguments, "-g", global) {
				t.Fatalf("start arguments do not bind token and PID: %v", arguments)
			}
			return os.WriteFile(pidFile, []byte(strconv.Itoa(record.PID)+"\n"), 0o600)
		}
		openresty.matchStart = func(pid int, token string) error {
			if pid != record.PID || token != pending.Token {
				return fmt.Errorf("unexpected start identity pid=%d token=%q", pid, token)
			}
			return nil
		}
		if err := openresty.Activate(context.Background(), current); err != nil {
			t.Fatalf("Activate() start error=%v", err)
		}
		stored, err := readProcessRecord(pidFile + ".identity")
		if err != nil || stored != record {
			t.Fatalf("stored identity=%+v error=%v", stored, err)
		}
		if _, err := os.Stat(pidFile + ".identity.pending"); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("successful start left pending identity: %v", err)
		}
		if _, closes := handle.snapshot(); closes != 1 {
			t.Fatalf("started pidfd closes=%d", closes)
		}
	})

	t.Run("recover interrupted start", func(t *testing.T) {
		openresty, pidFile, current, record := newProcessRuntimeFixture(t)
		pending, err := newProcessStartIdentity(openresty.binary)
		if err != nil {
			t.Fatal(err)
		}
		record.ExecutableDevice = pending.ExecutableDevice
		record.ExecutableInode = pending.ExecutableInode
		record.OwnerUID = pending.OwnerUID
		if err := os.WriteFile(pidFile, []byte(strconv.Itoa(record.PID)+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(pidFile+".identity.pending", []byte(formatProcessStartIdentity(pending)), 0o600); err != nil {
			t.Fatal(err)
		}
		openresty.inspect = func(int) (processIdentity, error) { return record, nil }
		openresty.matchStart = func(_ int, token string) error {
			if token != pending.Token {
				return errors.New("wrong pending token")
			}
			return nil
		}
		handle := &fakeHTTP3ProcessHandle{}
		openresty.openProcess = func(int) (processHandle, error) { return handle, nil }
		starts := 0
		openresty.start = func(context.Context, []string, ...string) error { starts++; return nil }
		if err := openresty.Activate(context.Background(), current); err != nil {
			t.Fatalf("Activate() recovery error=%v", err)
		}
		if starts != 0 {
			t.Fatalf("recovery started a substitute process %d time(s)", starts)
		}
		signals, closes := handle.snapshot()
		if len(signals) != 1 || signals[0] != syscall.SIGHUP || closes != 1 {
			t.Fatalf("recovery signals=%v closes=%d", signals, closes)
		}
		stored, err := readProcessRecord(pidFile + ".identity")
		if err != nil || stored != record {
			t.Fatalf("recovered identity=%+v error=%v", stored, err)
		}
	})

	t.Run("reject missing launch token", func(t *testing.T) {
		openresty, pidFile, current, record := newProcessRuntimeFixture(t)
		pending, err := newProcessStartIdentity(openresty.binary)
		if err != nil {
			t.Fatal(err)
		}
		record.ExecutableDevice = pending.ExecutableDevice
		record.ExecutableInode = pending.ExecutableInode
		record.OwnerUID = pending.OwnerUID
		if err := os.WriteFile(pidFile, []byte(strconv.Itoa(record.PID)+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(pidFile+".identity.pending", []byte(formatProcessStartIdentity(pending)), 0o600); err != nil {
			t.Fatal(err)
		}
		openresty.inspect = func(int) (processIdentity, error) { return record, nil }
		tokenError := errors.New("launch token missing")
		openresty.matchStart = func(int, string) error { return tokenError }
		handle := &fakeHTTP3ProcessHandle{}
		openresty.openProcess = func(int) (processHandle, error) { return handle, nil }
		if err := openresty.Activate(context.Background(), current); !errors.Is(err, tokenError) {
			t.Fatalf("Activate() token error=%v", err)
		}
		if signals, closes := handle.snapshot(); len(signals) != 0 || closes != 0 {
			t.Fatalf("unowned pending process signals=%v closes=%d", signals, closes)
		}
	})
}

func TestOpenRestyFailsClosedWithoutProcfsOrPIDFD(t *testing.T) {
	t.Run("new start without Linux identity support", func(t *testing.T) {
		openresty, _, current, _ := newProcessRuntimeFixture(t)
		openresty.identityOK = false
		starts := 0
		openresty.start = func(context.Context, []string, ...string) error { starts++; return nil }
		if err := openresty.Activate(context.Background(), current); err == nil {
			t.Fatal("start without stable process identity support succeeded")
		}
		if starts != 0 {
			t.Fatalf("unsupported start ran %d time(s)", starts)
		}
	})

	t.Run("pidfd unavailable", func(t *testing.T) {
		openresty, pidFile, current, record := newProcessRuntimeFixture(t)
		writeProcessFixture(t, pidFile, record)
		openresty.openProcess = func(int) (processHandle, error) { return nil, syscall.ENOSYS }
		starts := 0
		openresty.start = func(context.Context, []string, ...string) error { starts++; return nil }
		if err := openresty.Activate(context.Background(), current); !errors.Is(err, syscall.ENOSYS) {
			t.Fatalf("Activate() pidfd error=%v", err)
		}
		if starts != 0 {
			t.Fatalf("pidfd failure started substitute %d time(s)", starts)
		}
	})

	t.Run("procfs unavailable after pidfd capture", func(t *testing.T) {
		openresty, pidFile, current, record := newProcessRuntimeFixture(t)
		writeProcessFixture(t, pidFile, record)
		procError := errors.New("procfs unavailable")
		openresty.inspect = func(int) (processIdentity, error) { return processIdentity{}, procError }
		handle := &fakeHTTP3ProcessHandle{}
		openresty.openProcess = func(int) (processHandle, error) { return handle, nil }
		if err := openresty.Activate(context.Background(), current); !errors.Is(err, procError) {
			t.Fatalf("Activate() procfs error=%v", err)
		}
		if signals, closes := handle.snapshot(); len(signals) != 0 || closes != 1 {
			t.Fatalf("procfs failure signals=%v closes=%d", signals, closes)
		}
	})
}

func TestOpenRestyInterruptedStartCleanupJoinsErrorsAndClosesHandle(t *testing.T) {
	openresty, pidFile, current, record := newProcessRuntimeFixture(t)
	startError := errors.New("start failed")
	removeError := errors.New("cleanup remove failed")
	closeError := errors.New("pidfd close failed")
	openresty.start = func(context.Context, []string, ...string) error {
		if err := os.WriteFile(pidFile, []byte(strconv.Itoa(record.PID)+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return startError
	}
	openresty.inspect = func(int) (processIdentity, error) { return record, nil }
	openresty.matchStart = func(int, string) error { return nil }
	handle := &fakeHTTP3ProcessHandle{closeErr: closeError}
	openresty.openProcess = func(int) (processHandle, error) { return handle, nil }
	openresty.removeProcessFile = func(string) error { return removeError }
	err := openresty.Activate(context.Background(), current)
	for _, expected := range []error{startError, removeError, closeError} {
		if !errors.Is(err, expected) {
			t.Fatalf("Activate() error=%v does not preserve %v", err, expected)
		}
	}
	signals, closes := handle.snapshot()
	if len(signals) != 1 || signals[0] != syscall.SIGQUIT || closes != 1 {
		t.Fatalf("interrupted cleanup signals=%v closes=%d", signals, closes)
	}
}

func TestOpenRestyCloseCleansPendingStartAndJoinsErrors(t *testing.T) {
	openresty, pidFile, _, record := newProcessRuntimeFixture(t)
	pending, err := newProcessStartIdentity(openresty.binary)
	if err != nil {
		t.Fatal(err)
	}
	record.ExecutableDevice = pending.ExecutableDevice
	record.ExecutableInode = pending.ExecutableInode
	record.OwnerUID = pending.OwnerUID
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(record.PID)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pidFile+".identity.pending", []byte(formatProcessStartIdentity(pending)), 0o600); err != nil {
		t.Fatal(err)
	}
	openresty.inspect = func(int) (processIdentity, error) { return record, nil }
	openresty.matchStart = func(int, string) error { return nil }
	signalError := errors.New("quit failed")
	closeError := errors.New("close failed")
	handle := &fakeHTTP3ProcessHandle{closeErr: closeError, onSignal: func(syscall.Signal) error { return signalError }}
	openresty.openProcess = func(int) (processHandle, error) { return handle, nil }
	err = openresty.Close()
	if !errors.Is(err, signalError) || !errors.Is(err, closeError) {
		t.Fatalf("Close() error=%v", err)
	}
	if signals, closes := handle.snapshot(); len(signals) != 1 || signals[0] != syscall.SIGQUIT || closes != 1 {
		t.Fatalf("Close() signals=%v closes=%d", signals, closes)
	}
	if err := openresty.Close(); err != nil {
		t.Fatalf("second Close()=%v", err)
	}
}

func TestOpenRestyReloadStopCloseRaceIsSerialized(t *testing.T) {
	openresty, pidFile, current, record := newProcessRuntimeFixture(t)
	writeProcessFixture(t, pidFile, record)
	openresty.inspect = func(int) (processIdentity, error) { return record, nil }
	entered := make(chan struct{})
	release := make(chan struct{})
	var stateMu sync.Mutex
	activeHandles := 0
	maxActiveHandles := 0
	var handles []*fakeHTTP3ProcessHandle
	openresty.openProcess = func(int) (processHandle, error) {
		stateMu.Lock()
		activeHandles++
		if activeHandles > maxActiveHandles {
			maxActiveHandles = activeHandles
		}
		handleNumber := len(handles)
		handle := &fakeHTTP3ProcessHandle{onClose: func() {
			stateMu.Lock()
			activeHandles--
			stateMu.Unlock()
		}}
		if handleNumber == 0 {
			handle.onSignal = func(signal syscall.Signal) error {
				if signal == syscall.SIGHUP {
					close(entered)
					<-release
				}
				return nil
			}
		}
		handles = append(handles, handle)
		stateMu.Unlock()
		return handle, nil
	}

	activateDone := make(chan error, 1)
	go func() { activateDone <- openresty.Activate(context.Background(), current) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("reload did not reach captured pidfd signal")
	}
	stopDone := make(chan error, 1)
	closeDone := make(chan error, 1)
	go func() { stopDone <- openresty.Stop(context.Background(), current) }()
	go func() { closeDone <- openresty.Close() }()
	time.Sleep(20 * time.Millisecond)
	stateMu.Lock()
	openedWhileReloadBlocked := len(handles)
	stateMu.Unlock()
	if openedWhileReloadBlocked != 1 {
		t.Fatalf("concurrent operation opened %d handles while reload held one", openedWhileReloadBlocked)
	}
	close(release)
	if err := <-activateDone; err != nil {
		t.Fatalf("Activate()=%v", err)
	}
	<-stopDone
	<-closeDone
	stateMu.Lock()
	defer stateMu.Unlock()
	if maxActiveHandles != 1 || activeHandles != 0 {
		t.Fatalf("pidfd concurrency max=%d remaining=%d", maxActiveHandles, activeHandles)
	}
	for index, handle := range handles {
		_, closes := handle.snapshot()
		if closes != 1 {
			t.Fatalf("handle %d closes=%d", index, closes)
		}
	}
}

func TestOpenRestyPreservesSignalAndCloseErrors(t *testing.T) {
	openresty, pidFile, current, record := newProcessRuntimeFixture(t)
	writeProcessFixture(t, pidFile, record)
	openresty.inspect = func(int) (processIdentity, error) { return record, nil }
	signalError := errors.New("reload signal failed")
	closeError := errors.New("reload pidfd close failed")
	handle := &fakeHTTP3ProcessHandle{
		closeErr: closeError,
		onSignal: func(signal syscall.Signal) error {
			if signal != syscall.SIGHUP {
				t.Fatalf("signal=%v", signal)
			}
			return signalError
		},
	}
	openresty.openProcess = func(int) (processHandle, error) { return handle, nil }
	err := openresty.Activate(context.Background(), current)
	if !errors.Is(err, signalError) || !errors.Is(err, closeError) {
		t.Fatalf("Activate() error=%v", err)
	}
	if _, closes := handle.snapshot(); closes != 1 {
		t.Fatalf("reload pidfd closes=%d", closes)
	}
}

func TestRemoveProcessPathsJoinsCleanupAndSyncErrors(t *testing.T) {
	removeError := errors.New("remove failed")
	syncError := errors.New("sync failed")
	removes := 0
	err := removeProcessPaths([]string{"/tmp/http3-one", "/tmp/http3-two"}, func(string) error {
		removes++
		if removes == 2 {
			return removeError
		}
		return nil
	}, func(string) error { return syncError })
	if !errors.Is(err, removeError) || !errors.Is(err, syncError) {
		t.Fatalf("removeProcessPaths() error=%v", err)
	}
}

func TestLinuxPIDFDHandleClosesWithoutLeak(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux pidfd smoke")
	}
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 64; index++ {
		handle, err := openPIDFD(os.Getpid())
		if err != nil {
			t.Fatal(err)
		}
		alive, err := handle.Alive()
		if err != nil || !alive {
			t.Fatalf("pidfd alive=%v error=%v", alive, err)
		}
		pidfd := handle.(*pidfdHandle)
		if err := handle.Close(); err != nil {
			t.Fatal(err)
		}
		var stat syscall.Stat_t
		if err := syscall.Fstat(pidfd.fd, &stat); !errors.Is(err, syscall.EBADF) {
			t.Fatalf("closed pidfd Fstat error=%v", err)
		}
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("pidfd loop leaked descriptors: before=%d after=%d", len(before), len(after))
	}
}

func containsArgumentPair(arguments []string, first, second string) bool {
	for index := 0; index+1 < len(arguments); index++ {
		if arguments[index] == first && arguments[index+1] == second {
			return true
		}
	}
	return false
}
