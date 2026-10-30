//go:build linux

package nativeruntime

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/dynroute"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/l4runtime"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/oldmaster"
)

// Real native runtime switch acceptance (node-runtime-upgrade), driven by
// scripts/native-runtime-upgrade-acceptance.sh in a disposable --rm debian:12
// container: the real OpenResty/Lua payload of a native node package
// (CDNCA_NATIVE_PAYLOAD_DIR: runtime/ and lua/), re-signed with a test key
// into releases that differ only in one Lua module. /opt/cdnca-node and
// /usr/local are this container's own: the test refuses to run elsewhere.
//
//   1. switch A -> B: the HTTP master is hot upgraded (new master pid, new
//      Lua answers); config.json points into B; A is kept as previous;
//   2. old sessions are cut, not waited for (BATCH 77b): a streaming
//      response started on A that would outlast the grace, and a TCP session
//      established on A's L4 master (started by l4runtime, as the Agent runs
//      it), are both cut within QUIT + 10 s + TERM + 5 s; A's masters are gone
//      once Commit returns; the new L4 master runs B's binary and new HTTP
//      requests and L4 sessions go to B's masters;
//   3. a package with the same runtime (only the Agent differs): unchanged,
//      same master, same link;
//   4. a package whose Lua fails `openresty -t`: RUNTIME_PRECHECK_FAILED, the
//      link and config.json are back, B keeps serving from the same master;
//   5. B -> E and right away E -> F, each with sessions held on the masters
//      being replaced: both switches succeed (no master left over to make
//      nginx ignore USR2), the held sessions are cut, only E/F remain and
//      exactly one HTTP and one L4 master run;
//   6. a master an earlier upgrade left running (an Agent that stopped
//      during the grace; here: USR2 by hand, never retired) is ended first:
//      F -> G succeeds, both F-era HTTP masters are gone.

const (
	realRoot      = "/opt/cdnca-node"
	realBinary    = "/usr/local/openresty/bin/openresty"
	realHTTPPort  = 18480
	realL4Port    = 18490
	probeModule   = "lua/share/cdnca/cdnca_upgrade_probe.lua"
	streamedLines = 300 // 30 s: longer than the retire grace
)

type realNode struct {
	t        *testing.T
	payload  map[string][]byte
	modes    map[string]int64
	work     string
	private  ed25519.PrivateKey
	keys     map[string]ed25519.PublicKey
	config   string
	status   string
	httpRoot string
	l4Root   string
}

func TestRealNativeRuntimeUpgrade(t *testing.T) {
	payloadDir := os.Getenv("CDNCA_NATIVE_PAYLOAD_DIR")
	if os.Getenv("CDNCA_NATIVE_RUNTIME_REAL") != "1" || payloadDir == "" {
		t.Skip("CDNCA_NATIVE_RUNTIME_REAL=1 and CDNCA_NATIVE_PAYLOAD_DIR: scripts/native-runtime-upgrade-acceptance.sh")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil || os.Geteuid() != 0 {
		t.Fatal("only as root in a disposable container (it owns /opt/cdnca-node and /usr/local)")
	}
	if _, err := os.Lstat(realRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("%s already exists: not a fresh container", realRoot)
	}
	node := newRealNode(t, payloadDir)
	a := node.release("1.0.0", "A", `return { marker = "A" }`)
	b := node.release("1.0.1", "B", `return { marker = "B" }`)
	same := node.release("1.0.2", "B", `return { marker = "B" }`)
	broken := node.release("1.0.3", "broken", `return { marker = `)
	e := node.release("1.0.4", "E", `return { marker = "E" }`)
	f := node.release("1.0.5", "F", `return { marker = "F" }`)
	g := node.release("1.0.6", "G", `return { marker = "G" }`)
	node.install(a)

	httpMaster := node.startMaster(node.httpRoot, node.httpConfig())
	l4 := node.startL4(node.echoServer())
	l4Master := node.masterPID(node.l4Root)
	defer func() { _ = syscall.Kill(node.masterPID(node.l4Root), syscall.SIGTERM) }()
	node.expectMarker("A", httpMaster)

	// 1-2. A -> B with a streaming response and an L4 session on A's masters.
	pending, err := Prepare(context.Background(), node.agentConfig(b), node.precheck)
	if err != nil || !pending.Switched() {
		t.Fatalf("prepare B: switched=%v err=%v", pending.Switched(), err)
	}
	upgraded := node.commitCuttingSessions(pending, "B", l4, httpMaster, l4Master)
	node.expectStatus(StateSwitched, "", b.sha)
	node.expectCurrent(b.sha)
	node.expectConfig(b.sha)
	node.expectL4("after-b", b.sha, l4Master)
	l4B := node.masterPID(node.l4Root)
	node.expectReleases(a.sha, b.sha)
	node.expectMasterCount(2)

	// 3. Same runtime, another Agent: nothing switches.
	pending, err = Prepare(context.Background(), node.agentConfig(same), node.precheck)
	if err != nil || pending.Switched() {
		t.Fatalf("prepare same runtime: switched=%v err=%v", pending.Switched(), err)
	}
	node.expectStatus(StateUnchanged, "", b.sha)
	node.expectCurrent(b.sha)
	if node.masterPID(node.httpRoot) != upgraded || node.masterPID(node.l4Root) != l4B {
		t.Fatal("same runtime restarted a master")
	}

	// 4. Lua that fails `openresty -t`: back to B, still serving.
	before, _ := os.ReadFile(node.config)
	if _, err := Prepare(context.Background(), node.agentConfig(broken), node.precheck); Code(err) != CodePrecheck {
		t.Fatalf("broken Lua: code %q (%v), want %s", Code(err), err, CodePrecheck)
	}
	node.expectStatus(StateFailed, CodePrecheck, "")
	node.expectCurrent(b.sha)
	if after, _ := os.ReadFile(node.config); !bytes.Equal(before, after) {
		t.Fatal("config.json not restored after the precheck failure")
	}
	node.expectMarker("B", upgraded)

	// 5. B -> E, then right away E -> F: each cuts the sessions held on the
	// masters it replaces and leaves none of them running.
	previousHTTP, previousL4 := upgraded, l4B
	for _, next := range []struct {
		release realRelease
		marker  string
		kept    string
	}{{e, "E", b.sha}, {f, "F", e.sha}} {
		pending, err = Prepare(context.Background(), node.agentConfig(next.release), node.precheck)
		if err != nil || !pending.Switched() {
			t.Fatalf("prepare %s: switched=%v err=%v", next.marker, pending.Switched(), err)
		}
		previousHTTP = node.commitCuttingSessions(pending, next.marker, l4, previousHTTP, previousL4)
		node.expectStatus(StateSwitched, "", next.release.sha)
		node.expectL4("after-"+next.marker, next.release.sha, previousL4)
		previousL4 = node.masterPID(node.l4Root)
		node.expectReleases(next.kept, next.release.sha)
		node.expectMasterCount(2)
	}

	// 6. An HTTP master an earlier upgrade left running: USR2 by hand and no
	// retire, so F's first master still is the parent of the one serving.
	leftover := previousHTTP
	if err := syscall.Kill(leftover, syscall.SIGUSR2); err != nil {
		t.Fatal(err)
	}
	child := 0
	for deadline := time.Now().Add(10 * time.Second); child == 0; time.Sleep(50 * time.Millisecond) {
		if pid, err := readPIDFile(filepath.Join(node.httpRoot, "nginx.pid")); err == nil && pid != leftover && parentPID(pid) == leftover {
			child = pid
		} else if time.Now().After(deadline) {
			t.Fatal("USR2 by hand started no new HTTP master")
		}
	}
	pending, err = Prepare(context.Background(), node.agentConfig(g), node.precheck)
	if err != nil || !pending.Switched() {
		t.Fatalf("prepare G: switched=%v err=%v", pending.Switched(), err)
	}
	if err := pending.Commit(context.Background(), node.httpRuntime("G"), l4); err != nil {
		t.Fatalf("commit G with a leftover master: %v", err)
	}
	node.expectMarker("G", node.masterPID(node.httpRoot))
	for _, pid := range []int{leftover, child} {
		if exited(pid, time.Second) != nil {
			t.Fatalf("F-era HTTP master %d still running after G", pid)
		}
	}
	node.expectStatus(StateSwitched, "", g.sha)
	node.expectReleases(f.sha, g.sha)
	node.expectMasterCount(2)
}

// retireLimit bounds Commit with sessions held on both masters: each old
// master gets QUIT, TERM 10 s later and KILL 5 s after that.
const retireLimit = 2*(oldmaster.QuitGrace+oldmaster.TermGrace) + 15*time.Second

// commitCuttingSessions commits marker's switch while a streaming response
// and an L4 session are held on the masters httpOld/l4Old: both are cut, the
// old masters are gone when Commit returns (within retireLimit), and the new
// HTTP master answers with marker. It returns the new HTTP master.
func (n *realNode) commitCuttingSessions(pending *Pending, marker string, l4 *l4runtime.OpenResty, httpOld, l4Old int) int {
	t := n.t
	session := n.dialL4()
	defer session.Close()
	n.echo(session, "before-"+marker)
	streamed := n.stream()
	time.Sleep(500 * time.Millisecond)
	started := time.Now()
	if err := pending.Commit(context.Background(), n.httpRuntime(marker), l4); err != nil {
		t.Fatalf("commit %s: %v", marker, err)
	}
	if elapsed := time.Since(started); elapsed > retireLimit {
		t.Fatalf("commit %s took %v, more than the retire grace", marker, elapsed)
	}
	for _, pid := range []int{httpOld, l4Old} {
		if exited(pid, time.Second) != nil {
			t.Fatalf("old master %d still running after commit %s", pid, marker)
		}
	}
	select {
	case lines := <-streamed:
		if lines >= streamedLines {
			t.Fatalf("streaming response on the old master was not cut (%d lines)", lines)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("streaming response on the old master still open after its master exited")
	}
	_ = session.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = session.Write([]byte("after-cut\n"))
	if line, err := bufio.NewReader(session).ReadString('\n'); err == nil {
		t.Fatalf("L4 session on the old master still carries data: %q", line)
	}
	upgraded := n.masterPID(n.httpRoot)
	if upgraded == httpOld {
		t.Fatal("HTTP master pid unchanged: no binary upgrade")
	}
	n.expectMarker(marker, upgraded)
	return upgraded
}

// expectMasterCount: exactly want OpenResty masters run (HTTP and L4; no
// replaced master left over).
func (n *realNode) expectMasterCount(want int) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		n.t.Fatal(err)
	}
	var masters []int
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		if cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid)); err == nil &&
			bytes.HasPrefix(cmdline, []byte("nginx: master process")) && !zombie(pid) {
			masters = append(masters, pid)
		}
	}
	if len(masters) != want {
		n.t.Fatalf("OpenResty masters %v, want %d", masters, want)
	}
}

type realRelease struct{ version, sha, packagePath, agent string }

func newRealNode(t *testing.T, payloadDir string) *realNode {
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	if err := os.Chmod(work, 0o755); err != nil { // the workers (nobody) traverse the prefixes
		t.Fatal(err)
	}
	node := &realNode{t: t, payload: map[string][]byte{}, modes: map[string]int64{}, work: work, private: private,
		keys: map[string]ed25519.PublicKey{"acceptance": public}, config: filepath.Join(work, "config.json"),
		status: filepath.Join(work, "state", "status.json"), httpRoot: filepath.Join(work, "http"), l4Root: filepath.Join(work, "l4")}
	for _, prefix := range []string{"runtime", "lua"} {
		err := filepath.WalkDir(filepath.Join(payloadDir, prefix), func(path string, entry fs.DirEntry, err error) error {
			if err != nil || entry.IsDir() {
				return err
			}
			relative, _ := filepath.Rel(payloadDir, path)
			relative = filepath.ToSlash(relative)
			if !safeMember(relative) {
				return nil
			}
			info, err := os.Stat(path) // a payload symlink ships as the file it names
			if err != nil || !info.Mode().IsRegular() {
				return err
			}
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			node.payload[relative], node.modes[relative] = content, 0o444
			if info.Mode()&0o111 != 0 {
				node.modes[relative] = 0o555
			}
			return nil
		})
		if err != nil {
			t.Fatalf("read payload %s: %v", prefix, err)
		}
	}
	for _, name := range required {
		if _, ok := node.payload[name]; !ok && name != AgentPath {
			t.Fatalf("payload lacks %s", name)
		}
	}
	for _, dir := range []string{node.httpRoot, node.l4Root, filepath.Dir(node.status)} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, root := range []string{node.httpRoot, node.l4Root} {
			if pid, err := readPIDFile(filepath.Join(root, "nginx.pid")); err == nil {
				_ = syscall.Kill(pid, syscall.SIGTERM)
			}
		}
	})
	return node
}

// release writes the signed package of version: the payload, the probe
// module and an Agent of its own.
func (n *realNode) release(version, marker, probe string) realRelease {
	t := n.t
	files := map[string][]byte{probeModule: []byte(probe + "\n"), AgentPath: []byte("agent-" + version + "\n")}
	modes := map[string]int64{probeModule: 0o444, AgentPath: 0o555}
	for name, content := range n.payload {
		files[name], modes[name] = content, n.modes[name]
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	inventory := make([]map[string]any, 0, len(names))
	for _, name := range names {
		inventory = append(inventory, map[string]any{"path": name, "size": len(files[name]),
			"mode": fmt.Sprintf("%04o", modes[name]), "sha256": sha(files[name])})
	}
	manifest, err := json.Marshal(map[string]any{
		"schema": "cdnca.native-node.release/v1", "key_id": "acceptance", "version": version,
		"source":   map[string]string{"commit": strings.Repeat("a", 40), "tree": strings.Repeat("b", 40)},
		"platform": map[string]string{"os": "linux", "arch": "amd64"},
		"runtime": map[string]any{"openresty_version": n.openRestyVersion(), "nginx_version": "1.31.1",
			"source_sha256": sha([]byte("source")), "patch_manifest_sha256": sha([]byte("patches")), "release_eligible": true},
		"files": inventory,
	})
	if err != nil {
		t.Fatal(err)
	}
	signature := base64.StdEncoding.EncodeToString(ed25519.Sign(n.private, append([]byte(signatureDomain), manifest...))) + "\n"
	path := filepath.Join(n.work, version+"-"+marker+".tar.gz")
	output, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	compressed := gzip.NewWriter(output)
	archive := tar.NewWriter(compressed)
	write := func(name string, content []byte, mode int64) {
		if err := archive.WriteHeader(&tar.Header{Name: name, Mode: mode, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := archive.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	write(manifestName, manifest, 0o444)
	write(signatureName, []byte(signature), 0o444)
	for _, name := range names {
		write(name, files[name], modes[name])
	}
	if err := errors.Join(archive.Close(), compressed.Close(), output.Close()); err != nil {
		t.Fatal(err)
	}
	agent := filepath.Join(n.work, "edge-agent-"+version)
	if err := os.WriteFile(agent, files[AgentPath], 0o555); err != nil {
		t.Fatal(err)
	}
	return realRelease{version: version, sha: sha(manifest), packagePath: path, agent: agent}
}

// openRestyVersion is the manifest metadata of every release here (the
// payload's own OpenResty; CDNCA_NATIVE_OPENRESTY_VERSION overrides).
func (n *realNode) openRestyVersion() string {
	if version := os.Getenv("CDNCA_NATIVE_OPENRESTY_VERSION"); version != "" {
		return version
	}
	return "1.31.1.1"
}

// install is the first installation as install-node.sh activates it.
func (n *realNode) install(release realRelease) {
	t := n.t
	pkg, err := Verify(release.packagePath, n.keys)
	if err != nil {
		t.Fatalf("verify first package: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(realRoot, "releases"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := pkg.Extract(filepath.Join(realRoot, "releases", release.sha)); err != nil {
		t.Fatal(err)
	}
	links := map[string]string{
		filepath.Join(realRoot, "current"): "releases/" + release.sha,
		"/usr/local/openresty":             realRoot + "/current/runtime/openresty",
		"/usr/local/share/cdnca":           realRoot + "/current/lua/share/cdnca",
	}
	for link, target := range links {
		if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
	}
	security := map[string]any{"enabled": true, "mode": "native"}
	for name, file := range map[string]string{"waf": "cdnca_waf.lua", "cc": "cc.lua", "adaptive": "cc_adaptive.lua"} {
		member := SecurityRoot + "/" + file
		security[name] = map[string]any{"path": filepath.Join(realRoot, "releases", release.sha, member), "sha256": pkg.SignedSHA256(member)}
	}
	raw, err := json.MarshalIndent(map[string]any{"version": 2,
		"openresty":        map[string]any{"binary": realBinary, "version": n.openRestyVersion()},
		"security_runtime": security}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(n.config, append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (n *realNode) agentConfig(release realRelease) Config {
	return Config{Root: realRoot, PackagePath: release.packagePath, AgentPath: release.agent, AgentVersion: release.version,
		ConfigPath: n.config, StatusPath: n.status, Keys: n.keys, Timeout: 2 * time.Minute}
}
func (n *realNode) httpConfig() string {
	return fmt.Sprintf(`user nobody nogroup;
worker_processes 2;
worker_shutdown_timeout 30s;
pid %[1]s/nginx.pid;
error_log %[1]s/error.log notice;
events { worker_connections 256; }
http {
  access_log off;
  lua_package_path '/usr/local/share/cdnca/?.lua;;';
  init_by_lua_block { cdnca_upgrade_probe = require("cdnca_upgrade_probe") }
  server {
    listen 127.0.0.1:%[2]d;
    location = /marker { content_by_lua_block { ngx.say(cdnca_upgrade_probe.marker, " ", ngx.worker.pid()) } }
    location = /stream {
      content_by_lua_block {
        for i = 1, %[3]d do ngx.say(i) ngx.flush(true) ngx.sleep(0.1) end
      }
    }
  }
}
`, n.httpRoot, realHTTPPort, streamedLines)
}

// l4Config: the L4 master as l4runtime runs it (l4runtime passes the pid
// file with -g). No worker_shutdown_timeout: a retired worker keeps its
// sessions until they end.
func (n *realNode) l4Config(upstream string) string {
	return fmt.Sprintf(`user nobody nogroup;
worker_processes 1;
error_log %[1]s/error.log notice;
events { worker_connections 64; }
stream { server { listen 127.0.0.1:%[2]d; proxy_timeout 10m; proxy_pass %[3]s; } }
`, n.l4Root, realL4Port, upstream)
}

func (n *realNode) echoServer() string {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		n.t.Fatal(err)
	}
	n.t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { defer connection.Close(); _, _ = io.Copy(connection, connection) }()
		}
	}()
	return listener.Addr().String()
}

// startL4 starts the L4 master through l4runtime (pid + kernel identity
// record), the way the Agent does and later resumes it.
func (n *realNode) startL4(upstream string) *l4runtime.OpenResty {
	t := n.t
	if err := os.WriteFile(filepath.Join(n.l4Root, "nginx.conf"), []byte(n.l4Config(upstream)), 0o644); err != nil {
		t.Fatal(err)
	}
	l4, err := l4runtime.NewOpenResty(realBinary, filepath.Join(n.l4Root, "nginx.pid"), 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := l4.Activate(context.Background(), n.l4Root); err != nil {
		t.Fatalf("start the L4 master: %v", err)
	}
	return l4
}

func (n *realNode) startMaster(root, config string) int {
	t := n.t
	if err := os.WriteFile(filepath.Join(root, "nginx.conf"), []byte(config), 0o644); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command(realBinary, "-p", root+"/", "-c", "nginx.conf").CombinedOutput(); err != nil {
		t.Fatalf("start OpenResty in %s: %v: %s", root, err, output)
	}
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if pid, err := readPIDFile(filepath.Join(root, "nginx.pid")); err == nil {
			return pid
		}
	}
	t.Fatalf("OpenResty in %s wrote no pid", root)
	return 0
}

func (n *realNode) masterPID(root string) int {
	pid, err := readPIDFile(filepath.Join(root, "nginx.pid"))
	if err != nil {
		n.t.Fatalf("master pid of %s: %v", root, err)
	}
	return pid
}

// precheck is the Agent's (PrecheckOpenResty) of the live HTTP configuration
// through the switched link.
func (n *realNode) precheck(ctx context.Context) error {
	return PrecheckOpenResty(ctx, realBinary, n.httpRoot+"/", filepath.Join(n.httpRoot, "nginx.conf"), "")
}

// realHTTP drives dynroute.UpgradeMaster (Runtime.UpgradeBinary without the
// site index): the new master serves once one of its workers answers with
// the marker of the release.
type realHTTP struct {
	node   *realNode
	marker string
}

func (n *realNode) httpRuntime(marker string) Master { return realHTTP{node: n, marker: marker} }

func (h realHTTP) UpgradeBinary(ctx context.Context) error {
	return dynroute.UpgradeMaster(ctx, filepath.Join(h.node.httpRoot, "nginx.pid"), func(ctx context.Context, fresh int) error {
		ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		for {
			if marker, worker, err := getMarker(); err == nil && marker == h.marker && parentPID(worker) == fresh {
				return nil
			}
			select {
			case <-ctx.Done():
				return fmt.Errorf("no worker of master %d answers %q: %w", fresh, h.marker, ctx.Err())
			case <-time.After(50 * time.Millisecond):
			}
		}
	})
}

func getMarker() (string, int, error) {
	client := http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	response, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/marker", realHTTPPort))
	if err != nil {
		return "", 0, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	fields := strings.Fields(string(body))
	if err != nil || response.StatusCode != http.StatusOK || len(fields) != 2 {
		return "", 0, fmt.Errorf("marker response %d %q: %v", response.StatusCode, body, err)
	}
	worker, err := strconv.Atoi(fields[1])
	return fields[0], worker, err
}

// expectMarker: 20 consecutive answers (fresh connections, both workers)
// come from workers of master with the marker. Right after a hot upgrade an
// old worker may take a connection until it handles WINCH: 10 s to settle.
func (n *realNode) expectMarker(marker string, master int) {
	var got string
	var worker int
	var err error
	consecutive := 0
	for deadline := time.Now().Add(10 * time.Second); consecutive < 20; {
		got, worker, err = getMarker()
		if err == nil && got == marker && parentPID(worker) == master {
			consecutive++
			continue
		}
		consecutive = 0
		if time.Now().After(deadline) {
			n.t.Fatalf("marker %q from worker %d (parent %d), want %q from master %d: %v",
				got, worker, parentPID(worker), marker, master, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// stream starts a response of streamedLines lines over 30 s and reports how
// many arrived before the connection ended.
func (n *realNode) stream() <-chan int {
	lines := make(chan int, 1)
	go func() {
		client := http.Client{Timeout: time.Minute, Transport: &http.Transport{DisableKeepAlives: true}}
		response, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/stream", realHTTPPort))
		if err != nil {
			lines <- 0
			return
		}
		defer response.Body.Close()
		count := 0
		for scanner := bufio.NewScanner(response.Body); scanner.Scan(); count++ {
		}
		lines <- count
	}()
	return lines
}

func (n *realNode) dialL4() net.Conn {
	connection, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", realL4Port), 5*time.Second)
	if err != nil {
		n.t.Fatalf("L4 connection: %v", err)
	}
	return connection
}

func (n *realNode) echo(connection net.Conn, text string) {
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := connection.Write([]byte(text + "\n")); err != nil {
		n.t.Fatalf("L4 session write %q: %v", text, err)
	}
	line, err := bufio.NewReader(connection).ReadString('\n')
	if err != nil || line != text+"\n" {
		n.t.Fatalf("L4 session echo %q = %q: %v", text, line, err)
	}
}

// expectL4: the L4 master named by the pid file is a new process (not
// previous) running release's binary and takes a new session.
func (n *realNode) expectL4(text, release string, previous int) {
	master := n.masterPID(n.l4Root)
	if master == previous {
		n.t.Fatal("L4 master pid unchanged: no binary upgrade")
	}
	exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", master))
	if err != nil || !strings.Contains(exe, "/releases/"+release+"/") {
		n.t.Fatalf("L4 master %d binary %q (%v), want release %s", master, exe, err, release)
	}
	fresh := n.dialL4()
	defer fresh.Close()
	n.echo(fresh, text+"-new")
}

func (n *realNode) expectStatus(state, code, release string) {
	status, err := ReadStatus(n.status)
	if err != nil || status.State != state || status.ErrorCode != code || (release != "" && status.Release != release) {
		n.t.Fatalf("status %+v (%v), want state %s code %q release %s", status, err, state, code, release)
	}
}

func (n *realNode) expectCurrent(release string) {
	target, err := os.Readlink(filepath.Join(realRoot, "current"))
	if err != nil || target != "releases/"+release {
		n.t.Fatalf("current -> %q (%v), want releases/%s", target, err, release)
	}
}

func (n *realNode) expectConfig(release string) {
	raw, err := os.ReadFile(n.config)
	if err != nil {
		n.t.Fatal(err)
	}
	var config struct {
		OpenResty       struct{ Version string }   `json:"openresty"`
		SecurityRuntime map[string]json.RawMessage `json:"security_runtime"`
	}
	if err := json.Unmarshal(raw, &config); err != nil || config.OpenResty.Version != n.openRestyVersion() {
		n.t.Fatalf("config.json openresty: %s (%v)", raw, err)
	}
	for _, name := range []string{"waf", "cc", "adaptive"} {
		var asset struct{ Path, SHA256 string }
		if err := json.Unmarshal(config.SecurityRuntime[name], &asset); err != nil ||
			!strings.HasPrefix(asset.Path, filepath.Join(realRoot, "releases", release)+"/") || fileDigest(asset.Path) != asset.SHA256 {
			n.t.Fatalf("security_runtime.%s = %+v (%v), want a signed file of release %s", name, asset, err, release)
		}
	}
}

func (n *realNode) expectReleases(want ...string) {
	entries, err := os.ReadDir(filepath.Join(realRoot, "releases"))
	if err != nil {
		n.t.Fatal(err)
	}
	var got []string
	for _, entry := range entries {
		if digestPattern.MatchString(entry.Name()) {
			got = append(got, entry.Name())
		}
	}
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		n.t.Fatalf("releases %v, want %v (current and previous)", got, want)
	}
}

func fileDigest(path string) string {
	content, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return sha(content)
}

func readPIDFile(path string) (int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || pid < 2 || syscall.Kill(pid, 0) != nil {
		return 0, errors.New("no live master")
	}
	return pid, nil
}

// parentPID is field 4 of /proc/<pid>/stat (after the parenthesised name).
func parentPID(pid int) int {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(raw[bytes.LastIndexByte(raw, ')')+1:]))
	if len(fields) < 2 {
		return 0
	}
	parent, _ := strconv.Atoi(fields[1])
	return parent
}

func exited(pid int, limit time.Duration) error {
	for deadline := time.Now().Add(limit); ; time.Sleep(100 * time.Millisecond) {
		if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); errors.Is(err, os.ErrNotExist) || zombie(pid) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("process %d still running", pid)
		}
	}
}

// zombie: pid exited and waits for its parent (state Z).
func zombie(pid int) bool {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	fields := strings.Fields(string(raw[bytes.LastIndexByte(raw, ')')+1:]))
	return len(fields) > 0 && fields[0] == "Z"
}
