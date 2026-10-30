package cachetask

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	edgeconfig "github.com/cdnca/cdnca/libs/edgeconfig"
)

func TestCacheTaskSmokeTemplateMatchesProductionLegacyKey(t *testing.T) {
	templatePath := filepath.Join(filepath.Dir(smokeTestSourcePath(t)), "..", "..", "..", "..", "edge", "openresty", "cache", "cache-task-smoke.conf.tmpl")
	content, err := os.ReadFile(templatePath)
	if err != nil {
		t.Fatal(err)
	}
	config := string(content)
	wants := map[string]int{
		`proxy_cache_key "{{V2_KEY_PREFIX}}$uri$is_args$args";`:    2,
		`proxy_cache_key "{{V1_KEY_PREFIX}}$uri$is_args$args";`:    1,
		`proxy_cache_key "{{OTHER_KEY_PREFIX}}$uri$is_args$args";`: 1,
	}
	for directive, count := range wants {
		if got := strings.Count(config, directive); got != count {
			t.Errorf("%s count=%d, want %d", directive, got, count)
		}
	}
	v2RuleKeyTTL := "proxy_cache v2_zone;\n      proxy_cache_key \"{{V2_KEY_PREFIX}}$uri$is_args$args\";\n      proxy_cache_valid 200 60s;"
	if got := strings.Count(config, v2RuleKeyTTL); got != 2 {
		t.Errorf("public/loopback v2 rule-key-TTL count=%d, want 2", got)
	}
	for _, stale := range []string{"v2|tenant-a|site-a|2|config-v2|", "v2|tenant-a|site-a|1|config-v1|"} {
		if strings.Contains(config, stale) {
			t.Errorf("template still includes config revision in cache key: %q", stale)
		}
	}

	prefix := edgeconfig.CacheKeyPrefix("tenant-a", "site-a", "config-v2", "cache.example.test", 18100)
	if prefix != "v2|tenant-a|site-a|config-v2|cache.example.test|18100|" {
		t.Fatalf("unexpected production legacy key prefix %q", prefix)
	}
}

func TestEdgeCacheRunbookMatchesProductionIdentityAndRuntimeEvidence(t *testing.T) {
	runbookPath := filepath.Join(filepath.Dir(smokeTestSourcePath(t)), "..", "..", "..", "..", "docs", "runbooks", "edge-cache-task.md")
	content, err := os.ReadFile(runbookPath)
	if err != nil {
		t.Fatal(err)
	}
	document := string(content)
	for _, want := range []string{
		`v2\0<tenant-id>\0<site-id>\0<config-version-id>`,
		`v2|<tenant-id>|<site-id>|<config-version-id>|<host>|<public-port>|<uri>?<raw-query>`,
		`v2|<tenant-id>|<site-id>|<config-version-id>|<host>|<public-port>|<uri>?~q=<query-sha256>&~v=<vary-sha256>`,
		`<tag>:<UTF-8-byte-length>:<value>;`,
		`cdnca-cache-query-v1`,
		`cdnca-cache-vary-v1`,
		"`preserve`:保留原始 `raw`",
		"`include`/`exclude`:按原始顺序加入 `pair`",
		"`ignore`:固定 `state=ignored`",
		"`name` + `state=absent|empty|value`",
		`共享 OpenResty renderer 已接入`,
		`真实 OpenResty runtime 证明：**PASS**`,
		`记录的容器/镜像 ID 仍是首选清理目标`,
		`ID 丢失或已消失时`,
		`稳定容器名和镜像 tag`,
		`精确 task owner label`,
		`foreign、replacement 或 owner 无法证明`,
	} {
		if !strings.Contains(document, want) {
			t.Errorf("runbook is missing %q", want)
		}
	}
	for _, stale := range []string{
		`\0<config-revision>`,
		`|<config-revision>|<config-version-id>|`,
		`共享 OpenResty renderer 也尚未采用 v2`,
		`当前 libs/edgeconfig/config.go 仍把 cache key 渲染为`,
		`真实 OpenResty runtime 证明：**PENDING**`,
		`真实 smoke 使用固定 digest 的 OpenResty 1.27.1.2，在任务专属容器、镜像和状态目录中\n验证`,
	} {
		if strings.Contains(document, stale) {
			t.Errorf("runbook retains stale claim %q", stale)
		}
	}
}

func TestEdgeCacheSmokeScriptsCleanOnlyExactOwnedDockerIDs(t *testing.T) {
	repositoryRoot := filepath.Clean(filepath.Join(filepath.Dir(smokeTestSourcePath(t)), "..", "..", "..", ".."))
	for _, relative := range []string{"scripts/edge-cache-task-smoke.sh"} {
		t.Run(filepath.Base(relative), func(t *testing.T) {
			content, err := os.ReadFile(filepath.Join(repositoryRoot, relative))
			if err != nil {
				t.Fatal(err)
			}
			script := string(content)
			for _, required := range []string{
				`task_owner=`, `container_id=`, `image_id=`, `cdnca.smoke.owner`,
				`container name collision`, `image tag collision`, `cleanup_failed=`,
				`docker rm -f "${container_id}"`, `docker image rm "${image_id}"`,
				`docker rm -f "${container}"`, `docker image rm "${image}"`,
				`docker inspect --type container "${1}"`, `docker image inspect "${1}"`,
				`inspect_container "${container_id}"`, `inspect_image "${image_id}"`,
			} {
				if !strings.Contains(script, required) {
					t.Errorf("%s missing exact ownership cleanup contract %q", relative, required)
				}
			}
		})
	}
}

func TestEdgeCacheSmokeScriptCleanupFailureAndReplacementSemantics(t *testing.T) {
	repositoryRoot := filepath.Clean(filepath.Join(filepath.Dir(smokeTestSourcePath(t)), "..", "..", "..", ".."))
	for _, relative := range []string{"scripts/edge-cache-task-smoke.sh"} {
		t.Run(filepath.Base(relative), func(t *testing.T) {
			content, err := os.ReadFile(filepath.Join(repositoryRoot, relative))
			if err != nil {
				t.Fatal(err)
			}
			script := string(content)
			start := strings.Index(script, "inspect_container() {")
			end := strings.Index(script[start:], "\n}\ntrap")
			if start < 0 || end < 0 {
				t.Fatal("cleanup function not found")
			}
			cleanupFunction := script[start : start+end+2]

			fakeRoot := t.TempDir()
			dockerLog := filepath.Join(fakeRoot, "docker.log")
			fakeDocker := filepath.Join(fakeRoot, "docker")
			fake := `#!/bin/sh
printf '%s\n' "$*" >>"${DOCKER_LOG}"
target=""
formatted=0
for argument do
  target="${argument}"
  [ "${argument}" = "--format" ] && formatted=1
done
case "${FAKE_MODE}" in
  absent)
    printf '%s\n' "Error: No such object: ${target}" >&2
    exit 1
    ;;
  daemon-error) printf '%s\n' 'Cannot connect to the Docker daemon' >&2; exit 125 ;;
  permission-denied) printf '%s\n' 'permission denied' >&2; exit 126 ;;
  replacement)
    case "${target}" in
      owned-container-id|owned-image-id) printf '%s\n' "Error: No such object: ${target}" >&2; exit 1 ;;
      smoke-container|smoke-image) exit 0 ;;
    esac
    ;;
  malformed-owner)
    if [ "${formatted}" -eq 1 ]; then printf 'smoke-owner\nextra\n'; fi
    exit 0
    ;;
  owner-error)
    if [ "${formatted}" -eq 1 ]; then printf '%s\n' 'owner inspect failed' >&2; exit 125; fi
    exit 0
    ;;
  partial-failure)
    if [ "${formatted}" -eq 1 ]; then printf '%s\n' 'smoke-owner'; exit 0; fi
    case "${1}:${2}:${target}" in
      rm:-f:owned-container-id) exit 1 ;;
      image:rm:owned-image-id) exit 0 ;;
      *) exit 0 ;;
    esac
    ;;
  lost-owned|lost-foreign)
    if [ "${formatted}" -eq 1 ]; then
      if [ "${FAKE_MODE}" = "lost-owned" ]; then printf '%s\n' 'smoke-owner'; else printf '%s\n' 'foreign-owner'; fi
      exit 0
    fi
    case "${1}:${2}:${target}" in
      inspect:--type:smoke-container|image:inspect:smoke-image|rm:-f:smoke-container|image:rm:smoke-image) exit 0 ;;
    esac
    ;;
esac
exit 1
`
			if err := os.WriteFile(fakeDocker, []byte(fake), 0o700); err != nil {
				t.Fatal(err)
			}
			run := func(mode string, containerID, imageID string, createWorkdir bool) ([]byte, error) {
				t.Helper()
				workdir := filepath.Join(fakeRoot, "cdnca-edge-cache-task.case")
				if createWorkdir {
					if err := os.MkdirAll(workdir, 0o700); err != nil {
						t.Fatal(err)
					}
				}
				harness := strings.Join([]string{
					"set -eu", "tmp_base=" + shellQuote(fakeRoot), "workdir=" + shellQuote(workdir),
					"container=smoke-container", "image=smoke-image", "task_owner=smoke-owner",
					"container_label_key=cdnca.smoke.owner", "image_label_key=org.opencontainers.image.revision",
					"container_id=" + shellQuote(containerID), "image_id=" + shellQuote(imageID), "cleanup_failed=0",
					cleanupFunction, "cleanup 0",
				}, "\n")
				command := exec.Command("sh", "-c", harness)
				command.Env = append(os.Environ(), "PATH="+fakeRoot+":"+os.Getenv("PATH"), "DOCKER_LOG="+dockerLog, "FAKE_MODE="+mode)
				return command.CombinedOutput()
			}

			if output, err := run("replacement", "owned-container-id", "owned-image-id", true); err == nil {
				t.Fatalf("replacement cleanup succeeded: %s", output)
			}
			log, err := os.ReadFile(dockerLog)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(log), "rm -f") {
				t.Fatalf("replacement was deleted:\n%s", log)
			}
			if err := os.WriteFile(dockerLog, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if output, err := run("partial-failure", "owned-container-id", "owned-image-id", true); err == nil {
				t.Fatalf("removal failure was hidden: %s", output)
			}
			log, err = os.ReadFile(dockerLog)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(log), "rm -f owned-container-id") {
				t.Fatalf("exact owned ID was not removed:\n%s", log)
			}
			if !strings.Contains(string(log), "image rm owned-image-id") {
				t.Fatalf("partial cleanup did not continue to image:\n%s", log)
			}
			if output, err := run("absent", "owned-container-id", "owned-image-id", false); err != nil {
				t.Fatalf("idempotent cleanup error = %v: %s", err, output)
			}
			if err := os.WriteFile(dockerLog, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if output, err := run("lost-owned", "", "", true); err != nil {
				t.Fatalf("lost-ID owned cleanup error = %v: %s", err, output)
			}
			log, err = os.ReadFile(dockerLog)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(log), "rm -f smoke-container") ||
				!strings.Contains(string(log), "image rm smoke-image") {
				t.Fatalf("lost-ID owned resources were not removed by stable identity:\n%s", log)
			}
			if err := os.WriteFile(dockerLog, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if output, err := run("lost-foreign", "", "", true); err == nil {
				t.Fatalf("lost-ID foreign cleanup succeeded: %s", output)
			}
			log, err = os.ReadFile(dockerLog)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(log), "rm -f smoke-container") ||
				strings.Contains(string(log), "image rm smoke-image") {
				t.Fatalf("foreign stable resources were removed:\n%s", log)
			}
			for _, mode := range []string{"daemon-error", "permission-denied", "malformed-owner", "owner-error"} {
				if err := os.WriteFile(dockerLog, nil, 0o600); err != nil {
					t.Fatal(err)
				}
				output, runErr := run(mode, "owned-container-id", "owned-image-id", true)
				if runErr == nil {
					t.Fatalf("ambiguous %s cleanup succeeded: %s", mode, output)
				}
				log, err = os.ReadFile(dockerLog)
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(string(log), "owned-image-id") {
					t.Fatalf("ambiguous %s cleanup stopped before image inspection:\n%s", mode, log)
				}
			}
		})
	}
}

func TestEdgeCacheSmokeScriptsFailBeforeBuildOnNameCollisions(t *testing.T) {
	repositoryRoot := filepath.Clean(filepath.Join(filepath.Dir(smokeTestSourcePath(t)), "..", "..", "..", ".."))
	for _, relative := range []string{"scripts/edge-cache-task-smoke.sh"} {
		for _, mode := range []string{"container", "image"} {
			t.Run(filepath.Base(relative)+"/"+mode, func(t *testing.T) {
				fakeRoot := t.TempDir()
				fakeDocker := filepath.Join(fakeRoot, "docker")
				fake := `#!/bin/sh
case "${1}:${2}:${FAKE_COLLISION}" in
  info:* ) printf '%s\n' arm64; exit 0 ;;
  inspect:--type:container) exit 0 ;;
  inspect:--type:image) printf '%s\n' 'Error: No such object: smoke-container' >&2; exit 1 ;;
  image:inspect:image) exit 0 ;;
  image:inspect:container) printf '%s\n' 'Error: No such object: smoke-image' >&2; exit 1 ;;
  *) printf '%s\n' 'Error: No such object: smoke-resource' >&2; exit 1 ;;
esac
`
				if err := os.WriteFile(fakeDocker, []byte(fake), 0o700); err != nil {
					t.Fatal(err)
				}
				command := exec.Command("sh", filepath.Join(repositoryRoot, relative))
				command.Env = append(os.Environ(), "PATH="+fakeRoot+":"+os.Getenv("PATH"), "TMPDIR="+fakeRoot, "FAKE_COLLISION="+mode)
				output, err := command.CombinedOutput()
				if err == nil || !strings.Contains(string(output), mode+" name collision") &&
					!strings.Contains(string(output), mode+" tag collision") {
					t.Fatalf("%s %s collision error=%v output=%s", relative, mode, err, output)
				}
			})
		}
	}
}

func TestEdgeCacheTaskSmokeDefaultRunsRealLinuxLifecycle(t *testing.T) {
	repositoryRoot := filepath.Clean(filepath.Join(filepath.Dir(smokeTestSourcePath(t)), "..", "..", "..", ".."))
	content, err := os.ReadFile(filepath.Join(repositoryRoot, "scripts", "edge-cache-task-smoke.sh"))
	if err != nil {
		t.Fatal(err)
	}
	script := string(content)
	for _, testName := range []string{
		"TestSmokeProcessGroupPidfdsCollectsRealLinuxWorker",
		"TestStopSmokeRuntimeCleansRealLinuxWorkerAfterCommandLeaderExit",
		"TestStopSmokeRuntimeRetriesRealLinuxDescendantCloseFailure",
		"TestOpenRestyCacheTaskSmoke",
	} {
		if !strings.Contains(script, testName) {
			t.Errorf("default Linux smoke omits %s", testName)
		}
	}
	if !strings.Contains(script, `docker exec \`) ||
		strings.Contains(script, `/usr/local/bin/cachetask-smoke.test -test.run "${test_run}" -test.v ||`) {
		t.Fatal("Linux test failure is not propagated directly through docker exec")
	}
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func TestStartSmokeRuntimeBindsIdentityBeforeWait(t *testing.T) {
	originalPrepare := smokePrepareRuntimeCommand
	originalOpen := smokeOpenPidfd
	originalKill := smokeKillStartedProcess
	originalIdentity := smokeReadProcessIdentity
	originalStartWait := smokeStartCommandWait
	originalClose := smokeClosePidfd
	t.Cleanup(func() {
		smokePrepareRuntimeCommand = originalPrepare
		smokeOpenPidfd = originalOpen
		smokeKillStartedProcess = originalKill
		smokeReadProcessIdentity = originalIdentity
		smokeStartCommandWait = originalStartWait
		smokeClosePidfd = originalClose
	})
	smokePrepareRuntimeCommand = func(command *exec.Cmd) (*exec.Cmd, error) { return command, nil }

	events := make([]string, 0, 3)
	smokeOpenPidfd = func(int) (int, error) {
		events = append(events, "pidfd")
		return 7301, nil
	}
	smokeReadProcessIdentity = func(int) (string, bool) {
		events = append(events, "identity")
		return "original", true
	}
	smokeStartCommandWait = func(command *exec.Cmd) <-chan error {
		events = append(events, "wait")
		wait := make(chan error, 1)
		wait <- command.Wait()
		close(wait)
		return wait
	}
	var closes atomic.Int32
	smokeClosePidfd = func(int) error { closes.Add(1); return nil }

	runtime, err := startSmokeRuntime(exec.Command("sh", "-c", "exit 0"))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"pidfd", "identity", "wait"}; !reflect.DeepEqual(events, want) {
		t.Fatalf("startup acquisition order = %v, want %v", events, want)
	}
	if runtime.pidfd != 7301 || !runtime.ownsPidfd {
		t.Fatalf("started runtime pidfd=%d owns=%v", runtime.pidfd, runtime.ownsPidfd)
	}
	if err := stopSmokeRuntime(runtime, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if runtime.ownsPidfd || closes.Load() != 1 {
		t.Fatalf("stopped runtime owns=%v closes=%d", runtime.ownsPidfd, closes.Load())
	}
	if err := stopSmokeRuntime(runtime, &bytes.Buffer{}); err != nil || closes.Load() != 1 {
		t.Fatalf("repeated stop error=%v closes=%d", err, closes.Load())
	}
}

func TestStartSmokeRuntimeSurfacesBindingFailures(t *testing.T) {
	originalPrepare := smokePrepareRuntimeCommand
	originalOpen := smokeOpenPidfd
	originalKill := smokeKillStartedProcess
	originalIdentity := smokeReadProcessIdentity
	originalStartWait := smokeStartCommandWait
	originalPidfdSignal := smokeSignalPidfd
	originalClose := smokeClosePidfd
	t.Cleanup(func() {
		smokePrepareRuntimeCommand = originalPrepare
		smokeOpenPidfd = originalOpen
		smokeKillStartedProcess = originalKill
		smokeReadProcessIdentity = originalIdentity
		smokeStartCommandWait = originalStartWait
		smokeSignalPidfd = originalPidfdSignal
		smokeClosePidfd = originalClose
	})
	smokePrepareRuntimeCommand = func(command *exec.Cmd) (*exec.Cmd, error) { return command, nil }

	t.Run("pidfd open", func(t *testing.T) {
		openErr := errors.New("start pidfd open failure")
		killErr := errors.New("start pidfd cleanup kill failure")
		waitErr := errors.New("start pidfd cleanup wait failure")
		smokeOpenPidfd = func(int) (int, error) { return -1, openErr }
		smokeKillStartedProcess = func(*exec.Cmd) error { return killErr }
		smokeStartCommandWait = func(command *exec.Cmd) <-chan error {
			wait := make(chan error, 1)
			wait <- errors.Join(command.Wait(), waitErr)
			close(wait)
			return wait
		}
		_, err := startSmokeRuntime(exec.Command("sh", "-c", "exit 0"))
		if !errors.Is(err, openErr) || !errors.Is(err, killErr) || !errors.Is(err, waitErr) {
			t.Fatalf("pidfd open error = %v", err)
		}
	})

	t.Run("identity and wait", func(t *testing.T) {
		killErr := errors.New("identity cleanup kill failure")
		waitErr := errors.New("identity cleanup wait failure")
		closeErr := errors.New("identity cleanup close failure")
		var closes atomic.Int32
		smokeOpenPidfd = func(int) (int, error) { return 7302, nil }
		smokeReadProcessIdentity = func(int) (string, bool) { return "", false }
		smokeKillStartedProcess = func(*exec.Cmd) error { return killErr }
		smokeStartCommandWait = func(command *exec.Cmd) <-chan error {
			wait := make(chan error, 1)
			wait <- errors.Join(command.Wait(), waitErr)
			close(wait)
			return wait
		}
		smokeClosePidfd = func(int) error { closes.Add(1); return closeErr }
		_, err := startSmokeRuntime(exec.Command("sh", "-c", "exit 0"))
		if err == nil || !errors.Is(err, killErr) || !errors.Is(err, waitErr) ||
			!errors.Is(err, closeErr) || closes.Load() != 1 {
			t.Fatalf("identity failure error=%v closes=%d", err, closes.Load())
		}
	})
}

func TestSmokeProcessGroupPidfdsBindsDescendantIdentity(t *testing.T) {
	originalList := smokeListProcessSnapshots
	originalReadSnapshot := smokeReadProcessSnapshot
	originalReadLeader := smokeReadProcessIdentity
	originalOpen := smokeOpenPidfd
	originalSignal := smokeSignalPidfd
	originalClose := smokeClosePidfd
	t.Cleanup(func() {
		smokeListProcessSnapshots = originalList
		smokeReadProcessSnapshot = originalReadSnapshot
		smokeReadProcessIdentity = originalReadLeader
		smokeOpenPidfd = originalOpen
		smokeSignalPidfd = originalSignal
		smokeClosePidfd = originalClose
	})

	leader := &smokeRuntimeProcess{processID: 500, startTime: "leader", pidfd: 9000, ownsPidfd: true}
	smokeReadProcessIdentity = func(processID int) (string, bool) {
		return "leader", processID == leader.processID
	}
	smokeListProcessSnapshots = func() ([]smokeProcessSnapshot, error) {
		return []smokeProcessSnapshot{{processID: 501, processGroup: 500, startIdentity: "worker-original"}}, nil
	}
	smokeOpenPidfd = func(processID int) (int, error) {
		if processID != 501 {
			t.Fatalf("open pidfd process = %d", processID)
		}
		return 9101, nil
	}

	t.Run("stable worker", func(t *testing.T) {
		var probes []int
		var closes atomic.Int32
		smokeReadProcessSnapshot = func(processID int) (smokeProcessSnapshot, bool) {
			return smokeProcessSnapshot{processID: processID, processGroup: 500, startIdentity: "worker-original"}, true
		}
		smokeSignalPidfd = func(pidfd int, signal syscall.Signal) error {
			if signal != 0 {
				t.Fatalf("unexpected signal %v", signal)
			}
			probes = append(probes, pidfd)
			return nil
		}
		smokeClosePidfd = func(int) error { closes.Add(1); return nil }
		collection, err := smokeProcessGroupPidfds(leader)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(collection.descendants, []int{9101}) || len(collection.rejected) != 0 {
			t.Fatalf("stable worker pidfds = %+v", collection)
		}
		if want := []int{9000, 9101}; !reflect.DeepEqual(probes, want) {
			t.Fatalf("identity probes = %v, want %v", probes, want)
		}
		if closes.Load() != 0 {
			t.Fatalf("retained worker closes = %d", closes.Load())
		}
	})

	t.Run("reused worker", func(t *testing.T) {
		var probes []int
		var closes atomic.Int32
		smokeReadProcessSnapshot = func(processID int) (smokeProcessSnapshot, bool) {
			return smokeProcessSnapshot{processID: processID, processGroup: 500, startIdentity: "worker-reused"}, true
		}
		smokeSignalPidfd = func(pidfd int, signal syscall.Signal) error {
			if signal != 0 {
				t.Fatalf("unexpected signal %v", signal)
			}
			probes = append(probes, pidfd)
			return nil
		}
		smokeClosePidfd = func(int) error { closes.Add(1); return nil }
		collection, err := smokeProcessGroupPidfds(leader)
		if err != nil {
			t.Fatal(err)
		}
		if len(collection.descendants) != 0 || len(collection.rejected) != 0 || closes.Load() != 1 {
			t.Fatalf("reused worker pidfds=%+v closes=%d", collection, closes.Load())
		}
		if want := []int{9000}; !reflect.DeepEqual(probes, want) {
			t.Fatalf("reused worker probes = %v, want %v", probes, want)
		}
	})

	t.Run("open failure", func(t *testing.T) {
		openErr := errors.New("worker pidfd open failure")
		smokeOpenPidfd = func(int) (int, error) { return -1, openErr }
		smokeSignalPidfd = func(int, syscall.Signal) error { return nil }
		collection, err := smokeProcessGroupPidfds(leader)
		if len(collection.descendants) != 0 || len(collection.rejected) != 0 || !errors.Is(err, openErr) {
			t.Fatalf("open failure pidfds=%+v error=%v", collection, err)
		}
	})
}

func TestStopSmokeRuntimeRetriesRejectedPidfdCloseFailures(t *testing.T) {
	originalList := smokeListProcessSnapshots
	originalReadSnapshot := smokeReadProcessSnapshot
	originalReadLeader := smokeReadProcessIdentity
	originalOpen := smokeOpenPidfd
	originalPidfdSignal := smokeSignalPidfd
	originalLeaderSignal := smokeSignalProcessGroup
	originalClose := smokeClosePidfd
	originalTimeout := smokeStopTimeout
	t.Cleanup(func() {
		smokeListProcessSnapshots = originalList
		smokeReadProcessSnapshot = originalReadSnapshot
		smokeReadProcessIdentity = originalReadLeader
		smokeOpenPidfd = originalOpen
		smokeSignalPidfd = originalPidfdSignal
		smokeSignalProcessGroup = originalLeaderSignal
		smokeClosePidfd = originalClose
		smokeStopTimeout = originalTimeout
	})
	smokeStopTimeout = time.Millisecond
	wait := make(chan error, 1)
	runtime := &smokeRuntimeProcess{
		processID: 500, startTime: "leader", pidfd: 9000, ownsPidfd: true, wait: wait,
	}
	smokeReadProcessIdentity = func(processID int) (string, bool) {
		return "leader", processID == runtime.processID
	}
	var lists atomic.Int32
	smokeListProcessSnapshots = func() ([]smokeProcessSnapshot, error) {
		if lists.Add(1) != 1 {
			return nil, nil
		}
		return []smokeProcessSnapshot{
			{processID: 501, processGroup: 500, startIdentity: "accepted"},
			{processID: 502, processGroup: 500, startIdentity: "rejected-a"},
			{processID: 503, processGroup: 500, startIdentity: "rejected-b"},
		}, nil
	}
	smokeOpenPidfd = func(processID int) (int, error) { return processID + 8600, nil }
	smokeReadProcessSnapshot = func(processID int) (smokeProcessSnapshot, bool) {
		identity := "accepted"
		if processID != 501 {
			identity = "reused"
		}
		return smokeProcessSnapshot{processID: processID, processGroup: 500, startIdentity: identity}, true
	}
	smokePidfdSignalCalls := make(map[int]int)
	smokeSignalPidfd = func(pidfd int, signal syscall.Signal) error {
		smokePidfdSignalCalls[pidfd]++
		if pidfd == 9101 && signal == 0 && smokePidfdSignalCalls[pidfd] > 1 {
			return syscall.ESRCH
		}
		return nil
	}
	smokeSignalProcessGroup = func(_ *smokeRuntimeProcess, signal syscall.Signal) error {
		if signal == syscall.SIGTERM {
			wait <- nil
		}
		return nil
	}
	closeA := errors.New("rejected pidfd A close failure")
	closeB := errors.New("rejected pidfd B close failure")
	closeAttempts := make(map[int]int)
	closeSuccesses := make(map[int]int)
	smokeClosePidfd = func(pidfd int) error {
		closeAttempts[pidfd]++
		if closeAttempts[pidfd] == 1 {
			switch pidfd {
			case 9102:
				return closeA
			case 9103:
				return closeB
			}
		}
		closeSuccesses[pidfd]++
		return nil
	}

	firstErr := stopSmokeRuntime(runtime, &bytes.Buffer{})
	if !errors.Is(firstErr, closeA) || !errors.Is(firstErr, closeB) || runtime.stopped {
		t.Fatalf("first close error=%v stopped=%v", firstErr, runtime.stopped)
	}
	finalErr := stopSmokeRuntime(runtime, &bytes.Buffer{})
	if !errors.Is(finalErr, closeA) || !errors.Is(finalErr, closeB) || !runtime.stopped {
		t.Fatalf("final close error=%v stopped=%v", finalErr, runtime.stopped)
	}
	for _, pidfd := range []int{9102, 9103} {
		if closeAttempts[pidfd] != 2 || closeSuccesses[pidfd] != 1 {
			t.Errorf("rejected pidfd %d close attempts=%d successes=%d", pidfd, closeAttempts[pidfd], closeSuccesses[pidfd])
		}
	}
	if closeAttempts[9101] != 1 || closeSuccesses[9101] != 1 {
		t.Errorf("accepted pidfd close attempts=%d successes=%d", closeAttempts[9101], closeSuccesses[9101])
	}
}

func TestSmokeProcessGroupPidfdsCollectsRealLinuxWorker(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires Linux pidfds and /proc")
	}
	workerReader, workerWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	releaseReader, releaseWriter, err := os.Pipe()
	if err != nil {
		_ = workerReader.Close()
		_ = workerWriter.Close()
		t.Fatal(err)
	}
	command := exec.Command("sh", "-c", `sleep 300 & worker=$!; printf '%s\n' "$worker" >&3; IFS= read -r _ <&4; wait "$worker"`)
	command.ExtraFiles = []*os.File{workerWriter, releaseReader}
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	smokeRuntime, err := startSmokeRuntime(command)
	_ = workerWriter.Close()
	_ = releaseReader.Close()
	if err != nil {
		_ = workerReader.Close()
		_ = releaseWriter.Close()
		t.Fatal(err)
	}
	var workerPID int
	if _, err := fmt.Fscan(workerReader, &workerPID); err != nil {
		_ = workerReader.Close()
		_ = releaseWriter.Close()
		_ = stopSmokeRuntime(smokeRuntime, &bytes.Buffer{})
		t.Fatal(err)
	}
	_ = workerReader.Close()
	workerCleanupFD, err := smokePidfdOpen(workerPID)
	if err != nil {
		_ = releaseWriter.Close()
		_ = stopSmokeRuntime(smokeRuntime, &bytes.Buffer{})
		t.Fatal(err)
	}
	workerCleaned := false
	t.Cleanup(func() {
		if !workerCleaned {
			_ = smokePidfdSendSignal(workerCleanupFD, syscall.SIGKILL)
		}
		_ = syscall.Close(workerCleanupFD)
		_, _ = releaseWriter.Write([]byte("release\n"))
		_ = releaseWriter.Close()
		_ = stopSmokeRuntime(smokeRuntime, &bytes.Buffer{})
	})

	foreign := exec.Command("sleep", "300")
	foreign.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := foreign.Start(); err != nil {
		t.Fatal(err)
	}
	foreignFD, err := smokePidfdOpen(foreign.Process.Pid)
	if err != nil {
		_ = foreign.Process.Kill()
		_ = foreign.Wait()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = smokePidfdSendSignal(foreignFD, syscall.SIGKILL)
		_ = syscall.Close(foreignFD)
		_ = foreign.Wait()
	})

	collection, err := smokeProcessGroupPidfds(smokeRuntime)
	if err != nil {
		t.Fatal(err)
	}
	if len(collection.descendants) < 2 || len(collection.rejected) != 0 {
		t.Fatalf("collected descendant pidfds = %+v, want command child and worker", collection)
	}
	workerFound := false
	var closedStat syscall.Stat_t
	for _, pidfd := range collection.descendants {
		collectedPID, identityErr := smokePidfdProcessID(pidfd)
		if identityErr != nil {
			t.Fatal(identityErr)
		}
		if collectedPID == foreign.Process.Pid {
			t.Fatalf("collector captured foreign pid=%d", collectedPID)
		}
		if collectedPID == workerPID {
			workerFound = true
			if err := smokePidfdSendSignal(pidfd, syscall.SIGKILL); err != nil {
				t.Fatal(err)
			}
		}
		if err := syscall.Close(pidfd); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Fstat(pidfd, &closedStat); !errors.Is(err, syscall.EBADF) {
			t.Fatalf("descendant pidfd remained open: %v", err)
		}
	}
	if !workerFound {
		t.Fatalf("collector omitted worker pid=%d", workerPID)
	}
	workerCleaned = true
	if _, err := releaseWriter.Write([]byte("release\n")); err != nil {
		t.Fatal(err)
	}
	if err := releaseWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := waitForSmokeProcessExit(workerPID, time.Second); err != nil {
		t.Fatal(err)
	}
	// The supervisor must record the command's non-zero status before TERM;
	// otherwise its trap exits with the initial status 0 (seen under CPU contention).
	if err := waitForSmokeSupervisorIdle(smokeRuntime.processID, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	leaderFD := smokeRuntime.pidfd
	stopErr := stopSmokeRuntime(smokeRuntime, &bytes.Buffer{})
	if stopErr == nil {
		t.Fatal("killed worker wait failure was suppressed")
	}
	if smokeRuntime.ownsPidfd {
		t.Fatal("terminal leader retained pidfd ownership")
	}
	if err := syscall.Fstat(leaderFD, &closedStat); !errors.Is(err, syscall.EBADF) {
		t.Fatalf("leader pidfd remained open: %v", err)
	}
	if repeated := stopSmokeRuntime(smokeRuntime, &bytes.Buffer{}); repeated != stopErr {
		t.Fatalf("repeated stop error=%v, want identical %v", repeated, stopErr)
	}
}

func TestStopSmokeRuntimeRetriesRealLinuxDescendantCloseFailure(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires Linux pidfds and /proc")
	}
	originalClose := smokeClosePidfd
	originalOpen := smokeOpenPidfd
	originalTimeout := smokeStopTimeout
	t.Cleanup(func() {
		smokeClosePidfd = originalClose
		smokeOpenPidfd = originalOpen
		smokeStopTimeout = originalTimeout
	})
	smokeStopTimeout = 100 * time.Millisecond

	workerReader, workerWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("sh", "-c", `trap '' TERM; sleep 300 & worker=$!; printf '%s\n' "$worker" >&3; wait "$worker"`)
	command.ExtraFiles = []*os.File{workerWriter}
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	smokeRuntime, err := startSmokeRuntime(command)
	_ = workerWriter.Close()
	if err != nil {
		_ = workerReader.Close()
		t.Fatal(err)
	}
	var workerPID int
	if _, err := fmt.Fscan(workerReader, &workerPID); err != nil {
		_ = workerReader.Close()
		_ = stopSmokeRuntime(smokeRuntime, &bytes.Buffer{})
		t.Fatal(err)
	}
	_ = workerReader.Close()
	workerCleanupFD, err := smokePidfdOpen(workerPID)
	if err != nil {
		_ = stopSmokeRuntime(smokeRuntime, &bytes.Buffer{})
		t.Fatal(err)
	}
	workerReaped := false
	t.Cleanup(func() {
		if !workerReaped {
			_ = smokePidfdSendSignal(workerCleanupFD, syscall.SIGKILL)
		}
		_ = syscall.Close(workerCleanupFD)
		_ = stopSmokeRuntime(smokeRuntime, &bytes.Buffer{})
	})

	foreign := exec.Command("sleep", "300")
	foreign.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := foreign.Start(); err != nil {
		t.Fatal(err)
	}
	foreignFD, err := smokePidfdOpen(foreign.Process.Pid)
	if err != nil {
		_ = foreign.Process.Kill()
		_ = foreign.Wait()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = smokePidfdSendSignal(foreignFD, syscall.SIGKILL)
		_ = syscall.Close(foreignFD)
		_ = foreign.Wait()
	})

	closeErr := errors.New("real worker pidfd close failure")
	var workerCloseAttempts, leaderCloses atomic.Int32
	var workerFD atomic.Int32
	smokeOpenPidfd = func(processID int) (int, error) {
		pidfd, openErr := originalOpen(processID)
		if openErr == nil && processID == workerPID {
			workerFD.Store(int32(pidfd))
		}
		return pidfd, openErr
	}
	smokeClosePidfd = func(pidfd int) error {
		if pidfd == smokeRuntime.pidfd {
			leaderCloses.Add(1)
			return originalClose(pidfd)
		}
		if int32(pidfd) == workerFD.Load() {
			if workerCloseAttempts.Add(1) == 1 {
				return closeErr
			}
		}
		return originalClose(pidfd)
	}

	firstErr := stopSmokeRuntime(smokeRuntime, &bytes.Buffer{})
	if !errors.Is(firstErr, closeErr) || smokeRuntime.stopped || !smokeRuntime.leaderExited ||
		len(smokeRuntime.descendantPidfds) != 1 || workerCloseAttempts.Load() != 1 || leaderCloses.Load() != 0 {
		t.Fatalf("first real stop error=%v stopped=%v leaderExited=%v descendants=%v workerCloses=%d leaderCloses=%d",
			firstErr, smokeRuntime.stopped, smokeRuntime.leaderExited, smokeRuntime.descendantPidfds,
			workerCloseAttempts.Load(), leaderCloses.Load())
	}
	if err := smokePidfdSendSignal(foreignFD, 0); err != nil {
		t.Fatalf("foreign process changed after first stop: %v", err)
	}

	finalErr := stopSmokeRuntime(smokeRuntime, &bytes.Buffer{})
	if !errors.Is(finalErr, closeErr) || !smokeRuntime.stopped || smokeRuntime.ownsPidfd ||
		len(smokeRuntime.descendantPidfds) != 0 || workerCloseAttempts.Load() != 2 || leaderCloses.Load() != 1 {
		t.Fatalf("final real stop error=%v stopped=%v owns=%v descendants=%v workerCloses=%d leaderCloses=%d",
			finalErr, smokeRuntime.stopped, smokeRuntime.ownsPidfd, smokeRuntime.descendantPidfds,
			workerCloseAttempts.Load(), leaderCloses.Load())
	}
	if err := waitForSmokeProcessExit(workerPID, time.Second); err != nil {
		t.Fatal(err)
	}
	workerReaped = true
	if err := smokePidfdSendSignal(foreignFD, 0); err != nil {
		t.Fatalf("foreign process changed after retry: %v", err)
	}
	beforeWorkerCloses, beforeLeaderCloses := workerCloseAttempts.Load(), leaderCloses.Load()
	if repeated := stopSmokeRuntime(smokeRuntime, &bytes.Buffer{}); repeated != finalErr ||
		workerCloseAttempts.Load() != beforeWorkerCloses || leaderCloses.Load() != beforeLeaderCloses {
		t.Fatalf("repeated real stop error=%v workerCloses=%d leaderCloses=%d",
			repeated, workerCloseAttempts.Load(), leaderCloses.Load())
	}
}

func TestStopSmokeRuntimeCleansRealLinuxWorkerAfterCommandLeaderExit(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires Linux pidfds and /proc")
	}
	originalClose := smokeClosePidfd
	originalOpen := smokeOpenPidfd
	originalTimeout := smokeStopTimeout
	t.Cleanup(func() {
		smokeClosePidfd = originalClose
		smokeOpenPidfd = originalOpen
		smokeStopTimeout = originalTimeout
	})
	smokeStopTimeout = 100 * time.Millisecond

	identityReader, identityWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("sh", "-c", `sleep 300 & worker=$!; printf '%s %s\n' "$$" "$worker" >&3; exit 0`)
	command.ExtraFiles = []*os.File{identityWriter}
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	smokeRuntime, err := startSmokeRuntime(command)
	_ = identityWriter.Close()
	if err != nil {
		_ = identityReader.Close()
		t.Fatal(err)
	}
	var commandLeaderPID, workerPID int
	if _, err := fmt.Fscan(identityReader, &commandLeaderPID, &workerPID); err != nil {
		_ = identityReader.Close()
		_ = stopSmokeRuntime(smokeRuntime, &bytes.Buffer{})
		t.Fatal(err)
	}
	_ = identityReader.Close()
	workerCleanupFD, err := smokePidfdOpen(workerPID)
	if err != nil {
		_ = stopSmokeRuntime(smokeRuntime, &bytes.Buffer{})
		t.Fatal(err)
	}
	workerReaped := false
	t.Cleanup(func() {
		if !workerReaped {
			_ = smokePidfdSendSignal(workerCleanupFD, syscall.SIGKILL)
		}
		_ = syscall.Close(workerCleanupFD)
		_ = stopSmokeRuntime(smokeRuntime, &bytes.Buffer{})
	})
	if err := waitForSmokeProcessExit(commandLeaderPID, time.Second); err != nil {
		t.Fatal(err)
	}
	// A group TERM racing the supervisor's fork of its idle sleep is missed by the
	// new child, and dash defers the trap until that child exits (KILL path).
	if err := waitForSmokeSupervisorIdle(smokeRuntime.processID, 5*time.Second); err != nil {
		t.Fatal(err)
	}

	closeErr := errors.New("post-leader worker pidfd close failure")
	var workerCloseAttempts, workerCloseSuccesses, leaderCloses atomic.Int32
	var workerFD atomic.Int32
	smokeOpenPidfd = func(processID int) (int, error) {
		pidfd, openErr := originalOpen(processID)
		if openErr == nil && processID == workerPID {
			workerFD.Store(int32(pidfd))
		}
		return pidfd, openErr
	}
	smokeClosePidfd = func(pidfd int) error {
		if pidfd == smokeRuntime.pidfd {
			leaderCloses.Add(1)
			return originalClose(pidfd)
		}
		if int32(pidfd) == workerFD.Load() {
			if workerCloseAttempts.Add(1) == 1 {
				return closeErr
			}
			workerCloseSuccesses.Add(1)
		}
		return originalClose(pidfd)
	}
	firstErr := stopSmokeRuntime(smokeRuntime, &bytes.Buffer{})
	if !errors.Is(firstErr, closeErr) || smokeRuntime.stopped || workerCloseAttempts.Load() != 1 || leaderCloses.Load() != 0 {
		t.Fatalf("first post-leader stop error=%v stopped=%v worker closes=%d leader closes=%d",
			firstErr, smokeRuntime.stopped, workerCloseAttempts.Load(), leaderCloses.Load())
	}
	finalErr := stopSmokeRuntime(smokeRuntime, &bytes.Buffer{})
	if !errors.Is(finalErr, closeErr) || !smokeRuntime.stopped || workerCloseAttempts.Load() != 2 ||
		workerCloseSuccesses.Load() != 1 || leaderCloses.Load() != 1 {
		t.Fatalf("final post-leader stop error=%v stopped=%v attempts=%d successes=%d leader closes=%d",
			finalErr, smokeRuntime.stopped, workerCloseAttempts.Load(), workerCloseSuccesses.Load(), leaderCloses.Load())
	}
	if err := waitForSmokeProcessExit(workerPID, time.Second); err != nil {
		t.Fatal(err)
	}
	workerReaped = true
}

func smokePidfdProcessID(pidfd int) (int, error) {
	content, err := os.ReadFile(filepath.Join("/proc/self/fdinfo", strconv.Itoa(pidfd)))
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(content), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "Pid:" {
			return strconv.Atoi(fields[1])
		}
	}
	return 0, errors.New("pidfd process identity is unavailable")
}

func waitForSmokeProcessExit(processID int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(filepath.Join("/proc", strconv.Itoa(processID))); errors.Is(err, os.ErrNotExist) {
			return nil
		}
		time.Sleep(time.Millisecond)
	}
	return fmt.Errorf("process %d was not reaped", processID)
}

// waitForSmokeSupervisorIdle waits until the smoke supervisor has reaped the
// wrapped command and entered its sleep loop, i.e. child_status is recorded.
func waitForSmokeSupervisorIdle(supervisorPID int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		entries, err := os.ReadDir("/proc")
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if _, err := strconv.Atoi(entry.Name()); err != nil {
				continue
			}
			content, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "stat"))
			closing := bytes.LastIndexByte(content, ')')
			opening := bytes.IndexByte(content, '(')
			if err != nil || opening < 0 || closing < opening {
				continue
			}
			fields := strings.Fields(string(content[closing+1:]))
			if len(fields) > 1 && fields[1] == strconv.Itoa(supervisorPID) && string(content[opening+1:closing]) == "sleep" {
				return nil
			}
		}
		time.Sleep(time.Millisecond)
	}
	return fmt.Errorf("smoke supervisor %d did not reach its idle loop", supervisorPID)
}

func TestStopSmokeRuntimeUsesIdentityBoundSignalOrdering(t *testing.T) {
	originalSignal := smokeSignalProcessGroup
	originalPidfdSignal := smokeSignalPidfd
	originalClose := smokeClosePidfd
	originalCollect := smokeCollectProcessGroupPidfds
	originalTimeout := smokeStopTimeout
	t.Cleanup(func() {
		smokeSignalProcessGroup = originalSignal
		smokeSignalPidfd = originalPidfdSignal
		smokeClosePidfd = originalClose
		smokeCollectProcessGroupPidfds = originalCollect
		smokeStopTimeout = originalTimeout
	})
	smokeStopTimeout = time.Millisecond
	smokeClosePidfd = func(int) error { return nil }

	t.Run("completed wait is consumed before signaling", func(t *testing.T) {
		wait := make(chan error, 1)
		wait <- nil
		close(wait)
		var signals, collections atomic.Int32
		smokeSignalProcessGroup = func(*smokeRuntimeProcess, syscall.Signal) error { signals.Add(1); return nil }
		smokeCollectProcessGroupPidfds = func(*smokeRuntimeProcess) (smokePidfdCollection, error) {
			collections.Add(1)
			return smokePidfdCollection{}, nil
		}
		runtime := &smokeRuntimeProcess{processID: 42001, startTime: "owned", wait: wait}
		if err := stopSmokeRuntime(runtime, &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
		if signals.Load() != 0 || collections.Load() != 0 {
			t.Fatalf("completed runtime signals=%d collections=%d", signals.Load(), collections.Load())
		}
	})

	t.Run("leader loss never collects numeric process group", func(t *testing.T) {
		wait := make(chan error, 1)
		var collections, descendantSignals atomic.Int32
		smokeSignalProcessGroup = func(_ *smokeRuntimeProcess, signal syscall.Signal) error {
			switch signal {
			case syscall.SIGTERM:
				return nil
			case syscall.SIGSTOP:
				wait <- nil
				return syscall.ESRCH
			case syscall.SIGKILL:
				select {
				case wait <- nil:
				default:
				}
				return nil
			default:
				return nil
			}
		}
		smokeCollectProcessGroupPidfds = func(*smokeRuntimeProcess) (smokePidfdCollection, error) {
			collections.Add(1)
			return smokePidfdCollection{descendants: []int{9901}}, nil
		}
		smokeSignalPidfd = func(int, syscall.Signal) error { descendantSignals.Add(1); return nil }
		runtime := &smokeRuntimeProcess{processID: 42002, startTime: "owned", wait: wait}
		if err := stopSmokeRuntime(runtime, &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
		if collections.Load() != 0 || descendantSignals.Load() != 0 {
			t.Fatalf("unproven leader collections=%d descendant signals=%d", collections.Load(), descendantSignals.Load())
		}
	})

	t.Run("frozen live leader anchors descendant collection", func(t *testing.T) {
		wait := make(chan error, 1)
		events := make([]string, 0, 6)
		smokeSignalProcessGroup = func(_ *smokeRuntimeProcess, signal syscall.Signal) error {
			events = append(events, "leader:"+strconv.Itoa(int(signal)))
			if signal == syscall.SIGKILL {
				wait <- nil
			}
			return nil
		}
		smokeCollectProcessGroupPidfds = func(*smokeRuntimeProcess) (smokePidfdCollection, error) {
			events = append(events, "collect")
			return smokePidfdCollection{descendants: []int{9902}}, nil
		}
		smokeSignalPidfd = func(pidfd int, signal syscall.Signal) error {
			events = append(events, fmt.Sprintf("pidfd:%d:%d", pidfd, signal))
			if signal == 0 && strings.Count(strings.Join(events, ","), fmt.Sprintf("pidfd:%d:0", pidfd)) == 2 {
				return syscall.ESRCH
			}
			return nil
		}
		runtime := &smokeRuntimeProcess{processID: 42003, startTime: "owned", wait: wait}
		if err := stopSmokeRuntime(runtime, &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
		want := []string{
			"leader:" + strconv.Itoa(int(syscall.SIGSTOP)),
			"collect",
			"leader:0",
			"leader:" + strconv.Itoa(int(syscall.SIGTERM)),
			"leader:" + strconv.Itoa(int(syscall.SIGCONT)),
			fmt.Sprintf("pidfd:%d:%d", 9902, syscall.SIGKILL),
			fmt.Sprintf("pidfd:%d:0", 9902),
			"leader:" + strconv.Itoa(int(syscall.SIGKILL)),
			fmt.Sprintf("pidfd:%d:0", 9902),
		}
		if !reflect.DeepEqual(events, want) {
			t.Fatalf("signal order = %v, want %v", events, want)
		}
	})

	t.Run("term exit still cleans bound descendants", func(t *testing.T) {
		wait := make(chan error, 1)
		var events []string
		var closes []int
		smokeSignalProcessGroup = func(_ *smokeRuntimeProcess, signal syscall.Signal) error {
			events = append(events, "leader:"+strconv.Itoa(int(signal)))
			if signal == syscall.SIGTERM {
				wait <- nil
			}
			return nil
		}
		smokeCollectProcessGroupPidfds = func(*smokeRuntimeProcess) (smokePidfdCollection, error) {
			events = append(events, "collect")
			return smokePidfdCollection{descendants: []int{9904}}, nil
		}
		smokeSignalPidfd = func(pidfd int, signal syscall.Signal) error {
			events = append(events, fmt.Sprintf("pidfd:%d:%d", pidfd, signal))
			if signal == 0 {
				return syscall.ESRCH
			}
			return nil
		}
		smokeClosePidfd = func(pidfd int) error {
			closes = append(closes, pidfd)
			return nil
		}
		runtime := &smokeRuntimeProcess{
			processID: 42011, startTime: "owned", pidfd: 9802, ownsPidfd: true, wait: wait,
		}
		if err := stopSmokeRuntime(runtime, &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
		want := []string{
			"leader:" + strconv.Itoa(int(syscall.SIGSTOP)),
			"collect",
			"leader:0",
			"leader:" + strconv.Itoa(int(syscall.SIGTERM)),
			"leader:" + strconv.Itoa(int(syscall.SIGCONT)),
			fmt.Sprintf("pidfd:%d:%d", 9904, syscall.SIGKILL),
			fmt.Sprintf("pidfd:%d:0", 9904),
		}
		if !reflect.DeepEqual(events, want) || !reflect.DeepEqual(closes, []int{9904, 9802}) {
			t.Fatalf("term exit events=%v closes=%v, want events=%v closes=%v", events, closes, want, []int{9904, 9802})
		}
	})
}

func TestStopSmokeRuntimeRetriesIncompleteCleanup(t *testing.T) {
	originalSignal := smokeSignalProcessGroup
	originalCollect := smokeCollectProcessGroupPidfds
	originalTimeout := smokeStopTimeout
	t.Cleanup(func() {
		smokeSignalProcessGroup = originalSignal
		smokeCollectProcessGroupPidfds = originalCollect
		smokeStopTimeout = originalTimeout
	})
	smokeStopTimeout = time.Millisecond
	wait := make(chan error, 1)
	var phase, signals atomic.Int32
	smokeCollectProcessGroupPidfds = func(*smokeRuntimeProcess) (smokePidfdCollection, error) {
		return smokePidfdCollection{}, nil
	}
	smokeSignalProcessGroup = func(_ *smokeRuntimeProcess, signal syscall.Signal) error {
		signals.Add(1)
		if phase.Load() == 0 {
			if signal == syscall.SIGKILL {
				return syscall.EPERM
			}
			return nil
		}
		if signal == syscall.SIGTERM {
			wait <- nil
		}
		return nil
	}
	runtime := &smokeRuntimeProcess{processID: 42004, startTime: "owned", wait: wait}
	if err := stopSmokeRuntime(runtime, &bytes.Buffer{}); err == nil {
		t.Fatal("incomplete first stop succeeded")
	}
	firstSignals := signals.Load()
	phase.Store(1)
	start := make(chan struct{})
	errorsSeen := make(chan error, 2)
	for range 2 {
		go func() {
			<-start
			errorsSeen <- stopSmokeRuntime(runtime, &bytes.Buffer{})
		}()
	}
	close(start)
	for range 2 {
		if err := <-errorsSeen; !errors.Is(err, syscall.EPERM) {
			t.Fatalf("retry stop error = %v, want retained EPERM", err)
		}
	}
	if signals.Load() != firstSignals+4 {
		t.Fatalf("concurrent retry signals=%d, want %d", signals.Load(), firstSignals+4)
	}
}

func TestStopSmokeRuntimeRetainsDescendantsAcrossLeaderExit(t *testing.T) {
	originalSignal := smokeSignalProcessGroup
	originalPidfdSignal := smokeSignalPidfd
	originalClose := smokeClosePidfd
	originalCollect := smokeCollectProcessGroupPidfds
	originalTimeout := smokeStopTimeout
	t.Cleanup(func() {
		smokeSignalProcessGroup = originalSignal
		smokeSignalPidfd = originalPidfdSignal
		smokeClosePidfd = originalClose
		smokeCollectProcessGroupPidfds = originalCollect
		smokeStopTimeout = originalTimeout
	})
	smokeStopTimeout = time.Millisecond
	wait := make(chan error, 1)
	workerKillErr := errors.New("worker KILL failure")
	var phase, collections atomic.Int32
	var signals []string
	var closes []int
	smokeSignalProcessGroup = func(_ *smokeRuntimeProcess, signal syscall.Signal) error {
		signals = append(signals, "leader:"+strconv.Itoa(int(signal)))
		if signal == syscall.SIGKILL {
			wait <- nil
		}
		return nil
	}
	smokeCollectProcessGroupPidfds = func(*smokeRuntimeProcess) (smokePidfdCollection, error) {
		collections.Add(1)
		return smokePidfdCollection{descendants: []int{9903}}, nil
	}
	smokeSignalPidfd = func(pidfd int, signal syscall.Signal) error {
		signals = append(signals, fmt.Sprintf("worker:%d:%d", pidfd, signal))
		if signal == syscall.SIGKILL && phase.Load() == 0 {
			return workerKillErr
		}
		if signal == 0 {
			return syscall.ESRCH
		}
		return nil
	}
	smokeClosePidfd = func(pidfd int) error {
		closes = append(closes, pidfd)
		return nil
	}
	runtime := &smokeRuntimeProcess{
		processID: 42009, startTime: "owned", pidfd: 9800, ownsPidfd: true, wait: wait,
	}
	firstErr := stopSmokeRuntime(runtime, &bytes.Buffer{})
	if !errors.Is(firstErr, workerKillErr) || runtime.stopped || !runtime.leaderExited ||
		!runtime.ownsPidfd || !reflect.DeepEqual(runtime.descendantPidfds, []int{9903}) {
		t.Fatalf("first stop error=%v stopped=%v leaderExited=%v owns=%v descendants=%v",
			firstErr, runtime.stopped, runtime.leaderExited, runtime.ownsPidfd, runtime.descendantPidfds)
	}
	if len(closes) != 0 || collections.Load() != 1 {
		t.Fatalf("first stop closes=%v collections=%d", closes, collections.Load())
	}
	phase.Store(1)
	finalErr := stopSmokeRuntime(runtime, &bytes.Buffer{})
	if !errors.Is(finalErr, workerKillErr) || !runtime.stopped || runtime.ownsPidfd ||
		len(runtime.descendantPidfds) != 0 {
		t.Fatalf("final stop error=%v stopped=%v owns=%v descendants=%v",
			finalErr, runtime.stopped, runtime.ownsPidfd, runtime.descendantPidfds)
	}
	if !reflect.DeepEqual(closes, []int{9903, 9800}) || collections.Load() != 1 {
		t.Fatalf("final closes=%v collections=%d", closes, collections.Load())
	}
	beforeSignals := len(signals)
	if repeated := stopSmokeRuntime(runtime, &bytes.Buffer{}); repeated != finalErr || len(signals) != beforeSignals {
		t.Fatalf("repeated stop error=%v signals=%v", repeated, signals)
	}
}

func TestStopSmokeRuntimeRetriesCollectorFailureBeforeLeaderExit(t *testing.T) {
	originalSignal := smokeSignalProcessGroup
	originalCollect := smokeCollectProcessGroupPidfds
	originalClose := smokeClosePidfd
	originalTimeout := smokeStopTimeout
	t.Cleanup(func() {
		smokeSignalProcessGroup = originalSignal
		smokeCollectProcessGroupPidfds = originalCollect
		smokeClosePidfd = originalClose
		smokeStopTimeout = originalTimeout
	})
	smokeStopTimeout = time.Millisecond
	wait := make(chan error, 1)
	collectErr := errors.New("descendant list/open/probe failure")
	var phase, leaderKills atomic.Int32
	smokeSignalProcessGroup = func(_ *smokeRuntimeProcess, signal syscall.Signal) error {
		if signal == syscall.SIGKILL {
			leaderKills.Add(1)
			wait <- nil
		}
		return nil
	}
	smokeCollectProcessGroupPidfds = func(*smokeRuntimeProcess) (smokePidfdCollection, error) {
		if phase.Load() == 0 {
			return smokePidfdCollection{}, collectErr
		}
		return smokePidfdCollection{}, nil
	}
	smokeClosePidfd = func(int) error { return nil }
	runtime := &smokeRuntimeProcess{
		processID: 42010, startTime: "owned", pidfd: 9801, ownsPidfd: true, wait: wait,
	}
	firstErr := stopSmokeRuntime(runtime, &bytes.Buffer{})
	if !errors.Is(firstErr, collectErr) || runtime.stopped || runtime.leaderExited || leaderKills.Load() != 0 {
		t.Fatalf("collector failure error=%v stopped=%v leaderExited=%v leaderKills=%d",
			firstErr, runtime.stopped, runtime.leaderExited, leaderKills.Load())
	}
	phase.Store(1)
	finalErr := stopSmokeRuntime(runtime, &bytes.Buffer{})
	if !errors.Is(finalErr, collectErr) || !runtime.stopped || leaderKills.Load() != 1 {
		t.Fatalf("collector retry error=%v stopped=%v leaderKills=%d", finalErr, runtime.stopped, leaderKills.Load())
	}
}

func TestStopSmokeRuntimeBindsIdentitySignalsAndWaitOnce(t *testing.T) {
	originalSignal := smokeSignalProcessGroup
	originalPidfdSignal := smokeSignalPidfd
	originalClose := smokeClosePidfd
	originalCollect := smokeCollectProcessGroupPidfds
	originalIdentity := smokeReadProcessIdentity
	originalTimeout := smokeStopTimeout
	t.Cleanup(func() {
		smokeSignalProcessGroup = originalSignal
		smokeSignalPidfd = originalPidfdSignal
		smokeClosePidfd = originalClose
		smokeCollectProcessGroupPidfds = originalCollect
		smokeReadProcessIdentity = originalIdentity
		smokeStopTimeout = originalTimeout
	})
	smokeStopTimeout = 10 * time.Millisecond
	smokeClosePidfd = func(int) error { return nil }
	smokeCollectProcessGroupPidfds = func(*smokeRuntimeProcess) (smokePidfdCollection, error) {
		return smokePidfdCollection{}, nil
	}

	t.Run("completed wait is idempotent and unsignaled", func(t *testing.T) {
		wait := make(chan error, 1)
		wait <- nil
		close(wait)
		var signals atomic.Int32
		smokeSignalProcessGroup = func(*smokeRuntimeProcess, syscall.Signal) error { signals.Add(1); return nil }
		smokeReadProcessIdentity = func(int) (string, bool) { return "replacement", true }
		runtime := &smokeRuntimeProcess{processID: 41001, startTime: "owned", wait: wait}
		if err := stopSmokeRuntime(runtime, &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
		if err := stopSmokeRuntime(runtime, &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
		if signals.Load() != 0 {
			t.Fatalf("completed runtime signals = %d", signals.Load())
		}
	})

	t.Run("recycled numeric identity still signals owned pidfd", func(t *testing.T) {
		wait := make(chan error, 1)
		var signals atomic.Int32
		smokeSignalProcessGroup = func(_ *smokeRuntimeProcess, signal syscall.Signal) error {
			signals.Add(1)
			if signal == syscall.SIGTERM {
				wait <- nil
				close(wait)
			}
			return nil
		}
		smokeReadProcessIdentity = func(int) (string, bool) { return "replacement", true }
		runtime := &smokeRuntimeProcess{processID: 41002, startTime: "owned", wait: wait}
		if err := stopSmokeRuntime(runtime, &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
		if signals.Load() != 4 {
			t.Fatalf("owned pidfd signals = %d", signals.Load())
		}
	})

	t.Run("owned process receives one term", func(t *testing.T) {
		wait := make(chan error, 1)
		var signals []syscall.Signal
		smokeSignalProcessGroup = func(_ *smokeRuntimeProcess, signal syscall.Signal) error {
			signals = append(signals, signal)
			if signal == syscall.SIGTERM {
				wait <- nil
				close(wait)
			}
			return nil
		}
		smokeReadProcessIdentity = func(int) (string, bool) { return "owned", true }
		runtime := &smokeRuntimeProcess{processID: 41003, startTime: "owned", wait: wait}
		if err := stopSmokeRuntime(runtime, &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
		if err := stopSmokeRuntime(runtime, &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
		want := []syscall.Signal{syscall.SIGSTOP, 0, syscall.SIGTERM, syscall.SIGCONT}
		if !reflect.DeepEqual(signals, want) {
			t.Fatalf("owned process signals = %v, want %v", signals, want)
		}
	})

	t.Run("kill failure is surfaced", func(t *testing.T) {
		wait := make(chan error)
		var signals atomic.Int32
		smokeSignalProcessGroup = func(_ *smokeRuntimeProcess, signal syscall.Signal) error {
			signals.Add(1)
			if signal == syscall.SIGKILL {
				return syscall.EPERM
			}
			return nil
		}
		smokeReadProcessIdentity = func(int) (string, bool) { return "owned", true }
		runtime := &smokeRuntimeProcess{processID: 41004, startTime: "owned", wait: wait}
		if err := stopSmokeRuntime(runtime, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "KILL") {
			t.Fatalf("kill failure error = %v", err)
		}
		if signals.Load() != 5 {
			t.Fatalf("kill failure signals = %d", signals.Load())
		}
	})

	t.Run("term failure still consumes wait", func(t *testing.T) {
		wait := make(chan error, 1)
		waitResult := errors.New("term wait result")
		go func() {
			time.Sleep(time.Millisecond)
			wait <- waitResult
		}()
		smokeSignalProcessGroup = func(_ *smokeRuntimeProcess, signal syscall.Signal) error {
			if signal == syscall.SIGTERM {
				return syscall.EPERM
			}
			return nil
		}
		smokeReadProcessIdentity = func(int) (string, bool) { return "owned", true }
		runtime := &smokeRuntimeProcess{processID: 41005, startTime: "owned", wait: wait}
		err := stopSmokeRuntime(runtime, &bytes.Buffer{})
		if err == nil || !strings.Contains(err.Error(), "TERM") || !strings.Contains(err.Error(), waitResult.Error()) {
			t.Fatalf("term failure error = %v", err)
		}
		time.Sleep(2 * time.Millisecond)
		select {
		case remaining := <-wait:
			t.Fatalf("term failure left Wait unconsumed: %v", remaining)
		default:
		}
	})

	t.Run("kill failure still consumes wait", func(t *testing.T) {
		wait := make(chan error, 1)
		waitResult := errors.New("kill wait result")
		go func() {
			time.Sleep(15 * time.Millisecond)
			wait <- waitResult
		}()
		smokeSignalProcessGroup = func(_ *smokeRuntimeProcess, signal syscall.Signal) error {
			if signal == syscall.SIGKILL {
				return syscall.EPERM
			}
			return nil
		}
		smokeReadProcessIdentity = func(int) (string, bool) { return "owned", true }
		runtime := &smokeRuntimeProcess{processID: 41006, startTime: "owned", wait: wait}
		err := stopSmokeRuntime(runtime, &bytes.Buffer{})
		if err == nil || !strings.Contains(err.Error(), "KILL") || !strings.Contains(err.Error(), waitResult.Error()) {
			t.Fatalf("kill failure error = %v", err)
		}
		time.Sleep(20 * time.Millisecond)
		select {
		case remaining := <-wait:
			t.Fatalf("kill failure left Wait unconsumed: %v", remaining)
		default:
		}
	})
}

func TestStopSmokeRuntimeSurfacesSuccessfulSignalWaitErrors(t *testing.T) {
	originalSignal := smokeSignalProcessGroup
	originalClose := smokeClosePidfd
	originalCollect := smokeCollectProcessGroupPidfds
	originalTimeout := smokeStopTimeout
	t.Cleanup(func() {
		smokeSignalProcessGroup = originalSignal
		smokeClosePidfd = originalClose
		smokeCollectProcessGroupPidfds = originalCollect
		smokeStopTimeout = originalTimeout
	})
	smokeStopTimeout = time.Millisecond
	smokeClosePidfd = func(int) error { return nil }
	smokeCollectProcessGroupPidfds = func(*smokeRuntimeProcess) (smokePidfdCollection, error) {
		return smokePidfdCollection{}, nil
	}

	t.Run("term success", func(t *testing.T) {
		wait := make(chan error, 1)
		waitResult := errors.New("term success wait result")
		var signals []syscall.Signal
		smokeSignalProcessGroup = func(_ *smokeRuntimeProcess, signal syscall.Signal) error {
			signals = append(signals, signal)
			if signal == syscall.SIGTERM {
				wait <- waitResult
			}
			return nil
		}
		runtime := &smokeRuntimeProcess{processID: 41007, startTime: "owned", wait: wait}
		err := stopSmokeRuntime(runtime, &bytes.Buffer{})
		if err == nil || !errors.Is(err, waitResult) || !strings.Contains(err.Error(), "wait for openresty after TERM") ||
			!strings.Contains(err.Error(), waitResult.Error()) {
			t.Fatalf("TERM success wait error = %v", err)
		}
		if repeated := stopSmokeRuntime(runtime, &bytes.Buffer{}); repeated != err {
			t.Fatalf("repeated TERM stop error = %v, want identical %v", repeated, err)
		}
		want := []syscall.Signal{syscall.SIGSTOP, 0, syscall.SIGTERM, syscall.SIGCONT}
		if !reflect.DeepEqual(signals, want) {
			t.Fatalf("TERM success signals = %v, want %v", signals, want)
		}
	})

	t.Run("kill success", func(t *testing.T) {
		wait := make(chan error, 1)
		waitResult := errors.New("kill success wait result")
		var signals []syscall.Signal
		smokeSignalProcessGroup = func(_ *smokeRuntimeProcess, signal syscall.Signal) error {
			signals = append(signals, signal)
			if signal == syscall.SIGKILL {
				wait <- waitResult
			}
			return nil
		}
		runtime := &smokeRuntimeProcess{processID: 41008, startTime: "owned", wait: wait}
		err := stopSmokeRuntime(runtime, &bytes.Buffer{})
		if err == nil || !errors.Is(err, waitResult) || !strings.Contains(err.Error(), "wait for openresty after KILL") ||
			!strings.Contains(err.Error(), waitResult.Error()) {
			t.Fatalf("KILL success wait error = %v", err)
		}
		if repeated := stopSmokeRuntime(runtime, &bytes.Buffer{}); repeated != err {
			t.Fatalf("repeated KILL stop error = %v, want identical %v", repeated, err)
		}
		want := []syscall.Signal{syscall.SIGSTOP, 0, syscall.SIGTERM, syscall.SIGCONT, syscall.SIGKILL}
		if !reflect.DeepEqual(signals, want) {
			t.Fatalf("KILL success signals = %v, want %v", signals, want)
		}
	})
}

func smokeTestSourcePath(t *testing.T) string {
	t.Helper()
	_, path, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve smoke test source path")
	}
	return path
}

type smokeEvidence struct {
	OpenRestyVersion             string   `json:"openresty_version"`
	BeforePurge                  []string `json:"before_purge"`
	AfterPurge                   []string `json:"after_purge"`
	PurgeAffected                int      `json:"purge_affected"`
	PrewarmRateLimitElapsedMS    int64    `json:"prewarm_rate_limit_elapsed_ms"`
	RetryAttempts                int      `json:"retry_attempts"`
	RetryPlanReused              bool     `json:"retry_plan_reused"`
	RetryKeptActiveCache         bool     `json:"retry_kept_active_cache"`
	RevisionOneAfterPurge        string   `json:"revision_one_after_purge"`
	OtherSiteAfterPurge          string   `json:"other_site_after_purge"`
	FirstRequestAfterPrewarm     string   `json:"first_request_after_prewarm"`
	PrewarmNoStoreCode           string   `json:"prewarm_no_store_code"`
	PrewarmNoStoreRequests       int      `json:"prewarm_no_store_requests"`
	FailedPurgeCode              string   `json:"failed_purge_code"`
	RevisionOneAfterFailure      string   `json:"revision_one_after_failure"`
	OtherSiteAfterFailure        string   `json:"other_site_after_failure"`
	DedicatedPrewarmListener     bool     `json:"dedicated_prewarm_listener"`
	PublicPrewarmRuleKeyTTL      bool     `json:"public_prewarm_rule_key_ttl"`
	VersionNamespacesDiffer      bool     `json:"version_namespaces_differ"`
	VersionKeyPathsDiffer        bool     `json:"version_key_paths_differ"`
	PurgeRemovedActiveVersionKey bool     `json:"purge_removed_active_version_key"`
	PurgeKeptPreviousVersionKey  bool     `json:"purge_kept_previous_version_key"`
	ListenerCacheIdentityBound   bool     `json:"listener_cache_identity_bound"`
	OpenRestyProcessGroupZero    bool     `json:"openresty_process_group_zero"`
	OriginListenerZero           bool     `json:"origin_listener_zero"`
	PIDFileZero                  bool     `json:"pid_file_zero"`
	TaskListenersZero            bool     `json:"task_listeners_zero"`
	RuntimeTempZero              bool     `json:"runtime_temp_zero"`
	PPID1ResidueZero             bool     `json:"ppid1_residue_zero"`
	CallerStateRootPreserved     bool     `json:"caller_state_root_preserved"`
}

func TestOpenRestyCacheTaskSmoke(t *testing.T) {
	if os.Getenv("CDNCA_CACHE_TASK_SMOKE") != "1" {
		t.Skip("set CDNCA_CACHE_TASK_SMOKE=1 inside the pinned OpenResty runtime")
	}
	binary := os.Getenv("CDNCA_OPENRESTY_BIN")
	templatePath := os.Getenv("CDNCA_CACHE_TASK_TEMPLATE")
	if binary == "" || templatePath == "" {
		t.Fatal("smoke runtime environment is incomplete")
	}
	versionOutput, err := exec.Command(binary, "-v").CombinedOutput()
	if err != nil {
		t.Fatalf("openresty version: %v", err)
	}

	var noStoreRequests atomic.Int32
	// CACHE-ADD-07: /slow-* holds the first prewarm target until released so
	// the task is cancelled while it runs; slowRequests counts origin fetches.
	var slowRequests atomic.Int32
	slowStarted := make(chan struct{}, 4)
	slowRelease := make(chan struct{})
	var rateRequestsMu sync.Mutex
	var rateRequests []time.Time
	origin := startTestHTTPServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/rate-limit" {
			rateRequestsMu.Lock()
			rateRequests = append(rateRequests, time.Now())
			rateRequestsMu.Unlock()
		}
		if request.URL.Path == "/no-store" {
			noStoreRequests.Add(1)
			writer.Header().Set("Cache-Control", "private, no-store")
			writer.Header().Set("Set-Cookie", "smoke=session")
			writer.Header().Set("Vary", "*")
		} else {
			writer.Header().Set("Cache-Control", "public, max-age=60")
		}
		if request.URL.Path == "/failure" {
			http.Error(writer, "upstream unavailable", http.StatusBadGateway)
			return
		}
		if strings.HasPrefix(request.URL.Path, "/slow-") {
			slowRequests.Add(1)
			slowStarted <- struct{}{}
			select {
			case <-slowRelease:
			case <-request.Context().Done():
			}
		}
		_, _ = fmt.Fprintf(writer, "%s|%s", request.Host, request.URL.RequestURI())
	}))
	ports := reserveSmokePorts(t, 4)
	tempRoot := t.TempDir()
	stateRoot := filepath.Join(tempRoot, "edge-state")
	for _, directory := range []string{filepath.Dir(tempRoot), tempRoot} {
		if err := os.Chmod(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := prepareSmokeProductionRuntimePaths(stateRoot, 65534, 65534); err != nil {
		t.Fatalf("prepare cache task production runtime paths: %v", err)
	}
	runtimeTempRoot, err := os.MkdirTemp(tempRoot, "openresty-runtime-")
	if err != nil {
		t.Fatal(err)
	}
	releaseRoot := filepath.Join(runtimeTempRoot, "runtime")
	if err := os.Mkdir(releaseRoot, 0o755); err != nil {
		t.Fatal(err)
	}

	v2 := testSite("tenant-a", "site-a", "config-v2", "cache.example.test", ports[0], ports[1], 2)
	v1 := testSite("tenant-a", "site-a", "config-v1", "cache.example.test", ports[2], 0, 1)
	other := testSite("tenant-a", "site-b", "config-v2", "other.example.test", ports[3], 0, 2)
	configBody, err := os.ReadFile(templatePath)
	if err != nil {
		t.Fatal(err)
	}
	replacements := map[string]string{
		"{{STATE_ROOT}}": stateRoot, "{{ORIGIN_PORT}}": strconv.Itoa(int(origin.port())),
		"{{V2_PUBLIC_PORT}}": strconv.Itoa(int(v2.ListenPort)), "{{V2_PREWARM_PORT}}": strconv.Itoa(int(v2.PrewarmPort)),
		"{{V2_PREWARM_PATH_PREFIX}}": v2.PrewarmPathPrefix, "{{V2_PREWARM_PREFIX_REGEX}}": regexp.QuoteMeta(v2.PrewarmPathPrefix),
		"{{V1_PUBLIC_PORT}}": strconv.Itoa(int(v1.ListenPort)), "{{OTHER_PUBLIC_PORT}}": strconv.Itoa(int(other.ListenPort)),
		"{{V2_NAMESPACE}}": v2.CacheIdentity, "{{V1_NAMESPACE}}": v1.CacheIdentity,
		"{{OTHER_NAMESPACE}}":  other.CacheIdentity,
		"{{V2_KEY_PREFIX}}":    edgeconfig.CacheKeyPrefix(v2.TenantID, v2.SiteID, v2.ConfigVersionID, v2.Domain, v2.ListenPort),
		"{{V1_KEY_PREFIX}}":    edgeconfig.CacheKeyPrefix(v1.TenantID, v1.SiteID, v1.ConfigVersionID, v1.Domain, v1.ListenPort),
		"{{OTHER_KEY_PREFIX}}": edgeconfig.CacheKeyPrefix(other.TenantID, other.SiteID, other.ConfigVersionID, other.Domain, other.ListenPort),
	}
	config := string(configBody)
	for marker, value := range replacements {
		config = strings.ReplaceAll(config, marker, value)
	}
	if strings.Contains(config, "{{") {
		t.Fatal("unresolved smoke configuration marker")
	}
	if err := os.WriteFile(filepath.Join(releaseRoot, "nginx.conf"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}

	var runtimeLog bytes.Buffer
	runtime := exec.Command(binary, "-p", releaseRoot+string(filepath.Separator), "-c", "nginx.conf", "-g", "daemon off;")
	runtime.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	runtime.Stdout = &runtimeLog
	runtime.Stderr = &runtimeLog
	ownedRuntime, err := startSmokeRuntime(runtime)
	if err != nil {
		t.Fatal(err)
	}
	runtimeStopped := false
	t.Cleanup(func() {
		if !runtimeStopped {
			_ = stopSmokeRuntime(ownedRuntime, &runtimeLog)
		}
	})
	if err := waitForSmokeListener(v2.ListenPort, 5*time.Second); err != nil {
		t.Fatalf("openresty did not start: %v: %s", err, runtimeLog.String())
	}

	request := func(site SiteContext, path string) string {
		t.Helper()
		value, err := smokeCacheRequest(site, path)
		if err != nil {
			t.Fatalf("request %s: %v", site.SiteID, err)
		}
		return value
	}
	evidence := smokeEvidence{
		OpenRestyVersion:         strings.TrimSpace(string(versionOutput)),
		BeforePurge:              []string{request(v2, "/asset?q=1"), request(v2, "/asset?q=1")},
		DedicatedPrewarmListener: v2.PrewarmPort != v2.ListenPort,
		PublicPrewarmRuleKeyTTL:  strings.Count(config, "proxy_cache v2_zone;\n      proxy_cache_key \""+edgeconfig.CacheKeyPrefix(v2.TenantID, v2.SiteID, v2.ConfigVersionID, v2.Domain, v2.ListenPort)+"$uri$is_args$args\";\n      proxy_cache_valid 200 60s;") == 2,
		VersionNamespacesDiffer:  v2.CacheIdentity != v1.CacheIdentity,
	}
	if first, second := request(v1, "/asset?q=1"), request(v1, "/asset?q=1"); first != "MISS" || second != "HIT" {
		t.Fatalf("revision one seed=%s/%s", first, second)
	}
	if first, second := request(other, "/asset?q=1"), request(other, "/asset?q=1"); first != "MISS" || second != "HIT" {
		t.Fatalf("other site seed=%s/%s", first, second)
	}
	evidence.ListenerCacheIdentityBound = true
	v2KeyPath := nginxCachePath(filepath.Join(stateRoot, "shared", "cache", v2.CacheIdentity), cacheKeyValue(v2, "/asset?q=1"))
	v1KeyPath := nginxCachePath(filepath.Join(stateRoot, "shared", "cache", v1.CacheIdentity), cacheKeyValue(v1, "/asset?q=1"))
	if _, err := os.Stat(v2KeyPath); err != nil {
		t.Fatalf("active version cache key: %v", err)
	}
	if _, err := os.Stat(v1KeyPath); err != nil {
		t.Fatalf("previous version cache key: %v", err)
	}
	evidence.VersionKeyPathsDiffer = v2KeyPath != v1KeyPath

	manager := testManager(t, stateRoot, resolverFor(v2, v1, other), func(config *Config) {
		config.RequestTimeout = time.Second
	})
	purge, err := manager.Execute(context.Background(), taskFor(v2, "runtime-purge", ActionPurgeExact, cacheURL(v2, "/asset?q=1")))
	if err != nil || purge.State != StateSucceeded || purge.Items[0].Affected != 1 {
		t.Fatalf("purge=%+v error=%v", purge, err)
	}
	evidence.PurgeAffected = purge.Items[0].Affected
	_, activeVersionErr := os.Stat(v2KeyPath)
	_, previousVersionErr := os.Stat(v1KeyPath)
	evidence.PurgeRemovedActiveVersionKey = errors.Is(activeVersionErr, os.ErrNotExist)
	evidence.PurgeKeptPreviousVersionKey = previousVersionErr == nil
	evidence.AfterPurge = []string{request(v2, "/asset?q=1"), request(v2, "/asset?q=1")}
	evidence.RevisionOneAfterPurge = request(v1, "/asset?q=1")
	evidence.OtherSiteAfterPurge = request(other, "/asset?q=1")

	prewarmTask := taskFor(v2, "runtime-prewarm", ActionPrewarm, cacheURL(v2, "/warm"), cacheURL(v2, "/no-store"))
	prewarmTask.Budget.MaxAttempts = 1
	prewarm, err := manager.Execute(context.Background(), prewarmTask)
	if err != nil || prewarm.State != StatePartialFailed || prewarm.Items[0].Code != CodePrewarmed ||
		prewarm.Items[1].Code != CodePrewarmNotCacheable || noStoreRequests.Load() != 2 {
		t.Fatalf("prewarm=%+v error=%v", prewarm, err)
	}
	evidence.FirstRequestAfterPrewarm = request(v2, "/warm")
	evidence.PrewarmNoStoreCode = prewarm.Items[1].Code
	evidence.PrewarmNoStoreRequests = int(noStoreRequests.Load())

	// CACHE-ADD-07 (待出包前在真实 OpenResty 里跑): a cancel while the
	// first target is fetching stops the task; the targets not run never
	// reach the origin and the task is cancelled.
	cancelTask := taskFor(v2, "runtime-prewarm-cancel", ActionPrewarm,
		cacheURL(v2, "/slow-1"), cacheURL(v2, "/slow-2"), cacheURL(v2, "/slow-3"))
	cancelTask.Budget.MaxAttempts = 1
	cancelTask.Budget.MaxConcurrency = 1
	cancelDone := make(chan Result, 1)
	go func() {
		result, executeErr := manager.Execute(context.Background(), cancelTask)
		if executeErr != nil {
			t.Errorf("cancelled prewarm execute: %v", executeErr)
		}
		cancelDone <- result
	}()
	select {
	case <-slowStarted:
	case <-time.After(10 * time.Second):
		t.Fatal("slow prewarm target did not reach the origin")
	}
	if _, err := manager.Cancel(context.Background(), referenceFromTask(cancelTask)); err != nil {
		t.Fatalf("cancel running prewarm: %v", err)
	}
	close(slowRelease)
	var cancelled Result
	select {
	case cancelled = <-cancelDone:
	case <-time.After(10 * time.Second):
		t.Fatal("cancelled prewarm did not settle")
	}
	if cancelled.State != StateCancelled || slowRequests.Load() != 1 {
		t.Fatalf("cancelled prewarm=%+v origin slow requests=%d", cancelled, slowRequests.Load())
	}

	originalGlobalRate := manager.globalRate
	originalSiteRequestsPerSecond := manager.config.SiteRequestsPerSecond
	originalSiteBurst := manager.config.SiteBurst
	originalSiteRates := manager.siteRates
	manager.globalRate = newTokenBucket(5, 1)
	manager.config.SiteRequestsPerSecond = 5
	manager.config.SiteBurst = 1
	manager.siteRates = make(map[string]*siteRateEntry)
	rateTask := taskFor(v2, "runtime-rate-limit", ActionPrewarm, cacheURL(v2, "/rate-limit"))
	rateTask.Budget.MaxAttempts = 1
	rateTask.Budget.MaxConcurrency = 1
	rateTask.Budget.RequestsPerSecond = 5
	rateTask.Budget.Burst = 1
	rateStartedAt := time.Now()
	rateResult, err := manager.Execute(context.Background(), rateTask)
	evidence.PrewarmRateLimitElapsedMS = time.Since(rateStartedAt).Milliseconds()
	manager.globalRate = originalGlobalRate
	manager.config.SiteRequestsPerSecond = originalSiteRequestsPerSecond
	manager.config.SiteBurst = originalSiteBurst
	manager.siteRates = originalSiteRates
	if err != nil || rateResult.State != StateSucceeded || rateResult.Items[0].Code != CodePrewarmed {
		t.Fatalf("rate-limited prewarm=%+v error=%v", rateResult, err)
	}
	rateRequestsMu.Lock()
	if len(rateRequests) != 1 {
		t.Fatalf("rate-limited prewarm origin requests=%d, want one cache miss", len(rateRequests))
	}
	rateRequestsMu.Unlock()

	if first, second := request(v2, "/retry-purge"), request(v2, "/retry-purge"); first != "MISS" || second != "HIT" {
		t.Fatalf("retry purge seed=%s/%s", first, second)
	}
	originalExactEntry := manager.exactEntry
	originalDeleteEntries := manager.deleteEntries
	originalSleep := manager.config.Sleep
	var exactEntryCalls, deleteCalls int
	var plannedEntry, attemptedEntry cacheEntry
	manager.exactEntry = func(ctx context.Context, site SiteContext, target normalizedTarget, budget *cacheScanBudget) (*cacheEntry, error) {
		exactEntryCalls++
		entry, lookupErr := originalExactEntry(ctx, site, target, budget)
		if entry != nil {
			plannedEntry = *entry
		}
		return entry, lookupErr
	}
	manager.deleteEntries = func(_ context.Context, entries []cacheEntry) (int, error) {
		deleteCalls++
		if len(entries) != 1 {
			return 0, ErrInvalidState
		}
		attemptedEntry = entries[0]
		return 0, errors.New("transient cache storage failure")
	}
	manager.config.Sleep = func(ctx context.Context, _ time.Duration) error {
		evidence.RetryKeptActiveCache = request(v2, "/retry-purge") == "HIT"
		return ctx.Err()
	}
	retryTask := taskFor(v2, "runtime-retry-purge", ActionPurgeExact, cacheURL(v2, "/retry-purge"))
	retryTask.Budget.MaxAttempts = 2
	retryTask.Budget.InitialRetryBackoff = time.Second
	retryTask.Budget.MaximumRetryBackoff = time.Second
	retryResult, err := manager.Execute(context.Background(), retryTask)
	manager.exactEntry = originalExactEntry
	manager.deleteEntries = originalDeleteEntries
	manager.config.Sleep = originalSleep
	if err != nil || retryResult.State != StateSucceeded || retryResult.Items[0].Code != CodePurged ||
		retryResult.Items[0].Attempts != 2 || retryResult.Items[0].Affected != 1 {
		t.Fatalf("retried purge=%+v error=%v", retryResult, err)
	}
	evidence.RetryAttempts = retryResult.Items[0].Attempts
	evidence.RetryPlanReused = exactEntryCalls == 1 && deleteCalls == 1 &&
		plannedEntry.relative == attemptedEntry.relative && plannedEntry.size == attemptedEntry.size &&
		plannedEntry.device == attemptedEntry.device && plannedEntry.inode == attemptedEntry.inode

	malformedKey := cacheKeyValue(v2, "/malformed")
	malformedPath := nginxCachePath(filepath.Join(stateRoot, "shared", "cache", v2.CacheIdentity), malformedKey)
	if err := os.MkdirAll(filepath.Dir(malformedPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(malformedPath, []byte("invalid cache metadata"), 0o600); err != nil {
		t.Fatal(err)
	}
	failed, err := manager.Execute(context.Background(), taskFor(v2, "runtime-failure", ActionPurgeSite))
	if err != nil || failed.State != StateFailed || failed.Items[0].Code != CodeCacheMetadataInvalid {
		t.Fatalf("failed purge=%+v error=%v", failed, err)
	}
	evidence.FailedPurgeCode = failed.Items[0].Code
	evidence.RevisionOneAfterFailure = request(v1, "/asset?q=1")
	evidence.OtherSiteAfterFailure = request(other, "/asset?q=1")

	cleanup, cleanupErr := cleanupOpenRestySmoke(ownedRuntime, &runtimeLog, origin,
		filepath.Join(stateRoot, "shared", "nginx.pid"), runtimeTempRoot, stateRoot,
		append(append([]uint16(nil), ports...), origin.port()))
	if cleanupErr != nil {
		t.Fatal(cleanupErr)
	}
	runtimeStopped = true
	evidence.OpenRestyProcessGroupZero = cleanup.processGroupZero
	evidence.OriginListenerZero = cleanup.originListenerZero
	evidence.PIDFileZero = cleanup.pidFileZero
	evidence.TaskListenersZero = cleanup.taskListenersZero
	evidence.RuntimeTempZero = cleanup.runtimeTempZero
	evidence.PPID1ResidueZero = cleanup.ppid1ResidueZero
	evidence.CallerStateRootPreserved = cleanup.callerStateRootPreserved

	if strings.Join(evidence.BeforePurge, ",") != "MISS,HIT" || strings.Join(evidence.AfterPurge, ",") != "MISS,HIT" ||
		evidence.PrewarmRateLimitElapsedMS < 150 || evidence.RetryAttempts != 2 || !evidence.RetryPlanReused ||
		!evidence.RetryKeptActiveCache || !evidence.VersionKeyPathsDiffer || !evidence.PurgeRemovedActiveVersionKey ||
		!evidence.PurgeKeptPreviousVersionKey || !evidence.ListenerCacheIdentityBound ||
		evidence.RevisionOneAfterPurge != "HIT" || evidence.OtherSiteAfterPurge != "HIT" ||
		evidence.FirstRequestAfterPrewarm != "HIT" || evidence.PrewarmNoStoreCode != CodePrewarmNotCacheable ||
		evidence.PrewarmNoStoreRequests != 2 || evidence.RevisionOneAfterFailure != "HIT" ||
		evidence.OtherSiteAfterFailure != "HIT" || !evidence.DedicatedPrewarmListener || !evidence.PublicPrewarmRuleKeyTTL ||
		!evidence.VersionNamespacesDiffer || !evidence.OpenRestyProcessGroupZero || !evidence.OriginListenerZero ||
		!evidence.PIDFileZero || !evidence.TaskListenersZero || !evidence.RuntimeTempZero || !evidence.PPID1ResidueZero ||
		!evidence.CallerStateRootPreserved {
		t.Fatalf("smoke evidence failed: %+v", evidence)
	}
	encoded, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(encoded))
}

// prepareSmokeProductionRuntimePaths creates the private state directories
// the production runtime writes (the release's own paths are its own).
func prepareSmokeProductionRuntimePaths(stateRoot string, ownerUID, ownerGID int) error {
	if ownerUID < 0 || ownerGID < 0 {
		return errors.New("production state directory owner is invalid")
	}
	for _, directory := range []string{stateRoot, filepath.Join(stateRoot, "shared"), filepath.Join(stateRoot, "shared", "cache")} {
		if err := ensureSmokePrivateDirectory(directory, ownerUID, ownerGID); err != nil {
			return err
		}
	}
	return nil
}

func ensureSmokePrivateDirectory(path string, ownerUID, ownerGID int) error {
	info, err := os.Lstat(path)
	created := errors.Is(err, os.ErrNotExist)
	if created {
		if err := os.Mkdir(path, 0o700); err != nil {
			return err
		}
		info, err = os.Lstat(path)
		if err == nil {
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok {
				return errors.New("runtime directory owner is unavailable")
			}
			if stat.Uid != uint32(ownerUID) || stat.Gid != uint32(ownerGID) {
				if err := os.Chown(path, ownerUID, ownerGID); err != nil {
					return err
				}
			}
		}
	}
	if err != nil {
		return err
	}
	return requireSmokePrivateDirectory(path, ownerUID, ownerGID)
}

func requireSmokePrivateDirectory(path string, ownerUID, ownerGID int) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return errors.New("production state directory is not private")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(ownerUID) || stat.Gid != uint32(ownerGID) {
		return errors.New("production state directory owner is invalid")
	}
	return nil
}

type smokeRuntimeProcess struct {
	processID        int
	startTime        string
	pidfd            int
	ownsPidfd        bool
	wait             <-chan error
	descendantPidfds []int
	rejectedPidfds   []int
	descendantKilled map[int]bool
	leaderExited     bool
	leaderWaitErr    error
	pendingStopErr   error
	stopMu           sync.Mutex
	stopped          bool
	stopErr          error
}

var smokeSignalPidfd = smokePidfdSendSignal

var smokeClosePidfd = syscall.Close

var smokeSignalProcessGroup = func(runtime *smokeRuntimeProcess, signal syscall.Signal) error {
	if runtime == nil || !runtime.ownsPidfd {
		return errors.New("openresty process group leader pidfd is not owned")
	}
	if err := smokeSignalPidfd(runtime.pidfd, 0); err != nil {
		return fmt.Errorf("probe openresty process group leader: %w", err)
	}
	startTime, ok := smokeReadProcessIdentity(runtime.processID)
	if !ok || startTime != runtime.startTime {
		return errors.New("openresty process group leader identity changed")
	}
	return syscall.Kill(-runtime.processID, signal)
}

var smokeCollectProcessGroupPidfds = smokeProcessGroupPidfds

var smokeReadProcessIdentity = smokeProcessIdentity

var smokeStopTimeout = 2 * time.Second

var smokeOpenPidfd = smokePidfdOpen

var smokeKillStartedProcess = func(command *exec.Cmd) error {
	return syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
}

var smokePrepareRuntimeCommand = prepareSmokeRuntimeCommand

var smokeStartCommandWait = func(command *exec.Cmd) <-chan error {
	wait := make(chan error, 1)
	go func() {
		wait <- command.Wait()
		close(wait)
	}()
	return wait
}

func startSmokeRuntime(command *exec.Cmd) (*smokeRuntimeProcess, error) {
	if command == nil {
		return nil, errors.New("openresty command is nil")
	}
	ownedCommand, err := smokePrepareRuntimeCommand(command)
	if err != nil {
		return nil, err
	}
	command = ownedCommand
	if err := command.Start(); err != nil {
		return nil, err
	}
	processID := command.Process.Pid
	pidfd, pidfdErr := smokeOpenPidfd(processID)
	if pidfdErr != nil {
		killErr := smokeKillStartedProcess(command)
		wait := smokeStartCommandWait(command)
		waitErr := smokeWaitStartedProcess(wait, smokeStopTimeout)
		return nil, errors.Join(
			fmt.Errorf("open openresty pidfd: %w", pidfdErr),
			wrapSmokeCause("kill unbound openresty process", killErr),
			wrapSmokeCause("wait for unbound openresty process", waitErr),
		)
	}
	startTime, ok := smokeReadProcessIdentity(processID)
	if !ok {
		killErr := smokeKillStartedProcess(command)
		wait := smokeStartCommandWait(command)
		waitErr := smokeWaitStartedProcess(wait, smokeStopTimeout)
		closeErr := smokeClosePidfd(pidfd)
		return nil, errors.Join(
			errors.New("capture openresty process identity"),
			wrapSmokeCause("kill identity-unavailable openresty process", killErr),
			wrapSmokeCause("wait for identity-unavailable openresty process", waitErr),
			wrapSmokeCause("close identity-unavailable openresty pidfd", closeErr),
		)
	}
	wait := smokeStartCommandWait(command)
	return &smokeRuntimeProcess{
		processID: processID,
		startTime: startTime,
		pidfd:     pidfd,
		ownsPidfd: true,
		wait:      wait,
	}, nil
}

func prepareSmokeRuntimeCommand(command *exec.Cmd) (*exec.Cmd, error) {
	if command == nil || command.Path == "" || len(command.Args) == 0 {
		return nil, errors.New("openresty command is incomplete")
	}
	if command.SysProcAttr != nil && !command.SysProcAttr.Setpgid {
		return nil, errors.New("openresty command must use a dedicated process group")
	}
	script := `child_status=0
trap 'exit "$child_status"' TERM INT HUP
"$@" &
child=$!
wait "$child" || child_status=$?
while :; do sleep 3600; done`
	supervisor := exec.Command("sh", "-c", script, "cdnca-smoke-supervisor", command.Path)
	supervisor.Args = append(supervisor.Args, command.Args[1:]...)
	supervisor.Env = command.Env
	supervisor.Dir = command.Dir
	supervisor.Stdin = command.Stdin
	supervisor.Stdout = command.Stdout
	supervisor.Stderr = command.Stderr
	supervisor.ExtraFiles = command.ExtraFiles
	supervisor.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return supervisor, nil
}

func wrapSmokeCause(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", operation, err)
}

func stopSmokeRuntime(runtime *smokeRuntimeProcess, runtimeLog *bytes.Buffer) error {
	if runtime == nil {
		return errors.New("openresty runtime is nil")
	}
	runtime.stopMu.Lock()
	defer runtime.stopMu.Unlock()
	if runtime.stopped {
		return runtime.stopErr
	}
	stopErr, terminal := runtime.stop(runtimeLog)
	if !terminal {
		return stopErr
	}
	if runtime.ownsPidfd {
		if closeErr := smokeClosePidfd(runtime.pidfd); closeErr != nil {
			runtime.rememberStopError(wrapSmokeCause("close openresty leader pidfd", closeErr))
			return runtime.pendingStopErr
		}
		runtime.ownsPidfd = false
	}
	runtime.stopped = true
	runtime.stopErr = runtime.pendingStopErr
	return runtime.stopErr
}

func (runtime *smokeRuntimeProcess) stop(runtimeLog *bytes.Buffer) (error, bool) {
	if len(runtime.rejectedPidfds) != 0 {
		closeErr, complete := runtime.closeRejectedPidfds()
		runtime.rememberStopError(closeErr)
		if !complete {
			return runtime.pendingStopErr, false
		}
	}
	if runtime.leaderExited {
		cleanupErr, complete := runtime.cleanupDescendantPidfds(true)
		runtime.rememberStopError(cleanupErr)
		return runtime.pendingStopErr, complete
	}
	if len(runtime.descendantPidfds) != 0 {
		cleanupErr, complete := runtime.cleanupDescendantPidfds(true)
		runtime.rememberStopError(cleanupErr)
		if !complete {
			return runtime.pendingStopErr, false
		}
	}
	select {
	case err := <-runtime.wait:
		runtime.leaderExited = true
		runtime.leaderWaitErr = err
		if err != nil {
			runtime.rememberStopError(fmt.Errorf("openresty exited before stop: %w: %s", err, runtimeLog.String()))
		}
		return runtime.pendingStopErr, true
	default:
	}
	stopErr := smokeSignalProcessGroup(runtime, syscall.SIGSTOP)
	if errors.Is(stopErr, syscall.ESRCH) {
		if exited, waitErr := runtime.waitForExitWithin(smokeStopTimeout); exited {
			runtime.rememberStopError(errors.Join(
				wrapSmokeWaitError("leader loss", waitErr),
			))
			return runtime.pendingStopErr, true
		}
		runtime.rememberStopError(errors.Join(
			errors.New("openresty leader disappeared before descendant scan and was not reaped"),
		))
		return runtime.pendingStopErr, false
	}
	if stopErr != nil {
		return runtime.killLeaderAndWait(runtimeLog, nil, wrapSmokeSignalError("STOP", stopErr))
	}

	collection, descendantsErr := smokeCollectProcessGroupPidfds(runtime)
	runtime.addDescendantPidfds(collection.descendants)
	runtime.rejectedPidfds = append(runtime.rejectedPidfds, collection.rejected...)
	if descendantsErr != nil {
		runtime.rememberStopError(descendantsErr)
		return runtime.pendingStopErr, false
	}
	probeErr := smokeSignalProcessGroup(runtime, 0)
	if probeErr != nil {
		runtime.rememberStopError(wrapSmokeSignalError("probe", probeErr))
	}
	termErr := smokeSignalProcessGroup(runtime, syscall.SIGTERM)
	if errors.Is(termErr, syscall.ESRCH) {
		termErr = nil
	}
	continueErr := smokeSignalProcessGroup(runtime, syscall.SIGCONT)
	if errors.Is(continueErr, syscall.ESRCH) {
		continueErr = nil
	}
	if exited, waitErr := runtime.waitForExitWithin(smokeStopTimeout); exited {
		runtime.rememberStopError(errors.Join(
			wrapSmokeSignalError("TERM", termErr),
			wrapSmokeSignalError("CONT", continueErr),
			wrapSmokeWaitError("TERM", waitErr),
		))
		cleanupErr, complete := runtime.cleanupDescendantPidfds(true)
		runtime.rememberStopError(cleanupErr)
		return runtime.pendingStopErr, complete
	}
	cleanupErr, _ := runtime.cleanupDescendantPidfds(true)
	runtime.rememberStopError(cleanupErr)
	return runtime.killLeaderAndWait(runtimeLog, termErr, wrapSmokeSignalError("CONT", continueErr))
}

func (runtime *smokeRuntimeProcess) closeRejectedPidfds() (error, bool) {
	remaining := runtime.rejectedPidfds[:0]
	var result error
	for _, pidfd := range runtime.rejectedPidfds {
		if closeErr := smokeClosePidfd(pidfd); closeErr != nil {
			result = errors.Join(result, wrapSmokeCause("retry close rejected openresty descendant pidfd", closeErr))
			remaining = append(remaining, pidfd)
		}
	}
	runtime.rejectedPidfds = remaining
	return result, len(remaining) == 0
}

func (runtime *smokeRuntimeProcess) killLeaderAndWait(runtimeLog *bytes.Buffer, termErr, priorErr error) (error, bool) {
	killErr := smokeSignalProcessGroup(runtime, syscall.SIGKILL)
	if errors.Is(killErr, syscall.ESRCH) {
		killErr = nil
	}
	exited, waitErr := runtime.waitForExitWithin(smokeStopTimeout)
	runtime.rememberStopError(errors.Join(
		wrapSmokeSignalError("TERM", termErr),
		priorErr,
		wrapSmokeSignalError("KILL", killErr),
		wrapSmokeWaitError("KILL", waitErr),
	))
	if !exited {
		runtime.rememberStopError(fmt.Errorf("openresty process did not stop: %s", runtimeLog.String()))
		return runtime.pendingStopErr, false
	}
	cleanupErr, complete := runtime.cleanupDescendantPidfds(false)
	runtime.rememberStopError(cleanupErr)
	return runtime.pendingStopErr, complete
}

func (runtime *smokeRuntimeProcess) addDescendantPidfds(pidfds []int) {
	if runtime.descendantKilled == nil {
		runtime.descendantKilled = make(map[int]bool, len(pidfds))
	}
	runtime.descendantPidfds = append(runtime.descendantPidfds, pidfds...)
}

func (runtime *smokeRuntimeProcess) cleanupDescendantPidfds(retryKills bool) (error, bool) {
	remaining := runtime.descendantPidfds[:0]
	var result error
	for _, pidfd := range runtime.descendantPidfds {
		killed := runtime.descendantKilled[pidfd]
		if !killed && retryKills {
			killErr := smokeSignalPidfd(pidfd, syscall.SIGKILL)
			if errors.Is(killErr, syscall.ESRCH) {
				killed = true
			} else if killErr != nil {
				result = errors.Join(result, wrapSmokeCause("kill openresty descendant", killErr))
				remaining = append(remaining, pidfd)
				continue
			} else {
				killed = true
			}
			runtime.descendantKilled[pidfd] = killed
		}
		if !killed {
			remaining = append(remaining, pidfd)
			continue
		}
		exited, probeErr := smokeWaitPidfdExit(pidfd, runtime.leaderExited)
		if probeErr != nil {
			result = errors.Join(result, wrapSmokeCause("probe killed openresty descendant", probeErr))
			remaining = append(remaining, pidfd)
			continue
		}
		if !exited {
			remaining = append(remaining, pidfd)
			continue
		}
		if closeErr := smokeClosePidfd(pidfd); closeErr != nil {
			result = errors.Join(result, wrapSmokeCause("close openresty descendant pidfd", closeErr))
			remaining = append(remaining, pidfd)
			continue
		}
		delete(runtime.descendantKilled, pidfd)
	}
	runtime.descendantPidfds = remaining
	return result, len(remaining) == 0
}

func smokeWaitPidfdExit(pidfd int, wait bool) (bool, error) {
	deadline := time.Now().Add(smokeStopTimeout)
	for {
		probeErr := smokeSignalPidfd(pidfd, 0)
		if errors.Is(probeErr, syscall.ESRCH) {
			return true, nil
		}
		if probeErr != nil {
			return false, probeErr
		}
		if !wait || !time.Now().Before(deadline) {
			return false, nil
		}
		time.Sleep(time.Millisecond)
	}
}

func (runtime *smokeRuntimeProcess) rememberStopError(err error) {
	if err != nil {
		runtime.pendingStopErr = errors.Join(runtime.pendingStopErr, err)
	}
}

func wrapSmokeSignalError(name string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("signal openresty process %s: %w", name, err)
}

func wrapSmokeWaitError(stage string, waitErr error) error {
	if waitErr == nil {
		return nil
	}
	return fmt.Errorf("wait for openresty after %s: %w", stage, waitErr)
}

func closeSmokePidfds(pidfds []int) error {
	var result error
	for _, pidfd := range pidfds {
		result = errors.Join(result, smokeClosePidfd(pidfd))
	}
	return result
}

func (runtime *smokeRuntimeProcess) ownsProcessGroup() bool {
	startTime, ok := smokeReadProcessIdentity(runtime.processID)
	return ok && startTime == runtime.startTime
}

func (runtime *smokeRuntimeProcess) waitForExitWithin(timeout time.Duration) (bool, error) {
	select {
	case err := <-runtime.wait:
		runtime.leaderExited = true
		runtime.leaderWaitErr = err
		return true, err
	case <-time.After(timeout):
		return false, nil
	}
}

func smokeWaitStartedProcess(wait <-chan error, timeout time.Duration) error {
	select {
	case err := <-wait:
		return err
	case <-time.After(timeout):
		return errors.New("process wait timed out")
	}
}

const (
	linuxSysPidfdSendSignal = 424
	linuxSysPidfdOpen       = 434
)

func smokePidfdOpen(processID int) (int, error) {
	if runtime.GOOS != "linux" {
		return -1, errors.New("pidfd requires linux")
	}
	fileDescriptor, _, errno := syscall.Syscall(uintptr(linuxSysPidfdOpen), uintptr(processID), 0, 0)
	if errno != 0 {
		return -1, errno
	}
	return int(fileDescriptor), nil
}

func smokePidfdSendSignal(pidfd int, signal syscall.Signal) error {
	if runtime.GOOS != "linux" {
		return errors.New("pidfd requires linux")
	}
	_, _, errno := syscall.Syscall6(uintptr(linuxSysPidfdSendSignal), uintptr(pidfd), uintptr(signal), 0, 0, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

type smokeProcessSnapshot struct {
	processID     int
	processGroup  int
	startIdentity string
}

type smokePidfdCollection struct {
	descendants []int
	rejected    []int
}

var smokeListProcessSnapshots = listSmokeProcessSnapshots

var smokeReadProcessSnapshot = readSmokeProcessSnapshot

func listSmokeProcessSnapshots() ([]smokeProcessSnapshot, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	snapshots := make([]smokeProcessSnapshot, 0, len(entries))
	for _, entry := range entries {
		processID, parseErr := strconv.Atoi(entry.Name())
		if parseErr != nil || processID <= 1 {
			continue
		}
		snapshot, ok := readSmokeProcessSnapshot(processID)
		if ok {
			snapshots = append(snapshots, snapshot)
		}
	}
	return snapshots, nil
}

func smokeProcessGroupPidfds(leader *smokeRuntimeProcess) (smokePidfdCollection, error) {
	if leader == nil {
		return smokePidfdCollection{}, errors.New("openresty leader is nil")
	}
	if !leader.ownsPidfd {
		return smokePidfdCollection{}, errors.New("openresty leader pidfd is not owned")
	}
	if err := smokeSignalPidfd(leader.pidfd, 0); err != nil {
		return smokePidfdCollection{}, fmt.Errorf("probe openresty leader pidfd: %w", err)
	}
	leaderStart, leaderOK := smokeReadProcessIdentity(leader.processID)
	if !leaderOK || leaderStart != leader.startTime {
		return smokePidfdCollection{}, errors.New("openresty leader identity changed before descendant scan")
	}
	snapshots, err := smokeListProcessSnapshots()
	if err != nil {
		return smokePidfdCollection{}, err
	}
	collection := smokePidfdCollection{descendants: make([]int, 0)}
	var result error
	reject := func(pidfd int, cause error) {
		closeErr := smokeClosePidfd(pidfd)
		if closeErr != nil {
			collection.rejected = append(collection.rejected, pidfd)
		}
		result = errors.Join(result, cause, wrapSmokeCause("close rejected openresty descendant pidfd", closeErr))
	}
	for _, snapshot := range snapshots {
		processID := snapshot.processID
		if processID == leader.processID || snapshot.processGroup != leader.processID {
			continue
		}
		pidfd, openErr := smokeOpenPidfd(processID)
		if openErr != nil {
			if !errors.Is(openErr, syscall.ESRCH) {
				result = errors.Join(result, openErr)
			}
			continue
		}
		current, identityOK := smokeReadProcessSnapshot(processID)
		if !identityOK || current != snapshot || current.processID == leader.processID ||
			current.processGroup != leader.processID {
			reject(pidfd, nil)
			continue
		}
		if probeErr := smokeSignalPidfd(pidfd, 0); probeErr != nil {
			if errors.Is(probeErr, syscall.ESRCH) {
				probeErr = nil
			}
			reject(pidfd, probeErr)
			continue
		}
		revalidated, identityOK := smokeReadProcessSnapshot(processID)
		if !identityOK || revalidated != current {
			reject(pidfd, nil)
			continue
		}
		collection.descendants = append(collection.descendants, pidfd)
	}
	return collection, result
}

func readSmokeProcessSnapshot(processID int) (smokeProcessSnapshot, bool) {
	content, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(processID), "stat"))
	closing := bytes.LastIndexByte(content, ')')
	if err != nil || closing < 0 {
		return smokeProcessSnapshot{}, false
	}
	fields := strings.Fields(string(content[closing+1:]))
	if len(fields) < 20 {
		return smokeProcessSnapshot{}, false
	}
	processGroup, parseErr := strconv.Atoi(fields[2])
	if parseErr != nil || processGroup <= 1 || fields[19] == "" {
		return smokeProcessSnapshot{}, false
	}
	return smokeProcessSnapshot{processID: processID, processGroup: processGroup, startIdentity: fields[19]}, true
}

func smokeProcessIdentity(processID int) (string, bool) {
	snapshot, ok := smokeReadProcessSnapshot(processID)
	return snapshot.startIdentity, ok && snapshot.processGroup == processID
}

type smokeCleanupEvidence struct {
	processGroupZero, originListenerZero, pidFileZero, taskListenersZero bool
	runtimeTempZero, ppid1ResidueZero, callerStateRootPreserved          bool
}

func cleanupOpenRestySmoke(runtime *smokeRuntimeProcess, runtimeLog *bytes.Buffer, origin *testHTTPServer,
	pidFile, runtimeTempRoot, stateRoot string, ports []uint16) (smokeCleanupEvidence, error) {
	result := smokeCleanupEvidence{}
	if err := stopSmokeRuntime(runtime, runtimeLog); err != nil {
		return result, err
	}
	if err := os.Remove(pidFile); err != nil && !errors.Is(err, os.ErrNotExist) {
		return result, fmt.Errorf("remove owned nginx pid file: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := origin.server.Shutdown(ctx); err != nil {
		return result, fmt.Errorf("stop smoke origin: %w", err)
	}
	if err := os.RemoveAll(runtimeTempRoot); err != nil {
		return result, fmt.Errorf("remove owned runtime temp: %w", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		groupResidue, ppid1Residue := smokeTestProcessGroupResidue(runtime.processID)
		result.processGroupZero = !groupResidue && !runtime.ownsProcessGroup()
		result.ppid1ResidueZero = !ppid1Residue
		result.originListenerZero = !smokePortListening(origin.port())
		result.taskListenersZero = true
		for _, port := range ports {
			result.taskListenersZero = result.taskListenersZero && !smokePortListening(port)
		}
		_, pidErr := os.Lstat(pidFile)
		result.pidFileZero = errors.Is(pidErr, os.ErrNotExist)
		_, tempErr := os.Lstat(runtimeTempRoot)
		result.runtimeTempZero = errors.Is(tempErr, os.ErrNotExist)
		stateInfo, stateErr := os.Stat(stateRoot)
		result.callerStateRootPreserved = stateErr == nil && stateInfo.IsDir()
		if result.processGroupZero && result.ppid1ResidueZero && result.originListenerZero && result.taskListenersZero &&
			result.pidFileZero && result.runtimeTempZero && result.callerStateRootPreserved {
			return result, nil
		}
		if time.Now().After(deadline) {
			return result, fmt.Errorf("smoke cleanup residue: %+v", result)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func smokePortListening(port uint16) bool {
	connection, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))), 20*time.Millisecond)
	if err != nil {
		return false
	}
	_ = connection.Close()
	return true
}

func smokeTestProcessGroupResidue(processGroupID int) (bool, bool) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return true, false
	}
	groupResidue, ppid1Residue := false, false
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		processID, parseErr := strconv.Atoi(entry.Name())
		if parseErr != nil || processID <= 1 {
			continue
		}
		stat, readErr := os.ReadFile(filepath.Join("/proc", entry.Name(), "stat"))
		closing := bytes.LastIndexByte(stat, ')')
		if readErr != nil || closing < 0 {
			continue
		}
		fields := strings.Fields(string(stat[closing+1:]))
		if len(fields) < 3 {
			continue
		}
		parentID, parentErr := strconv.Atoi(fields[1])
		groupID, groupErr := strconv.Atoi(fields[2])
		if parentErr != nil || groupErr != nil || groupID != processGroupID {
			continue
		}
		groupResidue = true
		ppid1Residue = ppid1Residue || parentID == 1
	}
	return groupResidue, ppid1Residue
}

func reserveSmokePorts(t *testing.T, count int) []uint16 {
	t.Helper()
	ports := make([]uint16, 0, count)
	for len(ports) < count {
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := uint16(listener.Addr().(*net.TCPAddr).Port)
		if err := listener.Close(); err != nil {
			t.Fatal(err)
		}
		duplicate := false
		for _, existing := range ports {
			duplicate = duplicate || existing == port
		}
		if !duplicate {
			ports = append(ports, port)
		}
	}
	return ports
}

func waitForSmokeListener(port uint16, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		connection, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))), 50*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return errors.New("listener timeout")
}

func smokeCacheRequest(site SiteContext, path string) (string, error) {
	request, err := http.NewRequest(http.MethodGet,
		"http://"+net.JoinHostPort("127.0.0.1", strconv.Itoa(int(site.ListenPort)))+path, nil)
	if err != nil {
		return "", err
	}
	request.Host = site.Domain
	client := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, Timeout: 2 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status %d", response.StatusCode)
	}
	if response.Header.Get("X-CDNCA-Config-Version") != site.ConfigVersionID ||
		response.Header.Get("X-CDNCA-Cache-Namespace") != site.CacheIdentity {
		return "", errors.New("runtime identity header mismatch")
	}
	cache := response.Header.Get("X-CDN-Cache")
	if cache != "MISS" && cache != "HIT" {
		return "", fmt.Errorf("unexpected cache state %q", cache)
	}
	return cache, nil
}
