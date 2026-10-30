package drainruntime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestNewOpenRestyRejectsUnsafeBinaryAndStateDirectories(t *testing.T) {
	for _, test := range []struct {
		name  string
		build func(*testing.T, string, string) (string, string)
	}{
		{name: "symlink prefix", build: func(t *testing.T, root, binary string) (string, string) {
			target := filepath.Join(root, "target")
			if err := os.Mkdir(target, 0o700); err != nil {
				t.Fatal(err)
			}
			prefix := filepath.Join(root, "prefix")
			if err := os.Symlink(target, prefix); err != nil {
				t.Fatal(err)
			}
			return binary, prefix
		}},
		{name: "group writable prefix", build: func(t *testing.T, root, binary string) (string, string) {
			prefix := filepath.Join(root, "prefix")
			if err := os.Mkdir(prefix, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(prefix, 0o770); err != nil {
				t.Fatal(err)
			}
			return binary, prefix
		}},
		{name: "symlink logs", build: func(t *testing.T, root, binary string) (string, string) {
			prefix := filepath.Join(root, "prefix")
			target := filepath.Join(root, "logs-target")
			if err := os.Mkdir(prefix, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(target, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, filepath.Join(prefix, "logs")); err != nil {
				t.Fatal(err)
			}
			return binary, prefix
		}},
		{name: "symlink binary", build: func(t *testing.T, root, binary string) (string, string) {
			link := filepath.Join(root, "openresty-link")
			if err := os.Symlink(binary, link); err != nil {
				t.Fatal(err)
			}
			return link, filepath.Join(root, "prefix")
		}},
		{name: "writable binary", build: func(t *testing.T, root, binary string) (string, string) {
			if err := os.Chmod(binary, 0o722); err != nil {
				t.Fatal(err)
			}
			return binary, filepath.Join(root, "prefix")
		}},
		{name: "hardlinked binary", build: func(t *testing.T, root, binary string) (string, string) {
			if err := os.Link(binary, filepath.Join(root, "openresty-hardlink")); err != nil {
				t.Fatal(err)
			}
			return binary, filepath.Join(root, "prefix")
		}},
		{name: "world writable binary ancestor", build: func(t *testing.T, root, binary string) (string, string) {
			unsafe := filepath.Join(root, "unsafe-binary-parent")
			if err := os.Mkdir(unsafe, 0o700); err != nil {
				t.Fatal(err)
			}
			moved := filepath.Join(unsafe, filepath.Base(binary))
			if err := os.Rename(binary, moved); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(unsafe, 0o777); err != nil {
				t.Fatal(err)
			}
			return moved, filepath.Join(root, "prefix")
		}},
		{name: "world writable prefix ancestor", build: func(t *testing.T, root, binary string) (string, string) {
			unsafe := filepath.Join(root, "unsafe-prefix-parent")
			if err := os.Mkdir(unsafe, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(unsafe, 0o777); err != nil {
				t.Fatal(err)
			}
			return binary, filepath.Join(unsafe, "prefix")
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			binary := testExecutable(t, root)
			binary, prefix := test.build(t, root, binary)
			if _, err := NewOpenResty(binary, prefix, time.Second); !errors.Is(err, ErrInvalidPath) {
				t.Fatalf("NewOpenResty() error = %v, want ErrInvalidPath", err)
			}
		})
	}
}

func TestOpenRestyRejectsPostConstructionRuntimePathReplacement(t *testing.T) {
	for _, replaced := range []string{"binary", "prefix", "logs"} {
		t.Run(replaced, func(t *testing.T) {
			root := t.TempDir()
			marker := filepath.Join(root, "executed")
			binary := filepath.Join(root, "openresty")
			writeMarkerExecutable(t, binary, marker)
			prefix := filepath.Join(root, "prefix")
			runtime, err := NewOpenResty(binary, prefix, time.Second)
			if err != nil {
				t.Fatal(err)
			}

			switch replaced {
			case "binary":
				if err := os.Rename(binary, binary+".pinned"); err != nil {
					t.Fatal(err)
				}
				writeMarkerExecutable(t, binary, marker)
			case "prefix":
				if err := os.Rename(prefix, prefix+".pinned"); err != nil {
					t.Fatal(err)
				}
				if err := os.MkdirAll(filepath.Join(prefix, "logs"), 0o700); err != nil {
					t.Fatal(err)
				}
			case "logs":
				logs := filepath.Join(prefix, "logs")
				if err := os.Rename(logs, logs+".pinned"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(logs, 0o700); err != nil {
					t.Fatal(err)
				}
			}

			artifacts := Artifacts{
				CandidatePath: filepath.Join(root, "candidate.conf"),
				DrainingPath:  filepath.Join(root, "draining.conf"),
				RollbackPath:  filepath.Join(root, "rollback.conf"),
			}
			if err := runtime.Precheck(context.Background(), Plan{}, artifacts); !errors.Is(err, ErrInvalidPath) {
				t.Fatalf("Precheck() error = %v, want ErrInvalidPath", err)
			}
			if err := runtime.runStartCommand(context.Background(), strings.Repeat("a", 64)); !errors.Is(err, ErrInvalidPath) {
				t.Fatalf("runStartCommand() error = %v, want ErrInvalidPath", err)
			}
			if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("replacement crossed runtime path fence: marker error = %v", err)
			}
		})
	}
}

func TestCommandPinsRuntimePrefixForChild(t *testing.T) {
	root := t.TempDir()
	runtime, err := NewOpenResty(testExecutable(t, root), filepath.Join(root, "prefix"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	command, err := runtime.command(context.Background(), "-p", withSeparator(runtime.prefix), "-c", "current.conf")
	if err != nil {
		t.Fatal(err)
	}
	prefixFD := 3
	wantFiles := 1
	rootPath := "/dev/fd"
	if goruntime.GOOS == "linux" {
		prefixFD = 4
		wantFiles = 2
		rootPath = "/proc/self/fd"
	}
	wantPrefix := withSeparator(filepath.Join(rootPath, strconv.Itoa(prefixFD)))
	if len(command.Args) != 5 || command.Args[2] != wantPrefix || command.Args[2] == withSeparator(runtime.prefix) {
		t.Fatalf("command args = %q, want pinned prefix %q", command.Args, wantPrefix)
	}
	if len(command.ExtraFiles) != wantFiles || command.ExtraFiles[wantFiles-1] != runtime.prefixDir {
		t.Fatalf("command extra files = %v, want pinned prefix descriptor", command.ExtraFiles)
	}
}

func TestRunStartCommandDoesNotExportPendingToken(t *testing.T) {
	root := t.TempDir()
	outputPath := filepath.Join(root, "environment-result")
	binary := filepath.Join(root, "openresty-env-check")
	script := "#!/bin/sh\nif [ \"${" + processStartEnvironment + "+x}\" = x ]; then printf present > \"$1\"; else printf absent > \"$1\"; fi\n"
	if err := os.WriteFile(binary, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	runtime, err := NewOpenResty(binary, filepath.Join(root, "prefix"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.runStartCommand(context.Background(), strings.Repeat("a", 64), outputPath); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "absent" {
		t.Fatalf("pending start token environment = %q, want absent", content)
	}
}

func TestWorkerTrackingRejectsResourceExhaustingGeneration(t *testing.T) {
	runtime, artifacts := newIdentityTestRuntime(t)
	master := testIdentity(41, 100)
	workers := make([]processIdentity, 257)
	pids := make([]int, len(workers))
	for index := range workers {
		workers[index] = testIdentity(1000+index, uint64(2000+index))
		pids[index] = workers[index].PID
	}
	record := makeWorkerRecord(artifacts, master, workers, true)
	if err := validateWorkerRecord(record); !errors.Is(err, ErrCorruptState) {
		t.Fatalf("validateWorkerRecord() error = %v, want ErrCorruptState", err)
	}

	installMasterFixture(t, runtime, master)
	runtime.children = stableChildren(pids...)
	runtime.inspect = identityLookup(master)
	opened := 0
	runtime.openProcess = func(int) (processHandle, error) {
		opened++
		return nil, errors.New("unexpected worker pidfd open")
	}
	masterHandle := &fakeDrainProcessHandle{alive: true}
	if _, _, err := runtime.captureWorkerGenerationWithHandle(masterHandle, master); !errors.Is(err, ErrCorruptState) {
		t.Fatalf("captureWorkerGenerationWithHandle() error = %v, want ErrCorruptState", err)
	}
	if opened != 0 {
		t.Fatalf("opened %d worker pidfds before enforcing generation limit", opened)
	}
}

func TestCompiledFixturePreservesIdleSessionsForMaximumDrain(t *testing.T) {
	plan := validPlan(1)
	plan.Drain.MaxDrainSeconds = maxDrainTimeoutSeconds
	compiled, err := Compile(plan)
	if err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string][]byte{
		"candidate": compiled.CandidateNginx,
		"draining":  compiled.DrainingNginx,
		"rollback":  compiled.RollbackNginx,
	} {
		fixture := string(content)
		for _, directive := range []string{
			"proxy_read_timeout " + strconv.Itoa(maxDrainTimeoutSeconds) + "s;",
			"proxy_send_timeout " + strconv.Itoa(maxDrainTimeoutSeconds) + "s;",
			"proxy_timeout " + strconv.Itoa(maxDrainTimeoutSeconds) + "s;",
		} {
			if !strings.Contains(fixture, directive) {
				t.Errorf("%s fixture missing %q", name, directive)
			}
		}
		if strings.Contains(fixture, "proxy_read_timeout 1h;") || strings.Contains(fixture, "proxy_timeout 1h;") {
			t.Errorf("%s fixture retained a one-hour idle session limit", name)
		}
	}
}

func testExecutable(t *testing.T, root string) string {
	t.Helper()
	path := filepath.Join(root, "openresty")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeMarkerExecutable(t *testing.T, path, marker string) {
	t.Helper()
	script := "#!/bin/sh\nprintf executed > '" + marker + "'\n"
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
}
