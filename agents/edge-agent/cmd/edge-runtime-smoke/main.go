package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/deployment"
)

type startableRuntime struct {
	openresty *deployment.OpenResty
	binary    string
	config    string
	pidFile   string
}

func (r *startableRuntime) Reload(ctx context.Context, versionID, currentPath string) error {
	running, err := processRunning(r.pidFile)
	if err != nil {
		return err
	}
	if !running {
		if err := os.Remove(r.pidFile); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		command := exec.CommandContext(ctx, r.binary, "-p", currentPath+string(filepath.Separator), "-c", r.config)
		output, commandErr := command.CombinedOutput()
		if commandErr != nil {
			fmt.Fprintf(os.Stderr, "smoke OpenResty start failed: %s\n", strings.TrimSpace(string(output)))
		}
		return commandErr
	}
	return r.openresty.Reload(ctx, versionID, currentPath)
}

func processRunning(pidFile string) (bool, error) {
	value, err := os.ReadFile(pidFile)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(value)))
	if err != nil || pid <= 1 {
		return false, nil
	}
	err = syscall.Kill(pid, 0)
	if errors.Is(err, syscall.ESRCH) {
		return false, nil
	}
	if err != nil && !errors.Is(err, syscall.EPERM) {
		return false, err
	}
	return true, nil
}

func (r *startableRuntime) Healthy(ctx context.Context, versionID string) error {
	return r.openresty.Healthy(ctx, versionID)
}

func (r *startableRuntime) stop(stateRoot string) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	current := filepath.Join(stateRoot, "current")
	command := exec.CommandContext(ctx, r.binary, "-s", "quit", "-p", current+string(filepath.Separator), "-c", r.config)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	_ = command.Run()
}

type evidence struct {
	Baseline         []deployment.State `json:"baseline"`
	HealthyReload    []deployment.State `json:"healthy_reload"`
	HealthRollback   []deployment.State `json:"health_rollback"`
	PrecheckFailure  []deployment.State `json:"precheck_failure"`
	PrecheckError    string             `json:"precheck_error"`
	CurrentVersion   string             `json:"current_version"`
	PreviousVersion  string             `json:"previous_version"`
	FinalHealth      string             `json:"final_health"`
	RunningUnchanged bool               `json:"running_unchanged"`
}

func main() {
	stateRoot := flag.String("state-root", "/var/lib/cdnca-edge", "absolute edge state root")
	binary := flag.String("openresty-bin", "/usr/local/openresty/bin/openresty", "absolute OpenResty binary")
	listenPort := flag.Int("listen-port", 18080, "container health listen port")
	keepRuntime := flag.Bool("keep-runtime", false, "leave OpenResty running for an external probe")
	flag.Parse()
	if err := run(*stateRoot, *binary, *listenPort, *keepRuntime); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(stateRoot, binary string, listenPort int, keepRuntime bool) error {
	if !filepath.IsAbs(stateRoot) || filepath.Clean(stateRoot) != stateRoot || listenPort < 1 || listenPort > 65535 {
		return fmt.Errorf("invalid smoke-test arguments")
	}
	shared := filepath.Join(stateRoot, "shared")
	if err := os.MkdirAll(shared, 0o700); err != nil {
		return fmt.Errorf("create shared runtime directory: %w", err)
	}
	healthURL := fmt.Sprintf("http://127.0.0.1:%d/healthz", listenPort)
	probe := func(ctx context.Context, versionID string) error {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
		if err != nil {
			return err
		}
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, 256))
		if err != nil {
			return err
		}
		if response.StatusCode != http.StatusOK || response.Header.Get("X-CDNCA-Config-Version") != versionID || string(body) != "ok:"+versionID+"\n" {
			return fmt.Errorf("runtime has not confirmed version %s", versionID)
		}
		return nil
	}
	openresty, err := deployment.NewOpenResty(binary, "nginx.conf", nil, probe)
	if err != nil {
		return err
	}
	runtime := &startableRuntime{
		openresty: openresty,
		binary:    binary,
		config:    "nginx.conf",
		pidFile:   filepath.Join(shared, "nginx.pid"),
	}
	if !keepRuntime {
		defer runtime.stop(stateRoot)
	}
	config := deployment.DefaultConfig()
	config.PrecheckTimeout = 5 * time.Second
	config.ReloadTimeout = 5 * time.Second
	config.HealthTimeout = 800 * time.Millisecond
	config.HealthInterval = 25 * time.Millisecond
	manager, err := deployment.NewManagerWithConfig(stateRoot, openresty, runtime, config)
	if err != nil {
		return err
	}

	baseline, err := manager.Process(context.Background(), command("deploy-v1", "cfg-v1", "", healthyConfig("cfg-v1", "cfg-v1", stateRoot, listenPort)))
	if err != nil || baseline.State != deployment.StateHealthy {
		return fmt.Errorf("baseline activation failed: result=%+v error=%v", baseline, err)
	}
	healthy, err := manager.Process(context.Background(), command("deploy-v2", "cfg-v2", "cfg-v1", healthyConfig("cfg-v2", "cfg-v2", stateRoot, listenPort)))
	if err != nil || healthy.State != deployment.StateHealthy {
		return fmt.Errorf("healthy reload failed: result=%+v error=%v", healthy, err)
	}
	rollback, err := manager.Process(context.Background(), command("deploy-v3", "cfg-v3", "cfg-v2", healthyConfig("cfg-v3", "unhealthy", stateRoot, listenPort)))
	if err != nil || rollback.State != deployment.StateReverted {
		return fmt.Errorf("health rollback failed: result=%+v error=%v", rollback, err)
	}
	precheck, err := manager.Process(context.Background(), command("deploy-v4", "cfg-v4", "cfg-v2", []byte("worker_processes 1;\nthis_directive_does_not_exist on;\n")))
	if err != nil || precheck.State != deployment.StateFailed || precheck.ErrorCode != "PRECHECK_FAILED" || !precheck.RunningConfigUnchanged {
		return fmt.Errorf("invalid configuration was not rejected safely: result=%+v error=%v", precheck, err)
	}
	pointers, err := manager.Pointers()
	if err != nil {
		return err
	}
	if pointers.Current != "cfg-v2" || pointers.Previous != "cfg-v1" {
		return fmt.Errorf("unexpected final pointers: %+v", pointers)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := probe(ctx, "cfg-v2"); err != nil {
		return fmt.Errorf("final rollback health: %w", err)
	}

	encoded, err := json.MarshalIndent(evidence{
		Baseline:         states(baseline),
		HealthyReload:    states(healthy),
		HealthRollback:   states(rollback),
		PrecheckFailure:  states(precheck),
		PrecheckError:    precheck.ErrorCode,
		CurrentVersion:   pointers.Current,
		PreviousVersion:  pointers.Previous,
		FinalHealth:      "ok:cfg-v2",
		RunningUnchanged: precheck.RunningConfigUnchanged,
	}, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(encoded))
	return nil
}

func healthyConfig(versionID, bodyVersion, stateRoot string, listenPort int) []byte {
	return []byte(fmt.Sprintf(`worker_processes 1;
pid %s;
error_log %s notice;
events { worker_connections 128; }
http {
  access_log off;
  server {
    listen 0.0.0.0:%d;
    server_name _;
    location = /healthz {
      default_type text/plain;
      add_header X-CDNCA-Config-Version %s always;
      return 200 "ok:%s\n";
    }
  }
}
`, filepath.Join(stateRoot, "shared", "nginx.pid"), filepath.Join(stateRoot, "shared", "error.log"), listenPort, versionID, bodyVersion))
}

func command(deploymentID, versionID, previous string, config []byte) deployment.Command {
	fileSum := sha256.Sum256(config)
	manifest := deployment.Manifest{Files: []deployment.FileManifest{{
		Path:   "nginx.conf",
		Size:   int64(len(config)),
		SHA256: hex.EncodeToString(fileSum[:]),
	}}}
	manifestDigest, err := deployment.ManifestDigest(manifest)
	if err != nil {
		panic(err)
	}
	return deployment.Command{
		DeploymentID:      deploymentID,
		Attempt:           1,
		Action:            deployment.ActionApply,
		ConfigVersionID:   versionID,
		PreviousVersionID: previous,
		Bundle: deployment.Bundle{
			Manifest:       manifest,
			ManifestSHA256: manifestDigest,
			Files:          map[string][]byte{"nginx.conf": config},
		},
	}
}

func states(result deployment.Result) []deployment.State {
	values := make([]deployment.State, 0, len(result.Transitions))
	for _, transition := range result.Transitions {
		values = append(values, transition.State)
	}
	return values
}
