package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/rangecache"
)

type openRestyRuntime struct {
	binary  string
	pidPath string
}

func (runtime openRestyRuntime) Precheck(ctx context.Context, config string) error {
	return runtime.run(ctx, "-t", "-p", "/", "-c", config)
}

func (runtime openRestyRuntime) Reload(ctx context.Context, config string) error {
	if runtime.running() {
		return runtime.run(ctx, "-p", "/", "-c", config, "-s", "reload")
	}
	return runtime.run(ctx, "-p", "/", "-c", config)
}

func (runtime openRestyRuntime) Healthy(ctx context.Context, config string) error {
	policy, err := readPolicy(filepath.Join(filepath.Dir(config), "policy.json"))
	if err != nil {
		return err
	}
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            (&net.Dialer{Timeout: time.Second}).DialContext,
		DisableKeepAlives:      true,
		MaxResponseHeaderBytes: 4096,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("range cache health redirect rejected")
		},
	}
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	var lastErr error
	for {
		if runtime.running() {
			if err := probePolicy(ctx, client, policy); err == nil {
				return nil
			} else {
				lastErr = err
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("range cache health check failed: %v: %w", lastErr, ctx.Err())
		case <-ticker.C:
		}
	}
}

func (runtime openRestyRuntime) Stop(ctx context.Context, config string) error {
	if !runtime.running() {
		return nil
	}
	if err := runtime.run(ctx, "-p", "/", "-c", config, "-s", "quit"); err != nil {
		return err
	}
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for runtime.running() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
	return nil
}

func readPolicy(path string) (rangecache.Policy, error) {
	file, err := os.Open(path)
	if err != nil {
		return rangecache.Policy{}, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, rangecache.MaxPolicyBytes+1))
	if err != nil {
		return rangecache.Policy{}, err
	}
	if len(raw) > rangecache.MaxPolicyBytes {
		return rangecache.Policy{}, errors.New("stored range cache policy is too large")
	}
	var policy rangecache.Policy
	if err := json.Unmarshal(raw, &policy); err != nil || policy.SchemaVersion != rangecache.SchemaVersion || policy.PolicyVersion == 0 || len(policy.Sites) == 0 {
		return rangecache.Policy{}, errors.New("stored range cache policy is invalid")
	}
	return policy, nil
}

func probePolicy(ctx context.Context, client *http.Client, policy rangecache.Policy) error {
	expected := "ok:" + strconv.FormatUint(policy.PolicyVersion, 10) + "\n"
	for _, site := range policy.Sites {
		if len(site.Hosts) == 0 {
			return errors.New("range cache health site has no host")
		}
		address := site.ListenAddress
		if address == "0.0.0.0" {
			address = "127.0.0.1"
		} else if address == "::" {
			address = "::1"
		}
		endpoint := "http://" + net.JoinHostPort(address, strconv.Itoa(int(site.ListenPort))) + "/_cdnca/range-healthz"
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return err
		}
		request.Host = site.Hosts[0]
		response, err := client.Do(request)
		if err != nil {
			return err
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 65))
		closeErr := response.Body.Close()
		if readErr != nil {
			return readErr
		}
		if closeErr != nil {
			return closeErr
		}
		if response.StatusCode != http.StatusOK || len(body) > 64 || string(body) != expected {
			return fmt.Errorf("range cache health response for site %q was status=%d body=%q", site.SiteID, response.StatusCode, body)
		}
	}
	return nil
}

func (runtime openRestyRuntime) running() bool {
	raw, err := os.ReadFile(runtime.pidPath)
	if err != nil {
		return false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	return err == nil && pid > 1 && syscall.Kill(pid, 0) == nil
}

func (runtime openRestyRuntime) run(ctx context.Context, arguments ...string) error {
	command := exec.CommandContext(ctx, runtime.binary, arguments...)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("openresty %s: %w: %s", strings.Join(arguments, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}

func main() {
	policyRoot := flag.String("policy-root", "", "absolute policy release root")
	stateRoot := flag.String("state-root", "", "absolute mutable cache runtime root")
	luaRoot := flag.String("lua-root", "", "absolute range guard module root")
	openResty := flag.String("openresty-bin", "/usr/local/openresty/bin/openresty", "OpenResty binary")
	flag.Parse()
	if *policyRoot == "" || *stateRoot == "" || *luaRoot == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: range-policy -policy-root /policy -state-root /runtime -lua-root /opt/cdnca-range < policy.json")
		os.Exit(2)
	}
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, rangecache.MaxPolicyBytes+1))
	if err != nil {
		fatal(err)
	}
	runtime := openRestyRuntime{binary: *openResty, pidPath: filepath.Join(*stateRoot, "range-cache.pid")}
	publisher, err := rangecache.NewPublisher(*policyRoot, rangecache.RuntimePaths{StateRoot: *stateRoot, LuaRoot: *luaRoot}, runtime)
	if err != nil {
		fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	publication, err := publisher.ApplyJSON(ctx, raw)
	if err != nil {
		fatal(err)
	}
	fmt.Printf("policy_version=%d sha256=%x changed=%t current=%s\n", publication.PolicyVersion, publication.Digest, publication.Changed, filepath.Join(*policyRoot, "current", "nginx.conf"))
}

func fatal(err error) {
	if errors.Is(err, context.DeadlineExceeded) {
		fmt.Fprintln(os.Stderr, "range policy activation timed out")
	} else {
		fmt.Fprintln(os.Stderr, err)
	}
	os.Exit(1)
}
