// Package wafprobe is the node's self test of the automatic exclusion cost
// (adjusted per node): a short lived OpenResty of
// its own (one worker, lowered priority, a unix socket, never the business
// workers) runs one tier in use twice, location /a without exclusions and
// /b with N in its bucket rule, and interleaved rounds of the same clean
// request on both give the time one exclusion adds to one request on this
// machine as it is loaded now. A few seconds in all.
package wafprobe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sync"
	"syscall"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/dynwaf"
	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// Config of one measurement.
type Config struct {
	OpenResty string // the node's OpenResty binary
	Dir       string // scratch directory (recreated)
	Probe     *dynwaf.Probe
	// Exclusions on /b (default 256), Rounds interleaved rounds (default
	// 7) of Requests requests a variant (default 300) from Clients
	// concurrent clients (default 4).
	Exclusions, Rounds, Requests, Clients int
}

// Result of a measurement.
type Result struct {
	CostNanos int64 // per exclusion per request, >= 0
	// BaseNanos / LoadedNanos: the medians of the rounds' worker time a
	// request on /a and on /b.
	BaseNanos, LoadedNanos int64
	Duration               time.Duration
}

// probeSite is the synthetic site of the probe's context and bucket.
const probeSite = "0c0ffee0-0000-4000-8000-000000000001"

// context is a clean c3 context of probeSite (engine on, no detector, no
// tightening): what the node's Lua writes for an ordinary request. The
// request ID never ends in DynamicWAFSampleDigit, so nothing is audited.
func context3() string {
	return edgeconfig.DynamicWAFContext{SiteID: probeSite, RequestID: "probe1"}.String()
}

// Config renders the probe's nginx.conf.
func renderConfig(cfg Config, bucketFile string) string {
	tx := context3()
	location := func(name, rules string) string {
		return fmt.Sprintf("    location ^~ %s/ {\n      modsecurity on;\n      modsecurity_rules_file %s;\n"+
			"      modsecurity_transaction_id \"%s\";\n      content_by_lua_block { ngx.exit(200) }\n    }\n", name, rules, tx)
	}
	return fmt.Sprintf("daemon off;\nmaster_process off;\nworker_processes 1;\npid %s;\nerror_log %s warn;\nload_module %s;\n"+
		"events { worker_connections 64; }\nhttp {\n  access_log off;\n"+
		"  modsecurity_rules 'SecUnicodeMapFile %s 20127';\n  modsecurity_rules_file %s;\n"+
		"  server {\n    listen unix:%s;\n%s%s  }\n}\n",
		filepath.Join(cfg.Dir, "nginx.pid"), filepath.Join(cfg.Dir, "error.log"), cfg.Probe.Engine.ModulePath,
		cfg.Probe.Engine.UnicodeMapPath, cfg.Probe.RulesPath, filepath.Join(cfg.Dir, "probe.sock"),
		location("/a", cfg.Probe.TierFile), location("/b", bucketFile))
}

// Batch sizing: the warm batch's requests, the time a measuring batch aims
// at and its fewest requests.
const (
	warmRequests = 60
	batchTime    = time.Second
	minBatch     = 40
)

// path is the probe request: a clean query with a few parameters, cookies
// and headers (CRS reads every one of them).
const path = "/x?id=12345&q=hello+world&page=2&sort=name&lang=zh-CN"

func (cfg *Config) defaults() {
	if cfg.Exclusions <= 0 {
		cfg.Exclusions = 256
	}
	if cfg.Rounds <= 0 {
		cfg.Rounds = 7
	}
	if cfg.Requests <= 0 {
		cfg.Requests = 300
	}
	if cfg.Clients <= 0 {
		cfg.Clients = 4
	}
}

// Measure runs the self test.
func Measure(ctx context.Context, cfg Config) (Result, error) {
	cfg.defaults()
	if cfg.Probe == nil || cfg.OpenResty == "" || cfg.Dir == "" {
		return Result{}, errors.New("wafprobe: OpenResty, Dir and Probe are required")
	}
	started := time.Now()
	if err := os.RemoveAll(cfg.Dir); err != nil {
		return Result{}, err
	}
	if err := os.MkdirAll(cfg.Dir, 0o700); err != nil {
		return Result{}, err
	}
	defer os.RemoveAll(cfg.Dir)
	bucket, err := cfg.Probe.ProbeBucket(probeSite, cfg.Exclusions)
	if err != nil {
		return Result{}, err
	}
	bucketFile := filepath.Join(cfg.Dir, "bucket.conf")
	if err := os.WriteFile(bucketFile, bucket, 0o600); err != nil {
		return Result{}, err
	}
	if err := os.WriteFile(filepath.Join(cfg.Dir, "nginx.conf"), []byte(renderConfig(cfg, bucketFile)), 0o600); err != nil {
		return Result{}, err
	}
	command := exec.CommandContext(ctx, cfg.OpenResty, "-p", cfg.Dir+"/", "-c", "nginx.conf")
	command.Cancel = func() error { return command.Process.Signal(syscall.SIGQUIT) }
	command.WaitDelay = 5 * time.Second
	if err := command.Start(); err != nil {
		return Result{}, fmt.Errorf("wafprobe: start OpenResty: %w", err)
	}
	// below the business workers (best effort)
	_ = syscall.Setpriority(syscall.PRIO_PROCESS, command.Process.Pid, 10)
	defer func() {
		_ = command.Process.Signal(syscall.SIGQUIT)
		_ = command.Wait()
	}()
	socket := filepath.Join(cfg.Dir, "probe.sock")
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{MaxIdleConnsPerHost: cfg.Clients,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		}}}
	defer client.CloseIdleConnections()
	get := func(location string) error {
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://probe"+location+path, nil)
		request.Header.Set("Accept", "text/html,application/xhtml+xml")
		request.Header.Set("User-Agent", "Mozilla/5.0 (cdnca waf probe)")
		request.Header.Set("Cookie", "session=abc123; theme=dark")
		response, err := client.Do(request)
		if err != nil {
			return err
		}
		_, _ = io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return fmt.Errorf("wafprobe: %s: status %d", location, response.StatusCode)
		}
		return nil
	}
	for deadline := time.Now().Add(15 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		if err := get("/a"); err == nil {
			break
		} else if time.Now().After(deadline) || ctx.Err() != nil {
			raw, _ := os.ReadFile(filepath.Join(cfg.Dir, "error.log"))
			return Result{}, fmt.Errorf("wafprobe: OpenResty not ready: %v %s", err, tail(raw))
		}
	}
	// batch: requests from clients, the worker time a request (wall time
	// over requests: the one worker is the bottleneck)
	batch := func(location string, requests int) (int64, error) {
		var wg sync.WaitGroup
		errs := make(chan error, cfg.Clients)
		begin := time.Now()
		for client := range cfg.Clients {
			share := requests / cfg.Clients
			if client < requests%cfg.Clients {
				share++
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				for range share {
					if err := get(location); err != nil {
						errs <- err
						return
					}
				}
			}()
		}
		wg.Wait()
		close(errs)
		if err := <-errs; err != nil {
			return 0, err
		}
		return time.Since(begin).Nanoseconds() / int64(requests), nil
	}
	// warm both; the loaded one's time a request sizes the batches to about
	// batchTime each (a loaded node takes fewer requests a round, so the
	// test stays within seconds; waf-exclcap2 S4: 68 s at --cpus 1 with two
	// busy threads before)
	slowest := int64(1)
	for _, location := range []string{"/a", "/b"} {
		value, err := batch(location, warmRequests)
		if err != nil {
			return Result{}, err
		}
		slowest = max(slowest, value)
	}
	requests := int(min(max(batchTime.Nanoseconds()/slowest, minBatch), int64(cfg.Requests)))
	var base, loaded, diff []int64
	for round := range cfg.Rounds {
		order := []string{"/a", "/b"}
		if round%2 == 1 {
			order = []string{"/b", "/a"}
		}
		values := map[string]int64{}
		for _, location := range order {
			value, err := batch(location, requests)
			if err != nil {
				return Result{}, err
			}
			values[location] = value
		}
		base, loaded = append(base, values["/a"]), append(loaded, values["/b"])
		diff = append(diff, values["/b"]-values["/a"])
	}
	// the upper quartile of the rounds' differences, not the median: on a
	// loaded node the rounds scatter, and underestimating the cost would
	// let a request pay more than the budget (waf-exclcap2 S4: --cpus 4
	// with 2 busy threads, the median gave 5.4 us an exclusion where the
	// site paid 8.4)
	return Result{CostNanos: max(quantile(diff, 0.75), 0) / int64(cfg.Exclusions), BaseNanos: median(base), LoadedNanos: median(loaded),
		Duration: time.Since(started)}, nil
}

// quantile is the value at q of values (nearest rank).
func quantile(values []int64, q float64) int64 {
	sorted := slices.Clone(values)
	slices.Sort(sorted)
	return sorted[min(len(sorted)-1, int(q*float64(len(sorted))))]
}

func median(values []int64) int64 {
	sorted := slices.Clone(values)
	slices.Sort(sorted)
	return sorted[len(sorted)/2]
}

func tail(raw []byte) string {
	if len(raw) > 512 {
		raw = raw[len(raw)-512:]
	}
	return string(raw)
}
