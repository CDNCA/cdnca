// cdnca-plugin-host: ADR 0017 PoC of the out-of-process node plugin host
// (not product code).
//
// One process per node runs third-party WASM plugins under wazero; nginx
// calls it over a unix socket from access_by_lua (lua/plugin_call.lua). The
// process boundary is the crash/memory boundary for nginx; inside the
// process each call gets a fresh deadline (wazero CloseOnContextDone), a
// linear memory cap (MemoryLimitPages) and an instance from a fixed pool.
// An instance that traps, times out or hits the memory cap is discarded and
// replaced, so one bad request cannot poison the next.
//
// Wire format (both directions): 4-byte big-endian length + payload.
// Request payload "METHOD URI\nheader: value\n..."; reply payload is the
// plugin decision, or "error <reason>" (the nginx side then applies its
// fail-open/fail-closed policy). The payload "STATS" returns counters.
//
// SIGHUP reloads -plugin from disk: a file that does not compile keeps the
// last good plugin (LKG); a missing file unloads (replies "none").
package main

import (
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

const maxPayload = 64 << 10

var (
	socketPath = flag.String("socket", "/run/cdnca-plugin.sock", "unix socket")
	pluginPath = flag.String("plugin", "/plugins/plugin.wasm", "plugin file")
	poolSize   = flag.Int("pool", 8, "instances per plugin")
	callBudget = flag.Duration("timeout", 20*time.Millisecond, "per-call deadline")
	waitBudget = flag.Duration("wait", 5*time.Millisecond, "max wait for a free instance")
	memoryMiB  = flag.Int("memory-mib", 64, "linear memory cap per instance")
)

type counters struct {
	calls, ok, timeouts, traps, busy, recycled, reloads, reloadRejected atomic.Int64
}

var stats counters

type instance struct {
	module api.Module
	alloc  api.Function
	handle api.Function
}

// plugin is one loaded plugin version: its compiled code and instance pool.
type plugin struct {
	runtime  wazero.Runtime
	compiled wazero.CompiledModule
	pool     chan *instance
	sha      string
}

func newPlugin(ctx context.Context, code []byte) (*plugin, error) {
	config := wazero.NewRuntimeConfigCompiler().WithCloseOnContextDone(true).
		WithMemoryLimitPages(uint32(*memoryMiB * 16))
	runtime := wazero.NewRuntimeWithConfig(ctx, config)
	wasi_snapshot_preview1.MustInstantiate(ctx, runtime)
	compiled, err := runtime.CompileModule(ctx, code)
	if err != nil {
		runtime.Close(ctx)
		return nil, fmt.Errorf("compile: %w", err)
	}
	// The plugin sees no filesystem, no env, no args, no network: WASI gives
	// it clocks and random only (wazero denies everything not configured).
	p := &plugin{runtime: runtime, compiled: compiled, pool: make(chan *instance, *poolSize)}
	for range *poolSize {
		inst, err := p.instantiate(ctx)
		if err != nil {
			runtime.Close(ctx)
			return nil, err
		}
		p.pool <- inst
	}
	return p, nil
}

func (p *plugin) instantiate(ctx context.Context) (*instance, error) {
	initCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	module, err := p.runtime.InstantiateModule(initCtx, p.compiled,
		wazero.NewModuleConfig().WithName("").WithStartFunctions("_initialize"))
	if err != nil {
		return nil, fmt.Errorf("instantiate: %w", err)
	}
	alloc, handle := module.ExportedFunction("cdnca_alloc"), module.ExportedFunction("cdnca_on_request")
	if alloc == nil || handle == nil {
		module.Close(ctx)
		return nil, errors.New("plugin does not export cdnca_alloc / cdnca_on_request")
	}
	return &instance{module: module, alloc: alloc, handle: handle}, nil
}

// call runs one request through a pooled instance.
func (p *plugin) call(ctx context.Context, request []byte) string {
	stats.calls.Add(1)
	var inst *instance
	select {
	case inst = <-p.pool:
	case <-time.After(*waitBudget):
		stats.busy.Add(1)
		return "error busy"
	}
	callCtx, cancel := context.WithTimeout(ctx, *callBudget)
	defer cancel()
	decision, err := invoke(callCtx, inst, request)
	if err == nil {
		p.pool <- inst
		stats.ok.Add(1)
		return decision
	}
	reason := "trap"
	if callCtx.Err() != nil {
		reason = "timeout"
		stats.timeouts.Add(1)
	} else {
		stats.traps.Add(1)
	}
	// The instance state is unknown after a trap/timeout: replace it.
	_ = inst.module.Close(context.Background())
	stats.recycled.Add(1)
	go func() {
		fresh, err := p.instantiate(context.Background())
		if err != nil {
			log.Printf("re-instantiate: %v", err)
			return
		}
		p.pool <- fresh
	}()
	return "error " + reason
}

func invoke(ctx context.Context, inst *instance, request []byte) (string, error) {
	results, err := inst.alloc.Call(ctx, uint64(len(request)))
	if err != nil {
		return "", err
	}
	ptr := uint32(results[0])
	if !inst.module.Memory().Write(ptr, request) {
		return "", errors.New("request out of plugin memory")
	}
	results, err = inst.handle.Call(ctx, uint64(ptr), uint64(len(request)))
	if err != nil {
		return "", err
	}
	out, ok := inst.module.Memory().Read(uint32(results[0]>>32), uint32(results[0]))
	if !ok || len(out) > 1024 {
		return "", errors.New("decision out of range")
	}
	return string(out), nil
}

func (p *plugin) close() { p.runtime.Close(context.Background()) }

type host struct {
	mu      sync.RWMutex
	current *plugin
}

func (h *host) load(ctx context.Context) {
	stats.reloads.Add(1)
	code, err := os.ReadFile(*pluginPath)
	if errors.Is(err, os.ErrNotExist) {
		h.swap(nil)
		log.Printf("plugin removed: unloaded")
		return
	}
	started := time.Now()
	var next *plugin
	if err == nil {
		next, err = newPlugin(ctx, code)
	}
	if err != nil {
		stats.reloadRejected.Add(1)
		log.Printf("reload rejected, keeping last good plugin: %v", err)
		return
	}
	log.Printf("plugin loaded: %d bytes, compile+%d instances in %s", len(code), *poolSize, time.Since(started))
	h.swap(next)
}

func (h *host) swap(next *plugin) {
	h.mu.Lock()
	previous := h.current
	h.current = next
	h.mu.Unlock()
	if previous != nil {
		// In-flight calls hold instances of previous; a real host would drain.
		time.AfterFunc(2*time.Second, previous.close)
	}
}

func (h *host) serve(conn net.Conn) {
	defer conn.Close()
	header := make([]byte, 4)
	for {
		if _, err := io.ReadFull(conn, header); err != nil {
			return
		}
		size := binary.BigEndian.Uint32(header)
		if size > maxPayload {
			return
		}
		payload := make([]byte, size)
		if _, err := io.ReadFull(conn, payload); err != nil {
			return
		}
		var reply string
		if string(payload) == "STATS" {
			reply = fmt.Sprintf("calls=%d ok=%d timeouts=%d traps=%d busy=%d recycled=%d reloads=%d reload_rejected=%d",
				stats.calls.Load(), stats.ok.Load(), stats.timeouts.Load(), stats.traps.Load(), stats.busy.Load(),
				stats.recycled.Load(), stats.reloads.Load(), stats.reloadRejected.Load())
		} else {
			h.mu.RLock()
			current := h.current
			h.mu.RUnlock()
			if current == nil {
				reply = "none"
			} else {
				reply = current.call(context.Background(), payload)
			}
		}
		out := make([]byte, 4+len(reply))
		binary.BigEndian.PutUint32(out, uint32(len(reply)))
		copy(out[4:], reply)
		if _, err := conn.Write(out); err != nil {
			return
		}
	}
}

func main() {
	flag.Parse()
	ctx := context.Background()
	h := &host{}
	h.load(ctx)
	_ = os.Remove(*socketPath)
	listener, err := net.Listen("unix", *socketPath)
	if err != nil {
		log.Fatal(err)
	}
	_ = os.Chmod(*socketPath, 0o666)
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			h.load(ctx)
		}
	}()
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go h.serve(conn)
	}
}
