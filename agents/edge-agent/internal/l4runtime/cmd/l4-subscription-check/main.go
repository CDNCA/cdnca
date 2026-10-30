// Command l4-subscription-check is the ADR 0012 ML-07 layer 4 acceptance
// against a real OpenResty (tests/l4-subscription-limits/run.sh starts it in
// the node runtime image, one --rm --network none container): the agent's
// own v2 compiler (CompileV2) renders streams whose subscription_limits
// carry concurrent sessions, new sessions per second, bandwidth and stop,
// for each of throttle / pause (same node limits; pause is DNS only) and
// stop, and the check drives TCP clients at them:
//   - conn: 3 sessions open, the 4th is closed without reaching the origin,
//     closing one frees a slot, two streams of one subscription share the
//     count, another subscription with the same limit does not;
//   - new: 5 of 12 sessions opened within one second pass, the next second
//     passes again;
//   - bandwidth: one session alone gets the rate, two share it, and two
//     long sessions together stay within the subscription's rate after the
//     burst (L4F-E02: a per-session share fixed at entry let them take 1.5x);
//   - stop: every session is closed.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/l4runtime"
)

var (
	luaRoot   = flag.String("lua", "/opt/cdnca/l4geo", "L4 Lua tree")
	stateRoot = flag.String("state", "/tmp/l4sub", "state directory")
)

const (
	tenant     = "0e4a0000-0000-4000-8000-000000000001"
	originPort = 19500
	payload    = 200_000 // bytes the origin sends per session
	bandwidth  = 800_000 // bit/s = 100 000 B/s
)

var failures int

func check(name string, ok bool, format string, args ...any) {
	state := "PASS"
	if !ok {
		state, failures = "FAIL", failures+1
	}
	fmt.Printf("%s %s %s\n", state, name, fmt.Sprintf(format, args...))
}

type stream struct {
	name, id, sub string
	port          int
	limits        l4runtime.SubscriptionLimitsV2
}

func streams() []stream {
	var result []stream
	index := 0
	add := func(name, sub string, limits l4runtime.SubscriptionLimitsV2) {
		index++
		limits.SubscriptionID = sub
		result = append(result, stream{name: name, id: fmt.Sprintf("0e4a0000-0000-4000-8000-0000000001%02d", index),
			sub: sub, port: 18500 + index, limits: limits})
	}
	for subIndex, action := range []string{"throttle", "pause", "stop"} {
		base := 10 * (subIndex + 1)
		stopped := action == "stop"
		add("conn-"+action, fmt.Sprintf("0e4a0000-0000-4000-8000-0000000003%02d", base+1), l4runtime.SubscriptionLimitsV2{MaxConnections: 3, Stopped: stopped})
		add("new-"+action, fmt.Sprintf("0e4a0000-0000-4000-8000-0000000003%02d", base+2), l4runtime.SubscriptionLimitsV2{NewPerSecond: 5, Stopped: stopped})
		add("bw-"+action, fmt.Sprintf("0e4a0000-0000-4000-8000-0000000003%02d", base+3), l4runtime.SubscriptionLimitsV2{BandwidthBPS: bandwidth, Stopped: stopped})
	}
	// conn-throttle's subscription on a second stream, and another
	// subscription with the same limit (isolation)
	add("conn-throttle-2", result[0].sub, l4runtime.SubscriptionLimitsV2{MaxConnections: 3})
	add("conn-other", "0e4a0000-0000-4000-8000-000000000399", l4runtime.SubscriptionLimitsV2{MaxConnections: 3})
	return result
}

func spec(value stream) l4runtime.StreamRuntimeSpecV2 {
	limits := value.limits
	return l4runtime.StreamRuntimeSpecV2{
		SchemaVersion: l4runtime.SchemaVersionV2, TenantID: tenant, StreamID: value.id, Revision: 1,
		Listener: l4runtime.ListenerSocketV2{Protocol: l4runtime.ProtocolTCP, Address: "0.0.0.0", Port: value.port},
		Endpoint: l4runtime.EndpointV2{Address: "127.0.0.1", Port: originPort},
		Geo: l4runtime.GeoPolicyV2{TenantID: tenant, StreamID: value.id, Revision: 1,
			UnknownRegionAction: l4runtime.GeoActionAllow, TrustedProxyCIDRs: []string{}, BlockedRegions: []string{}, RegionCIDRs: []l4runtime.RegionCIDRsV2{}},
		ConnectTimeoutMS: 1000, ResponseTimeoutMS: 30000, MaxConnectionsPerClient: 100, DrainTimeoutMS: 30000,
		SubscriptionLimits: &limits,
	}
}

// origin: every session gets "origin\n" at once, then payload bytes after
// the client sends "big\n"; otherwise it stays open until the client closes.
func origin() {
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", originPort))
	if err != nil {
		panic(err)
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = conn.Write([]byte("origin\n"))
				line := make([]byte, 4)
				if _, err := io.ReadFull(conn, line); err == nil && string(line) == "big\n" {
					_, _ = conn.Write(bytes.Repeat([]byte("x"), payload))
					return
				} else if err == nil && string(line) == "inf\n" {
					chunk := bytes.Repeat([]byte("x"), 16384)
					for {
						if _, err := conn.Write(chunk); err != nil {
							return
						}
					}
				}
				_, _ = io.Copy(io.Discard, conn)
			}()
		}
	}()
}

// session opens a session; ok = the origin's greeting arrived (the node
// let it through), else the node closed it.
func session(port int) (net.Conn, bool) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		return nil, false
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	greeting := make([]byte, 7)
	if _, err := io.ReadFull(conn, greeting); err != nil || string(greeting) != "origin\n" {
		conn.Close()
		return nil, false
	}
	_ = conn.SetReadDeadline(time.Time{})
	return conn, true
}

func download(port int) (time.Duration, int) {
	conn, ok := session(port)
	if !ok {
		return 0, 0
	}
	defer conn.Close()
	started := time.Now()
	_, _ = conn.Write([]byte("big\n"))
	_ = conn.SetReadDeadline(time.Now().Add(20 * time.Second))
	received, _ := io.Copy(io.Discard, conn)
	return time.Since(started), int(received)
}

// steadyRate keeps sessions endless downloads of one stream for warmup, then
// counts each session's bytes over window: the bytes per second of each.
func steadyRate(port, sessions int, warmup, window time.Duration) []float64 {
	counts := make([]int64, sessions)
	var mu sync.Mutex
	counting := false
	var wait sync.WaitGroup
	deadline := time.Now().Add(warmup + window)
	for index := range sessions {
		conn, ok := session(port)
		if !ok {
			return nil
		}
		_, _ = conn.Write([]byte("inf\n"))
		wait.Add(1)
		go func() {
			defer wait.Done()
			defer conn.Close()
			_ = conn.SetReadDeadline(deadline)
			buffer := make([]byte, 16384)
			for {
				n, err := conn.Read(buffer)
				mu.Lock()
				if counting {
					counts[index] += int64(n)
				}
				mu.Unlock()
				if err != nil {
					return
				}
			}
		}()
	}
	time.Sleep(warmup)
	mu.Lock()
	counting = true
	mu.Unlock()
	wait.Wait()
	rates := make([]float64, sessions)
	for index, count := range counts {
		rates[index] = float64(count) / window.Seconds()
	}
	return rates
}

func byName(all []stream, name string) stream {
	for _, value := range all {
		if value.name == name {
			return value
		}
	}
	panic(name)
}

func openresty(args ...string) error {
	command := exec.Command("openresty", append([]string{"-p", *stateRoot + "/", "-c", "nginx.conf"}, args...)...)
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("openresty %v: %v: %s", args, err, output)
	}
	return nil
}

func start(all []stream) error {
	specs := make([]l4runtime.StreamRuntimeSpecV2, len(all))
	addresses := map[string][]netip.Addr{}
	for index, value := range all {
		specs[index] = spec(value)
		addresses[value.id] = []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	}
	config, err := l4runtime.AggregateStreamRuntimeSpecsV2("ml07-l4", 1, specs)
	if err != nil {
		return err
	}
	compiled, err := l4runtime.CompileV2(config, addresses)
	if err != nil {
		return err
	}
	// The agent's stream configuration in a minimal main context; telemetry
	// paths moved under the state directory, the Lua tree from -lua.
	conf := string(compiled.NginxConfig)
	conf = strings.Replace(conf, "error_log stderr notice;", "error_log logs/error.log notice;\npid logs/nginx.pid;", 1)
	conf = strings.ReplaceAll(conf, "'/opt/cdnca/l4geo/?.lua;/opt/cdnca/?.lua;;'", "'"+*luaRoot+"/?.lua;;'")
	conf = strings.ReplaceAll(conf, "/var/lib/cdnca-edge/shared/", *stateRoot+"/shared/")
	_ = os.RemoveAll(*stateRoot)
	for _, dir := range []string{"logs", "shared"} {
		if err := os.MkdirAll(filepath.Join(*stateRoot, dir), 0o777); err != nil {
			return err
		}
	}
	// nginx opens the session logs; their directories must exist
	for _, line := range strings.Split(conf, "\n") {
		if field := strings.Fields(line); len(field) == 3 && field[0] == "access_log" {
			if err := os.MkdirAll(filepath.Dir(strings.Trim(field[1], `"`)), 0o777); err != nil {
				return err
			}
		}
	}
	if err := os.WriteFile(filepath.Join(*stateRoot, "nginx.conf"), []byte(conf), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*stateRoot, "config.json"), compiled.GeoJSON, 0o644); err != nil {
		return err
	}
	_ = filepath.Walk(*stateRoot, func(path string, info os.FileInfo, err error) error {
		if err == nil {
			_ = os.Chmod(path, info.Mode()|0o755)
		}
		return nil
	})
	return openresty()
}

func main() {
	flag.Parse()
	all := streams()
	origin()
	if err := start(all); err != nil {
		check("start", false, "%v", err)
		fmt.Printf("RESULT failures=%d\n", failures)
		os.Exit(1)
	}
	time.Sleep(500 * time.Millisecond)
	for _, name := range []string{"conn-stop", "new-stop", "bw-stop"} {
		value := byName(all, name)
		passed := 0
		for range 3 {
			if conn, ok := session(value.port); ok {
				passed++
				conn.Close()
			}
		}
		check("l4-"+name, passed == 0, "%d of 3 sessions reached the origin (stopped)", passed)
	}
	for _, action := range []string{"throttle", "pause"} {
		value := byName(all, "conn-"+action)
		var open []net.Conn
		for range 3 {
			if conn, ok := session(value.port); ok {
				open = append(open, conn)
			}
		}
		_, fourth := session(value.port)
		check("l4-conn-"+action+"-limit", len(open) == 3 && !fourth, "%d of 3 open, a 4th passed: %t", len(open), fourth)
		if action == "throttle" {
			_, shared := session(byName(all, "conn-throttle-2").port)
			other, isolated := session(byName(all, "conn-other").port)
			if other != nil {
				other.Close()
			}
			check("l4-conn-isolation", !shared && isolated, "same subscription other stream passed: %t, another subscription: %t", shared, isolated)
		}
		open[0].Close()
		time.Sleep(300 * time.Millisecond)
		again, freed := session(value.port)
		check("l4-conn-"+action+"-release", freed, "a closed session frees its slot")
		if again != nil {
			again.Close()
		}
		for _, conn := range open[1:] {
			conn.Close()
		}

		value = byName(all, "new-"+action)
		now := time.Now()
		time.Sleep(now.Truncate(time.Second).Add(time.Second + 50*time.Millisecond).Sub(now))
		var wait sync.WaitGroup
		var mu sync.Mutex
		passed := 0
		for range 12 {
			wait.Add(1)
			go func() {
				defer wait.Done()
				if conn, ok := session(value.port); ok {
					mu.Lock()
					passed++
					mu.Unlock()
					conn.Close()
				}
			}()
		}
		wait.Wait()
		time.Sleep(1100 * time.Millisecond)
		next, ok := session(value.port)
		if next != nil {
			next.Close()
		}
		check("l4-new-"+action, passed == 5 && ok, "12 sessions in one second (limit 5): %d passed; next second %t", passed, ok)

		value = byName(all, "bw-"+action)
		alone, size := download(value.port)
		// 200 000 bytes at 100 000 B/s: about 2 s (nginx lets the first
		// second's worth through at once)
		check("l4-bw-"+action+"-single", size == payload && alone > 900*time.Millisecond && alone < 4*time.Second,
			"%d bytes in %s", size, alone.Round(time.Millisecond))
		if action == "throttle" {
			durations := make([]time.Duration, 2)
			for index := range durations {
				wait.Add(1)
				go func() { defer wait.Done(); durations[index], _ = download(value.port) }()
				time.Sleep(50 * time.Millisecond)
			}
			wait.Wait()
			// the second session starts at half the rate
			check("l4-bw-shared", durations[1] > alone+500*time.Millisecond, "alone %s, first %s, second %s",
				alone.Round(time.Millisecond), durations[0].Round(time.Millisecond), durations[1].Round(time.Millisecond))
			// L4F-E02: after a 3 s warmup (the 1 s burst spent), two and
			// then three endless sessions together get the subscription's
			// rate, not more, and each a fair part of it
			for _, sessions := range []int{2, 3} {
				rates := steadyRate(value.port, sessions, 3*time.Second, 8*time.Second)
				total, fair := 0.0, len(rates) == sessions
				for _, rate := range rates {
					total += rate
					fair = fair && rate > bandwidth/8/float64(sessions)/3
				}
				check(fmt.Sprintf("l4-bw-total-%d", sessions), fair && total <= bandwidth/8*1.1 && total >= bandwidth/8*0.7,
					"%d sessions: %.0f B/s together (limit %d B/s), each %v", sessions, total, bandwidth/8, rates)
			}
		}
	}
	data, _ := os.ReadFile(filepath.Join(*stateRoot, "logs", "error.log"))
	var bad []string
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, "[alert]") || strings.Contains(line, "[crit]") || strings.Contains(line, "[emerg]") ||
			strings.Contains(line, "[error]") {
			bad = append(bad, line)
		}
	}
	check("l4-error-log", len(bad) == 0, "%d lines %v", len(bad), bad[:min(3, len(bad))])
	_ = openresty("-s", "stop")
	fmt.Printf("RESULT failures=%d\n", failures)
	if failures > 0 {
		os.Exit(1)
	}
}
