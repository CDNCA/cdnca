package mtlstunnel

// conn-perf 测量（CDNCA_CONN_PERF=1 才跑）：经带人工 RTT 的 TCP 代理走隧道，
// 记冷连接（TCP+外层 TLS+WS 升级+内层 mTLS）与复用连接的请求耗时，以及每条空闲隧道的内存/goroutine。

import (
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"
)

// latencyProxy forwards to target, delaying every chunk by half the RTT in each direction.
func latencyProxy(t *testing.T, target string, rtt time.Duration) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			client, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				server, err := net.Dial("tcp", target)
				if err != nil {
					_ = client.Close()
					return
				}
				go delayCopy(server, client, rtt/2)
				delayCopy(client, server, rtt/2)
			}()
		}
	}()
	return listener.Addr().String()
}

func delayCopy(dst, src net.Conn, delay time.Duration) {
	type chunk struct {
		at   time.Time
		data []byte
	}
	queue := make(chan chunk, 1024)
	go func() {
		defer dst.Close()
		for c := range queue {
			time.Sleep(time.Until(c.at))
			if _, err := dst.Write(c.data); err != nil {
				return
			}
		}
	}()
	buffer := make([]byte, 64<<10)
	for {
		n, err := src.Read(buffer)
		if n > 0 {
			queue <- chunk{at: time.Now().Add(delay), data: append([]byte(nil), buffer[:n]...)}
		}
		if err != nil {
			close(queue)
			return
		}
	}
}

func perfEnabled(t *testing.T) {
	if os.Getenv("CDNCA_CONN_PERF") != "1" {
		t.Skip("set CDNCA_CONN_PERF=1 to measure")
	}
}

func TestMeasureTunnelColdWarm(t *testing.T) {
	perfEnabled(t)
	const rtt = 40 * time.Millisecond
	f := newFixture(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	front := f.tunnelURL[len("https://"):]
	slow := "https://" + latencyProxy(t, front, rtt)
	client := f.httpClient(t, f.inner.issue(t, x509.ExtKeyUsageClientAuth, "", nil))
	tunnel, _ := NewClient("https://auth.cdnca.test:9448", slow, TargetPluginRuntime)
	tunnel.Roots = f.outerRoots
	client.Transport.(*http.Transport).DialContext = tunnel.DialContext
	get := func() time.Duration {
		start := time.Now()
		response, err := client.Get("https://auth.cdnca.test:9448/v1/x")
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		return time.Since(start)
	}
	cold := get()
	warm := get()
	t.Logf("RTT %v: cold %v (%.1f RTT), warm %v (%.1f RTT)", rtt, cold.Round(time.Millisecond),
		float64(cold)/float64(rtt), warm.Round(time.Millisecond), float64(warm)/float64(rtt))
}

func TestMeasureIdleTunnelFootprint(t *testing.T) {
	perfEnabled(t)
	const tunnels = 50
	f := newFixture(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	certificate := f.inner.issue(t, x509.ExtKeyUsageClientAuth, "", nil)
	f.server.TotalLimit = 4 * tunnels
	clients := make([]*http.Client, tunnels)
	for i := range clients {
		clients[i] = f.httpClient(t, certificate)
	}
	measure := func() (uint64, int) {
		runtime.GC()
		var stats runtime.MemStats
		runtime.ReadMemStats(&stats)
		return stats.HeapInuse, runtime.NumGoroutine()
	}
	heapBefore, goroutinesBefore := measure()
	var wg sync.WaitGroup
	for _, client := range clients {
		wg.Add(1)
		go func() {
			defer wg.Done()
			response, err := client.Get("https://auth.cdnca.test:9448/v1/x")
			if err != nil {
				t.Error(err)
				return
			}
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
		}()
	}
	wg.Wait()
	time.Sleep(200 * time.Millisecond)
	heapAfter, goroutinesAfter := measure()
	t.Logf("%d idle tunnels (client+bridge+backend in one process): heap %+d KiB/tunnel, goroutines %+.1f/tunnel",
		tunnels, (int64(heapAfter)-int64(heapBefore))/tunnels/1024, float64(goroutinesAfter-goroutinesBefore)/tunnels)
}
