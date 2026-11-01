package gateway

// conn-perf 测量（CDNCA_CONN_PERF=1 才跑）：N 条节点 ws 隧道 gRPC 连接（内层 mTLS 已握手、无流）
// 建立后的堆内存与 goroutine 增量（客户端与网关在同一进程，两侧合计）。

import (
	"crypto/tls"
	"os"
	"runtime"
	"testing"
	"time"

	"google.golang.org/grpc"
)

func TestMeasureGatewayIdleTunnelFootprint(t *testing.T) {
	if os.Getenv("CDNCA_CONN_PERF") != "1" {
		t.Skip("set CDNCA_CONN_PERF=1 to measure")
	}
	const tunnels = 50
	g := startSharedTestServers(t)
	inner := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: "localhost", RootCAs: g.pki.rootPool, Certificates: []tls.Certificate{g.node.certificate}}
	measure := func() (uint64, int) {
		runtime.GC()
		var stats runtime.MemStats
		runtime.ReadMemStats(&stats)
		return stats.HeapInuse, runtime.NumGoroutine()
	}
	heapBefore, goroutinesBefore := measure()
	connections := make([]*grpc.ClientConn, 0, tunnels)
	for range tunnels {
		connection, _, err := g.tunnelConnection(t, g.agent, TunnelPath, g.node.token(testTunnelAudience, TunnelPath, time.Now(), randomNonce(t)), inner)
		if err != nil {
			t.Fatal(err)
		}
		connections = append(connections, connection)
	}
	time.Sleep(300 * time.Millisecond)
	heapAfter, goroutinesAfter := measure()
	t.Logf("%d idle node tunnels (node+gateway in one process): heap %+d KiB/tunnel, goroutines %+.1f/tunnel",
		tunnels, (int64(heapAfter)-int64(heapBefore))/tunnels/1024, float64(goroutinesAfter-goroutinesBefore)/tunnels)
	for _, connection := range connections {
		_ = connection.Close()
	}
}
