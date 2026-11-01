package gateway

import (
	"bytes"
	"context"
	"log"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type logTestServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (stream logTestServerStream) Context() context.Context { return stream.ctx }

func captureStreamRPCLog(t *testing.T, ctx context.Context) string {
	t.Helper()
	var out bytes.Buffer
	previous, flags := log.Writer(), log.Flags()
	log.SetOutput(&out)
	t.Cleanup(func() { log.SetOutput(previous); log.SetFlags(flags) })
	info := &grpc.StreamServerInfo{FullMethod: "/agent.v1.AgentGatewayService/Connect"}
	handler := func(any, grpc.ServerStream) error {
		return status.Error(codes.Unavailable, "could not subscribe to auto defense snapshots")
	}
	if err := logStreamRPCError(nil, logTestServerStream{ctx: ctx}, info, handler); status.Code(err) != codes.Unavailable {
		t.Fatalf("the handler error must be returned unchanged: %v", err)
	}
	return out.String()
}

// 73（10-30）：Agent 学到能力后立刻断开重连，在途的 consumer 绑定被取消，
// 不能记成 "stream failed"。
func TestLogStreamRPCErrorPeerClosedIsNotAFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	line := captureStreamRPCLog(t, ctx)
	if !strings.Contains(line, "stream closed by peer") || strings.Contains(line, "stream failed") {
		t.Fatalf("a stream the peer closed must not be logged as failed: %q", line)
	}
}

func TestLogStreamRPCErrorLiveStreamIsAFailure(t *testing.T) {
	line := captureStreamRPCLog(t, context.Background())
	if !strings.Contains(line, "stream failed") {
		t.Fatalf("an error on a live stream must be logged as failed: %q", line)
	}
}
