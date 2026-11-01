package enrollment

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

// 直连注册端口快速失败后改走管理端 443 的 ws 隧道；两者都失败时错误写清两种方式。
func TestRunFallsBackToTunnelWhenDirectDialFails(t *testing.T) {
	if DirectDialTimeout < 3*time.Second || DirectDialTimeout > 5*time.Second {
		t.Fatalf("DirectDialTimeout = %s, want 3-5s", DirectDialTimeout)
	}
	saved := DirectDialTimeout
	DirectDialTimeout = 50 * time.Millisecond
	t.Cleanup(func() { DirectDialTimeout = saved })
	fixture := newFixture(t)
	config := fixture.config(t)
	config.Address = "203.0.113.5:26080"
	config.FallbackTunnelAddress = "control.example:443"
	success := fixture.fakeDial(nil)
	var tried []string
	var directBudget time.Duration
	config.Dial = func(ctx context.Context, c Config) (RPC, io.Closer, error) {
		tried = append(tried, c.Address+"/"+c.Transport+"/"+c.TunnelHost+"/"+c.ServerName)
		if c.Transport != "ws" {
			deadline, _ := ctx.Deadline()
			directBudget = time.Until(deadline)
			<-ctx.Done()
			return nil, nil, errors.New("context deadline exceeded")
		}
		return success(ctx, c)
	}
	if _, err := Run(context.Background(), config, testToken); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if directBudget <= 0 || directBudget > DirectDialTimeout {
		t.Fatalf("direct dial budget = %s", directBudget)
	}
	want := "203.0.113.5:26080///gateway.test,control.example:443/ws//gateway.test"
	if strings.Join(tried, ",") != want {
		t.Fatalf("tried = %v, want %s", tried, want)
	}
}

func TestRunReportsDirectAndTunnelFailures(t *testing.T) {
	fixture := newFixture(t)
	config := fixture.config(t)
	config.Address = "203.0.113.5:26080"
	config.FallbackTunnelAddress = "control.example:443"
	config.Dial = func(_ context.Context, c Config) (RPC, io.Closer, error) {
		if c.Transport == "ws" {
			return nil, nil, errors.New("gateway tunnel upgrade 502 Bad Gateway: bad handshake")
		}
		return nil, nil, errors.New("connection refused")
	}
	_, err := Run(context.Background(), config, testToken)
	var connectErr *ConnectError
	if !errors.Is(err, ErrEnrollmentRejected) || !errors.As(err, &connectErr) {
		t.Fatalf("Run() error = %v", err)
	}
	if connectErr.DirectAddress != "203.0.113.5:26080" || connectErr.TunnelAddress != "control.example:443" ||
		!strings.Contains(connectErr.Direct.Error(), "connection refused") || !strings.Contains(connectErr.Tunnel.Error(), "502") {
		t.Fatalf("connect error = %#v", connectErr)
	}
	for _, want := range []string{"direct gRPC to 203.0.113.5:26080: connection refused", "websocket via control.example:443: gateway tunnel upgrade 502"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q lacks %q", err, want)
		}
	}
}
