package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/deployment"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/l4runtime"
)

type l4BridgeOutputPrecheckRuntime struct {
	l4BridgeRemovalRuntime
	output string
}

func (runtime *l4BridgeOutputPrecheckRuntime) Precheck(context.Context, string) error {
	return errors.New(runtime.output)
}

// 部署通道四层预检失败上报主控的摘要曾是固定的
// "release precheck failed"，主控看不到原因；应与节点本地 l4_precheck_failed 同文（单行、≤512 字节）。
func TestL4DeploymentPrecheckFailureReportsTheRealCause(t *testing.T) {
	root := t.TempDir()
	t.Cleanup(func() {
		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err == nil && info.IsDir() {
				_ = os.Chmod(path, 0o700)
			}
			return nil
		})
	})
	runtime := &l4BridgeOutputPrecheckRuntime{output: `OpenResty command failed: nginx: [emerg] getgrnam("nobody") failed` +
		"\nnginx: configuration file test failed\n" + strings.Repeat("x", 2000)}
	l4, err := l4runtime.NewDeploymentManager(filepath.Join(root, "l4"), runtime)
	if err != nil {
		t.Fatal(err)
	}
	dns, err := l4runtime.NewDNSCoordinator(filepath.Join(root, "dns"), daemonL4DNSResolver{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	delegate, err := deployment.NewOpenResty("/usr/local/openresty/bin/openresty", "nginx.conf",
		func(context.Context, string, ...string) error { return nil }, func(context.Context, string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	bridge := &l4DeploymentBridge{delegate: delegate, manager: l4, dns: dns}
	manager, err := deployment.NewManager(filepath.Join(root, "http"), bridge, bridge)
	if err != nil {
		t.Fatal(err)
	}
	result, err := manager.Process(context.Background(), l4BridgeDeploymentCommand(t, "initial", "", true))
	if err != nil || result.State != deployment.StateFailed || result.ErrorCode != "PRECHECK_FAILED" {
		t.Fatalf("Process() = (%+v, %v)", result, err)
	}
	if !strings.HasPrefix(result.Summary, `L4 configuration precheck failed: OpenResty command failed: nginx: [emerg] getgrnam("nobody") failed`) ||
		strings.ContainsAny(result.Summary, "\r\n") || len(result.Summary) > 512 {
		t.Fatalf("summary = %q (len %d)", result.Summary, len(result.Summary))
	}
}
