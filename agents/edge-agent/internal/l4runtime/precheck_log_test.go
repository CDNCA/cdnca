package l4runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

// node-logs 10-31：四层预检失败只上报主控，节点 journal 查不到。
// 预检失败要在本地写一条 WARN（失败项+命令输出摘要，限长），内容与上报的错误一致。
func TestManagerLogsPrecheckFailureLikeTheReport(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	defer slog.SetDefault(previous)

	output := `nginx: [emerg] getgrnam("nobody") failed in /var/lib/cdnca-edge/l4/stage/nginx.conf:1` +
		"\nnginx: configuration file test failed\n" + strings.Repeat("x", 2000)
	runtime := &listenerLifecycleRuntime{}
	manager, _ := testManager(t, runtime)
	if _, err := manager.Apply(context.Background(), validConfig("l4-v1")); err != nil {
		t.Fatal(err)
	}
	logs.Reset()
	runtime.precheckErr = errors.New("OpenResty command failed: " + output + ": exit status 1")
	_, reported := manager.Apply(context.Background(), validConfig("l4-v2"))
	if !errors.Is(reported, ErrPrecheck) {
		t.Fatalf("Apply() error = %v, want ErrPrecheck", reported)
	}

	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(logs.Bytes()), &entry); err != nil {
		t.Fatalf("want one structured log line, got %q: %v", logs.String(), err)
	}
	message, _ := entry["error"].(string)
	if entry["level"] != "WARN" || entry["event"] != "l4_precheck_failed" || entry["operation"] != "apply" ||
		entry["version_id"] != "l4-v2" {
		t.Fatalf("log entry = %v", entry)
	}
	if !strings.Contains(message, `getgrnam("nobody") failed`) || strings.ContainsAny(message, "\n\r") ||
		len(message) > precheckLogLimit {
		t.Fatalf("logged error = %q (len %d)", message, len(message))
	}
	// same text as the reported error (the gateway summary is ≤512 bytes, one line)
	if want := precheckLogSummary(reported.Error()); message != want ||
		!strings.HasPrefix(message, "L4 configuration precheck failed: OpenResty command failed: ") {
		t.Fatalf("logged %q, reported %q", message, want)
	}
}

func TestManagerLogsListenerPrecheckFailure(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	defer slog.SetDefault(previous)

	runtime := &listenerLifecycleRuntime{precheckErr: listenerFailure{id: "edit", reason: "LISTENER_PORT_CONFLICT"}}
	manager, _ := testManager(t, runtime)
	if _, err := manager.Apply(context.Background(), validConfig("l4-v1")); !errors.Is(err, ErrPrecheck) {
		t.Fatalf("Apply() error = %v", err)
	}
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(logs.Bytes()), &entry); err != nil {
		t.Fatalf("want one structured log line, got %q: %v", logs.String(), err)
	}
	if entry["listener_id"] != "edit" || entry["reason_code"] != "LISTENER_PORT_CONFLICT" {
		t.Fatalf("log entry = %v", entry)
	}
}
