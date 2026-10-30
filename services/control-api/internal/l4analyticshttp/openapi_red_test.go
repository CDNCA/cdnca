package l4analyticshttp

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestL4RealtimeOpenAPIExposesTenantAndAdminContracts(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "../../../../"))
	content, err := os.ReadFile(filepath.Join(root, "api/control-l4-realtime.openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(content)
	for _, want := range []string{
		"/v1/analytics/l4-realtime:", "/v1/admin/analytics/l4-realtime:",
		"operationId: getTenantL4Realtime", "operationId: getAdminL4Realtime",
		"source_watermark:", "finalized_through:", "sessions:", "bytes_up:", "bytes_down:", "errors:",
		"stream_id:", "listener_id:", "node_id:", "protocol:", "next_cursor:",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("L4 OpenAPI omitted %q", want)
		}
	}
}
