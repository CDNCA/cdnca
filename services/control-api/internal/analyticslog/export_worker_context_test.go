package analyticslog

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

// TF-C01：后台任务上下文必须带上持久化的请求编号，非法/缺失时用导出编号兜底。
func TestExportJobContextCarriesPersistedRequestID(t *testing.T) {
	exportID := uuid.MustParse("018f0000-0000-7000-8000-000000000001")
	for _, test := range []struct {
		name, requestID, want string
	}{
		{name: "persisted", requestID: "req-1", want: "req-1"},
		{name: "empty", requestID: "", want: exportID.String()},
		{name: "invalid", requestID: "bad id\n", want: exportID.String()},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := exportJobContext(context.Background(), test.requestID, "trace-1", exportID)
			if got := RequestIDFromContext(ctx); got != test.want {
				t.Fatalf("request id = %q, want %q", got, test.want)
			}
			if got := traceIDFromContext(ctx); got != "trace-1" {
				t.Fatalf("trace id = %q", got)
			}
		})
	}
}
