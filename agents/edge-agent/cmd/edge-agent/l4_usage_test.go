package main

import (
	"errors"
	"fmt"
	"testing"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/l4usage"
)

// NR-M01/NR-M02：账本满、缺发布身份、其他检查点失败各自有节点错误码，节点
// 状态显示降级；一轮成功即清除。
func TestL4UsageErrorCodes(t *testing.T) {
	for err, want := range map[error]string{
		nil: "",
		fmt.Errorf("%w: 3 live sessions", l4usage.ErrLedgerFull):      "L4_USAGE_LEDGER_FULL",
		fmt.Errorf("%w: 1 live sessions", l4usage.ErrIdentityMissing): "L4_USAGE_ATTRIBUTION_PENDING",
		errors.New("spool L4 usage checkpoints: full"):                "L4_USAGE_CHECKPOINT_FAILED",
	} {
		if got := l4UsageErrorCode(err); got != want {
			t.Fatalf("%v: %q, want %q", err, got, want)
		}
	}
}
