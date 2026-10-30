package nodednspupprobe

import (
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnspupprobe"
)

func results(statuses ...string) []dnspupprobe.Result {
	isps := []string{"中国电信", "中国联通", "中国移动"}
	out := make([]dnspupprobe.Result, len(statuses))
	for index, status := range statuses {
		out[index] = dnspupprobe.Result{NodeID: string(rune('a' + index)), Region: "广东", ISP: isps[index%3], Status: status}
	}
	return out
}

// 失败检测点 >50% 才算本轮失败（默认阈值 50）；无应答检测点不计票。
func TestRoundCountsFailedCheckpointsAboveThreshold(t *testing.T) {
	settings := DefaultSettings()
	for _, test := range []struct {
		name          string
		statuses      []string
		failed, total int
		roundFailed   bool
	}{
		{"half failed is not more than 50%", []string{"ok", "timeout", "ok", "bad"}, 2, 4, false},
		{"majority failed", []string{"timeout", "bad", "ok"}, 2, 3, true},
		{"unavailable are no votes", []string{"unavailable", "unavailable", "timeout"}, 1, 1, true},
		{"no votes", []string{"unavailable"}, 0, 0, false},
	} {
		round := Round(results(test.statuses...), settings)
		if round.Failed != test.failed || round.Total != test.total || round.RoundFailed() != test.roundFailed {
			t.Errorf("%s: round=%+v failed=%v", test.name, round, round.RoundFailed())
		}
	}
	settings.FailurePercent = 49
	if round := Round(results("ok", "timeout", "bad", "ok"), settings); !round.RoundFailed() {
		t.Error("50% failed with a 49% threshold must fail")
	}
}

// 未勾选的运营商组的检测点不计入判定。
func TestRoundKeepsOnlySelectedGroups(t *testing.T) {
	settings := DefaultSettings()
	settings.Groups = []string{GroupTelecom}
	round := Round(results("timeout", "ok", "ok", "timeout"), settings) // 电信 a、d 失败；联通 b、移动 c 不计
	if round.Failed != 2 || round.Total != 2 || !round.RoundFailed() {
		t.Fatalf("telecom only round=%+v", round)
	}
	if len(round.Checkpoints) != 2 || round.Checkpoints[0].Group != GroupTelecom {
		t.Fatalf("checkpoints=%+v", round.Checkpoints)
	}
}

// 连续 3 次失败才判 failing；1 次成功即恢复（默认）。
func TestStateNeedsConsecutiveFailures(t *testing.T) {
	settings := DefaultSettings()
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	var state State
	for index := range 2 {
		state = state.Next(true, true, settings, now)
		if state.Failing {
			t.Fatalf("failing after %d rounds", index+1)
		}
	}
	state = state.Next(true, true, settings, now)
	if !state.Failing || state.ConsecutiveFailed != 3 {
		t.Fatalf("state after 3 failed rounds=%+v", state)
	}
	// 无票的一轮不改变判定。
	if next := state.Next(false, false, settings, now); next.Failing != state.Failing || next.ConsecutiveFailed != 3 {
		t.Fatalf("undecided round changed state=%+v", next)
	}
	state = state.Next(true, false, settings, now)
	if state.Failing || state.ConsecutiveFailed != 0 {
		t.Fatalf("state after a good round=%+v", state)
	}
}

// 余额：低于预警线降频（间隔 ×3），用完停用；频率关闭时不拨测。
func TestBudgetIntervalAndState(t *testing.T) {
	settings := DefaultSettings()
	if got := BudgetFor(0, 0, settings.LowBalance); got != BudgetNormal {
		t.Fatalf("no monthly limit (unlimited) = %s", got)
	}
	if got := BudgetFor(10_000, 9_500, 1000); got != BudgetLow {
		t.Fatalf("500 left under 1000 = %s", got)
	}
	if got := BudgetFor(10_000, 10_000, 1000); got != BudgetExhausted {
		t.Fatalf("none left = %s", got)
	}
	if got := EffectiveInterval(settings, BudgetNormal); got != 5*time.Minute {
		t.Fatalf("normal interval %s", got)
	}
	if got := EffectiveInterval(settings, BudgetLow); got != 15*time.Minute {
		t.Fatalf("low interval %s", got)
	}
	if got := EffectiveInterval(settings, BudgetExhausted); got != 0 {
		t.Fatalf("exhausted interval %s", got)
	}
	settings.IntervalSeconds = 0
	if got := EffectiveInterval(settings, BudgetNormal); got != 0 {
		t.Fatalf("off interval %s", got)
	}
}

// 估算：dnspup 按请求计量，每个节点 IP 每轮 1 次，检测点数不影响扣量。
func TestEstimateCountsRequestsPerProbedAddress(t *testing.T) {
	settings := DefaultSettings() // 5 分钟 → 每天 288 次
	estimate := Estimate(settings, 10)
	if estimate.RoundsPerDay != 288 || estimate.RequestsPerDay != 2880 || estimate.RequestsPerMonth != 2880*30 ||
		estimate.CheckpointsPerRound != 9 {
		t.Fatalf("estimate=%+v", estimate)
	}
	settings.IntervalSeconds = 0
	if estimate := Estimate(settings, 10); estimate.RequestsPerDay != 0 {
		t.Fatalf("off estimate=%+v", estimate)
	}
}

func TestValidateSettings(t *testing.T) {
	if err := Validate(DefaultSettings()); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []func(*Settings){
		func(value *Settings) { value.IntervalSeconds = 120 },
		func(value *Settings) { value.Groups = nil },
		func(value *Settings) { value.Groups = []string{"telecom", "telecom"} },
		func(value *Settings) { value.Groups = []string{"bgp"} },
		func(value *Settings) { value.PointsPerGroup = 21 },
		func(value *Settings) { value.FailurePercent = 100 },
		func(value *Settings) { value.FailureRounds = 0 },
		func(value *Settings) { value.RecoveryRounds = 11 },
		func(value *Settings) { value.LowBalance = -1 },
	} {
		value := DefaultSettings()
		bad(&value)
		if Validate(value) == nil {
			t.Errorf("accepted %+v", value)
		}
	}
}
