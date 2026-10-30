package nodeprobe

import (
	"slices"
	"testing"
)

func TestProberGroups(t *testing.T) {
	for _, item := range []struct {
		region, carrier string
		want            []string
	}{
		{"广东", "电信", []string{GroupDomestic, GroupTelecom}},
		{"cn", "CMCC", []string{GroupDomestic, GroupMobile}},
		{"", "联通", []string{GroupDomestic, GroupUnicom}},
		{"北京", "BGP", []string{GroupDomestic}},
		{"香港", "电信", []string{GroupOverseas}},
		{"", "", nil},
	} {
		if got := ProberGroups(item.region, item.carrier); !slices.Equal(got, item.want) {
			t.Errorf("ProberGroups(%q,%q)=%v, want %v", item.region, item.carrier, got, item.want)
		}
	}
}

// 主控探测失败且多数互拨节点失败，端点才判失败。
func TestDecideControllerAndPeerMajority(t *testing.T) {
	controller := func(ok bool) Vote { return Vote{Prober: ControllerProberID, Groups: []string{GroupDomestic}, OK: ok} }
	peer := func(id string, ok bool) Vote {
		return Vote{Prober: id, Groups: []string{GroupDomestic, GroupTelecom}, OK: ok}
	}
	for _, item := range []struct {
		name             string
		votes            []Vote
		decided, healthy bool
	}{
		{"主控失败+唯一对端失败（2 节点）", []Vote{controller(false), peer("a", false)}, true, false},
		{"主控失败+唯一对端成功", []Vote{controller(false), peer("a", true)}, true, true},
		{"主控成功+对端全失败", []Vote{controller(true), peer("a", false), peer("b", false)}, true, true},
		{"主控失败+对端半数失败", []Vote{controller(false), peer("a", false), peer("b", true)}, true, false},
		{"主控失败+对端少数失败", []Vote{controller(false), peer("a", false), peer("b", true), peer("c", true)}, true, true},
		{"无对端只看主控", []Vote{controller(false)}, true, false},
		{"主控未投票只看对端多数", []Vote{peer("a", false), peer("b", false), peer("c", true)}, true, false},
		{"地区未知对端也计票", []Vote{controller(false), {Prober: "x", OK: false}}, true, false},
		{"无票不判定", nil, false, false},
	} {
		verdict := Decide(item.votes, 50)
		if verdict.Decided != item.decided || (item.decided && verdict.Healthy != item.healthy) {
			t.Errorf("%s: %+v", item.name, verdict)
		}
	}
	// failure_ratio 只作用于对端：100 要求全部对端失败。
	if verdict := Decide([]Vote{controller(false), peer("a", false), peer("b", true)}, 100); !verdict.Healthy {
		t.Errorf("ratio 100 = %+v", verdict)
	}
}
