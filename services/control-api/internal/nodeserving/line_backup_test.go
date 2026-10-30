package nodeserving

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

// fix-backupnotify：线路组某地址族主 IP 全被摘除、开始发布备用 IP 时发一次“启用备用”，
// 主 IP 恢复、备用不再发布时发一次“恢复主 IP”；同一观察重复出现不重复发。
func TestDecideLineBackupTransitions(t *testing.T) {
	none := LineBackupState{}
	normal := LineBackupState{Found: true, State: LineBackupNormal, Sequence: 2}
	active := LineBackupState{Found: true, State: LineBackupActive, Sequence: 3}
	backups := []string{"192.0.2.20"}
	for _, test := range []struct {
		name     string
		current  LineBackupState
		observed LineBackupObservation
		write    bool
		state    string
		sequence int64
		event    string
	}{
		{"主 IP 全挂首次启用备用", none, LineBackupObservation{Present: true, Backups: backups}, true, LineBackupActive, 1, EventTypeLineBackupActivated},
		{"恢复后再次启用备用", normal, LineBackupObservation{Present: true, Backups: backups}, true, LineBackupActive, 3, EventTypeLineBackupActivated},
		{"主 IP 恢复", active, LineBackupObservation{Present: true}, true, LineBackupNormal, 4, EventTypeLineBackupRestored},
		{"备用持续启用不重复发", active, LineBackupObservation{Present: true, Backups: []string{"192.0.2.21"}}, false, "", 0, ""},
		{"从未启用且正常不写行", none, LineBackupObservation{Present: true}, false, "", 0, ""},
		{"已正常不重复发恢复", normal, LineBackupObservation{Present: true}, false, "", 0, ""},
		{"地址族或线路组已不在当前版本：静默回正常", active, LineBackupObservation{}, true, LineBackupNormal, 4, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := DecideLineBackup(test.current, test.observed)
			if got.Write != test.write || got.State != test.state || got.Sequence != test.sequence || got.EventType != test.event {
				t.Fatalf("DecideLineBackup = %+v, want write=%v state=%q sequence=%d event=%q",
					got, test.write, test.state, test.sequence, test.event)
			}
		})
	}
}

// 抖动：主 IP 恢复后又被摘除，每次迁移序号都前进，通知各发一次；同一序号重放只认当前状态。
func TestLineBackupFlapUsesFreshSequences(t *testing.T) {
	state := LineBackupState{}
	var events []string
	for _, observed := range []LineBackupObservation{
		{Present: true, Backups: []string{"192.0.2.20"}}, {Present: true, Backups: []string{"192.0.2.20"}},
		{Present: true}, {Present: true},
		{Present: true, Backups: []string{"192.0.2.20"}},
	} {
		decision := DecideLineBackup(state, observed)
		if !decision.Write {
			continue
		}
		state = LineBackupState{Found: true, State: decision.State, Sequence: decision.Sequence}
		events = append(events, decision.EventType+"/"+strings.Repeat("x", int(decision.Sequence)))
	}
	want := []string{EventTypeLineBackupActivated + "/x", EventTypeLineBackupRestored + "/xx", EventTypeLineBackupActivated + "/xxx"}
	if strings.Join(events, ",") != strings.Join(want, ",") {
		t.Fatalf("events = %v, want %v", events, want)
	}
}

func TestLineBackupSourceEventIDRoundTrip(t *testing.T) {
	groupID := uuid.New()
	id := lineBackupSourceEventID(EventTypeLineBackupRestored, groupID, 6, 9)
	if id != "node-line-backup/restored/"+groupID.String()+"/6/9" {
		t.Fatalf("source event id = %q", id)
	}
	gotGroup, family, sequence, ok := parseLineBackupSourceEventID(id)
	if !ok || gotGroup != groupID || family != 6 || sequence != 9 {
		t.Fatalf("parse = %v %d %d %v", gotGroup, family, sequence, ok)
	}
	for _, bad := range []string{"node-availability/x/1", "node-line-backup/activated/" + groupID.String() + "/5/1",
		"node-line-backup/other/" + groupID.String() + "/4/1", "node-line-backup/activated/not-a-uuid/4/1"} {
		if _, _, _, ok := parseLineBackupSourceEventID(bad); ok {
			t.Fatalf("parsed %q", bad)
		}
	}
}

func TestLineBackupAddressText(t *testing.T) {
	if got := lineBackupAddressText(nil); got != "-" {
		t.Fatalf("empty = %q", got)
	}
	many := []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4", "192.0.2.5", "192.0.2.6"}
	if got := lineBackupAddressText(many); got != "192.0.2.1、192.0.2.2、192.0.2.3、192.0.2.4、192.0.2.5 等 6 个" {
		t.Fatalf("many = %q", got)
	}
	if lineBackupFamilyText(6) != "IPv6" || lineBackupFamilyText(4) != "IPv4" {
		t.Fatal("family text")
	}
}
