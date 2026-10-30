package securityban

import (
	"fmt"
	"testing"
	"time"

	contract "github.com/cdnca/cdnca/libs/edgeconfig/securityban"
	"github.com/google/uuid"
)

func truncationBans(count int, until int64) []contract.Ban {
	bans := make([]contract.Ban, count)
	for index := range bans {
		bans[index] = contract.Ban{SiteID: fmt.Sprintf("%08x-0000-4000-8000-000000000000", index), Client: "198.51.100.1",
			Until: until, Source: "manual"}
	}
	return bans
}

// One entry over the limit cuts exactly one ban: the one ending soonest;
// releases are never cut, even when they alone leave room for few bans.
func TestTruncateKeepsReleasesAndLongestBans(t *testing.T) {
	releases := []contract.Release{{SiteID: "ffffffff-0000-4000-8000-000000000000", Client: "198.51.100.9", ReleasedAt: 1}}
	bans := truncationBans(contract.MaxEntries, 2000)
	bans[17].Until = 1000 // ends soonest
	kept, cut := Truncate(bans, releases, nil)
	if cut != 1 || len(kept)+len(releases) != contract.MaxEntries {
		t.Fatalf("cut %d, kept %d", cut, len(kept))
	}
	for _, ban := range kept {
		if ban.SiteID == bans[17].SiteID {
			t.Fatal("the ban ending soonest was kept")
		}
	}
	if kept, cut := Truncate(bans[:10], releases, nil); cut != 0 || len(kept) != 10 {
		t.Fatalf("under the limit: cut %d", cut)
	}
}

// Same remaining time: the most recently created ban is kept.
func TestTruncateTieBreaksOnNewestCreation(t *testing.T) {
	bans := truncationBans(contract.MaxEntries+1, 2000)
	created := map[[2]string]time.Time{}
	base := time.Unix(1_000_000, 0)
	for index, ban := range bans {
		created[[2]string{ban.SiteID, ban.Client}] = base.Add(time.Duration(index+10) * time.Second)
	}
	oldest := bans[contract.MaxEntries/2]
	created[[2]string{oldest.SiteID, oldest.Client}] = base
	kept, cut := Truncate(bans, nil, created)
	if cut != 1 || len(kept) != contract.MaxEntries {
		t.Fatalf("cut %d kept %d", cut, len(kept))
	}
	for _, ban := range kept {
		if ban.SiteID == oldest.SiteID {
			t.Fatal("the oldest ban was kept")
		}
	}
}

func TestListTruncatedSourceEventIDBucketsByNodeAndHour(t *testing.T) {
	node := uuid.New()
	at := time.Date(2026, 10, 23, 10, 5, 0, 0, time.UTC)
	if ListTruncatedSourceEventID(ListKindSecurityBan, node, at) != ListTruncatedSourceEventID(ListKindSecurityBan, node, at.Add(50*time.Minute)) {
		t.Fatal("same hour split")
	}
	if ListTruncatedSourceEventID(ListKindSecurityBan, node, at) == ListTruncatedSourceEventID(ListKindSiteDrop, node, at) ||
		ListTruncatedSourceEventID(ListKindSecurityBan, node, at) == ListTruncatedSourceEventID(ListKindSecurityBan, uuid.New(), at) {
		t.Fatal("kinds or nodes merged")
	}
}
