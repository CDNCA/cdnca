package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 439 (ML-17: stop complaint notices in the notification
// center) is a placeholder number: the loader needs consecutive versions, so
// it sits on this branch's head 429_market_notices + 1. Everything that
// changes with the renumbering is here.
const (
	migration439Version         = 439
	migration439ID              = "439_market_complaint_notices"
	migration439PreviousID      = "438_market_downstream_attacked"
	migration439PreviousUpSHA   = "ae1a20624da0170d149465598480aa93c393d936d14fd8bd162dbe664ee0263b"
	migration439PreviousDownSHA = "ebb5be2fb4091cd4f94170b7901d7624be88ba94ff9119ed1371aa3b31b3a007"
	migration439UpSHA           = "1165c0df8220c4b5e9c385bb2734f176ed8dbc7da4edfe8a8508482ded48e039"
	migration439DownSHA         = "1a20978565668bb12c43091033ef38faf40f7ba5db8149ae0e7a1eb1bce0dae3"
)

// marketComplaintKinds mirrors notice.KindComplaintResolved/Actioned.
var marketComplaintKinds = []string{"market.complaint.resolved", "market.complaint.actioned"}

func TestMarketComplaintNotices439Contract(t *testing.T) {
	up := []string{
		fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration439Version-1),
		fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration439Version-1),
		"migration_id='" + migration439PreviousID + "'", migration439PreviousUpSHA, migration439PreviousDownSHA,
		"ERRCODE='P4390'",
	}
	for _, kind := range marketComplaintKinds {
		up = append(up, "('"+kind+"', true", "('"+kind+".zh-cn', 1, 'sms'", "('"+kind+".zh-cn', 1, 'email'")
	}
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration439ID + ".up.sql", migration439UpSHA, up},
		{migration439ID + ".down.sql", migration439DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration439Version),
			"migration_id='" + migration439ID + "'", "ERRCODE='P4391'", "ERRCODE='P4392'",
		}},
	} {
		raw, err := FS.ReadFile(script.name)
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != script.sha {
			t.Fatalf("%s checksum drift: %s", script.name, got)
		}
		for _, required := range script.required {
			if !strings.Contains(string(raw), required) {
				t.Errorf("%s missing %q", script.name, required)
			}
		}
	}
}
