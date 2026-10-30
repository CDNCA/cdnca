package dynroute

import "testing"

func TestParseSubscriptionMinutes(t *testing.T) {
	got, err := ParseSubscriptionMinutes([]byte(`{"minutes":[{"schema":"cdnca.edge.subscription-minute/v1","minute":1800000000,` +
		`"subscription_id":"s1","max_requests":3,"max_connections":2,"max_new_cps":1,"max_qps":9,"bytes_out":100,"peak_bps":800}]}`))
	if err != nil || len(got) != 1 || got[0].SubscriptionID != "s1" || got[0].Minute.Unix() != 1800000000 || got[0].PeakBPS != 800 {
		t.Fatalf("%+v %v", got, err)
	}
	if got, err := ParseSubscriptionMinutes([]byte(`{"minutes":[]}`)); err != nil || len(got) != 0 {
		t.Fatal(got, err)
	}
	for _, raw := range []string{
		`{"minutes":[{"schema":"other","minute":1800000000,"subscription_id":"s1"}]}`,
		`{"minutes":[{"schema":"cdnca.edge.subscription-minute/v1","minute":1800000001,"subscription_id":"s1"}]}`,
		`{"minutes":[{"schema":"cdnca.edge.subscription-minute/v1","minute":1800000000,"subscription_id":"s1","bytes_out":-1}]}`,
		`[]`,
	} {
		if _, err := ParseSubscriptionMinutes([]byte(raw)); err == nil {
			t.Errorf("accepted %s", raw)
		}
	}
}
