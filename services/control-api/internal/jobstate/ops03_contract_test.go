package jobstate_test

import (
	"os"
	"strings"
	"testing"
)

func TestOPS03ProducerTransactionsUseUnifiedJobState(t *testing.T) {
	producer, err := os.ReadFile("producer.go")
	if err != nil {
		t.Fatalf("read producer adapter: %v", err)
	}
	for _, token := range []string{"func CreateTx(", "func StartTx(", "func ReportTx("} {
		if !strings.Contains(string(producer), token) {
			t.Fatalf("producer adapter missing %q", token)
		}
	}

	files := map[string][]string{
		"../cachecontrol/operation.go":       {"jobstate.CreateTx("},
		"../cachecontrol/lifecycle.go":       {"jobstate.StartTx(", "jobstate.ReportTx(", "jobstate.RetryTx(", "jobstate.CancelTx("},
		"../analyticslog/export_postgres.go": {"jobstate.CreateTx(", "jobstate.StartTx(", "jobstate.ReportTx("},
		"../edgepublish/service.go":          {"jobstate.CreateTx(", "jobstate.StartTx(", "jobstate.ReportTx("},
	}
	for name, tokens := range files {
		content, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		for _, token := range tokens {
			if !strings.Contains(string(content), token) {
				t.Errorf("%s missing atomic unified job call %q", name, token)
			}
		}
	}
}
