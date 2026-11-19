package eventspool

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

// A quarantined line carries why it was refused (a
// valid JSON line refused by attribution was only reported as
// TAIL_INVALID_JSON).
func TestTailerQuarantineIssueReason(t *testing.T) {
	source, spool, config := newTailHarness(t)
	valid := sourceAccess(tenantOne)
	appendSource(t, source, valid, true)
	file, err := os.OpenFile(source, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = file.Write([]byte("{\"password\":\"source-secret\"\n"))
	_ = file.Close()
	config.Identity = TrustedIdentity{EnrollmentNodeID: nodeOne}
	config.Resolve = func(line []byte) (ResolvedLine, error) {
		if strings.Contains(string(line), "password") {
			return ResolvedLine{}, errors.New("resolver: line is not a JSON object")
		}
		return ResolvedLine{}, errors.New("resolver: site s does not serve 192.0.2.1:80")
	}
	tailer, err := NewTailer(config)
	if err != nil {
		t.Fatal(err)
	}
	result, err := tailer.TailOnce(context.Background(), spool)
	if err != nil || len(result.Issues) != 2 {
		t.Fatalf("tail = %#v, %v", result, err)
	}
	for index, want := range []string{"site s does not serve 192.0.2.1:80", "line is not valid JSON"} {
		issue := result.Issues[index]
		if issue.Code != "TAIL_INVALID_JSON" || !strings.Contains(issue.Reason, want) || strings.Contains(issue.Reason, "source-secret") {
			t.Fatalf("issue %d = %#v, want reason %q", index, issue, want)
		}
	}
}
