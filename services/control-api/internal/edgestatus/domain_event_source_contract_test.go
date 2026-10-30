package edgestatus

import (
	"os"
	"strings"
	"testing"
)

func TestProjectEnqueuesDeploymentSourceEventInsideProjectionTransaction(t *testing.T) {
	source, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(source)
	begin := strings.Index(body, "err = pgx.BeginFunc")
	if begin < 0 {
		t.Fatal("Project transaction callback not found")
	}
	end := strings.Index(body[begin:], "\n\t})")
	if end < 0 {
		t.Fatal("Project transaction callback end not found")
	}
	body = body[begin : begin+end]
	if !strings.Contains(body, "enqueueDeploymentStatusEvent(ctx, tx,") {
		t.Fatal("Project must enqueue the source event through the transaction")
	}
	helper, err := os.ReadFile("domain_event.go")
	if err != nil || !strings.Contains(string(helper), "domaineventsource.NewDeploymentStatusFact") ||
		!strings.Contains(string(helper), "domaineventsource.EnqueueTx(ctx, tx, fact)") {
		t.Fatal("deployment event helper must append through the caller transaction")
	}
	if strings.Index(body, "enqueueDeploymentStatusEvent(ctx, tx,") > strings.Index(body, "result.Outcome = OutcomeAdvanced") {
		t.Fatal("source event must be enqueued before reporting OutcomeAdvanced")
	}
	if !strings.Contains(body, "if stale") {
		t.Fatal("Project must keep stale events out of the source outbox")
	}
}
