package nodeisolation

import "testing"

// audit_events.result only accepts success/denied/failure (migration 001);
// writing the raw sync outcome ("succeeded") made every isolation report fail.
func TestIsolationAuditResultUsesAuditResultValues(t *testing.T) {
	for outcome, want := range map[Outcome]string{
		OutcomeSucceeded: "success",
		OutcomeFailed:    "failure",
		OutcomeUnknown:   "failure",
	} {
		if got := isolationAuditResult(outcome); got != want {
			t.Errorf("isolationAuditResult(%s) = %s, want %s", outcome, got, want)
		}
	}
}

func TestIsolationAuditActionIsCatalogued(t *testing.T) {
	for code, want := range map[string]string{
		AuditSyncResultRecorded: "node.config_sync.result_recorded",
		AuditNodeIsolated:       "node.config_sync.isolated",
		AuditNodeRecovered:      "node.config_sync.recovered",
	} {
		if got := isolationAuditAction(code); got != want {
			t.Errorf("isolationAuditAction(%s) = %s, want %s", code, got, want)
		}
	}
}
