package dnscheck

import (
	"testing"
	"time"
)

func TestMergeProviderReportRecoversRetryableFailure(t *testing.T) {
	current := OperationResult{
		ClientRequestID:   "dns-request",
		ProviderRequestID: "provider-request",
		ProviderRevision:  7,
		Status:            OperationTransientFailed,
		RetryAfter:        45 * time.Second,
		ErrorClass:        ProviderErrorTransient,
		ErrorCode:         "provider_rate_limited",
		ReportSequence:    4,
	}
	success := ProviderReport{
		ClientRequestID:   current.ClientRequestID,
		ProviderRequestID: current.ProviderRequestID,
		ProviderRecordID:  "record-1",
		ProviderRevision:  8,
		Status:            OperationSucceeded,
		Sequence:          5,
	}

	got, changed := MergeProviderReport(current, success)
	if !changed || got.Status != OperationSucceeded || got.RetryAfter != 0 ||
		got.ErrorClass != ProviderErrorNone || got.ProviderRecordID != success.ProviderRecordID ||
		got.ProviderRevision != success.ProviderRevision || got.ReportSequence != success.Sequence {
		t.Fatalf("MergeProviderReport() = (%#v, %t), want recovered success", got, changed)
	}

	t.Run("rejected recovery preserves the durable result", func(t *testing.T) {
		boundRecord := current
		boundRecord.ProviderRecordID = "record-bound"
		for _, test := range []struct {
			name    string
			current OperationResult
			report  ProviderReport
		}{
			{name: "exact replay", current: current, report: func() ProviderReport {
				report := success
				report.Sequence = current.ReportSequence
				return report
			}()},
			{name: "stale sequence", current: current, report: func() ProviderReport {
				report := success
				report.Sequence = current.ReportSequence - 1
				return report
			}()},
			{name: "request identity drift", current: current, report: func() ProviderReport {
				report := success
				report.ProviderRequestID = "other-provider-request"
				return report
			}()},
			{name: "record identity drift", current: boundRecord, report: func() ProviderReport {
				report := success
				report.ProviderRecordID = "other-record"
				return report
			}()},
			{name: "provider revision regression", current: current, report: func() ProviderReport {
				report := success
				report.ProviderRevision = current.ProviderRevision - 1
				return report
			}()},
		} {
			t.Run(test.name, func(t *testing.T) {
				got, changed := MergeProviderReport(test.current, test.report)
				if changed || got != test.current {
					t.Fatalf("MergeProviderReport() = (%#v, %t), want unchanged %#v", got, changed, test.current)
				}
			})
		}
	})

	t.Run("non-retryable terminal states remain immutable", func(t *testing.T) {
		for _, status := range []OperationStatus{
			OperationPermanentFailed,
			OperationRevisionConflict,
			OperationCancelled,
		} {
			t.Run(string(status), func(t *testing.T) {
				terminal := current
				terminal.Status = status
				got, changed := MergeProviderReport(terminal, success)
				if changed || got != terminal {
					t.Fatalf("MergeProviderReport() = (%#v, %t), want unchanged %#v", got, changed, terminal)
				}
			})
		}
	})
}
