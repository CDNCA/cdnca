package dnscheck

import (
	"testing"
	"time"
)

func TestMergeProviderReportRetryAfterContract(t *testing.T) {
	base := OperationResult{
		ClientRequestID:   "provider-request",
		ProviderRequestID: "provider-operation",
		Status:            OperationRunning,
		RetryAfter:        90 * time.Second,
		ReportSequence:    10,
	}

	t.Run("transient and timeout hints update durable wait with clamp", func(t *testing.T) {
		for _, test := range []struct {
			name       string
			class      ProviderErrorClass
			retryAfter time.Duration
			want       time.Duration
		}{
			{name: "transient", class: ProviderErrorTransient, retryAfter: 3 * time.Minute, want: 3 * time.Minute},
			{name: "timeout", class: ProviderErrorTimeout, retryAfter: 2 * time.Hour, want: maxProviderRetryAfter},
		} {
			t.Run(test.name, func(t *testing.T) {
				got, changed := MergeProviderReport(base, ProviderReport{
					ClientRequestID:   base.ClientRequestID,
					ProviderRequestID: base.ProviderRequestID,
					Status:            OperationTransientFailed,
					ErrorClass:        test.class,
					ErrorCode:         "provider_recovery_pending",
					RetryAfter:        test.retryAfter,
					Sequence:          base.ReportSequence + 1,
				})
				if !changed || got.Status != OperationTransientFailed || got.RetryAfter != test.want || got.ReportSequence != base.ReportSequence+1 {
					t.Fatalf("MergeProviderReport() = (%#v, %t), want transient failure with retry_after %s", got, changed, test.want)
				}
			})
		}
	})

	t.Run("failed report without hint preserves durable wait", func(t *testing.T) {
		got, changed := MergeProviderReport(base, ProviderReport{
			ClientRequestID:   base.ClientRequestID,
			ProviderRequestID: base.ProviderRequestID,
			Status:            OperationTransientFailed,
			ErrorClass:        ProviderErrorTransient,
			ErrorCode:         "provider_unavailable",
			Sequence:          base.ReportSequence + 1,
		})
		if !changed || got.RetryAfter != base.RetryAfter {
			t.Fatalf("MergeProviderReport() = (%#v, %t), want preserved retry_after %s", got, changed, base.RetryAfter)
		}
	})

	t.Run("successful report clears stale durable wait", func(t *testing.T) {
		got, changed := MergeProviderReport(base, ProviderReport{
			ClientRequestID:   base.ClientRequestID,
			ProviderRequestID: base.ProviderRequestID,
			Status:            OperationSucceeded,
			Sequence:          base.ReportSequence + 1,
		})
		if !changed || got.Status != OperationSucceeded || got.RetryAfter != 0 {
			t.Fatalf("MergeProviderReport() = (%#v, %t), want success with cleared retry_after", got, changed)
		}
	})

	t.Run("invalid retry hints reject the complete report", func(t *testing.T) {
		for _, test := range []struct {
			name       string
			status     OperationStatus
			class      ProviderErrorClass
			retryAfter time.Duration
		}{
			{name: "running", status: OperationRunning, retryAfter: time.Second},
			{name: "success", status: OperationSucceeded, retryAfter: time.Second},
			{name: "permanent", status: OperationPermanentFailed, class: ProviderErrorPermanent, retryAfter: time.Second},
			{name: "revision conflict", status: OperationRevisionConflict, class: ProviderErrorRevisionConflict, retryAfter: time.Second},
			{name: "cancelled", status: OperationCancelled, class: ProviderErrorCancelled, retryAfter: time.Second},
			{name: "negative transient", status: OperationTransientFailed, class: ProviderErrorTransient, retryAfter: -time.Second},
			{name: "wrong transient class", status: OperationTransientFailed, class: ProviderErrorPermanent, retryAfter: time.Second},
		} {
			t.Run(test.name, func(t *testing.T) {
				report := ProviderReport{
					ClientRequestID:   base.ClientRequestID,
					ProviderRequestID: base.ProviderRequestID,
					Status:            test.status,
					ErrorClass:        test.class,
					RetryAfter:        test.retryAfter,
					Sequence:          base.ReportSequence + 1,
				}
				got, changed := MergeProviderReport(base, report)
				if changed || got != base {
					t.Fatalf("MergeProviderReport(%#v) = (%#v, %t), want unchanged %#v", report, got, changed, base)
				}
			})
		}
	})

	t.Run("existing rejection preserves retry hint and sequence", func(t *testing.T) {
		for _, report := range []ProviderReport{
			{ClientRequestID: base.ClientRequestID, ProviderRequestID: base.ProviderRequestID, Status: OperationTransientFailed, ErrorClass: ProviderErrorTransient, RetryAfter: time.Minute, Sequence: base.ReportSequence},
			{ClientRequestID: "other-request", ProviderRequestID: base.ProviderRequestID, Status: OperationTransientFailed, ErrorClass: ProviderErrorTransient, RetryAfter: time.Minute, Sequence: base.ReportSequence + 1},
			{ClientRequestID: base.ClientRequestID, ProviderRequestID: "other-operation", Status: OperationTransientFailed, ErrorClass: ProviderErrorTransient, RetryAfter: time.Minute, Sequence: base.ReportSequence + 1},
		} {
			got, changed := MergeProviderReport(base, report)
			if changed || got != base {
				t.Fatalf("MergeProviderReport(%#v) = (%#v, %t), want unchanged %#v", report, got, changed, base)
			}
		}
	})
}
