package cachecontrol

import (
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestNormalizeReportAcceptsOnlyCanonicalCancellation(t *testing.T) {
	request := ReportRequest{
		ScopeID: uuid.New(), OperationID: uuid.New(), NodeID: uuid.New(),
		WorkerID: "cache-worker", LeaseID: uuid.New(), Attempt: 1, Sequence: 3,
		RequestID: "cancelled-report", Results: []TargetResult{{
			TargetOrdinal: 1, State: ItemCancelled, ErrorCode: codeCancelled,
		}},
	}
	results, _, err := normalizeReport(request)
	if err != nil || len(results) != 1 || results[0].State != ItemCancelled ||
		results[0].ErrorCode != codeCancelled {
		t.Fatalf("canonical cancelled report results=%+v err=%v", results, err)
	}

	for _, code := range []string{"", "worker_stopped"} {
		invalid := request
		invalid.Results = append([]TargetResult(nil), request.Results...)
		invalid.Results[0].ErrorCode = code
		if _, _, err := normalizeReport(invalid); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("cancelled error_code=%q err=%v, want ErrInvalidInput", code, err)
		}
	}
}

func TestSummarizeReportResultsIncludesCancellation(t *testing.T) {
	tests := []struct {
		name   string
		states []ItemState
		state  State
		reason string
	}{
		{name: "all succeeded", states: []ItemState{ItemSucceeded, ItemSucceeded}, state: StateSucceeded},
		{name: "all failed", states: []ItemState{ItemFailed, ItemFailed}, state: StateFailed, reason: codeTargetFailed},
		{name: "all cancelled", states: []ItemState{ItemCancelled, ItemCancelled}, state: StateCancelled, reason: codeCancelled},
		{name: "success and failed", states: []ItemState{ItemSucceeded, ItemFailed}, state: StatePartialFailed, reason: codeTargetFailed},
		{name: "success and cancelled", states: []ItemState{ItemSucceeded, ItemCancelled}, state: StatePartialFailed, reason: codeCancelled},
		{name: "failed and cancelled", states: []ItemState{ItemFailed, ItemCancelled}, state: StatePartialFailed, reason: codeTargetFailed},
		{name: "all terminal kinds", states: []ItemState{ItemSucceeded, ItemFailed, ItemCancelled}, state: StatePartialFailed, reason: codeTargetFailed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := make([]TargetResult, len(test.states))
			for index, state := range test.states {
				results[index] = TargetResult{TargetOrdinal: index + 1, State: state}
			}
			state, reason := summarizeReportResults(results)
			if state != test.state || reason != test.reason {
				t.Fatalf("state=%q reason=%q, want state=%q reason=%q", state, reason, test.state, test.reason)
			}
		})
	}
}
