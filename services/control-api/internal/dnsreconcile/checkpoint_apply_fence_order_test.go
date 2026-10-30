package dnsreconcile

import (
	"os"
	"strings"
	"testing"
)

func TestPostgresCheckpointApplyFencesIdenticalReplayBeforeNoop(t *testing.T) {
	source, err := os.ReadFile("postgres_store.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	start := strings.Index(text, "func (store *PostgresStore) appendResult(")
	end := strings.Index(text, "func consumeRetryAfterHints(")
	if start < 0 || end <= start {
		t.Fatal("appendResult source not found")
	}
	appendResult := text[start:end]
	workerFence := strings.Index(appendResult, "if source == \"worker\" {")
	claimFence := strings.Index(appendResult, "assertLiveApplyClaim(")
	identicalNoop := strings.Index(appendResult, "if sameResult(current.Result, checkpointResult) && retryDelay == 0 {")
	if workerFence < 0 || claimFence < 0 || identicalNoop < 0 {
		t.Fatal("appendResult checkpoint fence contract is incomplete")
	}
	if workerFence > claimFence || claimFence > identicalNoop {
		t.Fatal("worker apply claim must be fenced before an identical checkpoint can return success")
	}
}
