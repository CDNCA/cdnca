#!/bin/sh
set -eu

repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"

(
  cd "${repo_root}/agents/edge-agent"
  GOMAXPROCS=1 GOWORK=off go test ./internal/cachetask \
    -run '^TestCacheTask(BulkTargetsBuildOneIndexAndInvalidateAll|ConcurrentBulkRefreshIsolationAndSingleIndexes|ScanFailureDoesNotMutateActiveCache|BulkPlanningResourceBounds)$' \
    -count=1
  GOMAXPROCS=1 GOWORK=off go test ./internal/cachetask \
    -run '^$' \
    -bench '^BenchmarkCacheTaskBulkPurgePlanning$' \
    -benchtime=1x -count=5 -cpu=1 -benchmem
)
