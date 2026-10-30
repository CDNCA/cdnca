package httppolicycontrol

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestHTTPPolicyListPageBudgetPaginatesMaximumPoliciesWithoutGaps(t *testing.T) {
	config := maxSizedListTestConfig(t)
	now := time.Date(2026, 7, 25, 4, 0, 0, 0, time.UTC)
	rows := make([]storedPolicy, 3)
	for index := range rows {
		policy := Policy{
			ID:              uuid.MustParse(fmt.Sprintf("01983f00-0000-7000-8000-%012d", 3-index)),
			TenantScopeID:   uuid.MustParse("01983f00-0000-7000-8000-000000000010"),
			SiteID:          uuid.MustParse(fmt.Sprintf("01983f00-0000-7000-8000-%012d", 10+index)),
			SiteOwnerUserID: uuid.MustParse("01983f00-0000-7000-8000-000000000020"),
			Revision:        1, PublicationRevision: 1,
			CreatedAt: now.Add(-time.Duration(index) * time.Microsecond),
			UpdatedAt: now.Add(-time.Duration(index) * time.Microsecond),
		}
		applyConfig(&policy, config)
		rows[index] = storedPolicy{Policy: policy, TenantID: uuid.New()}
	}
	all := ListResult{Items: []Policy{rows[0].Policy, rows[1].Policy, rows[2].Policy}}
	if encoded, err := json.Marshal(all); err != nil || len(encoded)+1 <= maxResponseBytes {
		t.Fatalf("unpaginated response bytes=%d error=%v, want over %d", len(encoded)+1, err, maxResponseBytes)
	}

	seen := make(map[uuid.UUID]struct{}, len(rows))
	pages := 0
	for offset := 0; offset < len(rows); pages++ {
		page := listPageAccumulator{result: ListResult{Items: make([]Policy, 0, 100)}}
		next := offset
		for next < len(rows) && len(page.result.Items) < 100 {
			added, err := page.add(rows[next])
			if err != nil {
				t.Fatal(err)
			}
			if !added {
				break
			}
			next++
		}
		result, err := page.finish(next < len(rows))
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Items) != 1 {
			t.Fatalf("page %d emitted %d maximum policies, want 1", pages, len(result.Items))
		}
		encoded, err := json.Marshal(result)
		if err != nil || len(encoded)+1 > maxResponseBytes {
			t.Fatalf("page %d bytes=%d error=%v, max=%d", pages, len(encoded)+1, err, maxResponseBytes)
		}
		for _, item := range result.Items {
			if _, duplicate := seen[item.ID]; duplicate {
				t.Fatalf("duplicate policy %s", item.ID)
			}
			seen[item.ID] = struct{}{}
		}
		if next < len(rows) {
			expected, err := encodeCursor(pageCursor{CreatedAt: rows[next-1].CreatedAt, ID: rows[next-1].ID})
			if err != nil {
				t.Fatal(err)
			}
			if result.NextCursor != expected {
				t.Fatalf("page %d cursor=%q want last-emitted %q", pages, result.NextCursor, expected)
			}
		} else if result.NextCursor != "" {
			t.Fatalf("final cursor=%q, want empty", result.NextCursor)
		}
		if next == offset {
			t.Fatalf("page %d did not emit the maximum legal policy", pages)
		}
		offset = next
	}
	if pages < 2 || len(seen) != len(rows) {
		t.Fatalf("pages=%d unique policies=%d want %d", pages, len(seen), len(rows))
	}
}

func maxSizedListTestConfig(t *testing.T) Config {
	t.Helper()
	actions := make([]HeaderAction, MaxHeaderActions)
	for actionIndex := range actions {
		values := make([]string, MaxHeaderValues)
		for valueIndex := range values {
			values[valueIndex] = "a"
		}
		actions[actionIndex] = HeaderAction{
			Kind: HeaderSet, Name: fmt.Sprintf("x-list-budget-%02d", actionIndex), Values: values,
		}
	}
	config := Config{
		MaxUploadBytes: 1, RequestHeaders: actions,
		ResponseHeaders: []HeaderAction{}, Rewrites: []RewriteRule{},
		RedirectAllowedHosts: []string{}, Redirects: []RedirectRule{},
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	remaining := MaxPolicyBytes - len(encoded)
	for actionIndex := range config.RequestHeaders {
		for valueIndex := range config.RequestHeaders[actionIndex].Values {
			added := min(remaining, MaxHeaderBytes-1)
			config.RequestHeaders[actionIndex].Values[valueIndex] += strings.Repeat("a", added)
			remaining -= added
			if remaining == 0 {
				break
			}
		}
		if remaining == 0 {
			break
		}
	}
	if remaining != 0 {
		t.Fatalf("maximum legal header capacity is %d bytes short", remaining)
	}
	normalized, err := normalizeConfig(config)
	if err != nil {
		t.Fatalf("normalize maximum list config: %v", err)
	}
	encoded, err = json.Marshal(normalized)
	if err != nil || len(encoded) != MaxPolicyBytes {
		t.Fatalf("maximum list config bytes=%d want=%d error=%v", len(encoded), MaxPolicyBytes, err)
	}
	return normalized
}
