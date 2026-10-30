package sitequickblock

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

func boolPointer(value bool) *bool { return &value }

func TestUpdateRejectsInvalidRequestsBeforeTheStore(t *testing.T) {
	service := NewService(nil) // the store is never reached
	actor := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant"}
	valid := UpdateRequest{SiteID: uuid.New(), ExpectedRevision: 1, IdempotencyKey: "key-1", RequestID: "req-1"}
	for name, mutate := range map[string]func(*Actor, *UpdateRequest){
		"no site":         func(_ *Actor, request *UpdateRequest) { request.SiteID = uuid.Nil },
		"no revision":     func(_ *Actor, request *UpdateRequest) { request.ExpectedRevision = 0 },
		"bad key":         func(_ *Actor, request *UpdateRequest) { request.IdempotencyKey = "has space" },
		"no request id":   func(_ *Actor, request *UpdateRequest) { request.RequestID = " " },
		"unknown scope":   func(actor *Actor, _ *UpdateRequest) { actor.ScopeKind = "node" },
		"unknown carrier": func(_ *Actor, request *UpdateRequest) { request.Override.Carriers = &[]string{"carrier:nope"} },
		"bad crawler cidr": func(_ *Actor, request *UpdateRequest) {
			request.Override.AllowedCrawlers = &[]securitypolicy.TrustedCrawler{{Networks: []string{"nope"}, UserAgentPrefixes: []string{"Googlebot"}}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			actor, request := actor, valid
			mutate(&actor, &request)
			if _, err := service.Update(context.Background(), actor, request); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("Update = %v, want ErrInvalidInput", err)
			}
		})
	}
}

// Rule 10: the audit event summarises each item's change (inherit, the
// switch, the list; crawlers by their networks) and leaves unchanged items out.
func TestOverrideChangesSummarisesChangedItems(t *testing.T) {
	previous := securitypolicy.QuickBlockOverride{BlockIDCCN: boolPointer(true), Carriers: &[]string{"carrier:cn-mobile"}}
	next := securitypolicy.QuickBlockOverride{BlockIDCCN: boolPointer(true), BlockIDCGlobal: boolPointer(false),
		AllowedCrawlers: &[]securitypolicy.TrustedCrawler{{Networks: []string{"66.249.64.0/19"}, UserAgentPrefixes: []string{"Googlebot"}}}}
	changes := overrideChanges(previous, next)
	if _, unchanged := changes["block_idc_cn"]; unchanged || len(changes) != 3 {
		t.Fatalf("changes = %v", changes)
	}
	want := map[string]string{
		"block_idc_global": "map[from:inherit to:false]",
		"carriers":         "map[from:[carrier:cn-mobile] to:inherit]",
		"allowed_crawlers": "map[from:inherit to:[66.249.64.0/19]]",
	}
	for key, text := range want {
		if got := fmt.Sprint(changes[key]); got != text {
			t.Errorf("%s = %s, want %s", key, got, text)
		}
	}
	// An empty list (off) differs from inherit.
	if got := fmt.Sprint(overrideChanges(securitypolicy.QuickBlockOverride{},
		securitypolicy.QuickBlockOverride{Carriers: &[]string{}})["carriers"]); got != "map[from:inherit to:[]]" {
		t.Fatalf("off carriers = %s", got)
	}
}

func TestDeniedReasonCodes(t *testing.T) {
	for err, reason := range map[error]string{
		ErrLocked: "site_locked", ErrRevisionConflict: "revision_conflict", ErrIdempotencyConflict: "idempotency_conflict",
		ErrNoLibrary: "no_waf_library", securitypolicy.ErrQuickBlockIPIntelUnavailable: "ip_intel_unavailable",
		securitypolicy.ErrQuickBlockUnsupported: "unsupported_policy", securitypolicy.ErrQuickBlockLastRules: "last_rules",
		securitypolicy.ErrQuickBlockRuleBudget: "rule_budget", ErrNotFound: "", errors.New("db down"): "",
	} {
		if got := deniedReason(fmt.Errorf("wrapped: %w", err)); got != reason {
			t.Errorf("deniedReason(%v) = %q, want %q", err, got, reason)
		}
	}
}
