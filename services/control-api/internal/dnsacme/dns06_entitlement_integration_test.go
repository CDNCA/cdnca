package dnsacme

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type dns06EntitlementChecker struct {
	check entitlementguard.FeatureCheck
	err   error
}

func (checker *dns06EntitlementChecker) CheckFeature(
	_ context.Context,
	_ pgx.Tx,
	check entitlementguard.FeatureCheck,
) (entitlementguard.FeatureDecision, error) {
	checker.check = check
	return entitlementguard.FeatureDecision{}, checker.err
}

func TestDNS06CreateOrderEntitlementPreflight(t *testing.T) {
	actor := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant"}
	request := CreateOrderRequest{TargetScopeID: actor.ScopeID, RequestID: "dns06-entitlement-denied"}
	orderID := uuid.New()
	for name, denial := range map[string]error{
		"missing lease or trust": entitlementguard.ErrUnavailable,
		"uncertain lease":        entitlementguard.ErrInvalid,
		"expired or revoked":     entitlementguard.ErrStateDenied,
		"missing feature":        entitlementguard.ErrFeatureDenied,
		"revocation unavailable": entitlementguard.ErrRevocationUnavailable,
		"revocation invalid":     entitlementguard.ErrRevocationInvalid,
		"revocation expired":     entitlementguard.ErrRevocationExpired,
	} {
		t.Run(name, func(t *testing.T) {
			checker := &dns06EntitlementChecker{err: denial}
			store := &Store{guard: checker}

			err := store.checkCreateOrderEntitlement(t.Context(), nil, actor, request, orderID)
			if !errors.Is(err, denial) || !entitlementguard.IsDenial(err) {
				t.Fatalf("checkCreateOrderEntitlement() error = %v, want fail-closed %v", err, denial)
			}
			check := checker.check
			if check.TargetScopeID != request.TargetScopeID || check.ActorScopeID != actor.ScopeID ||
				check.ActorUserID != actor.UserID || check.ResourceType != "certificate_order" ||
				check.ResourceID != orderID || check.RequestID != request.RequestID ||
				check.Operation != "certificate.order.create" || check.Feature != entitlementguard.FeatureCertificatesIssue ||
				check.Quota != "" || check.Count != nil {
				t.Fatalf("feature check = %#v", check)
			}
		})
	}
}

func TestDNS06CreateOrderChecksEntitlementBeforeMutation(t *testing.T) {
	source, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatalf("read store.go: %v", err)
	}
	text := string(source)
	start := strings.Index(text, "func (s *Store) CreateOrder(")
	end := strings.Index(text[start:], "func (s *Store) ScheduleDueRenewal(")
	if start < 0 || end < 0 {
		t.Fatal("CreateOrder source block not found")
	}
	block := text[start : start+end]
	guardAt := strings.Index(block, "s.checkCreateOrderEntitlement(")
	if guardAt < 0 {
		t.Fatal("CreateOrder does not call the entitlement preflight")
	}
	for _, mutation := range []string{
		"reserveWrite(",
		"INSERT INTO certificate_orders",
		"enqueueCertificateOrder(",
	} {
		mutationAt := strings.Index(block, mutation)
		if mutationAt < 0 || guardAt >= mutationAt {
			t.Fatalf("entitlement preflight must precede %q", mutation)
		}
	}
	if !strings.Contains(block, "entitlementguard.IsDenial(err)") ||
		!strings.Contains(block, "denial != nil") || !strings.Contains(block, "err = denial") {
		t.Fatal("CreateOrder must commit the durable denial audit before returning the denial")
	}
}
