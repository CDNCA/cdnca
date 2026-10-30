package identity

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestSuspendMembershipRejectsInvalidInputBeforeStoreAccess(t *testing.T) {
	validActor := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform"}
	validInput := SuspendMembershipInput{
		ScopeID: uuid.New(), UserID: uuid.New(), ExpectedStatus: MembershipStatusActive,
		ReasonCode: "security_review", IdempotencyKey: "membership-suspend-1",
		RequestID: "request-1", TraceID: "trace-1",
	}
	tests := map[string]struct {
		actor Actor
		input SuspendMembershipInput
	}{
		"missing actor user":  {actor: Actor{ScopeID: validActor.ScopeID, ScopeKind: "platform"}, input: validInput},
		"missing actor scope": {actor: Actor{UserID: validActor.UserID, ScopeKind: "platform"}, input: validInput},
		"unknown actor scope kind": {
			actor: Actor{UserID: validActor.UserID, ScopeID: validActor.ScopeID, ScopeKind: "operator"}, input: validInput,
		},
		"missing target scope": {actor: validActor, input: withMembershipInput(validInput, func(input *SuspendMembershipInput) {
			input.ScopeID = uuid.Nil
		})},
		"missing target user": {actor: validActor, input: withMembershipInput(validInput, func(input *SuspendMembershipInput) {
			input.UserID = uuid.Nil
		})},
		"unsupported expected status": {actor: validActor, input: withMembershipInput(validInput, func(input *SuspendMembershipInput) {
			input.ExpectedStatus = MembershipStatusSuspended
		})},
		"invalid reason": {actor: validActor, input: withMembershipInput(validInput, func(input *SuspendMembershipInput) {
			input.ReasonCode = "Security review"
		})},
		"invalid idempotency key": {actor: validActor, input: withMembershipInput(validInput, func(input *SuspendMembershipInput) {
			input.IdempotencyKey = "membership suspend"
		})},
		"missing request ID": {actor: validActor, input: withMembershipInput(validInput, func(input *SuspendMembershipInput) {
			input.RequestID = "  "
		})},
		"missing trace ID": {actor: validActor, input: withMembershipInput(validInput, func(input *SuspendMembershipInput) {
			input.TraceID = "  "
		})},
	}
	service := new(Service)
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := service.SuspendMembership(t.Context(), test.actor, test.input); !errors.Is(err, ErrInvalidMembershipInput) {
				t.Fatalf("SuspendMembership() error = %v, want ErrInvalidMembershipInput", err)
			}
		})
	}
}

func TestNormalizeSuspendMembershipInputCanonicalizesMetadata(t *testing.T) {
	actor := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant"}
	input := SuspendMembershipInput{
		ScopeID: actor.ScopeID, UserID: uuid.New(), ExpectedStatus: " active ",
		ReasonCode: " security_review ", IdempotencyKey: "membership-suspend-1",
		RequestID: " request-1 ", TraceID: " trace-1 ",
	}
	if err := normalizeSuspendMembershipInput(actor, &input); err != nil {
		t.Fatalf("normalizeSuspendMembershipInput() error = %v", err)
	}
	if input.ExpectedStatus != MembershipStatusActive || input.ReasonCode != "security_review" ||
		input.RequestID != "request-1" || input.TraceID != "trace-1" {
		t.Fatalf("normalized input = %#v", input)
	}
}

func TestMembershipMutationDigestCoversSemanticInputOnly(t *testing.T) {
	base := SuspendMembershipInput{
		ScopeID: uuid.New(), UserID: uuid.New(), ExpectedStatus: MembershipStatusActive,
		ReasonCode: "security_review", IdempotencyKey: "membership-suspend-1",
		RequestID: "request-1", TraceID: "trace-1",
	}
	want, err := digestMembershipMutation(base)
	if err != nil {
		t.Fatal(err)
	}
	metadataOnly := base
	metadataOnly.RequestID = "request-2"
	metadataOnly.TraceID = "trace-2"
	metadataDigest, err := digestMembershipMutation(metadataOnly)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want[:], metadataDigest[:]) {
		t.Fatal("request and trace metadata changed the idempotency digest")
	}
	for name, mutate := range map[string]func(*SuspendMembershipInput){
		"scope":           func(input *SuspendMembershipInput) { input.ScopeID = uuid.New() },
		"user":            func(input *SuspendMembershipInput) { input.UserID = uuid.New() },
		"expected status": func(input *SuspendMembershipInput) { input.ExpectedStatus = MembershipStatusSuspended },
		"reason":          func(input *SuspendMembershipInput) { input.ReasonCode = "policy_violation" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := base
			mutate(&changed)
			got, err := digestMembershipMutation(changed)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(want[:], got[:]) {
				t.Fatalf("digest did not cover %s", name)
			}
		})
	}
}

func TestMembershipMutationDatabaseErrorsAreStable(t *testing.T) {
	for _, code := range []string{"40001", "40P01", "23505"} {
		err := mapMembershipMutationError(&pgconn.PgError{
			Code: code, Message: "reviewer database detail", Detail: "SQLSTATE " + code,
		})
		if !errors.Is(err, ErrMembershipUnavailable) {
			t.Fatalf("mapMembershipMutationError(%s) = %v, want ErrMembershipUnavailable", code, err)
		}
		for _, leaked := range []string{"reviewer", "database detail", "SQLSTATE", code} {
			if strings.Contains(err.Error(), leaked) {
				t.Fatalf("public membership error leaked %q: %v", leaked, err)
			}
		}
	}
	for _, stable := range []error{
		ErrPermissionDenied, ErrMembershipNotFound, ErrMembershipStatusConflict, ErrIdempotencyConflict,
	} {
		if got := mapMembershipMutationError(stable); !errors.Is(got, stable) {
			t.Fatalf("mapMembershipMutationError(%v) = %v", stable, got)
		}
	}
}

func withMembershipInput(
	input SuspendMembershipInput,
	mutate func(*SuspendMembershipInput),
) SuspendMembershipInput {
	mutate(&input)
	return input
}
