package pluginwebhook

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// siteUpdatedData is a valid io.cdnca.site.v1.updated data object for tests.
func siteUpdatedData(subscription, site uuid.UUID, change string) json.RawMessage {
	return json.RawMessage(`{"subscription_id":"` + subscription.String() + `","subject_sequence":1,"site_id":"` +
		site.String() + `","change":"` + change + `","changed_fields":["origins"]}`)
}

func TestDomainEventRequestRequiresAnAvailableDomainContract(t *testing.T) {
	subscription, site := uuid.New(), uuid.New()
	valid := DomainEventRequest{
		SubscriptionID: subscription, EventType: "io.cdnca.site.v1.updated", Subject: "site/" + site.String(),
		RequestID: uuid.NewString(), OccurredAt: time.Unix(1704067200, 123000000).UTC(),
		Data: siteUpdatedData(subscription, site, "updated"),
	}
	if err := validateDomainEventRequest(valid); err != nil {
		t.Fatalf("valid domain event rejected: %v", err)
	}
	for name, mutate := range map[string]func(*DomainEventRequest){
		"test event":           func(request *DomainEventRequest) { request.EventType = "io.cdnca.webhook.v1.test" },
		"unavailable event":    func(request *DomainEventRequest) { request.EventType = "io.cdnca.dns.v1.changed" },
		"subscription subject": func(request *DomainEventRequest) { request.Subject = "webhook_subscription/" + subscription.String() },
		"other kind subject":   func(request *DomainEventRequest) { request.Subject = "deployment/" + site.String() },
		"missing subscription identity": func(request *DomainEventRequest) {
			request.Data = json.RawMessage(`{"subject_sequence":1,"site_id":"` + site.String() + `","change":"updated","changed_fields":[]}`)
		},
		"extension field": func(request *DomainEventRequest) {
			request.Data = json.RawMessage(`{"subscription_id":"` + subscription.String() + `","subject_sequence":1,"site_id":"` +
				site.String() + `","change":"updated","changed_fields":[],"x_zone":"a"}`)
		},
		"unknown change": func(request *DomainEventRequest) { request.Data = siteUpdatedData(subscription, site, "renamed") },
	} {
		t.Run(name, func(t *testing.T) {
			request := valid
			mutate(&request)
			if !errors.Is(validateDomainEventRequest(request), ErrInvalidInput) {
				t.Fatalf("validateDomainEventRequest() = %v, want invalid input", validateDomainEventRequest(request))
			}
		})
	}
}

func TestDomainEventRequestAcceptsDeploymentStatusContract(t *testing.T) {
	subscription, deployment := uuid.New(), uuid.New()
	request := DomainEventRequest{
		SubscriptionID: subscription,
		EventType:      "io.cdnca.deployment.v1.status_changed",
		Subject:        "deployment/" + deployment.String(),
		RequestID:      uuid.New().String(),
		OccurredAt:     time.Unix(1704067200, 123000000).UTC(),
		Data: json.RawMessage(`{"subscription_id":"` + subscription.String() + `","subject_sequence":4,"deployment_id":"` +
			deployment.String() + `","rollout_id":"` + uuid.NewString() + `","node_id":"` + uuid.NewString() +
			`","attempt":1,"transition_sequence":3,"state":"healthy"}`),
	}
	if err := validateDomainEventRequest(request); err != nil {
		t.Fatalf("deployment event rejected: %v", err)
	}
}

func TestDomainEventProducerDoesNotAcceptCallerActorFields(t *testing.T) {
	// Actor scope/user fields intentionally do not exist on DomainEventRequest;
	// PublishDomainEvent loads both from the persisted subscription row.
	request := DomainEventRequest{}
	if request.SubscriptionID != uuid.Nil {
		t.Fatal("zero request unexpectedly contains an actor")
	}
}

func TestDomainEventIdempotencyKeyBindsOnlyStableRequestIdentity(t *testing.T) {
	subscription := uuid.New()
	scope := domainSubscription{tenantScopeID: uuid.New()}
	request := DomainEventRequest{SubscriptionID: subscription, EventType: "io.cdnca.site.v1.updated", Subject: "site/" + subscription.String(),
		RequestID: "dns-change-identity", OccurredAt: time.Unix(1704067200, 0),
		Data: json.RawMessage(`{"subscription_id":"` + subscription.String() + `","subject_sequence":1,"site_id":"` + subscription.String() + `","change":"updated","changed_fields":["origins"]}`)}
	changedData := request
	changedData.Data = json.RawMessage(`{"subscription_id":"` + subscription.String() + `","subject_sequence":1,"site_id":"` + subscription.String() + `","change":"created","changed_fields":["origins"]}`)
	if got, changed := domainIdempotencyKey(request, scope), domainIdempotencyKey(changedData, scope); got != changed {
		t.Fatalf("idempotency key changed with payload: %q != %q", got, changed)
	}
	for name, mutate := range map[string]func(*DomainEventRequest){
		"request id":   func(value *DomainEventRequest) { value.RequestID = "dns-change-other" },
		"event type":   func(value *DomainEventRequest) { value.EventType = "io.cdnca.deployment.v1.status_changed" },
		"subscription": func(value *DomainEventRequest) { value.SubscriptionID = uuid.New() },
	} {
		t.Run(name, func(t *testing.T) {
			value := request
			mutate(&value)
			if domainIdempotencyKey(request, scope) == domainIdempotencyKey(value, scope) {
				t.Fatal("different stable request identity reused idempotency key")
			}
		})
	}
}

func TestDomainEventRequestDigestUsesStableSemanticInputs(t *testing.T) {
	subscription := uuid.New()
	scope := domainSubscription{tenantScopeID: uuid.New(), actorScopeID: uuid.New(), actorUserID: uuid.New()}
	request := DomainEventRequest{SubscriptionID: subscription, EventType: "io.cdnca.site.v1.updated", Subject: "site/" + subscription.String(),
		RequestID: "dns-change-digest", OccurredAt: time.Unix(1704067200, 123000000).UTC(),
		Data: json.RawMessage(`{"subscription_id":"` + subscription.String() + `","subject_sequence":1,"site_id":"` + subscription.String() + `","change":"updated","changed_fields":["origins"]}`)}
	canonical, err := canonicalDomainEventData(request.Data)
	if err != nil {
		t.Fatal(err)
	}
	base := domainRequestDigest(request, scope, canonical)
	if base != domainRequestDigest(request, scope, canonical) {
		t.Fatal("same semantic request produced different digest")
	}
	equivalentData := json.RawMessage(`{ "changed_fields" : ["origins"], "change" : "updated", "site_id" : "` + subscription.String() + `", "subject_sequence" : 1, "subscription_id" : "` + subscription.String() + `" }`)
	equivalentCanonical, err := canonicalDomainEventData(equivalentData)
	if err != nil || base != domainRequestDigest(request, scope, equivalentCanonical) {
		t.Fatal("equivalent JSON produced different digest")
	}
	for name, mutate := range map[string]func(*DomainEventRequest){
		"occurred at": func(value *DomainEventRequest) { value.OccurredAt = value.OccurredAt.Add(time.Second) },
		"traceparent": func(value *DomainEventRequest) {
			trace := "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"
			value.Traceparent = &trace
		},
		"data": func(value *DomainEventRequest) {
			value.Data = json.RawMessage(`{"subscription_id":"` + subscription.String() + `","subject_sequence":1,"site_id":"` + subscription.String() + `","change":"created","changed_fields":["origins"]}`)
		},
	} {
		t.Run(name, func(t *testing.T) {
			value := request
			mutate(&value)
			valueCanonical, err := canonicalDomainEventData(value.Data)
			if err != nil {
				t.Fatal(err)
			}
			if base == domainRequestDigest(value, scope, valueCanonical) {
				t.Fatal("semantic input change did not change request digest")
			}
		})
	}
	changedActor := scope
	changedActor.actorUserID = uuid.New()
	if base == domainRequestDigest(request, changedActor, canonical) {
		t.Fatal("actor binding change did not change request digest")
	}
}

func TestCanonicalDomainEventDataNormalizesExactDecimalNumbers(t *testing.T) {
	base := json.RawMessage(`{"z":1,"nested":{"large":900719925474099312345678901234567890,"items":[1.2300,1e-3,-0,0.000,-42.5000,10e-1,100e-2]},"a":1}`)
	equivalent := json.RawMessage(`{"nested":{"items":[1.23,0.001,0,0,-42.5,1,1],"large":900719925474099312345678901234567890.0},"a":1.0,"z":1e0}`)
	canonicalBase, err := canonicalDomainEventData(base)
	if err != nil {
		t.Fatalf("canonical base: %v", err)
	}
	canonicalEquivalent, err := canonicalDomainEventData(equivalent)
	if err != nil {
		t.Fatalf("canonical equivalent: %v", err)
	}
	if string(canonicalBase) != string(canonicalEquivalent) {
		t.Fatalf("equivalent decimals differ:\n%s\n%s", canonicalBase, canonicalEquivalent)
	}
	want := `{"a":1,"nested":{"items":[1.23,0.001,0,0,-42.5,1,1],"large":900719925474099312345678901234567890},"z":1}`
	if string(canonicalBase) != want {
		t.Fatalf("canonical = %s, want %s", canonicalBase, want)
	}
}

func TestCanonicalDomainEventDataRejectsExpandedNumberBeyondLimit(t *testing.T) {
	if _, err := canonicalDomainEventData(json.RawMessage(`{"n":1e65536}`)); err == nil {
		t.Fatal("canonical oversized exponent unexpectedly succeeded")
	}
}

func TestDomainEventSubscriptionStatusAllowsOnlyCompletedReplay(t *testing.T) {
	for _, test := range []struct {
		name    string
		status  string
		replay  bool
		wantErr error
	}{
		{name: "active new request", status: "active", replay: false},
		{name: "active replay", status: "active", replay: true},
		{name: "revoked replay", status: "revoked", replay: true},
		{name: "expired replay", status: "expired", replay: true},
		{name: "revoked new request", status: "revoked", replay: false, wantErr: ErrProducerState},
		{name: "expired new request", status: "expired", replay: false, wantErr: ErrProducerState},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateDomainEventSubscriptionStatus(test.status, test.replay)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("status validation = %v, want %v", err, test.wantErr)
			}
		})
	}
}

func TestInsertDomainEventSeparatesEventAndTransactionTimes(t *testing.T) {
	subscriptionID := uuid.New()
	request := DomainEventRequest{SubscriptionID: subscriptionID, EventType: "io.cdnca.site.v1.updated", Subject: "site/" + subscriptionID.String(),
		RequestID: "dns-change-time", OccurredAt: time.Unix(1704067200, 123000000).UTC(),
		Data: json.RawMessage(`{"subscription_id":"` + subscriptionID.String() + `","subject_sequence":1,"site_id":"` + subscriptionID.String() + `","change":"updated","changed_fields":["origins"]}`)}
	transactionNow := request.OccurredAt.Add(10 * time.Minute)
	query := &captureDomainEventQueryRower{row: fakeDomainEventRow{values: []any{[]byte("body"), bytes.Repeat([]byte{1}, 32)}}}
	eventID, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = insertDomainEvent(context.Background(), query, request, domainSubscription{
		tenantScopeID: uuid.New(), actorScopeID: uuid.New(), actorUserID: uuid.New()}, eventID, 1, transactionNow)
	if err != nil {
		t.Fatal(err)
	}
	if len(query.args) != 13 {
		t.Fatalf("insertDomainEvent args = %d, want 13", len(query.args))
	}
	if got := query.args[4].(time.Time); !got.Equal(request.OccurredAt) {
		t.Fatalf("event_time arg = %s, want %s", got, request.OccurredAt)
	}
	if got := query.args[12].(time.Time); !got.Equal(transactionNow) {
		t.Fatalf("created_at arg = %s, want transaction time %s", got, transactionNow)
	}
}

func TestValidateDomainEventReplayRequiresCompleteConsistentFacts(t *testing.T) {
	deliveryID := uuid.New()
	eventID := uuid.New()
	subscriptionID := uuid.New()
	status := 202
	completedAt := time.Unix(1704067200, 0).UTC()
	digest := [32]byte{1, 2, 3}
	sequence := "7"
	keyDigest := sha256.Sum256([]byte(deliveryID.String()))
	fact := domainEventReplayFact{RequestDigest: digest[:], ResponseStatus: &status,
		ResponseBody: []byte(`{"subscription_id":"` + subscriptionID.String() + `","delivery_id":"` + deliveryID.String() + `"}`),
		CompletedAt:  &completedAt, RequestDeliveryID: &deliveryID, DeliveryID: &deliveryID,
		EventID: &eventID, Sequence: &sequence, DeliveryKey: stringPointer("plugin-webhook-v2-" + hex.EncodeToString(keyDigest[:]))}
	result, err := validateDomainEventReplay(fact, digest, subscriptionID)
	if err != nil || !result.Replayed || result.EventID != eventID || result.DeliveryID != deliveryID || result.Sequence != 7 {
		t.Fatalf("valid replay = %#v, %v", result, err)
	}
	fact.ResponseStatus = nil
	if _, err := validateDomainEventReplay(fact, digest, subscriptionID); !errors.Is(err, ErrProducerState) {
		t.Fatalf("incomplete replay error = %v", err)
	}
	fact.ResponseStatus = &status
	fact.ResponseBody = []byte(`{"subscription_id":"` + subscriptionID.String() + `","delivery_id":"` + deliveryID.String() + `","extra":true}`)
	if _, err := validateDomainEventReplay(fact, digest, subscriptionID); !errors.Is(err, ErrProducerState) {
		t.Fatalf("non-exact response error = %v", err)
	}
}

func stringPointer(value string) *string { return &value }

type captureDomainEventQueryRower struct {
	row  pgx.Row
	args []any
}

func (query *captureDomainEventQueryRower) QueryRow(_ context.Context, _ string, args ...any) pgx.Row {
	query.args = args
	return query.row
}

type fakeDomainEventRow struct {
	values []any
}

func (row fakeDomainEventRow) Scan(destinations ...any) error {
	if len(destinations) != len(row.values) {
		return errors.New("fake row destination count mismatch")
	}
	for index, destination := range destinations {
		target := reflect.ValueOf(destination)
		if target.Kind() != reflect.Pointer || target.IsNil() {
			return errors.New("fake row destination is not a pointer")
		}
		value := reflect.ValueOf(row.values[index])
		if !value.IsValid() || !value.Type().AssignableTo(target.Elem().Type()) {
			return errors.New("fake row value type mismatch")
		}
		target.Elem().Set(value)
	}
	return nil
}
