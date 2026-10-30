package l4forward

import (
	"errors"
	"testing"

	"github.com/google/uuid"
)

// cdncaCE: the community edition has no packages. A forward without a
// subscription (migration 597 lets package_subscription_id be NULL) is
// stored, read back and still refused on a port conflict.
func TestCommunityForwardWithoutPackage(t *testing.T) {
	fixture := newStreamAddonFixture(t)
	service, actor := NewService(NewStore(fixture.pool)), fixture.actor
	create := func(name string, port uint16) CreateRequest {
		key := uuid.NewString()
		return CreateRequest{Fields: Fields{Name: name, Protocol: ProtocolTCP, ListenAddress: "*", ListenPort: port,
			UpstreamAddress: "192.0.2.10", UpstreamPort: 3306,
			ConnectTimeoutMS: 1000, ResponseTimeoutMS: 30000, MaxConnectionsPerClient: 100, Enabled: true},
			IdempotencyKey: key, RequestID: key}
	}
	created, err := service.Create(t.Context(), actor, create("db", 23306))
	if err != nil {
		t.Fatalf("create without a package: %v", err)
	}
	if created.Forward.PackageSubscriptionID != nil {
		t.Fatalf("stored subscription %v, want none", *created.Forward.PackageSubscriptionID)
	}
	var stored *uuid.UUID
	if err := fixture.pool.QueryRow(t.Context(), `SELECT package_subscription_id FROM l4_forwards WHERE id=$1`,
		created.Forward.ID).Scan(&stored); err != nil || stored != nil {
		t.Fatalf("row package_subscription_id = %v, %v; want NULL", stored, err)
	}
	fetched, err := service.Get(t.Context(), actor, created.Forward.ID)
	if err != nil || fetched.ListenPort != 23306 || fetched.PackageSubscriptionID != nil {
		t.Fatalf("read back: %+v %v", fetched, err)
	}
	_, err = service.Create(t.Context(), actor, create("dup", 23306))
	if !errors.Is(err, ErrPortConflict) {
		t.Fatalf("second forward on the same port: %v, want a port conflict", err)
	}
}
