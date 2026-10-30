package l4forward

import (
	"errors"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/packageaddon"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// 端口范围 / 跟随端口回源 (migration 334) through the store: a range is
// stored and published, counts every port against stream_ports, and a save
// overlapping another forward, a website port or a node port is refused with
// where it collides.
func TestPortRangeStoreConflictsAndQuota(t *testing.T) {
	fixture := newStreamAddonFixture(t)
	service, actor := NewService(NewStore(fixture.pool)), fixture.actor
	siteID := uuid.New()
	if err := pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `INSERT INTO sites(id,display_id,scope_id,owner_user_id,domain,http_ports,origins,origin_hosts,created_by_user_id,updated_by_user_id)
			VALUES($1,2,$2,$3,'range-site.example',ARRAY['25080'],ARRAY['192.0.2.10'],ARRAY['192.0.2.10'],$3,$3)`, siteID, actor.ScopeID, actor.UserID); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO site_origin_pools(site_id) VALUES($1)`, siteID); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO site_origins(site_id,position,host,port) VALUES($1,1,'192.0.2.10',80)`, siteID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	unlimited := fixture.subscription(t, actor.UserID, -1)
	create := func(subscription uuid.UUID, name, protocol string, port, end uint16) CreateRequest {
		key := uuid.NewString()
		return CreateRequest{Fields: Fields{PackageSubscriptionID: new(subscription),
			Name: name, Protocol: protocol, ListenAddress: "*", ListenPort: port, ListenPortEnd: end,
			UpstreamAddress: "192.0.2.10", UpstreamFollowPort: true,
			ConnectTimeoutMS: 1000, ResponseTimeoutMS: 30000, MaxConnectionsPerClient: 100, Enabled: true},
			IdempotencyKey: key, RequestID: key}
	}
	created, err := service.Create(t.Context(), actor, create(unlimited, "game", ProtocolTCP, 21000, 21099))
	if err != nil {
		t.Fatal(err)
	}
	spec := created.Forward.PublishIntent.RuntimeSpec
	if created.Forward.ListenPortEnd != 21099 || !created.Forward.UpstreamFollowPort || created.Forward.UpstreamPort != 21000 ||
		spec.Listener.PortEnd != 21099 || !spec.Endpoint.FollowPort || spec.Endpoint.Port != 21000 {
		t.Fatalf("stored range: %+v intent %+v", created.Forward, spec)
	}
	fetched, err := service.Get(t.Context(), actor, created.Forward.ID)
	if err != nil || fetched.ListenPortEnd != 21099 || !fetched.UpstreamFollowPort {
		t.Fatalf("read back: %+v %v", fetched, err)
	}
	port := int64(21050)
	listed, err := service.List(t.Context(), actor, ListFilter{ListenPort: &port, Page: 1, Limit: 10})
	if err != nil || len(listed.Items) != 1 || listed.Items[0].ID != created.Forward.ID {
		t.Fatalf("listen_port filter inside the range: %+v %v", listed.Items, err)
	}

	for name, check := range map[string]struct {
		request CreateRequest
		want    PortConflictError
	}{
		"single port inside another range": {create(unlimited, "inside", ProtocolTCP, 21050, 0),
			PortConflictError{Protocol: ProtocolTCP, Port: 21050, With: PortConflictStream, Name: "game"}},
		"range overlapping another range": {create(unlimited, "overlap", ProtocolTCP, 21090, 21200),
			PortConflictError{Protocol: ProtocolTCP, Port: 21090, PortEnd: 21099, With: PortConflictStream, Name: "game"}},
		"range over a website port": {create(unlimited, "site", ProtocolTCP, 25000, 25100),
			PortConflictError{Protocol: ProtocolTCP, Port: 25080, With: PortConflictSite, Name: "range-site.example"}},
		"range over a node port": {create(unlimited, "node", ProtocolTCP, 18000, 18100),
			PortConflictError{Protocol: ProtocolTCP, Port: 18080, With: PortConflictReserved}},
	} {
		_, err := service.Create(t.Context(), actor, check.request)
		var located *PortConflictError
		if !errors.As(err, &located) || !errors.Is(err, ErrPortConflict) || *located != check.want {
			t.Fatalf("%s: %v (%+v)", name, err, located)
		}
	}
	if _, err := service.Create(t.Context(), actor, create(unlimited, "udp", ProtocolUDP, 21000, 21099)); err != nil {
		t.Fatalf("same range on UDP: %v", err)
	}

	// stream_ports counts every port of a range.
	limited := fixture.subscription(t, actor.UserID, 100)
	if _, err := service.Create(t.Context(), actor, create(limited, "over", ProtocolTCP, 22000, 22100)); !errors.Is(err, packageaddon.ErrQuotaExceeded) {
		t.Fatalf("101 ports on a 100-port package: %v", err)
	}
	if _, err := service.Create(t.Context(), actor, create(limited, "fits", ProtocolTCP, 22000, 22099)); err != nil {
		t.Fatalf("100 ports on a 100-port package: %v", err)
	}
	if _, err := service.Create(t.Context(), actor, create(limited, "one more", ProtocolTCP, 23000, 0)); !errors.Is(err, packageaddon.ErrQuotaExceeded) {
		t.Fatalf("port 101: %v", err)
	}
}
